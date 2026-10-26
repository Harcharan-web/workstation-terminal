//! Loopback-only OTLP/HTTP (JSON) receiver for Claude Code's telemetry.
//!
//! `POST /v1/logs` and `POST /v1/metrics` on `127.0.0.1:<otlp_port>`. The bearer token names the
//! tab; posts without a known token are kept as unattributed (`tab: null`), so tampering shows.
//! Only the log events and metrics OpsAPI uses are kept; personal attributes are dropped and long
//! text is cut.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde_json::{Map, Value, json};

use super::WorkLog;

pub const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_PROMPT_BYTES: usize = 16 * 1024;
const MAX_TOOL_TEXT_BYTES: usize = 8 * 1024;
const LOG_EVENTS: [&str; 5] = [
    "user_prompt",
    "api_request",
    "api_error",
    "tool_result",
    "tool_decision",
];
const METRICS: [&str; 4] = [
    "claude_code.lines_of_code.count",
    "claude_code.commit.count",
    "claude_code.pull_request.count",
    "claude_code.active_time.total",
];
const DROPPED_ATTRS: [&str; 3] = ["user.email", "user.account_uuid", "organization.id"];

/// One kept log record or metric data point, before it gets its id and tab.
#[derive(Debug, Clone, PartialEq)]
pub struct Draft {
    /// Unix seconds (millisecond precision).
    pub at: f64,
    pub kind: String,
    pub session: Option<String>,
    pub prompt_id: Option<String>,
    pub attrs: Map<String, Value>,
}

fn items<'a>(v: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    v.get(key).and_then(Value::as_array).into_iter().flatten()
}

/// An OTLP integer: a string in OTLP JSON, a number accepted too.
fn int(v: &Value) -> Option<Value> {
    match v {
        Value::String(s) => s.parse::<i64>().ok().map(Value::from),
        Value::Number(_) => Some(v.clone()),
        _ => None,
    }
}

/// An OTLP `AnyValue` as JSON; arrays and maps are left out.
fn any_value(v: &Value) -> Option<Value> {
    if let Some(s) = v.get("stringValue") {
        return s.as_str().map(Value::from);
    }
    if let Some(i) = v.get("intValue") {
        return int(i);
    }
    if let Some(d) = v.get("doubleValue") {
        return d.as_f64().map(Value::from);
    }
    v.get("boolValue").and_then(Value::as_bool).map(Value::from)
}

fn attributes(v: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    for a in items(v, "attributes") {
        if let (Some(k), Some(v)) = (a["key"].as_str(), any_value(&a["value"])) {
            out.insert(k.to_string(), v);
        }
    }
    out
}

/// Unix nanoseconds (a string in OTLP JSON, or a number) as seconds; None for missing or 0.
fn seconds(v: Option<&Value>) -> Option<f64> {
    let n = match v? {
        Value::String(s) => s.parse::<u64>().ok()?,
        n => n.as_u64()?,
    };
    (n > 0).then(|| (n / 1_000_000) as f64 / 1000.0)
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as f64 / 1000.0)
        .unwrap_or(0.0)
}

fn take_str(attrs: &mut Map<String, Value>, key: &str) -> Option<String> {
    match attrs.remove(key)? {
        Value::String(s) => Some(s),
        other => Some(other.to_string()),
    }
}

/// Cut a string attribute to at most `max` bytes, on a character boundary.
fn cut(attrs: &mut Map<String, Value>, key: &str, max: usize) {
    if let Some(Value::String(s)) = attrs.get_mut(key)
        && s.len() > max
    {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

/// `resourceLogs[].scopeLogs[].logRecords[]` -> the kept events.
pub fn parse_logs(body: &Value) -> Vec<Draft> {
    let mut out = Vec::new();
    for rl in items(body, "resourceLogs") {
        for sl in items(rl, "scopeLogs") {
            for r in items(sl, "logRecords") {
                let mut attrs = attributes(r);
                let name = take_str(&mut attrs, "event.name")
                    .or_else(|| r.get("eventName")?.as_str().map(str::to_string))
                    .unwrap_or_default();
                let name = name.strip_prefix("claude_code.").unwrap_or(&name);
                if !LOG_EVENTS.contains(&name) {
                    continue;
                }
                let session = take_str(&mut attrs, "session.id");
                let prompt_id = take_str(&mut attrs, "prompt.id");
                for k in DROPPED_ATTRS {
                    attrs.remove(k);
                }
                cut(&mut attrs, "prompt", MAX_PROMPT_BYTES);
                cut(&mut attrs, "tool_parameters", MAX_TOOL_TEXT_BYTES);
                cut(&mut attrs, "tool_input", MAX_TOOL_TEXT_BYTES);
                out.push(Draft {
                    at: seconds(r.get("timeUnixNano"))
                        .or_else(|| seconds(r.get("observedTimeUnixNano")))
                        .unwrap_or_else(now),
                    kind: name.to_string(),
                    session,
                    prompt_id,
                    attrs,
                });
            }
        }
    }
    out
}

/// `resourceMetrics[].scopeMetrics[].metrics[]` (sum or gauge data points) -> `metric` events
/// with attrs `{name, type?, model?, value}`. Zero values (nothing happened in a delta) are
/// left out.
pub fn parse_metrics(body: &Value) -> Vec<Draft> {
    let mut out = Vec::new();
    for rm in items(body, "resourceMetrics") {
        for sm in items(rm, "scopeMetrics") {
            for m in items(sm, "metrics") {
                let Some(name) = m.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if !METRICS.contains(&name) {
                    continue;
                }
                let points = ["sum", "gauge"]
                    .into_iter()
                    .filter_map(|k| m.get(k))
                    .flat_map(|d| items(d, "dataPoints"));
                for p in points {
                    let value = match (p.get("asInt"), p.get("asDouble")) {
                        (Some(i), _) => int(i),
                        (None, Some(d)) => d.as_f64().map(Value::from),
                        _ => None,
                    };
                    let Some(value) = value.filter(|v| v.as_f64() != Some(0.0)) else {
                        continue;
                    };
                    let mut pa = attributes(p);
                    let mut attrs = Map::new();
                    attrs.insert("name".into(), name.into());
                    for k in ["type", "model"] {
                        if let Some(v) = pa.remove(k) {
                            attrs.insert(k.into(), v);
                        }
                    }
                    attrs.insert("value".into(), value);
                    out.push(Draft {
                        at: seconds(p.get("timeUnixNano")).unwrap_or_else(now),
                        kind: "metric".into(),
                        session: take_str(&mut pa, "session.id"),
                        prompt_id: None,
                        attrs,
                    });
                }
            }
        }
    }
    out
}

pub fn router(wl: Arc<WorkLog>) -> Router {
    Router::new()
        .route("/v1/logs", post(logs))
        .route("/v1/metrics", post(metrics))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(wl)
}

async fn logs(State(wl): State<Arc<WorkLog>>, headers: HeaderMap, body: Bytes) -> Response {
    receive(&wl, &headers, &body, parse_logs)
}

async fn metrics(State(wl): State<Arc<WorkLog>>, headers: HeaderMap, body: Bytes) -> Response {
    receive(&wl, &headers, &body, parse_metrics)
}

fn receive(
    wl: &WorkLog,
    headers: &HeaderMap,
    body: &[u8],
    parse: fn(&Value) -> Vec<Draft>,
) -> Response {
    let get = |h| headers.get(h).and_then(|v| v.to_str().ok()).unwrap_or("");
    // Only Claude on this machine: a web page can't send JSON here without a CORS preflight
    // (never answered), and a rebound DNS name shows in Host.
    let host = get(header::HOST);
    let port = wl.otlp_port;
    if host != format!("127.0.0.1:{port}") && host != format!("localhost:{port}") {
        return (StatusCode::MISDIRECTED_REQUEST, "unknown host").into_response();
    }
    if !get(header::CONTENT_TYPE).starts_with("application/json") {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "send http/json").into_response();
    }
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return (StatusCode::BAD_REQUEST, "bad JSON").into_response();
    };
    let tab = get(header::AUTHORIZATION)
        .strip_prefix("Bearer ")
        .and_then(|t| wl.tab_for_token(t.trim()));
    wl.push_events(tab.as_deref(), parse(&v));
    axum::Json(json!({})).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(k: &str, v: &str) -> Value {
        json!({"key": k, "value": {"stringValue": v}})
    }

    fn logs_body(records: Vec<Value>) -> Value {
        json!({"resourceLogs": [{
            "resource": {"attributes": [s("service.name", "claude-code")]},
            "scopeLogs": [{
                "scope": {"name": "com.anthropic.claude_code.events"},
                "logRecords": records
            }]
        }]})
    }

    fn record(name: &str, mut attrs: Vec<Value>) -> Value {
        attrs.push(s("event.name", name));
        attrs.push(s("session.id", "sess-1"));
        attrs.push(s("prompt.id", "p-1"));
        attrs.push(s("user.email", "priya@example.com"));
        attrs.push(s("user.account_uuid", "acc"));
        attrs.push(s("organization.id", "org"));
        json!({
            "timeUnixNano": "1792828050123456789",
            "observedTimeUnixNano": "1792828051000000000",
            "body": {"stringValue": format!("claude_code.{name}")},
            "attributes": attrs
        })
    }

    #[test]
    fn logs_keep_only_the_five_events_without_personal_attributes() {
        let body = logs_body(vec![
            record("managed_settings_resolved", vec![]),
            record("hook_registered", vec![]),
            record(
                "user_prompt",
                vec![
                    s("prompt", "fix the header"),
                    json!({"key": "prompt_length", "value": {"intValue": "14"}}),
                ],
            ),
            record(
                "api_request",
                vec![
                    s("model", "claude-opus-5-5"),
                    json!({"key": "input_tokens", "value": {"intValue": 2}}),
                    json!({"key": "cost_usd", "value": {"doubleValue": 0.13839}}),
                    s("duration_ms", "2560"),
                    json!({"key": "list", "value": {"arrayValue": {"values": []}}}),
                ],
            ),
            record("assistant_response", vec![]),
            record(
                "tool_result",
                vec![json!({"key": "success", "value": {"boolValue": true}})],
            ),
        ]);
        let d = parse_logs(&body);
        let kinds: Vec<_> = d.iter().map(|d| d.kind.as_str()).collect();
        assert_eq!(kinds, ["user_prompt", "api_request", "tool_result"]);
        let p = &d[0];
        assert_eq!(p.at, 1792828050.123);
        assert_eq!(p.session.as_deref(), Some("sess-1"));
        assert_eq!(p.prompt_id.as_deref(), Some("p-1"));
        assert_eq!(
            Value::Object(p.attrs.clone()),
            json!({"prompt": "fix the header", "prompt_length": 14})
        );
        let a = &d[1].attrs;
        assert_eq!(a["input_tokens"], 2);
        assert_eq!(a["cost_usd"], 0.13839);
        assert_eq!(a["duration_ms"], "2560", "strings stay as given");
        assert!(!a.contains_key("list"));
        let lifted = ["event.name", "session.id", "prompt.id"];
        for k in DROPPED_ATTRS.iter().chain(&lifted) {
            assert!(d.iter().all(|e| !e.attrs.contains_key(*k)), "{k}");
        }
        assert_eq!(d[2].attrs["success"], true);
    }

    #[test]
    fn long_text_is_cut_on_a_character_boundary() {
        let body = logs_body(vec![
            record("user_prompt", vec![s("prompt", &"é".repeat(10_000))]),
            record(
                "tool_decision",
                vec![
                    s("tool_parameters", &"x".repeat(9000)),
                    s("tool_input", "ls"),
                ],
            ),
        ]);
        let d = parse_logs(&body);
        let p = d[0].attrs["prompt"].as_str().unwrap();
        assert_eq!(p.len(), MAX_PROMPT_BYTES, "a boundary: 2-byte characters");
        let text = format!("a{}", "é".repeat(10_000));
        let odd = logs_body(vec![record("user_prompt", vec![s("prompt", &text)])]);
        let p = parse_logs(&odd)[0].attrs["prompt"].as_str().unwrap().len();
        assert_eq!(p, MAX_PROMPT_BYTES - 1);
        assert_eq!(d[1].attrs["tool_parameters"].as_str().unwrap().len(), 8192);
        assert_eq!(d[1].attrs["tool_input"], "ls");
    }

    #[test]
    fn metrics_keep_four_names_as_metric_events() {
        let point = |kind: &str, v: Value, attrs: Vec<Value>| {
            let mut p = json!({"timeUnixNano": "1792828060000000000", "attributes": attrs});
            p[kind] = v;
            p
        };
        let one = |name: &str, kind: &str, v: Value| {
            json!({"name": name, "sum": {"dataPoints": [point(kind, v, vec![])]}})
        };
        let added = vec![
            s("type", "added"),
            s("session.id", "sess-1"),
            s("user.email", "priya@example.com"),
        ];
        let lines = [
            point("asInt", json!("12"), added),
            point("asInt", json!(3), vec![s("type", "removed")]),
            point("asInt", json!("0"), vec![s("type", "removed")]),
        ];
        let active = point(
            "asDouble",
            json!(4.5),
            vec![s("type", "cli"), s("model", "m")],
        );
        let metrics = json!([
            one("claude_code.session.count", "asInt", json!("1")),
            one("claude_code.cost.usage", "asDouble", json!(0.5)),
            {"name": "claude_code.lines_of_code.count", "sum": {"dataPoints": lines}},
            {"name": "claude_code.active_time.total", "gauge": {"dataPoints": [active]}},
            one("claude_code.commit.count", "asInt", json!("1")),
        ]);
        let body = json!({"resourceMetrics": [{"scopeMetrics": [{"metrics": metrics}]}]});
        let d = parse_metrics(&body);
        let got: Vec<Value> = d.iter().map(|d| Value::Object(d.attrs.clone())).collect();
        assert_eq!(
            got,
            [
                json!({"name": "claude_code.lines_of_code.count", "type": "added", "value": 12}),
                json!({"name": "claude_code.lines_of_code.count", "type": "removed", "value": 3}),
                json!({"name": "claude_code.active_time.total", "type": "cli", "model": "m",
                       "value": 4.5}),
                json!({"name": "claude_code.commit.count", "value": 1}),
            ]
        );
        assert!(d.iter().all(|d| d.kind == "metric"));
        assert!(d.iter().all(|d| d.at == 1792828060.0));
        assert_eq!(d[0].session.as_deref(), Some("sess-1"));
        assert_eq!(d[1].session, None);
    }

    #[test]
    fn garbage_shapes_yield_nothing() {
        for v in [
            json!(null),
            json!([]),
            json!({"resourceLogs": "x"}),
            json!({"resourceLogs": [1]}),
        ] {
            assert!(parse_logs(&v).is_empty());
            assert!(parse_metrics(&v).is_empty());
        }
    }
}
