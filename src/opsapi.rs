//! Optional OpsAPI webhook when a terminal session is tied to a kanban task
//! (`opsapi_task` query / Open message field).

use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::config::OpsapiConfig;

/// Fire-and-forget HMAC-signed POST to OpsAPI. No-op when webhook_url/secret unset.
pub fn notify(cfg: &OpsapiConfig, event: &str, session_id: &str, user: &str, opsapi_task: Option<&str>) {
    let url = match cfg.webhook_url.as_deref() {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => return,
    };
    let secret = match cfg.webhook_secret.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            debug!("opsapi webhook_url set but webhook_secret empty; skip");
            return;
        }
    };
    let Some(task) = opsapi_task.filter(|t| !t.is_empty()) else {
        return;
    };
    let body = json!({
        "event": event,
        "session_id": session_id,
        "user": user,
        "opsapi_task": task,
        "ts": unix_now(),
    });
    let body_bytes = body.to_string();
    let sig = sign_hmac_sha256(&secret, body_bytes.as_bytes());
    tokio::spawn(async move {
        if let Err(e) = post(&url, &body_bytes, &sig).await {
            warn!(error = %e, url = %url, "opsapi webhook failed");
        }
    });
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// HMAC-SHA256 hex using a pure SHA256 keyed construction compatible with
/// resty.openssl.hmac (HMAC-SHA256). Implemented with hmac+sha2 via a small
/// manual HMAC so we do not add a new crate beyond sha2/hex already present.
fn sign_hmac_sha256(secret: &str, body: &[u8]) -> String {
    // Standard HMAC-SHA256
    const BLOCK: usize = 64;
    let mut key = secret.as_bytes().to_vec();
    if key.len() > BLOCK {
        key = Sha256::digest(&key).to_vec();
    }
    if key.len() < BLOCK {
        key.resize(BLOCK, 0);
    }
    let mut ipad = vec![0x36u8; BLOCK];
    let mut opad = vec![0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(body);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    hex::encode(outer.finalize())
}

async fn post(url: &str, body: &str, sig_hex: &str) -> Result<(), String> {
    // Prefer reqwest when available (dev + prod dep).
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Opsapi-Signature", format!("sha256={sig_hex}"))
        .header("User-Agent", "sshweb-opsapi-webhook")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("status {}", res.status()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_known_vector() {
        // HMAC-SHA256("", "") = b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad
        let sig = sign_hmac_sha256("", b"");
        assert_eq!(
            sig,
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
    }
}
