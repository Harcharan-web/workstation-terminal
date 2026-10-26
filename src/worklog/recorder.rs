//! Screen recording: a local tab's PTY output (never its input) as asciicast v2, in parts.
//!
//! Part 0 starts with the header `{"version":2,"width":..,"height":..,"timestamp":..}`; then one
//! line per event, `[secs since the tab started, "o", text]` or `[secs, "r", "COLSxROWS"]`. A
//! part closes after 60 s or 1 MiB (uncompressed), and at tab close (the last part). It is
//! gzipped to `<state_dir>/recordings/<tab>-<part>.cast.gz` (0600) and queued for upload. While
//! `max_pending_mb` waits for upload, new parts are skipped: the tab's part numbers show the gap.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;
use tracing::warn;

use crate::audit::{Audit, AuditEvent};

pub const MAX_PART_BYTES: usize = 1024 * 1024;
pub const MAX_PART_AGE: Duration = Duration::from_secs(60);

/// A gzipped part on disk, waiting for upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub path: PathBuf,
    pub tab: String,
    pub part: u64,
    /// The tab's last part (`X-Opsapi-Final: 1`).
    pub last: bool,
    /// Size on disk.
    pub bytes: u64,
}

/// Parts waiting for upload, oldest first.
pub struct Uploads {
    pub dir: PathBuf,
    queue: Mutex<VecDeque<Part>>,
    pub ready: tokio::sync::Notify,
    /// Bytes of the queued parts, and the most that may wait.
    pending: AtomicU64,
    cap: u64,
    /// A part was skipped since the last one written (audited once per outage).
    over_cap: AtomicBool,
    audit: Arc<Audit>,
}

impl Uploads {
    pub fn new(dir: PathBuf, cap: u64, audit: Arc<Audit>) -> Self {
        Self {
            dir,
            queue: Mutex::new(VecDeque::new()),
            ready: tokio::sync::Notify::new(),
            pending: AtomicU64::new(0),
            cap,
            over_cap: AtomicBool::new(false),
            audit,
        }
    }

    pub fn push(&self, p: Part) {
        self.pending.fetch_add(p.bytes, Ordering::Relaxed);
        self.queue.lock().unwrap().push_back(p);
        self.ready.notify_one();
    }

    pub fn front(&self) -> Option<Part> {
        self.queue.lock().unwrap().front().cloned()
    }

    pub fn pop_front(&self) {
        if let Some(p) = self.queue.lock().unwrap().pop_front() {
            self.pending.fetch_sub(p.bytes, Ordering::Relaxed);
        }
    }

    /// Is there room for another part of `tab`? The first refusal of an outage is audited.
    fn room(&self, tab: &str) -> bool {
        if self.pending.load(Ordering::Relaxed) < self.cap {
            self.over_cap.store(false, Ordering::Relaxed);
            return true;
        }
        if !self.over_cap.swap(true, Ordering::Relaxed) {
            warn!(tab, "recordings waiting for upload reached max_pending_mb; skipping parts");
            let ev = AuditEvent::new("work_log_recording_skipped");
            self.audit.log(ev.field("tab", tab));
        }
        false
    }

    /// Queue parts left by an earlier run. Every tab in them has ended (sessions don't outlive
    /// the gateway), so each tab's highest part is its last.
    pub fn load_leftovers(&self) {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut found: BTreeMap<(String, u64), (PathBuf, u64)> = BTreeMap::new();
        for e in rd.flatten() {
            let path = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".tmp") {
                // A part being written when the gateway stopped: incomplete.
                let _ = std::fs::remove_file(&path);
            } else if let Some((tab, part)) = parse_name(&name) {
                let bytes = e.metadata().map(|m| m.len()).unwrap_or(0);
                found.insert((tab, part), (path, bytes));
            }
        }
        let parts: Vec<_> = found.into_iter().collect();
        for (i, ((tab, part), (path, bytes))) in parts.iter().enumerate() {
            let last = parts.get(i + 1).is_none_or(|((next, _), _)| next != tab);
            self.push(Part {
                path: path.clone(),
                tab: tab.clone(),
                part: *part,
                last,
                bytes: *bytes,
            });
        }
    }
}

/// `<tab>-<part>.cast.gz` -> (tab, part).
fn parse_name(name: &str) -> Option<(String, u64)> {
    let (tab, part) = name.strip_suffix(".cast.gz")?.rsplit_once('-')?;
    let valid = (1..=64).contains(&tab.len()) && tab.chars().all(|c| c.is_ascii_hexdigit());
    let part = part.parse().ok()?;
    valid.then(|| (tab.to_string(), part))
}

/// How many bytes at the end of `b` are the start of an unfinished UTF-8 character.
fn incomplete_tail(b: &[u8]) -> usize {
    for i in 1..=b.len().min(3) {
        let c = b[b.len() - i];
        if c & 0xC0 != 0x80 {
            let need = match c {
                0xF0.. => 4,
                0xE0.. => 3,
                0xC0.. => 2,
                _ => 1,
            };
            return if need > i { i } else { 0 };
        }
    }
    0
}

pub struct Recorder {
    uploads: Arc<Uploads>,
    tab: String,
    started: Instant,
    part: u64,
    part_started: Instant,
    /// asciicast lines of the current part.
    buf: Vec<u8>,
    events: usize,
    /// A character split across PTY reads, kept for the next one.
    carry: Vec<u8>,
    size: (u16, u16),
    finished: bool,
}

impl Recorder {
    pub fn new(uploads: Arc<Uploads>, tab: &str, cols: u16, rows: u16, timestamp: u64) -> Self {
        let header = json!({"version": 2, "width": cols, "height": rows, "timestamp": timestamp});
        let mut buf = header.to_string().into_bytes();
        buf.push(b'\n');
        Self {
            uploads,
            tab: tab.to_string(),
            started: Instant::now(),
            part: 0,
            part_started: Instant::now(),
            buf,
            events: 0,
            carry: Vec::new(),
            size: (cols, rows),
            finished: false,
        }
    }

    fn event(&mut self, code: &str, data: &str) {
        let t = self.started.elapsed().as_micros() as f64 / 1e6;
        self.buf
            .extend_from_slice(json!([t, code, data]).to_string().as_bytes());
        self.buf.push(b'\n');
        self.events += 1;
        if self.buf.len() >= MAX_PART_BYTES {
            self.close_part(false);
        }
    }

    pub fn output(&mut self, data: &[u8]) {
        if self.finished {
            return;
        }
        self.carry.extend_from_slice(data);
        let keep = incomplete_tail(&self.carry);
        let rest = self.carry.split_off(self.carry.len() - keep);
        let text = String::from_utf8_lossy(&self.carry).into_owned();
        self.carry = rest;
        if !text.is_empty() {
            self.event("o", &text);
        }
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        if !self.finished && self.size != (cols, rows) {
            self.size = (cols, rows);
            self.event("r", &format!("{cols}x{rows}"));
        }
    }

    /// Close the current part if it has events and is at least `age` old.
    pub fn rotate_if_older(&mut self, age: Duration) {
        if !self.finished && self.events > 0 && self.part_started.elapsed() >= age {
            self.close_part(false);
        }
    }

    /// The tab ended: write the last part (even with no events, so OpsAPI knows it's complete).
    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        if !self.carry.is_empty() {
            let rest = std::mem::take(&mut self.carry);
            self.event("o", &String::from_utf8_lossy(&rest));
        }
        self.close_part(true);
        self.finished = true;
    }

    fn close_part(&mut self, last: bool) {
        let mut data = std::mem::take(&mut self.buf);
        let room = self.uploads.room(&self.tab);
        if !room {
            // Too much waits for upload: drop the events. The last part still goes out (part 0
            // with its header), so OpsAPI knows the recording ended.
            let header = data.iter().position(|b| *b == b'\n').map_or(0, |i| i + 1);
            data.truncate(if self.part == 0 { header } else { 0 });
        }
        if room || last {
            let path = self
                .uploads
                .dir
                .join(format!("{}-{}.cast.gz", self.tab, self.part));
            // ponytail: gzip and write run on the PTY pump's task (a few ms per MiB); move to
            // spawn_blocking if output-heavy tabs ever stall.
            match write_part(&path, &data) {
                Ok(bytes) => self.uploads.push(Part {
                    path,
                    tab: self.tab.clone(),
                    part: self.part,
                    last,
                    bytes,
                }),
                Err(e) => warn!(error = %e, tab = %self.tab, "couldn't save a recording part"),
            }
        }
        self.part += 1;
        self.part_started = Instant::now();
        self.events = 0;
    }
}

/// Gzip `data` to `path` (0600), via a temporary file so a crash never leaves half a part.
/// Returns the size written.
fn write_part(path: &Path, data: &[u8]) -> std::io::Result<u64> {
    let dir = path.parent().unwrap_or(Path::new("."));
    crate::security::perms::ensure_private_dir(dir)?;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(data)?;
    let gz = gz.finish()?;
    let tmp = path.with_extension("gz.tmp");
    crate::security::perms::write_new_file(&tmp, &gz, 0o600, true)?;
    std::fs::rename(&tmp, path)?;
    Ok(gz.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::io::Read;

    fn gunzip(path: &Path) -> String {
        let mut s = String::new();
        flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
            .read_to_string(&mut s)
            .unwrap();
        s
    }

    fn drain(u: &Uploads) -> Vec<Part> {
        let mut v = Vec::new();
        while let Some(p) = u.front() {
            u.pop_front();
            v.push(p);
        }
        v
    }

    fn lines(s: &str) -> Vec<Value> {
        s.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    fn uploads(dir: &Path, cap: u64) -> Arc<Uploads> {
        Arc::new(Uploads::new(
            dir.to_path_buf(),
            cap,
            Arc::new(Audit::disabled()),
        ))
    }

    #[test]
    fn parts_rotate_by_size_and_age_with_the_header_only_in_part_0() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let u = uploads(&dir.path().join("recordings"), u64::MAX);
        let tab = "ab12";
        let mut r = Recorder::new(u.clone(), tab, 80, 24, 1792828000);
        // Over 1 MiB of output closes part 0 by itself.
        let chunk = "x".repeat(16 * 1024);
        for _ in 0..70 {
            r.output(chunk.as_bytes());
        }
        r.resize(80, 24);
        r.resize(120, 40);
        r.rotate_if_older(Duration::ZERO);
        r.rotate_if_older(Duration::ZERO); // nothing new: no empty part
        r.output("é".as_bytes());
        r.finish();
        r.output(b"after");
        r.finish();

        let parts = drain(&u);
        assert_eq!(
            parts.iter().map(|p| (p.part, p.last)).collect::<Vec<_>>(),
            [(0, false), (1, false), (2, true)]
        );
        let mode = std::fs::metadata(&parts[0].path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(parts[0].path.ends_with("ab12-0.cast.gz"));

        let p0 = lines(&gunzip(&parts[0].path));
        assert_eq!(p0[0]["version"], 2);
        assert_eq!(p0[0]["width"], 80);
        assert_eq!(p0[0]["timestamp"], 1792828000);
        assert!(p0[1][0].is_f64() && p0[1][1] == "o");
        let p1 = lines(&gunzip(&parts[1].path));
        assert!(p1.iter().all(|l| l.is_array()), "no header after part 0");
        assert_eq!(p1.last().unwrap()[1], "r");
        assert_eq!(p1.last().unwrap()[2], "120x40");
        assert_eq!(
            p1.iter().filter(|l| l[1] == "r").count(),
            1,
            "same size isn't recorded"
        );
        let p2 = lines(&gunzip(&parts[2].path));
        assert_eq!(p2.len(), 1);
        assert_eq!(p2[0][2], "é");
    }

    #[test]
    fn characters_split_across_reads_stay_whole() {
        let dir = tempfile::tempdir().unwrap();
        let u = uploads(dir.path(), u64::MAX);
        let mut r = Recorder::new(u.clone(), "cd34", 80, 24, 0);
        let s = "a€b😀".as_bytes();
        r.output(&s[..2]); // "a" + first byte of €
        r.output(&s[2..6]); // rest of € + "b" + first byte of 😀
        r.output(&s[6..]);
        r.finish();
        let text: String = lines(&gunzip(&drain(&u)[0].path))[1..]
            .iter()
            .map(|l| l[2].as_str().unwrap().to_string())
            .collect();
        assert_eq!(text, "a€b😀");
        assert_eq!(incomplete_tail(b"abc"), 0);
        assert_eq!(incomplete_tail(&"€".as_bytes()[..2]), 2);
    }

    #[test]
    fn leftovers_are_queued_with_each_tabs_highest_part_last() {
        let dir = tempfile::tempdir().unwrap();
        for f in [
            "aa-0.cast.gz",
            "aa-1.cast.gz",
            "bb-3.cast.gz",
            "bb-2.cast.gz.tmp",
            "x.txt",
        ] {
            std::fs::write(dir.path().join(f), b"").unwrap();
        }
        let u = uploads(dir.path(), u64::MAX);
        u.load_leftovers();
        let got: Vec<_> = drain(&u)
            .into_iter()
            .map(|p| (p.tab, p.part, p.last))
            .collect();
        assert_eq!(
            got,
            [
                ("aa".to_string(), 0, false),
                ("aa".to_string(), 1, true),
                ("bb".to_string(), 3, true),
            ]
        );
        assert!(!dir.path().join("bb-2.cast.gz.tmp").exists());
    }

    #[test]
    fn parts_are_skipped_while_too_much_waits_for_upload() {
        use crate::config::{AuditConfig, AuditDestination};
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.log");
        let audit = Audit::open(&AuditConfig {
            destination: AuditDestination::File,
            path: audit_path.clone(),
        })
        .unwrap();
        let u = Arc::new(Uploads::new(
            dir.path().join("recordings"),
            1,
            Arc::new(audit),
        ));
        let mut r = Recorder::new(u.clone(), "ef56", 80, 24, 0);
        let mut part = |text: &str| {
            r.output(text.as_bytes());
            r.rotate_if_older(Duration::ZERO);
        };
        part("a"); // written: nothing waits yet
        part("b"); // skipped, audited
        part("c"); // skipped
        u.pop_front(); // uploaded: room again
        part("d");
        r.output(b"e");
        r.finish(); // over the cap again: the last part goes out without its events
        let parts = drain(&u);
        assert_eq!(
            parts.iter().map(|p| (p.part, p.last)).collect::<Vec<_>>(),
            [(3, false), (4, true)]
        );
        assert_eq!(lines(&gunzip(&parts[0].path))[0][2], "d");
        assert_eq!(gunzip(&parts[1].path), "");
        let log = std::fs::read_to_string(&audit_path).unwrap();
        assert_eq!(log.matches("work_log_recording_skipped").count(), 2, "{log}");
        assert!(log.contains("\"tab\":\"ef56\""));

        // A tab whose only part is skipped still sends part 0 with its header.
        let u = uploads(&dir.path().join("recordings"), 0);
        let mut r = Recorder::new(u.clone(), "ab78", 100, 30, 7);
        r.output(b"lost");
        r.finish();
        let p = drain(&u);
        assert_eq!(p.len(), 1);
        let l = lines(&gunzip(&p[0].path));
        assert_eq!(l.len(), 1);
        assert_eq!(l[0]["width"], 100);
    }
}
