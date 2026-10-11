//! Frontend assets embedded in the binary at compile time.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/"]
#[exclude = "*.map"]
struct Assets;

pub fn serve(path: &str) -> Response {
    if path.contains("..") {
        return StatusCode::NOT_FOUND.into_response();
    }
    match Assets::get(path) {
        Some(f) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let mut r = f.data.into_owned().into_response();
            let h = r.headers_mut();
            if let Ok(v) = HeaderValue::from_str(mime.as_ref()) {
                h.insert(header::CONTENT_TYPE, v);
            }
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            r
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub fn exists(path: &str) -> bool {
    Assets::get(path).is_some()
}
