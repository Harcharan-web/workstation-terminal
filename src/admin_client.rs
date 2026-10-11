//! Minimal HTTP/1.1 client for the local admin Unix socket (used by CLI commands).

use std::path::Path;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;

pub async fn request(socket: &Path, method: Method, path: &str) -> Result<(StatusCode, String)> {
    let stream = tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| {
            format!(
                "cannot connect to admin socket {} (is `sshweb serve` running with this config?)",
                socket.display()
            )
        })?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost")
        .body(Empty::<Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}
