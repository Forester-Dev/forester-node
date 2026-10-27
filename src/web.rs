//! Web view: the owner's own site, served from this node.
//!
//! When `web_view` is on, the node listens on `web_port` (8097 by default) and serves Forester's
//! compact transfer site for whatever domain the owner points at it, through their own reverse
//! proxy or tunnel, which provides HTTPS. The page and its assets come from the Forester site
//! (`site_upstream`) over HTTPS and are cached here; the files themselves never pass through
//! this server.
//!
//! `/.well-known/forester-site?c=<challenge>` answers with a signature by this node's identity
//! key over the domain it was reached at, so Forester can confirm the domain really leads to
//! this node before it lets the domain use the owner's account.

use crate::link::Shared;
use crate::update;
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{info, warn};

const MAX_HEAD: usize = 16 * 1024;
const PAGE_TTL: Duration = Duration::from_secs(300);
const CACHE_LIMIT_BYTES: usize = 64 * 1024 * 1024;

struct Cached {
    body: bytes::Bytes,
    content_type: String,
    fetched: Instant,
}

/// Starts and stops the server as the owner switches the web view on and off.
pub async fn run_forever(shared: Arc<Shared>) {
    let mut server: Option<(u16, JoinHandle<()>)> = None;
    let cache: Arc<Mutex<HashMap<String, Cached>>> = Arc::default();
    loop {
        let c = shared.config();
        let want = c.web_view.then_some(c.web_port);
        match (&server, want) {
            (Some((port, _)), Some(p)) if *port == p => {}
            (current, want) => {
                if let Some((port, task)) = current {
                    task.abort();
                    info!("web view stopped on port {port}");
                }
                server = None;
                if let Some(port) = want {
                    match TcpListener::bind(("0.0.0.0", port)).await {
                        Ok(listener) => {
                            info!("web view serving on port {port}; point your domain's proxy or tunnel here");
                            let (s, cache) = (Arc::clone(&shared), Arc::clone(&cache));
                            server = Some((port, tokio::spawn(serve(listener, s, cache))));
                        }
                        Err(e) => warn!("web view could not listen on port {port}: {e}"),
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn serve(listener: TcpListener, shared: Arc<Shared>, cache: Arc<Mutex<HashMap<String, Cached>>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let (s, cache) = (Arc::clone(&shared), Arc::clone(&cache));
        tokio::spawn(async move {
            if let Err(e) = handle(stream, s, cache).await {
                tracing::debug!("web view request failed: {e:#}");
            }
        });
    }
}

struct Request {
    method: String,
    path: String,
    query: String,
    host: String,
}

async fn read_request(stream: &mut TcpStream) -> Result<Option<Request>> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut chunk)).await??;
        if n == 0 || buf.len() + n > MAX_HEAD {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let target = first.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut host = String::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            // Behind a proxy the original host may arrive as X-Forwarded-Host
            let k = k.trim().to_ascii_lowercase();
            if k == "x-forwarded-host" || (k == "host" && host.is_empty()) {
                host = v.trim().split(',').next().unwrap_or("").to_string();
            }
        }
    }
    let host = host.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(h, _)| h.to_string()).unwrap_or(host);
    Ok(Some(Request { method, path: path.to_string(), query: query.to_string(), host: host.to_ascii_lowercase() }))
}

async fn respond(stream: &mut TcpStream, status: &str, content_type: &str, cache_control: &str, body: &[u8], head_only: bool) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: {cache_control}\r\n\
         X-Content-Type-Options: nosniff\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    if !head_only {
        stream.write_all(body).await?;
    }
    stream.shutdown().await.ok();
    Ok(())
}

async fn handle(mut stream: TcpStream, shared: Arc<Shared>, cache: Arc<Mutex<HashMap<String, Cached>>>) -> Result<()> {
    let Some(req) = read_request(&mut stream).await? else { return Ok(()) };
    let head_only = req.method == "HEAD";
    if req.method != "GET" && !head_only {
        return respond(&mut stream, "405 Method Not Allowed", "text/plain", "no-store", b"Only GET is served here.", false).await;
    }

    if req.path == "/.well-known/forester-site" {
        let challenge = req.query.split('&').find_map(|kv| kv.strip_prefix("c=")).unwrap_or("");
        let valid = (16..=64).contains(&challenge.len())
            && challenge.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !valid || req.host.is_empty() {
            return respond(&mut stream, "400 Bad Request", "text/plain", "no-store", b"Bad challenge.", head_only).await;
        }
        let msg = format!("forester-site:v1:{}:{challenge}", req.host);
        let body = json!({
            "nodeId": shared.identity.node_id,
            "host": req.host,
            "sig": shared.identity.sign_b64(msg.as_bytes()),
        })
        .to_string();
        return respond(&mut stream, "200 OK", "application/json", "no-store", body.as_bytes(), head_only).await;
    }

    // Built assets are named by their content and never change; everything else is the app's page
    let is_asset = req.path.starts_with("/assets/") || req.path.starts_with("/fonts/") || req.path == "/favicon.svg";
    let upstream_path = if is_asset { req.path.clone() } else { "/site.html".to_string() };
    if upstream_path.contains("..") {
        return respond(&mut stream, "400 Bad Request", "text/plain", "no-store", b"Bad path.", head_only).await;
    }
    let ttl = if is_asset { None } else { Some(PAGE_TTL) };
    match fetch_cached(&shared, &cache, &upstream_path, ttl).await {
        Ok((body, content_type)) => {
            let cc = if is_asset { "public, max-age=31536000, immutable" } else { "no-cache" };
            respond(&mut stream, "200 OK", &content_type, cc, &body, head_only).await
        }
        Err(e) => {
            warn!("web view could not fetch {upstream_path}: {e:#}");
            respond(&mut stream, "502 Bad Gateway", "text/plain", "no-store", b"Forester is unreachable right now. Try again shortly.", head_only).await
        }
    }
}

async fn fetch_cached(
    shared: &Shared,
    cache: &Mutex<HashMap<String, Cached>>,
    path: &str,
    ttl: Option<Duration>,
) -> Result<(bytes::Bytes, String)> {
    if let Some(hit) = cache.lock().unwrap().get(path) {
        if ttl.is_none_or(|t| hit.fetched.elapsed() < t) {
            return Ok((hit.body.clone(), hit.content_type.clone()));
        }
    }
    let url = format!("{}{path}", shared.config().site_upstream.trim_end_matches('/'));
    let res = update::client()?.get(&url).send().await?;
    anyhow::ensure!(res.status().is_success(), "HTTP {}", res.status());
    let content_type = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let body = res.bytes().await?;
    let mut c = cache.lock().unwrap();
    if c.values().map(|v| v.body.len()).sum::<usize>() + body.len() > CACHE_LIMIT_BYTES {
        c.clear();
    }
    c.insert(path.to_string(), Cached { body: body.clone(), content_type: content_type.clone(), fetched: Instant::now() });
    Ok((body, content_type))
}
