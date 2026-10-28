//! Outbound control link to the Forester control plane (CP).
//!
//! The node dials out and keeps one WebSocket open, so it works behind home routers and
//! CGNAT with no port forwarding. Operations are multiplexed by request id (`rid`) and
//! stream with backpressure: a slow disk or socket slows the sender instead of buffering.

use base64::Engine as _;
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use ed25519_dalek::VerifyingKey;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

use crate::config::Config;
use crate::identity::{Identity, NodeState, parse_public_key};
use crate::rtc::RtcHandle;
use crate::store::BlobStore;
use crate::{cap, disk, meter, update};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The running node, for components (such as the WebRTC engine) started before it exists.
pub static SHARED: std::sync::OnceLock<Arc<Shared>> = std::sync::OnceLock::new();
const STATUS_EVERY: Duration = Duration::from_secs(30);
const READ_CHUNK: usize = 256 * 1024;

pub struct Shared {
    pub config: RwLock<Config>,
    pub identity: Identity,
    pub store: Arc<BlobStore>,
    pub state: Mutex<NodeState>,
    pub rtc: Option<RtcHandle>,
}

impl Shared {
    pub fn config(&self) -> Config {
        self.config.read().unwrap().clone()
    }

    pub fn cp_key(&self) -> Option<VerifyingKey> {
        let pinned = self
            .config()
            .cp_key_override
            .or_else(|| self.state.lock().unwrap().cp_public_key.clone())?;
        parse_public_key(&pinned).ok()
    }

    /// Re-reads config.toml so owner edits apply without a restart.
    pub fn reload_config(&self) {
        let dir = self.config().data_dir;
        match Config::load(&dir) {
            Ok(c) => *self.config.write().unwrap() = c,
            Err(e) => warn!("config reload failed, keeping previous settings: {e:#}"),
        }
    }

    pub fn disk_report(&self) -> Result<disk::DiskReport> {
        let c = self.config();
        Ok(disk::measure(&c.data_dir, self.store.used(), c.max_storage_bytes, c.reserve_free_bytes)?)
    }

    pub fn signed_status(&self) -> Result<Value> {
        let c = self.config();
        let d = self.disk_report()?;
        let report = json!({
            "nodeId": self.identity.node_id,
            "ts": now_ms(),
            "version": VERSION,
            "allocBytes": d.alloc_bytes,
            "usedBytes": d.used_bytes,
            "blobCount": self.store.count(),
            "diskTotal": d.disk_total,
            "diskAvailable": d.disk_available,
            "reserveBytes": c.reserve_free_bytes,
            "maxStorageBytes": c.max_storage_bytes,
            "settingsLocked": c.env_locked,
            "volumeFingerprint": disk::volume_fingerprint(&c.data_dir, c.volume_id.as_deref()),
            "personalSite": c.web_view,
            "name": c.name,
            "platform": update::platform(),
            "autoUpdate": c.auto_update,
            "selfUpdate": update::supported(),
            "update": update::status(),
            "traffic": meter::snapshot(),
        });
        let raw = serde_json::to_string(&report)?;
        let sig = self.identity.sign_b64(raw.as_bytes());
        Ok(json!({ "t": "status", "report": raw, "sig": sig }))
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn ws_url(orchestrator: &str) -> Result<String> {
    let mut u = url::Url::parse(orchestrator.trim_end_matches('/')).context("bad orchestrator URL")?;
    let scheme = match u.scheme() {
        "https" | "wss" => "wss",
        "http" | "ws" => "ws",
        other => bail!("unsupported orchestrator scheme {other}"),
    };
    u.set_scheme(scheme).ok();
    let base = u.path().trim_end_matches('/').to_string();
    let path = if base.ends_with("/share") {
        format!("{base}/v1/nodes/connect")
    } else {
        format!("{base}/share/v1/nodes/connect")
    };
    u.set_path(&path);
    Ok(u.to_string())
}

/// Keeps the link up forever with capped exponential backoff.
pub async fn run_forever(shared: Arc<Shared>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        match connect_once(&shared).await {
            Ok(()) => info!("control link closed"),
            Err(e) => warn!("control link error: {e:#}"),
        }
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
        }
        let jitter = Duration::from_millis(rand::random::<u64>() % 1000);
        tokio::time::sleep(backoff + jitter).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

type Out = mpsc::Sender<Message>;

fn text(v: Value) -> Message {
    Message::text(v.to_string())
}

fn binary(rid: u32, data: &[u8]) -> Message {
    let mut frame = Vec::with_capacity(4 + data.len());
    frame.extend_from_slice(&rid.to_be_bytes());
    frame.extend_from_slice(data);
    Message::Binary(Bytes::from(frame))
}

async fn connect_once(shared: &Arc<Shared>) -> Result<()> {
    let url = ws_url(&shared.config().orchestrator_url)?;
    info!("connecting to {url}");
    let (ws, _) = tokio_tungstenite::connect_async(&url).await.context("connect")?;
    let (mut sink, mut stream) = ws.split();

    // 1. Challenge, pin the CP key, prove our identity
    let challenge = next_json(&mut stream).await?;
    if challenge["t"] != "challenge" {
        bail!("expected challenge");
    }
    let nonce = challenge["nonce"].as_str().context("challenge without nonce")?;
    let offered_key = challenge["cpKey"].as_str().context("challenge without cpKey")?;
    pin_cp_key(shared, offered_key)?;

    let c = shared.config();
    let hello = json!({
        "t": "hello",
        "nodeId": shared.identity.node_id,
        "pubKey": shared.identity.public_key_b64,
        "sig": shared.identity.sign_b64(format!("forester-node-hello:v1:{nonce}").as_bytes()),
        "version": VERSION,
        "name": c.name,
        "settings": { "personalSite": c.web_view },
        "rtc": shared.rtc.as_ref().map(|r| r.describe()),
    });
    sink.send(text(hello)).await?;

    let welcome = next_json(&mut stream).await?;
    if welcome["t"] != "welcome" {
        bail!("handshake rejected: {}", welcome["error"].as_str().unwrap_or("unknown reason"));
    }
    {
        let mut st = shared.state.lock().unwrap();
        st.claimed = welcome["claimed"].as_bool().unwrap_or(false);
        st.pairing_code = welcome["pairingCode"].as_str().map(str::to_string);
        st.save(&c.data_dir).ok();
        match &st.pairing_code {
            Some(code) if !st.claimed => info!(
                "node {} is not linked to an account yet. Pairing code: {code} (enter it at share.forester.dev)",
                shared.identity.node_id
            ),
            _ => info!("connected as {} (linked to an account)", shared.identity.node_id),
        }
    }

    // 2. One writer task owns the sink; everything else sends through a bounded channel
    let (out, mut rx) = mpsc::channel::<Message>(64);
    let mut writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if sink.send(m).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    out.send(text(shared.signed_status()?)).await.ok();
    let mut status_tick = tokio::time::interval(STATUS_EVERY);
    status_tick.tick().await;
    let mut ping_tick = tokio::time::interval(Duration::from_secs(20));

    // Active uploads, by request id: frames are forwarded to the task writing that blob
    let mut puts: HashMap<u32, mpsc::Sender<Bytes>> = HashMap::new();

    loop {
        tokio::select! {
            msg = stream.next() => {
                let Some(msg) = msg else { break };
                match msg? {
                    Message::Text(t) => {
                        let v: Value = match serde_json::from_str(t.as_str()) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        handle_command(shared, &out, &mut puts, v).await;
                    }
                    Message::Binary(b) => {
                        if b.len() < 4 { continue; }
                        let rid = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                        if let Some(tx) = puts.get(&rid) {
                            // Awaiting here is the backpressure: we stop reading the socket
                            if tx.send(b.slice(4..)).await.is_err() {
                                puts.remove(&rid);
                            }
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            _ = status_tick.tick() => {
                shared.reload_config();
                if let Ok(s) = shared.signed_status() {
                    out.send(text(s)).await.ok();
                }
            }
            _ = ping_tick.tick() => {
                out.send(Message::Ping(Bytes::new())).await.ok();
            }
            _ = &mut writer => bail!("writer stopped"),
        }
    }
    drop(out);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    Ok(())
}

fn pin_cp_key(shared: &Shared, offered: &str) -> Result<()> {
    parse_public_key(offered).context("CP offered an invalid key")?;
    if let Some(forced) = shared.config().cp_key_override {
        if forced != offered {
            bail!("control plane key does not match FORESTER_CP_KEY; refusing to connect");
        }
        return Ok(());
    }
    let mut st = shared.state.lock().unwrap();
    match &st.cp_public_key {
        Some(pinned) if pinned != offered => {
            bail!("control plane key changed since this node was set up; refusing to connect")
        }
        Some(_) => Ok(()),
        None => {
            st.cp_public_key = Some(offered.to_string());
            st.save(&shared.config().data_dir)?;
            info!("pinned control plane key");
            Ok(())
        }
    }
}

async fn next_json<S>(stream: &mut S) -> Result<Value>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let fut = async {
        while let Some(m) = stream.next().await {
            if let Message::Text(t) = m? {
                return Ok(serde_json::from_str(t.as_str())?);
            }
        }
        bail!("connection closed during handshake")
    };
    tokio::time::timeout(Duration::from_secs(15), fut).await.context("handshake timed out")?
}

fn reply_err(out: &Out, rid: u64, error: impl std::fmt::Display) {
    let msg = text(json!({ "t": "err", "rid": rid, "error": error.to_string() }));
    let out = out.clone();
    tokio::spawn(async move {
        out.send(msg).await.ok();
    });
}

async fn handle_command(
    shared: &Arc<Shared>,
    out: &Out,
    puts: &mut HashMap<u32, mpsc::Sender<Bytes>>,
    v: Value,
) {
    let t = v["t"].as_str().unwrap_or("");
    let rid = v["rid"].as_u64().unwrap_or(0);
    let blob = v["blob"].as_str();
    let token = v["cap"].as_str().unwrap_or("");

    if t == "end" {
        // Closing the channel tells the put task the data is complete
        puts.remove(&(rid as u32));
        return;
    }

    let op = match t {
        "put" | "get" | "del" | "por" | "mproof" | "rtc" | "settings" | "update" => t,
        _ => return,
    };
    let Some(cp_key) = shared.cp_key() else {
        return reply_err(out, rid, "no pinned control plane key");
    };
    let node_id = shared.identity.node_id.clone();
    let blob_for_cap = if matches!(op, "rtc" | "settings" | "update") { None } else { blob };
    let capability = match cap::verify(token, &cp_key, &node_id, op, blob_for_cap) {
        Ok(c) => c,
        Err(e) => return reply_err(out, rid, format!("{e:#}")),
    };

    // Transfers hold a guard so a self-update waits for them; none start while it is pending
    let guard = if matches!(op, "put" | "get" | "del" | "por" | "mproof") {
        match update::begin_op() {
            Some(g) => Some(g),
            None => return reply_err(out, rid, "node_restarting"),
        }
    } else {
        None
    };

    match op {
        "put" => {
            let (blob, size) = (blob.unwrap_or("").to_string(), v["size"].as_u64().unwrap_or(0));
            let sha = v["sha256"].as_str().unwrap_or("").to_string();
            if size > capability.max {
                return reply_err(out, rid, "size exceeds capability");
            }
            match shared.disk_report() {
                Ok(d) if d.free_for_network() >= size => {}
                Ok(_) => return reply_err(out, rid, "insufficient_capacity"),
                Err(e) => return reply_err(out, rid, format!("disk: {e}")),
            }
            let handle = match shared.store.begin_put(&blob, size, &sha).await {
                Ok(h) => h,
                Err(e) => return reply_err(out, rid, format!("{e:#}")),
            };
            let (tx, mut rx) = mpsc::channel::<Bytes>(16);
            puts.insert(rid as u32, tx);
            let out = out.clone();
            tokio::spawn(async move {
                let _guard = guard;
                let mut handle = handle;
                let result: Result<u64> = async {
                    while let Some(chunk) = rx.recv().await {
                        handle.write(&chunk).await?;
                        meter::received(meter::Path::Link, chunk.len());
                    }
                    handle.finish().await
                }
                .await;
                let msg = match result {
                    Ok(bytes) => json!({ "t": "ok", "rid": rid, "bytes": bytes }),
                    Err(e) => json!({ "t": "err", "rid": rid, "error": format!("{e:#}") }),
                };
                out.send(text(msg)).await.ok();
            });
        }
        "get" => {
            let store = Arc::clone(&shared.store);
            let out = out.clone();
            let blob = blob.unwrap_or("").to_string();
            let offset = v["offset"].as_u64().unwrap_or(0);
            let length = v["length"].as_u64();
            tokio::spawn(async move {
                let _guard = guard;
                let result: Result<()> = async {
                    let (mut file, size, mut remaining) = store.open_range(&blob, offset, length).await?;
                    out.send(text(json!({ "t": "meta", "rid": rid, "size": size }))).await?;
                    let mut buf = vec![0u8; READ_CHUNK];
                    while remaining > 0 {
                        let want = remaining.min(READ_CHUNK as u64) as usize;
                        let n = file.read(&mut buf[..want]).await?;
                        if n == 0 {
                            break;
                        }
                        out.send(binary(rid as u32, &buf[..n])).await?;
                        meter::served(meter::Path::Link, n);
                        remaining -= n as u64;
                    }
                    out.send(text(json!({ "t": "end", "rid": rid }))).await?;
                    Ok(())
                }
                .await;
                if let Err(e) = result {
                    out.send(text(json!({ "t": "err", "rid": rid, "error": format!("{e:#}") }))).await.ok();
                }
            });
        }
        "del" => {
            let store = Arc::clone(&shared.store);
            let out = out.clone();
            let blob = blob.unwrap_or("").to_string();
            tokio::spawn(async move {
                let _guard = guard;
                let msg = match store.delete(&blob).await {
                    Ok(existed) => json!({ "t": "ok", "rid": rid, "existed": existed }),
                    Err(e) => json!({ "t": "err", "rid": rid, "error": format!("{e:#}") }),
                };
                out.send(text(msg)).await.ok();
            });
        }
        "por" => {
            let store = Arc::clone(&shared.store);
            let out = out.clone();
            let blob = blob.unwrap_or("").to_string();
            let (offset, length) = (v["offset"].as_u64().unwrap_or(0), v["length"].as_u64().unwrap_or(0));
            let nonce = hex::decode(v["nonce"].as_str().unwrap_or("")).unwrap_or_default();
            tokio::spawn(async move {
                let _guard = guard;
                let msg = match store.proof(&blob, offset, length, &nonce).await {
                    Ok(hash) => json!({ "t": "por", "rid": rid, "hash": hash }),
                    Err(e) => json!({ "t": "err", "rid": rid, "error": format!("{e:#}") }),
                };
                out.send(text(msg)).await.ok();
            });
        }
        "mproof" => {
            let store = Arc::clone(&shared.store);
            let out = out.clone();
            let blob = blob.unwrap_or("").to_string();
            let index = v["index"].as_u64().unwrap_or(0);
            tokio::spawn(async move {
                let _guard = guard;
                let msg = match store.merkle_proof(&blob, index).await {
                    Ok((chunk, path, size)) => json!({
                        "t": "mproof",
                        "rid": rid,
                        "chunk": base64::engine::general_purpose::STANDARD.encode(&chunk),
                        "path": path.iter().map(hex::encode).collect::<Vec<_>>(),
                        "size": size,
                    }),
                    Err(e) => json!({ "t": "err", "rid": rid, "error": format!("{e:#}") }),
                };
                out.send(text(msg)).await.ok();
            });
        }
        "rtc" => {
            let Some(rtc) = shared.rtc.clone() else {
                return reply_err(out, rid, "direct transfers are disabled on this node");
            };
            let out = out.clone();
            let sdp = v["sdp"].as_str().unwrap_or("").to_string();
            tokio::spawn(async move {
                let msg = match rtc.accept_offer(sdp).await {
                    Ok(answer) => json!({ "t": "rtc", "rid": rid, "sdp": answer }),
                    Err(e) => json!({ "t": "err", "rid": rid, "error": format!("{e:#}") }),
                };
                out.send(text(msg)).await.ok();
            });
        }
        "settings" => {
            let dir = shared.config().data_dir;
            let result: Result<()> = (|| {
                // "personalSite" is the wire name for the web view switch
                if let Some(on) = v["personalSite"].as_bool() {
                    Config::set_setting(&dir, "web_view", if on { "true" } else { "false" })?;
                }
                if let Some(gb) = v["maxStorageGb"].as_f64() {
                    Config::set_setting(&dir, "max_storage_gb", &gb.to_string())?;
                }
                if let Some(gb) = v["reserveFreeGb"].as_f64() {
                    Config::set_setting(&dir, "reserve_free_gb", &gb.to_string())?;
                }
                if let Some(on) = v["autoUpdate"].as_bool() {
                    Config::set_setting(&dir, "auto_update", if on { "true" } else { "false" })?;
                }
                if let Some(name) = v["name"].as_str() {
                    Config::set_setting(&dir, "name", name)?;
                }
                Ok(())
            })();
            shared.reload_config();
            let msg = match result {
                Ok(()) => json!({ "t": "ok", "rid": rid }),
                Err(e) => json!({ "t": "err", "rid": rid, "error": format!("{e:#}") }),
            };
            out.send(text(msg)).await.ok();
            if let Ok(s) = shared.signed_status() {
                out.send(text(s)).await.ok();
            }
        }
        "update" => {
            let shared = Arc::clone(shared);
            let out = out.clone();
            tokio::spawn(async move {
                let msg = match update::update_now(&shared).await {
                    Ok(v) => json!({ "t": "ok", "rid": rid, "installing": v, "current": VERSION }),
                    Err(e) => json!({ "t": "err", "rid": rid, "error": format!("{e:#}") }),
                };
                out.send(text(msg)).await.ok();
                if let Ok(s) = shared.signed_status() {
                    out.send(text(s)).await.ok();
                }
            });
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_urls() {
        assert_eq!(
            ws_url("https://api.forester.dev/share").unwrap(),
            "wss://api.forester.dev/share/v1/nodes/connect"
        );
        assert_eq!(
            ws_url("http://forester-edge:8092").unwrap(),
            "ws://forester-edge:8092/share/v1/nodes/connect"
        );
    }
}
