//! Direct browser <-> node transfers over WebRTC data channels (Phase C).
//!
//! Browsers reach the node peer to peer: on the same LAN the host candidates win and the
//! transfer runs at LAN speed; across the internet STUN-discovered addresses let typical
//! home NATs connect directly. The CP only relays the SDP; data never passes through it.
//!
//! One task owns every UDP socket and every `Rtc`, following str0m's rule that each
//! mutation is followed by a full drain of `poll_output`.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use str0m::change::SdpOffer;
use str0m::channel::ChannelId;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::link;
use crate::{cap, stun};

const MAX_SESSIONS: usize = 512;
const CHUNK: usize = 64 * 1024;
const GET_WINDOW_CHUNKS: usize = 32; // 2 MiB in flight per download
// str0m defaults to 128 KiB in flight per session, about 2.6 MB/s at 50 ms RTT. 8 MiB keeps
// long, fast paths full. The low-water signal must sit below the cap or it never fires.
const SCTP_SEND_BUFFER: usize = 8 * 1024 * 1024;
const BUFFERED_LOW: usize = 1024 * 1024;
const IDLE_SESSION: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct RtcHandle {
    cmd: mpsc::Sender<Cmd>,
    port: u16,
    candidates: Arc<RwLock<Vec<String>>>,
}

impl RtcHandle {
    pub fn describe(&self) -> Value {
        json!({ "port": self.port, "candidates": *self.candidates.read().unwrap() })
    }

    pub async fn accept_offer(&self, sdp: String) -> Result<String> {
        let (tx, rx) = oneshot::channel();
        self.cmd.send(Cmd::Offer { sdp, reply: tx }).await.context("rtc engine stopped")?;
        tokio::time::timeout(Duration::from_secs(10), rx).await.context("rtc engine busy")??
    }
}

enum Cmd {
    Offer { sdp: String, reply: oneshot::Sender<Result<String>> },
}

/// Work finished by spawned tasks that must be applied inside the engine loop.
enum Done {
    Text { session: u64, chan: ChannelId, msg: Value },
    Chunk { session: u64, chan: ChannelId, data: Bytes, permit: tokio::sync::OwnedSemaphorePermit },
    Finished { session: u64, chan: ChannelId, msg: Value },
}

struct Packet {
    source: SocketAddr,
    destination: SocketAddr,
    data: Vec<u8>,
}

#[derive(Default)]
struct Chan {
    put: Option<mpsc::UnboundedSender<Bytes>>,
    /// Outgoing items for an active download, in order. `None` data means a text message.
    queue: VecDeque<(Option<Bytes>, Option<Value>, Option<tokio::sync::OwnedSemaphorePermit>)>,
}

struct Session {
    id: u64,
    rtc: Rtc,
    next_timeout: Instant,
    last_activity: Instant,
    chans: HashMap<ChannelId, Chan>,
}

struct Socket {
    local: SocketAddr,
    sock: Arc<UdpSocket>,
}

fn local_ipv4s() -> Vec<IpAddr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback() && i.ip().is_ipv4())
        .map(|i| i.ip())
        .collect()
}

/// Binds one UDP socket per local IPv4 address and starts the engine.
pub async fn spawn(port: u16, announce: Vec<IpAddr>) -> Result<RtcHandle> {
    let ips = local_ipv4s();
    if ips.is_empty() {
        bail!("no usable network interface for direct transfers");
    }
    let mut sockets = Vec::new();
    let mut chosen_port = port;
    for ip in &ips {
        let sock = match UdpSocket::bind(SocketAddr::new(*ip, chosen_port)).await {
            Ok(s) => s,
            Err(e) if chosen_port != 0 && sockets.is_empty() => {
                return Err(e).context(format!("binding UDP port {chosen_port}"));
            }
            Err(_) => UdpSocket::bind(SocketAddr::new(*ip, 0)).await?,
        };
        let local = sock.local_addr()?;
        if chosen_port == 0 {
            chosen_port = local.port();
        }
        sockets.push(Socket { local, sock: Arc::new(sock) });
    }

    // Base candidates: every interface, plus announced addresses mapped onto the first socket
    // (Docker port publishing behaves like a 1:1 NAT, so they are server-reflexive).
    let mut candidates: Vec<Candidate> = Vec::new();
    for s in &sockets {
        candidates.push(Candidate::host(s.local, "udp")?);
    }
    for ip in announce {
        if ip.is_ipv4() {
            let addr = SocketAddr::new(ip, chosen_port);
            candidates.push(Candidate::server_reflexive(addr, sockets[0].local, "udp")?);
        }
    }

    let described = Arc::new(RwLock::new(
        candidates.iter().map(|c| c.addr().to_string()).collect::<Vec<_>>(),
    ));
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let handle = RtcHandle { cmd: cmd_tx, port: chosen_port, candidates: Arc::clone(&described) };

    let (pkt_tx, pkt_rx) = mpsc::channel::<Packet>(4096);
    for s in &sockets {
        let sock = Arc::clone(&s.sock);
        let local = s.local;
        let tx = pkt_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, source)) => {
                        let pkt = Packet { source, destination: local, data: buf[..n].to_vec() };
                        if tx.send(pkt).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => debug!("udp recv: {e}"),
                }
            }
        });
    }

    info!(
        "direct transfers enabled on UDP {chosen_port} ({} candidate(s))",
        candidates.len()
    );
    let engine = Engine {
        sockets,
        candidates,
        described,
        sessions: Vec::new(),
        next_id: 1,
        stun_pending: HashMap::new(),
    };
    tokio::spawn(engine.run(cmd_rx, pkt_rx));
    Ok(handle)
}

struct Engine {
    sockets: Vec<Socket>,
    candidates: Vec<Candidate>,
    described: Arc<RwLock<Vec<String>>>,
    sessions: Vec<Session>,
    next_id: u64,
    /// Outstanding STUN transactions -> local socket base
    stun_pending: HashMap<[u8; 12], SocketAddr>,
}

impl Engine {
    async fn run(mut self, mut cmd_rx: mpsc::Receiver<Cmd>, mut pkt_rx: mpsc::Receiver<Packet>) {
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<Done>();
        let mut stun_tick = tokio::time::interval(Duration::from_secs(300));

        loop {
            let deadline = self
                .sessions
                .iter()
                .map(|s| s.next_timeout)
                .min()
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(1));
            let sleep = tokio::time::sleep_until(deadline.into());

            tokio::select! {
                Some(pkt) = pkt_rx.recv() => self.on_packet(pkt, &done_tx).await,
                Some(cmd) = cmd_rx.recv() => match cmd {
                    Cmd::Offer { sdp, reply } => {
                        let _ = reply.send(self.on_offer(&sdp, &done_tx).await);
                    }
                },
                Some(done) = done_rx.recv() => self.on_done(done, &done_tx).await,
                _ = stun_tick.tick() => self.send_stun().await,
                _ = sleep => {
                    let now = Instant::now();
                    for i in 0..self.sessions.len() {
                        if self.sessions[i].next_timeout <= now {
                            let _ = self.sessions[i].rtc.handle_input(Input::Timeout(now));
                            self.drain(i, &done_tx).await;
                        }
                    }
                    self.reap();
                }
            }
        }
    }

    async fn send_stun(&mut self) {
        self.stun_pending.clear();
        for s in &self.sockets {
            for server in stun::SERVERS {
                let Ok(mut addrs) = tokio::net::lookup_host(server).await else { continue };
                let Some(addr) = addrs.find(|a| a.is_ipv4()) else { continue };
                let txid: [u8; 12] = rand::random();
                self.stun_pending.insert(txid, s.local);
                let _ = s.sock.send_to(&stun::binding_request(&txid), addr).await;
            }
        }
    }

    async fn on_packet(&mut self, pkt: Packet, done_tx: &mpsc::UnboundedSender<Done>) {
        // Our own STUN responses never reach an Rtc
        if pkt.data.len() >= 20 && pkt.data[0..2] == [0x01, 0x01]
            && let Ok(txid) = <[u8; 12]>::try_from(&pkt.data[8..20])
                && let Some(base) = self.stun_pending.remove(&txid) {
                    if let Some(mapped) = stun::parse_response(&pkt.data, &txid) {
                        self.add_srflx(mapped, base);
                    }
                    return;
                }
        let Ok(contents) = pkt.data.as_slice().try_into() else { return };
        let input = Input::Receive(
            Instant::now(),
            Receive { proto: Protocol::Udp, source: pkt.source, destination: pkt.destination, contents },
        );
        if let Some(i) = self.sessions.iter().position(|s| s.rtc.accepts(&input)) {
            self.sessions[i].last_activity = Instant::now();
            if let Err(e) = self.sessions[i].rtc.handle_input(input) {
                debug!("rtc input: {e}");
            }
            self.drain(i, done_tx).await;
            // Incoming acks free send buffer: resume any queued downloads right away
            if self.pump_all(i) {
                self.drain(i, done_tx).await;
            }
        }
    }

    fn add_srflx(&mut self, mapped: SocketAddr, base: SocketAddr) {
        if self.candidates.iter().any(|c| c.addr() == mapped) {
            return;
        }
        if let Ok(c) = Candidate::server_reflexive(mapped, base, "udp") {
            info!("public address for direct transfers: {mapped}");
            self.described.write().unwrap().push(mapped.to_string());
            self.candidates.push(c);
        }
    }

    async fn on_offer(&mut self, sdp: &str, done_tx: &mpsc::UnboundedSender<Done>) -> Result<String> {
        self.reap();
        if self.sessions.len() >= MAX_SESSIONS {
            bail!("node is at its direct-connection limit");
        }
        let offer = SdpOffer::from_sdp_string(sdp).context("bad SDP offer")?;
        let mut rtc = Rtc::builder()
            .set_sctp_max_buffered_amount(SCTP_SEND_BUFFER)
            .build(Instant::now());
        for c in &self.candidates {
            rtc.add_local_candidate(c.clone());
        }
        let answer = rtc.sdp_api().accept_offer(offer).context("offer rejected")?;
        let id = self.next_id;
        self.next_id += 1;
        self.sessions.push(Session {
            id,
            rtc,
            next_timeout: Instant::now(),
            last_activity: Instant::now(),
            chans: HashMap::new(),
        });
        let i = self.sessions.len() - 1;
        self.drain(i, done_tx).await;
        Ok(answer.to_sdp_string())
    }

    fn reap(&mut self) {
        let now = Instant::now();
        self.sessions
            .retain(|s| s.rtc.is_alive() && now.duration_since(s.last_activity) < IDLE_SESSION);
    }

    async fn on_done(&mut self, done: Done, done_tx: &mpsc::UnboundedSender<Done>) {
        let (sid, chan) = match &done {
            Done::Text { session, chan, .. }
            | Done::Chunk { session, chan, .. }
            | Done::Finished { session, chan, .. } => (*session, *chan),
        };
        let Some(i) = self.sessions.iter().position(|s| s.id == sid) else { return };
        let entry = self.sessions[i].chans.entry(chan).or_default();
        match done {
            Done::Text { msg, .. } => entry.queue.push_back((None, Some(msg), None)),
            Done::Finished { msg, .. } => entry.queue.push_back((None, Some(msg), None)),
            Done::Chunk { data, permit, .. } => entry.queue.push_back((Some(data), None, Some(permit))),
        }
        self.pump(i, chan);
        self.drain(i, done_tx).await;
    }

    /// Pumps every channel with queued data; returns whether anything may have been written.
    fn pump_all(&mut self, i: usize) -> bool {
        let busy: Vec<ChannelId> = self.sessions[i]
            .chans
            .iter()
            .filter(|(_, c)| !c.queue.is_empty())
            .map(|(id, _)| *id)
            .collect();
        for cid in &busy {
            self.pump(i, *cid);
        }
        !busy.is_empty()
    }

    /// Writes queued items while the SCTP buffer has room; resumes on BufferedAmountLow.
    fn pump(&mut self, i: usize, chan: ChannelId) {
        let session = &mut self.sessions[i];
        let Some(state) = session.chans.get_mut(&chan) else { return };
        let Some(mut ch) = session.rtc.channel(chan) else { return };
        while let Some((data, text, _)) = state.queue.front() {
            let accepted = match (data, text) {
                (Some(d), _) => ch.write(true, d).unwrap_or(false),
                (None, Some(t)) => ch.write(false, t.to_string().as_bytes()).unwrap_or(false),
                _ => true,
            };
            if !accepted {
                break;
            }
            // Dropping the permit lets the reader task fetch the next chunk
            state.queue.pop_front();
        }
    }

    async fn drain(&mut self, i: usize, done_tx: &mpsc::UnboundedSender<Done>) {
        loop {
            let out = match self.sessions[i].rtc.poll_output() {
                Ok(o) => o,
                Err(e) => {
                    debug!("rtc poll: {e}");
                    self.sessions[i].rtc.disconnect();
                    return;
                }
            };
            match out {
                Output::Timeout(t) => {
                    self.sessions[i].next_timeout = t;
                    return;
                }
                Output::Transmit(t) => {
                    if let Some(s) = self.sockets.iter().find(|s| s.local == t.source) {
                        let _ = s.sock.try_send_to(&t.contents, t.destination);
                    } else if let Some(s) = self.sockets.first() {
                        let _ = s.sock.try_send_to(&t.contents, t.destination);
                    }
                }
                Output::Event(e) => self.on_event(i, e, done_tx),
            }
        }
    }

    fn on_event(&mut self, i: usize, e: Event, done_tx: &mpsc::UnboundedSender<Done>) {
        let sid = self.sessions[i].id;
        match e {
            Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                self.sessions[i].rtc.disconnect();
            }
            Event::ChannelOpen(cid, _label) => {
                if let Some(mut ch) = self.sessions[i].rtc.channel(cid) {
                    ch.set_buffered_amount_low_threshold(BUFFERED_LOW);
                }
                self.sessions[i].chans.entry(cid).or_default();
            }
            Event::ChannelClose(cid) => {
                self.sessions[i].chans.remove(&cid);
            }
            Event::ChannelBufferedAmountLow(cid) => self.pump(i, cid),
            Event::ChannelData(d) => {
                self.sessions[i].last_activity = Instant::now();
                if d.binary {
                    if let Some(tx) = self.sessions[i].chans.get(&d.id).and_then(|c| c.put.as_ref()) {
                        let _ = tx.send(Bytes::from(d.data));
                    }
                } else if let Ok(v) = serde_json::from_slice::<Value>(&d.data) {
                    self.on_request(i, sid, d.id, v, done_tx);
                    self.pump(i, d.id);
                }
            }
            _ => {}
        }
    }

    fn on_request(&mut self, i: usize, sid: u64, chan: ChannelId, v: Value, done_tx: &mpsc::UnboundedSender<Done>) {
        let id = v["id"].clone();
        let op = v["op"].as_str().unwrap_or("");
        let reply_err = |state: &mut Chan, error: String| {
            state.queue.push_back((None, Some(json!({ "id": id, "error": error })), None));
        };
        let state = self.sessions[i].chans.entry(chan).or_default();

        if op == "end" {
            state.put = None; // closes the writer, which then finishes and replies
            return;
        }
        let Some(shared) = link::SHARED.get() else {
            return reply_err(state, "node not ready".into());
        };
        let Some(cp_key) = shared.cp_key() else {
            return reply_err(state, "no pinned control plane key".into());
        };
        let blob = v["blob"].as_str().unwrap_or("").to_string();
        let token = v["cap"].as_str().unwrap_or("");
        let capability = match cap::verify(token, &cp_key, &shared.identity.node_id, op, Some(&blob)) {
            Ok(c) => c,
            Err(e) => return reply_err(state, format!("{e:#}")),
        };

        // Held for the whole transfer so a self-update waits for it
        let Some(guard) = crate::update::begin_op() else {
            return reply_err(state, "node_restarting".into());
        };

        match op {
            "put" => {
                let size = v["size"].as_u64().unwrap_or(0);
                let sha = v["sha256"].as_str().unwrap_or("").to_string();
                if size > capability.max {
                    return reply_err(state, "size exceeds capability".into());
                }
                match shared.disk_report() {
                    Ok(d) if d.free_for_network() >= size => {}
                    _ => return reply_err(state, "insufficient_capacity".into()),
                }
                let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
                state.put = Some(tx);
                let store = Arc::clone(&shared.store);
                let done_tx = done_tx.clone();
                tokio::spawn(async move {
                    let _guard = guard;
                    let result: Result<u64> = async {
                        let mut h = store.begin_put(&blob, size, &sha).await?;
                        while let Some(chunk) = rx.recv().await {
                            h.write(&chunk).await?;
                            crate::meter::received(crate::meter::Path::Direct, chunk.len());
                        }
                        h.finish().await
                    }
                    .await;
                    let msg = match result {
                        Ok(bytes) => json!({ "id": id, "ok": true, "bytes": bytes }),
                        Err(e) => json!({ "id": id, "error": format!("{e:#}") }),
                    };
                    let _ = done_tx.send(Done::Text { session: sid, chan, msg });
                });
            }
            "get" => {
                let offset = v["offset"].as_u64().unwrap_or(0);
                let length = v["length"].as_u64();
                let store = Arc::clone(&shared.store);
                let done_tx = done_tx.clone();
                tokio::spawn(async move {
                    let _guard = guard;
                    let window = Arc::new(Semaphore::new(GET_WINDOW_CHUNKS));
                    let result: Result<()> = async {
                        let (mut file, size, mut remaining) = store.open_range(&blob, offset, length).await?;
                        let _ = done_tx.send(Done::Text {
                            session: sid,
                            chan,
                            msg: json!({ "id": id, "size": size, "length": remaining }),
                        });
                        while remaining > 0 {
                            let permit = Arc::clone(&window).acquire_owned().await?;
                            let want = remaining.min(CHUNK as u64) as usize;
                            let mut buf = vec![0u8; want];
                            file.read_exact(&mut buf).await?;
                            remaining -= want as u64;
                            crate::meter::served(crate::meter::Path::Direct, want);
                            if done_tx.send(Done::Chunk { session: sid, chan, data: Bytes::from(buf), permit }).is_err() {
                                break;
                            }
                        }
                        Ok(())
                    }
                    .await;
                    let msg = match result {
                        Ok(()) => json!({ "id": id, "done": true }),
                        Err(e) => json!({ "id": id, "error": format!("{e:#}") }),
                    };
                    let _ = done_tx.send(Done::Finished { session: sid, chan, msg });
                });
            }
            _ => reply_err(state, format!("unsupported op {op}")),
        }
    }
}

/// Starts direct transfers, or logs why not without taking the node down.
pub async fn try_spawn(port: u16, announce: Vec<IpAddr>) -> Option<RtcHandle> {
    match spawn(port, announce).await {
        Ok(h) => Some(h),
        Err(e) => {
            warn!("direct transfers unavailable: {e:#}");
            None
        }
    }
}
