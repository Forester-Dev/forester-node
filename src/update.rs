//! Signed self-updates.
//!
//! Releases are described by `release.json`: a payload signed with Forester's release key,
//! whose public half is compiled in below. The node downloads the binary for its platform
//! into `<data_dir>/bin`, checks its size, SHA-256 and that it runs, then drains in-flight
//! transfers and execs it in place. The process id stays the same, so systemd and Docker
//! never see a restart. The original binary stays untouched: on every start it re-verifies
//! the staged one against the signed manifest and execs it only if it is newer. A staged
//! build that fails to stay up three times in a row is discarded and that version skipped.

use anyhow::{Context, Result, bail, ensure};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use crate::identity::{parse_public_key, verify_b64};
use crate::link::{Shared, VERSION, now_ms};

/// Public half of the Forester release signing key (Ed25519, base64url).
pub const RELEASE_KEY: &str = "r5eugkgTGHS7QrYm-ALvMcFzAlR9fRDBtFq3qbJUD4M";
pub const DEFAULT_MANIFEST_URL: &str = "https://share.forester.dev/node/release.json";

const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(120);
const HEALTHY_AFTER: Duration = Duration::from_secs(120);
const MAX_ATTEMPTS: u32 = 3;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const STAGED_ENV: &str = "FORESTER_STAGED";

#[derive(Debug, Deserialize)]
struct Envelope {
    payload: String,
    sig: String,
}

#[derive(Debug, Deserialize)]
pub struct Release {
    pub v: u8,
    pub version: String,
    pub artifacts: HashMap<String, Artifact>,
}

#[derive(Debug, Deserialize)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

/// What the node reports about updates in its signed status.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    pub latest: Option<String>,
    pub checked_at: Option<u64>,
    pub error: Option<String>,
    /// idle, downloading or restarting
    pub state: &'static str,
}

static STATUS: Mutex<UpdateStatus> = Mutex::new(UpdateStatus {
    latest: None,
    checked_at: None,
    error: None,
    state: "idle",
});
static BUSY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static LAUNCHER: OnceLock<PathBuf> = OnceLock::new();

pub fn status() -> UpdateStatus {
    STATUS.lock().unwrap().clone()
}

fn set_state(state: &'static str) {
    STATUS.lock().unwrap().state = state;
}

pub fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Self-update needs exec(), so it is available on Unix-like systems only.
pub fn supported() -> bool {
    cfg!(unix)
}

// ---- In-flight transfers, so a restart never cuts one off -------------------------------

static INFLIGHT: AtomicUsize = AtomicUsize::new(0);
static DRAINING: AtomicBool = AtomicBool::new(false);

/// Held by every transfer for its whole duration.
pub struct OpGuard(());

impl Drop for OpGuard {
    fn drop(&mut self) {
        INFLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Registers a transfer, or refuses it while the node is about to restart.
pub fn begin_op() -> Option<OpGuard> {
    if DRAINING.load(Ordering::SeqCst) {
        return None;
    }
    INFLIGHT.fetch_add(1, Ordering::SeqCst);
    Some(OpGuard(()))
}

// ---- Versions and manifests ----------------------------------------------------------------

fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let mut it = s.trim().trim_start_matches('v').split('.').map(|p| p.parse::<u64>().ok());
    let v = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(v)
}

/// True when `candidate` is a strictly higher version than `current`.
pub fn newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

/// Checks the release key's signature and parses the payload.
pub fn verify_manifest(raw: &[u8]) -> Result<Release> {
    let env: Envelope = serde_json::from_slice(raw).context("release manifest is not valid JSON")?;
    let key = parse_public_key(RELEASE_KEY)?;
    verify_b64(&key, env.payload.as_bytes(), &env.sig).context("release manifest signature invalid")?;
    let rel: Release = serde_json::from_str(&env.payload).context("release payload malformed")?;
    ensure!(rel.v == 1, "unsupported release manifest version {}", rel.v);
    ensure!(parse_version(&rel.version).is_some(), "release has a malformed version");
    Ok(rel)
}

fn bin_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("bin")
}

fn staged_exe(data_dir: &Path) -> PathBuf {
    bin_dir(data_dir).join("forester-node")
}

fn sha256_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn read_attempts(dir: &Path) -> u32 {
    std::fs::read_to_string(dir.join("attempts"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn skipped_version(dir: &Path) -> Option<String> {
    std::fs::read_to_string(dir.join("skip")).ok().map(|s| s.trim().to_string())
}

fn discard_staged(dir: &Path) {
    for f in ["forester-node", "release.json", "attempts"] {
        let _ = std::fs::remove_file(dir.join(f));
    }
}

// ---- Startup: run the staged build when it is newer ----------------------------------------

/// Called first thing by `run`. Execs the verified staged build if it is newer than this
/// binary; returns normally when there is nothing to launch (or launching failed).
pub fn launch_staged(data_dir: &Path) {
    if let Ok(exe) = std::env::current_exe() {
        let _ = LAUNCHER.set(exe);
    }
    if !supported() {
        return;
    }
    let dir = bin_dir(data_dir);
    let Ok(raw) = std::fs::read(dir.join("release.json")) else { return };
    let running_staged = std::env::var_os(STAGED_ENV).is_some();

    let rel = match verify_manifest(&raw) {
        Ok(r) => r,
        Err(e) => {
            warn!("discarding staged update: {e:#}");
            return discard_staged(&dir);
        }
    };
    if running_staged && rel.version == VERSION {
        // We are the staged build; count it healthy once it has stayed up for a while
        tokio::spawn({
            let dir = dir.clone();
            async move {
                tokio::time::sleep(HEALTHY_AFTER).await;
                let _ = std::fs::remove_file(dir.join("attempts"));
            }
        });
        return;
    }
    if !newer(&rel.version, VERSION) {
        // The installed binary has caught up (or passed) the staged one
        return discard_staged(&dir);
    }
    let attempts = read_attempts(&dir);
    if attempts >= MAX_ATTEMPTS {
        warn!("update {} failed to start {attempts} times; going back to {VERSION} and skipping it", rel.version);
        let _ = std::fs::write(dir.join("skip"), &rel.version);
        return discard_staged(&dir);
    }
    let exe = staged_exe(data_dir);
    let ok = rel
        .artifacts
        .get(&platform())
        .map(|a| sha256_file(&exe).map(|h| h == a.sha256).unwrap_or(false))
        .unwrap_or(false);
    if !ok {
        warn!("staged update {} does not match its signed checksum; discarding it", rel.version);
        return discard_staged(&dir);
    }
    let _ = std::fs::write(dir.join("attempts"), (attempts + 1).to_string());
    info!("starting forester-node {} (installed binary is {VERSION})", rel.version);
    exec(&exe);
}

#[cfg(unix)]
fn exec(exe: &Path) {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(STAGED_ENV, "1")
        .exec();
    warn!("could not start {}: {err}", exe.display());
}

#[cfg(not(unix))]
fn exec(_exe: &Path) {}

// ---- Checking, downloading and applying ----------------------------------------------------

pub fn client() -> Result<&'static reqwest::Client> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let c = reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .user_agent(format!("forester-node/{VERSION}"))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(15 * 60))
        .build()?;
    Ok(CLIENT.get_or_init(|| c))
}

fn manifest_url(shared: &Shared) -> String {
    shared.config().update_url.unwrap_or_else(|| DEFAULT_MANIFEST_URL.to_string())
}

/// Fetches and verifies the current release manifest. Returns it with its raw bytes.
async fn fetch_manifest(url: &str) -> Result<(Release, Vec<u8>)> {
    let res = client()?.get(url).send().await.context("fetching release manifest")?;
    ensure!(res.status().is_success(), "release manifest: HTTP {}", res.status());
    let raw = res.bytes().await?;
    ensure!(raw.len() <= MAX_MANIFEST_BYTES, "release manifest too large");
    Ok((verify_manifest(&raw)?, raw.to_vec()))
}

async fn check(shared: &Shared) -> Result<(Release, Vec<u8>)> {
    let result = fetch_manifest(&manifest_url(shared)).await;
    let mut st = STATUS.lock().unwrap();
    st.checked_at = Some(now_ms());
    match &result {
        Ok((rel, _)) => {
            st.latest = Some(rel.version.clone());
            st.error = None;
        }
        Err(e) => st.error = Some(format!("{e:#}")),
    }
    result
}

/// Downloads the release for this platform into `<data_dir>/bin` and proves it runs.
async fn stage(shared: &Shared, rel: &Release, raw: &[u8]) -> Result<()> {
    let data_dir = shared.config().data_dir;
    let dir = bin_dir(&data_dir);
    let art = rel
        .artifacts
        .get(&platform())
        .with_context(|| format!("release {} has no build for {}", rel.version, platform()))?;
    ensure!(art.size <= MAX_BINARY_BYTES, "release binary is unreasonably large");

    // Already staged and intact: nothing to download
    if let Ok(cur) = std::fs::read(dir.join("release.json")) {
        if verify_manifest(&cur).map(|r| r.version == rel.version).unwrap_or(false)
            && sha256_file(&staged_exe(&data_dir)).map(|h| h == art.sha256).unwrap_or(false)
        {
            return Ok(());
        }
    }

    tokio::fs::create_dir_all(&dir).await?;
    let url = url::Url::parse(&manifest_url(shared))?.join(&art.path)?;
    info!("downloading forester-node {} from {url}", rel.version);
    let tmp = dir.join("forester-node.download");
    let result: Result<()> = async {
        let res = client()?.get(url.as_str()).send().await?;
        ensure!(res.status().is_success(), "download: HTTP {}", res.status());
        let mut file = tokio::fs::File::create(&tmp).await?;
        let mut hasher = Sha256::new();
        let mut got = 0u64;
        let mut body = res.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            got += chunk.len() as u64;
            ensure!(got <= art.size, "download is larger than the release says");
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;
        drop(file);
        ensure!(got == art.size, "download is incomplete");
        ensure!(hex::encode(hasher.finalize()) == art.sha256, "download does not match the signed checksum");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        }
        // Prove it starts and is the version it claims to be before switching to it
        let out = tokio::time::timeout(
            Duration::from_secs(20),
            tokio::process::Command::new(&tmp).arg("--version").output(),
        )
        .await
        .context("new build did not answer --version")?
        .context("new build cannot run from the data directory")?;
        let printed = String::from_utf8_lossy(&out.stdout);
        ensure!(
            out.status.success() && printed.split_whitespace().last() == Some(rel.version.as_str()),
            "new build reports version {:?}, expected {}",
            printed.trim(),
            rel.version
        );
        Ok(())
    }
    .await;
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, staged_exe(&data_dir))?;
    let manifest_tmp = dir.join("release.json.tmp");
    std::fs::write(&manifest_tmp, raw)?;
    std::fs::rename(&manifest_tmp, dir.join("release.json"))?;
    let _ = std::fs::remove_file(dir.join("attempts"));
    let _ = std::fs::remove_file(dir.join("skip"));
    Ok(())
}

/// Lets in-flight transfers finish, refuses new ones, then becomes the new build.
async fn restart(shared: Arc<Shared>) {
    set_state("restarting");
    DRAINING.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    while INFLIGHT.load(Ordering::SeqCst) > 0 && started.elapsed() < DRAIN_TIMEOUT {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let left = INFLIGHT.load(Ordering::SeqCst);
    if left > 0 {
        warn!("{left} transfer(s) still running after {}s; restarting anyway", DRAIN_TIMEOUT.as_secs());
    }
    // Let the last replies flush to the control plane
    tokio::time::sleep(Duration::from_secs(1)).await;
    let data_dir = shared.config().data_dir;
    let target = if std::env::var_os(STAGED_ENV).is_some() {
        staged_exe(&data_dir)
    } else {
        match LAUNCHER.get() {
            Some(p) => p.clone(),
            None => staged_exe(&data_dir),
        }
    };
    info!("restarting into the new build");
    exec(&target);
    // exec failed: keep serving on the current build
    DRAINING.store(false, Ordering::SeqCst);
    set_state("idle");
    STATUS.lock().unwrap().error = Some("could not start the new build".into());
}

/// Checks for a release and, when it is newer, installs it. `forced` ignores the owner's
/// auto-update setting and a previously skipped version (an explicit "Update now").
async fn check_and_apply(shared: &Arc<Shared>, forced: bool) -> Result<Option<String>> {
    if !supported() {
        bail!("self-update is not available on this platform");
    }
    let _busy = BUSY.try_lock().map_err(|_| anyhow::anyhow!("an update is already in progress"))?;
    let (rel, raw) = check(shared).await?;
    if !newer(&rel.version, VERSION) {
        return Ok(None);
    }
    let dir = bin_dir(&shared.config().data_dir);
    if !forced {
        if !shared.config().auto_update {
            return Ok(None);
        }
        if skipped_version(&dir).as_deref() == Some(rel.version.as_str()) {
            return Ok(None);
        }
    }
    set_state("downloading");
    if let Err(e) = stage(shared, &rel, &raw).await {
        set_state("idle");
        STATUS.lock().unwrap().error = Some(format!("{e:#}"));
        return Err(e);
    }
    info!("forester-node {} is ready; switching over once transfers finish", rel.version);
    tokio::spawn(restart(Arc::clone(shared)));
    Ok(Some(rel.version))
}

/// Owner-requested update. Returns the version being installed, or None if up to date.
pub async fn update_now(shared: &Arc<Shared>) -> Result<Option<String>> {
    check_and_apply(shared, true).await
}

/// Background checks: shortly after start, then every six hours with jitter so the
/// network does not update all at once.
pub async fn run_forever(shared: Arc<Shared>) {
    if !supported() {
        return;
    }
    tokio::time::sleep(Duration::from_secs(60 + rand::random::<u64>() % 540)).await;
    loop {
        match check_and_apply(&shared, false).await {
            Ok(Some(v)) => info!("updating to {v}"),
            Ok(None) => {}
            Err(e) => warn!("update check failed: {e:#}"),
        }
        let jitter = Duration::from_secs(rand::random::<u64>() % 1800);
        tokio::time::sleep(CHECK_EVERY + jitter).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering() {
        assert!(newer("2.1.0", "2.0.9"));
        assert!(newer("10.0.0", "9.9.9"));
        assert!(!newer("2.0.0", "2.0.0"));
        assert!(!newer("1.9.9", "2.0.0"));
        assert!(!newer("2.1", "2.0.0"));
        assert!(!newer("2.1.0-beta", "2.0.0"));
    }

    #[test]
    fn manifest_requires_release_signature() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::{Signer, SigningKey};
        let payload = r#"{"v":1,"version":"9.9.9","artifacts":{}}"#;
        // Signed by some other key: must be refused
        let other = SigningKey::from_bytes(&[7u8; 32]);
        let sig = URL_SAFE_NO_PAD.encode(other.sign(payload.as_bytes()).to_bytes());
        let raw = serde_json::json!({ "payload": payload, "sig": sig }).to_string();
        assert!(verify_manifest(raw.as_bytes()).is_err());
        assert!(verify_manifest(b"not json").is_err());
    }
}
