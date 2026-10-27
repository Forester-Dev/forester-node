//! Traffic counters: bytes this node received and served, through the control link and over
//! direct (browser and LAN) connections. Reported as running totals in the signed status; the
//! control plane turns them into rates and history. `boot` changes on every start, so a reset
//! counter is never mistaken for a negative delta.

use serde::Serialize;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

static LINK_IN: AtomicU64 = AtomicU64::new(0);
static LINK_OUT: AtomicU64 = AtomicU64::new(0);
static DIRECT_IN: AtomicU64 = AtomicU64::new(0);
static DIRECT_OUT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub enum Path {
    Link,
    Direct,
}

/// Bytes stored on this node (uploads to it).
pub fn received(path: Path, bytes: usize) {
    match path {
        Path::Link => &LINK_IN,
        Path::Direct => &DIRECT_IN,
    }
    .fetch_add(bytes as u64, Ordering::Relaxed);
}

/// Bytes served by this node (downloads from it).
pub fn served(path: Path, bytes: usize) {
    match path {
        Path::Link => &LINK_OUT,
        Path::Direct => &DIRECT_OUT,
    }
    .fetch_add(bytes as u64, Ordering::Relaxed);
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Traffic {
    pub boot: String,
    pub link_in: u64,
    pub link_out: u64,
    pub direct_in: u64,
    pub direct_out: u64,
}

pub fn snapshot() -> Traffic {
    static BOOT: OnceLock<String> = OnceLock::new();
    Traffic {
        boot: BOOT.get_or_init(|| format!("{:016x}", rand::random::<u64>())).clone(),
        link_in: LINK_IN.load(Ordering::Relaxed),
        link_out: LINK_OUT.load(Ordering::Relaxed),
        direct_in: DIRECT_IN.load(Ordering::Relaxed),
        direct_out: DIRECT_OUT.load(Ordering::Relaxed),
    }
}
