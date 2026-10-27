//! Live disk accounting: how much this node may hold for the network right now.
//!
//! The owner's own files (anything else on the disk) always win. Capacity is recomputed
//! from real free space on every report, so it grows, shrinks and fills with the disk.

use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskReport {
    pub disk_total: u64,
    pub disk_available: u64,
    /// Bytes this node may hold for the network in total (used + still free).
    pub alloc_bytes: u64,
    pub used_bytes: u64,
}

impl DiskReport {
    pub fn free_for_network(&self) -> u64 {
        self.alloc_bytes.saturating_sub(self.used_bytes)
    }
}

/// `used` is what the blob store already holds; that space is already gone from `available`.
pub fn compute(
    disk_total: u64,
    disk_available: u64,
    used: u64,
    max_storage: Option<u64>,
    reserve: u64,
) -> DiskReport {
    // Everything the network could have: what it already holds plus what's free,
    // minus the owner's guaranteed headroom.
    let possible = used.saturating_add(disk_available).saturating_sub(reserve);
    let alloc = match max_storage {
        Some(max) => possible.min(max),
        None => possible,
    };
    DiskReport {
        disk_total,
        disk_available,
        alloc_bytes: alloc,
        used_bytes: used,
    }
}

pub fn measure(path: &Path, used: u64, max_storage: Option<u64>, reserve: u64) -> std::io::Result<DiskReport> {
    let st = fs4::statvfs(path)?;
    Ok(compute(st.total_space(), st.available_space(), used, max_storage, reserve))
}

/// Identifies the physical volume, so the CP never counts two nodes on one disk twice
/// and never places two copies of a blob on the same disk. Stable across containers
/// that share a host volume (same kernel boot id and device).
pub fn volume_fingerprint(path: &Path, override_id: Option<&str>) -> String {
    if let Some(id) = override_id {
        return hex::encode(Sha256::digest(format!("id:{id}")));
    }
    let total = fs4::statvfs(path).map(|s| s.total_space()).unwrap_or(0);
    let machine = machine_scope();
    let dev = device_id(path);
    hex::encode(Sha256::digest(format!("vol:{machine}:{dev}:{total}")))
}

#[cfg(target_os = "linux")]
fn machine_scope() -> String {
    // Shared by every container on the host, unlike hostname or machine-id
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn machine_scope() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default()
}

#[cfg(unix)]
fn device_id(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).map(|m| m.dev()).unwrap_or(0)
}

#[cfg(not(unix))]
fn device_id(path: &Path) -> u64 {
    // Windows: the drive letter identifies the volume on one machine
    path.components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().bytes().map(u64::from).sum())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn owner_files_shrink_capacity_and_reserve_is_kept() {
        // 1 TB disk, 300 GB free, node holds 100 GB, owner keeps 20 GB.
        let r = compute(1000 * GB, 300 * GB, 100 * GB, None, 20 * GB);
        assert_eq!(r.alloc_bytes, 380 * GB);
        assert_eq!(r.free_for_network(), 280 * GB);

        // Owner fills 250 GB more of their own files: the network's share shrinks.
        let r = compute(1000 * GB, 50 * GB, 100 * GB, None, 20 * GB);
        assert_eq!(r.free_for_network(), 30 * GB);

        // Disk nearly full: nothing free for the network, never negative.
        let r = compute(1000 * GB, 5 * GB, 100 * GB, None, 20 * GB);
        assert_eq!(r.free_for_network(), 0);
    }

    #[test]
    fn owner_cap_applies() {
        let r = compute(4000 * GB, 3000 * GB, 0, Some(500 * GB), 20 * GB);
        assert_eq!(r.alloc_bytes, 500 * GB);
    }
}
