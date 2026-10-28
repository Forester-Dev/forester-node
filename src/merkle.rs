//! Merkle proofs of storage.
//!
//! The control plane keeps one 32-byte root per blob and checks storage by asking for a random
//! 4 KiB chunk with its path to the root. Any chunk can be asked for any number of times, so
//! nothing has to be prepared per check and the control plane never needs the data again.
//!
//! Tree (PROTOCOL.md, "mproof"): chunk i is `blob[i*4096 .. (i+1)*4096]` (the last may be
//! shorter); leaf = sha256(0x00 || chunk); leaves are padded to a power of two with
//! sha256(0x02); parent = sha256(0x01 || left || right). The path lists the sibling at each
//! level, leaf level first.

use sha2::{Digest, Sha256};

pub const CHUNK: usize = 4096;
pub type Hash = [u8; 32];

pub fn leaf(chunk: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(chunk);
    h.finalize().into()
}

fn parent(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn empty() -> Hash {
    Sha256::digest([0x02]).into()
}

/// Number of chunks in a blob of `size` bytes (an empty blob is one empty chunk).
pub fn chunk_count(size: usize) -> usize {
    size.div_ceil(CHUNK).max(1)
}

/// The leaf level, padded to a power of two.
fn leaves(blob: &[u8]) -> Vec<Hash> {
    let n = chunk_count(blob.len());
    let mut level: Vec<Hash> = (0..n)
        .map(|i| leaf(&blob[(i * CHUNK).min(blob.len())..((i + 1) * CHUNK).min(blob.len())]))
        .collect();
    level.resize(n.next_power_of_two(), empty());
    level
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn root(blob: &[u8]) -> Hash {
    let mut level = leaves(blob);
    while level.len() > 1 {
        level = level.chunks(2).map(|p| parent(&p[0], &p[1])).collect();
    }
    level[0]
}

/// Chunk `index` and the sibling hashes from it up to the root.
pub fn prove(blob: &[u8], index: usize) -> Option<(Vec<u8>, Vec<Hash>)> {
    if index >= chunk_count(blob.len()) {
        return None;
    }
    let chunk = blob[(index * CHUNK).min(blob.len())..((index + 1) * CHUNK).min(blob.len())].to_vec();
    let mut level = leaves(blob);
    let mut path = Vec::new();
    let mut i = index;
    while level.len() > 1 {
        path.push(level[i ^ 1]);
        level = level.chunks(2).map(|p| parent(&p[0], &p[1])).collect();
        i /= 2;
    }
    Some((chunk, path))
}

/// Checks a proof against a root (the control plane's side, here for tests).
#[cfg_attr(not(test), allow(dead_code))]
pub fn verify(root_hash: &Hash, index: usize, chunk: &[u8], path: &[Hash]) -> bool {
    let mut h = leaf(chunk);
    let mut i = index;
    for sib in path {
        h = if i % 2 == 0 { parent(&h, sib) } else { parent(sib, &h) };
        i /= 2;
    }
    &h == root_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn every_chunk_proves_against_the_root() {
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 5 * CHUNK + 17, 64 * CHUNK] {
            let b = blob(len);
            let r = root(&b);
            for i in 0..chunk_count(len) {
                let (chunk, path) = prove(&b, i).unwrap();
                assert!(verify(&r, i, &chunk, &path), "len {len} chunk {i}");
            }
            assert!(prove(&b, chunk_count(len)).is_none());
        }
    }

    #[test]
    fn tampered_or_moved_chunks_fail() {
        let b = blob(9 * CHUNK + 100);
        let r = root(&b);
        let (mut chunk, path) = prove(&b, 3).unwrap();
        assert!(!verify(&r, 4, &chunk, &path), "a chunk proved at another index");
        chunk[0] ^= 1;
        assert!(!verify(&r, 3, &chunk, &path), "a changed chunk");
    }

    #[test]
    fn matches_the_control_plane() {
        // Same vector as the control plane's self-test (api/src/selftest.ts, Invariant 20)
        let b: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
        assert_eq!(hex::encode(root(&b)), CONTROL_PLANE_ROOT);
    }

    const CONTROL_PLANE_ROOT: &str = "ea3000fb88f221862001c721d02221d33a02f3265ee72eec981169a830d4e3bf";
}
