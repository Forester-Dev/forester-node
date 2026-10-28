//! Encrypted blob store. Blobs are opaque ciphertext named by random ids; the node never
//! learns what they contain. Writes are crash-safe: data lands in `tmp/`, is size- and
//! hash-checked, fsynced, then atomically renamed into `blobs/xx/<id>`.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter};

/// Largest blob accepted. Segments are 4 MiB of plaintext plus a small crypto overhead.
pub const MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;

pub struct BlobStore {
    blobs: PathBuf,
    tmp: PathBuf,
    used: AtomicU64,
    count: AtomicU64,
}

pub fn valid_id(id: &str) -> bool {
    (16..=64).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl BlobStore {
    pub async fn open(data_dir: &Path) -> Result<Arc<BlobStore>> {
        let blobs = data_dir.join("blobs");
        let tmp = data_dir.join("tmp");
        fs::create_dir_all(&blobs).await?;
        // Leftovers from a crash mid-write are incomplete by definition
        let _ = fs::remove_dir_all(&tmp).await;
        fs::create_dir_all(&tmp).await?;

        let (mut used, mut count) = (0u64, 0u64);
        let mut shards = fs::read_dir(&blobs).await?;
        while let Some(shard) = shards.next_entry().await? {
            if !shard.file_type().await?.is_dir() {
                continue;
            }
            let mut entries = fs::read_dir(shard.path()).await?;
            while let Some(e) = entries.next_entry().await? {
                if let Ok(meta) = e.metadata().await
                    && meta.is_file() {
                        used += meta.len();
                        count += 1;
                    }
            }
        }
        Ok(Arc::new(BlobStore {
            blobs,
            tmp,
            used: AtomicU64::new(used),
            count: AtomicU64::new(count),
        }))
    }

    fn path(&self, id: &str) -> PathBuf {
        self.blobs.join(&id[..2]).join(id)
    }

    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub async fn begin_put(self: &Arc<Self>, id: &str, size: u64, sha256_hex: &str) -> Result<PutHandle> {
        if !valid_id(id) {
            bail!("invalid blob id");
        }
        if size == 0 || size > MAX_BLOB_BYTES {
            bail!("blob size out of range");
        }
        let expected: [u8; 32] = hex::decode(sha256_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .context("bad sha256")?;
        let tmp_path = self.tmp.join(format!("{id}.{}", rand::random::<u64>()));
        let file = File::create(&tmp_path).await?;
        Ok(PutHandle {
            store: Arc::clone(self),
            id: id.to_string(),
            tmp_path,
            writer: Some(BufWriter::with_capacity(1024 * 1024, file)),
            hasher: Sha256::new(),
            expected,
            size,
            written: 0,
        })
    }

    /// Opens a blob for streaming. Returns the file positioned at `offset` and the bytes to send.
    pub async fn open_range(&self, id: &str, offset: u64, length: Option<u64>) -> Result<(File, u64, u64)> {
        if !valid_id(id) {
            bail!("invalid blob id");
        }
        let mut file = File::open(self.path(id)).await.context("blob not found")?;
        let size = file.metadata().await?.len();
        if offset > size {
            bail!("offset beyond end of blob");
        }
        let len = length.unwrap_or(size - offset).min(size - offset);
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        Ok((file, size, len))
    }

    pub async fn delete(&self, id: &str) -> Result<bool> {
        if !valid_id(id) {
            bail!("invalid blob id");
        }
        let path = self.path(id);
        match fs::metadata(&path).await {
            Ok(meta) => {
                fs::remove_file(&path).await?;
                self.used.fetch_sub(meta.len(), Ordering::Relaxed);
                self.count.fetch_sub(1, Ordering::Relaxed);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    /// Proof of retrievability: only a node that really holds the bytes can answer.
    pub async fn proof(&self, id: &str, offset: u64, length: u64, nonce: &[u8]) -> Result<String> {
        let (mut file, _, len) = self.open_range(id, offset, Some(length)).await?;
        if len != length {
            bail!("challenge range beyond end of blob");
        }
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        let mut buf = vec![0u8; 256 * 1024];
        let mut remaining = len;
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = file.read(&mut buf[..want]).await?;
            if n == 0 {
                bail!("blob shorter than expected");
            }
            hasher.update(&buf[..n]);
            remaining -= n as u64;
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// Chunk `index` of a blob with its Merkle path, and the blob's size (see merkle.rs).
    pub async fn merkle_proof(&self, id: &str, index: u64) -> Result<(Vec<u8>, Vec<crate::merkle::Hash>, u64)> {
        let (mut file, size, _) = self.open_range(id, 0, None).await?;
        let mut data = Vec::with_capacity(size as usize);
        file.read_to_end(&mut data).await?;
        let proof = tokio::task::spawn_blocking(move || crate::merkle::prove(&data, index as usize)).await?;
        let (chunk, path) = proof.context("chunk index beyond end of blob")?;
        Ok((chunk, path, size))
    }
}

pub struct PutHandle {
    store: Arc<BlobStore>,
    id: String,
    tmp_path: PathBuf,
    writer: Option<BufWriter<File>>,
    hasher: Sha256,
    expected: [u8; 32],
    size: u64,
    written: u64,
}

impl PutHandle {
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.written += data.len() as u64;
        if self.written > self.size {
            bail!("more data than declared");
        }
        self.hasher.update(data);
        self.writer.as_mut().context("put already finished")?.write_all(data).await?;
        Ok(())
    }

    /// Verifies size and hash, makes the data durable, then publishes it atomically.
    pub async fn finish(mut self) -> Result<u64> {
        if self.written != self.size {
            bail!("size mismatch: got {} of {}", self.written, self.size);
        }
        let digest: [u8; 32] = std::mem::take(&mut self.hasher).finalize().into();
        if digest != self.expected {
            bail!("sha256 mismatch");
        }
        let mut writer = self.writer.take().context("put already finished")?;
        writer.flush().await?;
        let file = writer.into_inner();
        file.sync_all().await?;
        drop(file);

        let dest = self.store.path(&self.id);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).await?;
        }
        let replaced = fs::metadata(&dest).await.map(|m| m.len()).ok();
        fs::rename(&self.tmp_path, &dest).await?;
        match replaced {
            Some(old) => {
                self.store.used.fetch_sub(old, Ordering::Relaxed);
            }
            None => {
                self.store.count.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.store.used.fetch_add(self.size, Ordering::Relaxed);
        Ok(self.size)
    }
}

impl Drop for PutHandle {
    fn drop(&mut self) {
        // An abandoned or failed put leaves nothing behind
        if self.writer.is_some() {
            let _ = std::fs::remove_file(&self.tmp_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    #[tokio::test]
    async fn put_read_proof_delete_and_reject_corruption() {
        let dir = std::env::temp_dir().join(format!("fn-store-{}", rand::random::<u64>()));
        let store = BlobStore::open(&dir).await.unwrap();
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let id = "blob_abcdefghijklmnop";

        // Wrong hash is rejected and leaves nothing behind
        let mut bad = store.begin_put(id, data.len() as u64, &sha(b"other")).await.unwrap();
        bad.write(&data).await.unwrap();
        assert!(bad.finish().await.is_err());
        assert_eq!(store.used(), 0);
        assert_eq!(std::fs::read_dir(dir.join("tmp")).unwrap().count(), 0);

        let mut put = store.begin_put(id, data.len() as u64, &sha(&data)).await.unwrap();
        for chunk in data.chunks(65536) {
            put.write(chunk).await.unwrap();
        }
        assert_eq!(put.finish().await.unwrap(), data.len() as u64);
        assert_eq!((store.used(), store.count()), (data.len() as u64, 1));

        let (mut f, size, len) = store.open_range(id, 1000, Some(500)).await.unwrap();
        let mut buf = vec![0; len as usize];
        f.read_exact(&mut buf).await.unwrap();
        assert_eq!((size, &buf[..]), (data.len() as u64, &data[1000..1500]));

        let nonce = b"n0nce";
        let mut expect = Sha256::new();
        expect.update(nonce);
        expect.update(&data[4096..8192]);
        assert_eq!(store.proof(id, 4096, 4096, nonce).await.unwrap(), hex::encode(expect.finalize()));

        // Reopening rescans used bytes
        drop(store);
        let store = BlobStore::open(&dir).await.unwrap();
        assert_eq!(store.used(), data.len() as u64);
        assert!(store.delete(id).await.unwrap());
        assert_eq!((store.used(), store.count()), (0, 0));
        assert!(store.begin_put("../etc/passwd_xxxxxxxx", 10, &sha(b"x")).await.is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
