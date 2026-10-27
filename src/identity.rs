//! Node identity (Ed25519) and small persisted state such as the pinned control-plane key.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct Identity {
    key: SigningKey,
    pub node_id: String,
    pub public_key_b64: String,
}

impl Identity {
    /// Loads `identity.key`, creating a fresh key pair on first run.
    pub fn load_or_create(data_dir: &Path) -> Result<Identity> {
        let path = data_dir.join("identity.key");
        let seed: [u8; 32] = if path.exists() {
            let hex_seed = std::fs::read_to_string(&path)?;
            hex::decode(hex_seed.trim())
                .ok()
                .and_then(|b| b.try_into().ok())
                .context("identity.key is corrupt")?
        } else {
            let seed: [u8; 32] = rand::random();
            write_private(&path, hex::encode(seed).as_bytes())?;
            seed
        };
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        Ok(Identity {
            node_id: node_id_for(&public),
            public_key_b64: URL_SAFE_NO_PAD.encode(public),
            key,
        })
    }

    pub fn sign_b64(&self, message: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.key.sign(message).to_bytes())
    }
}

/// `fn_` + first 24 hex chars of sha256(public key). The CP recomputes this, so it can't be spoofed.
pub fn node_id_for(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!("fn_{}", &hex::encode(digest)[..24])
}

pub fn parse_public_key(b64: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .context("bad public key encoding")?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

pub fn verify_b64(key: &VerifyingKey, message: &[u8], sig_b64: &str) -> Result<()> {
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).context("bad signature encoding")?;
    let sig = Signature::from_slice(&sig_bytes).context("bad signature length")?;
    if key.verify(message, &sig).is_err() {
        bail!("signature does not verify");
    }
    Ok(())
}

fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Small persisted facts learned from the control plane.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NodeState {
    /// Control-plane signing key, pinned on first connect.
    pub cp_public_key: Option<String>,
    pub claimed: bool,
    pub pairing_code: Option<String>,
}

impl NodeState {
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("state.json")
    }

    pub fn load(data_dir: &Path) -> NodeState {
        std::fs::read_to_string(Self::path(data_dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, data_dir: &Path) -> Result<()> {
        write_private(&Self::path(data_dir), &serde_json::to_vec_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_and_signatures_verify() {
        let dir = std::env::temp_dir().join(format!("fn-id-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = Identity::load_or_create(&dir).unwrap();
        let b = Identity::load_or_create(&dir).unwrap();
        assert_eq!(a.node_id, b.node_id, "identity must persist across restarts");
        assert!(a.node_id.starts_with("fn_") && a.node_id.len() == 27);

        let pk = parse_public_key(&a.public_key_b64).unwrap();
        let sig = a.sign_b64(b"hello");
        verify_b64(&pk, b"hello", &sig).unwrap();
        assert!(verify_b64(&pk, b"tampered", &sig).is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
