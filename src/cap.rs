//! Capability tokens: short-lived permissions signed by the control plane. A node performs
//! an operation only when it carries a valid capability for exactly that operation.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use crate::identity::verify_b64;

#[derive(Debug, Deserialize)]
pub struct Capability {
    pub v: u8,
    pub op: String,
    pub node: String,
    pub blob: Option<String>,
    #[serde(default)]
    pub max: u64,
    pub exp: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Verifies `token` grants `op` on `blob` for this node. Returns the capability on success.
pub fn verify(
    token: &str,
    cp_key: &VerifyingKey,
    node_id: &str,
    op: &str,
    blob: Option<&str>,
) -> Result<Capability> {
    let (payload_b64, sig_b64) = token.split_once('.').context("malformed capability")?;
    let payload = URL_SAFE_NO_PAD.decode(payload_b64).context("malformed capability")?;
    verify_b64(cp_key, &payload, sig_b64).context("capability signature invalid")?;
    let cap: Capability = serde_json::from_slice(&payload).context("malformed capability")?;
    if cap.v != 1 {
        bail!("unsupported capability version");
    }
    if cap.node != node_id {
        bail!("capability is for another node");
    }
    if cap.op != op {
        bail!("capability does not allow {op}");
    }
    if cap.blob.as_deref() != blob {
        bail!("capability is for another blob");
    }
    if cap.exp < now_ms() {
        bail!("capability expired");
    }
    Ok(cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn token(key: &SigningKey, json: &str) -> String {
        let sig = key.sign(json.as_bytes()).to_bytes();
        format!("{}.{}", URL_SAFE_NO_PAD.encode(json), URL_SAFE_NO_PAD.encode(sig))
    }

    #[test]
    fn only_exact_valid_capabilities_pass() {
        let cp = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let pk = cp.verifying_key();
        let exp = now_ms() + 60_000;
        let ok = format!(r#"{{"v":1,"op":"get","node":"fn_a","blob":"b1","max":0,"exp":{exp}}}"#);

        assert!(verify(&token(&cp, &ok), &pk, "fn_a", "get", Some("b1")).is_ok());
        assert!(verify(&token(&other, &ok), &pk, "fn_a", "get", Some("b1")).is_err(), "forged signer");
        assert!(verify(&token(&cp, &ok), &pk, "fn_b", "get", Some("b1")).is_err(), "wrong node");
        assert!(verify(&token(&cp, &ok), &pk, "fn_a", "del", Some("b1")).is_err(), "wrong op");
        assert!(verify(&token(&cp, &ok), &pk, "fn_a", "get", Some("b2")).is_err(), "wrong blob");

        let expired = r#"{"v":1,"op":"get","node":"fn_a","blob":"b1","max":0,"exp":1}"#;
        assert!(verify(&token(&cp, expired), &pk, "fn_a", "get", Some("b1")).is_err(), "expired");

        // Tampering with the payload after signing breaks the signature
        let t = token(&cp, &ok);
        let tampered = t.replacen(&t[..4], "AAAA", 1);
        assert!(verify(&tampered, &pk, "fn_a", "get", Some("b1")).is_err());
    }
}
