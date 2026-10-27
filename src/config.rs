//! Node configuration: `config.toml` in the data directory, overridable by environment
//! variables (used by Docker and installers). Mutable settings are re-read while running,
//! so owners can change them without a restart.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const DEFAULT_ORCHESTRATOR: &str = "https://api.forester.dev/share";
const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

const DEFAULT_CONFIG_TOML: &str = r#"# forester-node configuration. Changes are picked up within 30 seconds.

# Display name shown to you on share.forester.dev
name = "My Forester Node"

# Most this node may use for the network, in GB. Leave unset to use free space automatically.
# max_storage_gb = 500

# Always keep at least this much disk free for yourself, in GB.
reserve_free_gb = 20

# Personal share site (yourname.forester.dev) served from this node. Off by default.
personal_site = false

# UDP port for direct browser and local-network transfers. 0 picks a free port.
rtc_port = 0

# Install signed updates automatically. Transfers in progress finish first.
auto_update = true

# Extra addresses to advertise for direct transfers, e.g. your LAN IP when running in Docker.
# announce_ips = ["192.168.1.20"]
"#;

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
struct FileConfig {
    orchestrator_url: Option<String>,
    name: Option<String>,
    max_storage_gb: Option<f64>,
    reserve_free_gb: Option<f64>,
    personal_site: Option<bool>,
    rtc_port: Option<u16>,
    announce_ips: Option<Vec<String>>,
    volume_id: Option<String>,
    auto_update: Option<bool>,
    update_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub orchestrator_url: String,
    pub name: String,
    /// Upper bound the owner set for network use; None means "use free space automatically".
    pub max_storage_bytes: Option<u64>,
    /// Space always left free for the owner.
    pub reserve_free_bytes: u64,
    pub personal_site: bool,
    pub rtc_port: u16,
    pub announce_ips: Vec<IpAddr>,
    pub volume_id: Option<String>,
    /// Install signed releases automatically (owners can always update from the Dashboard).
    pub auto_update: bool,
    /// Release manifest location; the official one when unset.
    pub update_url: Option<String>,
    /// Pins the control plane key instead of trusting it on first connect.
    pub cp_key_override: Option<String>,
    /// Settings fixed by environment variables; remote changes to these cannot take effect.
    pub env_locked: Vec<&'static str>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn env_any(names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| env(n))
}

pub fn default_data_dir() -> PathBuf {
    if let Some(d) = env_any(&["FORESTER_DATA_DIR", "DATA_DIR"]) {
        return PathBuf::from(d);
    }
    #[cfg(target_os = "windows")]
    {
        let base = env("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        return PathBuf::from(base).join("forester-node");
    }
    #[cfg(target_os = "macos")]
    {
        let home = env("HOME").unwrap_or_else(|| "/tmp".into());
        return PathBuf::from(home).join("Library/Application Support/forester-node");
    }
    #[allow(unreachable_code)]
    PathBuf::from("/var/lib/forester-node")
}

impl Config {
    pub fn config_path(data_dir: &Path) -> PathBuf {
        data_dir.join("config.toml")
    }

    pub fn load(data_dir: &Path) -> Result<Config> {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("creating data dir {}", data_dir.display()))?;
        let path = Self::config_path(data_dir);
        if !path.exists() {
            std::fs::write(&path, DEFAULT_CONFIG_TOML)
                .with_context(|| format!("writing {}", path.display()))?;
        }
        let raw = std::fs::read_to_string(&path)?;
        let file: FileConfig =
            toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;

        let gb = |v: f64| (v.max(0.0) * GIB) as u64;
        let orchestrator_url = env_any(&["FORESTER_ORCHESTRATOR_URL", "ORCHESTRATOR_URL"])
            .or(file.orchestrator_url)
            .unwrap_or_else(|| DEFAULT_ORCHESTRATOR.to_string());
        let name = env_any(&["FORESTER_NODE_NAME", "NODE_NAME"])
            .or(file.name)
            .unwrap_or_else(|| "Forester Node".into());
        let max_storage_bytes = env_any(&["FORESTER_MAX_STORAGE_GB", "MAX_STORAGE_GB"])
            .and_then(|v| v.parse::<f64>().ok())
            .or(file.max_storage_gb)
            .map(gb);
        let reserve_free_bytes = gb(env("FORESTER_RESERVE_FREE_GB")
            .and_then(|v| v.parse::<f64>().ok())
            .or(file.reserve_free_gb)
            .unwrap_or(20.0));
        let personal_site = env("FORESTER_PERSONAL_SITE")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "on" | "yes"))
            .or(file.personal_site)
            .unwrap_or(false);
        let rtc_port = env("FORESTER_RTC_PORT")
            .and_then(|v| v.parse().ok())
            .or(file.rtc_port)
            .unwrap_or(0);
        let announce_ips = env("FORESTER_ANNOUNCE_IPS")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .or(file.announce_ips)
            .unwrap_or_default()
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let auto_update = env("FORESTER_AUTO_UPDATE")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "on" | "yes"))
            .or(file.auto_update)
            .unwrap_or(true);
        let update_url = env("FORESTER_UPDATE_URL").or(file.update_url);
        let volume_id = env_any(&["FORESTER_VOLUME_ID", "VOLUME_ID"]).or(file.volume_id);

        let mut env_locked = Vec::new();
        if env_any(&["FORESTER_NODE_NAME", "NODE_NAME"]).is_some() { env_locked.push("name"); }
        if env_any(&["FORESTER_MAX_STORAGE_GB", "MAX_STORAGE_GB"]).is_some() { env_locked.push("maxStorageGb"); }
        if env("FORESTER_RESERVE_FREE_GB").is_some() { env_locked.push("reserveFreeGb"); }
        if env("FORESTER_PERSONAL_SITE").is_some() { env_locked.push("personalSite"); }
        if env("FORESTER_AUTO_UPDATE").is_some() { env_locked.push("autoUpdate"); }

        Ok(Config {
            data_dir: data_dir.to_path_buf(),
            orchestrator_url,
            name,
            max_storage_bytes,
            reserve_free_bytes,
            personal_site,
            rtc_port,
            announce_ips,
            volume_id,
            auto_update,
            update_url,
            cp_key_override: env("FORESTER_CP_KEY"),
            env_locked,
        })
    }

    /// Sets a known setting from user input, validating and quoting it for TOML.
    pub fn set_setting(data_dir: &Path, key: &str, value: &str) -> Result<()> {
        let toml_value = match key {
            "name" => {
                let v = value.trim();
                anyhow::ensure!(!v.is_empty() && v.len() <= 64, "name must be 1 to 64 characters");
                toml::Value::String(v.to_string()).to_string()
            }
            "max_storage_gb" | "reserve_free_gb" => {
                let n: f64 = value.trim().parse().context("expected a number of GB")?;
                anyhow::ensure!(n >= 0.0 && n < 1.0e7, "out of range");
                format!("{n}")
            }
            "personal_site" | "auto_update" => match value.trim() {
                "true" | "on" => "true".into(),
                "false" | "off" => "false".into(),
                _ => anyhow::bail!("expected on or off"),
            },
            "rtc_port" => format!("{}", value.trim().parse::<u16>().context("expected a port number")?),
            other => anyhow::bail!("unknown setting {other}"),
        };
        Self::set_value(data_dir, key, &toml_value)
    }

    /// Persists one setting into config.toml, keeping the owner's comments and other keys.
    pub fn set_value(data_dir: &Path, key: &str, value: &str) -> Result<()> {
        let path = Self::config_path(data_dir);
        let raw = std::fs::read_to_string(&path).unwrap_or_default();
        let mut out = String::new();
        let mut replaced = false;
        for line in raw.lines() {
            let trimmed = line.trim_start();
            let is_key = trimmed
                .strip_prefix(key)
                .map(|rest| rest.trim_start().starts_with('='))
                .unwrap_or(false);
            if is_key && !replaced {
                out.push_str(&format!("{key} = {value}\n"));
                replaced = true;
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        if !replaced {
            out.push_str(&format!("{key} = {value}\n"));
        }
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, out)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_keep_personal_site_off_and_round_trip_settings() {
        let dir = std::env::temp_dir().join(format!("fn-cfg-{}", rand::random::<u64>()));
        let cfg = Config::load(&dir).unwrap();
        assert!(!cfg.personal_site, "personal site must be off by default");
        assert_eq!(cfg.reserve_free_bytes, (20.0 * GIB) as u64);
        assert!(cfg.auto_update, "auto update is on by default");

        Config::set_value(&dir, "personal_site", "true").unwrap();
        Config::set_value(&dir, "max_storage_gb", "250").unwrap();
        let cfg = Config::load(&dir).unwrap();
        assert!(cfg.personal_site);
        assert_eq!(cfg.max_storage_bytes, Some((250.0 * GIB) as u64));
        // comments survive edits
        assert!(std::fs::read_to_string(Config::config_path(&dir)).unwrap().contains("# Display name"));
        std::fs::remove_dir_all(dir).ok();
    }
}
