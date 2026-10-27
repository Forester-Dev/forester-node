//! forester-node: storage node for the Forester mesh.
//!
//! Keeps the owner's files first, lends the rest of the disk to the network, and only ever
//! stores encrypted blobs it cannot read. See PROTOCOL.md for the wire protocol.

mod cap;
mod config;
mod disk;
mod identity;
mod link;
mod meter;
mod rtc;
mod store;
mod stun;
mod update;
mod web;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use tracing::info;

#[derive(Parser)]
#[command(name = "forester-node", version, about = "Storage node for the Forester mesh")]
struct Cli {
    /// Where blobs, identity and config.toml live
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the node (default)
    Run,
    /// Show identity, linking status, settings and disk allocation
    Status,
    /// Print the code that links this node to your share.forester.dev account
    PairingCode,
    /// Change a setting in config.toml: name, max_storage_gb, reserve_free_gb, web_view, web_port, auto_update, rtc_port
    ConfigSet { key: String, value: String },
    /// Serve your own transfer site from this node, on your own domain (off by default)
    #[command(alias = "personal-site")]
    WebView {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,str0m=warn,is=warn".into()),
        )
        .with_target(false)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let data_dir = cli.data_dir.unwrap_or_else(config::default_data_dir);

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => run(data_dir).await,
        Command::Status => status(data_dir).await,
        Command::PairingCode => {
            let st = identity::NodeState::load(&data_dir);
            match (st.claimed, st.pairing_code) {
                (true, _) => println!("This node is already linked to an account."),
                (false, Some(code)) => println!("{code}"),
                (false, None) => println!("No code yet: start the node once so it can connect."),
            }
            Ok(())
        }
        Command::ConfigSet { key, value } => {
            config::Config::load(&data_dir)?;
            config::Config::set_setting(&data_dir, &key, &value)?;
            println!("{key} updated. A running node applies it within 30 seconds.");
            Ok(())
        }
        Command::WebView { state } => {
            let cfg = config::Config::load(&data_dir)?;
            let on = state == "on";
            config::Config::set_value(&data_dir, "web_view", if on { "true" } else { "false" })?;
            if on {
                println!(
                    "Web view on. A running node starts serving on port {} within 30 seconds: point your domain's \
                     reverse proxy or tunnel there, then add the domain on your Dashboard.",
                    cfg.web_port
                );
            } else {
                println!("Web view off. A running node stops serving within 30 seconds.");
            }
            Ok(())
        }
    }
}

async fn status(data_dir: PathBuf) -> Result<()> {
    let cfg = config::Config::load(&data_dir)?;
    let id = identity::Identity::load_or_create(&data_dir)?;
    let st = identity::NodeState::load(&data_dir);
    let store = store::BlobStore::open(&data_dir).await?;
    let d = disk::measure(&data_dir, store.used(), cfg.max_storage_bytes, cfg.reserve_free_bytes)?;
    let gb = |b: u64| b as f64 / (1024.0 * 1024.0 * 1024.0);
    println!("node id        {}", id.node_id);
    println!("name           {}", cfg.name);
    println!("linked         {}", if st.claimed { "yes" } else { "no" });
    if let (false, Some(code)) = (st.claimed, &st.pairing_code) {
        println!("pairing code   {code}");
    }
    println!("orchestrator   {}", cfg.orchestrator_url);
    println!("web view       {}", if cfg.web_view { format!("on, port {}", cfg.web_port) } else { "off".into() });
    println!("auto update    {}", if cfg.auto_update { "on" } else { "off" });
    println!("disk           {:.1} GB free of {:.1} GB", gb(d.disk_available), gb(d.disk_total));
    println!(
        "network share  {:.1} GB allocated, {:.1} GB used by {} blob(s)",
        gb(d.alloc_bytes),
        gb(d.used_bytes),
        store.count()
    );
    println!("data dir       {}", data_dir.display());
    Ok(())
}

async fn run(data_dir: PathBuf) -> Result<()> {
    // Becomes a newer signed build staged by a previous self-update, if there is one
    update::launch_staged(&data_dir);
    let cfg = config::Config::load(&data_dir)?;
    let identity = identity::Identity::load_or_create(&data_dir)?;
    let store = store::BlobStore::open(&data_dir).await?;
    let state = identity::NodeState::load(&data_dir);
    info!("forester-node {} starting as {}", link::VERSION, identity.node_id);
    info!("data dir {}, holding {} blob(s)", data_dir.display(), store.count());

    let rtc = rtc::try_spawn(cfg.rtc_port, cfg.announce_ips.clone()).await;
    let shared = Arc::new(link::Shared {
        config: RwLock::new(cfg),
        identity,
        store,
        state: Mutex::new(state),
        rtc,
    });
    let _ = link::SHARED.set(Arc::clone(&shared));

    tokio::spawn(update::run_forever(Arc::clone(&shared)));
    tokio::spawn(web::run_forever(Arc::clone(&shared)));
    tokio::select! {
        _ = link::run_forever(shared) => {}
        _ = shutdown_signal() => info!("shutting down"),
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
