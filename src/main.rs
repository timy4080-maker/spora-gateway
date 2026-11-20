use clap::{Parser, Subcommand};
use spora_core::now_ms;
use spora_gateway::{
    config::Config,
    fake::{Channel, step},
    network,
    store::Store,
};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(about = "Spora GATEWAY-01. Durable opaque-envelope gateway and local channel simulator.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
    Serve {
        #[arg(long)]
        manual_workers: bool,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        secrets: PathBuf,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "127.0.0.1:7790")]
        listen: SocketAddr,
    },
    Forward {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        secrets: PathBuf,
    },
    FakeStep {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to: PathBuf,
        #[arg(long)]
        reverse: bool,
        #[arg(long)]
        duplicate: bool,
        #[arg(long)]
        drop_ack: bool,
        #[arg(long)]
        disconnected: bool,
        #[arg(long)]
        limit: Option<usize>,
    },
    InstallRoute {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        handle: String,
        #[arg(long)]
        file: PathBuf,
    },
    Gc {
        #[arg(long)]
        dir: PathBuf,
    },
    Backup {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Resume {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        transfer: String,
    },
    Check {
        #[arg(long)]
        dir: PathBuf,
    },
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.command {
        Command::Init { dir, config } => {
            let c: Config = serde_json::from_slice(&std::fs::read(config)?)?;
            Store::init(&dir, &c)?;
        }
        Command::Serve {
            manual_workers,
            dir,
            secrets,
            cert,
            key,
            listen,
        } => network::serve(dir, secrets, listen, &cert, &key, manual_workers).await?,
        Command::Forward { dir, secrets } => {
            println!("{}", network::forward(&dir, &secrets).await?)
        }
        Command::FakeStep {
            from,
            to,
            reverse,
            duplicate,
            drop_ack,
            disconnected,
            limit,
        } => println!(
            "{}",
            serde_json::to_string(&step(
                &from,
                &to,
                &Channel {
                    reverse,
                    duplicate,
                    drop_ack,
                    disconnected,
                    limit
                },
                now_ms()
            )?)?
        ),
        Command::InstallRoute { dir, handle, file } => Store::open(&dir)?.install_route(
            &handle,
            serde_json::from_slice(&std::fs::read(file)?)?,
            now_ms(),
        )?,
        Command::Gc { dir } => Store::open(&dir)?.gc(now_ms())?,
        Command::Backup { dir, output } => Store::open(&dir)?.backup(&output)?,
        Command::Resume {
            dir,
            owner,
            transfer,
        } => println!(
            "{}",
            serde_json::to_string(&Store::open(&dir)?.resume(&owner, &transfer, now_ms())?)?
        ),
        Command::Check { dir } => println!(
            "{}",
            serde_json::json!({"gateway_id":Store::open(&dir)?.config.gateway_id,"custody":"ready"})
        ),
    }
    Ok(())
}
