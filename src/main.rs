mod journal;
mod local;
mod network;
mod secure;
mod transport;
use anyhow::{Context, Result};
use std::{env, fs, path::Path};
fn required(n: &str) -> Result<String> {
    env::var(n).with_context(|| format!("missing {n}"))
}
fn main() -> Result<()> {
    secure::harden_process()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}
async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let uid = unsafe { libc::geteuid() };
    let mut local = local::Local::new(
        required("AGENT_KURA_UID")?.parse()?,
        env::var("AGENT_ADMIN_UID")
            .ok()
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(uid),
    );
    local.enable_configuration_updates(
        match env::var("AGENT_KURA_CONFIGURATION_UPDATE").as_deref() {
            Err(env::VarError::NotPresent) | Ok("0") => false,
            Ok("1") => true,
            _ => anyhow::bail!("invalid AGENT_KURA_CONFIGURATION_UPDATE; expected 0 or 1"),
        },
    );
    let socket =
        env::var("AGENT_SOCKET").unwrap_or("/run/kura-management-agent/control.sock".into());
    let listener = local.listen(Path::new(&socket)).await?;
    let config = transport::Config {
        endpoint: required("AGENT_CONSOLE_ENDPOINT")?,
        gateway: required("AGENT_GATEWAY_ID")?,
        ca: required("AGENT_CA")?,
        cert: required("AGENT_CERT")?,
        key: required("AGENT_KEY")?,
        state: required("AGENT_STATE_DB")?,
        boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().into())
            .unwrap_or_else(|_| format!("process-{}", uuid::Uuid::new_v4())),
    };
    secure::prepare(Path::new(&config.key), Path::new(&config.state))?;
    let network = network::Network::open(
        "/".into(),
        Path::new(&config.state)
            .parent()
            .context("state directory")?
            .join("network"),
        env::var("AGENT_NETWORK_INTERFACES")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
    )?;
    if env::var("AGENT_NETWORK_ALLOW_VIRTUAL_FIXTURE").as_deref() == Ok("1") {
        network.allow_virtual_fixture();
    }
    if let Err(error) = network.recover().await {
        tracing::error!(%error,"network recovery requires operator attention; agent remains available");
    }
    local.network = Some(network.clone());
    let kura_delegation = env::var("AGENT_KURA_NETWORK_INTERFACES")
        .map(|value| {
            value
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .ok();
    local.delegate_kura_network(kura_delegation)?;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            if let Err(error) = network.expire().await {
                tracing::error!(%error,"network recovery requires attention");
            }
        }
    });
    tracing::info!(socket=%socket,"agent local control ready");
    tokio::select! {result=local.clone().serve(listener)=>result?,result=transport::run(config,local)=>result?,_=tokio::signal::ctrl_c()=>{}}
    Ok(())
}
