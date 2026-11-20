mod boot_control;
mod configuration_outcome;
mod controlled_startup;
mod core_validation;
mod durable;
mod enrollment;
mod firewall;
mod journal;
mod local;
mod native_state;
mod network;
mod nm;
mod ordinary_boot;
mod ordinary_observation;
mod process;
mod recovery;
mod remote;
mod runtime_identity;
mod secure;
mod source_inspection;
mod snapshot_validation;
mod system_change;
mod system_control;
mod transport;
use anyhow::{Context, Result, ensure};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
fn required(n: &str) -> Result<String> {
    env::var(n).with_context(|| format!("missing {n}"))
}
fn main() -> Result<()> {
    secure::harden_process()?;
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?
        .block_on(run())
}
async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("observe-original-nm-fence") {
        ensure!(args.len() == 3 && unsafe { libc::geteuid() } == 0,
            "FORBIDDEN: original Root fence observation requires Root and the original operation");
        println!("{}", nm::handover::observe_original_root_fence(&args[2])?);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.get(1).map(String::as_str) == Some("inspect-original-nm-continuity") {
        ensure!(args.len() == 3, "INVALID_ARGUMENT: original NM operation required");
        println!("{}", nm::handover::continuity::inspect(&args[2])?);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.get(1).map(String::as_str) == Some("review-original-nm-legacy-startup") {
        ensure!(args.len() == 3, "INVALID_ARGUMENT: original NM operation required");
        println!("{}", nm::handover::continuity::review_legacy_startup(&args[2]).await?);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.get(1).map(String::as_str) == Some("execute-original-nm-legacy-startup") {
        ensure!(args.len() == 4, "INVALID_ARGUMENT: original NM operation and fixed startup phase required");
        let phase: nm::handover::continuity::ExecutionPhase = args[3].parse()?;
        println!("{}", nm::handover::continuity::execute_legacy_startup(&args[2],phase).await?);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.get(1).map(String::as_str) == Some("seal-original-nm-startup-profile") {
        ensure!(args.len() == 6 && args[2] == "--operation-id" && args[4] == "--request",
            "INVALID_ARGUMENT: original operation and private startup profile request required");
        println!("{}", nm::handover::continuity::seal_startup(&args[3], args[5].clone().into())?);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.get(1).map(String::as_str) == Some("prepare-original-nm-upgrade") {
        ensure!(args.len() == 4 && unsafe { libc::geteuid() } == 0,
            "FORBIDDEN: Root requires an original operation and candidate Debian version");
        println!("{}", nm::handover::continuity::prepare_upgrade(&args[2], &args[3])?);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.get(1).map(String::as_str) == Some("check-original-nm-upgrade") {
        ensure!(args.len() == 5 && unsafe { libc::geteuid() } == 0,
            "FORBIDDEN: fixed Root Debian continuation phase required");
        println!("{}", nm::handover::continuity::check_upgrade(&args[2], &args[3], &args[4])?);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.get(1).map(String::as_str) == Some("original-firewall-observed-upgrade") {
        ensure!(unsafe { libc::geteuid() } == 0,
            "FORBIDDEN: original firewall package upgrade requires Root");
        println!("{}", nm::handover::continuity::observed_upgrade::run(&args[2..])?);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.get(1).map(String::as_str) == Some("publish-original-nm-fence") {
        ensure!(args.len() == 4, "INVALID_ARGUMENT: original operation and paired Agent PID required");
        println!("{}", nm::handover::publish_root_fence(&args[2], args[3].parse()?).await?);
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("inspect-retained-state") {
        ensure!(args.len() == 6 && args[2] == "--initialization-id" && args[4] == "--directory",
            "INVALID_ARGUMENT: fixed retained inspection requires original initialization and a Root-created copy");
        let report = source_inspection::run(Path::new(&args[5]), &args[3]).await?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("initialize-native-state") {
        ensure!(
            args.len() == 4 && args[2] == "--operation-id",
            "INVALID_ARGUMENT: fixed native initialization requires its original UUID"
        );
        native_state::initialize(&args[3]).await?;
        println!(
            "{}",
            serde_json::json!({"schemaVersion":1,"operationId":args[3],"stateCreated":true})
        );
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("firewall-restore-confirmed") {
        ensure!(args.len() == 2, "INVALID_ARGUMENT: confirmed firewall restore takes no arguments");
        println!("{}", firewall::restore_confirmed_boot()?);
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("firewall-restore-confirmed-status") {
        ensure!(args.len() == 2, "INVALID_ARGUMENT: original firewall restore status takes no arguments");
        println!("{}", firewall::observe_original_boot_restore()?);
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("firewall-restore-confirmed-acknowledge") {
        ensure!(args.len() == 2, "INVALID_ARGUMENT: original firewall restore acknowledgement takes no arguments");
        println!("{}", firewall::acknowledge_original_boot_restore()?);
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("firewall-restore-imported-review") {
        ensure!(args.len() == 2, "INVALID_ARGUMENT: imported firewall boot review takes no arguments");
        println!("{}", firewall::review_imported_boot_restore()?);
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("firewall-rebind-imported-boot") {
        ensure!(args.len() == 2, "INVALID_ARGUMENT: imported firewall boot rebind takes no arguments");
        println!("{}", firewall::rebind_imported_boot_restore()?);
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("ordinary-boot") {
        anyhow::ensure!(
            unsafe { libc::geteuid() } == 0,
            "FORBIDDEN: ordinary boot administration requires root"
        );
        let action = args.get(2).map(String::as_str).unwrap_or("");
        anyhow::ensure!(
            args.len() >= 5 && args[3] == "--state-root",
            "usage: ordinary-boot ACTION --state-root ABSOLUTE_STATE_ROOT [--request PRIVATE_JSON | --id ID --token TOKEN]"
        );
        let boot = ordinary_boot::Boot::new(args[4].clone().into())?;
        let result = match action {
            "prepare" if args.len() == 7 && args[5] == "--request" => {
                boot.prepare(Path::new(&args[6]))?
            }
            "execute" | "cancel"
                if args.len() == 9 && args[5] == "--id" && args[7] == "--token" =>
            {
                if action == "execute" {
                    boot.execute(&args[6], &args[8])?
                } else {
                    boot.cancel(&args[6], &args[8])?
                }
            }
            "status" if args.len() == 5 => boot.status()?,
            "reconcile" if args.len() == 5 => boot.reconcile()?,
            _ => anyhow::bail!("INVALID_ARGUMENT: ordinary-boot action or parameters"),
        };
        println!("{result}");
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("seal-ordinary-profile") {
        anyhow::ensure!(
            args.len() == 6 && args[2] == "--request" && args[4] == "--output",
            "usage: seal-ordinary-profile --request PRIVATE_JSON --output NEW_PRIVATE_GRANT"
        );
        let result =
            recovery::seal_ordinary_profile(args[3].clone().into(), args[5].clone().into())?;
        println!("{result}");
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("seal-system-control") {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "FORBIDDEN: system control installation requires root"
        );
        ensure!(
            args.len() == 6 && args[2] == "--request" && args[4] == "--output",
            "usage: seal-system-control --request PRIVATE_JSON --output NEW_PRIVATE_GRANT"
        );
        println!(
            "{}",
            system_control::seal_profile(Path::new(&args[3]), Path::new(&args[5]))?
        );
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("check-transfer-revocation") {
        let mut transfer_id = None;
        let mut index = 2;
        while index < args.len() {
            match args[index].as_str() {
                "--transfer-id" if index + 1 < args.len() => {
                    transfer_id = Some(args[index + 1].clone());
                    index += 2;
                }
                _ => anyhow::bail!(
                    "usage: check-transfer-revocation --transfer-id UUID (identity from AGENT_* environment)"
                ),
            }
        }
        let transfer_id =
            transfer_id.ok_or_else(|| anyhow::anyhow!("--transfer-id is required"))?;
        match transport::check_transfer_revocation(
            &required("AGENT_CONSOLE_ENDPOINT")?,
            &required("AGENT_CA")?,
            &required("AGENT_CERT")?,
            &required("AGENT_KEY")?,
            &transfer_id,
        )
        .await
        {
            Ok(()) => println!("transfer authorization is ACTIVE"),
            Err(error) => {
                eprintln!("transfer revocation check refused: {error:#}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }
    let uid = unsafe { libc::geteuid() };
    let kura_uid = required("AGENT_KURA_UID")?.parse()?;
    let admin_uid = env::var("AGENT_ADMIN_UID")
        .ok()
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(uid);
    let socket =
        env::var("AGENT_SOCKET").unwrap_or("/run/kura-management-agent/control.sock".into());
    let state_path = required("AGENT_STATE_DB")?;
    let native = runtime_identity::enforce(
        env::var_os("AGENT_RUNTIME_IDENTITY").map(PathBuf::from),
        Path::new(&state_path),
        Path::new(&socket),
        kura_uid,
        admin_uid,
    )?;
    let mut local = local::Local::new(kura_uid, admin_uid);
    let configuration_updates = if native.is_some() {
        let initialization = native_state::verified_initialization().await?;
        runtime_identity::configuration_write_enabled(&initialization, kura_uid)?
    } else {
        match env::var("AGENT_KURA_CONFIGURATION_UPDATE").as_deref() {
            Err(env::VarError::NotPresent) | Ok("0") => false,
            Ok("1") => true,
            _ => anyhow::bail!("invalid AGENT_KURA_CONFIGURATION_UPDATE; expected 0 or 1"),
        }
    };
    local.enable_configuration_updates(configuration_updates);
    local.enable_snapshots(match env::var("AGENT_KURA_SNAPSHOT").as_deref() {
        Err(env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") => true,
        _ => anyhow::bail!("invalid AGENT_KURA_SNAPSHOT; expected 0 or 1"),
    });
    local.kura_firewall_write = match env::var("AGENT_KURA_FIREWALL_WRITE").as_deref() {
        Err(env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") => true,
        _ => anyhow::bail!("invalid AGENT_KURA_FIREWALL_WRITE; expected 0 or 1"),
    };
    local.firewall_remote = match env::var("AGENT_FIREWALL_REMOTE").as_deref() {
        Err(env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") => true,
        _ => anyhow::bail!("invalid AGENT_FIREWALL_REMOTE; expected 0 or 1"),
    };
    local.nm_remote = match env::var("AGENT_NM_REMOTE").as_deref() {
        Err(env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") => true,
        _ => anyhow::bail!("invalid AGENT_NM_REMOTE; expected 0 or 1"),
    };
    let listener = local.listen(Path::new(&socket)).await?;
    let identity_fields = [
        "AGENT_CONSOLE_ENDPOINT",
        "AGENT_GATEWAY_ID",
        "AGENT_BINDING_GENERATION",
        "AGENT_CA",
        "AGENT_CERT",
        "AGENT_KEY",
    ];
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| format!("process-{}", uuid::Uuid::new_v4()));
    let config = if identity_fields
        .iter()
        .any(|name| env::var_os(name).is_some())
    {
        Some(transport::Config {
            endpoint: required("AGENT_CONSOLE_ENDPOINT")?,
            gateway: required("AGENT_GATEWAY_ID")?,
            binding_generation: {
                let value = required("AGENT_BINDING_GENERATION")?;
                let generation: u64 = value
                    .parse()
                    .context("invalid AGENT_BINDING_GENERATION; expected a positive integer")?;
                if generation == 0 {
                    anyhow::bail!("AGENT_BINDING_GENERATION must be positive");
                }
                generation
            },
            ca: required("AGENT_CA")?,
            cert: required("AGENT_CERT")?,
            key: required("AGENT_KEY")?,
            boot_id: boot_id.clone(),
        })
    } else {
        None
    };
    secure::prepare_state(Path::new(&state_path))?;
    if let Some(config) = &config {
        secure::prepare(Path::new(&config.key), Path::new(&state_path))?;
    }
    let db = transport::database(&state_path).await?;
    let (enrollment_source, enrollment_socket) = runtime_identity::enrollment_paths(
        native.is_some(),
        kura_uid,
        env::var_os("AGENT_KURA_ENROLLMENT_DIR").map(PathBuf::from),
        env::var_os("AGENT_KURA_ENROLLMENT_READER_SOCKET").map(PathBuf::from),
    )?;
    let enrollment = enrollment::Enrollment::open_with_reader(
        Path::new(&state_path)
            .parent()
            .context("state directory")?
            .into(),
        config,
        enrollment_source,
        enrollment_socket,
        kura_uid,
        db.clone(),
        boot_id,
    )?;
    let config = enrollment.current();
    let remote = remote::Remote::open(
        Path::new(&state_path)
            .parent()
            .context("state directory")?
            .to_path_buf(),
        match env::var("AGENT_REMOTE_ENABLED").as_deref() {
            Err(env::VarError::NotPresent) | Ok("0") => false,
            Ok("1") => true,
            _ => anyhow::bail!("invalid AGENT_REMOTE_ENABLED; expected 0 or 1"),
        },
        config
            .as_ref()
            .map(|c| (c.endpoint.clone(), c.gateway.clone(), c.binding_generation)),
    )?;
    if enrollment.fault() {
        remote.inhibit_binding();
    }
    local.enrollment = Some(enrollment.clone());
    local.remote = Some(remote.clone());
    local.kura_remote_management = match env::var("AGENT_KURA_REMOTE_MANAGEMENT").as_deref() {
        Err(env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") => true,
        _ => anyhow::bail!("invalid AGENT_KURA_REMOTE_MANAGEMENT; expected 0 or 1"),
    };
    if let Some(path) = env::var_os("AGENT_ORDINARY_BOOT_REQUEST") {
        local.ordinary_boot = Some(boot_control::Control::new(
            Path::new(&state_path)
                .parent()
                .context("state directory")?
                .into(),
            path.into(),
            db.clone(),
        )?);
    }
    local.system_state = Some(
        Path::new(&state_path)
            .parent()
            .context("state directory")?
            .into(),
    );
    let network = network::Network::open(
        "/".into(),
        Path::new(&state_path)
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
    let recovery_units: Vec<String> = env::var("AGENT_RECOVERY_UNITS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let recovery = recovery::Recovery::open(
        "/".into(),
        Path::new(&state_path)
            .parent()
            .context("state directory")?
            .into(),
        recovery_units,
        PathBuf::from(
            env::var("AGENT_RECOVERY_SNAPSHOT_DIR")
                .unwrap_or_else(|_| "/opt/eclipse/kura/user/snapshots".into()),
        ),
        None,
    )?
    .with_execution_database(PathBuf::from(&state_path));
    let recovery = match env::var("AGENT_RECOVERY_VALIDATOR_CONFIG") {
        Ok(path) => {
            recovery.with_snapshot_validator(snapshot_validation::Validator::new(path.into())?)
        }
        Err(env::VarError::NotPresent) => recovery,
        Err(_) => anyhow::bail!("invalid AGENT_RECOVERY_VALIDATOR_CONFIG"),
    };
    let recovery = match env::var("AGENT_RECOVERY_STARTUP_CONFIG") {
        Ok(path) => {
            recovery.with_controlled_startup(controlled_startup::Startup::new(path.into())?)?
        }
        Err(env::VarError::NotPresent) => recovery,
        Err(_) => anyhow::bail!("invalid AGENT_RECOVERY_STARTUP_CONFIG"),
    };
    let recovery = match env::var("AGENT_RECOVERY_COMPENSATION_STARTUP_CONFIG") {
        Ok(path) => {
            recovery.with_inverse_startup(controlled_startup::Startup::new(path.into())?)?
        }
        Err(env::VarError::NotPresent) => recovery,
        Err(_) => anyhow::bail!("invalid AGENT_RECOVERY_COMPENSATION_STARTUP_CONFIG"),
    };
    let recovery = match env::var("AGENT_RECOVERY_NORMAL_STARTUP_CONFIG") {
        Ok(path) => recovery.with_normal_startup(controlled_startup::Startup::new(path.into())?)?,
        Err(env::VarError::NotPresent) => recovery,
        Err(_) => anyhow::bail!("invalid AGENT_RECOVERY_NORMAL_STARTUP_CONFIG"),
    };
    let recovery = match env::var("AGENT_RECOVERY_NORMAL_VALIDATOR_CONFIG") {
        Ok(path) => recovery
            .with_normal_snapshot_validator(snapshot_validation::Validator::new(path.into())?)?,
        Err(env::VarError::NotPresent) => recovery,
        Err(_) => anyhow::bail!("invalid AGENT_RECOVERY_NORMAL_VALIDATOR_CONFIG"),
    };
    let recovery = match env::var("AGENT_RECOVERY_FORWARD_NORMAL_CONFIG") {
        Ok(path) => recovery.with_forward_normal_profile(path.into())?,
        Err(env::VarError::NotPresent) => recovery,
        Err(_) => anyhow::bail!("invalid AGENT_RECOVERY_FORWARD_NORMAL_CONFIG"),
    };
    let recovery = match env::var("AGENT_RECOVERY_HEALTH_CONFIG") {
        Ok(path) => recovery.with_health_profile(path.into())?,
        Err(env::VarError::NotPresent) => recovery,
        Err(_) => anyhow::bail!("invalid AGENT_RECOVERY_HEALTH_CONFIG"),
    };
    let recovery = match env::var("AGENT_RECOVERY_COMPLETION_CONFIG") {
        Ok(path) => recovery.with_completion_profile(path.into())?,
        Err(env::VarError::NotPresent) => recovery,
        Err(_) => anyhow::bail!("invalid AGENT_RECOVERY_COMPLETION_CONFIG"),
    };
    let recovery = match env::var("AGENT_RECOVERY_ORDINARY_STARTUP_CONFIG") {
        Ok(path) => recovery.with_ordinary_profile(path.into())?,
        Err(env::VarError::NotPresent) => recovery,
        Err(_) => anyhow::bail!("invalid AGENT_RECOVERY_ORDINARY_STARTUP_CONFIG"),
    };
    let recovery = match env::var("AGENT_RECOVERY_ORDINARY_VALIDATOR_CONFIG") {
        Ok(path) => recovery
            .with_ordinary_snapshot_validator(snapshot_validation::Validator::new(path.into())?)?,
        Err(env::VarError::NotPresent) => recovery,
        Err(_) => anyhow::bail!("invalid AGENT_RECOVERY_ORDINARY_VALIDATOR_CONFIG"),
    };
    local.ordinary_handoff_remote = match env::var("AGENT_RECOVERY_ORDINARY_REMOTE").as_deref() {
        Err(env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") => {
            ensure!(
                recovery.ordinary_handoff_configured(),
                "ordinary remote handoff requires a fixed local ordinary profile"
            );
            true
        }
        _ => anyhow::bail!("invalid AGENT_RECOVERY_ORDINARY_REMOTE; expected 0 or 1"),
    };
    if let Err(error) = recovery.recover().await {
        tracing::error!(%error,"recovery journal compensation requires operator attention");
    }
    let firewall = firewall::Firewall::open(
        Path::new(&state_path)
            .parent()
            .context("state directory")?
            .into(),
        None,
    )?
    .enable_writes(match env::var("AGENT_FIREWALL_WRITE").as_deref() {
        Err(env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") => true,
        _ => anyhow::bail!("invalid AGENT_FIREWALL_WRITE; expected 0 or 1"),
    });
    if let Err(error) = firewall.recover().await {
        tracing::error!(%error,"firewall recovery requires operator attention; agent remains available");
    }
    local.network = Some(network.clone());
    local.firewall = Some(firewall.clone());
    local.recovery = Some(recovery.clone());
    local.nm = match env::var("AGENT_NM_CONFIG") {
        Ok(path) => match nm::Nm::open(
            Path::new(&path),
            Some(Path::new(&state_path).parent().context("state directory")?),
        ) {
            Ok(source) => Some(source.with_role_source(std::sync::Arc::new(
                nm::roles::BridgeSource::new(local.clone()),
            ))?),
            Err(error) => {
                tracing::error!(%error, "NM configuration unavailable; capability remains disabled");
                None
            }
        },
        Err(env::VarError::NotPresent) => None,
        Err(_) => anyhow::bail!("invalid AGENT_NM_CONFIG"),
    };
    let nm_tick = local.nm.clone();
    if let Some(path) = env::var_os("AGENT_SYSTEM_CONTROL_CONFIG") {
        match system_control::Control::new(
            Path::new(&state_path)
                .parent()
                .context("system state directory")?
                .into(),
            path.into(),
            db.clone(),
        ) {
            Ok(control) => local.system_control = Some(control),
            Err(error) => {
                tracing::error!(%error,"system control unavailable; agent remains running with retained state")
            }
        }
    }
    local.system_control_remote = match env::var("AGENT_SYSTEM_CONTROL_REMOTE").as_deref() {
        Err(env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") if local.system_control.is_some() => true,
        _ => {
            tracing::error!(
                "system control remote option or local grant unavailable; channel capability disabled"
            );
            false
        }
    };
    if let Some(control) = local.system_control.clone() {
        let peer = local.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            let mut previous_error = None;
            loop {
                tick.tick().await;
                match control.observe_pending(peer.clone()).await {
                    Ok(()) => previous_error = None,
                    Err(error) => {
                        let message = error.to_string();
                        if previous_error.as_ref() != Some(&message) {
                            tracing::error!(%error,"system control evidence requires inspection; no action is replayed");
                            previous_error = Some(message);
                        }
                    }
                }
            }
        });
    }
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
            if let Err(error) = firewall.expire().await {
                tracing::error!(%error,"firewall recovery requires attention");
            }
            if let Some(nm) = &nm_tick
                && let Err(error) = nm.expire().await
            {
                tracing::error!(%error,"NM transaction adjudication requires attention");
            }
        }
    });
    tracing::info!(socket=%socket,"agent local control ready");
    tokio::select! {result=local.clone().serve(listener)=>result?,result=transport::run(enrollment.subscribe(),local,remote,db)=>result?,_=tokio::signal::ctrl_c()=>{}}
    Ok(())
}
