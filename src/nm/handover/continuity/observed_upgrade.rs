//! Exact package transition from an already settled imported source observation.
//! All checks are read-only apart from preparing the single candidate receipt.
use super::*;

const RECORD: &str = "observed.json";
const STOP: &str = "observed-stop";
const BRIDGE: &str = "/usr/share/kura-management-agent/java/org.eclipse.kura.management.bridge.jar";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Admission {
    schema_version: u8,
    observation_id: uuid::Uuid,
    old_version: String,
    new_version: String,
    old_binary_sha256: String,
    candidate_binary_sha256: String,
    bridge_sha256: String,
    source: Source,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source {
    firewall: Value,
    pid_namespace: Value,
    core: Process,
    network_manager: Process,
    agent: Option<Process>,
}

fn require_process(current: &Process, expected: &Process) -> Result<()> {
    current.require_across_mounts(&serde_json::to_value(expected)?)
}

impl Source {
    fn require(&self, expected: &Self, stopped: bool) -> Result<()> {
        ensure!(
            self.firewall == expected.firewall && self.pid_namespace == expected.pid_namespace,
            "CONFLICT: original observation, physical head or PID namespace changed"
        );
        require_process(&self.core, &expected.core)?;
        require_process(&self.network_manager, &expected.network_manager)?;
        match (&self.agent, &expected.agent, stopped) {
            (Some(current), Some(original), false) => require_process(current, original),
            (None, Some(_), true) => Ok(()),
            _ => anyhow::bail!("CONFLICT: original Agent phase changed"),
        }
    }
}

fn processes(stopped: bool) -> Result<(Process, Process, Option<Process>)> {
    let agent = if stopped {
        ensure!(
            inspect_unit(Path::new("/usr/bin/systemctl"), AGENT_UNIT)?.stopped(),
            "CONFLICT: original Agent is not stopped"
        );
        None
    } else {
        let agent = Process::read(AGENT_UNIT)?;
        let settings = startup::runtime::text(
            &Path::new("/proc")
                .join(agent.unit.pid.to_string())
                .join("environ"),
            65_536,
        )?;
        let disabled = |key: &str| {
            settings
                .split('\0')
                .filter_map(|entry| entry.strip_prefix(key))
                .all(|value| value == "0")
        };
        ensure!(
            disabled("AGENT_REMOTE_ENABLED=")
                && disabled("AGENT_FIREWALL_WRITE=")
                && disabled("AGENT_KURA_FIREWALL_WRITE="),
            "FORBIDDEN: close remote and firewall write admission before package maintenance"
        );
        Some(agent)
    };
    Ok((Process::read(UNITS[0])?, Process::read(UNITS[2])?, agent))
}

fn observe(id: uuid::Uuid, stopped: bool) -> Result<Source> {
    let root = Path::new(LEGACY_STATE_ROOT);
    let _guard =
        crate::system_change::Guard::observe_existing_shared_for(root, Duration::from_secs(3))?;
    let (core, network_manager, agent) = processes(stopped)?;
    let pid_namespace = super::pid_namespace()?;
    let epoch = native::epoch::Epoch::capture()?;
    let firewall =
        initialization::observed_maintenance_source(root, id, &epoch, &observe_kernel()?)?;
    epoch.require(&native::epoch::Epoch::capture()?)?;
    let (core_after, nm_after, agent_after) = processes(stopped)?;
    ensure!(
        pid_namespace == super::pid_namespace()?
            && core == core_after
            && network_manager == nm_after
            && agent == agent_after,
        "CONFLICT: original maintenance process changed during observation"
    );
    Ok(Source {
        firewall,
        pid_namespace,
        core,
        network_manager,
        agent,
    })
}

fn bridge_digest() -> Result<String> {
    Ok(durable::hash(&crate::runtime_identity::protected(
        Path::new(BRIDGE),
        8 * 1024 * 1024,
    )?))
}

fn prepare(candidate: &str, operation: &str, new: &str) -> Result<Value> {
    ensure!(
        !new.is_empty()
            && new.len() <= 150
            && new
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".+~:-".contains(&c)),
        "INVALID_ARGUMENT: Debian version"
    );
    let old_version = installed_version()?;
    dpkg(
        "/usr/bin/dpkg",
        &["--compare-versions", &old_version, "lt", new],
    )?;
    let old_binary_sha256 = installed_binary()?;
    let bridge_sha256 = bridge_digest()?;
    ensure!(
        old_binary_sha256 != candidate,
        "CONFLICT: Agent candidate is already installed"
    );
    let observation_id = template::operation(operation)?;
    let source = observe(observation_id, false)?;
    ensure!(
        installed_version()? == old_version
            && installed_binary()? == old_binary_sha256
            && bridge_digest()? == bridge_sha256,
        "CONFLICT: installed release changed during preparation"
    );
    let receipt = Admission {
        schema_version: 1,
        observation_id,
        old_version,
        new_version: new.into(),
        old_binary_sha256,
        candidate_binary_sha256: candidate.into(),
        bridge_sha256,
        source,
    };
    durable::publish_new(
        &package_path(candidate, RECORD),
        &serde_json::to_vec(&receipt)?,
        FileMetadata {
            uid: 0,
            gid: 0,
            mode: 0o600,
        },
    )?;
    Ok(
        json!({"schemaVersion":1,"observationId":observation_id,"state":"PREPARED","dispatchAuthorized":false}),
    )
}

fn check(candidate: &str, phase: &str, old: &str, new: &str) -> Result<Value> {
    let record =
        crate::runtime_identity::protected_mode(&package_path(candidate, RECORD), 16_384, 0o600)?;
    let receipt: Admission = serde_json::from_slice(&record)?;
    ensure!(
        receipt.schema_version == 1
            && receipt.old_version == old
            && receipt.new_version == new
            && receipt.candidate_binary_sha256 == candidate
            && installed_version()? == old
            && installed_binary()? == receipt.old_binary_sha256
            && bridge_digest()? == receipt.bridge_sha256,
        "FORBIDDEN: original installed release and candidate do not pair"
    );
    let stopped = phase == "before-unpack";
    let record_sha = durable::hash(&record);
    let stop = package_path(candidate, STOP);
    if stopped {
        require_stop(&stop, &record_sha)?;
    } else {
        ensure!(
            fs::symlink_metadata(&stop)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "OUTCOME_UNKNOWN: original Agent stop already issued or missing status cannot be proven"
        );
    }
    let source = observe(receipt.observation_id, stopped)?;
    source.require(&receipt.source, stopped)?;
    ensure!(
        installed_version()? == old
            && installed_binary()? == receipt.old_binary_sha256
            && bridge_digest()? == receipt.bridge_sha256,
        "CONFLICT: installed release changed during review"
    );
    Ok(
        json!({"schemaVersion":1,"observationId":receipt.observation_id,"phase":phase,
        "transactionSha256": source.firewall["transactionSha256"],"admissionSha256":record_sha,
        "dispatchAuthorized":false}),
    )
}

pub(crate) fn run(args: &[String]) -> Result<Value> {
    let candidate = super::running_program_sha()?;
    staged_binary(&candidate)?;
    match args {
        [phase, operation, new] if phase == "prepare" => prepare(&candidate, operation, new),
        [phase, old, new] if matches!(phase.as_str(), "before-stop" | "before-unpack") => {
            check(&candidate, phase, old, new)
        }
        _ => anyhow::bail!("INVALID_ARGUMENT: fixed original firewall package phase required"),
    }
}
