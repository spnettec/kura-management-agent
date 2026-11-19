//! Read-only evidence for replacing a legacy Agent during its original
//! handover. This command does not grant write authority to a new registration.
use super::*;
use crate::system_control::{Unit, inspect_unit};
mod legacy_execution;
pub(crate) use legacy_execution::{ExecutionPhase, execute_legacy_startup};
pub(crate) mod observed_upgrade;

const UNITS: [&str; 3] = [
    "kura.service",
    "kura-management-agent.service",
    "NetworkManager.service",
];
const AGENT_UNIT: &str = "kura-management-agent.service";
const DIRECTORY: &str = "/etc/kura-management-agent/nm-continuity";
const LEGACY_RECORD: &str = "/etc/kura-management-agent/.nm-continuity-upgrade.json";
const LEGACY_STOP: &str = "/etc/kura-management-agent/.nm-continuity-stop";

fn package_path(binary: &str, suffix: &str) -> PathBuf {
    Path::new(DIRECTORY).join(format!("{binary}.{suffix}"))
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Process {
    unit: Unit,
    start_ticks: u64,
    proc_device: u64,
    proc_inode: u64,
    uid: u32,
    gid: u32,
}

impl Process {
    fn require_across_mounts(&self, original: &Value) -> Result<()> {
        // procfs allocates different device/inode pairs in the host and in the
        // service mount. They protect each individual sample inside read().
        // Equality across mounts comes from the same PID namespace, start
        // ticks, credentials, cgroup and systemd invocation.
        ensure!(
            serde_json::to_value(&self.unit)? == original["unit"]
                && original["startTicks"].as_u64() == Some(self.start_ticks)
                && original["uid"].as_u64() == Some(self.uid.into())
                && original["gid"].as_u64() == Some(self.gid.into()),
            "CONFLICT: original service process changed across Agent replacement"
        );
        Ok(())
    }

    fn read(name: &str) -> Result<Self> {
        let unit = inspect_unit(Path::new("/usr/bin/systemctl"), name)?;
        ensure!(
            unit.running() && unit.pid > 1 && unit.invocation_id.bytes().any(|b| b != b'0'),
            "CONFLICT: fixed continuity service is not active"
        );
        let directory = PathBuf::from("/proc").join(unit.pid.to_string());
        let birth = || {
            startup::runtime::start_ticks(
                unit.pid,
                &startup::runtime::text(&directory.join("stat"), 16_384)?,
            )
        };
        let start_ticks = birth()?;
        let metadata = fs::symlink_metadata(&directory)?;
        let status = startup::runtime::text(&directory.join("status"), 65_536)?;
        let [real_uid, uid, saved_uid, fs_uid] = startup::runtime::ids(&status, "Uid:")?;
        let [real_gid, gid, saved_gid, fs_gid] = startup::runtime::ids(&status, "Gid:")?;
        let again = fs::symlink_metadata(&directory)?;
        ensure!(
            metadata.is_dir()
                && metadata.ino() != 0
                && (metadata.dev(), metadata.ino()) == (again.dev(), again.ino())
                && real_uid == uid
                && saved_uid == uid
                && fs_uid == uid
                && real_gid == gid
                && saved_gid == gid
                && fs_gid == gid
                && (uid != 0) == (name == "kura.service")
                && birth()? == start_ticks,
            "CONFLICT: fixed continuity service credentials or birth changed"
        );
        Ok(Self {
            unit,
            start_ticks,
            proc_device: metadata.dev(),
            proc_inode: metadata.ino(),
            uid,
            gid,
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Original {
    operation_id: uuid::Uuid,
    phase: State,
    plan_sha256: String,
    source_digest: String,
    template_receipt: template::Binding,
    journal_identity: MarkerIdentity,
    network_marker: Option<MarkerIdentity>,
    firewall_marker: Option<MarkerIdentity>,
    root_publication_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initialized: Option<Initialized>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Initialized {
    applied_batch_sha256: String,
    kernel_sha256: String,
    policy_receipt_sha256: String,
}

impl Store {
    fn initialized_continuity(
        &self,
        journal: &Journal,
        plan: &Plan,
    ) -> Result<Option<Initialized>> {
        if journal.native.is_none() && journal.initialization.is_none() {
            return Ok(None);
        }
        ensure!(
            journal.state == State::Fenced,
            "OUTCOME_UNKNOWN: settle the original issued effect before Agent continuity"
        );
        self.require_initialization_ready(journal, plan)?;
        let initialization = journal
            .initialization
            .as_ref()
            .context("OUTCOME_UNKNOWN: original initialization missing")?;
        let status = initialization.parameters()?;
        Ok(Some(Initialized {
            applied_batch_sha256: self.native_applied_batch(journal)?,
            kernel_sha256: self.native_applied_digest(journal)?,
            policy_receipt_sha256: status["receiptSha256"]
                .as_str()
                .filter(|value| hex(value, 64))
                .context("CONFLICT: original initialization receipt missing")?
                .to_owned(),
        }))
    }

    pub(super) fn continuity_original(
        &self,
        operation: uuid::Uuid,
    ) -> Result<(Original, native::Transfer)> {
        self.continuity_original_for(operation, false)
    }

    fn continuity_original_for(
        &self,
        operation: uuid::Uuid,
        existing_startup: bool,
    ) -> Result<(Original, native::Transfer)> {
        let journal_file = BoundFile::open(&self.journal_path(), LIMIT)?;
        let (journal, plan) = self.load()?.context("NOT_FOUND: original NM handover")?;
        ensure!(
            serde_json::to_value(&journal)?
                == serde_json::from_slice::<Value>(&journal_file.bytes)?,
            "CONFLICT: original journal changed during continuity observation"
        );
        ensure!(
            journal.operation_id == operation && plan.actor == "local-uid:0",
            "FORBIDDEN: original local Root handover required"
        );
        ensure!(
            matches!(journal.state, State::Prepared | State::Fenced),
            "OUTCOME_UNKNOWN: settle the original issued effect before Agent continuity"
        );
        let initialized = self.initialized_continuity(&journal, &plan)?;
        if existing_startup {
            ensure!(initialized.is_some(), "CONFLICT: original startup requires committed initialization");
        } else {
            startup::require_no_native_child(&self.root, operation)?;
        }
        for suffix in ["receipt", "lease"] {
            ensure!(
                fs::symlink_metadata(self.artifact(operation, suffix))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "OUTCOME_UNKNOWN: original ownership settlement evidence exists"
            );
        }
        let transfer = plan
            .baseline
            .native_transfer
            .as_ref()
            .filter(|transfer| transfer.source_model_sha256.is_some())
            .context("UNSUPPORTED: complete original writer model required")?;
        let template = plan
            .template
            .as_ref()
            .context("CONFLICT: original encrypted export missing")?;
        let state_root = self
            .root
            .parent()
            .context("CONFLICT: original state root missing")?;
        let (current_template, exported_baseline) =
            template::Transfer::new(state_root).ready(operation, &plan.actor)?;
        ensure!(
            template == &current_template && plan.baseline == exported_baseline,
            "CONFLICT: original encrypted export and ownership source differ"
        );
        let root_publication_sha256 = if journal.state == State::Prepared {
            self.require_no_root_fence_arm(operation)?;
            ensure!(
                self.network_marker_absent()?,
                "CONFLICT: unexpected original network fence"
            );
            self.require_original_firewall_fence(&plan)?;
            None
        } else {
            Some(self.original_root_publication(&journal, &plan)?)
        };
        Ok((
            Original {
                operation_id: operation,
                phase: journal.state,
                plan_sha256: journal.plan_sha256,
                source_digest: plan.baseline.source_digest,
                template_receipt: current_template,
                journal_identity: journal_file.marker()?,
                network_marker: journal.marker,
                firewall_marker: journal.firewall_marker,
                root_publication_sha256,
                initialized,
            },
            transfer.clone(),
        ))
    }
}

pub(crate) fn inspect(operation: &str) -> Result<Value> {
    review(operation, false)
}

pub(crate) async fn review_legacy_startup(operation: &str) -> Result<Value> {
    use tokio::net::UnixStream;
    use yofc_management_protocol::{LocalFrame, read_frame, write_frame};

    let observed = review(operation, false)?;
    let id = template::operation(operation)?;
    let root = Path::new(LEGACY_STATE_ROOT);
    let _guard = crate::system_change::Guard::observe_existing_shared_for(root, Duration::from_secs(2))?;
    let store = Store::new(root);
    let (journal, plan) = store.load()?.context("NOT_FOUND: original startup parent")?;
    let original = store.requirements(id, &journal.token, "local-uid:0")?;
    let initialized = store.initialized_continuity(&journal, &plan)?
        .context("CONFLICT: original initialization required before legacy startup review")?;
    let binary = installed_binary()?;
    let version = installed_version()?;
    let (upgrade, upgrade_sha) = load_upgrade(&package_path(&binary, "json"))?;
    require_stop(&package_path(&binary, "stop"), &upgrade_sha)?;
    ensure!(
        upgrade.operation_id == id
            && upgrade.new_version == version
            && upgrade.candidate_binary_sha256 == binary
            && upgrade.source["original"] == observed["original"],
        "CONFLICT: installed Agent and original initialized Root do not pair"
    );
    compare_predecessor_services(&upgrade.source, &observed)?;
    let core = Process::read(UNITS[0])?;
    let agent = Process::read(AGENT_UNIT)?;
    core.require_across_mounts(&observed["processes"][0])?;
    agent.require_across_mounts(&observed["processes"][1])?;
    let mut socket = UnixStream::connect("/run/kura-management-agent/control.sock").await?;
    let credentials = socket.peer_cred()?;
    ensure!(
        credentials.pid().and_then(|pid| u32::try_from(pid).ok()) == Some(agent.unit.pid)
            && credentials.uid() == agent.uid && credentials.gid() == agent.gid,
        "FORBIDDEN: actual installed Agent peer required for legacy startup review"
    );
    let request = LocalFrame {
        version: 1,
        kind: "request".into(),
        request_id: uuid::Uuid::new_v4().to_string(),
        method: "network.nm.ownership.upgrade.verify".into(),
        params: Some(json!({"operationId":id})),
        result: None,
        error: None,
    };
    let response = tokio::time::timeout(Duration::from_secs(45), async {
        write_frame(&mut socket, &request).await?;
        read_frame(&mut socket).await
    }).await.context("TIMEOUT: original live JVM readback")??;
    ensure!(
        response.version == 1 && response.kind == "response"
            && response.request_id == request.request_id && response.method == request.method
            && response.error.is_none()
            && response.result == Some(json!({"schemaVersion":1, "operationId":id, "state":"FENCED",
                "planSha256":journal.plan_sha256,"registeredJvmPid":core.unit.pid,
                "pairedRegistration":true,"dispatchAuthorized":false})),
        "CONFLICT: paired Agent did not verify the original live JVM"
    );
    let result = startup::review_legacy(&store, &original, &core.unit, core.start_ticks,
        &upgrade_sha, &initialized.policy_receipt_sha256)?;
    let after = review(operation,false)?;
    compare_predecessor_services(&observed, &after)?;
    agent.require_across_mounts(&after["processes"][1])?;
    ensure!(after["original"] == observed["original"]
        && after["physicalEpoch"] == observed["physicalEpoch"]
        && after["netfilterGeneration"] == observed["netfilterGeneration"]
        && after["reviewedBatchSha256"] == observed["reviewedBatchSha256"]
        && installed_binary()? == binary && installed_version()? == version,
        "CONFLICT: original Root evidence changed during legacy startup review");
    Ok(result)
}

fn pid_namespace() -> Result<Value> {
    let namespace = File::open("/proc/thread-self/ns/pid")?.metadata()?;
    ensure!(
        namespace.ino() != 0 && namespace.dev() != 0,
        "CONFLICT: current PID namespace is unavailable"
    );
    Ok(json!({"device":namespace.dev(),"inode":namespace.ino()}))
}

fn observe_kernel() -> Result<Value> {
    native::raw::observe(
        || {
            let output = crate::process::run_isolated(
                Path::new("/usr/sbin/nft"),
                &["-j", "-p", "list", "ruleset"],
                Duration::from_secs(8),
            )?;
            ensure!(
                output.status.success(),
                "UNSUPPORTED: original Netfilter source unavailable"
            );
            Ok(serde_json::from_slice(&output.stdout)?)
        },
        Instant::now() + Duration::from_secs(12),
    )
}

fn review(operation: &str, stopped: bool) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "FORBIDDEN: installed legacy Root required"
    );
    let id = template::operation(operation)?;
    let root = Path::new(LEGACY_STATE_ROOT);
    let _guard =
        crate::system_change::Guard::observe_existing_shared_for(root, Duration::from_secs(2))?;
    let store = Store::new(root);
    let (original, transfer) = store.continuity_original(id)?;
    let processes = || {
        if stopped {
            let agent = inspect_unit(Path::new("/usr/bin/systemctl"), AGENT_UNIT)?;
            ensure!(
                agent.stopped(),
                "CONFLICT: original Agent did not stop cleanly"
            );
        }
        UNITS
            .iter()
            .filter(|name| !stopped || **name != AGENT_UNIT)
            .map(|name| Process::read(name))
            .collect::<Result<Vec<_>>>()
    };
    let before = processes()?;
    let epoch = native::epoch::Epoch::capture()?;
    let pid_namespace_before = pid_namespace()?;
    let kernel = observe_kernel()?;
    let generation = kernel["kernelGeneration"]
        .as_u64()
        .context("UNSUPPORTED: original physical Netfilter generation required")?;
    let batch_sha = if let Some(initialized) = &original.initialized {
        ensure!(
            transfer.acknowledge(&kernel, false)? == initialized.kernel_sha256,
            "CONFLICT: applied original Netfilter effect changed"
        );
        initialized.applied_batch_sha256.clone()
    } else {
        digest(&transfer.batch(&kernel, false)?)?
    };
    ensure!(
        processes()? == before
            && store.continuity_original(id)?.0 == original
            && pid_namespace()? == pid_namespace_before,
        "CONFLICT: original Root plan or service processes changed during observation"
    );
    epoch.require(&native::epoch::Epoch::capture()?)?;
    Ok(json!({
        "schemaVersion":1, "original":original, "physicalEpoch":epoch, "processes":before,
        "pidNamespace":pid_namespace_before,
        "netfilterGeneration":generation, "reviewedBatchSha256":batch_sha,
        "dispatchAuthorized":false,
    }))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Upgrade {
    schema_version: u8,
    operation_id: uuid::Uuid,
    old_version: String,
    new_version: String,
    old_binary_sha256: String,
    candidate_binary_sha256: String,
    source: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_sha256: Option<String>,
}

fn dpkg(program: &str, args: &[&str]) -> Result<String> {
    let output = crate::process::run_isolated(Path::new(program), args, Duration::from_secs(5))?;
    ensure!(
        output.status.success(),
        "CONFLICT: installed Agent Debian package version"
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn installed_version() -> Result<String> {
    dpkg(
        "/usr/bin/dpkg-query",
        &["-W", "-f=${Version}", "kura-management-agent"],
    )
}

fn installed_binary() -> Result<String> {
    Ok(durable::hash(&crate::runtime_identity::protected_mode(
        Path::new("/usr/bin/yofc-management-agent"),
        64 * 1024 * 1024,
        0o755,
    )?))
}

fn load_upgrade(path: &Path) -> Result<(Upgrade, String)> {
    let raw = crate::runtime_identity::protected_mode(path, 16_384, 0o600)?;
    let proof: Upgrade = serde_json::from_slice(&raw)?;
    ensure!(
        proof.schema_version == 1
            && !proof.operation_id.is_nil()
            && hex(&proof.old_binary_sha256, 64)
            && hex(&proof.candidate_binary_sha256, 64)
            && proof.source["original"]["operationId"] == json!(proof.operation_id)
            && proof.source["dispatchAuthorized"] == false
            && proof
                .previous_sha256
                .as_ref()
                .is_none_or(|sha| hex(sha, 64)),
        "FORBIDDEN: unpaired original Debian continuity record"
    );
    Ok((proof, durable::hash(&raw)))
}

fn require_stop(path: &Path, proof_sha: &str) -> Result<()> {
    let stopped = crate::runtime_identity::protected_mode(path, 65, 0o600)?;
    ensure!(
        stopped == format!("{proof_sha}\n").as_bytes(),
        "CONFLICT: original stop intent changed"
    );
    Ok(())
}

fn previous_upgrade(binary: &str, version: &str) -> Result<Option<(Upgrade, String)>> {
    let mut record = package_path(binary, "json");
    let mut stop = package_path(binary, "stop");
    if fs::symlink_metadata(&record).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        record = PathBuf::from(LEGACY_RECORD);
        stop = PathBuf::from(LEGACY_STOP);
        if fs::symlink_metadata(&record).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
            return Ok(None);
        }
    }
    let (previous, sha) = load_upgrade(&record)?;
    ensure!(
        previous.new_version == version && previous.candidate_binary_sha256 == binary,
        "FORBIDDEN: previous NM upgrade does not describe the installed predecessor"
    );
    require_stop(&stop, &sha)?;
    Ok(Some((previous, sha)))
}

fn compare_predecessor(previous: &Upgrade, previous_sha: &str, source: &Value) -> Result<()> {
    let old_original = &previous.source["original"];
    let new_original = &source["original"];
    ensure!(
        previous.source["physicalEpoch"] == source["physicalEpoch"]
            && previous.source["reviewedBatchSha256"] == source["reviewedBatchSha256"],
        "CONFLICT: predecessor does not bind the original Root plan and Netfilter source"
    );
    if old_original != new_original {
        ensure!(
            old_original["phase"] == "PREPARED"
                && new_original["phase"] == "FENCED"
                && new_original["initialized"].is_object()
                && [
                    "operationId",
                    "planSha256",
                    "sourceDigest",
                    "templateReceipt"
                ]
                .into_iter()
                .all(|field| old_original[field] == new_original[field]),
            "CONFLICT: predecessor does not bind this completed original transition"
        );
        let store = Store::new(Path::new(LEGACY_STATE_ROOT));
        let (journal, plan) = store
            .load()?
            .context("CONFLICT: original initialized transition missing")?;
        ensure!(
            journal.operation_id == previous.operation_id
                && journal.plan_sha256 == old_original["planSha256"],
            "CONFLICT: actual original initialized plan changed"
        );
        store.require_startup_publication(&journal, &plan, previous_sha)?;
    }
    compare_predecessor_services(&previous.source, source)
}

fn compare_predecessor_services(previous: &Value, current: &Value) -> Result<()> {
    let old = previous["processes"]
        .as_array()
        .context("CONFLICT: predecessor services missing")?;
    let new = current["processes"]
        .as_array()
        .context("CONFLICT: current services missing")?;
    ensure!(
        old.len() == UNITS.len() && new.len() == UNITS.len(),
        "CONFLICT: incomplete predecessor services"
    );
    if let Some(namespace) = previous.get("pidNamespace") {
        ensure!(
            namespace == &current["pidNamespace"]
                && ["device", "inode"]
                    .into_iter()
                    .all(|key| namespace[key].as_u64().is_some_and(|number| number != 0)),
            "CONFLICT: predecessor PID namespace changed"
        );
        // procfs can assign a new inode to the same process directory between
        // captures. Each capture separately validates its procfs metadata.
        for index in [0, 2] {
            let process: Process = serde_json::from_value(new[index].clone())?;
            process.require_across_mounts(&old[index])?;
        }
    } else {
        ensure!(
            old[0] == new[0] && old[2] == new[2],
            "CONFLICT: predecessor JVM or NM changed in the Root procfs view"
        );
    }
    Ok(())
}

fn staged_binary(sha: &str) -> Result<()> {
    let binary = package_path(sha, "bin");
    ensure!(
        std::env::current_exe()? == binary
            && durable::hash(&crate::runtime_identity::protected_mode(
                &binary,
                64 * 1024 * 1024,
                0o500
            )?) == sha,
        "FORBIDDEN: fixed Root-staged candidate binary required"
    );
    Ok(())
}

pub(crate) fn prepare_upgrade(operation: &str, version: &str) -> Result<Value> {
    let old_version = installed_version()?;
    ensure!(
        version.len() <= 150
            && version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".+~:-".contains(&c)),
        "INVALID_ARGUMENT: Debian version"
    );
    dpkg(
        "/usr/bin/dpkg",
        &["--compare-versions", &old_version, "lt", version],
    )?;
    let old_binary_sha256 = installed_binary()?;
    let candidate_binary_sha256 = super::running_program_sha()?;
    staged_binary(&candidate_binary_sha256)?;
    ensure!(
        old_binary_sha256 != candidate_binary_sha256,
        "CONFLICT: candidate and installed Agent are identical"
    );
    let source = review(operation, false)?;
    let operation_id = template::operation(operation)?;
    let predecessor = previous_upgrade(&old_binary_sha256, &old_version)?;
    if let Some((old, sha)) = &predecessor {
        compare_predecessor(old, sha, &source)?;
    }
    let record = package_path(&candidate_binary_sha256, "json");
    let proof = Upgrade {
        schema_version: 1,
        operation_id,
        old_version,
        new_version: version.into(),
        old_binary_sha256,
        candidate_binary_sha256,
        source,
        previous_sha256: predecessor.map(|(_, sha)| sha),
    };
    durable::publish_new(
        &record,
        &serde_json::to_vec(&proof)?,
        FileMetadata {
            uid: 0,
            gid: 0,
            mode: 0o600,
        },
    )?;
    Ok(json!({"schemaVersion":1, "operationId":operation_id, "state":"PREPARED"}))
}

pub(crate) fn check_upgrade(old: &str, new: &str, phase: &str) -> Result<Value> {
    let candidate_sha = super::running_program_sha()?;
    staged_binary(&candidate_sha)?;
    let (proof, _) = load_upgrade(&package_path(&candidate_sha, "json"))?;
    ensure!(
        proof.candidate_binary_sha256 == candidate_sha
            && proof.old_version == old
            && proof.new_version == new
            && installed_version()? == old
            && installed_binary()? == proof.old_binary_sha256,
        "FORBIDDEN: original Debian source and candidate do not pair"
    );
    let predecessor = previous_upgrade(&proof.old_binary_sha256, old)?;
    ensure!(
        predecessor.as_ref().map(|(_, sha)| sha) == proof.previous_sha256.as_ref(),
        "CONFLICT: original package predecessor changed"
    );
    if let Some((old, sha)) = &predecessor {
        compare_predecessor(old, sha, &proof.source)?;
    }
    let stopped = match phase {
        "before-stop" => false,
        "before-unpack" => true,
        _ => anyhow::bail!("INVALID_ARGUMENT: fixed Debian continuity phase required"),
    };
    let actual = review(&proof.operation_id.to_string(), stopped)?;
    let mut expected = proof.source;
    if stopped {
        expected["processes"]
            .as_array_mut()
            .context("CONFLICT: original services are missing")?
            .retain(|process| process["unit"]["unit"] != AGENT_UNIT);
    }
    ensure!(
        actual == expected,
        "CONFLICT: original Root, JVM, NM or kernel source changed"
    );
    Ok(json!({"schemaVersion":1, "operationId":proof.operation_id, "phase":phase, "verified":true}))
}

#[derive(PartialEq, Eq)]
pub(crate) struct RegistrationAnchor {
    original: Original,
    processes: Vec<Process>,
    expected_roles: roles::Observation,
    expected_firewall: roles::FirewallSource,
    expected_model_sha256: String,
    upgrade_sha256: String,
    reviewed_batch_sha256: String,
}

impl RegistrationAnchor {
    pub(in crate::nm) fn legacy_startup_source(
        &self,
        roles: &roles::Observation,
    ) -> Result<startup::legacy_source::Receipt> {
        let initialized = self.original.initialized.as_ref().context(
            "FORBIDDEN: original committed initialization must precede legacy JVM binding",
        )?;
        let core = &self.processes[0];
        let command = startup::runtime::text(
            &Path::new("/proc")
                .join(core.unit.pid.to_string())
                .join("cmdline"),
            65_536,
        )?;
        let mut args = command.split('\0');
        ensure!(
            command.as_bytes().last() == Some(&0)
                && args.next().is_some_and(|java| Path::new(java)
                    .file_name()
                    .is_some_and(|name| name == "java"))
                && !args.any(|arg| [
                    "-Dkura.recovery.request",
                    "-Dkura.management.ordinary.profile.id=",
                    "-Dkura.management.ordinary.verification.enabled=",
                    "-Dkura.network.confirmed.provider="
                ]
                .iter()
                .any(|prefix| arg.starts_with(prefix))),
            "FORBIDDEN: original live JVM is not the inspected legacy ordinary source"
        );
        let profile = crate::recovery::ordinary_profile::Profile::new(PathBuf::from(
            "/etc/kura-management-agent/nm-ownership-profile.json",
        ))?;
        let (config, _, raw) = profile.inputs()?;
        ensure!(
            config.unit == UNITS[0]
                && config.profile_id == format!("profile-{}", self.original.operation_id)
                && config.jvm_args_path == Path::new("/etc/kura-startup/nm-owner.jvm.args")
                && config.launcher_kind
                    == crate::recovery::ordinary_profile::Launcher::PackagedBackground
                && config.launcher_script_path.as_deref()
                    == Some(Path::new("/opt/eclipse/kura/bin/start_kura_background.sh")),
            "FORBIDDEN: original Root ordinary profile required"
        );
        let policy =
            crate::system_control::inspect_stop_policy(Path::new("/usr/bin/systemctl"), &config)?;
        Ok(startup::legacy_source::Receipt::new(
            self.original.operation_id,
            self.original.plan_sha256.clone(),
            core.unit.clone(),
            core.start_ticks,
            durable::hash(&raw),
            policy,
            self.upgrade_sha256.clone(),
            initialized.policy_receipt_sha256.clone(),
            roles.clone(),
        ))
    }

    pub(in crate::nm) fn require_batch(&self, batch: &Value) -> Result<()> {
        ensure!(
            digest(batch)? == self.reviewed_batch_sha256,
            "CONFLICT: original kernel generation or candidate batch changed after replacement"
        );
        Ok(())
    }

    pub(in crate::nm) fn continued(
        &self,
        roles: &roles::Observation,
    ) -> super::root_fence::ContinuedRegistration {
        super::root_fence::ContinuedRegistration {
            agent_instance: roles.agent_instance,
            bridge_epoch: roles.bridge_epoch,
            upgrade_sha256: self.upgrade_sha256.clone(),
        }
    }

    pub(crate) fn require_peer(&self, pid: Option<i32>) -> Result<()> {
        ensure!(
            pid.and_then(|pid| u32::try_from(pid).ok()) == Some(self.processes[0].unit.pid),
            "FORBIDDEN: new bridge is not the original live Kura JVM"
        );
        Ok(())
    }

    pub(crate) fn require_source(
        &self,
        roles: &roles::Observation,
        firewall: &roles::FirewallSource,
        origin: &roles::Origin,
    ) -> Result<()> {
        ensure!(
            roles.roles == self.expected_roles.roles
                && firewall.parameters()? == self.expected_firewall.parameters()?
                && digest(&origin.parameters()?)? == self.expected_model_sha256,
            "CONFLICT: original CM roles, firewall or writer model changed"
        );
        Ok(())
    }

    pub(crate) fn parameters(&self) -> Value {
        json!({"schemaVersion":1, "operationId":self.original.operation_id,
            "state":self.original.phase, "planSha256":self.original.plan_sha256,
            "registeredJvmPid":self.processes[0].unit.pid, "pairedRegistration":true,
            "dispatchAuthorized":false})
    }
}

pub(crate) fn registration_anchor(operation: uuid::Uuid) -> Result<RegistrationAnchor> {
    let root = Path::new(LEGACY_STATE_ROOT);
    let _guard =
        crate::system_change::Guard::observe_existing_shared_for(root, Duration::from_secs(2))?;
    registration_anchor_locked(operation)
}

pub(in crate::nm) fn registration_anchor_locked(
    operation: uuid::Uuid,
) -> Result<RegistrationAnchor> {
    anchor_locked(operation, None, false)
}

pub(in crate::nm) fn fenced_effect_anchor(
    operation: uuid::Uuid,
    plan_sha: &str,
    current: &roles::Observation,
) -> Result<RegistrationAnchor> {
    anchor_locked(operation, Some((plan_sha, current)), false)
}

pub(crate) fn legacy_stop_registration_anchor(
    operation: uuid::Uuid,
    parent_token: &str,
    child_token: &str,
) -> Result<RegistrationAnchor> {
    let root = Path::new(LEGACY_STATE_ROOT);
    let _guard = crate::system_change::Guard::observe_existing_shared_for(root, Duration::from_secs(2))?;
    let store = Store::new(root);
    let original = store.requirements(operation, parent_token, "local-uid:0")?;
    startup::require_legacy_pre_stop(&store, &original, child_token)?;
    anchor_locked(operation, None, true)
}

fn anchor_locked(
    operation: uuid::Uuid,
    effect: Option<(&str, &roles::Observation)>,
    existing_startup: bool,
) -> Result<RegistrationAnchor> {
    let binary = super::running_program_sha()?;
    let (proof, upgrade_sha256) = load_upgrade(&package_path(&binary, "json"))?;
    require_stop(&package_path(&binary, "stop"), &upgrade_sha256)?;
    ensure!(
        proof.operation_id == operation
            && std::env::current_exe()? == Path::new("/usr/bin/yofc-management-agent")
            && binary == proof.candidate_binary_sha256
            && fs::read_to_string("/proc/self/cgroup")?
                .lines()
                .any(|line| line == "0::/system.slice/kura-management-agent.service"),
        "FORBIDDEN: installed replacement and its original Root stop record required"
    );
    let root = Path::new(LEGACY_STATE_ROOT);
    let store = Store::new(root);
    let (journal, plan) = store
        .load()?
        .context("CONFLICT: original handover plan disappeared")?;
    let original = match effect {
        None => {
            let (actual, _) = store.continuity_original_for(operation, existing_startup)?;
            ensure!(
                serde_json::to_value(&actual)? == proof.source["original"],
                "CONFLICT: original Root state changed since Agent replacement"
            );
            actual
        }
        Some((plan_sha, current)) => {
            let anchored: Original = serde_json::from_value(proof.source["original"].clone())?;
            ensure!(
                plan.actor == "local-uid:0"
                    && journal.state == State::Fenced
                    && journal.operation_id == operation
                    && journal.plan_sha256 == plan_sha
                    && anchored.plan_sha256 == plan_sha
                    && anchored.source_digest == plan.baseline.source_digest
                    && plan.template.as_ref() == Some(&anchored.template_receipt),
                "FORBIDDEN: native effect is outside the original fenced Root plan"
            );
            match anchored.phase {
                State::Prepared => store.require_continued_publication(
                    &journal,
                    &plan,
                    &super::root_fence::ContinuedRegistration {
                        agent_instance: current.agent_instance,
                        bridge_epoch: current.bridge_epoch,
                        upgrade_sha256: upgrade_sha256.clone(),
                    },
                )?,
                State::Fenced => ensure!(
                    anchored.network_marker == journal.marker
                        && anchored.firewall_marker == journal.firewall_marker
                        && anchored.root_publication_sha256.as_deref()
                            == Some(store.original_root_publication(&journal, &plan)?.as_str()),
                    "CONFLICT: original already-published Root fence changed"
                ),
                _ => anyhow::bail!("FORBIDDEN: original upgrade did not bind this fence stage"),
            }
            anchored
        }
    };
    let processes = vec![Process::read(UNITS[0])?, Process::read(UNITS[2])?];
    let original_processes = proof.source["processes"]
        .as_array()
        .context("CONFLICT: missing original services")?;
    ensure!(
        original_processes.len() == UNITS.len()
            && pid_namespace()? == proof.source["pidNamespace"]
            && serde_json::to_value(native::epoch::Epoch::capture()?)?
                == proof.source["physicalEpoch"]
            && fs::read_to_string("/proc/self/stat")
                .ok()
                .and_then(|stat| startup::runtime::start_ticks(std::process::id(), &stat).ok())
                .is_some_and(|birth| original_processes[1]["startTicks"]
                    .as_u64()
                    .is_some_and(|old| birth > old)),
        "CONFLICT: original Root, JVM or NM process changed during Agent replacement"
    );
    processes[0].require_across_mounts(&original_processes[0])?;
    processes[1].require_across_mounts(&original_processes[2])?;
    Ok(RegistrationAnchor {
        original,
        processes,
        expected_roles: plan.baseline.roles,
        upgrade_sha256,
        reviewed_batch_sha256: proof.source["reviewedBatchSha256"]
            .as_str()
            .filter(|value| hex(value, 64))
            .context("CONFLICT: original candidate batch digest missing")?
            .to_owned(),
        expected_firewall: plan
            .baseline
            .firewall_source
            .context("CONFLICT: original firewall missing")?,
        expected_model_sha256: plan
            .baseline
            .native_transfer
            .context("CONFLICT: original native transfer missing")?
            .source_model_sha256
            .context("CONFLICT: original writer model missing")?,
    })
}

pub(super) fn require_publisher(journal: &Journal, upgrade_sha: &str) -> Result<()> {
    let binary = super::running_program_sha()?;
    let (proof, sha) = load_upgrade(&package_path(&binary, "json"))?;
    require_stop(&package_path(&binary, "stop"), &sha)?;
    let original = &proof.source["original"];
    ensure!(
        sha == upgrade_sha
            && proof.operation_id == journal.operation_id
            && binary == proof.candidate_binary_sha256
            && original["phase"] == "PREPARED"
            && original["planSha256"] == journal.plan_sha256
            && pid_namespace()? == proof.source["pidNamespace"]
            && serde_json::to_value(native::epoch::Epoch::capture()?)?
                == proof.source["physicalEpoch"],
        "CONFLICT: Root publisher has no matching original upgrade authority"
    );
    let services = proof.source["processes"]
        .as_array()
        .filter(|rows| rows.len() == 3)
        .context("CONFLICT: original upgrade services missing")?;
    Process::read(UNITS[0])?.require_across_mounts(&services[0])?;
    Process::read(UNITS[2])?.require_across_mounts(&services[2])
}

fn installed_core_home() -> Result<PathBuf> {
    let parent = Path::new("/opt/eclipse");
    let alias = parent.join("kura");
    let parent_info = fs::symlink_metadata(parent)?;
    let alias_info = fs::symlink_metadata(&alias)?;
    let home = fs::canonicalize(&alias)?;
    let info = fs::symlink_metadata(&home)?;
    let static_home = alias_info.is_dir() && home == alias;
    let linked_home = alias_info.file_type().is_symlink()
        && home
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("kura_"));
    ensure!(
        parent_info.is_dir()
            && parent_info.uid() == 0
            && parent_info.mode() & 0o022 == 0
            && alias_info.uid() == 0
            && home.parent() == Some(parent)
            && (static_home || linked_home),
        "FORBIDDEN: original packaged Core home layout required"
    );
    ensure!(
        info.is_dir() && info.uid() == 0 && info.mode() & 0o022 == 0,
        "FORBIDDEN: original packaged Core home is unsafe"
    );
    Ok(home)
}

pub(crate) fn seal_startup(operation: &str, request: PathBuf) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "FORBIDDEN: live ordinary seal requires Root"
    );
    let id = template::operation(operation)?;
    let root = Path::new(LEGACY_STATE_ROOT);
    let _guard = crate::system_change::Guard::acquire_existing_for(
        root,
        crate::system_change::Subsystem::NmOwnership,
        Duration::from_secs(3),
    )?;
    let store = Store::new(root);
    let (journal, plan) = store
        .load()?
        .context("NOT_FOUND: original initialized NM plan")?;
    ensure!(
        journal.operation_id == id && journal.state == State::Fenced && plan.actor == "local-uid:0",
        "FORBIDDEN: live ordinary seal requires the original fenced Root"
    );
    startup::require_no_native_child(&store.root, id)?;
    store.require_initialization_ready(&journal, &plan)?;
    let kernel_digest = store.native_applied_digest(&journal)?;
    let transfer = plan
        .baseline
        .native_transfer
        .as_ref()
        .context("CONFLICT: original native transfer missing")?;
    let binary = installed_binary()?;
    let (proof, proof_sha) = load_upgrade(&package_path(&binary, "json"))?;
    require_stop(&package_path(&binary, "stop"), &proof_sha)?;
    store.require_startup_publication(&journal, &plan, &proof_sha)?;
    ensure!(
        proof.operation_id == id
            && proof.source["original"]["planSha256"] == journal.plan_sha256
            && proof.candidate_binary_sha256 == binary
            && proof.new_version == installed_version()?
            && pid_namespace()? == proof.source["pidNamespace"]
            && serde_json::to_value(native::epoch::Epoch::capture()?)?
                == proof.source["physicalEpoch"],
        "CONFLICT: original installed Agent and startup parent no longer pair"
    );
    let processes = proof.source["processes"]
        .as_array()
        .filter(|rows| rows.len() == 3)
        .context("CONFLICT: original startup source processes missing")?;
    let core = Process::read(UNITS[0])?;
    let nm = Process::read(UNITS[2])?;
    core.require_across_mounts(&processes[0])?;
    nm.require_across_mounts(&processes[2])?;
    let home = installed_core_home()?;
    let verify = || -> Result<()> {
        let cmdline = startup::runtime::text(
            &Path::new("/proc")
                .join(core.unit.pid.to_string())
                .join("cmdline"),
            65_536,
        )?;
        ensure!(
            cmdline.as_bytes().last() == Some(&0)
                && !cmdline
                    .split('\0')
                    .any(|arg| arg.starts_with("-Dkura.recovery.request")),
            "FORBIDDEN: recovery JVM cannot authorize ordinary startup"
        );
        ensure!(
            transfer.acknowledge(&observe_kernel()?, false)? == kernel_digest
                && Process::read(UNITS[0])? == core
                && Process::read(UNITS[2])? == nm
                && installed_core_home()? == home,
            "CONFLICT: original loaded JVM, installed home or initialized kernel changed"
        );
        store.require_initialization_ready(&journal, &plan)
    };
    verify()?;
    let mut receipt = crate::recovery::ordinary_profile::seal_live_nm_source(
        request,
        PathBuf::from("/etc/kura-management-agent/nm-ownership-profile.json"),
        &core.unit,
        verify,
    )?;
    receipt["operationId"] = json!(id);
    receipt["planSha256"] = json!(journal.plan_sha256);
    receipt["initializedKernelSha256"] = json!(kernel_digest);
    receipt["runningJvmPid"] = json!(core.unit.pid);
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_process(unit: &str) -> Process {
        Process {
            unit: Unit {
                unit: unit.into(),
                active_state: "active".into(),
                pid: 32,
                invocation_id: "a".repeat(32),
                control_group: format!("/system.slice/{unit}"),
                unit_file_state: "enabled".into(),
            },
            start_ticks: 123,
            proc_device: 10,
            proc_inode: 11,
            uid: 997,
            gid: 995,
        }
    }

    #[test]
    fn continuity_binds_kernel_birth_credentials_and_unit_even_when_procfs_is_remounted() {
        let process = sample_process(UNITS[0]);
        let mut origin = serde_json::to_value(&process).unwrap();
        origin["procDevice"] = json!(12);
        origin["procInode"] = json!(13);
        process.require_across_mounts(&origin).unwrap();
        for (key, value) in [
            ("startTicks", json!(124)),
            ("uid", json!(0)),
            ("gid", json!(0)),
        ] {
            let mut changed = origin.clone();
            changed[key] = value;
            assert!(process.require_across_mounts(&changed).is_err());
        }
        origin["unit"]["invocationId"] = json!("b".repeat(32));
        assert!(process.require_across_mounts(&origin).is_err());
    }

    #[test]
    fn predecessor_continuity_requires_the_same_pinned_pid_namespace_to_compare_captures() {
        let original = json!({
            "pidNamespace": {"device": 4, "inode": 4026531836_u64},
            "processes": UNITS.map(sample_process),
        });
        let mut current = original.clone();
        current["processes"][0]["procInode"] = json!(51);
        current["processes"][2]["procInode"] = json!(52);
        compare_predecessor_services(&original, &current).unwrap();

        for (path, value) in [
            ("/pidNamespace/inode", json!(4026531837_u64)),
            ("/processes/0/unit/pid", json!(33)),
            (
                "/processes/2/unit/controlGroup",
                json!("/system.slice/other.service"),
            ),
        ] {
            let mut changed = current.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(compare_predecessor_services(&original, &changed).is_err());
        }
        let mut historical = original.clone();
        historical.as_object_mut().unwrap().remove("pidNamespace");
        compare_predecessor_services(&historical, &original).unwrap();
        assert!(compare_predecessor_services(&historical, &current).is_err());
    }
}
