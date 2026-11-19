//! Read-only evidence for replacing a legacy Agent during its original
//! handover. This command does not grant write authority to a new registration.
use super::*;
use crate::system_control::{Unit, inspect_unit};

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

#[derive(Serialize, PartialEq, Eq)]
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

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
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
}

impl Store {
    pub(super) fn continuity_original(
        &self,
        operation: uuid::Uuid,
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
            matches!(journal.state, State::Prepared | State::Fenced)
                && journal.native.is_none()
                && journal.initialization.is_none(),
            "OUTCOME_UNKNOWN: settle the original issued effect before Agent continuity"
        );
        startup::require_no_native_child(&self.root, operation)?;
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
            },
            transfer.clone(),
        ))
    }
}

pub(crate) fn inspect(operation: &str) -> Result<Value> {
    review(operation, false)
}

fn pid_namespace() -> Result<Value> {
    let namespace = File::open("/proc/thread-self/ns/pid")?.metadata()?;
    ensure!(
        namespace.ino() != 0 && namespace.dev() != 0,
        "CONFLICT: current PID namespace is unavailable"
    );
    Ok(json!({"device":namespace.dev(),"inode":namespace.ino()}))
}

fn review(operation: &str, stopped: bool) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "FORBIDDEN: installed legacy Root required"
    );
    let id = template::operation(operation)?;
    let root = Path::new(LEGACY_STATE_ROOT);
    let _guard = crate::system_change::Guard::observe_existing_shared(root)?;
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
    let kernel = native::raw::observe(
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
    )?;
    let batch = transfer.batch(&kernel, false)?;
    let generation = batch["expectedGeneration"]
        .as_u64()
        .context("UNSUPPORTED: original physical Netfilter generation required")?;
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
        "netfilterGeneration":generation, "reviewedBatchSha256":digest(&batch)?,
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

fn compare_predecessor(previous: &Upgrade, source: &Value) -> Result<()> {
    ensure!(
        previous.source["original"] == source["original"]
            && previous.source["physicalEpoch"] == source["physicalEpoch"]
            && previous.source["reviewedBatchSha256"] == source["reviewedBatchSha256"],
        "CONFLICT: predecessor does not bind the original Root plan and Netfilter source"
    );
    let old = previous.source["processes"]
        .as_array()
        .context("CONFLICT: predecessor services missing")?;
    let new = source["processes"]
        .as_array()
        .context("CONFLICT: current services missing")?;
    ensure!(
        old.len() == 3 && new.len() == 3 && old[0] == new[0] && old[2] == new[2],
        "CONFLICT: predecessor JVM or NM changed in the Root procfs view"
    );
    ensure!(
        previous
            .source
            .get("pidNamespace")
            .is_none_or(|ns| ns == &source["pidNamespace"]),
        "CONFLICT: predecessor PID namespace changed"
    );
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
    if let Some((old, _)) = &predecessor {
        compare_predecessor(old, &source)?;
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
    if let Some((old, _)) = &predecessor {
        compare_predecessor(old, &proof.source)?;
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
    let (original, transfer) = store.continuity_original(operation)?;
    let (_, plan) = store
        .load()?
        .context("CONFLICT: original handover plan disappeared")?;
    let processes = vec![Process::read(UNITS[0])?, Process::read(UNITS[2])?];
    let original_processes = proof.source["processes"]
        .as_array()
        .context("CONFLICT: missing original services")?;
    ensure!(
        original_processes.len() == UNITS.len()
            && serde_json::to_value(&original)? == proof.source["original"]
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
        expected_model_sha256: transfer
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuity_binds_kernel_birth_credentials_and_unit_even_when_procfs_is_remounted() {
        let process = Process {
            unit: Unit {
                unit: UNITS[0].into(),
                active_state: "active".into(),
                pid: 32,
                invocation_id: "a".repeat(32),
                control_group: "/system.slice/kura.service".into(),
                unit_file_state: "enabled".into(),
            },
            start_ticks: 123,
            proc_device: 10,
            proc_inode: 11,
            uid: 997,
            gid: 995,
        };
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
}
