//! Read-only evidence for replacing a legacy Agent during its original
//! handover. This command does not grant write authority to a new registration.
use super::*;
use crate::system_control::{Unit, inspect_unit};

const UNITS: [&str; 3] = [
    "kura.service",
    "kura-management-agent.service",
    "NetworkManager.service",
];

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
        UNITS
            .iter()
            .map(|name| Process::read(name))
            .collect::<Result<Vec<_>>>()
    };
    let before = processes()?;
    let epoch = native::epoch::Epoch::capture()?;
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
        processes()? == before && store.continuity_original(id)?.0 == original,
        "CONFLICT: original Root plan or service processes changed during observation"
    );
    epoch.require(&native::epoch::Epoch::capture()?)?;
    Ok(json!({
        "schemaVersion":1, "original":original, "physicalEpoch":epoch, "processes":before,
        "netfilterGeneration":generation, "reviewedBatchSha256":digest(&batch)?,
        "dispatchAuthorized":false,
    }))
}
