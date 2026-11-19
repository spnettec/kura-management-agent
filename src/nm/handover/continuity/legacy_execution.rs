//! Installed Root startup runner. Effect admission is serialized with the
//! original journal. Only the newly admitted command can issue a unit job.
use super::*;
use crate::system_change::{Guard, Subsystem};
use tokio::net::UnixStream;
use yofc_management_protocol::{LocalFrame, read_frame, write_frame};

const ACTOR: &str = "local-uid:0";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const BINARY: &str = "/usr/bin/yofc-management-agent";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionPhase {
    Original,
    Prepare,
    Stop,
    Publish,
    Start,
}

impl std::str::FromStr for ExecutionPhase {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "original" => Ok(Self::Original),
            "prepare" => Ok(Self::Prepare),
            "stop" => Ok(Self::Stop),
            "publish" => Ok(Self::Publish),
            "start" => Ok(Self::Start),
            _ => anyhow::bail!("INVALID_ARGUMENT: fixed original startup phase required"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Approval {
    confirmation_token: String,
    startup_confirmation_token: Option<String>,
}

impl Approval {
    fn read(phase: ExecutionPhase) -> Result<Self> {
        let mut raw = Vec::new();
        std::io::stdin().take(1025).read_to_end(&mut raw)?;
        ensure!(raw.len() <= 1024, "RESOURCE_EXHAUSTED: startup approval bounds");
        let approval: Self = serde_json::from_slice(&raw)
            .context("INVALID_ARGUMENT: original startup approval fields")?;
        let child_is_required = matches!(phase, ExecutionPhase::Stop | ExecutionPhase::Publish | ExecutionPhase::Start);
        ensure!(
            hex(&approval.confirmation_token, 32)
                && if child_is_required {
                    approval.startup_confirmation_token.as_ref().is_some_and(|token| hex(token, 32))
                } else { approval.startup_confirmation_token.is_none() },
            "INVALID_ARGUMENT: original startup approval shape"
        );
        Ok(approval)
    }

    fn child(&self) -> Result<&str> {
        self.startup_confirmation_token.as_deref()
            .context("INVALID_ARGUMENT: original startup approval required")
    }
}

struct Source {
    root: Original,
    core: Option<Process>,
    agent: Process,
    nm: Process,
    installed_binary: String,
    anchored_upgrade: String,
    generation: u64,
}

impl Source {
    fn installed(store: &Store, original: &Requirements, phase: ExecutionPhase) -> Result<Self> {
        let (root, transfer) = store.continuity_original_for(original.operation, phase != ExecutionPhase::Prepare)?;
        let initialized = root.initialized.as_ref()
            .context("CONFLICT: original startup requires committed initialization")?;
        let kernel = observe_kernel()?;
        ensure!(transfer.acknowledge(&kernel, false)? == initialized.kernel_sha256,
            "CONFLICT: original initialized Netfilter effect changed");

        let installed_binary = installed_binary()?;
        ensure!(installed_binary == super::super::running_program_sha()?,
            "FORBIDDEN: installed original Root startup executable required");
        let version = installed_version()?;
        let (upgrade, upgrade_sha) = load_upgrade(&package_path(&installed_binary, "json"))?;
        require_stop(&package_path(&installed_binary, "stop"), &upgrade_sha)?;
        ensure!(
            upgrade.operation_id == original.operation
                && upgrade.new_version == version
                && upgrade.candidate_binary_sha256 == installed_binary
                && upgrade.source["original"] == serde_json::to_value(&root)?
                && upgrade.source["pidNamespace"] == pid_namespace()?
                && upgrade.source["physicalEpoch"] == serde_json::to_value(native::epoch::Epoch::capture()?)?
                && upgrade.source["reviewedBatchSha256"] == initialized.applied_batch_sha256,
            "FORBIDDEN: installed startup executable is outside the original initialized Root"
        );
        let store_root = &store.root;
        let anchored_upgrade = startup::legacy_source::anchored_upgrade(store_root, original)?;
        require_upgrade_ancestry(&upgrade, &upgrade_sha, &anchored_upgrade)?;
        let rows = upgrade.source["processes"].as_array().filter(|rows| rows.len() == UNITS.len())
            .context("CONFLICT: installed source service identities missing")?;
        let core = if matches!(phase, ExecutionPhase::Prepare | ExecutionPhase::Stop) {
            let core = Process::read(UNITS[0])?;
            core.require_across_mounts(&rows[0])?;
            Some(core)
        } else { None };
        let agent = Process::read(AGENT_UNIT)?;
        require_installed_agent(&agent)?;
        ensure!(rows[1]["startTicks"].as_u64().is_some_and(|old| agent.start_ticks > old),
            "CONFLICT: current Agent is not the installed successor");
        let nm = Process::read(UNITS[2])?;
        nm.require_across_mounts(&rows[2])?;
        Ok(Self {
            root, core, agent, nm, installed_binary, anchored_upgrade,
            generation: kernel["kernelGeneration"].as_u64()
                .context("CONFLICT: original Netfilter generation missing")?,
        })
    }

    fn live(&self) -> Result<startup::legacy_source::Live<'_>> {
        let core = self.core.as_ref().context("CONFLICT: original legacy JVM not present")?;
        Ok(startup::legacy_source::Live {
            unit: &core.unit,
            start_ticks: core.start_ticks,
            upgrade: &self.anchored_upgrade,
            initialization: &self.root.initialized.as_ref()
                .context("CONFLICT: original initialization missing")?.policy_receipt_sha256,
        })
    }

    fn require_same(&self, later: &Self) -> Result<()> {
        ensure!(
            self.root == later.root && self.installed_binary == later.installed_binary
                && self.anchored_upgrade == later.anchored_upgrade && self.generation == later.generation,
            "CONFLICT: original Root startup source changed before admission"
        );
        later.agent.require_across_mounts(&serde_json::to_value(&self.agent)?)?;
        later.nm.require_across_mounts(&serde_json::to_value(&self.nm)?)?;
        if let Some(core) = &self.core {
            later.core.as_ref().context("CONFLICT: original Core disappeared")?
                .require_across_mounts(&serde_json::to_value(core)?)?;
        }
        Ok(())
    }

    async fn observe_registration(&self, original: &Requirements, approval: &Approval, phase: ExecutionPhase) -> Result<()> {
        let (method, params) = if phase == ExecutionPhase::Prepare {
            ("network.nm.ownership.upgrade.verify", json!({"operationId":original.operation}))
        } else {
            ("network.nm.ownership.startup.legacy.stop-review", json!({"operationId":original.operation,
                "confirmationToken":approval.confirmation_token,"startupConfirmationToken":approval.child()?}))
        };
        let mut stream = connect_agent(&self.agent).await?;
        let request = LocalFrame {
            version: 1, kind: "request".into(), request_id: uuid::Uuid::new_v4().to_string(),
            method: method.into(), params: Some(params), result: None, error: None,
        };
        let response = tokio::time::timeout(Duration::from_secs(35), async {
            write_frame(&mut stream, &request).await?;
            read_frame(&mut stream).await
        }).await.context("TIMEOUT: original startup registration read")??;
        ensure!(
            response.version == 1 && response.kind == "response"
                && response.request_id == request.request_id && response.method == request.method
                && response.error.is_none()
                && response.result == Some(json!({"schemaVersion":1, "operationId":original.operation,"state":"FENCED",
                    "planSha256":original.plan,"registeredJvmPid":self.live()?.unit.pid,
                    "pairedRegistration":true,"dispatchAuthorized":false})),
            "CONFLICT: original Agent/JVM registration did not authorize a fresh observation"
        );
        Ok(())
    }

    fn require_current_jvm_and_agent(&self) -> Result<()> {
        if let Some(core) = &self.core {
            Process::read(UNITS[0])?.require_across_mounts(&serde_json::to_value(core)?)?;
        }
        let agent = Process::read(AGENT_UNIT)?;
        agent.require_across_mounts(&serde_json::to_value(&self.agent)?)?;
        require_installed_agent(&agent)
    }
}

fn require_installed_agent(agent: &Process) -> Result<()> {
    ensure!(agent.unit.control_group == "/system.slice/kura-management-agent.service",
        "FORBIDDEN: installed Agent systemd process required");
    let proc = PathBuf::from(format!("/proc/{}/exe", agent.unit.pid));
    let program = fs::metadata(&proc)?;
    let installed = fs::symlink_metadata(BINARY)?;
    ensure!(fs::read_link(&proc)? == Path::new(BINARY)
        && (program.dev(), program.ino()) == (installed.dev(), installed.ino()),
        "CONFLICT: original running Agent is not the installed executable");
    Ok(())
}

async fn connect_agent(agent: &Process) -> Result<UnixStream> {
    let socket = UnixStream::connect("/run/kura-management-agent/control.sock").await?;
    let peer = socket.peer_cred()?;
    ensure!(peer.pid().and_then(|pid| u32::try_from(pid).ok()) == Some(agent.unit.pid)
            && peer.uid() == agent.uid && peer.gid() == agent.gid,
        "FORBIDDEN: actual paired Agent control socket required");
    Ok(socket)
}

fn require_upgrade_ancestry(upgrade: &Upgrade, digest: &str, anchored: &str) -> Result<()> {
    if digest == anchored { return Ok(()); }
    let mut previous = None;
    for _ in 0..32 {
        let current = previous.as_ref().unwrap_or(upgrade);
        let (old, sha) = previous_upgrade(&current.old_binary_sha256, &current.old_version)?
            .context("FORBIDDEN: original startup upgrade predecessor missing")?;
        ensure!(current.previous_sha256.as_ref() == Some(&sha)
            && old.operation_id == upgrade.operation_id
            && old.source["original"] == upgrade.source["original"]
            && old.source["physicalEpoch"] == upgrade.source["physicalEpoch"]
            && old.source["reviewedBatchSha256"] == upgrade.source["reviewedBatchSha256"],
            "FORBIDDEN: startup evidence must follow the original initialized package chain");
        compare_predecessor_services(&old.source, &upgrade.source)?;
        if sha == anchored { return Ok(()); }
        // The next record is resolved from the just-verified predecessor.
        previous = Some(old);
    }
    anyhow::bail!("FORBIDDEN: original startup source is absent from its installed package chain")
}

pub(crate) async fn execute_legacy_startup(operation: &str, phase: ExecutionPhase) -> Result<Value> {
    ensure!(unsafe { libc::geteuid() } == 0 && std::env::current_exe()? == Path::new(BINARY),
        "FORBIDDEN: installed local Root startup executable required");
    let id = template::operation(operation)?;
    let approval = Approval::read(phase)?;
    let root = Path::new(LEGACY_STATE_ROOT);
    let store = Store::new(root);
    let systemctl = Path::new(SYSTEMCTL);

    let (original, reviewed) = {
        let _guard = Guard::observe_existing_shared_for(root, Duration::from_secs(3))?;
        if phase == ExecutionPhase::Original {
            let (journal, plan) = store.load()?.context("NOT_FOUND: original startup parent")?;
            Store::authorize(&journal, &approval.confirmation_token, &plan, ACTOR)?;
            ensure!(journal.operation_id == id, "FORBIDDEN: original Root operation required");
            let result = startup::original(&store.root, id, &journal.plan_sha256, None)?
                .context("NOT_FOUND: original legacy startup child")?;
            ensure!(result["schemaVersion"] == 5, "FORBIDDEN: original typed legacy startup required");
            return Ok(result);
        }
        let original = store.requirements(id, &approval.confirmation_token, ACTOR)?;
        ensure!(!original.recovering(), "OUTCOME_UNKNOWN: original activation already issued");
        if phase == ExecutionPhase::Prepare {
            ensure!(startup::original(&store.root, id, &original.plan, None)?.is_none(),
                "OUTCOME_UNKNOWN: query the original startup proposal");
        } else {
            let status = startup::require_legacy_child(&store, &original, approval.child()?)?;
            if phase == ExecutionPhase::Stop && status.get("stop").is_some() {
                return Ok(status);
            }
        }
        let source = Source::installed(&store, &original, phase)?;
        if matches!(phase, ExecutionPhase::Prepare | ExecutionPhase::Stop) {
            source.observe_registration(&original, &approval, phase).await?;
        } else {
            connect_agent(&source.agent).await?;
        }
        (original, source)
    };

    let guard = Guard::acquire_existing_for(root, Subsystem::NmOwnership, Duration::from_secs(4))?;
    ensure!(store.requirements(id, &approval.confirmation_token, ACTOR)? == original,
        "CONFLICT: original startup parent changed before Root admission");
    let fresh = Source::installed(&store, &original, phase)?;
    reviewed.require_same(&fresh)?;

    let mut result = match phase {
        ExecutionPhase::Prepare => startup::prepare_legacy(&store, &original, &fresh.live()?)?,
        ExecutionPhase::Stop => {
            let command = startup::stop_legacy(&store, &original, approval.child()?, &fresh.live()?)?;
            drop(guard);
            fresh.require_current_jvm_and_agent()
                .context("OUTCOME_UNKNOWN: admitted original Core stop, do not redispatch")?;
            command.execute()?
        }
        ExecutionPhase::Publish => {
            match startup::publication_begin(&store.root, &original, ACTOR, approval.child()?, systemctl)? {
                startup::PublicationStep::Observed(value) => value,
                startup::PublicationStep::Dispatch(command) => {
                    drop(guard);
                    fresh.require_current_jvm_and_agent()
                        .context("OUTCOME_UNKNOWN: admitted original file publication, do not redispatch")?;
                    (*command).execute()?
                }
            }
        }
        ExecutionPhase::Start => {
            match startup::start_begin(&store.root, &original, ACTOR, approval.child()?, systemctl)? {
                startup::StartStep::Observed(value) => value,
                startup::StartStep::Dispatch(command) => {
                    drop(guard);
                    fresh.require_current_jvm_and_agent()
                        .context("OUTCOME_UNKNOWN: admitted original Core start, do not redispatch")?;
                    (*command).execute()?
                }
            }
        }
        // Read-only original queries return before effect admission.
        ExecutionPhase::Original => unreachable!(),
    };
    if phase != ExecutionPhase::Prepare {
        result.as_object_mut().expect("startup result must be an object").remove("confirmationToken");
    }
    Ok(result)
}
