//! The installed legacy Agent can attest the source from its registered JVM,
//! while only the separate Root publisher can see the actual fence directory.
use super::*;
#[cfg(target_os = "linux")]
use crate::system_change::{Guard, Subsystem};

#[cfg(target_os = "linux")]
pub(in crate::nm) fn running_program_sha() -> Result<String> {
    let mut binary = File::open("/proc/self/exe")?;
    let size = binary.metadata()?.len();
    ensure!(size > 0 && size <= 64 * 1024 * 1024, "FORBIDDEN: unexpected installed binary size");
    let mut bytes = Vec::new();
    (&mut binary).take(size + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == size, "CONFLICT: running binary changed");
    Ok(durable::hash(&bytes))
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Arm {
    schema_version: u8,
    operation_id: uuid::Uuid,
    plan_sha256: String,
    agent_instance: uuid::Uuid,
    bridge_epoch: u64,
}

impl Arm {
    fn new(journal: &Journal, plan: &Plan) -> Self {
        Self {
            schema_version: 1,
            operation_id: journal.operation_id,
            plan_sha256: journal.plan_sha256.clone(),
            agent_instance: plan.baseline.roles.agent_instance,
            bridge_epoch: plan.baseline.roles.bridge_epoch,
        }
    }
}

impl Store {
    #[cfg(target_os = "linux")]
    pub(super) fn original_root_publication(&self, journal: &Journal, plan: &Plan) -> Result<String> {
        let arm = read(&self.artifact(journal.operation_id, "root-fence-arm"))?;
        let dispatch = read(&self.artifact(journal.operation_id, "root-fence-dispatch"))?;
        ensure!(arm == dispatch && serde_json::from_slice::<Arm>(&arm)? == Arm::new(journal, plan),
            "CONFLICT: original Root fence publication differs from the original plan");
        Ok(durable::hash(&dispatch))
    }

    pub(in crate::nm) fn arm_root_fence(
        &self, id: uuid::Uuid, token: &str, actor: &str,
        reobserve: impl FnOnce() -> Result<Baseline>,
    ) -> Result<Value> {
        let (mut journal, plan) = self.load()?.context("NOT_FOUND: original paired fence")?;
        Self::authorize(&journal, token, &plan, actor)?;
        ensure!(actor == "local-uid:0" && journal.operation_id == id,
            "FORBIDDEN: original local Root operation required");
        ensure!(journal.state == State::Prepared, "OUTCOME_UNKNOWN: query the original fence");
        ensure!(plan.schema_version == 5 && plan.baseline.firewall_fence.is_some(),
            "UNSUPPORTED: complete original native pair required");
        self.require_no_root_fence_arm(id)?;
        ensure!(reobserve()? == plan.baseline, "CONFLICT: original registered source changed");
        self.require_original_firewall_fence(&plan)?;
        let arm = serde_json::to_vec(&Arm::new(&journal, &plan))?;
        durable::publish_new(&self.artifact(id, "root-fence-arm"), &arm, FileMetadata::private())
            .context("OUTCOME_UNKNOWN: preserve the original Root fence arm")?;
        journal.state = State::FenceIntent;
        durable::json(&self.journal_path(), &journal)
            .context("OUTCOME_UNKNOWN: preserve the original Root fence journal")?;
        Ok(json!({"schemaVersion":1,"operationId":id,"armSha256":durable::hash(&arm)}))
    }

    pub(super) fn prepared_root_fence(&self, id: uuid::Uuid) -> Result<Journal> {
        let (journal, plan) = self.load()?.context("NOT_FOUND: original paired fence")?;
        ensure!(journal.operation_id == id && plan.actor == "local-uid:0",
            "FORBIDDEN: original local Root operation required");
        ensure!(journal.state == State::Prepared, "OUTCOME_UNKNOWN: query the original fence");
        ensure!(plan.schema_version == 5 && plan.baseline.firewall_fence.is_some(),
            "UNSUPPORTED: complete original native pair required");
        self.require_no_root_fence_arm(id)?;
        self.require_original_firewall_fence(&plan)?;
        self.require_fence_destination()?;
        Ok(journal)
    }

    pub(super) fn require_no_root_fence_arm(&self, id: uuid::Uuid) -> Result<()> {
        ensure!([ "root-fence-arm", "root-fence-dispatch" ].into_iter().all(|kind|
            fs::symlink_metadata(self.artifact(id, kind)).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)),
            "OUTCOME_UNKNOWN: preserve the original Root fence arm");
        Ok(())
    }

    pub(super) fn publish_root_fence(&self, original: &Journal, arm_sha256: &str) -> Result<Value> {
        let (journal, plan) = self.load()?.context("OUTCOME_UNKNOWN: original fence disappeared")?;
        ensure!(journal.operation_id == original.operation_id && journal.plan_sha256 == original.plan_sha256
            && journal.token == original.token && journal.state == State::FenceIntent,
            "OUTCOME_UNKNOWN: original Root fence journal changed");
        let id = journal.operation_id;
        let arm = read(&self.artifact(id, "root-fence-arm"))?;
        ensure!(durable::hash(&arm) == arm_sha256
            && serde_json::from_slice::<Arm>(&arm)? == Arm::new(&journal, &plan),
            "OUTCOME_UNKNOWN: original Root fence arm changed");
        self.require_original_firewall_fence(&plan)?;
        self.require_fence_destination()?;
        // A lost publisher result can only be adjudicated against the original
        // markers. Exclusive publication prevents a second attempt after a crash.
        durable::publish_new(
            &self.artifact(id, "root-fence-dispatch"), &arm, FileMetadata::private(),
        ).context("OUTCOME_UNKNOWN: preserve the original Root publisher dispatch")?;
        self.publish_fence_pair(journal, &plan)
    }
}

#[cfg(target_os = "linux")]
pub(crate) async fn publish(operation: &str, agent_pid: i32) -> Result<Value> {
    use yofc_management_protocol::{LocalFrame, read_frame, write_frame};
    use tokio::net::UnixStream;
    use std::time::Duration;

    ensure!(unsafe { libc::geteuid() } == 0 && agent_pid > 1,
        "FORBIDDEN: installed Root publisher and paired Agent required");
    let id = template::operation(operation)?;
    let root = Path::new(LEGACY_STATE_ROOT);
    let store = Store::new(root);
    let original = {
        let _guard = Guard::acquire(root, Subsystem::NmOwnership)?;
        store.prepared_root_fence(id)?
    };
    let mut stream = UnixStream::connect("/run/kura-management-agent/control.sock").await
        .context("UNSUPPORTED: paired installed Agent socket unavailable")?;
    let credentials = stream.peer_cred()?;
    ensure!(credentials.pid() == Some(agent_pid) && credentials.uid() == 0
        && credentials.gid() == unsafe { libc::getegid() },
        "FORBIDDEN: socket does not belong to the paired Agent process");
    let birth = process_start(agent_pid)?;
    let program = running_program_sha()?;
    let request = LocalFrame {
        version: 1, kind: "request".into(), request_id: uuid::Uuid::new_v4().to_string(),
        method: "network.nm.ownership.fence.arm".into(),
        params: Some(json!({"operationId":id,"confirmationToken":original.token})),
        result: None, error: None,
    };
    let response = tokio::time::timeout(Duration::from_secs(75), async {
        write_frame(&mut stream, &request).await?;
        read_frame(&mut stream).await
    }).await.context("OUTCOME_UNKNOWN: original Root arm timed out")?
        .context("OUTCOME_UNKNOWN: original Root arm reply")?;
    ensure!(response.version == 1 && response.kind == "response" && response.request_id == request.request_id
        && response.method == request.method && response.error.is_none(),
        "OUTCOME_UNKNOWN: original Root arm reply was not confirmed");
    let result = response.result.context("OUTCOME_UNKNOWN: original Root arm result missing")?;
    let arm = result["armSha256"].as_str().filter(|sha| hex(sha, 64))
        .context("OUTCOME_UNKNOWN: original Root arm digest missing")?;
    ensure!(result == json!({"schemaVersion":1,"operationId":id,"armSha256":arm,"binarySha256":program}),
        "OUTCOME_UNKNOWN: original Root arm result or running binary changed");
    let _guard = Guard::acquire(root, Subsystem::NmOwnership)?;
    ensure!(process_start(agent_pid).ok() == Some(birth),
        "OUTCOME_UNKNOWN: original Agent process changed before publication");
    store.publish_root_fence(&original, arm)
        .context("OUTCOME_UNKNOWN: adjudicate the original Root fence")
}

#[cfg(target_os = "linux")]
fn process_start(pid: i32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(stat.rsplit_once(')').context("CONFLICT: paired Agent process stat")?.1
        .split_whitespace().nth(19).context("CONFLICT: paired Agent start identity")?.parse()?)
}
