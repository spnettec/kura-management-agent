//! A live predecessor without an ordinary-profile Java identity is bound by
//! its retained Root effect, kernel peer and actual installed unit definition.
use super::*;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::nm) struct Receipt {
    schema_version: u8,
    operation_id: uuid::Uuid,
    plan_sha256: String,
    unit: crate::system_control::Unit,
    process_start_ticks: u64,
    profile_sha256: String,
    stop_policy: crate::system_control::StopPolicy,
    upgrade_sha256: String,
    initialization_receipt_sha256: String,
    roles: roles::Observation,
}

impl Receipt {
    pub(in crate::nm) fn new(
        operation_id: uuid::Uuid,
        plan_sha256: String,
        unit: crate::system_control::Unit,
        process_start_ticks: u64,
        profile_sha256: String,
        stop_policy: crate::system_control::StopPolicy,
        upgrade_sha256: String,
        initialization_receipt_sha256: String,
        roles: roles::Observation,
    ) -> Self {
        Self {
            schema_version: 1,
            operation_id,
            plan_sha256,
            unit,
            process_start_ticks,
            profile_sha256,
            stop_policy,
            upgrade_sha256,
            initialization_receipt_sha256,
            roles,
        }
    }

    fn require(&self, original: &Requirements) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.operation_id == original.operation
                && self.plan_sha256 == original.plan
                && self.roles.roles == original.baseline.roles.roles
                && self.unit.unit == "kura.service"
                && self.unit.running()
                && self.process_start_ticks > 0
                && hex(&self.profile_sha256, 64)
                && hex(&self.upgrade_sha256, 64)
                && hex(&self.initialization_receipt_sha256, 64),
            "CONFLICT: original legacy JVM source receipt binding"
        );
        self.stop_policy.validate()?;
        self.roles.validate()
    }

    fn parameters(&self, sha: &str) -> Value {
        json!({"schemaVersion":1,"operationId":self.operation_id,"state":"LEGACY_JVM_BOUND",
            "scope":"original-live-legacy-jvm-root-and-bridge",
            "originalPlanSha256":self.plan_sha256,"runningJvmPid":self.unit.pid,
            "profileSha256":self.profile_sha256,"initializationReceiptSha256":self.initialization_receipt_sha256,
            "receiptSha256":sha,"stopDispatched":false})
    }
}

fn path(root: &Path, operation: uuid::Uuid) -> PathBuf {
    root.join(format!("{operation}.legacy-startup-source.json"))
}

pub(in crate::nm) fn require_unbound(root: &Path, operation: uuid::Uuid) -> Result<()> {
    ensure!(
        !present(&path(root, operation))?,
        "OUTCOME_UNKNOWN: query the original legacy JVM source receipt"
    );
    require_no_native_child(root, operation)
}

pub(in crate::nm) fn bind(root: &Path, original: &Requirements, receipt: Receipt) -> Result<Value> {
    receipt.require(original)?;
    require_unbound(root, original.operation)?;
    let bytes = serde_json::to_vec(&receipt)?;
    durable::publish_new(
        &path(root, original.operation),
        &bytes,
        FileMetadata::private(),
    )
    .context("OUTCOME_UNKNOWN: query the original legacy JVM source receipt")?;
    Ok(receipt.parameters(&durable::hash(&bytes)))
}

pub(in crate::nm) fn original(root: &Path, original: &Requirements) -> Result<Value> {
    let bytes = read(&path(root, original.operation))?;
    let receipt: Receipt = serde_json::from_slice(&bytes)?;
    receipt.require(original)?;
    Ok(receipt.parameters(&durable::hash(&bytes)))
}
