//! Original-child ordinary JVM/Core/network-writer proof. Historical completion
//! stays queryable; every new activation samples the live witnesses again.
use super::*;

#[derive(Clone,PartialEq,Eq)]
pub(in crate::nm) struct Challenge {
    pub(in crate::nm) spec:roles::StartupSpec,pub(in crate::nm) profile_id:String,
    pub(in crate::nm) unit:crate::system_control::Unit,
}
pub(in crate::nm) struct Witness {
    pub(in crate::nm) roles:roles::Observation,pub(in crate::nm) association:roles::StartupAssociation,
    pub(in crate::nm) owner:roles::Owner,
}
impl Witness {
    pub(in crate::nm) fn require(&self,original:&Requirements,challenge:&Challenge)->Result<()> {
        self.owner.require_complete()?;
        ensure!(self.roles.roles==original.baseline.roles.roles,"CONFLICT: original CM source differs during startup completion");
        self.association.require(&challenge.spec,&challenge.profile_id,challenge.unit.pid,&self.roles)?;
        original.verify(&self.owner)?;self.owner.require_registration(&self.roles)
    }
}
pub(in crate::nm) enum Step {Observed(Value),Challenge(Box<Challenge>)}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Receipt {
    schema_version:u8,startup_plan_sha256:String,parent_template_sha256:String,start_receipt_sha256:String,
    spec:roles::StartupSpec,unit:crate::system_control::Unit,
    roles:roles::Observation,association:roles::StartupAssociation,owner:roles::Owner,
}
fn path(root:&Path,id:uuid::Uuid)->PathBuf {root.join(format!("{id}.startup-completion.json"))}
fn challenge(root:&Path,plan:&Plan,journal:&Journal)->Result<Challenge> {
    ensure!(plan.schema_version>=4,"UNSUPPORTED: historical startup has no terminal execution authority");
    let unit=start::acknowledged_unit(root,plan,journal)?;
    let config:Config=serde_json::from_str(&plan.generated_profile)?;
    let nonce=durable::hash(format!("{}\n{}\n{}\nnetwork-startup-new-jvm-core-v1",journal.plan_sha256,
        journal.confirmation_token,journal.start_receipt_sha256.as_deref().context("OUTCOME_UNKNOWN: original start receipt missing")?).as_bytes());
    Ok(Challenge{spec:roles::StartupSpec::new(plan.operation_id,journal.plan_sha256.clone(),nonce)?,profile_id:config.profile_id,unit})
}
fn require_new_source(root:&Path,plan:&Plan,association:&roles::StartupAssociation,current:&roles::Observation)->Result<()> {
    if plan.legacy_source.is_some() {
        // The old JVM could not issue an ordinary observer ID. The new
        // association is bound to the acknowledged fresh unit invocation,
        // and the old actual bridge registration must have been replaced.
        return legacy_source::Binding::open(root,plan.operation_id)?.require_successor(plan,current);
    }
    let old=serde_json::from_slice::<AssociationProof>(&read(&proof_path(root,plan.operation_id))?)?;
    association.require_new_observer(&old.association)
}
fn record(root:&Path,plan:&Plan,journal:&Journal)->Result<Option<(Receipt,String)>> {
    let file=path(root,plan.operation_id);
    if !present(&file)? {
        ensure!(journal.completion_receipt_sha256.is_none(),"OUTCOME_UNKNOWN: acknowledged startup completion receipt missing");return Ok(None);
    }
    let bytes=read(&file)?;let hash=durable::hash(&bytes);let receipt:Receipt=serde_json::from_slice(&bytes)?;
    let expected=challenge(root,plan,journal)?;
    ensure!(receipt.schema_version==1 && receipt.startup_plan_sha256==journal.plan_sha256
        && hex(&receipt.parent_template_sha256,64) && journal.start_receipt_sha256.as_ref()==Some(&receipt.start_receipt_sha256)
        && receipt.spec==expected.spec && receipt.unit==expected.unit
        && plan.source_roles_sha256.as_deref()==Some(digest(&serde_json::to_value(&receipt.roles.roles)?)?.as_str())
        && journal.completion_receipt_sha256.as_ref().is_none_or(|known|known==&hash),
        "CONFLICT: original startup completion receipt binding");
    receipt.association.require(&expected.spec,&expected.profile_id,expected.unit.pid,&receipt.roles)?;
    require_new_source(root,plan,&receipt.association,&receipt.roles)?;
    receipt.owner.require_original(plan.operation_id,&plan.parent_plan_sha256,&receipt.parent_template_sha256,&receipt.roles.roles)?;
    receipt.owner.require_registration(&receipt.roles)?;Ok(Some((receipt,hash)))
}
pub(super) fn status(root:&Path,plan:&Plan,journal:&Journal)->Result<Option<Value>> {
    let Some((_,hash))=record(root,plan,journal)?else{return Ok(None)};
    Ok(Some(json!({"state":"STARTUP_VERIFIED","receiptSha256":hash,
        "receiptScope":"historical-ordinary-jvm-core-network-writer-drain-only",
        "freshWitnessesRequiredBeforeActivation":true,"allSystemWritersVerified":false,"systemAdoptionVerified":false})))
}
fn current(root:&Path,plan:&Plan,journal:&Journal,systemctl:&Path)->Result<Challenge> {
    let expected=challenge(root,plan,journal)?;
    publication::selected_raw(root,plan,journal)?;
    let config:Config=serde_json::from_str(&plan.generated_profile)?;
    ensure!(plan.stop_policy.as_ref()==Some(&crate::system_control::inspect_stop_policy(systemctl,&config)?)
        && crate::system_control::inspect_unit(systemctl,&config.unit)?==expected.unit,
        "CONFLICT: current startup files/policy/unit differ from original start receipt");Ok(expected)
}
fn terminal(root:&Path,plan:&Plan,journal:&Journal,template:&str,roles:&roles::ConfigurationRoles)->Result<String> {
    let (receipt,hash)=record(root,plan,journal)?.context("FORBIDDEN: prepared startup requires a terminal receipt before activation")?;
    ensure!(journal.completion_receipt_sha256.as_ref()==Some(&hash),"OUTCOME_UNKNOWN: startup completion is not fully acknowledged");
    ensure!(receipt.parent_template_sha256==template,"CONFLICT: original startup template changed");
    receipt.owner.require_original(plan.operation_id,&plan.parent_plan_sha256,template,roles)?;Ok(hash)
}
pub(super) fn begin(root:&Path,original:&Requirements,actor:&str,token:&str,systemctl:&Path)->Result<Step> {
    let (plan,mut journal)=authorized(root,original,actor,token)?;
    ensure!(plan.schema_version>=4,"UNSUPPORTED: historical startup has no terminal execution authority");
    if let Some((receipt,hash))=record(root,&plan,&journal)? {
        receipt.owner.require_original(original.operation,&original.plan,&original.template,&original.baseline.roles.roles)?;
        if journal.completion_receipt_sha256.as_ref()!=Some(&hash) {
            let file=BoundFile::open(&path(root,plan.operation_id),LIMIT)?;
            ensure!(durable::hash(&file.bytes)==hash,"CONFLICT: startup completion changed before acknowledgement");file.sync_exact()?;
            journal.completion_receipt_sha256=Some(hash);durable::json(&super::paths(root,plan.operation_id).1,&journal)?;
        }
        return Ok(Step::Observed(value(root,&plan,&journal,true)?));
    }
    current(root,&plan,&journal,systemctl).map(|expected|Step::Challenge(Box::new(expected)))
}
pub(super) fn finish(root:&Path,original:&Requirements,actor:&str,token:&str,expected:&Challenge,witness:Witness,systemctl:&Path)->Result<Value> {
    let (plan,mut journal)=authorized(root,original,actor,token)?;
    ensure!(current(root,&plan,&journal,systemctl)?==*expected,"CONFLICT: original startup changed during live completion reads");
    witness.require(original,expected)?;require_new_source(root,&plan,&witness.association,&witness.roles)?;
    ensure!(!present(&path(root,plan.operation_id))?,"OUTCOME_UNKNOWN: query the original completion receipt");
    let receipt=Receipt{schema_version:1,startup_plan_sha256:journal.plan_sha256.clone(),parent_template_sha256:original.template.clone(),
        start_receipt_sha256:journal.start_receipt_sha256.clone().context("OUTCOME_UNKNOWN: original start receipt missing")?,spec:expected.spec.clone(),
        unit:expected.unit.clone(),roles:witness.roles,association:witness.association,owner:witness.owner};
    let bytes=serde_json::to_vec(&receipt)?;ensure!(bytes.len() as u64<=LIMIT,"RESOURCE_EXHAUSTED: startup completion receipt quota");
    durable::publish_new(&path(root,plan.operation_id),&bytes,FileMetadata::private()).context("OUTCOME_UNKNOWN: original startup completion publication")?;
    journal.completion_receipt_sha256=Some(durable::hash(&bytes));
    durable::json(&super::paths(root,plan.operation_id).1,&journal).context("OUTCOME_UNKNOWN: original startup completion pointer")?;
    value(root,&plan,&journal,true)
}
pub(super) fn activation_challenge(root:&Path,original:&Requirements,systemctl:&Path)->Result<Challenge> {
    let (plan,journal)=load(root,original.operation,&original.plan)?.context("FORBIDDEN: terminal startup receipt required for every new activation")?;
    terminal(root,&plan,&journal,&original.template,&original.baseline.roles.roles)?;
    current(root,&plan,&journal,systemctl)
}
pub(super) fn activation_finish(root:&Path,original:&Requirements,expected:&Challenge,witness:&Witness,systemctl:&Path)->Result<String> {
    let (plan,journal)=load(root,original.operation,&original.plan)?.context("FORBIDDEN: terminal startup child required")?;
    let hash=terminal(root,&plan,&journal,&original.template,&original.baseline.roles.roles)?;
    ensure!(current(root,&plan,&journal,systemctl)?==*expected,"CONFLICT: startup changed during activation witnesses");
    witness.require(original,expected)?;require_new_source(root,&plan,&witness.association,&witness.roles)?;Ok(hash)
}
pub(super) fn require_lease(root:&Path,id:uuid::Uuid,parent:&str,template:&str,roles:&roles::ConfigurationRoles,hash:&str)->Result<()> {
    let (plan,journal)=load(root,id,parent)?.context("OUTCOME_UNKNOWN: original lease startup child missing")?;
    ensure!(terminal(root,&plan,&journal,template,roles)?==hash,"CONFLICT: original lease startup receipt changed");Ok(())
}

/// Read-only historical basis for a separate contemporaneous OS observation.
/// This does not change current()/activation_challenge's original-unit contract.
pub(super) struct RuntimeAnchor {
    pub(super) original: Challenge,
    pub(super) config: Config,
    pub(super) stop_policy: crate::system_control::StopPolicy,
    pub(super) receipt_sha256: String,
    pub(super) profile_sha256: String,
}
pub(super) fn runtime_anchor(root: &Path, original: &Requirements) -> Result<RuntimeAnchor> {
    let (plan, journal) = load(root, original.operation, &original.plan)?
        .context("FORBIDDEN: original terminal startup required")?;
    let receipt_sha256 = terminal(
        root,
        &plan,
        &journal,
        &original.template,
        &original.baseline.roles.roles,
    )?;
    let raw = publication::selected_raw(root, &plan, &journal)?;
    Ok(RuntimeAnchor {
        original: challenge(root, &plan, &journal)?,
        config: serde_json::from_str(&plan.generated_profile)?,
        stop_policy: plan
            .stop_policy
            .clone()
            .context("UNSUPPORTED: original pinned startup service policy required")?,
        receipt_sha256,
        profile_sha256: durable::hash(&raw),
    })
}
pub(super) fn runtime_witness(
    root: &Path,
    original: &Requirements,
    expected: &Challenge,
    witness: &Witness,
) -> Result<String> {
    let anchor = runtime_anchor(root, original)?;
    ensure!(
        expected.spec == anchor.original.spec
            && expected.profile_id == anchor.original.profile_id
            && expected.unit.unit == anchor.original.unit.unit
            && expected.unit.control_group == anchor.original.unit.control_group,
        "CONFLICT: current runtime is outside the original selected ordinary unit/profile"
    );
    witness.require(original, expected)?;
    let (plan, journal) = load(root, original.operation, &original.plan)?
        .context("OUTCOME_UNKNOWN: original startup child missing")?;
    require_new_source(root,&plan,&witness.association,&witness.roles)?;
    if expected.unit.pid != anchor.original.unit.pid
        || expected.unit.invocation_id != anchor.original.unit.invocation_id
    {
        let (receipt, _) = record(root, &plan, &journal)?
            .context("OUTCOME_UNKNOWN: original terminal startup receipt missing")?;
        witness
            .association
            .require_new_observer(&receipt.association)?;
    }
    Ok(anchor.receipt_sha256)
}
