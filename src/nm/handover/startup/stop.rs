//! Once-only fixed-unit stop in the existing original startup child. File
//! publication/start/complete adoption are later phases of this same chain.
use super::*;

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Intent {
    schema_version:u8,operation_id:uuid::Uuid,startup_plan_sha256:String,parent_plan_sha256:String,
    source_profile_digest:String,association_receipt_sha256:String,
    spec:roles::StartupSpec,roles:roles::Observation,association:roles::StartupAssociation,
    before_unit:crate::system_control::Unit,policy:crate::system_control::StopPolicy,
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Receipt {
    schema_version:u8,operation_id:uuid::Uuid,startup_plan_sha256:String,intent_sha256:String,
    stopped_unit:crate::system_control::Unit,stop_policy_sha256:String,
}
fn paths(root:&Path,id:uuid::Uuid)->(PathBuf,PathBuf) {
    (root.join(format!("{id}.startup-stop-intent.json")),root.join(format!("{id}.startup-stop-receipt.json")))
}
fn expiry(plan:&Plan)->Result<()> {
    let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64;
    ensure!(now<=plan.expires_at_unix_ms,"EXPIRED: original startup review expired before stop dispatch");Ok(())
}
fn valid_intent(plan:&Plan,journal:&Journal,intent:&Intent)->Result<()> {
    let challenge=challenge(plan,journal)?;
    ensure!(plan.schema_version==4 && plan.stop_policy.as_ref()==Some(&intent.policy)
        && intent.schema_version==1 && intent.operation_id==plan.operation_id && intent.startup_plan_sha256==journal.plan_sha256
        && intent.parent_plan_sha256==plan.parent_plan_sha256 && intent.source_profile_digest==plan.source_profile_digest
        && journal.old_association_sha256.as_ref()==Some(&intent.association_receipt_sha256)
        && intent.spec==challenge.spec && intent.before_unit==plan.before_unit
        && plan.source_roles_sha256.as_deref()==Some(digest(&serde_json::to_value(&intent.roles.roles)?)?.as_str()),
        "CONFLICT: original startup stop intent binding");
    intent.policy.validate()?;
    intent.association.require(&intent.spec,&challenge.profile_id,challenge.pid,&intent.roles)
}
pub(super) fn status(root:&Path,plan:&Plan,journal:&Journal)->Result<Option<Value>> {
    let (intent_path,receipt_path)=paths(root,plan.operation_id);
    let (has_intent,has_receipt)=(present(&intent_path)?,present(&receipt_path)?);
    if !has_intent && !has_receipt && journal.stop_intent_sha256.is_none() && journal.stop_receipt_sha256.is_none(){return Ok(None);}
    ensure!(has_intent,"OUTCOME_UNKNOWN: original startup stop intent missing");
    let bytes=read(&intent_path)?;let hash=durable::hash(&bytes);let intent:Intent=serde_json::from_slice(&bytes)?;
    valid_intent(plan,journal,&intent)?;
    ensure!(journal.stop_intent_sha256.as_ref().is_none_or(|known|known==&hash),"CONFLICT: original startup stop intent digest");
    ensure!(has_receipt || journal.stop_receipt_sha256.is_none(),"OUTCOME_UNKNOWN: original startup stop receipt missing");
    let receipt_hash=if has_receipt {
        let bytes=read(&receipt_path)?;let receipt_hash=durable::hash(&bytes);let receipt:Receipt=serde_json::from_slice(&bytes)?;
        ensure!(receipt.schema_version==1 && receipt.operation_id==plan.operation_id && receipt.startup_plan_sha256==journal.plan_sha256
            && receipt.intent_sha256==hash && receipt.stopped_unit.unit==intent.before_unit.unit && receipt.stopped_unit.stopped()
            && receipt.stopped_unit.unit_file_state==intent.before_unit.unit_file_state
            && receipt.stop_policy_sha256==intent.policy.definition_sha256
            && journal.stop_receipt_sha256.as_ref().is_none_or(|known|known==&receipt_hash),
            "CONFLICT: original startup stop receipt binding");Some(receipt_hash)
    } else {None};
    Ok(Some(json!({"state":if receipt_hash.is_some(){"STOPPED"}else{"STOP_OUTCOME_UNKNOWN"},
        "intentSha256":hash,"receiptSha256":receipt_hash,"unit":intent.before_unit.unit,
        "stopPolicySha256":intent.policy.definition_sha256,"timeoutSeconds":intent.policy.timeout_seconds,
        "commandMayHaveRun":true,"redispatchAllowed":false,"receiptScope":"historical-fixed-unit-stop-only",
        "freshStoppedUnitRequiredBeforeFilePublication":true,"startupFilesChanged":false,"systemAdoptionVerified":false})))
}
pub(super) fn begin(root:&Path,original:&Requirements,actor:&str,token:&str,systemctl:&Path)->Result<AssociationStep> {
    let (plan,journal)=authorized(root,original,actor,token)?;
    ensure!(plan.schema_version==4,"UNSUPPORTED: historical startup plan has no reviewed stop authority");
    let expected=challenge(&plan,&journal)?;
    if status(root,&plan,&journal)?.is_some(){return Ok(AssociationStep::Observed(value(root,&plan,&journal,true)?));}
    publication::recovery::forward_allowed(root,&plan,&journal)?;
    ensure!(journal.old_association_sha256.is_some(),"CONFLICT: original JVM association review required before stop");
    expiry(&plan)?;recheck(&plan,systemctl)?;
    let config:Config=serde_json::from_str(&plan.source_profile)?;
    ensure!(plan.stop_policy.as_ref()==Some(&crate::system_control::inspect_stop_policy(systemctl,&config)?),"CONFLICT: reviewed effective stop policy changed");
    Ok(AssociationStep::Challenge(expected))
}
pub(super) fn acknowledge(root:&Path,plan:&Plan,journal:&mut Journal)->Result<String> {
    let value=status(root,plan,journal)?.context("CONFLICT: original acknowledged stop required before file publication")?;
    let receipt_hash=value["receiptSha256"].as_str().context("OUTCOME_UNKNOWN: original stop has no acknowledged receipt")?.to_owned();
    let intent_hash=value["intentSha256"].as_str().context("CONFLICT: original stop intent digest missing")?.to_owned();
    if journal.stop_receipt_sha256.as_ref()!=Some(&receipt_hash) || journal.stop_intent_sha256.as_ref()!=Some(&intent_hash) {
        for (path,hash) in [(paths(root,plan.operation_id).0,&intent_hash),(paths(root,plan.operation_id).1,&receipt_hash)] {
            let file=BoundFile::open(&path,LIMIT)?;ensure!(durable::hash(&file.bytes)==*hash,"CONFLICT: original stop evidence changed before acknowledgement");file.sync_exact()?;
        }
        journal.stop_intent_sha256=Some(intent_hash);journal.stop_receipt_sha256=Some(receipt_hash.clone());
        durable::json(&super::paths(root,plan.operation_id).1,journal)?;
    }Ok(receipt_hash)
}
/// Constructed only by fresh admission, never reconstructed from a retained
/// intent. Consuming the value cannot redispatch an UNKNOWN original command.
pub(in crate::nm) struct Command {
    root:PathBuf,systemctl:PathBuf,plan:Plan,journal:Journal,intent:Intent,intent_sha256:String,execution:execution::Execution,
}
pub(super) fn arm(root:&Path,original:&Requirements,actor:&str,token:&str,
    witness:(roles::StartupAssociation,roles::Observation),systemctl:&Path,deadline:std::time::Instant)->Result<Command> {
    let (plan,mut journal)=authorized(root,original,actor,token)?;
    ensure!(plan.schema_version==4,"UNSUPPORTED: historical startup plan has no reviewed stop authority");
    let execution=execution::Execution::acquire(root,&plan,&journal)?;
    ensure!(status(root,&plan,&journal)?.is_none(),"OUTCOME_UNKNOWN: query original startup stop; never dispatch it again");
    publication::recovery::forward_allowed(root,&plan,&journal)?;
    expiry(&plan)?;let expected=challenge(&plan,&journal)?;
    let (association,roles)=witness;association.require(&expected.spec,&expected.profile_id,expected.pid,&roles)?;
    ensure!(plan.source_roles_sha256.as_deref()==Some(digest(&serde_json::to_value(&roles.roles)?)?.as_str()),"CONFLICT: original CM projection changed before stop");
    let association_receipt_sha256=journal.old_association_sha256.clone().context("CONFLICT: original JVM association review required before stop")?;
    recheck(&plan,systemctl)?;let config:Config=serde_json::from_str(&plan.source_profile)?;
    let policy=crate::system_control::inspect_stop_policy(systemctl,&config)?;
    ensure!(plan.stop_policy.as_ref()==Some(&policy),"CONFLICT: reviewed effective stop policy changed");recheck(&plan,systemctl)?;
    let intent=Intent{schema_version:1,operation_id:plan.operation_id,startup_plan_sha256:journal.plan_sha256.clone(),
        parent_plan_sha256:plan.parent_plan_sha256.clone(),source_profile_digest:plan.source_profile_digest.clone(),
        association_receipt_sha256,spec:expected.spec,roles,association,before_unit:plan.before_unit.clone(),policy};
    valid_intent(&plan,&journal,&intent)?;
    let bytes=serde_json::to_vec(&intent)?;let intent_sha256=durable::hash(&bytes);
    ensure!(bytes.len() as u64<=LIMIT,"RESOURCE_EXHAUSTED: original startup stop intent quota");
    execution.verify()?;
    // Full profile and unit rechecks can exhaust the callback budget. Refuse
    // before publishing an intent that would immediately become ambiguous.
    ensure!(std::time::Instant::now()<deadline,"TIMEOUT: startup stop observation budget expired before intent");
    durable::publish_new(&paths(root,plan.operation_id).0,&bytes,FileMetadata::private())
        .context("OUTCOME_UNKNOWN: original startup stop intent publication")?;
    journal.stop_intent_sha256=Some(intent_sha256.clone());
    durable::json(&super::paths(root,plan.operation_id).1,&journal).context("OUTCOME_UNKNOWN: original startup stop admission pointer")?;
    Ok(Command{root:root.into(),systemctl:systemctl.into(),plan,journal,intent,intent_sha256,execution})
}
impl Command {
    pub(in crate::nm) fn execute(self)->Result<Value> {
        // Any return after intent publication retains the original uncertain
        // command. No recover/query path constructs another Command.
        self.execute_inner().context("OUTCOME_UNKNOWN: original startup stop requires its retained receipt; do not resend")
    }
    fn execute_inner(self)->Result<Value> {
        self.execution.verify()?;
        let (plan,current)=load(&self.root,self.plan.operation_id,&self.plan.parent_plan_sha256)?.context("CONFLICT: original startup child disappeared")?;
        ensure!(current.stop_intent_sha256.as_ref()==Some(&self.intent_sha256)
            && current.stop_receipt_sha256.is_none() && current.plan_sha256==self.journal.plan_sha256
            && !present(&paths(&self.root,plan.operation_id).1)?,"CONFLICT: original startup stop admission changed");
        expiry(&plan)?;recheck(&plan,&self.systemctl)?;
        let config:Config=serde_json::from_str(&plan.source_profile)?;
        ensure!(crate::system_control::inspect_stop_policy(&self.systemctl,&config)?==self.intent.policy,"CONFLICT: effective stop policy changed after admission");
        self.execution.verify()?;
        let output=crate::process::run(&self.systemctl,&["stop",&config.unit],None,Duration::from_secs(self.intent.policy.timeout_seconds+5))?;
        ensure!(output.status.success(),"CONFLICT: fixed startup stop command did not acknowledge success");
        let stopped=crate::system_control::inspect_stopped_unit(&self.systemctl,&config.unit)?;
        ensure!(stopped.unit_file_state==self.intent.before_unit.unit_file_state
            && Profile::new(plan.source_path.clone())?.inputs()?.1==plan.source_profile_digest
            && Image::read(&config.jvm_args_path,ARGS_LIMIT)?.0==plan.source_args_image
            && plan.fences.iter().map(|item|fence(item.path.clone())).collect::<Result<Vec<_>>>()?==plan.fences
            && BoundFile::open(&plan.owner_marker,16384)?.marker()?==plan.owner_marker_identity
            && crate::system_control::inspect_stop_policy(&self.systemctl,&config)?==self.intent.policy,
            "CONFLICT: startup authority changed during stop");
        let receipt=Receipt{schema_version:1,operation_id:plan.operation_id,startup_plan_sha256:self.journal.plan_sha256.clone(),
            intent_sha256:self.intent_sha256,stopped_unit:stopped,stop_policy_sha256:self.intent.policy.definition_sha256};
        let bytes=serde_json::to_vec(&receipt)?;
        self.execution.verify()?;
        durable::publish_new(&paths(&self.root,plan.operation_id).1,&bytes,FileMetadata::private())?;
        let mut journal=current;journal.stop_receipt_sha256=Some(durable::hash(&bytes));
        durable::json(&super::paths(&self.root,plan.operation_id).1,&journal)?;
        self.execution.verify()?;
        value(&self.root,&plan,&journal,true)
    }
}
