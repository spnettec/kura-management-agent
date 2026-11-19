//! Once-only fixed-unit start after the original publication is acknowledged.
//! A service acknowledgement is historical process evidence, never Core/JVM
//! readiness or full adoption. Retained intents cannot create another command.
use super::*;

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Intent {
    schema_version:u8,operation_id:uuid::Uuid,startup_plan_sha256:String,parent_plan_sha256:String,
    stop_receipt_sha256:String,publication_receipt_sha256:String,
    generated_profile_sha256:String,generated_arguments_sha256:String,
    before_unit:crate::system_control::Unit,policy:crate::system_control::StopPolicy,timeout_seconds:u64,
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Receipt {
    schema_version:u8,operation_id:uuid::Uuid,startup_plan_sha256:String,intent_sha256:String,
    started_unit:crate::system_control::Unit,
}
pub(super) fn paths(root:&Path,id:uuid::Uuid)->(PathBuf,PathBuf) {
    (root.join(format!("{id}.startup-start-intent.json")),root.join(format!("{id}.startup-start-receipt.json")))
}
fn expiry(plan:&Plan)->Result<()> {
    let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64;
    ensure!(now<=plan.expires_at_unix_ms,"EXPIRED: original startup review expired before start dispatch");Ok(())
}
fn validate_intent(plan:&Plan,journal:&Journal,intent:&Intent)->Result<()> {
    let source:Config=serde_json::from_str(&plan.source_profile)?;
    ensure!(plan.schema_version>=4 && intent.schema_version==1 && intent.operation_id==plan.operation_id
        && intent.startup_plan_sha256==journal.plan_sha256 && intent.parent_plan_sha256==plan.parent_plan_sha256
        && journal.stop_receipt_sha256.as_ref()==Some(&intent.stop_receipt_sha256)
        && journal.publication_receipt_sha256.as_ref()==Some(&intent.publication_receipt_sha256)
        && hex(&intent.stop_receipt_sha256,64) && hex(&intent.publication_receipt_sha256,64)
        && intent.generated_profile_sha256==durable::hash(plan.generated_profile.as_bytes())
        && intent.generated_arguments_sha256==argument_binding(plan,&source)?.0
        && intent.before_unit.unit==source.unit && intent.before_unit.stopped()
        && intent.before_unit.unit_file_state==plan.before_unit.unit_file_state
        && plan.stop_policy.as_ref()==Some(&intent.policy) && intent.timeout_seconds==source.timeout_seconds,
        "CONFLICT: original startup start intent binding");intent.policy.validate()
}
fn validate_started(plan:&Plan,intent:&Intent,unit:&crate::system_control::Unit)->Result<()> {
    ensure!(unit.unit==intent.before_unit.unit && unit.running()
        && unit.unit_file_state==intent.before_unit.unit_file_state && unit.invocation_id!=plan.before_unit.invocation_id,
        "CONFLICT: original startup did not produce a fresh active fixed-unit invocation");Ok(())
}
pub(super) fn status(root:&Path,plan:&Plan,journal:&Journal)->Result<Option<Value>> {
    let (intent_path,receipt_path)=paths(root,plan.operation_id);
    let (has_intent,has_receipt)=(present(&intent_path)?,present(&receipt_path)?);
    if !has_intent && !has_receipt && journal.start_intent_sha256.is_none() && journal.start_receipt_sha256.is_none(){return Ok(None);}
    ensure!(has_intent,"OUTCOME_UNKNOWN: original startup start intent missing");
    let bytes=read(&intent_path)?;let hash=durable::hash(&bytes);let intent:Intent=serde_json::from_slice(&bytes)?;
    validate_intent(plan,journal,&intent)?;
    ensure!(journal.start_intent_sha256.as_ref().is_none_or(|known|known==&hash),"CONFLICT: original startup start intent digest");
    ensure!(has_receipt || journal.start_receipt_sha256.is_none(),"OUTCOME_UNKNOWN: acknowledged original startup start receipt missing");
    let receipt_hash=if has_receipt {
        let bytes=read(&receipt_path)?;let receipt_hash=durable::hash(&bytes);let receipt:Receipt=serde_json::from_slice(&bytes)?;
        ensure!(receipt.schema_version==1 && receipt.operation_id==plan.operation_id && receipt.startup_plan_sha256==journal.plan_sha256
            && receipt.intent_sha256==hash
            && journal.start_receipt_sha256.as_ref().is_none_or(|known|known==&receipt_hash),"CONFLICT: original startup start receipt binding");
        validate_started(plan,&intent,&receipt.started_unit)?;Some(receipt_hash)
    }else{None};
    Ok(Some(json!({"state":if receipt_hash.is_some(){"STARTED"}else{"START_OUTCOME_UNKNOWN"},
        "intentSha256":hash,"receiptSha256":receipt_hash,"unit":intent.before_unit.unit,"timeoutSeconds":intent.timeout_seconds,
        "commandMayHaveRun":true,"redispatchAllowed":false,"receiptScope":"historical-fixed-unit-start-only",
        "freshJvmAssociationRequired":true,"freshCoreOwnerAndDrainRequired":true,"systemAdoptionVerified":false})))
}
pub(super) fn acknowledged_unit(root:&Path,plan:&Plan,journal:&Journal)->Result<crate::system_control::Unit> {
    let status=status(root,plan,journal)?.context("OUTCOME_UNKNOWN: original startup start receipt required")?;
    let hash=status["receiptSha256"].as_str().context("OUTCOME_UNKNOWN: original start was not acknowledged")?;
    ensure!(journal.start_receipt_sha256.as_deref()==Some(hash)
        && journal.start_intent_sha256.as_deref()==status["intentSha256"].as_str(),
        "OUTCOME_UNKNOWN: original start evidence is not fully acknowledged");
    let bytes=read(&paths(root,plan.operation_id).1)?;ensure!(durable::hash(&bytes)==hash,"CONFLICT: original start receipt changed during read");
    Ok(serde_json::from_slice::<Receipt>(&bytes)?.started_unit)
}
fn current(root:&Path,plan:&Plan,journal:&Journal,systemctl:&Path)->Result<crate::system_control::Unit> {
    publication::selected_raw(root,plan,journal)?;
    let config:Config=serde_json::from_str(&plan.generated_profile)?;
    ensure!(plan.stop_policy.as_ref()==Some(&crate::system_control::inspect_stop_policy(systemctl,&config)?),
        "CONFLICT: original startup effective policy changed before start");
    let unit=crate::system_control::inspect_stopped_unit(systemctl,&config.unit)?;
    ensure!(unit.unit_file_state==plan.before_unit.unit_file_state,"CONFLICT: original startup enablement changed before start");Ok(unit)
}
pub(in crate::nm) enum Step {Observed(Value),Dispatch(Box<Command>)}
pub(in crate::nm) struct Command {root:PathBuf,systemctl:PathBuf,plan:Plan,intent:Intent,intent_sha256:String,execution:execution::Execution}
pub(super) fn begin(root:&Path,original:&Requirements,actor:&str,token:&str,systemctl:&Path)->Result<Step> {
    let (plan,mut journal)=authorized(root,original,actor,token)?;
    ensure!(plan.schema_version>=4,"UNSUPPORTED: historical startup plan has no fixed-unit start authority");
    if let Some(status)=status(root,&plan,&journal)? {
        // A complete original receipt can acknowledge its missing pointer. A
        // later active unit alone can never recreate a missing command receipt.
        if let Some(receipt)=status["receiptSha256"].as_str() {
            let hash=status["intentSha256"].as_str().context("CONFLICT: original start intent hash")?;
            if journal.start_intent_sha256.as_deref()!=Some(hash) || journal.start_receipt_sha256.as_deref()!=Some(receipt) {
                let execution=execution::Execution::acquire(root,&plan,&journal)?;execution.verify()?;
                for (path,expected) in [(paths(root,plan.operation_id).0,hash),(paths(root,plan.operation_id).1,receipt)] {
                    let file=BoundFile::open(&path,LIMIT)?;ensure!(durable::hash(&file.bytes)==expected,"CONFLICT: original start evidence changed before acknowledgement");file.sync_exact()?;
                }
                journal.start_intent_sha256=Some(hash.into());journal.start_receipt_sha256=Some(receipt.into());
                durable::json(&super::paths(root,plan.operation_id).1,&journal)?;
                execution.verify()?;
            }
        }
        return Ok(Step::Observed(value(root,&plan,&journal,true)?));
    }
    publication::recovery::forward_allowed(root,&plan,&journal)?;
    let execution=execution::Execution::acquire(root,&plan,&journal)?;
    ensure!(status(root,&plan,&journal)?.is_none(),"OUTCOME_UNKNOWN: original start was admitted concurrently; query it without redispatch");
    expiry(&plan)?;let before_unit=current(root,&plan,&journal,systemctl)?;
    let source:Config=serde_json::from_str(&plan.source_profile)?;
    let intent=Intent{schema_version:1,operation_id:plan.operation_id,startup_plan_sha256:journal.plan_sha256.clone(),
        parent_plan_sha256:plan.parent_plan_sha256.clone(),
        stop_receipt_sha256:journal.stop_receipt_sha256.clone().context("OUTCOME_UNKNOWN: original stop acknowledgement missing")?,
        publication_receipt_sha256:journal.publication_receipt_sha256.clone().context("OUTCOME_UNKNOWN: original publication acknowledgement missing")?,
        generated_profile_sha256:durable::hash(plan.generated_profile.as_bytes()),generated_arguments_sha256:argument_binding(&plan,&source)?.0,
        before_unit,policy:plan.stop_policy.clone().context("CONFLICT: original startup policy missing")?,timeout_seconds:source.timeout_seconds};
    validate_intent(&plan,&journal,&intent)?;ensure!(current(root,&plan,&journal,systemctl)?==intent.before_unit,
        "CONFLICT: original stopped startup unit changed during admission");
    let bytes=serde_json::to_vec(&intent)?;let intent_sha256=durable::hash(&bytes);
    ensure!(bytes.len() as u64<=LIMIT,"RESOURCE_EXHAUSTED: original startup start intent quota");
    execution.verify()?;
    durable::publish_new(&paths(root,plan.operation_id).0,&bytes,FileMetadata::private())
        .context("OUTCOME_UNKNOWN: original startup start intent publication")?;
    journal.start_intent_sha256=Some(intent_sha256.clone());
    durable::json(&super::paths(root,plan.operation_id).1,&journal).context("OUTCOME_UNKNOWN: original startup start admission pointer")?;
    Ok(Step::Dispatch(Box::new(Command{root:root.into(),systemctl:systemctl.into(),plan,intent,intent_sha256,execution})))
}
impl Command {
    pub(in crate::nm) fn execute(self)->Result<Value> {
        self.execute_inner().context("OUTCOME_UNKNOWN: original startup start requires its retained receipt;do not resend")
    }
    fn execute_inner(self)->Result<Value> {
        self.execution.verify()?;
        let (plan,mut journal)=load(&self.root,self.plan.operation_id,&self.plan.parent_plan_sha256)?.context("CONFLICT: original startup child disappeared")?;
        ensure!(journal.start_intent_sha256.as_ref()==Some(&self.intent_sha256) && journal.start_receipt_sha256.is_none()
            && !present(&paths(&self.root,plan.operation_id).1)?,"CONFLICT: original startup start admission changed");
        expiry(&plan)?;ensure!(current(&self.root,&plan,&journal,&self.systemctl)?==self.intent.before_unit,
            "CONFLICT: stopped startup authority changed after admission");
        self.execution.verify()?;
        let output=crate::process::run(&self.systemctl,&["start",&self.intent.before_unit.unit],None,Duration::from_secs(self.intent.timeout_seconds))?;
        ensure!(output.status.success(),"CONFLICT: fixed startup start command did not acknowledge success");
        let started_unit=crate::system_control::inspect_unit(&self.systemctl,&self.intent.before_unit.unit)?;
        validate_started(&plan,&self.intent,&started_unit)?;
        publication::selected_raw(&self.root,&plan,&journal)?;
        let config:Config=serde_json::from_str(&plan.generated_profile)?;
        ensure!(crate::system_control::inspect_stop_policy(&self.systemctl,&config)?==self.intent.policy
            && crate::system_control::inspect_unit(&self.systemctl,&config.unit)?==started_unit,
            "CONFLICT: startup identity or policy changed while acknowledging start");
        let bytes=serde_json::to_vec(&Receipt{schema_version:1,operation_id:plan.operation_id,startup_plan_sha256:journal.plan_sha256.clone(),
            intent_sha256:self.intent_sha256,started_unit})?;
        self.execution.verify()?;
        durable::publish_new(&paths(&self.root,plan.operation_id).1,&bytes,FileMetadata::private())?;
        journal.start_receipt_sha256=Some(durable::hash(&bytes));
        durable::json(&super::paths(&self.root,plan.operation_id).1,&journal)?;
        self.execution.verify()?;
        value(&self.root,&plan,&journal,true)
    }
}
