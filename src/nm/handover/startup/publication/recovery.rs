//! Explicit file compensation. Historical original intents/receipts are never
//! repaired or replayed. Fences and both preimages remain for retirement review.
use super::*;

#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Slot {path:PathBuf,parent:Directory,image:Option<Image>}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Evidence {stop_intent:String,stop_receipt:String,publication_intent:String,publication_steps:Vec<String>,publication_receipt:Option<String>}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Snapshot {evidence:Evidence,files:Vec<Slot>,unit:crate::system_control::Unit}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Review {schema_version:u8,operation_id:uuid::Uuid,recovery_id:uuid::Uuid,startup_plan_sha256:String,parent_plan_sha256:String,
    actor:String,token_sha256:String,snapshot:Snapshot,quarantine:PathBuf,expires_at_unix_ms:u64}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Ledger {schema_version:u8,recovery_id:uuid::Uuid,review_sha256:String,confirmation_token:String,state:String,
    intent_sha256:Option<String>,receipt_sha256:Option<String>,cancel_sha256:Option<String>}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Seal {schema_version:u8,recovery_id:uuid::Uuid,review_sha256:String}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct StepReceipt {schema_version:u8,recovery_id:uuid::Uuid,intent_sha256:String,index:u8,image:Option<Image>}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Receipt {schema_version:u8,recovery_id:uuid::Uuid,review_sha256:String,intent_sha256:String,steps:Vec<String>}
struct Record {review:Review,ledger:Ledger,hash:String,intent:Option<String>,steps:Vec<(String,StepReceipt)>,receipt:Option<String>,cancel:Option<String>}
fn artifact(root:&Path,op:uuid::Uuid,id:uuid::Uuid,suffix:&str)->PathBuf {root.join(format!("{op}.startup-recovery-{id}.{suffix}.json"))}
fn slot(path:&Path,parent:&Directory,limit:u64)->Result<Slot> {
    let bound=Parent::bound(parent)?;
    Ok(Slot{path:path.into(),parent:parent.clone(),image:if bound.exists(path)?{Some(bound.read(path,limit)?.image)}else{None}})
}
fn evidence(root:&Path,plan:&Plan,journal:&Journal)->Result<(Evidence,Intent)> {
    ensure!(plan.schema_version==4 && journal.start_intent_sha256.is_none() && journal.start_receipt_sha256.is_none()
        && !present(&start::paths(root,plan.operation_id).0)? && !present(&start::paths(root,plan.operation_id).1)?,
        "FORBIDDEN: original start authority excludes file compensation");
    let stopped=stop::status(root,plan,journal)?.context("OUTCOME_UNKNOWN: acknowledged original stop required for recovery")?;
    let si=stopped["intentSha256"].as_str().context("OUTCOME_UNKNOWN: original stop intent missing")?;
    let sr=stopped["receiptSha256"].as_str().context("OUTCOME_UNKNOWN: original stop receipt missing")?;
    ensure!(journal.stop_intent_sha256.as_deref()==Some(si) && journal.stop_receipt_sha256.as_deref()==Some(sr),
        "OUTCOME_UNKNOWN: original stop must already be acknowledged");
    let (intent,hash,steps,receipt)=records(root,plan,journal)?.context("FORBIDDEN: original file publication intent required for recovery")?;
    Ok((Evidence{stop_intent:si.into(),stop_receipt:sr.into(),publication_intent:hash,publication_steps:steps,publication_receipt:receipt},intent))
}
// --all is essential: systemd v258 systemctl-show.c prints an empty Job for
// job id zero. Reject missing, duplicated, nonempty and unexpected output.
fn no_job(systemctl:&Path,unit:&str)->Result<()> {
    let output=crate::process::run(systemctl,&["show",unit,"--all","--property=Job"],None,Duration::from_secs(5))?;
    ensure!(output.status.success() && output.stdout==b"Job=\n","CONFLICT: fixed unit has a job or job observation is unavailable");Ok(())
}
fn capture_files(root:&Path,plan:&Plan,journal:&Journal)->Result<(Evidence,Vec<Slot>)> {
    let (proof,intent)=evidence(root,plan,journal)?;let config:Config=serde_json::from_str(&plan.source_profile)?;
    let mut files=vec![slot(&intent.arguments_path,&intent.steps[0].parent,ARGS_LIMIT)?,slot(&intent.backup_path,&intent.steps[0].parent,ARGS_LIMIT)?];
    for step in intent.steps.iter().skip(2){files.push(slot(&step.path,&step.parent,PLAN_LIMIT)?);}
    let source_parent=Parent::open(plan.source_path.parent().context("source grant parent")?)?;
    let source=source_parent.read(&plan.source_path,PLAN_LIMIT)?;
    ensure!(source.bytes==plan.source_profile.as_bytes() && source.image.metadata.mode&0o077==0,"CONFLICT: original recovery grant changed");
    files.push(Slot{path:plan.source_path.clone(),parent:source_parent.identity,image:Some(source.image)});
    let owner=Parent::open(plan.owner_marker.parent().context("owner parent")?)?;let image=owner.read(&plan.owner_marker,16384)?.image;
    ensure!(image.device==plan.owner_marker_identity.device && image.inode==plan.owner_marker_identity.inode && image.sha256==plan.owner_marker_identity.sha256,
        "CONFLICT: original recovery fence changed");files.push(Slot{path:plan.owner_marker.clone(),parent:owner.identity,image:Some(image)});
    for pin in config.profile_files.iter().filter(|pin|pin.path!=config.jvm_args_path) {
        let parent=Parent::open(pin.path.parent().context("profile input parent")?)?;let image=parent.read(&pin.path,256<<20)?.image;
        ensure!(image.sha256==pin.sha256,"CONFLICT: original recovery input changed");files.push(Slot{path:pin.path.clone(),parent:parent.identity,image:Some(image)});
    }Ok((proof,files))
}
fn capture(root:&Path,plan:&Plan,journal:&Journal,systemctl:&Path)->Result<Snapshot> {
    let config:Config=serde_json::from_str(&plan.source_profile)?;no_job(systemctl,&config.unit)?;
    let unit=crate::system_control::inspect_stopped_unit(systemctl,&config.unit)?;
    ensure!(unit.unit_file_state==plan.before_unit.unit_file_state
        && plan.stop_policy.as_ref()==Some(&crate::system_control::inspect_stop_policy(systemctl,&config)?),"CONFLICT: recovery stopped unit policy changed");
    let (evidence,files)=capture_files(root,plan,journal)?;no_job(systemctl,&config.unit)?;
    ensure!(crate::system_control::inspect_stopped_unit(systemctl,&config.unit)?==unit,"CONFLICT: recovery stopped unit changed during inspection");
    Ok(Snapshot{evidence,files,unit})
}
fn target(review:&Review)->bool {needs_copy(review) && review.snapshot.files[0].image.is_some()}
fn needs_copy(review:&Review)->bool {review.snapshot.files[1].image.is_some()}
fn inspect(root:&Path,plan:&Plan,journal:&Journal,snapshot:&Snapshot)->Result<()> {
    let (_,intent)=evidence(root,plan,journal)?;let count=snapshot.evidence.publication_steps.len();
    let args=&snapshot.files[0].image;let backup=&snapshot.files[1].image;
    if let Some(backup)=backup {
        ensure!(original_inode(backup,&plan.source_args_image),"CONFLICT: original recovery backup inode/hash/metadata changed");
        if let Some(args)=args {ensure!(args.sha256==intent.steps[1].sha256 && args.metadata==intent.steps[1].metadata
            && (args.device!=backup.device || args.inode!=backup.inode),"CONFLICT: foreign arguments cannot be compensated");}
    }else {ensure!(count==0 && args.as_ref()==Some(&plan.source_args_image),"CONFLICT: original recovery preimage missing");}
    for (index,step) in intent.steps.iter().enumerate() {
        let observed=if index==0{backup}else if index==1{args}else{&snapshot.files[index].image};
        if index<count {
            let bytes=read(&step_path(root,plan.operation_id,index as u8))?;
            ensure!(durable::hash(&bytes)==snapshot.evidence.publication_steps[index],"CONFLICT: recovery original step evidence changed");
            let receipt:super::StepReceipt=serde_json::from_slice(&bytes)?;
            ensure!(observed.as_ref()==Some(&receipt.image),"CONFLICT: acknowledged original recovery image changed");
        }else if index>=2 {
            if let Some(image)=observed {ensure!(step.before.as_ref()==Some(image) || (step.before.is_none() && image.sha256==step.sha256 && image.metadata==step.metadata),
                "CONFLICT: foreign original fence/profile cannot be adopted for recovery");}
            else {ensure!(step.before.is_none(),"CONFLICT: original retained recovery fence missing");}
        }
    }Ok(())
}
fn load_record(root:&Path,plan:&Plan,journal:&Journal,id:uuid::Uuid)->Result<Record> {
    let raw=read(&artifact(root,plan.operation_id,id,"plan"))?;let hash=durable::hash(&raw);let review:Review=serde_json::from_slice(&raw)?;
    let ledger:Ledger=serde_json::from_slice(&read(&artifact(root,plan.operation_id,id,"journal"))?)?;
    let config:Config=serde_json::from_str(&plan.source_profile)?;
    let expected=config.jvm_args_path.with_file_name(format!(".{}.nm-recovered-{id}",config.jvm_args_path.file_name().and_then(|x|x.to_str()).context("recovery arguments filename")?));
    ensure!(plan.schema_version==4 && review.schema_version==1 && review.operation_id==plan.operation_id && review.recovery_id==id && !id.is_nil()
        && review.startup_plan_sha256==journal.plan_sha256 && review.parent_plan_sha256==plan.parent_plan_sha256 && review.actor==plan.actor
        && ledger.schema_version==1 && ledger.recovery_id==id && ledger.review_sha256==hash && hex(&ledger.confirmation_token,32)
        && review.token_sha256==durable::hash(ledger.confirmation_token.as_bytes()) && review.quarantine==expected
        && review.snapshot.files.len()==config.profile_files.len()+7 && review.snapshot.files[0].path==config.jvm_args_path
        && review.snapshot.files[1].path==backup(&config,plan.operation_id)? && review.snapshot.unit.stopped()
        && review.snapshot.unit.unit==config.unit && review.snapshot.unit.unit_file_state==plan.before_unit.unit_file_state,
        "CONFLICT: original file recovery review binding");
    let sealed=|suffix:&str|->Result<Option<String>> {
        let path=artifact(root,plan.operation_id,id,suffix);if !present(&path)?{return Ok(None);}
        let bytes=read(&path)?;let seal:Seal=serde_json::from_slice(&bytes)?;
        ensure!(seal.schema_version==1 && seal.recovery_id==id && seal.review_sha256==hash,"CONFLICT: recovery intent/cancel binding");Ok(Some(durable::hash(&bytes)))
    };
    let intent=sealed("intent")?;let cancel=sealed("cancel")?;let mut steps=Vec::new();let mut gap=false;
    for index in 0..2 {
        let path=artifact(root,plan.operation_id,id,&format!("step-{index}"));if !present(&path)?{gap=true;continue;}
        ensure!(!gap && intent.is_some(),"OUTCOME_UNKNOWN: recovery receipt prefix incomplete");
        let bytes=read(&path)?;let step:StepReceipt=serde_json::from_slice(&bytes)?;
        ensure!(step.schema_version==1 && step.recovery_id==id && step.intent_sha256.as_str()==intent.as_deref().unwrap() && step.index==index,
            "CONFLICT: recovery step binding");
        if index==0 {
            if target(&review){ensure!(step.image.as_ref().zip(review.snapshot.files[0].image.as_ref()).is_some_and(|(image,before)|original_inode(image,before)),"CONFLICT: recovery quarantine identity");}
            else{ensure!(step.image.is_none(),"CONFLICT: unexpected recovery quarantine receipt");}
        }else {let image=step.image.as_ref().context("CONFLICT: recovery restored image missing")?;
            ensure!(image.sha256==plan.source_args_image.sha256 && image.metadata==plan.source_args_image.metadata && image.size==plan.source_args_image.size && image.inode>0
                && if needs_copy(&review){review.snapshot.files[1].image.as_ref().is_some_and(|backup|image.device==backup.device && image.inode!=backup.inode)}else{review.snapshot.files[0].image.as_ref()==Some(image)},
                "CONFLICT: recovery restored arguments identity");}
        steps.push((durable::hash(&bytes),step));
    }
    let path=artifact(root,plan.operation_id,id,"receipt");let receipt=if present(&path)? {
        let bytes=read(&path)?;let value:Receipt=serde_json::from_slice(&bytes)?;
        ensure!(value.schema_version==1 && value.recovery_id==id && value.review_sha256==hash && Some(value.intent_sha256.as_str())==intent.as_deref()
            && steps.len()==2 && value.steps==steps.iter().map(|(hash,_)|hash.clone()).collect::<Vec<_>>(),"OUTCOME_UNKNOWN: recovery aggregate receipt incomplete");Some(durable::hash(&bytes))
    }else{None};
    ensure!(!(intent.is_some() && cancel.is_some()) && (cancel.is_none() || (steps.is_empty() && receipt.is_none()))
        && ledger.intent_sha256.as_ref().is_none_or(|hash|intent.as_ref()==Some(hash))
        && ledger.receipt_sha256.as_ref().is_none_or(|hash|receipt.as_ref()==Some(hash))
        && ledger.cancel_sha256.as_ref().is_none_or(|hash|cancel.as_ref()==Some(hash))
        && match ledger.state.as_str(){"PREPARED"=>ledger.intent_sha256.is_none() && ledger.receipt_sha256.is_none() && ledger.cancel_sha256.is_none(),
            "EXECUTING"=>ledger.intent_sha256.is_some() && ledger.receipt_sha256.is_none() && ledger.cancel_sha256.is_none(),
            "RESTORED"=>ledger.intent_sha256.is_some() && ledger.receipt_sha256.is_some() && ledger.cancel_sha256.is_none(),
            "CANCELLED"=>ledger.cancel_sha256.is_some() && intent.is_none(),_=>false},"OUTCOME_UNKNOWN: recovery journal/receipt pointers incomplete");
    Ok(Record{review,ledger,hash,intent,steps,receipt,cancel})
}
fn history(root:&Path,plan:&Plan,journal:&Journal)->Result<Vec<Record>> {
    let prefix=format!("{}.startup-recovery-",plan.operation_id);let mut ids=BTreeSet::new();
    for (index,entry) in fs::read_dir(root)?.enumerate() {
        ensure!(index<4096,"RESOURCE_EXHAUSTED: original recovery directory inventory");let entry=entry?;let name=entry.file_name();let name=name.to_string_lossy();
        let Some(rest)=name.strip_prefix(&prefix)else{continue};let (id,suffix)=rest.split_once('.').context("OUTCOME_UNKNOWN: unrecognized recovery artifact")?;
        ensure!(["plan.json","journal.json","intent.json","receipt.json","cancel.json","step-0.json","step-1.json"].contains(&suffix),"OUTCOME_UNKNOWN: unrecognized recovery artifact suffix");
        let parsed=uuid::Uuid::parse_str(id).context("OUTCOME_UNKNOWN: invalid recovery artifact identity")?;
        ensure!(parsed.to_string()==id,"OUTCOME_UNKNOWN: noncanonical recovery artifact identity");
        ids.insert(parsed);ensure!(ids.len()<=16,"RESOURCE_EXHAUSTED: retained original recovery reviews");
    }
    let records=ids.into_iter().map(|id|load_record(root,plan,journal,id).context("OUTCOME_UNKNOWN: original recovery evidence is incomplete or inconsistent")).collect::<Result<Vec<_>>>()?;
    if let Some(link)=&journal.recovery {ensure!(records.iter().any(|record|record.review.recovery_id==link.id && record.hash==link.plan_sha256),"OUTCOME_UNKNOWN: linked recovery review missing");}
    Ok(records)
}
pub(in crate::nm::handover::startup) fn forward_allowed(root:&Path,plan:&Plan,journal:&Journal)->Result<()> {
    ensure!(history(root,plan,journal)?.iter().all(|r|r.ledger.state=="CANCELLED" && r.cancel.as_ref()==r.ledger.cancel_sha256.as_ref()),
        "CONFLICT: explicit original file recovery excludes forward startup actions");Ok(())
}
fn state(r:&Record)->&'static str {if r.cancel.is_some(){"CANCELLED"}else if r.receipt.is_some(){"ARGUMENTS_RESTORED"}else if r.intent.is_some(){"RECOVERY_OUTCOME_UNKNOWN"}else{"PREPARED"}}
fn value(r:&Record,linked:bool,token:bool)->Value {
    let mut value=json!({"recoveryId":r.review.recovery_id,"planSha256":r.hash,"state":state(r),"linked":linked,
        "expiresAtUnixMs":r.review.expires_at_unix_ms,"intentSha256":r.intent,"receiptSha256":r.receipt,"acknowledgedSteps":r.steps.len(),
        "quarantinePlanned":target(&r.review),"originalBackupRetained":true,"fencesRetained":true,"originalUnknownCleared":false,
        "ledgerState":r.ledger.state,"currentProfileSelectionRequiresFreshFiles":true,
        "redispatchAllowed":false,"systemAdoptionVerified":false,"receiptScope":"original-argument-file-compensation-only"});
    if token{value["confirmationToken"]=json!(r.ledger.confirmation_token);}value
}
pub(in crate::nm::handover::startup) fn status(root:&Path,plan:&Plan,journal:&Journal,token:bool)->Result<Option<Value>> {
    let records=history(root,plan,journal)?;let active=records.iter().filter(|r|r.ledger.state!="CANCELLED").collect::<Vec<_>>();
    ensure!(active.len()<=1,"OUTCOME_UNKNOWN: multiple active original recovery records");
    let selected=active.first().copied().or_else(||journal.recovery.as_ref().and_then(|link|records.iter().find(|r|r.review.recovery_id==link.id)));
    Ok(selected.map(|r|value(r,journal.recovery.as_ref().is_some_and(|link|link.id==r.review.recovery_id && link.plan_sha256==r.hash),token)))
}
fn link(root:&Path,plan:&Plan,journal:&mut Journal,r:&Record)->Result<()> {
    for suffix in ["plan","journal"]{
        let file=BoundFile::open(&artifact(root,plan.operation_id,r.review.recovery_id,suffix),PLAN_LIMIT)?;
        ensure!(if suffix=="plan"{durable::hash(&file.bytes)==r.hash}else{serde_json::from_slice::<Value>(&file.bytes)?==serde_json::to_value(&r.ledger)?},
            "CONFLICT: recovery review evidence changed before link acknowledgement");file.sync_exact()?;
    }
    journal.recovery=Some(RecoveryLink{id:r.review.recovery_id,plan_sha256:r.hash.clone()});
    durable::json(&super::super::paths(root,plan.operation_id).1,journal).context("OUTCOME_UNKNOWN: recovery original link acknowledgement uncertain")
}
pub(in crate::nm::handover::startup) fn prepare(root:&Path,original:&Requirements,actor:&str,token:&str,id:uuid::Uuid,systemctl:&Path)->Result<Value> {
    ensure!(!id.is_nil() && id!=original.operation,"INVALID_ARGUMENT: fresh recovery identity required");let (plan,mut journal)=authorized(root,original,actor,token)?;
    ensure!(plan.schema_version==4 && !original.recovering(),"FORBIDDEN: fenced current startup required for compensation");
    let records=history(root,&plan,&journal)?;let execution=execution::Execution::acquire(root,&plan,&journal)?;
    if let Some(r)=records.iter().find(|r|r.review.recovery_id==id) {
        ensure!(records.iter().all(|other|other.review.recovery_id==id || other.ledger.state=="CANCELLED"),"OUTCOME_UNKNOWN: another original recovery review is active");
        // Complete private review evidence may acknowledge a lost link. This
        // neither rebuilds the review nor dispatches a compensation command.
        execution.verify()?;link(root,&plan,&mut journal,r)?;execution.verify()?;return Ok(value(r,true,true));
    }
    forward_allowed(root,&plan,&journal)?;ensure!(records.len()<16,"RESOURCE_EXHAUSTED: retained recovery review limit");
    let snapshot=capture(root,&plan,&journal,systemctl)?;inspect(root,&plan,&journal,&snapshot)?;
    let path=&snapshot.files[0].path;let quarantine=path.with_file_name(format!(".{}.nm-recovered-{id}",path.file_name().and_then(|x|x.to_str()).context("recovery filename")?));
    ensure!(quarantine.file_name().unwrap().as_bytes().len()<=255 && !Parent::bound(&snapshot.files[0].parent)?.exists(&quarantine)?,"CONFLICT: recovery quarantine destination unavailable");
    ensure!(capture(root,&plan,&journal,systemctl)?==snapshot,"CONFLICT: recovery original changed during review");
    let secret=uuid::Uuid::new_v4().simple().to_string();let config:Config=serde_json::from_str(&plan.source_profile)?;
    let review=Review{schema_version:1,operation_id:plan.operation_id,recovery_id:id,startup_plan_sha256:journal.plan_sha256.clone(),parent_plan_sha256:plan.parent_plan_sha256.clone(),actor:actor.into(),
        token_sha256:durable::hash(secret.as_bytes()),snapshot,quarantine,expires_at_unix_ms:now()?+config.valid_for_seconds*1000};
    let bytes=serde_json::to_vec(&review)?;ensure!(bytes.len() as u64<=PLAN_LIMIT.min(LIMIT),"RESOURCE_EXHAUSTED: recovery review quota");
    let ledger=Ledger{schema_version:1,recovery_id:id,review_sha256:durable::hash(&bytes),confirmation_token:secret,state:"PREPARED".into(),intent_sha256:None,receipt_sha256:None,cancel_sha256:None};
    execution.verify()?;durable::publish_new(&artifact(root,plan.operation_id,id,"plan"),&bytes,FileMetadata::private()).context("OUTCOME_UNKNOWN: recovery review publication uncertain;query this recovery identity")?;
    durable::publish_new(&artifact(root,plan.operation_id,id,"journal"),&serde_json::to_vec(&ledger)?,FileMetadata::private()).context("OUTCOME_UNKNOWN: recovery journal publication uncertain;query this recovery identity")?;
    let r=load_record(root,&plan,&journal,id)?;link(root,&plan,&mut journal,&r)?;execution.verify()?;Ok(value(&r,true,true))
}
fn now()->Result<u64>{Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64)}
fn confirmed(root:&Path,original:&Requirements,actor:&str,token:&str,id:uuid::Uuid,recovery_token:&str)->Result<(Plan,Journal,Record)> {
    let (plan,journal)=authorized(root,original,actor,token)?;let records=history(root,&plan,&journal)?;
    let r=records.into_iter().find(|r|r.review.recovery_id==id).context("NOT_FOUND: original recovery review missing")?;
    ensure!(hex(recovery_token,32) && recovery_token==r.ledger.confirmation_token && journal.recovery.as_ref().is_some_and(|link|link.id==id && link.plan_sha256==r.hash),"FORBIDDEN: linked original recovery token required");
    Ok((plan,journal,r))
}
pub(in crate::nm::handover::startup) fn original(root:&Path,original:&Requirements,actor:&str,token:&str,id:uuid::Uuid)->Result<Value> {
    let (plan,journal)=authorized(root,original,actor,token)?;let records=history(root,&plan,&journal)?;
    let r=records.iter().find(|r|r.review.recovery_id==id).context("NOT_FOUND: original recovery review missing")?;
    Ok(value(r,journal.recovery.as_ref().is_some_and(|link|link.id==id && link.plan_sha256==r.hash),true))
}
pub(in crate::nm::handover::startup) fn cancel(root:&Path,original:&Requirements,actor:&str,token:&str,id:uuid::Uuid,recovery_token:&str)->Result<Value> {
    let (plan,journal,mut r)=confirmed(root,original,actor,token,id,recovery_token)?;
    ensure!(r.intent.is_none() && r.steps.is_empty() && r.receipt.is_none(),"OUTCOME_UNKNOWN: issued recovery cannot be cancelled");
    let execution=execution::Execution::acquire(root,&plan,&journal)?;execution.verify()?;
    if r.cancel.is_none(){durable::publish_new(&artifact(root,plan.operation_id,id,"cancel"),&serde_json::to_vec(&Seal{schema_version:1,recovery_id:id,review_sha256:r.hash.clone()})?,FileMetadata::private())
        .context("OUTCOME_UNKNOWN: recovery cancellation receipt publication uncertain")?;}
    r=load_record(root,&plan,&journal,id)?;
    let file=BoundFile::open(&artifact(root,plan.operation_id,id,"cancel"),PLAN_LIMIT)?;file.sync_exact()?;
    ensure!(r.cancel.as_deref()==Some(durable::hash(&file.bytes).as_str()),"CONFLICT: recovery cancellation receipt changed before acknowledgement");
    r.ledger.state="CANCELLED".into();r.ledger.cancel_sha256=Some(durable::hash(&file.bytes));
    durable::json(&artifact(root,plan.operation_id,id,"journal"),&r.ledger).context("OUTCOME_UNKNOWN: recovery cancellation pointer uncertain")?;execution.verify()?;
    Ok(value(&load_record(root,&plan,&journal,id)?,true,true))
}
pub(in crate::nm) enum Step {Observed(Value),Dispatch(Box<Command>)}
pub(in crate::nm) struct Command {root:PathBuf,systemctl:PathBuf,plan:Plan,journal:Journal,record:Record,execution:execution::Execution}
pub(in crate::nm::handover::startup) fn begin(root:&Path,original:&Requirements,actor:&str,token:&str,id:uuid::Uuid,recovery_token:&str,systemctl:&Path)->Result<Step> {
    let (plan,journal,mut r)=confirmed(root,original,actor,token,id,recovery_token)?;
    let execution=execution::Execution::acquire(root,&plan,&journal)?;
    if r.receipt.is_some(){acknowledge(root,&plan,&mut r)?;execution.verify()?;return Ok(Step::Observed(value(&r,true,true)));}
    if r.intent.is_some() || r.cancel.is_some(){return Ok(Step::Observed(value(&r,true,true)));}
    ensure!(!original.recovering() && now()?<=r.review.expires_at_unix_ms,"EXPIRED: original recovery review expired or activation already issued");
    ensure!(capture(root,&plan,&journal,systemctl)?==r.review.snapshot,"CONFLICT: recovery reviewed inputs changed");
    inspect(root,&plan,&journal,&r.review.snapshot)?;ensure!(!Parent::bound(&r.review.snapshot.files[0].parent)?.exists(&r.review.quarantine)?,"CONFLICT: recovery quarantine no longer absent");
    execution.verify()?;let bytes=serde_json::to_vec(&Seal{schema_version:1,recovery_id:id,review_sha256:r.hash.clone()})?;
    durable::publish_new(&artifact(root,plan.operation_id,id,"intent"),&bytes,FileMetadata::private()).context("OUTCOME_UNKNOWN: recovery intent publication;never redispatch")?;
    r.ledger.intent_sha256=Some(durable::hash(&bytes));r.ledger.state="EXECUTING".into();
    durable::json(&artifact(root,plan.operation_id,id,"journal"),&r.ledger).context("OUTCOME_UNKNOWN: recovery admission pointer;never redispatch")?;
    let record=load_record(root,&plan,&journal,id)?;
    Ok(Step::Dispatch(Box::new(Command{root:root.into(),systemctl:systemctl.into(),plan,journal,record,execution})))
}
fn expected_files(r:&Record)->Vec<Slot> {
    let mut files=r.review.snapshot.files.clone();
    if !r.steps.is_empty() && target(&r.review){files[0].image=None;}
    if let Some((_,step))=r.steps.get(1){files[0].image=step.image.clone();}files
}
fn physical(root:&Path,plan:&Plan,journal:&Journal,r:&Record)->Result<()> {
    let (proof,files)=capture_files(root,plan,journal)?;
    ensure!(proof==r.review.snapshot.evidence && files==expected_files(r),"CONFLICT: recovery file authority changed");
    let parent=Parent::bound(&files[0].parent)?;
    if let Some((_,step))=r.steps.first().filter(|_|target(&r.review)) {
        ensure!(parent.read(&r.review.quarantine,ARGS_LIMIT)?.image==*step.image.as_ref().unwrap(),"CONFLICT: recovery quarantine changed");
    }else {ensure!(!parent.exists(&r.review.quarantine)?,"CONFLICT: recovery quarantine unexpectedly exists");}Ok(())
}
fn shared(root:&Path,plan:&Plan,journal:&Journal,r:&Record,systemctl:&Path)->Result<()> {
    physical(root,plan,journal,r)?;let current=capture(root,plan,journal,systemctl)?;
    ensure!(current.unit==r.review.snapshot.unit && current.evidence==r.review.snapshot.evidence && current.files==expected_files(r),"CONFLICT: recovery unit/source changed");Ok(())
}
fn acknowledge(root:&Path,plan:&Plan,r:&mut Record)->Result<()> {
    let hash=r.receipt.as_ref().context("OUTCOME_UNKNOWN: missing recovery receipt cannot be rebuilt")?;
    for (suffix,expected) in [("intent",r.intent.as_ref().unwrap()),("step-0",&r.steps[0].0),("step-1",&r.steps[1].0),("receipt",hash)] {
        let file=BoundFile::open(&artifact(root,plan.operation_id,r.review.recovery_id,suffix),PLAN_LIMIT)?;
        ensure!(durable::hash(&file.bytes)==*expected,"CONFLICT: recovery acknowledgement evidence changed");file.sync_exact()?;
    }
    if r.ledger.receipt_sha256.as_ref()!=Some(hash) || r.ledger.intent_sha256!=r.intent {
        r.ledger.state="RESTORED".into();r.ledger.intent_sha256=r.intent.clone();r.ledger.receipt_sha256=Some(hash.clone());
        durable::json(&artifact(root,plan.operation_id,r.review.recovery_id,"journal"),&r.ledger)?;
    }Ok(())
}
impl Command {
    pub(in crate::nm) fn execute(self)->Result<Value>{self.execute_inner().context("OUTCOME_UNKNOWN: original file compensation requires its own receipts;never redispatch")}
    fn effect(&self,index:u8)->Result<StepReceipt> {
        let id=self.record.review.recovery_id;
        let parent=Parent::bound(&self.record.review.snapshot.files[0].parent)?;let path=&self.record.review.snapshot.files[0].path;
        let image=if index==0 {
            if target(&self.record.review){
                let before=parent.read(path,ARGS_LIMIT)?;
                ensure!(Some(&before.image)==self.record.review.snapshot.files[0].image.as_ref(),"CONFLICT: planned argument identity changed before quarantine");
                parent.verify_file(path,&before)?;parent.retain(path,&self.record.review.quarantine)?;
                let file=parent.read(&self.record.review.quarantine,ARGS_LIMIT)?;
                ensure!(original_inode(&file.image,&before.image),"CONFLICT: quarantined argument inode changed");
                parent.sync(&self.record.review.quarantine,&file)?;Some(file.image)
            }else{None}
        }else{
            if needs_copy(&self.record.review) {
                let backup=parent.read(&self.record.review.snapshot.files[1].path,ARGS_LIMIT)?;
                ensure!(Some(&backup.image)==self.record.review.snapshot.files[1].image.as_ref(),"CONFLICT: original recovery backup changed before copy");
                parent.sync(&self.record.review.snapshot.files[1].path,&backup)?;
                parent.publish(path,&backup.bytes,self.plan.source_args_image.metadata,id,1)?;
                parent.verify_file(&self.record.review.snapshot.files[1].path,&backup)?;
            }
            let file=parent.read(path,ARGS_LIMIT)?;parent.sync(path,&file)?;Some(file.image)
        };
        Ok(StepReceipt{schema_version:1,recovery_id:id,intent_sha256:self.record.intent.clone().unwrap(),index,image})
    }
    #[cfg(test)]
    pub(in crate::nm::handover::startup) fn fixture_prefix(mut self,count:u8,unacknowledged:bool)->Result<()> {
        ensure!((1..=2).contains(&count),"fixture prefix range");
        for index in 0..count {
            shared(&self.root,&self.plan,&self.journal,&self.record,&self.systemctl)?;self.execution.verify()?;
            let step=self.effect(index)?;
            if unacknowledged && index+1==count{return Ok(());}
            durable::publish_new(&artifact(&self.root,self.plan.operation_id,self.record.review.recovery_id,&format!("step-{index}")),&serde_json::to_vec(&step)?,FileMetadata::private())?;
            self.record=load_record(&self.root,&self.plan,&self.journal,self.record.review.recovery_id)?;
        }Ok(())
    }
    fn execute_inner(mut self)->Result<Value> {
        let id=self.record.review.recovery_id;self.execution.verify()?;
        let (_,journal)=load(&self.root,self.plan.operation_id,&self.plan.parent_plan_sha256)?.context("CONFLICT: original startup child missing")?;
        let admitted=load_record(&self.root,&self.plan,&journal,id)?;
        ensure!(admitted.hash==self.record.hash && admitted.intent==self.record.intent && admitted.steps.is_empty() && admitted.receipt.is_none()
            && journal.recovery.as_ref().is_some_and(|link|link.id==id && link.plan_sha256==admitted.hash),"CONFLICT: recovery admission changed");
        self.journal=journal;ensure!(now()?<=self.record.review.expires_at_unix_ms,"EXPIRED: recovery review expired before first effect");
        for index in 0..2 {
            shared(&self.root,&self.plan,&self.journal,&self.record,&self.systemctl)?;self.execution.verify()?;
            let step=self.effect(index)?;
            let bytes=serde_json::to_vec(&step)?;self.execution.verify()?;
            durable::publish_new(&artifact(&self.root,self.plan.operation_id,id,&format!("step-{index}")),&bytes,FileMetadata::private())?;
            self.record=load_record(&self.root,&self.plan,&self.journal,id)?;
        }
        shared(&self.root,&self.plan,&self.journal,&self.record,&self.systemctl)?;self.execution.verify()?;
        let receipt=Receipt{schema_version:1,recovery_id:id,review_sha256:self.record.hash.clone(),intent_sha256:self.record.intent.clone().unwrap(),steps:self.record.steps.iter().map(|(hash,_)|hash.clone()).collect()};
        durable::publish_new(&artifact(&self.root,self.plan.operation_id,id,"receipt"),&serde_json::to_vec(&receipt)?,FileMetadata::private())?;
        self.record=load_record(&self.root,&self.plan,&self.journal,id)?;acknowledge(&self.root,&self.plan,&mut self.record)?;self.execution.verify()?;
        Ok(value(&self.record,true,true))
    }
}
pub(in crate::nm::handover::startup) fn selected(root:&Path,plan:&Plan,journal:&Journal)->Result<Option<Vec<u8>>> {
    let records=history(root,plan,journal)?;
    let Some(r)=records.iter().find(|r|r.ledger.state!="CANCELLED")else{return Ok(None)};
    ensure!(journal.recovery.as_ref().is_some_and(|link|link.id==r.review.recovery_id && link.plan_sha256==r.hash)
        && r.receipt.is_some() && r.receipt.as_ref()==r.ledger.receipt_sha256.as_ref() && r.ledger.state=="RESTORED",
        "OUTCOME_UNKNOWN: original recovery has no acknowledged restored generation");
    physical(root,plan,journal,r)?;Ok(Some(plan.source_profile.as_bytes().to_vec()))
}
