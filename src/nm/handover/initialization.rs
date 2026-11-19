//! Imported policy publication is a once-only phase of the SAME ownership
//! journal. The original baseline is never replaced by initialized observations.
use super::*;
use std::collections::BTreeMap;
mod projection;
mod journal;
pub(crate) use journal::producer;
pub(crate) use native::lineage::{BootImage, validate_boot_readback};
/// Original query with a fresh read-only native observation when needed. The
/// caller authenticates the registered exact UID and holds the observation guard.
pub(crate) fn original_native_outcome(root:&Path,uid:u32,input:producer::Outcome,
    read:impl FnOnce()->Result<Value>)->Result<Value> {
    let deadline=std::time::Instant::now()+std::time::Duration::from_secs(30);
    producer::execution::outcome(root,uid,input,||native::raw::observe(read,deadline))
}


const POLICY:&str="firewall/imported-confirmed.json";
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Document {
    schema_version:u8,revision:u64,operation_id:uuid::Uuid,plan_sha256:String,
    original_source_digest:String,original_firewall_digest:String,
    marker_path:PathBuf,roles:roles::Observation,writer_model:Value,native_transfer:native::Transfer,kernel:Value,
    #[serde(default,skip_serializing_if="Option::is_none")]native_epoch:Option<native::epoch::Epoch>,
}
impl Document {
    fn validate(&self)->Result<String> {
        ensure!([1,2].contains(&self.schema_version)&&(self.schema_version==2)==self.native_epoch.is_some()&&self.revision==1&&!self.operation_id.is_nil()&&hex(&self.plan_sha256,64)&&hex(&self.original_firewall_digest,64),"CONFLICT: imported initialization identity");
        if let Some(epoch)=&self.native_epoch {epoch.validate()?;}
        ensure!(self.marker_path.is_absolute()&&self.marker_path.as_os_str().len()<=4096,"CONFLICT: initialized marker path");
        self.native_transfer.validate()?;
        ensure!(self.native_transfer.operation_id==self.operation_id&&self.native_transfer.source_binding()?==self.original_source_digest,"CONFLICT: initialized policy lost original source binding");
        let origin=roles::Origin::new(self.roles.agent_instance,self.roles.bridge_epoch,&self.roles,self.writer_model.clone())?;
        ensure!(self.native_transfer.source_model_sha256.as_ref()==Some(&digest(&origin.parameters()?)?),"CONFLICT: initialized writer model differs from original");
        let before=json!({"revision":0,"confirmedSha256":"","journalSettled":true});
        ensure!(digest(&before)?==self.original_firewall_digest,"CONFLICT: imported policy requires the original uninitialized firewall source");
        self.native_transfer.acknowledge(&self.kernel,false)
    }
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
enum Phase {Intent,Committed}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(super) struct Step {schema_version:u8,state:Phase,document:Document,document_sha256:String,#[serde(default,skip_serializing_if="Option::is_none")]file:Option<MarkerIdentity>}
impl Step {
    pub(super) fn parameters(&self)->Result<Value> {
        Ok(json!({"schemaVersion":1,"state":self.state,"operationId":self.document.operation_id,"originalSourceDigest":self.document.original_source_digest,
            "originalFirewallDigest":self.document.original_firewall_digest,"initializedPolicySha256":self.document_sha256,"initializedRevision":self.document.revision,
            "initializedLayoutSha256":self.document.native_transfer.acknowledge(&self.document.kernel,false)?,"receiptSha256":digest(&serde_json::to_value(self)?)?}))
    }
}
fn present(path:&Path)->Result<bool> {match fs::symlink_metadata(path){Ok(_)=>Ok(true),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(false),Err(e)=>Err(e.into())}}

impl Store {
    pub(super) fn require_initialization_ready(&self,j:&Journal,p:&Plan)->Result<()> {
        if p.baseline.native_transfer.as_ref().is_some_and(|native|native.source_model_sha256.is_some()) {
            let step=j.initialization.as_ref().filter(|step|step.state==Phase::Committed).context("OUTCOME_UNKNOWN: original imported initialization must be committed before startup or owner activation")?;
            let file=BoundFile::open(&self.initialization_target()?,LIMIT)?;
            ensure!(step.file.as_ref()==Some(&file.marker()?)&&file.bytes==serde_json::to_vec(&step.document)?,"CONFLICT: original initialized policy is missing or changed");
        }
        Ok(())
    }
    pub(super) fn validate_initialization_journal(&self,j:&Journal,p:&Plan)->Result<()> {
        if let Some(step)=&j.initialization {
            ensure!(step.schema_version==1&&matches!(j.state,State::Fenced|State::LeaseIntent|State::Committed),"CONFLICT: initialization outside the original paired fence");
            ensure!(p.baseline.native_transfer.as_ref()==Some(&step.document.native_transfer)&&step.document.operation_id==j.operation_id&&step.document.plan_sha256==j.plan_sha256
                &&step.document.marker_path==self.marker&&step.document.roles==p.baseline.roles&&step.document.original_source_digest==p.baseline.source_digest&&step.document.original_firewall_digest==p.baseline.firewall_digest,
                "CONFLICT: initialization changed original operation/plan/baseline");
            let kernel=step.document.validate()?;
            ensure!(step.document.native_epoch==self.native_epoch(j),"CONFLICT: initialization physical epoch differs from its original native intent");
            ensure!(self.native_applied_digest(j)?==kernel&&durable::hash(&serde_json::to_vec(&step.document)?)==step.document_sha256,"CONFLICT: initialization is not the original acknowledged native outcome");
            ensure!(match step.state{Phase::Intent=>step.file.is_none(),Phase::Committed=>step.file.as_ref().is_some_and(|f|f.sha256==step.document_sha256)},"CONFLICT: initialization receipt shape");
        }
        if matches!(j.state,State::LeaseIntent|State::Committed) {self.require_initialization_ready(j,p)?;}
        Ok(())
    }
    fn initialization_target(&self)->Result<PathBuf> {Ok(self.root.parent().context("ownership gateway root")?.join(POLICY))}
    fn initialization_document(&self,j:&Journal,p:&Plan,kernel:&Value,model:Value)->Result<Document> {
        let native=p.baseline.native_transfer.as_ref().context("UNSUPPORTED: original native plan required")?;
        ensure!(native.source_model_sha256.is_some(),"UNSUPPORTED: complete original writer binding required for initialization");
        let epoch=self.native_epoch(j).context("UNSUPPORTED: original native intent has no physical epoch;never backfill historical evidence")?;
        let document=Document{schema_version:2,revision:1,operation_id:j.operation_id,plan_sha256:j.plan_sha256.clone(),original_source_digest:p.baseline.source_digest.clone(),
            original_firewall_digest:p.baseline.firewall_digest.clone(),marker_path:self.marker.clone(),roles:p.baseline.roles.clone(),writer_model:model,native_transfer:native.clone(),kernel:native::canonical_source(kernel)?,native_epoch:Some(epoch)};
        document.validate()?;ensure!(serde_json::to_vec(&document)?.len()<=LIMIT as usize-65536,"RESOURCE_EXHAUSTED: complete imported policy evidence");Ok(document)
    }
    pub(in crate::nm) fn initialize_policy(&self,id:uuid::Uuid,token:&str,actor:&str,
        inspect:impl FnMut(&Baseline,uuid::Uuid,&str)->Result<(Value,Value)>,publish:impl FnOnce(&Path,&[u8])->Result<()>)->Result<Value> {
        self.initialize_policy_at(id,token,actor,(inspect,publish,native::epoch::Epoch::capture))
    }
    #[cfg(test)]
    pub(in crate::nm) fn initialize_policy_fixture(&self,id:uuid::Uuid,token:&str,actor:&str,
        inspect:impl FnMut(&Baseline,uuid::Uuid,&str)->Result<(Value,Value)>,publish:impl FnOnce(&Path,&[u8])->Result<()>)->Result<Value> {
        self.initialize_policy_at(id,token,actor,(inspect,publish,||Ok(native::epoch::Epoch::storage_fixture())))
    }
    fn initialize_policy_at(&self,id:uuid::Uuid,token:&str,actor:&str,
        io:(impl FnMut(&Baseline,uuid::Uuid,&str)->Result<(Value,Value)>,impl FnOnce(&Path,&[u8])->Result<()>,impl FnMut()->Result<native::epoch::Epoch>))->Result<Value> {
        let (mut inspect,publish,mut observe_epoch)=io;
        let (mut journal,plan)=self.load()?.context("NOT_FOUND: original initialization plan")?;Self::authorize(&journal,token,&plan,actor)?;
        ensure!(journal.operation_id==id&&journal.state==State::Fenced,"CONFLICT: initialization requires original fenced plan");
        ensure!(journal.initialization.is_none(),"OUTCOME_UNKNOWN: query original initialization;never publish again");
        self.require_native_ready(&journal,&plan)?;startup::require_no_native_child(&self.root,id)?;self.require_pair_identity(&journal,&plan)?;
        let target=self.initialization_target()?;let gateway=self.root.parent().unwrap();
        for file in [target.clone(),gateway.join("firewall/confirmed.json"),gateway.join("firewall/transaction.json")] {ensure!(!present(&file)?,"CONFLICT: retained firewall evidence blocks imported initialization");}
        private_directory(target.parent().unwrap())?;
        let epoch=self.native_epoch(&journal).context("UNSUPPORTED: original native intent lacks physical epoch;no new initialization")?;
        epoch.require(&observe_epoch()?)?;
        let (kernel,model)=inspect(&plan.baseline,id,&journal.plan_sha256)?;
        epoch.require(&observe_epoch()?)?;
        let document=self.initialization_document(&journal,&plan,&kernel,model)?;ensure!(document.validate()?==self.native_applied_digest(&journal)?,"CONFLICT: original native outcome changed before initialization");
        let bytes=serde_json::to_vec(&document)?;let hash=durable::hash(&bytes);
        journal.initialization=Some(Step{schema_version:1,state:Phase::Intent,document,document_sha256:hash,file:None});
        ensure!(serde_json::to_vec(&journal)?.len()<=LIMIT as usize,"RESOURCE_EXHAUSTED: original initialization journal");
        ensure!(journal.marker.as_ref()==Some(&self.check_marker(&journal)?),"CONFLICT: original marker changed before initialization intent");self.require_pair_identity(&journal,&plan)?;
        epoch.require(&observe_epoch()?)?;
        durable::json(&self.journal_path(),&journal)?;
        durable::directory(target.parent().unwrap()).context("OUTCOME_UNKNOWN: original policy directory publication unavailable;query only")?;
        publish(&target,&bytes).map_err(|_|anyhow::anyhow!("OUTCOME_UNKNOWN: original policy publication reply unavailable;query only"))?;
        self.initialization_original_at(id,actor,inspect,observe_epoch).context("OUTCOME_UNKNOWN: original initialization remains unacknowledged;query only")
    }
    pub(in crate::nm) fn initialization_original(&self,id:uuid::Uuid,actor:&str,inspect:impl FnMut(&Baseline,uuid::Uuid,&str)->Result<(Value,Value)>)->Result<Value> {
        self.initialization_original_at(id,actor,inspect,native::epoch::Epoch::capture)
    }
    #[cfg(test)]
    pub(in crate::nm) fn initialization_original_fixture(&self,id:uuid::Uuid,actor:&str,inspect:impl FnMut(&Baseline,uuid::Uuid,&str)->Result<(Value,Value)>)->Result<Value> {
        self.initialization_original_at(id,actor,inspect,||Ok(native::epoch::Epoch::storage_fixture()))
    }
    fn initialization_original_at(&self,id:uuid::Uuid,actor:&str,mut inspect:impl FnMut(&Baseline,uuid::Uuid,&str)->Result<(Value,Value)>,mut observe_epoch:impl FnMut()->Result<native::epoch::Epoch>)->Result<Value> {
        let (mut journal,plan)=self.load()?.context("NOT_FOUND: original initialization plan")?;
        ensure!(journal.operation_id==id&&plan.actor==actor,"FORBIDDEN: original initialization actor required");
        let Some(step)=&journal.initialization else{return self.status();};
        let target=self.initialization_target()?;let file=BoundFile::open(&target,LIMIT).context("OUTCOME_UNKNOWN: original initialized policy is absent or unsafe;do not republish")?;
        let gateway=self.root.parent().unwrap();
        ensure!(file.bytes==serde_json::to_vec(&step.document)?,"CONFLICT: original initialized policy changed");let identity=file.marker()?;
        if step.state==Phase::Committed {
            ensure!(step.file.as_ref()==Some(&identity),"CONFLICT: acknowledged initialized policy was replaced");
            self.require_pair_identity(&journal,&plan)?;file.verify_binding()?;return self.status();
        }
        ensure!(!present(&gateway.join("firewall/confirmed.json"))?&&!present(&gateway.join("firewall/transaction.json"))?,"CONFLICT: another firewall authority appeared during initialization");
        if let Some(epoch)=&step.document.native_epoch {epoch.require(&observe_epoch()?)?;}
        let (kernel,model)=inspect(&plan.baseline,id,&journal.plan_sha256)?;
        if let Some(epoch)=&step.document.native_epoch {epoch.require(&observe_epoch()?)?;}
        ensure!(plan.baseline.native_transfer.as_ref().unwrap().acknowledge(&kernel,false)?==self.native_applied_digest(&journal)?&&digest(&model)?==digest(&step.document.writer_model)?,"CONFLICT: initialization source/model/native outcome changed");
        self.require_pair_identity(&journal,&plan)?;ensure!(journal.marker.as_ref()==Some(&self.check_marker(&journal)?),"CONFLICT: original initialization marker changed");
        match step.state {
            Phase::Intent=>{let step=journal.initialization.as_mut().unwrap();step.state=Phase::Committed;step.file=Some(identity);durable::json(&self.journal_path(),&journal)?;},
            Phase::Committed=>ensure!(step.file.as_ref()==Some(&identity),"CONFLICT: acknowledged initialized policy was replaced"),
        }
        file.verify_binding()?;self.status()
    }
}

/// A source witness, not an owner grant. The original journal and both actual
/// marker identities are rechecked; an uncommitted standalone file has no authority.
pub(crate) fn confirmed_source(root:&Path,native:Option<&Value>)->Result<Option<Value>> {
    confirmed_read(root,native,false,None,false)
}

/// Confirmed structured configuration for the registered Core API. This reads
/// the original receipt; it neither observes live kernel state nor enables writes.
pub(crate) fn core_view(root:&Path)->Result<Option<Value>> {
    confirmed_read(root,None,true,None,false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct LayoutPreview {expected_revision:u64,source_digest:String,candidate:Value,destination_prefixes:BTreeMap<String,Vec<u8>>,#[serde(default)]operation_id:Option<uuid::Uuid>}

pub(crate) fn preview_update(root:&Path,input:Value)->Result<Value> {
    let input:LayoutPreview=serde_json::from_value(input).context("INVALID_ARGUMENT: original layout preview")?;
    confirmed_read(root,None,true,Some(&input),false)?.context("UNSUPPORTED: imported confirmed source required")
}

pub(crate) fn compiled_original_layout(family:&str,layout:&Value)->Result<Value> {native::classify::compiled_layout(family,layout)}

struct Original {file:BoundFile,document:Document,origin:roles::Origin,source:Value}
fn original(root:&Path)->Result<Option<Original>> {
    original_at_marker(root, None)
}

fn original_at_marker(root: &Path, required_marker: Option<&Path>) -> Result<Option<Original>> {
    let target=root.join(POLICY);if !present(&target)? {return Ok(None);}
    let file=BoundFile::open(&target,LIMIT)?;let document:Document=serde_json::from_slice(&file.bytes)?;
    ensure!(required_marker.is_none_or(|marker| document.marker_path == marker),
        "FORBIDDEN: imported boot requires the canonical paired Root");
    let original_kernel=document.validate()?;
    let store=Store{root:root.join("nm-ownership"),marker:document.marker_path.clone()};let (journal,plan)=store.load()?.context("CONFLICT: initialized policy has no original journal")?;
    let step=journal.initialization.as_ref().filter(|step|step.state==Phase::Committed).context("OUTCOME_UNKNOWN: original initialization is not committed")?;
    ensure!(document==step.document&&step.file.as_ref()==Some(&file.marker()?)&&step.document_sha256==durable::hash(&file.bytes),"CONFLICT: initialized policy receipt differs");
    let origin=roles::Origin::new(document.roles.agent_instance,document.roles.bridge_epoch,&document.roles,document.writer_model.clone())?;
    let source=json!({"schemaVersion":1,"sourceKind":"nft.imported.confirmed.v1","revision":document.revision.to_string(),"confirmedSha256":step.document_sha256,
        "sourceDigest":step.document_sha256,"semanticDigest":original_kernel,"operationId":document.operation_id,"planSha256":document.plan_sha256,"journalSettled":true,"transaction":null,
        "originalSourceDigest":document.original_source_digest,"originalFirewallDigest":document.original_firewall_digest,"storedFirewall":origin.stored(&plan.baseline.roles)?.parameters()?,"originalStaticRules":origin.stored(&plan.baseline.roles)?.rules(),
        "initializationReceiptSha256":digest(&serde_json::to_value(step)?)?,"policy":origin.model_rules()});
    file.verify_binding()?;Ok(Some(Original{file,document,origin,source}))
}

/// Side-effect-free planning from the exact canonical lease and resolved head.
pub(crate) fn review_imported_boot(root: &Path) -> Result<Value> {
    let (owner, image) = imported_boot_source(root)?;
    let mut review = image.review()?;
    review["ownerLeaseSha256"] = json!(owner);
    Ok(review)
}

pub(crate) fn imported_boot_source(root: &Path) -> Result<(String, BootImage)> {
    let store = Store::new(root);
    let owner = store.firewall_boot_lease(5, "FORBIDDEN: complete imported paired owner lease required")?;
    let Original { file, document, origin, source } = original_at_marker(root, Some(&store.marker))?
        .context("FORBIDDEN: original imported initialization required")?;
    let current = match journal::read(root, &document, &origin, &source)? {
        Some(view) => {
            ensure!(view.settled, "OUTCOME_UNKNOWN: original imported transaction must settle before boot planning");
            view.current
        }
        None => journal::initial(&document, &origin, &source)?,
    };
    let image = BootImage::new(current)?;
    file.verify_binding()?;
    ensure!(owner == store.firewall_boot_lease(5, "FORBIDDEN: complete imported paired owner lease required")?,
        "CONFLICT: original imported lease changed during boot planning");
    Ok((owner, image))
}

fn confirmed_read(root:&Path,native:Option<&Value>,core:bool,preview:Option<&LayoutPreview>,finish_marker:bool)->Result<Option<Value>> {
    let Some(Original{file,document,origin,source:mut result})=original(root)? else{return Ok(None);};
    if finish_marker {journal::finish_marker(root,&document,&origin,&result)?;}
    let current=journal::read(root,&document,&origin,&result)?;
    if let Some(value)=native {
        if let Some(current)=current.as_ref().filter(|value|value.has_current) {current.current.require_native(value)?;}
        else {ensure!(document.native_transfer.acknowledge(value,false)?==result["semanticDigest"].as_str().unwrap(),"CONFLICT: initialized native layout changed");}
    }
    if let Some(current)=&current {
        result["journalSettled"]=json!(current.settled);result["transaction"]=serde_json::to_value(&current.transaction)?;
        if current.has_current {
            let witness=current.current.witness()?;
            for key in ["revision","sourceDigest","semanticDigest","currentPolicy","currentDestinationPrefixes","currentLayouts"] {result[key]=witness[key].clone();}
            result["confirmedSha256"]=witness["sourceDigest"].clone();
        }
    }
    let result=if core {projection::view(&document,&origin,&result)?}else{result};
    let result=if let Some(input)=preview {
        ensure!(current.as_ref().is_none_or(|value|value.settled),"OUTCOME_UNKNOWN: query the retained imported transaction before any new plan");
        projection::preview(&document,&origin,&result,input,current.as_ref().filter(|value|value.has_current).map(|value|&value.current))?
    }else{result};
    file.verify_binding()?;Ok(Some(result))
}

/// Boot recovery observes an imported transaction; the private engine must never
/// apply its text compiler or inverse to a differently tagged backend.
pub(crate) fn recover_imported_transaction(root:&Path)->Result<Option<Value>> {
    if !present(&root.join(POLICY))?&&!journal::recognized(root)? {return Ok(None);}
    let source=confirmed_read(root,None,false,None,true)?.context("CONFLICT: imported transaction has no original initialization")?;
    Ok(Some(json!({"journalSettled":source["journalSettled"],"transaction":source["transaction"]})))
}
pub(crate) fn owns_firewall_domain(root:&Path)->Result<bool> {
    Ok(present(&root.join(POLICY))? || journal::recognized(root)?)
}

/// Other system writers must not infer settlement from a missing active file.
/// The original firewall controller and ownership adjudicator validate their
/// own evidence; configuration keeps its existing independent admission rules.
pub(crate) fn transaction_settled(root:&Path)->Result<bool> {
    if let Some(source)=confirmed_source(root,None)? {return Ok(source["journalSettled"]==true);}
    ensure!(!journal::recognized(root)?,"CONFLICT: typed firewall evidence has no original initialization");
    Ok(true)
}

#[cfg(test)]
mod tests;
