//! Original-bound startup file publication. Argument preimages stay beside the
//! Kura source, never in agent journals. A retained intent never redispatches.
use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
pub(super) mod recovery;

#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Directory {path:PathBuf,device:u64,inode:u64}
struct Parent {identity:Directory,file:File}
struct Observed {image:Image,bytes:Vec<u8>,file:File}
fn name(path:&Path)->Result<std::ffi::CString> {
    std::ffi::CString::new(path.file_name().context("CONFLICT: startup filename missing")?.as_bytes()).map_err(Into::into)
}
impl Parent {
    fn open(path:&Path)->Result<Self> {
        ensure!(canonical(path),"FORBIDDEN: canonical installed startup parent required");
        let file=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(path)?;
        let info=file.metadata()?;let identity=Directory{path:path.into(),device:info.dev(),inode:info.ino()};
        let parent=Self{identity,file};parent.verify()?;Ok(parent)
    }
    fn bound(identity:&Directory)->Result<Self> {
        let parent=Self::open(&identity.path)?;
        ensure!(parent.identity==*identity,"CONFLICT: original startup parent was replaced");Ok(parent)
    }
    fn verify(&self)->Result<()> {
        let path=fs::symlink_metadata(&self.identity.path)?;let file=self.file.metadata()?;
        ensure!(path.is_dir() && file.is_dir() && path.dev()==self.identity.device && path.ino()==self.identity.inode
            && file.dev()==path.dev() && file.ino()==path.ino() && path.mode()&0o022==0
            && (path.uid()==0 || path.uid()==unsafe{libc::geteuid()}),"CONFLICT: original startup directory binding changed");Ok(())
    }
    fn child(&self,path:&Path)->Result<std::ffi::CString> {
        ensure!(canonical(path) && path.parent()==Some(self.identity.path.as_path()),"CONFLICT: startup file escaped its bound parent");name(path)
    }
    fn exists(&self,path:&Path)->Result<bool> {
        self.verify()?;let name=self.child(path)?;let mut info=std::mem::MaybeUninit::<libc::stat>::uninit();
        let result=unsafe{libc::fstatat(self.file.as_raw_fd(),name.as_ptr(),info.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)};
        if result==0{return Ok(true);}
        let error=std::io::Error::last_os_error();if error.kind()==std::io::ErrorKind::NotFound{Ok(false)}else{Err(error.into())}
    }
    fn read(&self,path:&Path,limit:u64)->Result<Observed> {
        self.verify()?;let name=self.child(path)?;
        let fd=unsafe{libc::openat(self.file.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
        ensure!(fd>=0,"CONFLICT: startup file could not be opened safely");let mut file=unsafe{File::from_raw_fd(fd)};
        let before=file.metadata()?;
        ensure!(before.is_file() && before.nlink()==1 && before.len()<=limit && before.mode()&0o022==0
            && (before.uid()==0 || before.uid()==unsafe{libc::geteuid()}),"CONFLICT: unsafe installed startup file");
        let mut bytes=Vec::new();(&mut file).take(limit+1).read_to_end(&mut bytes)?;let after=file.metadata()?;
        ensure!(after.len()==before.len() && bytes.len() as u64==after.len() && after.nlink()==1
            && after.ctime()==before.ctime() && after.ctime_nsec()==before.ctime_nsec()
            && FileMetadata::from_fs(&after)==FileMetadata::from_fs(&before),"CONFLICT: startup file changed while reading");
        let observed=Observed{image:Image{sha256:durable::hash(&bytes),metadata:FileMetadata::from_fs(&after),device:after.dev(),inode:after.ino(),
            size:after.len(),ctime:after.ctime(),ctime_nanos:after.ctime_nsec()},bytes,file};
        self.verify_file(path,&observed)?;Ok(observed)
    }
    fn verify_file(&self,path:&Path,observed:&Observed)->Result<()> {
        self.verify()?;self.child(path)?;
        let current=fs::symlink_metadata(path)?;let opened=observed.file.metadata()?;
        ensure!(current.is_file() && current.nlink()==1 && current.dev()==observed.image.device && current.ino()==observed.image.inode
            && opened.dev()==current.dev() && opened.ino()==current.ino() && opened.nlink()==1
            && opened.len()==observed.image.size && opened.ctime()==observed.image.ctime && opened.ctime_nsec()==observed.image.ctime_nanos
            && FileMetadata::from_fs(&opened)==observed.image.metadata,"CONFLICT: installed startup file identity changed");Ok(())
    }
    fn sync(&self,path:&Path,observed:&Observed)->Result<()> {
        self.verify_file(path,observed)?;observed.file.sync_all()?;self.file.sync_all()?;self.verify_file(path,observed)
    }
    fn retain(&self,source:&Path,target:&Path)->Result<()> {
        self.verify()?;ensure!(!self.exists(target)?,"CONFLICT: startup preimage destination already exists");
        let from=self.child(source)?;let to=self.child(target)?;
        #[cfg(target_os="linux")]
        let result=unsafe{libc::renameat2(self.file.as_raw_fd(),from.as_ptr(),self.file.as_raw_fd(),to.as_ptr(),libc::RENAME_NOREPLACE)};
        #[cfg(target_os="macos")]
        let result=unsafe{libc::renameatx_np(self.file.as_raw_fd(),from.as_ptr(),self.file.as_raw_fd(),to.as_ptr(),libc::RENAME_EXCL)};
        #[cfg(not(any(target_os="linux",target_os="macos")))]
        let result=-1;
        ensure!(result==0,"CONFLICT: original startup retention failed");self.file.sync_all()?;self.verify()
    }
    fn publish(&self,path:&Path,bytes:&[u8],metadata:FileMetadata,operation:uuid::Uuid,index:u8)->Result<()> {
        self.verify()?;ensure!(!self.exists(path)?,"CONFLICT: original startup create-only destination exists");
        let target=self.child(path)?;let temporary=std::ffi::CString::new(format!(".nm-startup-{operation}-{index}.new"))?;
        let fd=unsafe{libc::openat(self.file.as_raw_fd(),temporary.as_ptr(),libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};
        ensure!(fd>=0,"CONFLICT: original startup temporary already exists or cannot be created");
        let mut file=unsafe{File::from_raw_fd(fd)};
        file.write_all(bytes)?;
        let info=file.metadata()?;
        if info.uid()!=metadata.uid || info.gid()!=metadata.gid {
            ensure!(unsafe{libc::fchown(file.as_raw_fd(),metadata.uid,metadata.gid)}==0,"FORBIDDEN: startup ownership could not be retained");
        }
        file.set_permissions(fs::Permissions::from_mode(metadata.mode))?;file.sync_all()?;self.verify()?;
        ensure!(unsafe{libc::linkat(self.file.as_raw_fd(),temporary.as_ptr(),self.file.as_raw_fd(),target.as_ptr(),0)}==0,
            "CONFLICT: original startup create-only publication failed");
        ensure!(unsafe{libc::unlinkat(self.file.as_raw_fd(),temporary.as_ptr(),0)}==0,"CONFLICT: startup temporary unlink failed");
        self.file.sync_all()?;self.verify()
    }
}

#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="kebab-case")]
enum Action {RetainArguments,PublishArguments,PreserveFence,PublishFence,PublishProfile}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Step {index:u8,action:Action,path:PathBuf,parent:Directory,sha256:String,metadata:FileMetadata,before:Option<Image>}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Intent {
    schema_version:u8,operation_id:uuid::Uuid,startup_plan_sha256:String,parent_plan_sha256:String,
    stop_receipt_sha256:String,arguments_path:PathBuf,backup_path:PathBuf,profile_path:PathBuf,steps:Vec<Step>,
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct StepReceipt {schema_version:u8,operation_id:uuid::Uuid,intent_sha256:String,index:u8,image:Image}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Receipt {schema_version:u8,operation_id:uuid::Uuid,intent_sha256:String,step_sha256:Vec<String>}
fn paths(root:&Path,id:uuid::Uuid)->(PathBuf,PathBuf) {
    (root.join(format!("{id}.startup-files-intent.json")),root.join(format!("{id}.startup-files-receipt.json")))
}
fn step_path(root:&Path,id:uuid::Uuid,index:u8)->PathBuf {root.join(format!("{id}.startup-files-step-{index}.json"))}
fn backup(config:&Config,id:uuid::Uuid)->Result<PathBuf> {
    let file=config.jvm_args_path.file_name().and_then(|value|value.to_str()).context("FORBIDDEN: bounded startup filename required")?;
    let name=format!(".{file}.nm-before-{id}");ensure!(name.len()<=255,"FORBIDDEN: startup retained filename too long");
    Ok(config.jvm_args_path.parent().context("startup argument parent")?.join(name))
}
fn profile_path(root:&Path,id:uuid::Uuid)->PathBuf {root.join(format!("{id}.startup-profile.json"))}
fn original_inode(image:&Image,original:&Image)->bool {
    image.sha256==original.sha256 && image.metadata==original.metadata && image.device==original.device
        && image.inode==original.inode && image.size==original.size
}
fn definitions(root:&Path,plan:&Plan,parents:Option<&[Step]>)->Result<Vec<Step>> {
    let config:Config=serde_json::from_str(&plan.source_profile)?;let backup=backup(&config,plan.operation_id)?;
    ensure!(!config.jvm_args_path.starts_with(root) && !backup.starts_with(root),"FORBIDDEN: Kura argument preimage cannot be retained in agent ownership records");
    let (hash,_)=argument_binding(plan,&config)?;
    let mut specs=vec![(Action::RetainArguments,backup,plan.source_args_image.sha256.clone(),plan.source_args_image.metadata,Some(plan.source_args_image.clone())),
        (Action::PublishArguments,config.jvm_args_path,hash,plan.source_args_image.metadata,None)];
    for fence in &plan.fences {
        specs.push(match &fence.before {
            Some(before)=>(Action::PreserveFence,fence.path.clone(),before.sha256.clone(),before.metadata,Some(before.clone())),
            None=>(Action::PublishFence,fence.path.clone(),plan.owner_marker_identity.sha256.clone(),FileMetadata::private(),None),
        });
    }
    specs.push((Action::PublishProfile,profile_path(root,plan.operation_id),durable::hash(plan.generated_profile.as_bytes()),FileMetadata::private(),None));
    let mut steps=Vec::new();let mut directories=std::collections::BTreeMap::new();let mut slots=BTreeSet::new();
    for (index,(action,path,sha256,metadata,before)) in specs.into_iter().enumerate() {
        let parent_path=path.parent().context("startup publication parent")?;
        let parent=if let Some(known)=parents {
            let stored=known.get(index).context("CONFLICT: startup publication step missing")?;
            ensure!(stored.parent.path==parent_path && canonical(parent_path) && stored.parent.inode>0,"CONFLICT: startup publication parent binding");stored.parent.clone()
        } else {Parent::open(parent_path)?.identity};
        if let Some(previous)=directories.insert(parent.path.clone(),(parent.device,parent.inode)) {
            ensure!(previous==(parent.device,parent.inode),"CONFLICT: inconsistent original startup directory bindings");
        }
        ensure!(slots.insert((parent.device,parent.inode,path.file_name().context("startup publication filename")?.as_bytes().to_vec())),
            "CONFLICT: startup publication destinations alias the same physical slot");
        if action!=Action::RetainArguments {
            ensure!(before.as_ref().is_none_or(|image|image.device!=plan.source_args_image.device || image.inode!=plan.source_args_image.inode),
                "CONFLICT: mutable startup arguments alias a retained fence");
        }
        steps.push(Step{index:index as u8,action,path,parent,sha256,metadata,before});
    }Ok(steps)
}
fn validate_intent(root:&Path,plan:&Plan,journal:&Journal,intent:&Intent)->Result<()> {
    let config:Config=serde_json::from_str(&plan.source_profile)?;
    ensure!(plan.schema_version>=4 && intent.schema_version==1 && intent.operation_id==plan.operation_id
        && intent.startup_plan_sha256==journal.plan_sha256 && intent.parent_plan_sha256==plan.parent_plan_sha256
        && journal.stop_receipt_sha256.as_ref()==Some(&intent.stop_receipt_sha256) && intent.arguments_path==config.jvm_args_path
        && intent.backup_path==backup(&config,plan.operation_id)? && intent.profile_path==profile_path(root,plan.operation_id)
        && intent.steps.len()==6,"CONFLICT: original startup publication identity");
    let expected=definitions(root,plan,Some(&intent.steps))?;
    ensure!(serde_json::to_vec(&expected)?==serde_json::to_vec(&intent.steps)?,"CONFLICT: original startup publication transformation changed");Ok(())
}
fn validate_step(plan:&Plan,intent_hash:&str,step:&Step,receipt:&StepReceipt)->Result<()> {
    ensure!(receipt.schema_version==1 && receipt.operation_id==plan.operation_id && receipt.intent_sha256==intent_hash && receipt.index==step.index
        && receipt.image.sha256==step.sha256 && receipt.image.metadata==step.metadata && receipt.image.device==step.parent.device
        && receipt.image.inode>0 && receipt.image.size<=PLAN_LIMIT,"CONFLICT: original startup file receipt identity");
    match step.action {
        Action::RetainArguments=>ensure!(original_inode(&receipt.image,&plan.source_args_image),"CONFLICT: original Kura argument inode was not retained"),
        Action::PreserveFence=>ensure!(step.before.as_ref()==Some(&receipt.image),"CONFLICT: original retained fence changed"),
        Action::PublishArguments=>ensure!(receipt.image.device!=plan.source_args_image.device || receipt.image.inode!=plan.source_args_image.inode,
            "CONFLICT: generated arguments alias the retained original"),
        _=>{},
    }Ok(())
}
type Records=(Intent,String,Vec<String>,Option<String>);
fn records(root:&Path,plan:&Plan,journal:&Journal)->Result<Option<Records>> {
    let (intent_path,receipt_path)=paths(root,plan.operation_id);
    let (has_intent,has_receipt)=(present(&intent_path)?,present(&receipt_path)?);
    let has_step=(0..6).map(|index|present(&step_path(root,plan.operation_id,index))).collect::<Result<Vec<_>>>()?;
    if !has_intent && !has_receipt && !has_step.iter().any(|value|*value)
        && journal.publication_intent_sha256.is_none() && journal.publication_receipt_sha256.is_none(){return Ok(None);}
    ensure!(has_intent,"OUTCOME_UNKNOWN: original startup publication intent missing");
    let bytes=read(&intent_path)?;let intent_hash=durable::hash(&bytes);let intent:Intent=serde_json::from_slice(&bytes)?;
    validate_intent(root,plan,journal,&intent)?;
    ensure!(journal.publication_intent_sha256.as_ref().is_none_or(|known|known==&intent_hash),"CONFLICT: original startup publication intent digest");
    let mut hashes=Vec::new();let mut gap=false;
    for step in &intent.steps {
        if !has_step[step.index as usize]{gap=true;continue;}
        ensure!(!gap,"OUTCOME_UNKNOWN: original startup file receipt prefix incomplete");
        let bytes=read(&step_path(root,plan.operation_id,step.index))?;let receipt:StepReceipt=serde_json::from_slice(&bytes)?;
        validate_step(plan,&intent_hash,step,&receipt)?;hashes.push(durable::hash(&bytes));
    }
    ensure!(has_receipt || journal.publication_receipt_sha256.is_none(),"OUTCOME_UNKNOWN: acknowledged startup publication receipt missing");
    let receipt_hash=if has_receipt {
        let bytes=read(&receipt_path)?;let hash=durable::hash(&bytes);let receipt:Receipt=serde_json::from_slice(&bytes)?;
        ensure!(receipt.schema_version==1 && receipt.operation_id==plan.operation_id && receipt.intent_sha256==intent_hash
            && hashes.len()==6 && receipt.step_sha256==hashes
            && journal.publication_receipt_sha256.as_ref().is_none_or(|known|known==&hash),"OUTCOME_UNKNOWN: original startup publication receipt binding incomplete");Some(hash)
    }else{None};Ok(Some((intent,intent_hash,hashes,receipt_hash)))
}
pub(super) fn status(root:&Path,plan:&Plan,journal:&Journal)->Result<Option<Value>> {
    let Some((_,intent_hash,steps,receipt))=records(root,plan,journal)?else{return Ok(None)};
    Ok(Some(json!({"state":if receipt.is_some(){"FILES_PUBLISHED"}else{"PUBLICATION_OUTCOME_UNKNOWN"},
        "intentSha256":intent_hash,"receiptSha256":receipt,"acknowledgedSteps":steps.len(),"totalSteps":6,
        "redispatchAllowed":false,"receiptScope":"historical-planned-startup-files-only",
        "freshStoppedUnitRequiredBeforeStart":true,"profileSelectionCommitted":false,"systemAdoptionVerified":false})))
}
fn sync_record(path:&Path,hash:&str)->Result<()> {
    let observed=BoundFile::open(path,LIMIT)?;
    ensure!(durable::hash(&observed.bytes)==hash,"CONFLICT: original startup file evidence changed before acknowledgement");observed.sync_exact()
}
fn settle(root:&Path,plan:&Plan,journal:&mut Journal,hash:&str,steps:&[String],known:Option<&str>)->Result<()> {
    ensure!(steps.len()==6,"OUTCOME_UNKNOWN: original startup file receipts incomplete");
    sync_record(&paths(root,plan.operation_id).0,hash)?;
    for (index,hash) in steps.iter().enumerate(){sync_record(&step_path(root,plan.operation_id,index as u8),hash)?;}
    let receipt_hash=if let Some(hash)=known {sync_record(&paths(root,plan.operation_id).1,hash)?;hash.to_owned()}else{
        ensure!(journal.publication_receipt_sha256.is_none(),"OUTCOME_UNKNOWN: acknowledged startup file receipt missing");
        let receipt=Receipt{schema_version:1,operation_id:plan.operation_id,intent_sha256:hash.into(),step_sha256:steps.to_vec()};
        let bytes=serde_json::to_vec(&receipt)?;durable::publish_new(&paths(root,plan.operation_id).1,&bytes,FileMetadata::private())?;durable::hash(&bytes)
    };
    journal.publication_intent_sha256=Some(hash.into());journal.publication_receipt_sha256=Some(receipt_hash);
    durable::json(&super::paths(root,plan.operation_id).1,journal)
}
fn files(root:&Path,plan:&Plan,intent:&Intent,seen:&[StepReceipt],selection:bool)->Result<()> {
    let config:Config=serde_json::from_str(&plan.source_profile)?;
    ensure!(crate::controlled_startup::trusted_file(&plan.source_path,256<<10)?==plan.source_profile.as_bytes()
        && fs::symlink_metadata(&plan.source_path)?.mode()&0o077==0,"CONFLICT: original startup grant changed during publication");
    for file in config.profile_files.iter().filter(|file|file.path!=config.jvm_args_path) {
        let identity=fs::symlink_metadata(&file.path)?;
        ensure!(identity.dev()!=plan.source_args_image.device || identity.ino()!=plan.source_args_image.inode,
            "CONFLICT: mutable startup arguments have another pinned path alias");
        ensure!(durable::hash(&crate::controlled_startup::trusted_file(&file.path,256<<20)?)==file.sha256,"CONFLICT: retained startup input changed during publication");
    }
    let pair = if selection && plan.legacy_source.is_some() && plan.owner_marker==Path::new(MARKER)
        && root.parent()==Some(Path::new(LEGACY_STATE_ROOT)) {
        Store::new(Path::new(LEGACY_STATE_ROOT)).read_root_pair()?
    } else {None};
    let network = if let Some(pair)=&pair {
        pair.network.clone().context("CONFLICT: original Root network fence missing")?
    } else {BoundFile::open(&plan.owner_marker,16384)?.marker()?};
    ensure!(network==plan.owner_marker_identity,"CONFLICT: original startup authority changed");
    let arguments=Parent::bound(&intent.steps[0].parent)?;
    if seen.is_empty() {
        ensure!(arguments.read(&intent.arguments_path,ARGS_LIMIT)?.image==plan.source_args_image && !arguments.exists(&intent.backup_path)?,
            "CONFLICT: original arguments or retained destination changed");
    }else{
        ensure!(arguments.read(&intent.backup_path,ARGS_LIMIT)?.image==seen[0].image,"CONFLICT: retained original startup preimage changed");
        if seen.len()==1 {ensure!(!arguments.exists(&intent.arguments_path)?,"CONFLICT: retained argument destination is no longer absent");}
        else {ensure!(arguments.read(&intent.arguments_path,ARGS_LIMIT)?.image==seen[1].image,"CONFLICT: generated startup arguments changed");}
    }
    for (index,fence) in plan.fences.iter().enumerate() {
        if let Some(pair)=pair.as_ref().filter(|_|index==0) {
            let before=fence.before.as_ref().context("CONFLICT: original retained Root firewall fence missing")?;
            let identity=MarkerIdentity{device:before.device,inode:before.inode,sha256:before.sha256.clone()};
            ensure!(pair.firewall.as_ref()==Some(&identity) && seen.get(index+2).is_some_and(|receipt|receipt.image==*before),
                "CONFLICT: original retained Root firewall fence changed");
            continue;
        }
        let step=&intent.steps[index+2];let parent=Parent::bound(&step.parent)?;
        if let Some(receipt)=seen.get(index+2) {
            ensure!(parent.read(&fence.path,16384)?.image==receipt.image,"CONFLICT: published startup fence changed");
        }else if let Some(before)=&fence.before {
            ensure!(parent.read(&fence.path,16384)?.image==*before,"CONFLICT: original retained startup fence changed");
        }else {ensure!(!parent.exists(&fence.path)?,"CONFLICT: startup fence create-only destination changed");}
    }
    let target=Parent::bound(&intent.steps[5].parent)?;
    if let Some(receipt)=seen.get(5) {ensure!(target.read(&intent.profile_path,PLAN_LIMIT)?.image==receipt.image,"CONFLICT: generated ordinary grant changed");}
    else {ensure!(!target.exists(&intent.profile_path)?,"CONFLICT: generated ordinary grant destination exists");}
    Ok(())
}
fn shared(root:&Path,plan:&Plan,intent:&Intent,seen:&[StepReceipt],systemctl:&Path)->Result<()> {
    files(root,plan,intent,seen,false)?;
    let config:Config=serde_json::from_str(&plan.source_profile)?;
    let stopped=crate::system_control::inspect_stopped_unit(systemctl,&config.unit)?;
    ensure!(stopped.unit_file_state==plan.before_unit.unit_file_state
        && plan.stop_policy.as_ref()==Some(&crate::system_control::inspect_stop_policy(systemctl,&config)?),
        "CONFLICT: original stopped startup authority changed");Ok(())
}
/// Current material for read-only runtime consumers. The publication receipt is
/// historical; every physical file/directory binding is checked again. No unit
/// action/readiness is inferred and pending handover grants no write permission.
pub(super) fn selected_raw(root:&Path,plan:&Plan,journal:&Journal)->Result<Vec<u8>> {
    let (intent,hash,steps,receipt)=records(root,plan,journal)?.context("OUTCOME_UNKNOWN: original profile publication missing")?;
    ensure!(steps.len()==6 && receipt.as_ref()==journal.publication_receipt_sha256.as_ref() && receipt.is_some()
        && journal.publication_intent_sha256.as_ref()==Some(&hash),"OUTCOME_UNKNOWN: original profile publication is not fully acknowledged");
    let mut seen=Vec::new();
    for step in &intent.steps {
        let bytes=read(&step_path(root,plan.operation_id,step.index))?;
        ensure!(durable::hash(&bytes)==steps[step.index as usize],"CONFLICT: original profile file receipt changed during read");
        let observed:StepReceipt=serde_json::from_slice(&bytes)?;validate_step(plan,&hash,step,&observed)?;seen.push(observed);
    }
    files(root,plan,&intent,&seen,true)?;
    let parent=Parent::bound(&intent.steps[5].parent)?;let grant=parent.read(&intent.profile_path,PLAN_LIMIT)?;
    ensure!(grant.image==seen[5].image && grant.bytes==plan.generated_profile.as_bytes(),"CONFLICT: selected original profile material changed");Ok(grant.bytes)
}
pub(in crate::nm) enum StepResult {Observed(Value),Dispatch(Box<Command>)}
pub(in crate::nm) struct Command {root:PathBuf,systemctl:PathBuf,plan:Plan,journal:Journal,intent:Intent,intent_hash:String,execution:execution::Execution}
pub(super) fn begin(root:&Path,original:&Requirements,actor:&str,token:&str,systemctl:&Path)->Result<StepResult> {
    let (plan,mut journal)=authorized(root,original,actor,token)?;
    ensure!(plan.schema_version>=4,"UNSUPPORTED: historical startup plan has no reviewed file publication authority");
    if let Some((_,hash,steps,receipt))=records(root,&plan,&journal)? {
        if steps.len()==6 && (journal.publication_receipt_sha256.is_none() || journal.publication_intent_sha256.is_none()) {
            recovery::forward_allowed(root,&plan,&journal)?;
            let execution=execution::Execution::acquire(root,&plan,&journal)?;execution.verify()?;
            settle(root,&plan,&mut journal,&hash,&steps,receipt.as_deref())
                .context("OUTCOME_UNKNOWN: original startup file evidence acknowledgement")?;
            execution.verify()?;
        }
        return Ok(StepResult::Observed(value(root,&plan,&journal,true)?));
    }
    recovery::forward_allowed(root,&plan,&journal)?;
    let execution=execution::Execution::acquire(root,&plan,&journal)?;
    ensure!(records(root,&plan,&journal)?.is_none(),"OUTCOME_UNKNOWN: original publication was admitted concurrently; query it without redispatch");
    let stop_receipt_sha256=stop::acknowledge(root,&plan,&mut journal)?;
    let config:Config=serde_json::from_str(&plan.source_profile)?;
    let steps=definitions(root,&plan,None)?;
    let intent=Intent{schema_version:1,operation_id:plan.operation_id,startup_plan_sha256:journal.plan_sha256.clone(),
        parent_plan_sha256:plan.parent_plan_sha256.clone(),stop_receipt_sha256,arguments_path:config.jvm_args_path.clone(),
        backup_path:backup(&config,plan.operation_id)?,profile_path:profile_path(root,plan.operation_id),steps};
    validate_intent(root,&plan,&journal,&intent)?;shared(root,&plan,&intent,&[],systemctl)?;
    let bytes=serde_json::to_vec(&intent)?;ensure!(bytes.len() as u64<=LIMIT,"RESOURCE_EXHAUSTED: original startup publication intent quota");
    let intent_hash=durable::hash(&bytes);
    execution.verify()?;
    durable::publish_new(&paths(root,plan.operation_id).0,&bytes,FileMetadata::private())
        .context("OUTCOME_UNKNOWN: original startup publication admission")?;
    journal.publication_intent_sha256=Some(intent_hash.clone());
    durable::json(&super::paths(root,plan.operation_id).1,&journal).context("OUTCOME_UNKNOWN: original startup publication pointer")?;
    Ok(StepResult::Dispatch(Box::new(Command{root:root.into(),systemctl:systemctl.into(),plan,journal,intent,intent_hash,execution})))
}
impl Command {
    pub(in crate::nm) fn execute(self)->Result<Value> {
        self.execute_inner().context("OUTCOME_UNKNOWN: original startup file publication requires original receipts;never redispatch")
    }
    fn execute_inner(mut self)->Result<Value> {
        self.execution.verify()?;
        let (plan,current)=load(&self.root,self.plan.operation_id,&self.plan.parent_plan_sha256)?.context("CONFLICT: original startup child disappeared")?;
        let Some((_,hash,steps,receipt))=records(&self.root,&plan,&current)?else{anyhow::bail!("OUTCOME_UNKNOWN: original startup publication intent disappeared")};
        ensure!(hash==self.intent_hash && steps.is_empty() && receipt.is_none() && current.publication_intent_sha256.as_ref()==Some(&hash)
            && current.plan_sha256==self.journal.plan_sha256,"CONFLICT: original publication admission changed");
        let mut seen=Vec::new();let mut hashes=Vec::new();let config:Config=serde_json::from_str(&plan.source_profile)?;
        let marker=serde_json::to_vec(&Marker{schema_version:1,operation_id:plan.operation_id,plan_sha256:plan.parent_plan_sha256.clone()})?;
        for step in &self.intent.steps {
            shared(&self.root,&plan,&self.intent,&seen,&self.systemctl)?;let parent=Parent::bound(&step.parent)?;
            self.execution.verify()?;
            match step.action {
                Action::RetainArguments=>parent.retain(&self.intent.arguments_path,&self.intent.backup_path)?,
                Action::PublishArguments=>{
                    let original=parent.read(&self.intent.backup_path,ARGS_LIMIT)?;
                    ensure!(original.image==seen[0].image,"CONFLICT: original retained argument descriptor changed");
                    let (body,grant,_)=generated_for(&plan,&config,std::str::from_utf8(&original.bytes)?)?;
                    ensure!(durable::hash(body.as_bytes())==step.sha256 && grant==plan.generated_profile,"CONFLICT: regenerated startup target differs from original plan");
                    parent.publish(&step.path,body.as_bytes(),step.metadata,plan.operation_id,step.index)?;
                }
                Action::PublishFence=>parent.publish(&step.path,&marker,step.metadata,plan.operation_id,step.index)?,
                Action::PreserveFence=>{},
                Action::PublishProfile=>parent.publish(&step.path,plan.generated_profile.as_bytes(),step.metadata,plan.operation_id,step.index)?,
            }
            let observed=parent.read(&step.path,PLAN_LIMIT)?;parent.sync(&step.path,&observed)?;
            let receipt=StepReceipt{schema_version:1,operation_id:plan.operation_id,intent_sha256:self.intent_hash.clone(),index:step.index,image:observed.image};
            validate_step(&plan,&self.intent_hash,step,&receipt)?;
            let bytes=serde_json::to_vec(&receipt)?;
            self.execution.verify()?;
            durable::publish_new(&step_path(&self.root,plan.operation_id,step.index),&bytes,FileMetadata::private())?;
            hashes.push(durable::hash(&bytes));seen.push(receipt);
        }
        shared(&self.root,&plan,&self.intent,&seen,&self.systemctl)?;
        self.execution.verify()?;
        settle(&self.root,&plan,&mut self.journal,&self.intent_hash,&hashes,None)?;
        self.execution.verify()?;
        value(&self.root,&plan,&self.journal,true)
    }
}
