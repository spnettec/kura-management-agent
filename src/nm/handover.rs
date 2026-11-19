//! Explicit delegation records. Neither a marker nor a caller-supplied role
//! object grants ownership: the original plan, source checks and receipt bind it.
use super::*;
pub(crate) mod template;
pub(in crate::nm) mod startup;
pub(in crate::nm) mod dual_fence;
mod fence_reader;
mod root_fence;
#[cfg(target_os = "linux")]
pub(crate) mod continuity;
pub(crate) use fence_reader::observe_original as observe_original_root_fence;
#[cfg(target_os = "linux")]
pub(crate) use root_fence::publish as publish_root_fence;
#[cfg(target_os = "linux")]
pub(super) use root_fence::running_program_sha;
pub(in crate::nm) mod native;
mod native_store;
pub(crate) mod initialization;
use crate::durable::{self, FileMetadata};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{fs::{MetadataExt, OpenOptionsExt}, io::{AsRawFd, FromRawFd}, ffi::OsStrExt},
    path::PathBuf,
};

const LIMIT: u64 = 1 << 20;
const MARKER: &str = "/etc/kura/network-owner-agent";
const LEGACY_STATE_ROOT: &str = "/var/lib/kura-management-agent";

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ProfileBinding {
    pub(super) interface: String,
    pub(super) profile_uuid: Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(super) origin_cas:Option<String>,
}
impl ProfileBinding {
    pub(super) fn observe(device:&Device)->Result<Self> {
        Ok(Self{interface:device.interface.clone(),profile_uuid:device.active_profile.as_ref().map(|p|p.uuid.clone()),
            origin_cas:Some(digest(&serde_json::to_value(device)?)?)})
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Baseline {
    pub(super) source_digest: String,
    pub(super) roles: roles::Observation,
    pub(super) profiles: Vec<ProfileBinding>,
    /// Static policy/source observations, never an authorization flag.
    pub(super) firewall_digest: String,
    pub(super) automatic_nat: Value,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(super) firewall_source:Option<roles::FirewallSource>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(super) firewall_fence:Option<dual_fence::Origin>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(super) native_transfer:Option<native::Transfer>,
}

impl Baseline {
    pub(super) fn bind_source(backend:&str,firewall:Option<&roles::FirewallSource>)->Result<String> {
        ensure!(hex(backend,64),"CONFLICT: backend source digest");
        match firewall {
            None=>Ok(backend.into()),
            Some(source)=>digest(&json!({"schemaVersion":1,"backendSourceDigest":backend,"originalFirewallSource":source})),
        }
    }
    pub(super) fn bind_pair_source(backend:&str,firewall:Option<&roles::FirewallSource>,fence:Option<&dual_fence::Origin>)->Result<String> {
        let source=Self::bind_source(backend,firewall)?;
        match fence {
            None=>Ok(source),
            Some(origin)=>{origin.validate()?;ensure!(firewall.is_some(),"CONFLICT: paired fence requires original firewall source");
                digest(&json!({"schemaVersion":2,"domain":"nm.ownership.firewall-fence.v1","sourceDigest":source,"firewallFence":origin}))},
        }
    }
    fn validate(&self) -> Result<()> {
        ensure!(serde_json::to_vec(self)?.len()<=LIMIT as usize-65536,"RESOURCE_EXHAUSTED: complete original ownership source");
        ensure!(hex(&self.source_digest, 64) && hex(&self.firewall_digest, 64),
            "CONFLICT: ownership source digest");
        self.roles.validate()?;
        if let Some(source)=&self.firewall_source {source.require(&self.roles)?;}
        if let Some(native)=&self.native_transfer {
            native.validate()?;
            ensure!(self.firewall_source.is_some() && self.firewall_fence.is_some() && self.profiles.iter().all(|p|p.origin_cas.is_some())
                && self.source_digest==native.source_binding()?,"CONFLICT: complete original native source binding");
        }
          if let Some(origin)=&self.firewall_fence {ensure!(self.firewall_source.is_some(),"CONFLICT: firewall fence without original source");origin.validate()?;}
        ensure!(!self.profiles.is_empty() && self.profiles.len() <= 16,
            "CONFLICT: ownership profile bounds");
        let mut names = std::collections::BTreeSet::new();
        let mut uuids = std::collections::BTreeSet::new();
        for row in &self.profiles {
            ensure!(row.origin_cas.as_ref().is_none_or(|value|hex(value,64)),"CONFLICT: original profile CAS binding");
            ensure!(!row.interface.is_empty() && row.interface.len() <= 15
                && row.interface.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                && names.insert(&row.interface), "CONFLICT: ownership interface binding");
            if let Some(id) = &row.profile_uuid {
                ensure!(uuid::Uuid::parse_str(id).is_ok_and(|u| !u.is_nil() && u.to_string() == *id)
                    && uuids.insert(id), "CONFLICT: ownership profile UUID");
            }
        }
        if !self.automatic_nat.is_null() {
            serde_json::from_value::<nat::NatSet>(self.automatic_nat.clone())?.pairs()?;
        }
        Ok(())
    }
    pub(super) fn validate_current(&self, allowed: &[String], devices: &[Device]) -> Result<()> {
        self.validate()?;
        let expected: std::collections::BTreeMap<_,_> = self.profiles.iter()
            .map(|row| (row.interface.as_str(), row.profile_uuid.as_deref())).collect();
        let names: std::collections::BTreeSet<_> = allowed.iter().map(String::as_str).collect();
        ensure!(names.len() == allowed.len() && names == expected.keys().copied().collect()
            && devices.len() == expected.len(), "FORBIDDEN: delegated interface scope changed");
        let mut seen = std::collections::BTreeSet::new();
        for device in devices {
            ensure!(device.managed && seen.insert(device.interface.as_str())
                && expected.get(device.interface.as_str()) == Some(&device.active_profile.as_ref().map(|p|p.uuid.as_str())),
                "CONFLICT: delegated active profile binding changed");
        }
        Ok(())
    }
    pub(super) fn validate_origin_current(&self,allowed:&[String],devices:&[Device])->Result<()> {
        self.validate_current(allowed,devices)?;
        let expected=self.roles.roles.adopted_nat(devices)?;
        let actual:Option<nat::NatSet>=serde_json::from_value(self.automatic_nat.clone())?;
        ensure!(coordinator::settlement::nat_equal(expected.as_ref(),actual.as_ref()),
            "CONFLICT: original automatic NAT differs from the complete adopted CM role policy");
        for device in devices {
            let original=self.profiles.iter().find(|row|row.interface==device.interface).context("CONFLICT: original device scope")?;
            ensure!(original.origin_cas.as_ref()==ProfileBinding::observe(device)?.origin_cas.as_ref(),
                "CONFLICT: original backend profile CAS or device identity changed");
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Binding {
    operation_id: uuid::Uuid,
    plan_sha256: String,
    lease_sha256: String,
}
impl Binding {
    pub(in crate::nm) fn operation(&self)->uuid::Uuid {self.operation_id}
    pub(in crate::nm) fn plan_hash(&self)->&str {&self.plan_sha256}
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(!self.operation_id.is_nil() && hex(&self.plan_sha256,64) && hex(&self.lease_sha256,64),
            "CONFLICT: invalid delegation binding");Ok(())
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Active { pub(super) binding: Binding, pub(super) baseline: Baseline }

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum State { Prepared, FenceIntent, Fenced, LeaseIntent, Committed, Cancelled }
#[derive(Clone,PartialEq,Eq)]
pub(super) struct Requirements {
    operation:uuid::Uuid,plan:String,template:String,state:State,marker:MarkerIdentity,
    pub(super) baseline:Baseline,
}
/// A verified material overlay for the same administrator-owned ordinary grant.
/// This carries no independent operation/delegation/write authority.
#[derive(Clone)]
pub(crate) struct OrdinarySelection {
    pub(crate) raw:Vec<u8>,pub(crate) unit:String,pub(crate) arguments_path:PathBuf,
    source_arguments_sha256:String,selected_arguments_sha256:String,
}
impl OrdinarySelection {
    pub(crate) fn pinned_hash(&self,path:&Path,original:&str)->Result<String> {
        if path!=self.arguments_path{return Ok(original.into());}
        ensure!(original==self.source_arguments_sha256 || original==self.selected_arguments_sha256,
            "CONFLICT: system grant does not pin either original authorized argument generation");
        Ok(self.selected_arguments_sha256.clone())
    }
}
impl Requirements {
    pub(super) fn verify(&self,owner:&roles::Owner)->Result<()> {
        owner.require_original(self.operation,&self.plan,&self.template,&self.baseline.roles.roles)
    }
    pub(super) fn recovering(&self)->bool {self.state==State::LeaseIntent}
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Plan {
    schema_version: u8,
    operation_id: uuid::Uuid,
    actor: String,
    token_sha256: String,
    baseline: Baseline,
    #[serde(default, skip_serializing_if="Option::is_none")]
    template: Option<template::Binding>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Journal {
    schema_version: u8,
    operation_id: uuid::Uuid,
    plan_sha256: String,
    token: String,
    state: State,
    receipt_sha256: Option<String>,
    marker: Option<MarkerIdentity>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    firewall_marker:Option<MarkerIdentity>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    native:Option<native_store::Step>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    initialization:Option<initialization::Step>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MarkerIdentity { device: u64, inode: u64, sha256: String }
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Marker {
    schema_version: u8,
    operation_id: uuid::Uuid,
    plan_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Lease {
    schema_version: u8,
    operation_id: uuid::Uuid,
    plan_sha256: String,
    baseline: Baseline,
    marker: MarkerIdentity,
    #[serde(default,skip_serializing_if="Option::is_none")]
    firewall_marker:Option<MarkerIdentity>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    owner_proof:Option<roles::Owner>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    startup_receipt_sha256:Option<String>,
}
impl Lease {
    fn version(&self)->u8 {if self.baseline.native_transfer.is_some(){5}else if self.firewall_marker.is_some(){4}else if self.startup_receipt_sha256.is_some(){3}else if self.owner_proof.is_some(){2}else{1}}
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Receipt {
    schema_version: u8,
    operation_id: uuid::Uuid,
    plan_sha256: String,
    state: State,
    lease_sha256: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Pointer {
    schema_version: u8,
    operation_id: uuid::Uuid,
    lease_sha256: String,
    receipt_sha256: String,
}

fn hex(value: &str, size: usize) -> bool {
    value.len() == size && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn private_directory(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) => {
            ensure!(m.is_dir() && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o777 == 0o700, "FORBIDDEN: unsafe ownership evidence directory");
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn read(path: &Path) -> Result<Vec<u8>> {
    ensure!(private_directory(path.parent().context("ownership parent")?)?,
        "CONFLICT: ownership evidence parent missing");
    Ok(BoundFile::open(path, LIMIT)?.bytes)
}

/// Read and fsync the same no-follow descriptor. Reopening the pathname after
/// checking bytes could sync a replacement, including a link to another file.
struct BoundFile { path: PathBuf, directory: File, file: File, bytes: Vec<u8>, observed: fs::Metadata }
impl BoundFile {
    fn open(path: &Path, limit: u64) -> Result<Self> {
        let directory = OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path.parent().context("ownership parent")?)?;
        let name = std::ffi::CString::new(path.file_name().context("ownership filename")?.as_bytes())?;
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        ensure!(fd >= 0, "CONFLICT: ownership evidence could not be opened safely");
        let mut file = unsafe { File::from_raw_fd(fd) };
        let before = file.metadata()?;
        ensure!(before.is_file() && before.nlink() == 1 && before.len() <= limit
            && FileMetadata::from_fs(&before) == FileMetadata::private(),
            "FORBIDDEN: unsafe ownership evidence file");
        let mut bytes = Vec::new();
        (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        ensure!(bytes.len() as u64 == before.len() && bytes.len() as u64 <= limit
            && before.len() == after.len() && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(), "CONFLICT: ownership evidence changed during read");
        let result = Self { path: path.into(), directory, file, bytes, observed: after };
        result.verify_binding()?;
        Ok(result)
    }
    fn verify_binding(&self) -> Result<()> {
        let parent = fs::symlink_metadata(self.path.parent().context("ownership parent")?)?;
        let directory = self.directory.metadata()?;
        let path = fs::symlink_metadata(&self.path)?;
        let file = self.file.metadata()?;
        ensure!(parent.is_dir() && parent.dev() == directory.dev() && parent.ino() == directory.ino()
            && parent.uid() == unsafe { libc::geteuid() } && parent.mode() & 0o022 == 0
            && path.is_file() && path.dev() == file.dev() && path.ino() == file.ino()
            && path.nlink() == 1 && FileMetadata::from_fs(&path) == FileMetadata::private()
            && file.nlink() == 1 && file.len() == self.observed.len()
            && file.ctime() == self.observed.ctime() && file.ctime_nsec() == self.observed.ctime_nsec(),
            "CONFLICT: ownership evidence path was replaced");
        Ok(())
    }
    fn marker(&self) -> Result<MarkerIdentity> {
        self.verify_binding()?;
        let info = self.file.metadata()?;
        Ok(MarkerIdentity { device: info.dev(), inode: info.ino(), sha256: durable::hash(&self.bytes) })
    }
    fn sync_exact(&self) -> Result<()> {
        self.verify_binding()?;
        self.file.sync_all()?;
        self.directory.sync_all()?;
        self.verify_binding()
    }
}

pub(super) struct Store { root: PathBuf, marker: PathBuf }
impl Store {
    pub(super) fn new(root: &Path) -> Self {
        Self { root: root.join("nm-ownership"), marker: MARKER.into() }
    }
    #[cfg(test)]
    pub(super) fn relocated(root: &Path, marker: PathBuf) -> Self {
        Self { root: root.join("nm-ownership"), marker }
    }
    fn journal_path(&self) -> PathBuf { self.root.join("transaction.json") }
    fn artifact(&self, id: uuid::Uuid, suffix: &str) -> PathBuf {
        self.root.join(format!("{id}.{suffix}.json"))
    }
    fn load(&self) -> Result<Option<(Journal, Plan)>> {
        if !private_directory(&self.root)? { return Ok(None); }
        let bytes = match fs::symlink_metadata(self.journal_path()) {
            Ok(_) => read(&self.journal_path())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ensure!(fs::read_dir(&self.root)?.next().is_none(),
                    "CONFLICT: orphan ownership evidence; preserve state");
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };
        let journal: Journal = serde_json::from_slice(&bytes)?;
        ensure!(journal.schema_version == 1 && !journal.operation_id.is_nil()
            && hex(&journal.plan_sha256, 64) && hex(&journal.token, 32),
            "CONFLICT: ownership journal identity");
        let bytes = read(&self.artifact(journal.operation_id, "intent"))?;
        ensure!(durable::hash(&bytes) == journal.plan_sha256,
            "CONFLICT: original ownership intent changed");
        let plan: Plan = serde_json::from_slice(&bytes)?;
          ensure!(plan.schema_version == (if plan.template.is_some() {if plan.baseline.native_transfer.is_some(){5}else if plan.baseline.firewall_fence.is_some(){4}else if plan.baseline.firewall_source.is_some(){3}else{2}} else {1})
              && (plan.baseline.firewall_fence.is_none() || plan.template.is_some())
            && plan.operation_id == journal.operation_id
            && !plan.actor.is_empty() && plan.actor.len() <= 256
            && plan.actor.bytes().all(|b| b.is_ascii_graphic())
            && plan.token_sha256 == durable::hash(journal.token.as_bytes()),
            "CONFLICT: original ownership plan binding");
        plan.baseline.validate()?;
          self.validate_native_journal(&journal,&plan)?;
            self.validate_initialization_journal(&journal,&plan)?;
        if let Some(binding)=&plan.template {
            template::Transfer::new(self.root.parent().context("ownership state root")?).validate_binding(binding)?;
        }
        if matches!(journal.state, State::Prepared | State::FenceIntent | State::Cancelled) {
              ensure!(journal.marker.is_none() && journal.firewall_marker.is_none(), "CONFLICT: unexpected ownership marker identity");
        } else {
            let (network, firewall) = self.check_marker_pair(&journal, &plan)?;
            ensure!(journal.marker.as_ref() == Some(&network),
                "CONFLICT: original ownership marker identity changed");
            ensure!(journal.firewall_marker == firewall, "CONFLICT: original firewall fence identity changed");
        }
        if !matches!(journal.state, State::Committed | State::Cancelled) {
            ensure!(journal.receipt_sha256.is_none(),
                "CONFLICT: nonterminal ownership receipt contradiction");
        } else {
            let receipt = self.receipt(&journal)?;
            ensure!(receipt.state == journal.state, "CONFLICT: ownership terminal state");
            if journal.state == State::Committed { self.lease(&journal, &plan, &receipt)?; }
            else { ensure!(receipt.lease_sha256.is_none(), "CONFLICT: cancelled ownership lease"); }
        }
        Ok(Some((journal, plan)))
    }
    fn receipt(&self, journal: &Journal) -> Result<Receipt> {
        let bytes = read(&self.artifact(journal.operation_id, "receipt"))?;
        ensure!(journal.receipt_sha256.as_deref() == Some(durable::hash(&bytes).as_str()),
            "CONFLICT: ownership receipt changed");
        let receipt: Receipt = serde_json::from_slice(&bytes)?;
        ensure!(receipt.schema_version == 1 && receipt.operation_id == journal.operation_id
            && receipt.plan_sha256 == journal.plan_sha256,
            "CONFLICT: ownership receipt binding");
        Ok(receipt)
    }
    fn marker_bytes(journal: &Journal) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&Marker { schema_version: 1, operation_id: journal.operation_id,
            plan_sha256: journal.plan_sha256.clone() })?)
    }
    fn require_fence_destination(&self) -> Result<()> {
        // Both barriers share this parent. Detect a known inability to publish
        // before recording an issued fence or writing the first barrier.
        let directory = OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.marker.parent().context("marker parent")?)
            .context("FORBIDDEN: cannot open the installed fence directory")?;
        let parent = directory.metadata()?;
        ensure!(parent.is_dir() && parent.uid() == unsafe { libc::geteuid() }
            && parent.mode() & 0o022 == 0, "FORBIDDEN: marker parent must be installed safely");
        ensure!(!fence_reader::readonly_filesystem(&directory)?,
            "UNSUPPORTED: installed fence directory requires a paired Root publisher");
        ensure!(fs::symlink_metadata(&self.marker).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "CONFLICT: existing network owner marker needs explicit reconciliation");
        Ok(())
    }
    fn check_marker(&self, journal: &Journal) -> Result<MarkerIdentity> {
        if let Some(pair) = self.read_root_pair()? {
            return Self::checked_network_identity(journal, pair.network);
        }
        // The fixed system parent may be traversable by Kura; it is not a private
        // journal directory and must never be chmod'ed to 0700 by this code.
        let parent = fs::symlink_metadata(self.marker.parent().context("marker parent")?)?;
        ensure!(parent.is_dir() && parent.uid() == unsafe { libc::geteuid() }
            && parent.mode() & 0o022 == 0, "FORBIDDEN: unsafe network owner marker parent");
        let file = BoundFile::open(&self.marker, 16384)?;
        ensure!(file.bytes == Self::marker_bytes(journal)?,
            "CONFLICT: network owner marker is not this original operation");
        file.marker()
    }
    fn checked_network_identity(journal: &Journal, observed: Option<MarkerIdentity>) -> Result<MarkerIdentity> {
        let identity = observed.context("CONFLICT: original network fence is absent")?;
        ensure!(identity.sha256 == durable::hash(&Self::marker_bytes(journal)?),
            "CONFLICT: network owner marker is not this original operation");
        Ok(identity)
    }
    fn check_marker_pair(&self, journal: &Journal, plan: &Plan) -> Result<(MarkerIdentity, Option<MarkerIdentity>)> {
        if let Some(pair) = self.read_root_pair()? {
            return Ok((Self::checked_network_identity(journal, pair.network)?,
                Self::checked_firewall_identity(journal, plan, pair.firewall)?));
        }
        Ok((self.check_marker(journal)?, self.check_firewall_marker(journal, plan)?))
    }
    fn lease(&self, journal: &Journal, plan: &Plan, receipt: &Receipt) -> Result<Lease> {
        ensure!(receipt.state == State::Committed, "CONFLICT: ownership not committed");
        let bytes = read(&self.artifact(journal.operation_id, "lease"))?;
        let lease_sha256 = durable::hash(&bytes);
        ensure!(receipt.lease_sha256.as_deref() == Some(lease_sha256.as_str()),
            "CONFLICT: ownership lease changed");
        let lease: Lease = serde_json::from_slice(&bytes)?;
        ensure!(lease.schema_version == lease.version() && lease.operation_id == journal.operation_id
            && lease.plan_sha256 == journal.plan_sha256 && lease.baseline == plan.baseline
            && Some(&lease.marker) == journal.marker.as_ref()
            && lease.marker == self.check_marker(journal)?,
            "CONFLICT: ownership lease source or marker binding");
        self.validate_lease_owner(&lease,journal,plan)?;
        let pointer: Pointer = serde_json::from_slice(&read(&self.root.join("confirmed.json"))?)?;
        ensure!(pointer.schema_version == 1 && pointer.operation_id == journal.operation_id
            && pointer.lease_sha256 == lease_sha256
            && Some(&pointer.receipt_sha256) == journal.receipt_sha256.as_ref(),
            "CONFLICT: ownership confirmed pointer binding");
        Ok(lease)
    }
    fn validate_lease_owner(&self,lease:&Lease,journal:&Journal,plan:&Plan)->Result<()> {
        self.require_lease_pair(lease,journal,plan)?;
        if let Some(template)=&plan.template {
            lease.owner_proof.as_ref().context("CONFLICT: actual Core owner proof missing")?
                .require_original(journal.operation_id,&journal.plan_sha256,template.template_hash(),&plan.baseline.roles.roles)?;
        } else {ensure!(lease.owner_proof.is_none() && lease.startup_receipt_sha256.is_none(),"CONFLICT: unexpected legacy owner proof");}
        if let Some(hash)=&lease.startup_receipt_sha256 {
            ensure!(hex(hash,64) && lease.owner_proof.is_some(),"CONFLICT: original startup lease proof shape");
            startup::require_lease(&self.root,journal.operation_id,&journal.plan_sha256,
                plan.template.as_ref().context("CONFLICT: startup lease template missing")?.template_hash(),&plan.baseline.roles.roles,hash)?;
        }Ok(())
    }
    pub(super) fn requirements(&self,id:uuid::Uuid,token:&str,actor:&str)->Result<Requirements> {
        let (j,p)=self.load()?.context("CONFLICT: original ownership plan missing")?;Self::authorize(&j,token,&p,actor)?;
        ensure!(j.operation_id==id && matches!(j.state,State::Fenced|State::LeaseIntent),"OUTCOME_UNKNOWN: query original ownership phase");
        self.require_native_ready(&j,&p)?;
        self.require_initialization_ready(&j,&p)?;
        Ok(Requirements{operation:id,plan:j.plan_sha256.clone(),template:p.template.as_ref().context("UNSUPPORTED: original template required")?.template_hash().into(),
            state:j.state.clone(),marker:self.check_marker(&j)?,baseline:p.baseline})
    }
    pub(super) fn startup_prepare(&self,id:uuid::Uuid,token:&str,actor:&str,profile:&Path,systemctl:&Path)->Result<Value> {
        let requirements=self.requirements(id,token,actor)?;
        ensure!(!requirements.recovering(),"OUTCOME_UNKNOWN: original activation already issued");
        startup::prepare(&self.root,&self.marker,&requirements,actor,profile,systemctl)
    }
    pub(super) fn startup_association_begin(&self,id:uuid::Uuid,token:&str,actor:&str,child_token:&str,systemctl:&Path)->Result<startup::AssociationStep> {
        let expected=self.requirements(id,token,actor)?;ensure!(!expected.recovering(),"OUTCOME_UNKNOWN: original activation already issued");
        startup::association_begin(&self.root,&expected,actor,child_token,systemctl)
    }
    pub(super) fn startup_association_finish(&self,expected:&Requirements,actor:&str,child_token:&str,
        challenge:&startup::AssociationChallenge,witness:(roles::StartupAssociation,roles::Observation),systemctl:&Path)->Result<Value> {
        startup::association_finish(&self.root,expected,actor,child_token,challenge,witness,systemctl)
    }
    pub(super) fn startup_stop_begin(&self,id:uuid::Uuid,token:&str,actor:&str,child_token:&str,systemctl:&Path)->Result<startup::AssociationStep> {
        let expected=self.requirements(id,token,actor)?;ensure!(!expected.recovering(),"OUTCOME_UNKNOWN: original activation already issued");
        startup::stop_begin(&self.root,&expected,actor,child_token,systemctl)
    }
    pub(super) fn startup_stop_arm(&self,expected:&Requirements,actor:&str,child_token:&str,
        witness:(roles::StartupAssociation,roles::Observation),systemctl:&Path,deadline:std::time::Instant)->Result<startup::StopCommand> {
        startup::stop_arm(&self.root,expected,actor,child_token,witness,systemctl,deadline)
    }
    pub(super) fn startup_publication_begin(&self,id:uuid::Uuid,token:&str,actor:&str,child_token:&str,systemctl:&Path)->Result<startup::PublicationStep> {
        let expected=self.requirements(id,token,actor)?;ensure!(!expected.recovering(),"OUTCOME_UNKNOWN: original activation already issued");
        startup::publication_begin(&self.root,&expected,actor,child_token,systemctl)
    }
    pub(super) fn startup_start_begin(&self,id:uuid::Uuid,token:&str,actor:&str,child_token:&str,systemctl:&Path)->Result<startup::StartStep> {
        let expected=self.requirements(id,token,actor)?;ensure!(!expected.recovering(),"OUTCOME_UNKNOWN: original activation already issued");
        startup::start_begin(&self.root,&expected,actor,child_token,systemctl)
    }
    pub(super) fn startup_completion_begin(&self,id:uuid::Uuid,token:&str,actor:&str,child_token:&str,systemctl:&Path)->Result<startup::CompletionStep> {
        let expected=self.requirements(id,token,actor)?;ensure!(!expected.recovering(),"OUTCOME_UNKNOWN: original activation already issued");
        startup::completion_begin(&self.root,&expected,actor,child_token,systemctl)
    }
    pub(super) fn startup_recovery_prepare(&self,id:uuid::Uuid,token:&str,actor:&str,child_token:&str,recovery_id:uuid::Uuid,systemctl:&Path)->Result<Value> {
        let expected=self.requirements(id,token,actor)?;
        startup::recovery_prepare(&self.root,&expected,actor,child_token,recovery_id,systemctl)
    }
    pub(super) fn startup_recovery_original(&self,id:uuid::Uuid,token:&str,actor:&str,child_token:&str,recovery_id:uuid::Uuid)->Result<Value> {
        let expected=self.requirements(id,token,actor)?;
        startup::recovery_original(&self.root,&expected,actor,child_token,recovery_id)
    }
    pub(super) fn startup_recovery_cancel(&self,id:uuid::Uuid,token:&str,actor:&str,child_token:&str,approval:&startup::RecoveryApproval)->Result<Value> {
        let expected=self.requirements(id,token,actor)?;
        startup::recovery_cancel(&self.root,&expected,actor,child_token,approval)
    }
    pub(super) fn startup_recovery_begin(&self,id:uuid::Uuid,token:&str,actor:&str,child_token:&str,approval:&startup::RecoveryApproval,systemctl:&Path)->Result<startup::RecoveryStep> {
        let expected=self.requirements(id,token,actor)?;
        startup::recovery_begin(&self.root,&expected,actor,child_token,approval,systemctl)
    }
    pub(super) fn startup_completion_finish(&self,expected:&Requirements,actor:&str,child_token:&str,challenge:&startup::CompletionChallenge,witness:startup::CompletionWitness,systemctl:&Path)->Result<Value> {
        startup::completion_finish(&self.root,expected,actor,child_token,challenge,witness,systemctl)
    }
    pub(super) fn startup_activation_challenge(&self,expected:&Requirements,systemctl:&Path)->Result<startup::CompletionChallenge> {
        startup::activation_challenge(&self.root,expected,systemctl)
    }
    pub(super) fn startup_activation_finish(&self,expected:&Requirements,challenge:&startup::CompletionChallenge,witness:&startup::CompletionWitness,systemctl:&Path)->Result<String> {
        startup::activation_finish(&self.root,expected,challenge,witness,systemctl)
    }
    pub(super) fn recovery_requires_startup(&self,expected:&Requirements)->Result<bool> {
        ensure!(expected.recovering(),"CONFLICT: original lease intent required");
        // Existing recovery owns lease/version/receipt classification, including
        // missing leases remaining UNKNOWN. A schema3 lease still validates its
        // bound terminal child there even when the whole child disappeared.
        Ok(startup::original(&self.root,expected.operation,&expected.plan,None)?.is_some())
    }
    fn authorize(journal: &Journal, token: &str, plan: &Plan, actor: &str) -> Result<()> {
        ensure!(hex(token, 32) && token == journal.token && actor == plan.actor,
            "FORBIDDEN: original ownership actor and token required");
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn plan(&self, operation_id: uuid::Uuid, actor: String, baseline: Baseline) -> Result<Value> {
        self.plan_inner(operation_id,actor,baseline,None)
    }
    pub(super) fn plan_with_template(&self,operation_id:uuid::Uuid,actor:String,baseline:Baseline,binding:template::Binding)->Result<Value> {
        ensure!(baseline.firewall_source.is_some(),"UNSUPPORTED: complete original firewall source required for a new plan");
          ensure!(baseline.firewall_fence.is_some(),"UNSUPPORTED: paired firewall fence source required for a new plan");
        ensure!(baseline.profiles.iter().all(|p|p.origin_cas.is_some()),"UNSUPPORTED: original profile CAS observation required");
        let (original,source)=template::Transfer::new(self.root.parent().context("ownership state root")?).ready(operation_id,&actor)?;
        ensure!(original==binding && source==baseline,"CONFLICT: complete template source differs from ownership plan");
        self.plan_inner(operation_id,actor,baseline,Some(binding))
    }
    pub(super) fn ensure_unmanaged(&self)->Result<()> {
        ensure!(self.load()?.is_none(),"OUTCOME_UNKNOWN: query original ownership operation");
        ensure!(self.network_marker_absent()?,
            "CONFLICT: existing network owner marker needs explicit reconciliation");Ok(())
    }
    fn plan_inner(&self, operation_id: uuid::Uuid, actor: String, baseline: Baseline,template:Option<template::Binding>) -> Result<Value> {
        ensure!(!operation_id.is_nil() && !actor.is_empty() && actor.len() <= 256
            && actor.bytes().all(|b| b.is_ascii_graphic()), "INVALID_ARGUMENT: ownership plan identity");
        baseline.validate()?;
        ensure!(baseline.native_transfer.as_ref().is_none_or(|v|v.operation_id==operation_id),"CONFLICT: original native operation differs");
          ensure!(baseline.firewall_fence.is_none() || template.is_some(),"CONFLICT: paired fence requires original template binding");
        self.ensure_unmanaged()?;
        durable::directory(&self.root)?;
        let token = uuid::Uuid::new_v4().simple().to_string();
          let plan = Plan { schema_version: if template.is_some() {if baseline.native_transfer.is_some(){5}else if baseline.firewall_fence.is_some(){4}else if baseline.firewall_source.is_some(){3}else{2}} else {1}, operation_id, actor,
            token_sha256: durable::hash(token.as_bytes()), baseline, template };
          self.require_original_firewall_fence(&plan)?;
        let bytes = serde_json::to_vec(&plan)?;
        ensure!(bytes.len()<=LIMIT as usize,"RESOURCE_EXHAUSTED: original ownership plan");
        durable::publish_new(&self.artifact(operation_id, "intent"), &bytes, FileMetadata::private())?;
        let journal = Journal { schema_version: 1, operation_id, plan_sha256: durable::hash(&bytes),
                token: token.clone(), state: State::Prepared, receipt_sha256: None, marker: None,firewall_marker:None,native:None,initialization:None };
        durable::publish_new(&self.journal_path(), &serde_json::to_vec(&journal)?, FileMetadata::private())?;
        Ok(json!({"operationId":operation_id,"state":"PREPARED","confirmationToken":token,
            "sourceDigest":plan.baseline.source_digest,"rolesRevision":plan.baseline.roles.roles.revision}))
    }
    /// Marker dispatch is once-only. Later queries never publish it again.
    pub(super) fn fence(&self, token: &str, actor: &str,
        reobserve: impl FnOnce() -> Result<Baseline>) -> Result<Value> {
        let (mut journal, plan) = self.load()?.context("CONFLICT: ownership plan missing")?;
        Self::authorize(&journal, token, &plan, actor)?;
        ensure!(journal.state == State::Prepared, "OUTCOME_UNKNOWN: query original ownership fence");
        ensure!(plan.baseline.firewall_source.is_none() || plan.baseline.firewall_fence.is_some(),
            "UNSUPPORTED: historical single-fence plan;query or safely cancel its original preparation");
        self.require_no_root_fence_arm(journal.operation_id)?;
        ensure!(reobserve()? == plan.baseline, "CONFLICT: ownership source changed before fence");
        self.require_original_firewall_fence(&plan)?;
        self.require_fence_destination()?;
        journal.state = State::FenceIntent;
        durable::json(&self.journal_path(), &journal)?;
        self.publish_fence_pair(journal, &plan)
    }
    fn publish_fence_pair(&self, mut journal: Journal, plan: &Plan) -> Result<Value> {
        self.publish_firewall_fence(&journal, plan)
            .context("OUTCOME_UNKNOWN: original paired fence was already issued")?;
        self.require_fence_destination()
            .context("OUTCOME_UNKNOWN: original paired fence was already issued")?;
        durable::publish_new(&self.marker, &Self::marker_bytes(&journal)?, FileMetadata::private())
            .map_err(|_| anyhow::anyhow!("OUTCOME_UNKNOWN: original owner fence publication unconfirmed"))?;
        journal.marker = Some(self.check_marker(&journal)?);
        journal.firewall_marker = self.check_firewall_marker(&journal, plan)?;
        journal.state = State::Fenced;
        durable::json(&self.journal_path(), &journal)?;
        Ok(json!({"operationId":journal.operation_id,"state":"FENCED"}))
    }
    /// The trusted coordinator callback must verify the actual drained writer,
    /// unchanged backend scope and confirmed-only Core mirror readiness. It is
    /// not deserialized from an operator-supplied readiness Boolean.
    #[cfg(test)]
    pub(super) fn activate(&self, token: &str, actor: &str,
        verify_owner: impl FnOnce(&Baseline) -> Result<()>) -> Result<Value> {
        self.activate_inner(token,actor,None,None,verify_owner)
    }
    pub(super) fn activate_proven(&self,token:&str,actor:&str,owner:roles::Owner,startup_receipt:String,verify_backend:impl FnOnce(&Baseline)->Result<()>)->Result<Value> {
        owner.require_complete()?;
        let (j,p)=self.load()?.context("CONFLICT: original ownership plan missing")?;Self::authorize(&j,token,&p,actor)?;
        ensure!(p.baseline.firewall_source.is_some(),"UNSUPPORTED: original stored firewall source required for new activation");
        startup::require_lease(&self.root,j.operation_id,&j.plan_sha256,
            p.template.as_ref().context("FORBIDDEN: original startup template required")?.template_hash(),&p.baseline.roles.roles,&startup_receipt)?;
        self.activate_inner(token,actor,Some(owner),Some(startup_receipt),verify_backend)
    }
    /// Historical schema2 fixtures retain query/recovery coverage. This is not
    /// compiled into production and cannot admit a new runtime activation.
    #[cfg(test)]
    pub(super) fn seed_legacy_owner_fixture(&self,token:&str,actor:&str,owner:roles::Owner,verify:impl FnOnce(&Baseline)->Result<()>)->Result<Value> {
        self.activate_inner(token,actor,Some(owner),None,verify)
    }
    fn activate_inner(&self,token:&str,actor:&str,owner:Option<roles::Owner>,startup_receipt:Option<String>,verify_owner:impl FnOnce(&Baseline)->Result<()>)->Result<Value> {
        let (mut journal, plan) = self.load()?.context("CONFLICT: ownership plan missing")?;
        Self::authorize(&journal, token, &plan, actor)?;
        ensure!(journal.state == State::Fenced, "OUTCOME_UNKNOWN: query original ownership activation");
        self.require_native_ready(&journal,&plan)?;
        let marker = self.check_marker(&journal)?;
        verify_owner(&plan.baseline)?;
        ensure!(marker == self.check_marker(&journal)?, "CONFLICT: original marker changed during activation proof");
          self.require_pair_identity(&journal,&plan)?;
          let lease = Lease { schema_version: if plan.baseline.native_transfer.is_some(){5}else if journal.firewall_marker.is_some(){4}else if startup_receipt.is_some(){3}else if owner.is_some() {2} else {1}, operation_id: journal.operation_id,
              plan_sha256: journal.plan_sha256.clone(), baseline: plan.baseline.clone(), marker,firewall_marker:journal.firewall_marker.clone(),owner_proof:owner,startup_receipt_sha256:startup_receipt };
        self.validate_lease_owner(&lease,&journal,&plan)?;
        journal.state = State::LeaseIntent;
        durable::json(&self.journal_path(), &journal)?;
        let bytes = serde_json::to_vec(&lease)?;
        durable::publish_new(&self.artifact(journal.operation_id, "lease"), &bytes, FileMetadata::private())?;
        let receipt = Receipt { schema_version: 1, operation_id: journal.operation_id,
            plan_sha256: journal.plan_sha256.clone(), state: State::Committed,
            lease_sha256: Some(durable::hash(&bytes)) };
        let receipt_bytes = serde_json::to_vec(&receipt)?;
        durable::publish_new(&self.artifact(journal.operation_id, "receipt"), &receipt_bytes, FileMetadata::private())?;
        let receipt_sha256 = durable::hash(&receipt_bytes);
        durable::publish_new(&self.root.join("confirmed.json"), &serde_json::to_vec(&Pointer { schema_version: 1,
            operation_id: journal.operation_id, lease_sha256: receipt.lease_sha256.unwrap(),
            receipt_sha256: receipt_sha256.clone() })?, FileMetadata::private())?;
        journal.state = State::Committed;
        journal.receipt_sha256 = Some(receipt_sha256);
        durable::json(&self.journal_path(), &journal)?;
        Ok(json!({"operationId":journal.operation_id,"state":"COMMITTED"}))
    }
    pub(super) fn active(&self) -> Result<Option<Active>> {
        let Some((journal, plan)) = self.load()? else { return Ok(None); };
        if journal.state != State::Committed { return Ok(None); }
        let receipt = self.receipt(&journal)?;
        let lease = self.lease(&journal, &plan, &receipt)?;
        Ok(Some(Active { binding: Binding { operation_id: journal.operation_id,
            plan_sha256: journal.plan_sha256, lease_sha256: receipt.lease_sha256.context("ownership lease hash")? },
            baseline: lease.baseline }))
    }
    /// The immutable original owner is a comparison anchor. A new operation
    /// still needs a fresh registered Core cohort and live backend observation.
    pub(super) fn active_owner(&self)->Result<Option<(Active,roles::Owner)>> {
        let Some((journal,plan))=self.load()? else{return Ok(None);};
        if journal.state!=State::Committed {return Ok(None);}
        let receipt=self.receipt(&journal)?;let lease=self.lease(&journal,&plan,&receipt)?;
        let owner=lease.owner_proof.context("UNSUPPORTED: complete original Core owner lease required")?;
        owner.require_complete()?;
        Ok(Some((Active{binding:Binding{operation_id:journal.operation_id,plan_sha256:journal.plan_sha256,
            lease_sha256:receipt.lease_sha256.context("CONFLICT: original owner lease hash")?},baseline:lease.baseline},owner)))
    }
    /// Resample the original startup's actual selected files, stop policy and
    /// live unit. This neither creates a lease nor rewrites a historical receipt.
    fn committed_runtime_requirements(&self)->Result<Requirements> {
        let (journal,plan)=self.load()?.context("FORBIDDEN: original committed owner required")?;
        ensure!(journal.state==State::Committed,"FORBIDDEN: ordinary runtime requires committed ownership");
        let receipt=self.receipt(&journal)?;let lease=self.lease(&journal,&plan,&receipt)?;
        lease.owner_proof.as_ref().context("UNSUPPORTED: actual original Core owner missing")?.require_complete()?;
        ensure!(lease.startup_receipt_sha256.is_some(),"UNSUPPORTED: actual original startup receipt required");
        let template=plan.template.as_ref().context("UNSUPPORTED: actual original template required")?.template_hash().to_string();
        let marker=self.check_marker(&journal)?;
        let expected=Requirements{operation:journal.operation_id,plan:journal.plan_sha256,template,state:State::Committed,
            marker,baseline:plan.baseline};
        Ok(expected)
    }
    pub(super) fn current_runtime_challenge(&self,systemctl:&Path)->Result<(Requirements,startup::CurrentRuntimeChallenge)> {
        let original=self.committed_runtime_requirements()?;
        let challenge=startup::runtime_challenge(&self.root,&original,systemctl)?;
        Ok((original,challenge))
    }
    pub(super) fn current_runtime_is_stopped(&self,systemctl:&Path)->Result<bool> {
        let original=self.committed_runtime_requirements()?;
        startup::runtime_is_stopped(&self.root,&original,systemctl)
    }
    pub(super) fn stopped_runtime_challenge(&self,systemctl:&Path)->Result<(Requirements,startup::StoppedRuntimeChallenge)> {
        let original=self.committed_runtime_requirements()?;
        let challenge=startup::stopped_runtime_challenge(&self.root,&original,systemctl)?;
        Ok((original,challenge))
    }
    pub(super) fn stopped_runtime_finish(&self,expected:&Requirements,challenge:&startup::StoppedRuntimeChallenge,systemctl:&Path)->Result<String> {
        let (original,current)=self.stopped_runtime_challenge(systemctl)?;
        ensure!(&original==expected && &current==challenge,"CONFLICT: original stopped runtime changed during cohort observation");
        startup::stopped_runtime_finish(&self.root,expected,challenge,systemctl)
    }
    pub(super) fn current_runtime_finish(&self,expected:&Requirements,challenge:&startup::CurrentRuntimeChallenge,
        witness:&startup::CompletionWitness,systemctl:&Path)->Result<String> {
        let (current,current_challenge)=self.current_runtime_challenge(systemctl)?;
        ensure!(&current==expected && &current_challenge==challenge,"CONFLICT: original ordinary runtime changed during cohort observation");
        startup::runtime_finish(&self.root,expected,challenge,witness,systemctl)
    }
    pub(super) fn status(&self) -> Result<Value> {
        let Some((journal, plan)) = self.load()? else {
            return Ok(json!({"schemaVersion":1,"state":"UNMANAGED"}));
        };
        let mut status=json!({"schemaVersion":1,"operationId":journal.operation_id,"state":journal.state,
            "sourceDigest":plan.baseline.source_digest,"rolesRevision":plan.baseline.roles.roles.revision});
        if let Some(native)=&journal.native {status["nativeTransfer"]=serde_json::to_value(native)?;}
          if let Some(step)=&journal.initialization {status["initialization"]=step.parameters()?;}
        if let Some(child)=startup::original(&self.root,journal.operation_id,&journal.plan_sha256,None)? {status["startup"]=child;}
        Ok(status)
    }
    pub(super) fn original(&self,id:uuid::Uuid,actor:&str)->Result<Option<Value>> {
        let Some((j,p))=self.load()? else {return Ok(None)};
        ensure!(j.operation_id==id && p.actor==actor,"FORBIDDEN: original ownership actor required");
        let mut status=self.status()?;
        if j.state!=State::Cancelled {status["confirmationToken"]=json!(j.token);}
        if let Some(child)=startup::original(&self.root,j.operation_id,&j.plan_sha256,Some(actor))? {status["startup"]=child;}
        Ok(Some(status))
    }
    fn mirror_source(&self)->Result<(Journal,Plan)> {
        let (j,p)=self.load()?.context("UNSUPPORTED: no delegated NM confirmed mirror")?;
        ensure!(matches!(j.state,State::Fenced|State::LeaseIntent|State::Committed),"CONFLICT: no fenced confirmed NM source");
        let expected=p.template.as_ref().context("UNSUPPORTED: original complete template required")?;
        ensure!(matches!(template::Transfer::new(self.root.parent().context("ownership root")?).admission()?,
            template::Admission::Ready(binding) if &binding==expected),"CONFLICT: original template is not confirmed ready");Ok((j,p))
    }
    pub(in crate::nm) fn mirror(&self,method:&str,value:Value)->Result<Value> {
        let (j,p)=self.mirror_source()?;let binding=p.template.as_ref().context("complete template")?;
        if method=="network.nm.template.confirmed" {
            ensure!(value.is_null() || value==json!({}),"INVALID_ARGUMENT: confirmed mirror fields");
            return Ok(json!({"schemaVersion":1,"pid":roles::PID,"operationId":j.operation_id,"planSha256":j.plan_sha256,
                "templateSha256":binding.template_hash(),"sourceRevision":p.baseline.roles.roles.revision,
                "confirmedRevision":p.baseline.roles.roles.revision,"roles":p.baseline.roles.roles,"chunkCount":binding.chunk_count()}));
        }
        ensure!(method=="network.nm.template.chunk","UNSUPPORTED: confirmed mirror method");
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields,rename_all="camelCase")]
        struct Input {operation_id:String,plan_sha256:String,template_sha256:String,chunk_index:usize}
        let input:Input=serde_json::from_value(value).context("INVALID_ARGUMENT: confirmed chunk fields")?;
        ensure!(template::operation(&input.operation_id)?==j.operation_id && input.plan_sha256==j.plan_sha256
            && input.template_sha256==binding.template_hash(),"CONFLICT: original confirmed chunk binding");
        let chunk=template::Transfer::new(self.root.parent().context("ownership root")?).confirmed_chunk(binding,input.chunk_index)?;
        Ok(json!({"schemaVersion":1,"operationId":j.operation_id,"planSha256":j.plan_sha256,"templateSha256":binding.template_hash(),
            "chunkIndex":input.chunk_index,"chunkCount":binding.chunk_count(),"ciphertextChunk":chunk}))
    }
    pub(super) fn cancel_before_fence(&self,id:uuid::Uuid,actor:&str)->Result<()> {
        ensure!(self.network_marker_absent()?,
            "FORBIDDEN: retirement is required after a fence");
        let Some((mut j,p))=self.load()? else {return Ok(())};
        ensure!(j.operation_id==id && p.actor==actor,"FORBIDDEN: original ownership actor required");
        if j.state==State::Cancelled {return Ok(());}
        ensure!(j.state==State::Prepared,"OUTCOME_UNKNOWN: query the original fence before retirement");
          self.require_original_firewall_fence(&p)?;
        let bytes=serde_json::to_vec(&Receipt{schema_version:1,operation_id:id,plan_sha256:j.plan_sha256.clone(),state:State::Cancelled,lease_sha256:None})?;
        durable::publish_new(&self.artifact(id,"receipt"),&bytes,FileMetadata::private())?;
        j.state=State::Cancelled;j.receipt_sha256=Some(durable::hash(&bytes));durable::json(&self.journal_path(),&j)
    }
    /// Explicit original-operation adjudication. No marker or kernel action is
    /// dispatched. A missing or contradictory artifact remains uncertain.
    pub(super) fn recover(&self, token: &str, actor: &str,
        verify_owner: impl FnOnce(&Baseline) -> Result<()>) -> Result<Value> {
        let (mut journal, plan) = self.load()?.context("CONFLICT: ownership plan missing")?;
        Self::authorize(&journal, token, &plan, actor)?;
        match journal.state {
            State::Prepared if self.artifact(journal.operation_id,"receipt").try_exists()? => {
                ensure!(self.network_marker_absent()?,
                    "CONFLICT: cancellation cannot settle a present fence");
                  self.require_original_firewall_fence(&plan)?;
                let expected=Receipt{schema_version:1,operation_id:journal.operation_id,plan_sha256:journal.plan_sha256.clone(),state:State::Cancelled,lease_sha256:None};
                let f=BoundFile::open(&self.artifact(journal.operation_id,"receipt"),LIMIT)?;
                ensure!(f.bytes==serde_json::to_vec(&expected)?,"CONFLICT: original cancellation receipt differs");f.sync_exact()?;
                journal.state=State::Cancelled;journal.receipt_sha256=Some(durable::hash(&f.bytes));durable::json(&self.journal_path(),&journal)?;
            }
            State::FenceIntent => {
                let (marker, firewall_marker) = self.check_marker_pair(&journal, &plan)
                    .context("OUTCOME_UNKNOWN: original fence evidence is incomplete")?;
                journal.marker = Some(marker);
                  journal.firewall_marker=firewall_marker;
                journal.state = State::Fenced;
                durable::json(&self.journal_path(), &journal)?;
            }
            State::LeaseIntent => {
                let marker = self.check_marker(&journal)?;
                verify_owner(&plan.baseline)?;
                ensure!(marker == self.check_marker(&journal)?, "CONFLICT: original marker changed during recovery proof");
                  self.require_pair_identity(&journal,&plan)?;
                let lease_file = BoundFile::open(&self.artifact(journal.operation_id, "lease"), LIMIT)
                    .map_err(|_| anyhow::anyhow!("OUTCOME_UNKNOWN: original lease evidence is incomplete"))?;
                let lease: Lease = serde_json::from_slice(&lease_file.bytes)?;
                ensure!(lease.schema_version == lease.version() && lease.operation_id == journal.operation_id
                    && lease.plan_sha256 == journal.plan_sha256 && lease.baseline == plan.baseline
                    && lease.marker == marker,
                    "CONFLICT: original ownership lease differs");
                self.validate_lease_owner(&lease,&journal,&plan)?;
                let lease_sha256 = durable::hash(&lease_file.bytes);
                let receipt_file = BoundFile::open(&self.artifact(journal.operation_id, "receipt"), LIMIT)
                    .map_err(|_| anyhow::anyhow!("OUTCOME_UNKNOWN: original activation receipt is incomplete"))?;
                let expected = Receipt { schema_version: 1, operation_id: journal.operation_id,
                    plan_sha256: journal.plan_sha256.clone(), state: State::Committed,
                    lease_sha256: Some(lease_sha256.clone()) };
                ensure!(receipt_file.bytes == serde_json::to_vec(&expected)?,
                    "CONFLICT: original ownership activation receipt differs");
                lease_file.sync_exact()?;
                receipt_file.sync_exact()?;
                let receipt_sha256 = durable::hash(&receipt_file.bytes);
                let pointer = Pointer { schema_version: 1, operation_id: journal.operation_id,
                    lease_sha256, receipt_sha256: receipt_sha256.clone() };
                let path = self.root.join("confirmed.json");
                match fs::symlink_metadata(&path) {
                    Ok(_) => {
                        let file = BoundFile::open(&path, LIMIT)?;
                        ensure!(file.bytes == serde_json::to_vec(&pointer)?,
                            "CONFLICT: original ownership pointer differs");
                        file.sync_exact()?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        durable::publish_new(&path, &serde_json::to_vec(&pointer)?, FileMetadata::private())?;
                    }
                    Err(e) => return Err(e.into()),
                }
                journal.state = State::Committed;
                journal.receipt_sha256 = Some(receipt_sha256);
                durable::json(&self.journal_path(), &journal)?;
            }
            _ => {},
        }
        self.status()
    }
}

/// Registered-Kura-only caller supplies no PID/path. This uses retained original
/// state exclusively, including when optional NM writer configuration is absent.
pub(crate) fn confirmed_read(root:&Path,method:&str,value:Value)->Result<Value> {
    let _guard=crate::system_change::Guard::observe_shared(root,Duration::from_secs(1))?;
    Store::new(root).mirror(method,value)
}
/// Resolve only retained original evidence. New preparation still uses the fixed
/// production marker; readers follow the original recorded physical marker and
/// validate it against the complete parent journal/receipt/lease identity.
pub(crate) fn ordinary_selection(root:&Path,path:&Path,source:&str)->Result<Option<OrdinarySelection>> {
    ensure!(hex(source,64),"CONFLICT: original ordinary grant digest required");
    let store=Store::new(root);
    if !private_directory(&store.root)?{return Ok(None);}
    if !store.journal_path().try_exists()?{store.load()?;return Ok(None);}
    let initial:Journal=serde_json::from_slice(&read(&store.journal_path())?)?;
    if !matches!(initial.state,State::Fenced|State::LeaseIntent|State::Committed){store.load()?;return Ok(None);}
    let Some(marker)=startup::profile_marker(&store.root,initial.operation_id,&initial.plan_sha256)?else{return Ok(None)};
    let recorded=Store{root:store.root,marker};
    let (journal,_)=recorded.load()?.context("CONFLICT: original selected profile parent disappeared")?;
    ensure!(journal.operation_id==initial.operation_id && journal.plan_sha256==initial.plan_sha256,
        "CONFLICT: original selected profile parent changed during read");
    startup::resolve_profile(&recorded.root,journal.operation_id,&journal.plan_sha256,
        journal.marker.as_ref().context("CONFLICT: original selected profile marker missing")?,path,source)
}

/// Before the daemon is available, verify the existing Root-backed owner lease.
pub(crate) fn confirmed_private_firewall_boot_owner(root: &Path) -> Result<String> {
    let store = Store::new(root);
    store.firewall_boot_lease(4, "FORBIDDEN: complete private-layout paired owner lease required")
}

impl Store {
    fn firewall_boot_lease(&self, version: u8, scope_error: &'static str) -> Result<String> {
        let (journal, plan) = self.load()?.context("FORBIDDEN: original firewall owner required")?;
        ensure!(journal.state == State::Committed, "FORBIDDEN: original owner is not committed");
        let receipt = self.receipt(&journal)?;
        let lease = self.lease(&journal, &plan, &receipt)?;
        ensure!(
            lease.schema_version == version && lease.firewall_marker.is_some() && lease.startup_receipt_sha256.is_some(),
            "{scope_error}"
        );
        lease.owner_proof.context("FORBIDDEN: original Core owner proof required")?.require_complete()?;
        receipt.lease_sha256.context("CONFLICT: original owner lease hash")
    }
}

/// Root-level admission remains in force even if optional NM configuration is
/// removed. A terminal string alone cannot unlock other writers.
pub(crate) fn admission(root: &Path) -> Result<bool> {
    let store = Store::new(root);
    let parent=store.load()?;
    let settled=parent.as_ref().is_none_or(|(j,_)|matches!(j.state,State::Committed|State::Cancelled));
    Ok(settled && match template::Transfer::new(root).admission()? {
        template::Admission::Empty=>true,
        template::Admission::Pending=>false,
        template::Admission::Ready(binding)=>parent.as_ref().is_some_and(|(j,p)|j.state==State::Committed && p.template.as_ref()==Some(&binding)),
        template::Admission::Cancelled=>parent.as_ref().is_none_or(|(j,_)|j.state==State::Cancelled),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_change::{Guard, Subsystem};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fixture { root: PathBuf, store: Store, id: uuid::Uuid, token: String, source: Baseline }
    impl Fixture {
        fn new() -> Self {
            Self::with_template(false)
        }
        fn with_template(full:bool)->Self {
            let root = std::env::temp_dir().join(format!("nm-ownership-{}", uuid::Uuid::new_v4()));
            durable::directory(&root).unwrap();
            let marker_parent = root.join("installed"); durable::directory(&marker_parent).unwrap();
            let store = Store::relocated(&root, marker_parent.join("network-owner-agent"));
            let roles = roles::Observation::new(uuid::Uuid::new_v4(), 1, json!({
                "schemaVersion":1,"pid":roles::PID,"revision":"paired-origin",
                "interfaces":[{"id":"eth0","type":"ETHERNET","ipv4Status":"netIPv4StatusEnabledWAN","natEnabled":null}]
            })).unwrap();
            let source = Baseline { source_digest: "a".repeat(64), roles,
                profiles: vec![ProfileBinding { interface:"eth0".into(),
                    profile_uuid:Some(uuid::Uuid::new_v4().to_string()),origin_cas:full.then(||"c".repeat(64)) }],
                firewall_digest:"b".repeat(64),automatic_nat:Value::Null,native_transfer:None,firewall_fence:None,firewall_source:None };
            let id = uuid::Uuid::new_v4();
            let result=if full {
                let transfer=template::Transfer::new(&root);let nonce=transfer.start(id,"admin-uid:fixture".into(),source.clone()).unwrap();
                transfer.deposit(json!({"operationId":id,"revision":source.roles.roles.revision,"depositToken":nonce,
                    "templateSha256":durable::hash(b"AAAA-BBBB"),"chunkIndex":0,"chunkCount":1,"ciphertextChunk":"AAAA-BBBB"}),source.roles.agent_instance,source.roles.bridge_epoch).unwrap();
                let (binding,_)=transfer.ready(id,"admin-uid:fixture").unwrap();
                // Historical schema2 receipt fixtures intentionally keep the old
                // network-only baseline. They do not call new plan admission.
                store.plan_inner(id,"admin-uid:fixture".into(),source.clone(),Some(binding)).unwrap()
            } else {store.plan(id, "admin-uid:fixture".into(), source.clone()).unwrap()};
            Self { root, store, id, token:result["confirmationToken"].as_str().unwrap().into(), source }
        }
        fn fence(&self) { self.store.fence(&self.token, "admin-uid:fixture", || Ok(self.source.clone())).unwrap(); }
        fn activate(&self) {
            let callback=|b:&Baseline| {ensure!(*b==self.source,"fixture source drift");Ok(())};
            if self.store.load().unwrap().unwrap().1.template.is_some() {
                let view=self.store.mirror("network.nm.template.confirmed",json!({})).unwrap();
                // This seed deliberately retains historical persisted owner bytes,
                // not a fresh network-only wire projection accepted as authority.
                let proof:roles::Owner=serde_json::from_value(json!({"agentInstance":self.source.roles.agent_instance,
                    "bridgeEpoch":self.source.roles.bridge_epoch,"operationId":view["operationId"],
                    "planSha256":view["planSha256"],"mirrorSha256":view["templateSha256"],"roles":view["roles"]})).unwrap();
                self.store.seed_legacy_owner_fixture(&self.token,"admin-uid:fixture",proof,callback).unwrap();
            } else {self.store.activate(&self.token,"admin-uid:fixture",callback).unwrap();}
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
    }
    #[test]
    fn original_stored_source_is_absent_from_historical_baseline_bytes_and_keeps_old_digest_domain() {
        let f=Fixture::new();let bytes=serde_json::to_vec(&f.source).unwrap();
        #[derive(Serialize)]
        #[serde(rename_all="camelCase")]
        struct Old<'a> {source_digest:&'a str,roles:&'a roles::Observation,profiles:&'a [ProfileBinding],firewall_digest:&'a str,automatic_nat:&'a Value}
        let old=Old{source_digest:&f.source.source_digest,roles:&f.source.roles,profiles:&f.source.profiles,
            firewall_digest:&f.source.firewall_digest,automatic_nat:&f.source.automatic_nat};
        assert_eq!(bytes,serde_json::to_vec(&old).unwrap());
        let restored:Baseline=serde_json::from_slice(&bytes).unwrap();assert!(restored.firewall_source.is_none());
        assert_eq!(Baseline::bind_source(&f.source.source_digest,None).unwrap(),f.source.source_digest);
        let source=roles::fixture_firewall_source(&f.source.roles);
        assert_ne!(Baseline::bind_source(&f.source.source_digest,Some(&source)).unwrap(),f.source.source_digest);
    }
    #[test]
    fn original_stored_source_missing_cannot_admit_a_new_plan_or_rewrite_a_historical_one() {
        let f=Fixture::with_template(true);let before=read(&f.store.journal_path()).unwrap();
        let binding=template::Transfer::new(&f.root).ready(f.id,"admin-uid:fixture").unwrap().0;
        let error=f.store.plan_with_template(uuid::Uuid::new_v4(),"admin-uid:fixture".into(),f.source.clone(),binding).unwrap_err();
        assert!(error.to_string().contains("original firewall source"));assert_eq!(read(&f.store.journal_path()).unwrap(),before);
        assert!(f.store.original(f.id,"admin-uid:fixture").unwrap().is_some());
    }
    #[test]
    fn confirmed_mirror_requires_original_ready_template_and_actual_fence_before_serving_any_bytes() {
        let f=Fixture::with_template(true);
        assert!(f.store.mirror("network.nm.template.confirmed",json!({})).is_err());
        f.fence();let metadata=f.store.mirror("network.nm.template.confirmed",json!({})).unwrap();
        assert_eq!(metadata["operationId"],f.id.to_string());assert_eq!(metadata["sourceRevision"],"paired-origin");
        assert_eq!(metadata["chunkCount"],1);assert!(!metadata.to_string().contains(&f.token));
        let args=json!({"operationId":f.id,"planSha256":metadata["planSha256"],"templateSha256":metadata["templateSha256"],"chunkIndex":0});
        assert_eq!(f.store.mirror("network.nm.template.chunk",args).unwrap()["ciphertextChunk"],"AAAA-BBBB");
        f.activate();assert_eq!(f.store.mirror("network.nm.template.confirmed",json!({})).unwrap(),metadata);
    }
    #[test]
    fn confirmed_mirror_refuses_caller_pid_foreign_binding_out_of_range_and_missing_original_bytes() {
        let f=Fixture::with_template(true);f.fence();let metadata=f.store.mirror("network.nm.template.confirmed",json!({})).unwrap();
        assert!(f.store.mirror("network.nm.template.confirmed",json!({"pid":roles::PID})).is_err());
        for key in ["operationId","planSha256","templateSha256","chunkIndex","pid"] {
            let mut args=json!({"operationId":f.id,"planSha256":metadata["planSha256"],"templateSha256":metadata["templateSha256"],"chunkIndex":0});
            args[key]=if key=="operationId" {json!(uuid::Uuid::new_v4())} else if key=="chunkIndex" {json!(1)} else {json!("forged")};
            assert!(f.store.mirror("network.nm.template.chunk",args).is_err());
        }
        fs::remove_file(f.root.join("nm-template").join(format!("{}.chunk-0.cipher",f.id))).unwrap();
        assert!(f.store.mirror("network.nm.template.confirmed",json!({})).is_err());
    }
    #[test]
    fn prepared_plan_reserves_all_other_writers_and_never_leaks_a_token_in_status() {
        let f = Fixture::new();
        for kind in [Subsystem::Network,Subsystem::Nm,Subsystem::Firewall,Subsystem::Recovery,
            Subsystem::Configuration,Subsystem::Identity,Subsystem::OrdinaryBoot,Subsystem::SystemControl] {
            assert!(Guard::acquire(&f.root,kind).is_err());
        }
        assert!(Guard::acquire(&f.root,Subsystem::NmOwnership).is_ok());
        assert!(!f.store.status().unwrap().to_string().contains(&f.token));
        assert!(!f.store.marker.exists());
        assert!(f.store.plan(uuid::Uuid::new_v4(),"admin-uid:fixture".into(),f.source.clone()).is_err());
    }
    #[test]
    fn changed_source_wrong_actor_and_foreign_marker_never_install_or_claim_a_fence() {
        let f = Fixture::new();
        assert!(f.store.fence(&f.token,"another-actor",||Ok(f.source.clone())).is_err());
        let mut changed = f.source.clone(); changed.source_digest="c".repeat(64);
        assert!(f.store.fence(&f.token,"admin-uid:fixture",||Ok(changed)).is_err());
        assert!(!f.store.marker.exists());
        durable::publish_new(&f.store.marker,b"foreign owner",FileMetadata::private()).unwrap();
        let before = read(&f.store.journal_path()).unwrap();
        let error = f.store.fence(&f.token,"admin-uid:fixture",||Ok(f.source.clone())).unwrap_err();
        assert!(error.to_string().starts_with("CONFLICT:"));
        assert_eq!(fs::read(&f.store.marker).unwrap(),b"foreign owner");
        assert_eq!(read(&f.store.journal_path()).unwrap(), before);
        assert_eq!(f.store.status().unwrap()["state"], "PREPARED");
    }
    #[test]
    fn fixed_marker_and_live_confirmation_are_not_individually_an_active_lease() {
        let f = Fixture::new(); f.fence();
        assert!(f.store.active().unwrap().is_none());
        assert!(f.store.activate(&f.token,"admin-uid:fixture",|_|anyhow::bail!("KURA_UNAVAILABLE")).is_err());
        assert!(f.store.active().unwrap().is_none());
        f.activate();
        let restarted = Store::relocated(&f.root,f.store.marker.clone());
        assert_eq!(restarted.active().unwrap().unwrap().baseline.roles.roles.revision,"paired-origin");
        assert!(restarted.activate(&f.token,"admin-uid:fixture",|_|panic!("must not repeat")).is_err());
    }
    #[test]
    fn committed_cache_needs_no_live_kura_and_marker_drift_revokes_it() {
        let f = Fixture::new(); f.fence(); f.activate();
        let restarted = Store::relocated(&f.root,f.store.marker.clone());
        assert!(restarted.active().unwrap().is_some());
        durable::write(&f.store.marker,b"different owner",FileMetadata::private()).unwrap();
        assert!(restarted.active().is_err());
    }
    #[test]
    fn fence_publication_prefix_is_adjudicated_without_another_marker_dispatch() {
        let f = Fixture::new(); f.fence();
        let (mut journal,_) = f.store.load().unwrap().unwrap(); journal.state=State::FenceIntent;
        journal.marker=None;
        durable::json(&f.store.journal_path(),&journal).unwrap();
        let before=fs::symlink_metadata(&f.store.marker).unwrap().ino();
        assert_eq!(f.store.recover(&f.token,"admin-uid:fixture",|_|panic!("no activation verification")).unwrap()["state"],"FENCED");
        assert_eq!(fs::symlink_metadata(&f.store.marker).unwrap().ino(),before);
    }
    #[test]
    fn receipt_pointer_prefix_recovers_locally_but_incomplete_or_conflicting_evidence_stays_unknown() {
        for corrupt in [false,true] {
            let f = Fixture::new(); f.fence(); f.activate();
            let (mut journal,_) = f.store.load().unwrap().unwrap();
            journal.state=State::LeaseIntent; journal.receipt_sha256=None;
            durable::json(&f.store.journal_path(),&journal).unwrap();
            if corrupt { durable::write(&f.store.artifact(f.id,"receipt"),b"conflicting receipt",FileMetadata::private()).unwrap(); }
            else { durable::remove(&f.store.root.join("confirmed.json")).unwrap(); }
            let checks=AtomicUsize::new(0);
            let result=f.store.recover(&f.token,"admin-uid:fixture",|b|{
                checks.fetch_add(1,Ordering::SeqCst);ensure!(*b==f.source,"source");Ok(())
            });
            assert_eq!(result.is_ok(),!corrupt);assert_eq!(checks.load(Ordering::SeqCst),1);
            if !corrupt {assert!(f.store.active().unwrap().is_some());}
            else {assert!(f.store.active().unwrap().is_none());}
        }
    }
    #[test]
    fn broken_receipt_public_files_and_orphan_intent_never_become_a_grant() {
        use std::os::unix::fs::PermissionsExt;
        let f=Fixture::new();f.fence();f.activate();
        fs::set_permissions(f.store.artifact(f.id,"receipt"),fs::Permissions::from_mode(0o644)).unwrap();
        assert!(f.store.active().is_err());
        let g=Fixture::new();durable::remove(&g.store.journal_path()).unwrap();
        assert!(g.store.status().is_err());
    }
    #[test]
    fn identical_marker_bytes_at_a_new_inode_revoke_the_original_lease() {
        let f=Fixture::new();f.fence();f.activate();
        let bytes=fs::read(&f.store.marker).unwrap();
        let before=fs::symlink_metadata(&f.store.marker).unwrap().ino();
        durable::write(&f.store.marker,&bytes,FileMetadata::private()).unwrap();
        assert_ne!(fs::symlink_metadata(&f.store.marker).unwrap().ino(),before);
        assert!(f.store.active().is_err());
    }
    #[test]
    fn recovery_never_follows_replaced_files_or_parents_or_syncs_changed_bytes() {
        use std::os::unix::fs::symlink;
        for attack in ["symlink","hardlink","parent","same-inode"] {
            let f=Fixture::new();let path=f.store.root.join("pointer-fixture.json");
            durable::publish_new(&path,b"original",FileMetadata::private()).unwrap();
            let file=BoundFile::open(&path,LIMIT).unwrap();
            let other=f.root.join("protected-file");
            durable::publish_new(&other,b"untouched",FileMetadata::private()).unwrap();
            match attack {
                "symlink"=>{fs::remove_file(&path).unwrap();symlink(&other,&path).unwrap();}
                "hardlink"=>{fs::remove_file(&path).unwrap();fs::hard_link(&other,&path).unwrap();}
                "parent"=>{fs::rename(&f.store.root,f.root.join("retained-ownership")).unwrap();durable::directory(&f.store.root).unwrap();durable::publish_new(&path,b"foreign",FileMetadata::private()).unwrap();}
                "same-inode"=>{fs::write(&path,b"different").unwrap();}
                _=>unreachable!(),
            }
            assert!(file.sync_exact().is_err(),"accepted {attack}");
            assert_eq!(fs::read(&other).unwrap(),b"untouched");
            if attack=="symlink" || attack=="hardlink" {assert!(BoundFile::open(&path,LIMIT).is_err());}
        }
    }
    #[test]
    fn activation_does_not_replace_a_foreign_confirmed_pointer() {
        let f=Fixture::new();f.fence();
        let path=f.store.root.join("confirmed.json");
        durable::publish_new(&path,b"foreign pointer",FileMetadata::private()).unwrap();
        assert!(f.store.activate(&f.token,"admin-uid:fixture",|_|Ok(())).is_err());
        assert_eq!(fs::read(&path).unwrap(),b"foreign pointer");
        assert!(f.store.active().unwrap().is_none());
        assert!(f.store.recover(&f.token,"admin-uid:fixture",|_|Ok(())).is_err());
        assert_eq!(fs::read(&path).unwrap(),b"foreign pointer");
    }
}
