//! Imported records share the existing firewall transaction, confirmed pointer
//! and kura-history namespace. Protected files are evidence, never an owner grant.
use super::*;
use native::lineage::{CurrentSource, UpdatePlan};
use std::collections::BTreeSet;

const BACKEND: &str = "nft.imported.v1";
const MAX_HISTORY: usize = 4096;
pub(crate) mod producer;
pub(super) mod boot_lineage;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
enum Backend {
    #[serde(rename = "nft.imported.v1")]
    Imported,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Directory {
    device: u64,
    inode: u64,
}
fn directory(path: &Path) -> Result<Directory> {
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir()
            && !info.file_type().is_symlink()
            && info.uid() == unsafe { libc::geteuid() }
            && info.mode() & 0o777 == 0o700,
        "FORBIDDEN: unsafe imported evidence directory"
    );
    Ok(Directory {
        device: info.dev(),
        inode: info.ino(),
    })
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Reference {
    file: MarkerIdentity,
    firewall: Directory,
    history: Directory,
    parent: Directory,
}
impl Reference {
    fn validate(&self) -> Result<()> {
        ensure!(
            hex(&self.file.sha256, 64)
                && self.file.inode > 0
                && self.firewall.inode > 0
                && self.history.inode > 0
                && self.parent.inode > 0,
            "CONFLICT: imported evidence reference shape"
        );
        Ok(())
    }
    fn observe(root: &Path, path: &Path) -> Result<Self> {
        let file = BoundFile::open(path, LIMIT)?;
        Ok(Self {
            file: file.marker()?,
            firewall: directory(&root.join("firewall"))?,
            history: directory(&root.join("firewall/kura-history"))?,
            parent: directory(path.parent().unwrap())?,
        })
    }
    fn read(&self, root: &Path, path: &Path) -> Result<Vec<u8>> {
        self.validate()?;
        ensure!(
            self.firewall == directory(&root.join("firewall"))?
                && self.history == directory(&root.join("firewall/kura-history"))?
                && self.parent == directory(path.parent().unwrap())?,
            "CONFLICT: imported evidence directory was replaced"
        );
        let file = BoundFile::open(path, LIMIT)?;
        ensure!(
            self.file == file.marker()?,
            "CONFLICT: imported evidence file was replaced or changed"
        );
        file.verify_binding()?;
        Ok(file.bytes)
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Head {
    #[serde(rename = "INITIALIZATION")]
    Initialization {
        #[serde(rename = "receiptSha256")]
        receipt_sha256: String,
    },
    #[serde(rename = "TRANSACTION")]
    Transaction {
        uid: u32,
        #[serde(rename = "requestId")]
        request_id: String,
        reference: Reference,
    },
    #[serde(rename = "BOOT_RESTORE")]
    BootRestore {
        #[serde(rename = "bootId")]
        boot_id: uuid::Uuid,
        reference: MarkerIdentity,
    },
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum State {
    Observing,
    Observed,
    Prepared,
    Applying,
    WaitConfirm,
    Confirming,
    Committed,
    RollingBack,
    RolledBack,
    RecoveryRequired,
    Rejecting,
    Rejected,
}
impl State {
    fn settled(&self) -> bool {
        matches!(self, Self::Committed | Self::RolledBack | Self::Rejected | Self::Observed)
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Kind {
    SourceObservation,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Record {
    backend: Backend,
    schema_version: u8,
    #[serde(default, skip_serializing_if="Option::is_none")]
    origin: Option<producer::principal::OriginAudit>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    forward_command:Option<producer::principal::CommandAudit>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    inverse_command:Option<producer::principal::CommandAudit>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    confirmation_command:Option<producer::principal::CommandAudit>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    cancellation_command:Option<producer::principal::CommandAudit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<Kind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expiry: Option<producer::expiry::Decision>,
    id: uuid::Uuid,
    uid: u32,
    request_id: String,
    owner_sha256: String,
    input_sha256: String,
    initialization_receipt_sha256: String,
    state: State,
    deadline_ms: u64,
    base: Head,
    plan: Reference,
    forward_intent: bool,
    inverse_intent: bool,
    confirmed_decision: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    forward: Option<Reference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inverse: Option<Reference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization: Option<producer::Authorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    forward_dispatch: Option<producer::execution::Intent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inverse_dispatch: Option<producer::execution::Intent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    negative: Option<Reference>,
    #[serde(default)]
    forward_capture_intent: bool,
    #[serde(default)]
    inverse_capture_intent: bool,
    #[serde(default)]
    negative_capture_intent: bool,
    #[serde(default)]
    settlement_intent: bool,
}
impl Record {
    fn validate(&self) -> Result<()> {
        if let Some(origin)=&self.origin {origin.require(self.uid,&self.request_id,self.id)?;}
        else {request(self.uid, &self.request_id)?;}
        if let Some(origin)=&self.origin {
            for (command,operation) in [(&self.forward_command,41),(&self.inverse_command,43),(&self.confirmation_command,42),(&self.cancellation_command,44)] {
                if let Some(command)=command {command.require(origin,operation)?;}
            }
            ensure!(self.kind.is_none()||[&self.forward_command,&self.inverse_command,&self.confirmation_command,&self.cancellation_command].into_iter().all(Option::is_none),
                "CONFLICT: source observation cannot acquire remote action audit");
            ensure!(self.forward_intent==self.forward_command.is_some()
                && self.confirmed_decision==self.confirmation_command.is_some()
                && (self.inverse_intent==self.inverse_command.is_some() || self.expiry.is_some()&&self.inverse_intent&&self.inverse_command.is_none())
                && (self.cancellation_command.is_none() || !self.forward_intent&&!self.inverse_intent&&!self.confirmed_decision&&matches!(self.state,State::RollingBack|State::RolledBack))
                && (self.expiry.is_none()||self.inverse_command.is_none()&&self.cancellation_command.is_none()),
                "CONFLICT: original remote action/intent scope");
        } else {
            ensure!([&self.forward_command,&self.inverse_command,&self.confirmation_command,&self.cancellation_command].into_iter().all(Option::is_none),
                "CONFLICT: local records cannot acquire remote action audit");
        }
        let stopped=self.authorization.as_ref().is_some_and(producer::Authorization::stopped_authority)
            || [&self.forward_dispatch,&self.inverse_dispatch].into_iter().flatten()
                .any(producer::execution::Intent::stopped_authority);
        ensure!(
            self.backend == Backend::Imported
                && match self.schema_version {
                    1=>self.origin.is_none() && self.authorization.is_none() && self.kind.is_none() && !stopped && self.expiry.is_none(),
                    2=>self.origin.is_none() && self.authorization.is_some() && self.kind.is_none() && !stopped && self.expiry.is_none(),
                    3=>self.origin.is_none() && self.authorization.is_some() && self.kind==Some(Kind::SourceObservation) && !stopped && self.expiry.is_none(),
                    4=>self.origin.is_none() && self.authorization.is_some() && (stopped || self.expiry.is_some()),
                    5=>self.origin.is_some() && self.authorization.is_some(),
                    _=>false,
                }
                && !self.id.is_nil()
                && hex(&self.owner_sha256, 64)
                && hex(&self.input_sha256, 64)
                && hex(&self.initialization_receipt_sha256, 64)
                && self.deadline_ms > 0
                && self.deadline_ms <= i64::MAX as u64,
            "CONFLICT: imported transaction identity"
        );
        if let Some(authorization) = &self.authorization {
            authorization.validate()?;
        }
        if let Some(expiry)=&self.expiry {expiry.require_record(self)?;}
        if self.kind == Some(Kind::SourceObservation) {
            ensure!(matches!(self.state, State::Observing | State::Observed)
                && !self.forward_intent && !self.inverse_intent && !self.confirmed_decision
                && self.forward.is_none() && self.inverse.is_none() && self.negative.is_none()
                && self.forward_dispatch.is_none() && self.inverse_dispatch.is_none()
                && !self.forward_capture_intent && !self.inverse_capture_intent && !self.negative_capture_intent
                && (self.state != State::Observed || self.settlement_intent),
                "CONFLICT: source observation cannot acquire dispatch or confirmation authority");
            self.plan.validate()?;
            return Ok(());
        }
        if self.schema_version == 1 {
            ensure!(
                self.forward_dispatch.is_none()
                    && self.inverse_dispatch.is_none()
                    && self.negative.is_none()
                    && !self.forward_capture_intent
                    && !self.inverse_capture_intent
                    && !self.negative_capture_intent
                    && !self.settlement_intent,
                "CONFLICT: historical metadata cannot acquire ordinary intents"
            );
        } else {
            ensure!(
                self.forward_intent == self.forward_dispatch.is_some()
                    && self.inverse_intent == self.inverse_dispatch.is_some()
                    && (!self.forward_capture_intent || self.forward_intent)
                    && (!self.inverse_capture_intent || self.inverse_intent)
                    && (self.forward.is_none() || self.forward_capture_intent)
                    && (self.inverse.is_none() || self.inverse_capture_intent)
                    && (!self.negative_capture_intent || self.forward_intent)
                    && (self.negative.is_none() || self.negative_capture_intent),
                "CONFLICT: imported one-shot dispatch/capture intent shape"
            );
            for intent in [&self.forward_dispatch, &self.inverse_dispatch]
                .into_iter()
                .flatten()
            {
                intent.validate()?;
            }
            if let Some(reference) = &self.negative {
                reference.validate()?;
            }
            ensure!(
                self.negative.is_none()
                    || matches!(
                        self.state,
                        State::Rejecting | State::Rejected | State::RecoveryRequired
                    ),
                "CONFLICT: imported negative ACK phase"
            );
        }
        self.plan.validate()?;
        if let Some(reference) = &self.forward {
            reference.validate()?;
        }
        if let Some(reference) = &self.inverse {
            reference.validate()?;
        }
        let shape = match self.state {
            State::Observing | State::Observed => false,
            State::Prepared => {
                !self.forward_intent
                    && !self.inverse_intent
                    && !self.confirmed_decision
                    && self.forward.is_none()
                    && self.inverse.is_none()
            }
            State::Applying => {
                self.forward_intent
                    && !self.inverse_intent
                    && !self.confirmed_decision
                    && self.forward.is_none()
                    && self.inverse.is_none()
            }
            State::WaitConfirm => {
                self.forward_intent
                    && !self.inverse_intent
                    && !self.confirmed_decision
                    && self.forward.is_some()
                    && self.inverse.is_none()
            }
            State::Confirming | State::Committed => {
                self.forward_intent
                    && !self.inverse_intent
                    && self.confirmed_decision
                    && self.forward.is_some()
                    && self.inverse.is_none()
            }
            State::RollingBack => {
                if self.forward_intent {
                    self.forward_intent
                        && self.inverse_intent
                        && !self.confirmed_decision
                        && self.forward.is_some()
                } else {
                    matches!(self.schema_version,2|4|5)
                        && !self.inverse_intent
                        && !self.confirmed_decision
                        && self.forward.is_none()
                        && self.inverse.is_none()
                }
            }
            State::RolledBack => {
                !self.confirmed_decision
                    && if self.forward_intent {
                        self.inverse_intent && self.forward.is_some() && self.inverse.is_some()
                    } else {
                        !self.inverse_intent && self.forward.is_none() && self.inverse.is_none()
                    }
            }
            State::Rejecting | State::Rejected => {
                matches!(self.schema_version,2|4|5)
                    && self.forward_intent
                    && !self.inverse_intent
                    && !self.confirmed_decision
                    && self.forward.is_none()
                    && self.inverse.is_none()
                    && self.negative.is_some()
            }
            State::RecoveryRequired => {
                self.forward_intent
                    && !self.confirmed_decision
                    && (!self.inverse_intent || self.forward.is_some())
                    && self.inverse.is_none()
            }
        };
        ensure!(shape, "CONFLICT: imported transaction phase/receipt shape");
        Ok(())
    }
    fn path(&self, root: &Path, name: &str) -> PathBuf {
        root.join("firewall/kura-history")
            .join(format!("{}.artifacts", key(self.uid, &self.request_id)))
            .join(name)
    }
    fn checked_plan(
        &self,
        root: &Path,
        parent: &CurrentSource,
        original: &Value,
    ) -> Result<UpdatePlan> {
        self.validate()?;
        ensure!(self.kind.is_none(), "CONFLICT: source observation is not a native update plan");
        let plan = parent.decode_plan(&self.plan.read(root, &self.path(root, "plan.json"))?)?;
        ensure!(
            plan.parameters()?["operationId"] == json!(self.id)
                && plan.parameters()?["initializationReceiptSha256"]
                    == self.initialization_receipt_sha256,
            "CONFLICT: imported plan operation/initialization identity"
        );
        if let Some(authorization) = &self.authorization {
            authorization.require_source(root, &self.base, parent, original)?;
        }
        if let Some(reference) = &self.forward {
            plan.acknowledge(
                &serde_json::from_slice(&reference.read(root, &self.path(root, "forward.json"))?)?,
                false,
            )?;
        }
        if let Some(reference) = &self.inverse {
            plan.acknowledge(
                &serde_json::from_slice(&reference.read(root, &self.path(root, "inverse.json"))?)?,
                true,
            )?;
        }
        producer::execution::check_evidence(root, self, &plan)?;
        Ok(plan)
    }
    fn checked_observation(
        &self, root: &Path, parent: &CurrentSource, original: &Value,
    ) -> Result<native::lineage::ObservationPlan> {
        self.validate()?;
        ensure!(self.kind == Some(Kind::SourceObservation), "CONFLICT: source observation kind required");
        let plan = parent.decode_observation(&self.plan.read(root, &self.path(root, "plan.json"))?)?;
        ensure!(plan.operation() == self.id
            && plan.parameters()?["initializationReceiptSha256"] == self.initialization_receipt_sha256,
            "CONFLICT: source observation operation/initialization identity");
        self.authorization.as_ref().unwrap().require_source(root, &self.base, parent, original)?;
        Ok(plan)
    }
    fn checked_evidence(&self, root: &Path, parent: &CurrentSource, original: &Value) -> Result<()> {
        if self.kind == Some(Kind::SourceObservation) {
            self.checked_observation(root, parent, original)?;
        } else {
            self.checked_plan(root, parent, original)?;
        }
        Ok(())
    }
    fn replayed_source(&self, root: &Path, parent: &CurrentSource, original: &Value) -> Result<CurrentSource> {
        if self.kind == Some(Kind::SourceObservation) {
            ensure!(self.state == State::Observed, "CONFLICT: observation is not immutably settled");
            self.checked_observation(root, parent, original)?.settled_source(parent)
        } else {
            self.source(root, parent, &self.checked_plan(root, parent, original)?)
        }
    }
    fn advances_current(&self) -> bool {
        self.state == State::Observed && self.kind == Some(Kind::SourceObservation)
            || self.forward_intent && self.state != State::Rejected
    }
    fn source(
        &self,
        root: &Path,
        parent: &CurrentSource,
        plan: &UpdatePlan,
    ) -> Result<CurrentSource> {
        let (reference, name, inverse) = match self.state {
            State::Committed => (self.forward.as_ref(), "forward.json", false),
            State::RolledBack if self.inverse_intent => {
                (self.inverse.as_ref(), "inverse.json", true)
            }
            _ => anyhow::bail!("CONFLICT: current source requires a settled physical transaction"),
        };
        let bytes = reference
            .context("CONFLICT: imported settled source receipt")?
            .read(root, &self.path(root, name))?;
        plan.settled_source(parent, &serde_json::from_slice(&bytes)?, inverse)
    }
    fn projection(&self) -> Value {
        let expired = now_ms() >= self.deadline_ms;
        let mut value = json!({"id":self.id,"requestId":self.request_id,"state":self.state,"deadlineMs":self.deadline_ms,
            "deadlineExpired":expired,"requiresOriginalQuery":matches!(self.state,State::Observing|State::Applying|State::Confirming|State::RollingBack|State::RecoveryRequired|State::Rejecting)||expired&&!self.state.settled(),
            "writeEnabled":false,"ownerGrant":false});
        if self.kind.is_some() {
            value["kind"] = json!(self.kind);
            value["kernelEffect"] = json!(false);
            value["logicalRevisionChanged"] = json!(false);
        }
        if let Some(expiry)=&self.expiry {value["expiry"]=json!(expiry);}
        value
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Confirmed {
    backend: Backend,
    schema_version: u8,
    head: Head,
    revision: u64,
    source_digest: String,
}

impl Confirmed {
    fn require_head_kind(&self) -> Result<()> {
        ensure!(self.backend == Backend::Imported && matches!((&self.head, self.schema_version),
            (Head::Transaction { .. }, 1) | (Head::BootRestore { .. }, 2)),
            "CONFLICT: imported current pointer requires actual transaction or boot history");
        Ok(())
    }
}

fn request(uid: u32, value: &str) -> Result<()> {
    ensure!(uid>0 && !value.strip_prefix("remote-").is_some_and(|suffix|hex(suffix,64)),
        "CONFLICT: local Kura peer cannot use a remote principal identity");
    request_shape(uid,value)
}
fn request_shape(uid:u32,value:&str)->Result<()> {
    ensure!(
        uid <= i32::MAX as u32
            && !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)),
        "CONFLICT: imported transaction request identity"
    );
    Ok(())
}
fn key(uid: u32, request: &str) -> String {
    durable::hash(format!("{uid}:{request}").as_bytes())
}
fn history(root: &Path, uid: u32, request: &str) -> PathBuf {
    root.join("firewall/kura-history")
        .join(format!("{}.json", key(uid, request)))
}

/// The mutable pointer and active marker cannot make retained work disappear.
/// Old initialization epochs remain audit evidence, never the current source.
#[derive(Default)]
struct Inventory {
    records: BTreeMap<String, Record>,
    artifacts: BTreeSet<String>,
    entries: usize,
}
impl Inventory {
    fn read(root: &Path) -> Result<Self> {
        let mut result = Self::default();
        let path = root.join("firewall/kura-history");
        if !present(&path)? {
            return Ok(result);
        }
        directory(&root.join("firewall"))?;
        let original = directory(&path)?;
        for (index, entry) in fs::read_dir(&path)?.enumerate() {
            ensure!(
                index < MAX_HISTORY * 3,
                "RESOURCE_EXHAUSTED: imported history inventory"
            );
            result.entries = index + 1;
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .context("CONFLICT: non-UTF8 imported history name")?;
            if let Some(key) = name.strip_suffix(".artifacts") {
                ensure!(
                    hex(key, 64),
                    "CONFLICT: imported artifact directory identity"
                );
                directory(&entry.path())?;
                result.artifacts.insert(key.into());
            } else if let Some(key) = name.strip_suffix(".json") {
                ensure!(hex(key, 64), "CONFLICT: imported history filename identity");
                let file = BoundFile::open(&entry.path(), LIMIT)?;
                let value: Value = serde_json::from_slice(&file.bytes)?;
                if value.get("backend").is_none() {
                    continue; // The private engine retains its original history.
                }
                ensure!(
                    file.bytes.len() <= 16_384,
                    "RESOURCE_EXHAUSTED: imported history record"
                );
                let record: Record = serde_json::from_value(value)
                    .context("CONFLICT: unsupported imported history backend/record")?;
                record.validate()?;
                ensure!(
                    record.state.settled() && key == self::key(record.uid, &record.request_id),
                    "CONFLICT: immutable imported history identity/state"
                );
                file.verify_binding()?;
                result.records.insert(key.into(), record);
            }
        }
        ensure!(
            original == directory(&path)?,
            "CONFLICT: imported history directory was replaced"
        );
        Ok(result)
    }

    fn reconcile(
        &self,
        anchor: &str,
        reachable: &BTreeSet<String>,
        active: Option<&Record>,
    ) -> Result<()> {
        let active_key = active.map(|record| key(record.uid, &record.request_id));
        for (key, record) in &self.records {
            // A durable pre-dispatch cancellation has no physical source to
            // publish, so it legitimately stays outside the current head chain.
            let no_effect = record.state.settled() && !record.advances_current();
            ensure!(
                record.initialization_receipt_sha256 != anchor
                    || no_effect
                    || reachable.contains(key)
                    || active_key.as_ref() == Some(key),
                "OUTCOME_UNKNOWN: retained imported outcome lost its current pointer; query original work"
            );
        }
        for key in &self.artifacts {
            ensure!(
                self.records.contains_key(key) || active_key.as_ref() == Some(key),
                "OUTCOME_UNKNOWN: orphan imported artifacts; preserve original work without redispatch"
            );
        }
        Ok(())
    }
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

pub(super) fn initial(document: &Document, origin: &roles::Origin, source: &Value) -> Result<CurrentSource> {
    let view = projection::view(document, origin, source)?;
    ensure!(
        view["projectable"] == true,
        "UNSUPPORTED: complete original model metadata required for current history"
    );
    let prefixes = origin
        .families()
        .iter()
        .map(|family| {
            Ok((
                family.family.clone(),
                family
                    .runtime_port_forward_destination_prefixes
                    .clone()
                    .context("CONFLICT: original destination prefix evidence")?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut current = CurrentSource::from_acknowledged(
        source["initializationReceiptSha256"].as_str().unwrap(),
        document.revision,
        view["candidate"].clone(),
        prefixes,
        &document.native_transfer,
        &document.kernel,
        false,
    )?;
    current.bind_epoch(document.native_epoch.clone())?;
    Ok(current)
}

fn resolve(
    root: &Path,
    document: &Document,
    origin: &roles::Origin,
    source: &Value,
    head: &Head,
    reachable: &mut BTreeSet<String>,
) -> Result<CurrentSource> {
    Ok(resolve_with_boot(root, document, origin, source, head, reachable)?.0)
}

fn resolve_with_boot(
    root: &Path,
    document: &Document,
    origin: &roles::Origin,
    source: &Value,
    head: &Head,
    reachable: &mut BTreeSet<String>,
) -> Result<(CurrentSource, Option<uuid::Uuid>, usize)> {
    enum Link { Transaction(Record), Boot(boot_lineage::Binding) }
    let mut records = Vec::new();
    let mut next = head.clone();
    let mut seen = BTreeSet::new();
    let mut seen_boots = BTreeSet::new();
    let mut recent_boot = None;
    loop {
        match &next {
            Head::Initialization { receipt_sha256 } => {
                ensure!(
                    source["initializationReceiptSha256"] == *receipt_sha256,
                    "CONFLICT: imported history changed initialization anchor"
                );
                break;
            }
            Head::Transaction {
                uid,
                request_id,
                reference,
            } => {
                producer::principal::original_request(*uid, request_id)?;
                ensure!(
                    records.len() < MAX_HISTORY && seen.insert((*uid, request_id.clone())),
                    "RESOURCE_EXHAUSTED: cyclic or excessive imported history"
                );
                let record: Record = serde_json::from_slice(
                    &reference.read(root, &history(root, *uid, request_id))?,
                )?;
                record.validate()?;
                ensure!(
                    record.state.settled()
                        && record.uid == *uid
                        && record.request_id == *request_id
                        && source["initializationReceiptSha256"]
                            == record.initialization_receipt_sha256,
                    "CONFLICT: imported history identity/state"
                );
                reachable.insert(key(*uid, request_id));
                next = record.base.clone();
                records.push(Link::Transaction(record));
            }
            Head::BootRestore { boot_id, reference } => {
                ensure!(records.len() < MAX_HISTORY && seen_boots.insert(*boot_id),
                    "RESOURCE_EXHAUSTED: cyclic or excessive imported boot history");
                recent_boot.get_or_insert(*boot_id);
                let binding = boot_lineage::Binding::read(root, *boot_id, reference)?;
                next = binding.base.clone();
                records.push(Link::Boot(binding));
            }
        }
    }
    let mut current = initial(document, origin, source)?;
    for record in records.iter().rev() {
        current = match record {
            Link::Transaction(record) => record.replayed_source(root, &current, source)?,
            Link::Boot(binding) => binding.replay(root, current)?,
        };
    }
    Ok((current, recent_boot, records.len()))
}

pub(super) struct View {
    pub(super) current: CurrentSource,
    pub(super) has_current: bool,
    pub(super) settled: bool,
    pub(super) transaction: Option<Value>,
    head: Head,
    history_depth: usize,
    recent_boot: Option<uuid::Uuid>,
}

impl View {
    pub(super) fn from_boot_restore(&self) -> bool {
        matches!(self.head, Head::BootRestore { .. })
    }
}

pub(super) fn read(
    root: &Path,
    document: &Document,
    origin: &roles::Origin,
    source: &Value,
) -> Result<Option<View>> {
    let confirmed_path = root.join("firewall/confirmed.json");
    let active_path = root.join("firewall/transaction.json");
    let inventory = Inventory::read(root)?;
    let anchor = source["initializationReceiptSha256"].as_str().unwrap();
    let mut reachable = BTreeSet::new();
    if !present(&confirmed_path)? && !present(&active_path)? {
        inventory.reconcile(anchor, &reachable, None)?;
        return Ok(None);
    }
    directory(&root.join("firewall"))?;
    let original = Head::Initialization {
        receipt_sha256: source["initializationReceiptSha256"]
            .as_str()
            .unwrap()
            .into(),
    };
    let pointer = if present(&confirmed_path)? {
        Some(BoundFile::open(&confirmed_path, LIMIT)?)
    } else {
        None
    };
    let head = if let Some(file) = &pointer {
        let pointer: Confirmed = serde_json::from_slice(&file.bytes)
            .context("CONFLICT: imported and private confirmed authorities overlap")?;
        pointer.require_head_kind()?;
        let (current, recent_boot, depth) = resolve_with_boot(
            root,
            document,
            origin,
            source,
            &pointer.head,
            &mut reachable,
        )?;
        let witness = current.witness()?;
        ensure!(
            witness["revision"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                == Some(pointer.revision)
                && witness["sourceDigest"] == pointer.source_digest,
            "CONFLICT: current pointer revision/source differs from history"
        );
        (pointer.head, current, true, recent_boot, depth)
    } else {
        (original, initial(document, origin, source)?, false, None, 0)
    };
    let (current_head, current, has_current, recent_boot, depth) = head;
    let mut settled = true;
    let mut transaction = None;
    if present(&active_path)? {
        let file = BoundFile::open(&active_path, 16_384)?;
        let record: Record = serde_json::from_slice(&file.bytes)
            .context("CONFLICT: imported and private transaction authorities overlap")?;
        record.validate()?;
        ensure!(
            record.initialization_receipt_sha256 == anchor,
            "CONFLICT: active imported transaction belongs to another initialization"
        );
        // A boot restore advances the physical head with no new imported
        // transaction. The previous terminal marker remains byte-for-byte
        // tied to the head it settled on until a new transaction is prepared.
        let mut marker_head = current_head.clone();
        if record.state.settled() && record.base != marker_head {
            for _ in 0..MAX_HISTORY {
                let Head::BootRestore { boot_id, reference } = &marker_head else { break; };
                marker_head = boot_lineage::Binding::read(root, *boot_id, reference)?.base;
                if marker_head == record.base { break; }
            }
        }
        if record.base == marker_head {
            if marker_head == current_head {
                record.checked_evidence(root, &current, source)?;
            } else {
                let parent = resolve(root, document, origin, source, &marker_head, &mut reachable)?;
                record.checked_evidence(root, &parent, source)?;
            }
        } else {
            ensure!(
                matches!(&marker_head,Head::Transaction{uid,request_id,..} if *uid==record.uid&&*request_id==record.request_id),
                "CONFLICT: active transaction is not the current history head"
            );
        }
        if record.state.settled() || record.base != current_head {
            let path = history(root, record.uid, &record.request_id);
            let reference = Reference::observe(root, &path)?;
            let retained: Record = serde_json::from_slice(&reference.read(root, &path)?)?;
            let mut expected = record.clone();
            if !record.state.settled() {
                expected.state = match record.state {
                    State::Observing => State::Observed,
                    State::Confirming => State::Committed,
                    State::RollingBack => State::RolledBack,
                    State::Rejecting => State::Rejected,
                    _ => anyhow::bail!(
                        "CONFLICT: current publication outside a durable settlement decision"
                    ),
                };
            }
            ensure!(
                retained == expected && retained.state.settled(),
                "CONFLICT: active imported outcome differs from immutable history"
            );
            let expected_head = if retained.advances_current() {
                Head::Transaction {
                    uid: record.uid,
                    request_id: record.request_id.clone(),
                    reference,
                }
            } else {
                record.base.clone()
            };
            ensure!(
                marker_head == expected_head,
                "CONFLICT: current pointer lost its original settled transaction"
            );
        }
        settled = record.state.settled();
        transaction = Some(record.projection());
        inventory.reconcile(anchor, &reachable, Some(&record))?;
        file.verify_binding()?;
    } else {
        inventory.reconcile(anchor, &reachable, None)?;
    }
    if let Some(file) = pointer {
        file.verify_binding()?;
    }
    Ok(Some(View {
        current,
        has_current,
        settled,
        transaction,
        head: current_head,
        history_depth: depth,
        recent_boot,
    }))
}

pub(super) fn recognized(root: &Path) -> Result<bool> {
    for name in ["transaction.json", "confirmed.json"] {
        let path = root.join("firewall").join(name);
        if present(&path)? {
            let file = BoundFile::open(&path, LIMIT)?;
            let value: Value = serde_json::from_slice(&file.bytes)?;
            file.verify_binding()?;
            if let Some(backend) = value.get("backend") {
                ensure!(
                    backend == BACKEND,
                    "UNSUPPORTED: retained typed firewall backend"
                );
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Only finish the active marker after BOTH the immutable settled history and
/// its acknowledged current pointer already exist. Missing publications remain
/// unknown; no artifact, pointer, plan or native effect is recreated here.
pub(super) fn finish_marker(
    root: &Path,
    document: &Document,
    origin: &roles::Origin,
    source: &Value,
) -> Result<bool> {
    let Some(view) = read(root, document, origin, source)? else {
        return Ok(false);
    };
    if view.settled {
        return Ok(false);
    }
    let active_path = root.join("firewall/transaction.json");
    let active = BoundFile::open(&active_path, LIMIT)?;
    let mut record: Record = serde_json::from_slice(&active.bytes)?;
    if record.state == State::Rejecting
        || record.state == State::RollingBack && !record.forward_intent
    {
        let path = history(root, record.uid, &record.request_id);
        if !present(&path)? {
            return Ok(false);
        }
        let file = BoundFile::open(&path, LIMIT)?;
        let retained: Record = serde_json::from_slice(&file.bytes)?;
        record.state = if record.state == State::Rejecting {
            State::Rejected
        } else {
            State::RolledBack
        };
        record.validate()?;
        ensure!(
            record == retained && view.head == record.base,
            "CONFLICT: original no-effect cancellation differs from immutable history/current source"
        );
        active.verify_binding()?;
        file.verify_binding()?;
        durable::json(&active_path, &record)?;
        return Ok(true);
    }
    if !view.has_current {
        return Ok(false);
    }
    let terminal = match record.state {
        State::Observing => State::Observed,
        State::Confirming => State::Committed,
        State::RollingBack if record.inverse.is_some() => State::RolledBack,
        _ => return Ok(false),
    };
    let pointer = BoundFile::open(&root.join("firewall/confirmed.json"), LIMIT)?;
    let confirmed: Confirmed = serde_json::from_slice(&pointer.bytes)?;
    let Head::Transaction {
        uid,
        request_id,
        reference,
    } = confirmed.head
    else {
        return Ok(false);
    };
    if uid != record.uid || request_id != record.request_id {
        return Ok(false);
    }
    let retained: Record =
        serde_json::from_slice(&reference.read(root, &history(root, uid, &request_id))?)?;
    record.state = terminal;
    ensure!(
        record == retained,
        "CONFLICT: original imported final marker differs from its acknowledged history"
    );
    ensure!(
        serde_json::to_vec(&record)?.len() <= LIMIT as usize,
        "RESOURCE_EXHAUSTED: imported final marker"
    );
    active.verify_binding()?;
    pointer.verify_binding()?;
    durable::json(&active_path, &record)?;
    Ok(true)
}
