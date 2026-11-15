//! Explicit, durable adoption of reviewed native systemd boot entries.
//! This changes enablement only; it never starts/stops a service or certifies a boot.
use crate::{
    durable::{self, FileMetadata},
    system_change::{Guard, Subsystem},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct Boot {
    root: PathBuf,
    systemctl: PathBuf,
    links_root: PathBuf,
    policy_file: PathBuf,
    core_lock: PathBuf,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Request {
    schema: u32,
    ordinary_profile: PathBuf,
    ordinary_grant_sha256: String,
    retire: Vec<Retired>,
    valid_for_seconds: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Retired {
    unit: String,
    unit_file: PathBuf,
    unit_sha256: String,
    drop_ins: Vec<Pinned>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pinned {
    path: PathBuf,
    sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UnitState {
    unit: String,
    unit_file: PathBuf,
    enablement: String,
    pid: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Journal {
    schema: u32,
    id: String,
    token: String,
    state: String,
    expires_at: u64,
    request: Request,
    target: UnitState,
    retired: Vec<UnitState>,
    #[serde(rename = "actionIntents")]
    actions: Vec<String>,
    receipt_sha256: Option<String>,
    previous_confirmed_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    command_decisions: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued_command: Option<CommandBinding>,
}
/// Exact authenticated admission, never supplied by a UDS caller.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CommandBinding {
    command_id: String,
    request_sha256: String,
    operation: i32,
}
impl CommandBinding {
    pub(crate) fn from_command(c: &yofc_management_protocol::v1::ReadCommand) -> Result<Self> {
        use prost::Message;
        let b = Self {
            command_id: c.command_id.clone(),
            request_sha256: durable::hash(&c.encode_to_vec()),
            operation: c.operation,
        };
        ensure!(b.valid() && c.valid_payload(), "INVALID_ARGUMENT");
        Ok(b)
    }
    fn valid(&self) -> bool {
        canonical_uuid(&self.command_id)
            && hash(&self.request_sha256)
            && matches!(self.operation, 16..=19)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CommandDecision {
    schema: u32,
    binding: CommandBinding,
    transaction_id: String,
    result: Value,
}
fn canonical_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|u| u.to_string() == s)
}
fn same_policy(a: &Journal, b: &Journal) -> bool {
    let mut a = serde_json::to_value(a).unwrap();
    let mut b = serde_json::to_value(b).unwrap();
    a.as_object_mut().unwrap().remove("commandDecisions");
    b.as_object_mut().unwrap().remove("commandDecisions");
    a == b
}
const COMMITTED: &str = "BOOT_POLICY_COMMITTED";
const PREPARED: &str = "BOOT_POLICY_PREPARED";
const RR: &str = "RECOVERY_REQUIRED";
const FIELDS: &str = "Id,Names,LoadState,ActiveState,MainPID,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload,WantedBy,RequiredBy,BoundBy,ConsistsOf,TriggeredBy,UpheldBy,Requires,Wants,Requisite,BindsTo,PartOf,After";
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn name(s: &str) -> bool {
    s.ends_with(".service")
        && s.len() <= 200
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn absolute(p: &Path) -> Result<()> {
    ensure!(
        p.is_absolute()
            && p.components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "FORBIDDEN: normalized absolute boot path required"
    );
    Ok(())
}
fn private(p: &Path, limit: u64) -> Result<Vec<u8>> {
    absolute(p)?;
    let b = crate::controlled_startup::trusted_file(p, limit)?;
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "FORBIDDEN: private owned boot input required"
    );
    Ok(b)
}
fn journal_identity(j: &Journal) -> Result<()> {
    ensure!(
        j.schema == 1
            && j.id
                .strip_prefix("boot-")
                .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok_and(|id| id.to_string() == s))
            && uuid::Uuid::parse_str(&j.token).is_ok_and(|id| id.to_string() == j.token)
            && matches!(
                j.state.as_str(),
                PREPARED | COMMITTED | RR | "CANCELLED" | "APPLYING_BOOT_POLICY"
            )
            && name(&j.target.unit)
            && j.retired.len() <= 16
            && j.actions.len() <= 17
            && j.command_decisions.len() <= 64
            && j.command_decisions
                .iter()
                .all(|(id, h)| canonical_uuid(id) && hash(h))
            && j.issued_command
                .as_ref()
                .is_none_or(|b| b.valid() && b.operation == 17)
            && j.previous_confirmed_sha256.as_ref().is_none_or(|s| hash(s)),
        "CONFLICT: boot journal identity or shape"
    );
    Ok(())
}
fn pinned(p: &Path, h: &str) -> Result<Vec<u8>> {
    absolute(p)?;
    ensure!(hash(h), "INVALID_ARGUMENT: boot hash");
    let b = crate::controlled_startup::trusted_file(p, 256 << 20)?;
    ensure!(durable::hash(&b) == h, "CONFLICT: boot input changed");
    Ok(b)
}
// Only a simple native multi-user install contract is supported. No Alias/Also,
// runtime/generator/SysV entries or unreviewed install side effects are inferred.
fn install_contract(files: &[Vec<u8>], required: bool) -> Result<()> {
    let mut wanted = Vec::new();
    for file in files {
        let mut section = "";
        for line in std::str::from_utf8(file)?.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            ensure!(
                !line.ends_with('\\'),
                "FORBIDDEN: continued systemd boot declaration requires separate review"
            );
            if line.starts_with('[') && line.ends_with(']') {
                section = &line[1..line.len() - 1];
                continue;
            }
            if section == "Install" {
                let (k, v) = line
                    .split_once('=')
                    .context("INVALID_ARGUMENT: install declaration")?;
                ensure!(
                    k.trim() == "WantedBy",
                    "FORBIDDEN: only a native WantedBy boot entry is supported"
                );
                if v.trim().is_empty() {
                    wanted.clear();
                } else {
                    wanted.extend(v.split_whitespace().map(str::to_owned));
                }
            }
        }
    }
    ensure!(
        (wanted.is_empty() && !required) || wanted == ["multi-user.target"],
        "FORBIDDEN: exact multi-user boot install contract required"
    );
    Ok(())
}
impl Boot {
    pub fn new(root: PathBuf) -> Result<Self> {
        absolute(&root)?;
        Ok(Self {
            root,
            systemctl: PathBuf::from("/usr/bin/systemctl"),
            links_root: PathBuf::from("/etc/systemd/system"),
            policy_file: PathBuf::from("/etc/kura/ordinary-boot-policy.json"),
            core_lock: PathBuf::from("/run/lock/kura-ordinary-boot.lock"),
        })
    }
    fn state_dir(&self) -> PathBuf {
        self.root.join("ordinary-boot")
    }
    fn path(&self) -> PathBuf {
        self.state_dir().join("transaction.json")
    }
    fn registration(&self, create: bool) -> Result<()> {
        let body = json!({"schema":1,"stateRoot":self.root});
        match fs::symlink_metadata(&self.policy_file) {
            Ok(_) => ensure!(
                serde_json::from_slice::<Value>(&private(&self.policy_file, 4096)?)? == body,
                "CONFLICT: another state root owns the Core boot policy"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if create {
                    let parent = self
                        .policy_file
                        .parent()
                        .context("Core boot policy parent")?;
                    match fs::symlink_metadata(parent) {
                        Ok(m) => ensure!(
                            m.is_dir()
                                && m.uid() == unsafe { libc::geteuid() }
                                && m.mode() & 0o022 == 0,
                            "FORBIDDEN: unsafe Core boot policy directory"
                        ),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            use std::os::unix::fs::DirBuilderExt;
                            fs::DirBuilder::new().mode(0o755).create(parent)?;
                            durable::sync_directory(
                                parent.parent().context("Core policy ancestor")?,
                            )?;
                        }
                        Err(e) => return Err(e.into()),
                    }
                    durable::publish_new(
                        &self.policy_file,
                        &serde_json::to_vec(&body)?,
                        FileMetadata::private(),
                    )?;
                }
            }
            Err(e) => return Err(e.into()),
        };
        Ok(())
    }
    fn journal(&self) -> Result<Option<Journal>> {
        match fs::symlink_metadata(self.path()) {
            Ok(_) => {
                let j: Journal = serde_json::from_slice(&private(&self.path(), 1 << 20)?)?;
                journal_identity(&j)?;
                Ok(Some(j))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn persist(&self, j: &Journal) -> Result<()> {
        durable::directory(&self.state_dir())?;
        durable::json(&self.path(), j)
    }
    fn show(&self, unit: &str) -> Result<BTreeMap<String, String>> {
        ensure!(name(unit), "FORBIDDEN: native service name required");
        let args = ["show", unit, "--all", &format!("--property={FIELDS}")];
        let result = crate::process::run(&self.systemctl, &args, None, Duration::from_secs(5))?;
        ensure!(result.status.success(), "CONFLICT: boot unit unavailable");
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        for line in std::str::from_utf8(&result.stdout)?.lines() {
            let (k, v) = line.split_once('=').context("unit state format")?;
            ensure!(
                FIELDS.split(',').any(|s| s == k) && fields.insert(k.into(), v.into()).is_none(),
                "CONFLICT: ambiguous boot unit observation"
            );
        }
        ensure!(
            FIELDS.split(',').all(|k| fields.contains_key(k)),
            "CONFLICT: incomplete boot unit observation"
        );
        ensure!(
            fields["Id"] == unit
                && fields["Names"] == unit
                && fields["LoadState"] == "loaded"
                && fields["NeedDaemonReload"] == "no",
            "CONFLICT: unit identity, alias or reload drift"
        );
        for key in [
            "Requires",
            "Wants",
            "Requisite",
            "BindsTo",
            "PartOf",
            "After",
        ] {
            ensure!(
                !fields[key]
                    .split_whitespace()
                    .any(|s| s == "kura-management-agent.service"
                        || s.starts_with("kura-management-agent@")),
                "FORBIDDEN: Kura boot cannot depend on the management agent"
            );
        }
        Ok(fields)
    }
    fn unit(
        &self,
        unit: &str,
        file: &Path,
        files: Vec<Vec<u8>>,
        dropins: &[PathBuf],
        target: bool,
    ) -> Result<UnitState> {
        let f = self.show(unit)?;
        ensure!(
            f["FragmentPath"] == file.to_string_lossy(),
            "CONFLICT: boot fragment changed"
        );
        let actual = f["DropInPaths"]
            .split_whitespace()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        ensure!(
            actual == dropins,
            "CONFLICT: boot drop-in inventory changed"
        );
        install_contract(&files, target)?;
        let mode = &f["UnitFileState"];
        ensure!(
            matches!(mode.as_str(), "enabled" | "disabled") || (!target && mode == "static"),
            "FORBIDDEN: generated, indirect, runtime or masked boot entry"
        );
        let pid = f["MainPID"].parse::<u32>()?;
        ensure!(
            if target {
                f["ActiveState"] == "active" && pid > 0
            } else {
                f["ActiveState"] == "inactive" && pid == 0
            },
            "CONFLICT: target must run; retired services must be stopped"
        );
        for key in [
            "WantedBy",
            "RequiredBy",
            "BoundBy",
            "ConsistsOf",
            "TriggeredBy",
            "UpheldBy",
        ] {
            ensure!(
                f[key].is_empty()
                    || (key == "WantedBy" && f[key] == "multi-user.target" && mode == "enabled"),
                "FORBIDDEN: unreviewed activation path for boot service"
            );
        }
        Ok(UnitState {
            unit: unit.into(),
            unit_file: file.into(),
            enablement: mode.clone(),
            pid,
        })
    }
    fn observe(&self, r: &Request) -> Result<(UnitState, Vec<UnitState>)> {
        ensure!(
            r.schema == 1
                && hash(&r.ordinary_grant_sha256)
                && r.retire.len() <= 16
                && (60..=600).contains(&r.valid_for_seconds),
            "FORBIDDEN: boot request bounds"
        );
        let raw = private(&r.ordinary_profile, 256 << 10)?;
        ensure!(
            durable::hash(&raw) == r.ordinary_grant_sha256,
            "CONFLICT: reviewed ordinary grant changed"
        );
        let profile = crate::recovery::ordinary_boot_profile(&self.root,&r.ordinary_profile, &self.systemctl)?;
        ensure!(
            profile.grant_sha256 == r.ordinary_grant_sha256,
            "CONFLICT: ordinary grant changed during inspection"
        );
        let mut seen = BTreeSet::from([profile.unit.clone()]);
        let mut retired = Vec::new();
        let target_files = profile
            .install_files
            .iter()
            .map(|p| crate::controlled_startup::trusted_file(p, 256 << 10))
            .collect::<Result<Vec<_>>>()?;
        let target = self.unit(
            &profile.unit,
            &profile.unit_file,
            target_files,
            &profile.drop_ins,
            true,
        )?;
        for unit in &r.retire {
            ensure!(
                name(&unit.unit) && seen.insert(unit.unit.clone()) && unit.drop_ins.len() <= 32,
                "FORBIDDEN: duplicate boot retirement"
            );
            let mut files = vec![pinned(&unit.unit_file, &unit.unit_sha256)?];
            let mut paths = Vec::new();
            for p in &unit.drop_ins {
                files.push(pinned(&p.path, &p.sha256)?);
                paths.push(p.path.clone());
            }
            retired.push(self.unit(&unit.unit, &unit.unit_file, files, &paths, false)?);
        }
        Ok((target, retired))
    }
    fn receipt(&self, j: &Journal) -> Result<Vec<u8>> {
        let mut value = json!({"schema":"yofc.agent.ordinary-boot.v1","id":j.id,"request":j.request,"targetBefore":j.target,"retiredBefore":j.retired,"actionIntents":j.actions,"desiredTargetEnablement":"enabled","desiredRetiredEnablement":"disabled-or-static","status":COMMITTED,"scope":"administrator-reviewed-native-boot-entries","bootVerified":false,"kuraRecoveryVerified":false});
        if let Some(binding) = &j.issued_command {
            value["issuedCommand"] = serde_json::to_value(binding)?;
        }
        Ok(serde_json::to_vec(&value)?)
    }
    fn receipt_path(&self, j: &Journal) -> PathBuf {
        self.state_dir()
            .join("receipts")
            .join(format!("{}.json", j.id))
    }
    fn confirmed(&self) -> Result<Option<Journal>> {
        let path = self.state_dir().join("confirmed.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(_) => {
                let j: Journal = serde_json::from_slice(&private(&path, 1 << 20)?)?;
                journal_identity(&j)?;
                ensure!(
                    j.state == COMMITTED,
                    "CONFLICT: confirmed boot policy shape"
                );
                self.prove_receipt(&j)?;
                Ok(Some(j))
            }
        }
    }
    fn confirmed_hash(&self) -> Result<Option<String>> {
        let path = self.state_dir().join("confirmed.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
            Ok(_) => Ok(Some(durable::hash(&private(&path, 1 << 20)?))),
        }
    }
    fn prove_receipt(&self, j: &Journal) -> Result<()> {
        let bytes = private(&self.receipt_path(j), 1 << 20)?;
        ensure!(
            bytes == self.receipt(j)? && j.receipt_sha256.as_ref() == Some(&durable::hash(&bytes)),
            "CONFLICT: boot receipt changed"
        );
        Ok(())
    }
    fn status_value(j: &Journal) -> Value {
        json!({"id":j.id,"state":j.state,"targetUnit":j.target.unit,"retiredUnits":j.retired.iter().map(|u|&u.unit).collect::<Vec<_>>(),"actionIntents":j.actions,"scope":"administrator-reviewed-native-boot-entries","bootVerified":false,"kuraRecoveryVerified":false})
    }
    pub fn status(&self) -> Result<Value> {
        match self.journal()? {
            Some(j) => {
                let confirmed = self.confirmed()?;
                if j.state == COMMITTED {
                    self.prove_receipt(&j)?;
                    ensure!(
                        confirmed.as_ref().is_some_and(|c| same_policy(c, &j)),
                        "CONFLICT: confirmed boot policy changed"
                    );
                } else if j.state == "CANCELLED" {
                    ensure!(
                        j.actions.is_empty() && j.receipt_sha256.is_none(),
                        "CONFLICT: cancelled boot plan contains issued intent"
                    );
                }
                Ok(Self::status_value(&j))
            }
            None => {
                for name in ["receipts", "history", "commands"] {
                    let path = self.state_dir().join(name);
                    if path.try_exists()? {
                        ensure!(
                            fs::read_dir(path)?.next().is_none(),
                            "CONFLICT: boot journal missing with retained evidence"
                        );
                    }
                }
                ensure!(
                    !self.state_dir().join("confirmed.json").try_exists()?,
                    "CONFLICT: boot journal missing with confirmed policy"
                );
                Ok(json!({"state":"UNCONFIGURED","bootVerified":false}))
            }
        }
    }
    pub fn validate_request_file(path: &Path) -> Result<()> {
        absolute(path)?;
        let request: Request = serde_json::from_slice(&private(path, 256 << 10)?)?;
        ensure!(
            request.schema == 1 && (60..=600).contains(&request.valid_for_seconds),
            "INVALID_ARGUMENT: boot request schema/lifetime"
        );
        Ok(())
    }
    /// A coherent, token-free view separates the latest plan from the retained policy.
    pub fn view(&self) -> Result<Value> {
        let before = serde_json::to_value(self.journal()?)?;
        let confirmed_hash = self.confirmed_hash()?;
        let transaction = self.status()?;
        let confirmed = self.confirmed()?.as_ref().map(Self::status_value);
        ensure!(
            before == serde_json::to_value(self.journal()?)?
                && confirmed_hash == self.confirmed_hash()?,
            "CONFLICT: boot view changed during observation"
        );
        Ok(
            json!({"transaction":transaction,"confirmedPolicy":confirmed,"scope":"administrator-reviewed-native-boot-entries","bootVerified":false,"kuraRecoveryVerified":false}),
        )
    }
    pub fn prepare(&self, path: &Path) -> Result<Value> {
        self.prepare_bound(path, None)
    }
    pub(crate) fn prepare_bound(
        &self,
        path: &Path,
        binding: Option<&CommandBinding>,
    ) -> Result<Value> {
        let _core = Guard::native_boot_lock(&self.core_lock)?;
        let _guard = Guard::acquire(&self.root, Subsystem::OrdinaryBoot)?;
        self.registration(false)?;
        self.status()?;
        let old = self.journal()?;
        let confirmed = self.confirmed()?;
        if let Some(old) = &old {
            ensure!(
                matches!(old.state.as_str(), COMMITTED | "CANCELLED"),
                "CONFLICT: unresolved boot adoption; preserve state"
            );
            if old.state == COMMITTED {
                self.prove_receipt(old)?;
            }
        }
        let request: Request = serde_json::from_slice(&private(path, 256 << 10)?)?;
        let (target, retired) = self.observe(&request)?;
        if let Some(previous) = confirmed {
            let declared = retired
                .iter()
                .map(|u| u.unit.as_str())
                .collect::<BTreeSet<_>>();
            ensure!(
                previous
                    .retired
                    .iter()
                    .all(|u| declared.contains(u.unit.as_str()))
                    && (previous.target.unit == target.unit
                        || declared.contains(previous.target.unit.as_str())),
                "FORBIDDEN: prior boot entry retirements must remain explicit"
            );
        }
        let mut j = Journal {
            schema: 1,
            id: format!("boot-{}", uuid::Uuid::new_v4()),
            token: uuid::Uuid::new_v4().to_string(),
            state: PREPARED.into(),
            expires_at: now() + request.valid_for_seconds * 1000,
            request,
            target,
            retired,
            actions: vec![],
            receipt_sha256: None,
            previous_confirmed_sha256: self.confirmed_hash()?,
            command_decisions: BTreeMap::new(),
            issued_command: None,
        };
        if let Some(old) = old {
            let history = self.state_dir().join("history");
            durable::directory(&history)?;
            let path = history.join(format!("{}.json", old.id));
            let bytes = serde_json::to_vec(&old)?;
            if path.try_exists()? {
                ensure!(
                    private(&path, 1 << 20)? == bytes,
                    "CONFLICT: retained boot history changed"
                );
                fs::File::open(&path)?.sync_all()?;
                durable::sync_directory(&history)?;
            } else {
                durable::publish_new(&path, &bytes, FileMetadata::private())?;
            }
        }
        self.registration(true)?;
        let result = Self::prepare_value(&j);
        self.decide(&mut j, binding, result.clone())?;
        self.persist(&j)?;
        Ok(result)
    }
    fn prepare_value(j: &Journal) -> Value {
        let mut prepared = j.clone();
        prepared.state = PREPARED.into();
        prepared.actions.clear();
        let proposed = j
            .retired
            .iter()
            .filter(|u| u.enablement == "enabled")
            .map(|u| format!("disable {}", u.unit))
            .chain((j.target.enablement == "disabled").then(|| format!("enable {}", j.target.unit)))
            .collect::<Vec<_>>();
        json!({"plan":Self::status_value(&prepared),"targetBefore":j.target,"retiredBefore":j.retired,"proposedActions":proposed,"ordinaryGrantSha256":j.request.ordinary_grant_sha256,"confirmToken":j.token,"expiresAt":j.expires_at})
    }
    pub fn cancel(&self, id: &str, token: &str) -> Result<Value> {
        self.cancel_bound(id, token, None)
    }
    pub(crate) fn cancel_bound(
        &self,
        id: &str,
        token: &str,
        binding: Option<&CommandBinding>,
    ) -> Result<Value> {
        let _core = Guard::native_boot_lock(&self.core_lock)?;
        let _guard = Guard::acquire(&self.root, Subsystem::OrdinaryBoot)?;
        let mut j = self.journal()?.context("CONFLICT: boot plan missing")?;
        ensure!(
            j.id == id && j.token == token,
            "FORBIDDEN: boot identity/token"
        );
        ensure!(
            j.state == PREPARED && j.actions.is_empty(),
            "CONFLICT: issued boot adoption cannot be cancelled"
        );
        self.command_capacity(&j, binding)?;
        j.state = "CANCELLED".into();
        let result = Self::status_value(&j);
        self.decide(&mut j, binding, result)?;
        self.persist(&j)?;
        Ok(Self::status_value(&j))
    }
    fn command_capacity(&self, j: &Journal, binding: Option<&CommandBinding>) -> Result<()> {
        if let Some(b) = binding {
            ensure!(
                b.valid() && j.command_decisions.len() < 63,
                "CONFLICT: boot command evidence capacity"
            );
        }
        Ok(())
    }
    fn command_path(&self, id: &str) -> PathBuf {
        self.state_dir().join("commands").join(format!("{id}.json"))
    }
    fn decide(
        &self,
        j: &mut Journal,
        binding: Option<&CommandBinding>,
        result: Value,
    ) -> Result<()> {
        let Some(binding) = binding else {
            return Ok(());
        };
        let decision = CommandDecision {
            schema: 1,
            binding: binding.clone(),
            transaction_id: j.id.clone(),
            result,
        };
        let bytes = serde_json::to_vec(&decision)?;
        let path = self.command_path(&binding.command_id);
        durable::directory(path.parent().unwrap())?;
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                durable::publish_new(&path, &bytes, FileMetadata::private())?
            }
            Ok(_) => {
                ensure!(
                    private(&path, 1 << 20)? == bytes,
                    "CONFLICT: retained command decision changed"
                );
                fs::File::open(&path)?.sync_all()?;
                durable::sync_directory(path.parent().unwrap())?;
            }
            Err(e) => return Err(e.into()),
        }
        let digest = durable::hash(&bytes);
        if let Some(old) = j
            .command_decisions
            .insert(binding.command_id.clone(), digest.clone())
        {
            ensure!(old == digest, "CONFLICT: command decision changed");
        }
        ensure!(
            j.command_decisions.len() <= 64,
            "CONFLICT: boot command evidence capacity"
        );
        Ok(())
    }
    /// Authenticate a prior decision. No unit observation, command dispatch or journal mutation.
    pub(crate) fn prove_command(
        &self,
        command: &yofc_management_protocol::v1::ReadCommand,
    ) -> Result<Option<Value>> {
        let binding = CommandBinding::from_command(command)?;
        let path = self.command_path(&command.command_id);
        let bytes = match private(&path, 1 << 20) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        let d: CommandDecision = serde_json::from_slice(&bytes)?;
        ensure!(
            d.schema == 1 && d.binding == binding,
            "CONFLICT: command decision identity"
        );
        ensure!(
            d.transaction_id
                .strip_prefix("boot-")
                .is_some_and(canonical_uuid),
            "CONFLICT: boot decision transaction"
        );
        let current = self.journal()?;
        let jp = if current.as_ref().is_some_and(|j| j.id == d.transaction_id) {
            self.path()
        } else {
            self.state_dir()
                .join("history")
                .join(format!("{}.json", d.transaction_id))
        };
        let jb = match private(&jp, 1 << 20) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        let j: Journal = serde_json::from_slice(&jb)?;
        journal_identity(&j)?;
        let digest = durable::hash(&bytes);
        if j.id != d.transaction_id || j.command_decisions.get(&command.command_id) != Some(&digest)
        {
            return Ok(None);
        }
        let expected = match command.operation {
            16 => Self::prepare_value(&j),
            17 | 19 if j.state == COMMITTED => {
                self.prove_receipt(&j)?;
                if command.operation == 17 && j.issued_command.as_ref() != Some(&binding) {
                    return Ok(None);
                }
                Self::status_value(&j)
            }
            18 if j.state == "CANCELLED" && j.actions.is_empty() && j.receipt_sha256.is_none() => {
                Self::status_value(&j)
            }
            _ => return Ok(None),
        };
        if let Some(a) = &command.ordinary_boot_action
            && (a.transaction_id != j.id || a.confirmation_token != j.token)
        {
            return Ok(None);
        }
        ensure!(
            d.result == expected
                && private(&jp, 1 << 20)? == jb
                && private(&path, 1 << 20)? == bytes,
            "CONFLICT: changed boot decision evidence"
        );
        let mut result = d.result;
        result["reconciliation"] = json!({"source":"ordinary.boot.journal.v1","commandId":command.command_id,"operation":command.operation,"requestSha256":binding.request_sha256,"transactionId":j.id,"journalSha256":durable::hash(&jb),"decisionSha256":digest});
        Ok(Some(result))
    }
    fn desired(&self, j: &Journal) -> Result<()> {
        let (target, retired) = self.observe(&j.request)?;
        ensure!(
            target.unit == j.target.unit
                && target.pid == j.target.pid
                && target.enablement == "enabled",
            "CONFLICT: ordinary boot target unproven"
        );
        ensure!(
            retired
                .iter()
                .all(|u| u.enablement == "disabled" || u.enablement == "static"),
            "CONFLICT: old boot entries remain enabled"
        );
        Ok(())
    }
    fn commit(&self, j: &mut Journal, binding: Option<&CommandBinding>) -> Result<()> {
        self.registration(true)?;
        self.desired(j)?;
        // systemctl's reply is not a durability proof for the enablement links.
        // The supported install contract permits only these exact native links.
        let wants = self.links_root.join("multi-user.target.wants");
        let link = wants.join(&j.target.unit);
        ensure!(
            fs::symlink_metadata(&link)?.file_type().is_symlink(),
            "CONFLICT: boot link missing or not a symlink"
        );
        ensure!(
            link.canonicalize()? == j.target.unit_file.canonicalize()?,
            "CONFLICT: boot link target changed"
        );
        for old in &j.retired {
            ensure!(
                fs::symlink_metadata(wants.join(&old.unit))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "CONFLICT: retired native boot link remains"
            );
        }
        durable::sync_directory(&wants)?;
        durable::sync_directory(&self.links_root)?;
        self.desired(j)?;
        let receipt = self.receipt(j)?;
        let p = self.receipt_path(j);
        durable::directory(p.parent().context("boot receipt parent")?)?;
        match fs::symlink_metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                durable::publish_new(&p, &receipt, FileMetadata::private())?
            }
            Ok(_) => {
                ensure!(
                    private(&p, 1 << 20)? == receipt,
                    "CONFLICT: retained boot receipt mismatch"
                );
                fs::File::open(&p)?.sync_all()?;
                durable::sync_directory(p.parent().unwrap())?;
            }
            Err(e) => return Err(e.into()),
        };
        j.receipt_sha256 = Some(durable::hash(&receipt));
        j.state = COMMITTED.into();
        let result = Self::status_value(j);
        self.decide(j, j.issued_command.clone().as_ref(), result.clone())?;
        self.decide(j, binding, result)?;
        if self.confirmed_hash()? != j.previous_confirmed_sha256 {
            ensure!(
                self.confirmed()?
                    .as_ref()
                    .is_some_and(|current| same_policy(current, j)),
                "CONFLICT: confirmed boot policy changed; preserve both decisions"
            );
        }
        durable::json(&self.state_dir().join("confirmed.json"), j)?;
        self.persist(j)
    }
    pub fn execute(&self, id: &str, token: &str) -> Result<Value> {
        self.execute_bound(id, token, None)
    }
    pub(crate) fn execute_bound(
        &self,
        id: &str,
        token: &str,
        binding: Option<&CommandBinding>,
    ) -> Result<Value> {
        let _core = Guard::native_boot_lock(&self.core_lock)?;
        let _guard = Guard::acquire(&self.root, Subsystem::OrdinaryBoot)?;
        let mut j = self.journal()?.context("CONFLICT: boot plan missing")?;
        ensure!(
            j.id == id && j.token == token,
            "FORBIDDEN: boot identity/token"
        );
        ensure!(
            j.state == PREPARED && j.actions.is_empty() && now() < j.expires_at,
            "CONFLICT: boot plan expired or already attempted"
        );
        let (target, retired) = self.observe(&j.request)?;
        self.registration(true)?;
        ensure!(
            self.confirmed_hash()? == j.previous_confirmed_sha256,
            "CONFLICT: confirmed boot policy changed after preparation"
        );
        ensure!(
            serde_json::to_value((&target, &retired))?
                == serde_json::to_value((&j.target, &j.retired))?,
            "CONFLICT: boot preflight drift"
        );
        self.command_capacity(&j, binding)?;
        j.issued_command = binding.cloned();
        j.state = "APPLYING_BOOT_POLICY".into();
        self.persist(&j)?;
        let result: Result<()> = (|| {
            let mut changes = j
                .retired
                .iter()
                .filter(|u| u.enablement == "enabled")
                .map(|u| ("disable", u.unit.clone()))
                .collect::<Vec<_>>();
            if j.target.enablement == "disabled" {
                changes.push(("enable", j.target.unit.clone()));
            }
            for (action, unit) in changes {
                j.actions.push(format!("{action} {unit}"));
                self.persist(&j)?;
                let result = crate::process::run(
                    &self.systemctl,
                    &[action, &unit],
                    None,
                    Duration::from_secs(10),
                )?;
                ensure!(
                    result.status.success(),
                    "CONFLICT: boot action uncertain; reconcile without resending"
                );
            }
            self.commit(&mut j, None)
        })();
        if result.is_err() {
            j.state = RR.into();
            self.persist(&j)?;
            anyhow::bail!(
                "CONFLICT: boot policy unproven; preserve state and reconcile without replay"
            );
        }
        Ok(Self::status_value(&j))
    }
    pub fn reconcile(&self) -> Result<Value> {
        self.reconcile_bound(None)
    }
    pub(crate) fn reconcile_bound(&self, binding: Option<&CommandBinding>) -> Result<Value> {
        let _core = Guard::native_boot_lock(&self.core_lock)?;
        let _guard = Guard::acquire(&self.root, Subsystem::OrdinaryBoot)?;
        let mut j = self.journal()?.context("CONFLICT: boot plan missing")?;
        self.command_capacity(&j, binding)?;
        if j.state == COMMITTED {
            if self.status().is_err() {
                j.state = RR.into();
                self.persist(&j)?;
                anyhow::bail!("CONFLICT: boot receipt changed; preserve state");
            }
            let result = Self::status_value(&j);
            self.decide(&mut j, binding, result.clone())?;
            self.persist(&j)?;
            return Ok(result);
        }
        ensure!(
            matches!(j.state.as_str(), "APPLYING_BOOT_POLICY" | RR),
            "CONFLICT: no issued boot policy to reconcile"
        );
        if self.commit(&mut j, binding).is_err() {
            j.state = RR.into();
            self.persist(&j)?;
            anyhow::bail!(
                "CONFLICT: partial boot policy; no action repeated, preserve all evidence"
            );
        }
        Ok(Self::status_value(&j))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    struct Fixture {
        dir: PathBuf,
        boot: Boot,
        request: PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
    fn fixture() -> Fixture {
        let dir = std::env::temp_dir().join(format!("boot-adoption-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let unit = dir.join("ordinary.service");
        let old = dir.join("old.service");
        let body = "[Unit]\nDescription=Reviewed native Kura boot\n[Service]\nType=simple\nExecStart=/jdk/bin/java @ARGS -jar /launcher.jar\n[Install]\nWantedBy=multi-user.target\n";
        fs::write(&unit, body).unwrap();
        fs::write(&old, body).unwrap();
        let args = dir.join("ordinary.args");
        fs::write(&args,"-Dkura.management.ordinary.profile.id=profile-11111111-1111-1111-1111-111111111111\n-Dkura.management.ordinary.verification.enabled=true\n").unwrap();
        let mut definition = BTreeMap::from([
            ("FragmentPath".to_string(), unit.display().to_string()),
            ("DropInPaths".into(), "".into()),
            (
                "ExecStart".into(),
                format!(
                    "{{ path=/jdk/bin/java ; argv[]=/jdk/bin/java @{} -jar /launcher.jar",
                    args.display()
                ),
            ),
            ("Environment".into(), "".into()),
            ("EnvironmentFiles".into(), "".into()),
            (
                "UnsetEnvironment".into(),
                "JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS".into(),
            ),
            ("NeedDaemonReload".into(), "no".into()),
        ]);
        let digest = durable::hash(
            definition
                .iter()
                .map(|(k, v)| format!("{k}={v}\n"))
                .collect::<String>()
                .as_bytes(),
        );
        definition
            .get_mut("ExecStart")
            .unwrap()
            .push_str(" ; ignore_errors=no ; pid=0 }");
        let profile = dir.join("profile.json");
        durable::json(&profile,&json!({"schema":1,"profileId":"profile-11111111-1111-1111-1111-111111111111","unit":"ordinary.service","unitFile":unit,"jvmArgsPath":args,"unitDefinitionSha256":digest,"timeoutSeconds":2,"validForSeconds":300,"componentPids":["pid"],"checkIds":["business.check"],"profileFiles":[{"path":unit,"sha256":durable::hash(&fs::read(&unit).unwrap())},{"path":args,"sha256":durable::hash(&fs::read(&args).unwrap())}]})).unwrap();
        let request = dir.join("request.json");
        durable::json(&request,&json!({"schema":1,"ordinaryProfile":profile,"ordinaryGrantSha256":durable::hash(&fs::read(profile).unwrap()),"retire":[{"unit":"old.service","unitFile":old,"unitSha256":durable::hash(&fs::read(old).unwrap()),"dropIns":[]}],"validForSeconds":300})).unwrap();
        let links = dir.join("systemd");
        fs::create_dir(&links).unwrap();
        fs::create_dir(links.join("multi-user.target.wants")).unwrap();
        std::os::unix::fs::symlink(
            dir.join("old.service"),
            links.join("multi-user.target.wants/old.service"),
        )
        .unwrap();
        let db = dir.join("fake.json");
        durable::json(&db,&json!({"states":{"ordinary.service":"disabled","old.service":"enabled"},"definition":definition,"mode":"","pid":123})).unwrap();
        let script = dir.join("systemctl");
        let python = std::process::Command::new("python3")
            .args(["-c", "import sys;print(sys.executable)"])
            .output()
            .unwrap();
        let python = String::from_utf8(python.stdout).unwrap();
        let code=r#"
import json,sys,os
from pathlib import Path
root=Path(ROOT);db=root/'fake.json';v=json.loads(db.read_text());a=sys.argv[1:]
with (root/'calls').open('a') as f:f.write(' '.join(a)+'\n')
if a[0]=='show':
 unit=a[1];fields=next(x.split('=',1)[1] for x in a if x.startswith('--property=')).split(',')
 if 'ExecStart' in fields:
  for k in fields:print(k+'='+v['definition'].get(k,''))
 else:
  values={k:'' for k in fields};values.update(Id=unit,Names=unit,LoadState='loaded',ActiveState='active' if unit=='ordinary.service' else 'inactive',MainPID=str(v['pid']) if unit=='ordinary.service' else '0',UnitFileState=v['states'][unit],FragmentPath=str(root/unit),DropInPaths='',NeedDaemonReload='no',WantedBy='multi-user.target' if v['states'][unit]=='enabled' else '')
  values.update(v.get('override',{}))
  for k in fields:print(k+'='+values[k])
else:
 action,unit=a;assert action in ['disable','enable'];link=root/'systemd/multi-user.target.wants'/unit
 if v['mode']!='no-effect':
  v['states'][unit]='disabled' if action=='disable' else 'enabled'
  if action=='disable':link.unlink()
  else:link.symlink_to(root/unit)
 db.write_text(json.dumps(v))
 if v['mode']=='lose-after-'+action:sys.exit(1)
"#.replace("ROOT",&format!("{:?}",dir.to_str().unwrap()));
        fs::write(&script, format!("#!{}\n{}", python.trim(), code)).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let mut boot = Boot::new(dir.join("state")).unwrap();
        boot.systemctl = script;
        boot.links_root = links;
        boot.policy_file = dir.join("core-boot-policy.json");
        boot.core_lock = dir.join("core-boot.lock");
        Fixture { dir, boot, request }
    }
    fn mode(f: &Fixture, mode: &str) {
        let p = f.dir.join("fake.json");
        let mut v: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        v["mode"] = json!(mode);
        durable::json(&p, &v).unwrap();
    }
    fn actions(f: &Fixture) -> Vec<String> {
        fs::read_to_string(f.dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.starts_with("show "))
            .map(str::to_owned)
            .collect()
    }
    fn prepared(f: &Fixture) -> (String, String) {
        let p = f.boot.prepare(&f.request).unwrap();
        (
            p["plan"]["id"].as_str().unwrap().into(),
            p["confirmToken"].as_str().unwrap().into(),
        )
    }
    #[test]
    fn enablement_is_committed_once_without_start_stop_and_historical_proof_survives_later_shutdown()
     {
        let f = fixture();
        let (id, token) = prepared(&f);
        assert!(Guard::acquire(&f.boot.root, Subsystem::Configuration).is_err());
        let r = f.boot.execute(&id, &token).unwrap();
        assert_eq!(r["state"], COMMITTED);
        assert_eq!(r["bootVerified"], false);
        assert_eq!(
            actions(&f),
            ["disable old.service", "enable ordinary.service"]
        );
        assert!(Guard::acquire(&f.boot.root, Subsystem::Configuration).is_ok());
        let before = actions(&f);
        assert!(f.boot.execute(&id, &token).is_err());
        fs::write(f.dir.join("ordinary.service"), "legitimate later upgrade").unwrap();
        assert_eq!(f.boot.reconcile().unwrap()["state"], COMMITTED);
        assert_eq!(actions(&f), before);
    }
    #[test]
    fn lost_action_response_is_reconciled_by_observation_without_reissuing_any_command() {
        let f = fixture();
        mode(&f, "lose-after-enable");
        let (id, token) = prepared(&f);
        assert!(f.boot.execute(&id, &token).is_err());
        assert_eq!(f.boot.status().unwrap()["state"], RR);
        assert!(Guard::acquire(&f.boot.root, Subsystem::Recovery).is_err());
        let before = actions(&f);
        assert_eq!(f.boot.reconcile().unwrap()["state"], COMMITTED);
        assert_eq!(actions(&f), before);
    }
    #[test]
    fn partial_disable_and_unproven_positive_reply_preserve_rr_and_block_every_writer() {
        for m in ["lose-after-disable", "no-effect"] {
            let f = fixture();
            mode(&f, m);
            let (id, token) = prepared(&f);
            assert!(f.boot.execute(&id, &token).is_err());
            let before = actions(&f);
            assert!(f.boot.reconcile().is_err());
            assert!(f.boot.execute(&id, &token).is_err());
            assert!(f.boot.cancel(&id, &token).is_err());
            assert_eq!(actions(&f), before);
            for subsystem in [
                Subsystem::Configuration,
                Subsystem::Network,
                Subsystem::Firewall,
                Subsystem::Recovery,
                Subsystem::Identity,
            ] {
                assert!(Guard::acquire(&f.boot.root, subsystem).is_err());
            }
        }
    }
    #[test]
    fn invalid_metadata_plan_drift_expiry_and_wrong_tokens_never_issue_actions() {
        for m in [
            "alias",
            "generator",
            "dependency",
            "activation",
            "grant",
            "pid",
            "expired",
            "token",
        ] {
            let f = fixture();
            let (id, token) = prepared(&f);
            let p = f.dir.join("fake.json");
            let mut v: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
            match m {
                "alias" => v["override"] = json!({"Names":"ordinary.service alias.service"}),
                "generator" => v["override"] = json!({"UnitFileState":"generated"}),
                "dependency" => v["override"] = json!({"Requires":"kura-management-agent.service"}),
                "activation" => v["override"] = json!({"TriggeredBy":"old.timer"}),
                "grant" => {
                    fs::write(f.dir.join("ordinary.args"), "changed").unwrap();
                }
                "pid" => v["pid"] = json!(456),
                "expired" => {
                    let mut j = f.boot.journal().unwrap().unwrap();
                    j.expires_at = 0;
                    f.boot.persist(&j).unwrap();
                }
                _ => {}
            };
            durable::json(&p, &v).unwrap();
            assert!(
                f.boot
                    .execute(&id, if m == "token" { "wrong" } else { &token })
                    .is_err(),
                "{m}"
            );
            assert!(actions(&f).is_empty(), "{m}");
        }
    }
    #[test]
    fn prepared_plan_can_be_cancelled_and_unknown_install_side_effects_are_rejected() {
        let f = fixture();
        let (id, token) = prepared(&f);
        assert_eq!(f.boot.cancel(&id, &token).unwrap()["state"], "CANCELLED");
        assert!(Guard::acquire(&f.boot.root, Subsystem::Configuration).is_ok());
        for text in [
            "[Install]\nAlias=another.service\n",
            "[Install]\nWantedBy=multi-user.target\nAlso=other.service\n",
            "[Install]\nWantedBy=graphical.target\n",
        ] {
            assert!(install_contract(&[text.as_bytes().to_vec()], true).is_err());
        }
    }
    #[test]
    fn cancelled_followup_preserves_confirmed_policy_and_receipt_tamper_blocks_admission() {
        let f = fixture();
        let (id, token) = prepared(&f);
        f.boot.execute(&id, &token).unwrap();
        let anchor = fs::read(f.boot.state_dir().join("confirmed.json")).unwrap();
        let (id2, token2) = prepared(&f);
        assert_ne!(id, id2);
        f.boot.cancel(&id2, &token2).unwrap();
        assert_eq!(
            fs::read(f.boot.state_dir().join("confirmed.json")).unwrap(),
            anchor
        );
        assert!(Guard::acquire(&f.boot.root, Subsystem::Configuration).is_ok());
        let previous: Journal = serde_json::from_slice(&anchor).unwrap();
        let receipt = f.boot.receipt_path(&previous);
        let mut bytes = fs::read(&receipt).unwrap();
        bytes.push(b' ');
        fs::write(receipt, bytes).unwrap();
        assert!(f.boot.status().is_err());
        assert!(Guard::acquire(&f.boot.root, Subsystem::Configuration).is_err());
    }
    #[test]
    fn prior_retirements_cannot_be_dropped_and_missing_journal_never_discards_policy() {
        let f = fixture();
        let (id, token) = prepared(&f);
        f.boot.execute(&id, &token).unwrap();
        let mut request: Value = serde_json::from_slice(&fs::read(&f.request).unwrap()).unwrap();
        request["retire"] = json!([]);
        durable::json(&f.request, &request).unwrap();
        assert!(f.boot.prepare(&f.request).is_err());
        fs::rename(f.boot.path(), f.boot.path().with_extension("retained")).unwrap();
        assert!(f.boot.status().is_err());
        assert!(Guard::acquire(&f.boot.root, Subsystem::Recovery).is_err());
        assert!(f.boot.prepare(&f.request).is_err());
    }
    #[test]
    fn recovery_required_blocks_preparation_before_any_unit_action_or_registration() {
        let f = fixture();
        durable::directory(&f.boot.root.join("recovery")).unwrap();
        durable::json(
            &f.boot.root.join("recovery/transaction.json"),
            &json!({"state":"RECOVERY_REQUIRED"}),
        )
        .unwrap();
        assert!(f.boot.prepare(&f.request).is_err());
        assert!(actions(&f).is_empty());
        assert!(!f.boot.policy_file.exists());
        assert!(!f.boot.path().exists());
    }
    #[tokio::test]
    async fn center_boot_tasks_pin_authority_preserve_policy_and_never_replay_receipts() {
        use yofc_management_protocol::v1::*;
        let f = fixture();
        let db = crate::transport::database(f.dir.join("executions.db").to_str().unwrap())
            .await
            .unwrap();
        let mut local = crate::local::Local::new(1001, unsafe { libc::geteuid() });
        local.ordinary_boot = Some(crate::boot_control::Control::fixture(
            f.boot.clone(),
            f.request.clone(),
            db.clone(),
        ));
        let command = |op, action| ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: op,
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            expires_at_unix_ms: (now() + 60000) as i64,
            ordinary_boot_action: action,
            ..Default::default()
        };
        let prepared = crate::transport::execute(&db, &local, command(16, None))
            .await
            .unwrap();
        assert_eq!(prepared.state, TaskState::Succeeded as i32);
        let plan: Value = serde_json::from_slice(&prepared.result_json).unwrap();
        let action = OrdinaryBootAction {
            transaction_id: plan["plan"]["id"].as_str().unwrap().into(),
            confirmation_token: plan["confirmToken"].as_str().unwrap().into(),
        };
        let exec = command(17, Some(action));
        let result = crate::transport::execute(&db, &local, exec.clone())
            .await
            .unwrap();
        assert_eq!(result.state, TaskState::Succeeded as i32);
        assert_eq!(actions(&f).len(), 2);
        assert_eq!(
            crate::transport::execute(&db, &local, exec.clone())
                .await
                .unwrap(),
            result
        );
        assert_eq!(
            crate::transport::query_receipt(&db, &local, &exec.command_id)
                .await
                .unwrap(),
            result
        );
        assert_eq!(actions(&f).len(), 2);
        let follow = crate::transport::execute(&db, &local, command(16, None))
            .await
            .unwrap();
        let follow: Value = serde_json::from_slice(&follow.result_json).unwrap();
        let action = OrdinaryBootAction {
            transaction_id: follow["plan"]["id"].as_str().unwrap().into(),
            confirmation_token: follow["confirmToken"].as_str().unwrap().into(),
        };
        let cancelled = crate::transport::execute(&db, &local, command(18, Some(action)))
            .await
            .unwrap();
        assert_eq!(cancelled.state, TaskState::Succeeded as i32);
        let status = crate::transport::execute(&db, &local, command(15, None))
            .await
            .unwrap();
        let view: Value = serde_json::from_slice(&status.result_json).unwrap();
        assert_eq!(view["transaction"]["state"], "CANCELLED");
        assert_eq!(view["confirmedPolicy"]["state"], COMMITTED);
        assert!(
            !view
                .to_string()
                .contains(plan["confirmToken"].as_str().unwrap())
        );
        assert_eq!(actions(&f).len(), 2);
        let control = local.ordinary_boot.as_ref().unwrap();
        assert!(
            control
                .request(
                    "ordinary.boot.prepare",
                    json!({"unit":"evil.service"}),
                    None
                )
                .await
                .is_err()
        );
        db.close().await;
    }
    #[tokio::test]
    async fn center_lost_boot_response_is_unknown_and_fresh_writes_do_not_repeat_it() {
        use yofc_management_protocol::v1::*;
        let f = fixture();
        let db = crate::transport::database(f.dir.join("executions.db").to_str().unwrap())
            .await
            .unwrap();
        let mut local = crate::local::Local::new(1001, unsafe { libc::geteuid() });
        local.ordinary_boot = Some(crate::boot_control::Control::fixture(
            f.boot.clone(),
            f.request.clone(),
            db.clone(),
        ));
        let command = |op, action| ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: op,
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            expires_at_unix_ms: (now() + 60000) as i64,
            ordinary_boot_action: action,
            ..Default::default()
        };
        let p = crate::transport::execute(&db, &local, command(16, None))
            .await
            .unwrap();
        let p: Value = serde_json::from_slice(&p.result_json).unwrap();
        mode(&f, "lose-after-disable");
        let execute = command(
            17,
            Some(OrdinaryBootAction {
                transaction_id: p["plan"]["id"].as_str().unwrap().into(),
                confirmation_token: p["confirmToken"].as_str().unwrap().into(),
            }),
        );
        let unknown = crate::transport::execute(&db, &local, execute.clone())
            .await
            .unwrap();
        assert_eq!(unknown.state, TaskState::Unknown as i32);
        assert_eq!(unknown.error, ErrorCode::OutcomeUnknown as i32);
        let before = actions(&f);
        assert_eq!(
            crate::transport::query_receipt(&db, &local, &execute.command_id)
                .await
                .unwrap(),
            unknown
        );
        assert_eq!(
            crate::transport::execute(&db, &local, execute)
                .await
                .unwrap(),
            unknown
        );
        let new = crate::transport::execute(&db, &local, command(16, None))
            .await
            .unwrap();
        assert_eq!(new.state, TaskState::Failed as i32);
        assert_eq!(new.error, ErrorCode::Conflict as i32);
        assert_eq!(actions(&f), before);
        assert_eq!(f.boot.status().unwrap()["state"], RR);
        db.close().await;
    }
    async fn outcome_local(f: &Fixture) -> (sqlx::SqlitePool, crate::local::Local) {
        let db = crate::transport::database(f.dir.join("outcome.db").to_str().unwrap())
            .await
            .unwrap();
        let mut local = crate::local::Local::new(1001, unsafe { libc::geteuid() });
        local.ordinary_boot = Some(crate::boot_control::Control::fixture(
            f.boot.clone(),
            f.request.clone(),
            db.clone(),
        ));
        (db, local)
    }
    fn outcome_command(op: i32, plan: Option<&Value>) -> yofc_management_protocol::v1::ReadCommand {
        use yofc_management_protocol::v1::*;
        ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation: op,
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            expires_at_unix_ms: (now() + 60000) as i64,
            ordinary_boot_action: plan.map(|v| OrdinaryBootAction {
                transaction_id: v["plan"]["id"].as_str().unwrap().into(),
                confirmation_token: v["confirmToken"].as_str().unwrap().into(),
            }),
            ..Default::default()
        }
    }
    async fn public_prepare(db: &sqlx::SqlitePool, local: &crate::local::Local) -> Value {
        let r = crate::transport::execute(db, local, outcome_command(16, None))
            .await
            .unwrap();
        assert_eq!(
            r.state,
            yofc_management_protocol::v1::TaskState::Succeeded as i32
        );
        serde_json::from_slice(&r.result_json).unwrap()
    }
    fn exit_after_domain(
        f: &Fixture,
        command: &yofc_management_protocol::v1::ReadCommand,
    ) -> Value {
        use prost::Message;
        let dir = f.dir.join(&command.command_id);
        durable::directory(&dir).unwrap();
        durable::write(
            &dir.join("command.bin"),
            &command.encode_to_vec(),
            FileMetadata::private(),
        )
        .unwrap();
        durable::json(&dir.join("fixture.json"), &json!({"root":f.boot.root,"systemctl":f.boot.systemctl,"links":f.boot.links_root,"policy":f.boot.policy_file,"lock":f.boot.core_lock,"request":f.request,"db":f.dir.join("outcome.db")})).unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ordinary_boot::tests::domain_decision_process_exit_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("YOFC_BOOT_OUTCOME_EXIT_FIXTURE", &dir)
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(91),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice(&private(&dir.join("public-response.json"), 1 << 20).unwrap())
            .unwrap()
    }
    #[test]
    #[ignore = "explicit fresh process-loss fixture; never a production fault switch"]
    fn domain_decision_process_exit_fixture() {
        use prost::Message;
        let dir = PathBuf::from(
            std::env::var("YOFC_BOOT_OUTCOME_EXIT_FIXTURE").expect("explicit fixture required"),
        );
        let v: Value =
            serde_json::from_slice(&private(&dir.join("fixture.json"), 1 << 20).unwrap()).unwrap();
        let command = yofc_management_protocol::v1::ReadCommand::decode(
            private(&dir.join("command.bin"), 1 << 20)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let db = crate::transport::database(v["db"].as_str().unwrap())
                .await
                .unwrap();
            let mut boot = Boot::new(PathBuf::from(v["root"].as_str().unwrap())).unwrap();
            boot.systemctl = v["systemctl"].as_str().unwrap().into();
            boot.links_root = v["links"].as_str().unwrap().into();
            boot.policy_file = v["policy"].as_str().unwrap().into();
            boot.core_lock = v["lock"].as_str().unwrap().into();
            let control = crate::boot_control::Control::fixture(
                boot,
                v["request"].as_str().unwrap().into(),
                db.clone(),
            );
            let h = durable::hash(&command.encode_to_vec());
            assert!(
                crate::journal::claim(&db, &command, &h)
                    .await
                    .unwrap()
                    .is_none()
            );
            let method = match command.operation {
                16 => "ordinary.boot.prepare",
                17 => "ordinary.boot.execute",
                18 => "ordinary.boot.cancel",
                19 => "ordinary.boot.reconcile",
                _ => panic!("mutation only"),
            };
            let params = command
                .ordinary_boot_action
                .as_ref()
                .map(|a| serde_json::to_value(a).unwrap())
                .unwrap_or(Value::Null);
            let result = control.request(method, params, Some(&command)).await;
            let value =
                result.unwrap_or_else(|e| json!({"error":crate::boot_control::error_code(&e)}));
            durable::json(&dir.join("public-response.json"), &value).unwrap();
            // The actual process exits with a RUNNING encrypted admission and no execution receipt.
            std::process::exit(91);
        });
    }
    #[tokio::test]
    async fn all_four_boot_decisions_survive_process_exit_before_execution_receipt_without_any_replay()
     {
        use yofc_management_protocol::v1::TaskState;
        for op in 16..=19 {
            let f = fixture();
            let (db, local) = outcome_local(&f).await;
            let plan = if op != 16 {
                Some(public_prepare(&db, &local).await)
            } else {
                None
            };
            if op == 19 {
                crate::transport::execute(&db, &local, outcome_command(17, plan.as_ref()))
                    .await
                    .unwrap();
            }
            let command = outcome_command(
                op,
                if matches!(op, 17 | 18) {
                    plan.as_ref()
                } else {
                    None
                },
            );
            db.close().await;
            let expected = exit_after_domain(&f, &command);
            assert!(expected.get("error").is_none(), "{expected}");
            let (db, local) = outcome_local(&f).await;
            assert_eq!(
                crate::journal::receipt(&db, &command.command_id)
                    .await
                    .unwrap()
                    .state,
                TaskState::Unknown as i32
            );
            let calls = fs::read(f.dir.join("calls")).unwrap();
            let (a, b) = tokio::join!(
                crate::transport::query_receipt(&db, &local, &command.command_id),
                crate::transport::query_receipt(&db, &local, &command.command_id)
            );
            let a = a.unwrap();
            assert_eq!(a, b.unwrap());
            assert_eq!(a.state, TaskState::Succeeded as i32);
            let mut found: Value = serde_json::from_slice(&a.result_json).unwrap();
            assert_eq!(
                found["reconciliation"]["source"],
                "ordinary.boot.journal.v1"
            );
            assert_eq!(found["reconciliation"]["commandId"], command.command_id);
            found.as_object_mut().unwrap().remove("reconciliation");
            assert_eq!(found, expected);
            assert_eq!(
                crate::transport::execute(&db, &local, command.clone())
                    .await
                    .unwrap(),
                a
            );
            assert_eq!(
                calls,
                fs::read(f.dir.join("calls")).unwrap(),
                "a proof query/replay must not even observe live units"
            );
            let count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM execution_resolutions WHERE command_id=?")
                    .bind(&command.command_id)
                    .fetch_one(&db)
                    .await
                    .unwrap();
            assert_eq!(count, 1);
            assert!(f.boot.view().is_ok());
            db.close().await;
        }
    }
    #[tokio::test]
    async fn partial_boot_remains_unknown_until_explicit_read_only_policy_reconcile_then_original_command_is_proved()
     {
        use yofc_management_protocol::v1::TaskState;
        let f = fixture();
        let (db, local) = outcome_local(&f).await;
        let plan = public_prepare(&db, &local).await;
        let command = outcome_command(17, Some(&plan));
        db.close().await;
        mode(&f, "lose-after-enable");
        let result = exit_after_domain(&f, &command);
        assert_eq!(result["error"], "OUTCOME_UNKNOWN");
        let (db, local) = outcome_local(&f).await;
        let calls = fs::read(f.dir.join("calls")).unwrap();
        for _ in 0..2 {
            assert_eq!(
                crate::transport::query_receipt(&db, &local, &command.command_id)
                    .await
                    .unwrap()
                    .state,
                TaskState::Unknown as i32
            );
        }
        assert_eq!(calls, fs::read(f.dir.join("calls")).unwrap());
        assert_eq!(f.boot.status().unwrap()["state"], RR);
        let reconciled = crate::transport::execute(&db, &local, outcome_command(19, None))
            .await
            .unwrap();
        assert_eq!(reconciled.state, TaskState::Succeeded as i32);
        assert_eq!(
            crate::transport::query_receipt(&db, &local, &command.command_id)
                .await
                .unwrap()
                .state,
            TaskState::Succeeded as i32
        );
        assert_eq!(actions(&f).len(), 2);
        db.close().await;
    }
    #[tokio::test]
    async fn missing_legacy_unlinked_changed_and_cross_command_evidence_cannot_become_success_from_enablement()
     {
        use prost::Message;
        use yofc_management_protocol::v1::TaskState;
        let f = fixture();
        let (db, local) = outcome_local(&f).await;
        let plan = public_prepare(&db, &local).await;
        let command = outcome_command(17, Some(&plan));
        db.close().await;
        exit_after_domain(&f, &command);
        let (db, local) = outcome_local(&f).await;
        let path = f.boot.command_path(&command.command_id);
        let bytes = fs::read(&path).unwrap();
        let jp = f.boot.path();
        let original = fs::read(&jp).unwrap();
        let calls = fs::read(f.dir.join("calls")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            crate::transport::query_receipt(&db, &local, &command.command_id)
                .await
                .unwrap()
                .state,
            TaskState::Unknown as i32
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"{}").unwrap();
        assert_eq!(
            crate::transport::query_receipt(&db, &local, &command.command_id)
                .await
                .unwrap()
                .state,
            TaskState::Unknown as i32
        );
        fs::write(&path, &bytes).unwrap();
        let mut j: Value = serde_json::from_slice(&original).unwrap();
        j.as_object_mut().unwrap().remove("commandDecisions");
        durable::json(&jp, &j).unwrap();
        assert_eq!(
            crate::transport::query_receipt(&db, &local, &command.command_id)
                .await
                .unwrap()
                .state,
            TaskState::Unknown as i32
        );
        fs::write(&jp, &original).unwrap();
        let mut other = command.clone();
        other.command_id = uuid::Uuid::new_v4().to_string();
        let h = durable::hash(&other.encode_to_vec());
        crate::journal::claim(&db, &other, &h).await.unwrap();
        crate::journal::finish(&db, &h, crate::journal::unknown(&other.command_id, "TEST"))
            .await
            .unwrap();
        durable::write(
            &f.boot.command_path(&other.command_id),
            &bytes,
            FileMetadata::private(),
        )
        .unwrap();
        assert_eq!(
            crate::transport::query_receipt(&db, &local, &other.command_id)
                .await
                .unwrap()
                .state,
            TaskState::Unknown as i32
        );
        // A later local plan archives the native evidence. This read does not depend on live enablement/PID.
        let next = f.boot.prepare(&f.request).unwrap();
        f.boot
            .cancel(
                next["plan"]["id"].as_str().unwrap(),
                next["confirmToken"].as_str().unwrap(),
            )
            .unwrap();
        mode(&f, "no-effect");
        let calls_after = fs::read(f.dir.join("calls")).unwrap();
        assert!(calls_after.len() > calls.len());
        assert_eq!(
            crate::transport::query_receipt(&db, &local, &command.command_id)
                .await
                .unwrap()
                .state,
            TaskState::Succeeded as i32
        );
        assert_eq!(calls_after, fs::read(f.dir.join("calls")).unwrap());
        db.close().await;
    }
}
