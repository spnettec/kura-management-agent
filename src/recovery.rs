//! Explicit local artifact placement and compensation. This module does not
//! claim to validate Kura XML/crypto or application recovery; those remain a
//! separate format adapter. State changes are durable, serialized and bounded.
mod completion;
#[cfg(test)]
mod completion_tests;
mod health;
mod forward_normal;
#[cfg(test)]
mod forward_normal_tests;
#[cfg(test)]
mod forward_native_tests;
#[cfg(test)]
mod nonidempotent_native_tests;
mod normal_boot;
mod ordinary;
pub(crate) mod ordinary_profile;
#[cfg(test)]
mod ordinary_tests;
mod snapshot_set;
mod source;
pub(crate) use ordinary::outcome::has_evidence as ordinary_command_evidence;
pub(crate) use ordinary::validate_cancelled_retained as validate_cancelled_handoff;

use crate::{
    durable::{self, FileMetadata},
    system_change::{Guard, Subsystem},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Component, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
pub fn seal_ordinary_profile(request: PathBuf, output: PathBuf) -> Result<Value> {
    ordinary_profile::seal(request, output, std::path::Path::new("/usr/bin/systemctl"))
}
pub(crate) struct BootProfile {
    pub grant_sha256: String,
    pub unit: String,
    pub unit_file: PathBuf,
    pub install_files: Vec<PathBuf>,
    pub drop_ins: Vec<PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ControlProfile {
    pub unit: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub component_pids: Vec<String>,
    pub check_ids: Vec<String>,
}
pub(crate) fn ordinary_control_profile(
    path: &std::path::Path,
    systemctl: &std::path::Path,
) -> Result<ControlProfile> {
    ordinary_control_material(ordinary_profile::Profile::new(path.into())?.inspect()?,systemctl)
}
pub(crate) fn ordinary_control_material(material:ordinary_profile::Material,systemctl:&std::path::Path)->Result<ControlProfile> {
    let c=material.config;let digest=material.digest;
    let output = crate::process::run(
        systemctl,
        &[
            "show",
            &c.unit,
            "--all",
            &format!("--property={}", ordinary_profile::UNIT_FIELDS),
        ],
        None,
        Duration::from_secs(5),
    )?;
    ensure!(
        output.status.success(),
        "CONFLICT: fixed ordinary profile unavailable"
    );
    ordinary_profile::Profile::declaration(&c, &String::from_utf8(output.stdout)?)?;
    Ok(ControlProfile {
        unit: c.unit,
        profile_id: c.profile_id,
        profile_digest: digest,
        component_pids: c.component_pids,
        check_ids: c.check_ids,
    })
}
pub(crate) fn ordinary_boot_profile(
    state_root:&std::path::Path,
    path: &std::path::Path,
    systemctl: &std::path::Path,
) -> Result<BootProfile> {
    let material=ordinary_profile::Profile::runtime(path.into(),state_root.into())?.inspect()?;
    let config=material.config;
    let output = crate::process::run(
        systemctl,
        &[
            "show",
            &config.unit,
            "--all",
            &format!("--property={}", ordinary_profile::UNIT_FIELDS),
        ],
        None,
        Duration::from_secs(5),
    )?;
    ensure!(
        output.status.success(),
        "CONFLICT: ordinary boot profile inspection failed"
    );
    let definition = String::from_utf8(output.stdout)?;
    ordinary_profile::Profile::declaration(&config, &definition)?;
    let drop_ins = definition
        .lines()
        .find_map(|line| line.strip_prefix("DropInPaths="))
        .context("ordinary drop-ins")?
        .split_whitespace()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let mut install_files = vec![config.unit_file.clone()];
    install_files.extend(drop_ins.clone());
    Ok(BootProfile {
        // Boot-entry authority remains the immutable source grant. The exact
        // receipt-bound transformation changes neither unit nor install files;
        // current selected arguments are nevertheless fully checked above.
        grant_sha256: material.origin_sha256,
        unit: config.unit,
        unit_file: config.unit_file,
        install_files,
        drop_ins,
    })
}
const LIMIT_BYTES: u64 = 32 << 20;
const LIMIT_TOTAL: u64 = 64 << 20;
const LIMIT_FILES: usize = 128;
#[derive(Clone)]
pub struct Recovery(Arc<Engine>);
struct Engine {
    root: PathBuf,
    state: PathBuf,
    state_root: PathBuf,
    execution_db: PathBuf,
    systemctl: PathBuf,
    validator: Option<crate::snapshot_validation::Validator>,
    startup: Option<crate::controlled_startup::Startup>,
    inverse_startup: Option<crate::controlled_startup::Startup>,
    normal_startup: Option<crate::controlled_startup::Startup>,
    forward_normal: Option<forward_normal::Profile>,
    normal_validator: Option<crate::snapshot_validation::Validator>,
    health: Option<health::Profile>,
    completion: Option<completion::Profile>,
    ordinary: Option<ordinary_profile::Profile>,
    ordinary_validator: Option<crate::snapshot_validation::Validator>,
    units: Vec<String>,
    snapshots: PathBuf,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum State {
    Validated,
    Stopping,
    BackedUp,
    Committing,
    Starting,
    Verifying,
    AwaitingCompletion,
    CompensationPrepared,
    AwaitingCompensationCompletion,
    SnapshotSetPrepared,
    RestoringSnapshotSet,
    AwaitingSnapshotCompletion,
    NormalBootPrepared,
    StartingNormalBoot,
    AwaitingNormalBootCompletion,
    HealthPrepared,
    VerifyingHealth,
    AwaitingHealthCompletion,
    CompletionPrepared,
    CommittingCompletion,
    CompletedApprovedChecks,
    OrdinaryPrepared,
    CancellingOrdinary,
    OrdinaryCancelled,
    StoppingOrdinary,
    StartingOrdinary,
    VerifyingOrdinary,
    OrdinaryActiveApprovedChecks,
    Succeeded,
    Compensating,
    Failed,
    RecoveryRequired,
}
impl State {
    fn settled(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::CompletedApprovedChecks
                | Self::OrdinaryActiveApprovedChecks
                | Self::OrdinaryCancelled
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SnapshotFile {
    name: String,
    size: u64,
    sha256: String,
    metadata: FileMetadata,
}
#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    #[serde(default)]
    schema_version: u32,
    id: String,
    state: State,
    upload_id: String,
    sha256: String,
    size: u64,
    unit: String,
    target: String,
    backup_dir: String,
    confirm_token: String,
    started_at: u64,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    base: Vec<SnapshotFile>,
    #[serde(default)]
    backup_ready: bool,
    #[serde(default)]
    was_active: bool,
    #[serde(default)]
    target_metadata: Option<FileMetadata>,
    #[serde(default)]
    snapshot_validation: Option<crate::snapshot_validation::Proof>,
    #[serde(default)]
    controlled_startup: Option<crate::controlled_startup::Prepared>,
    #[serde(default)]
    controlled_issued: bool,
    #[serde(default)]
    cm_application: Option<crate::controlled_startup::Application>,
    #[serde(default)]
    inverse: Option<Inverse>,
    #[serde(default)]
    normal_boot: Option<normal_boot::Plan>,
    #[serde(default)]
    health: Option<health::Plan>,
    #[serde(default)]
    completion: Option<completion::Plan>,
    #[serde(default)]
    ordinary: Option<ordinary::Plan>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Inverse {
    id: String,
    confirm_token: String,
    unit: String,
    target: String,
    sha256: String,
    base: Vec<SnapshotFile>,
    startup: crate::controlled_startup::Prepared,
    parameters: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_application: Option<crate::controlled_startup::Application>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_partial: Option<crate::controlled_startup::PartialApplication>,
    source_journal_sha256: String,
    issued: bool,
    application: Option<crate::controlled_startup::Application>,
    #[serde(default)]
    snapshot_set: Option<snapshot_set::Plan>,
}
#[derive(Serialize, Deserialize)]
struct Manifest {
    schema_version: u32,
    files: Vec<SnapshotFile>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}
impl Recovery {
    pub fn open(
        root: PathBuf,
        state_root: PathBuf,
        units: Vec<String>,
        snapshots: PathBuf,
        systemctl: Option<PathBuf>,
    ) -> Result<Self> {
        for unit in &units {
            ensure!(
                safe_name(unit) && unit.ends_with(".service"),
                "INVALID_ARGUMENT: recoverable unit"
            );
        }
        ensure!(
            snapshots
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
            "INVALID_ARGUMENT: snapshot path"
        );
        durable::directory(&state_root)?;
        let state = state_root.join("recovery");
        durable::directory(&state)?;
        for name in ["staging", "backups", "receipts"] {
            durable::directory(&state.join(name))?;
        }
        let execution_db = state_root.join("results.sqlite");
        Ok(Self(Arc::new(Engine {
            validator: None,
            startup: None,
            inverse_startup: None,
            normal_startup: None,
            forward_normal: None,
            normal_validator: None,
            health: None,
            completion: None,
            ordinary: None,
            ordinary_validator: None,
            root,
            state_root,
            state,
            execution_db,
            units,
            snapshots,
            systemctl: systemctl.unwrap_or_else(|| "/usr/bin/systemctl".into()),
        })))
    }
    pub fn with_snapshot_validator(
        mut self,
        validator: crate::snapshot_validation::Validator,
    ) -> Self {
        Arc::get_mut(&mut self.0)
            .expect("configure before sharing recovery")
            .validator = Some(validator);
        self
    }
    pub fn with_controlled_startup(
        mut self,
        startup: crate::controlled_startup::Startup,
    ) -> Result<Self> {
        ensure!(
            self.0.validator.is_some(),
            "FORBIDDEN: controlled startup requires Java validator"
        );
        Arc::get_mut(&mut self.0)
            .expect("configure before sharing recovery")
            .startup = Some(startup);
        Ok(self)
    }
    /// Independent administrator grant: never replace the retained forward request.
    pub fn with_inverse_startup(
        mut self,
        startup: crate::controlled_startup::Startup,
    ) -> Result<Self> {
        let original = self
            .0
            .startup
            .as_ref()
            .context("FORBIDDEN: inverse requires controlled startup")?;
        ensure!(
            startup.request_path()? != original.request_path()?
                && startup.unit()? != original.unit()?
                && self.0.units.contains(&startup.unit()?),
            "FORBIDDEN: independent allowlisted inverse profile required"
        );
        Arc::get_mut(&mut self.0)
            .expect("configure before sharing recovery")
            .inverse_startup = Some(startup);
        Ok(self)
    }
    pub fn with_normal_startup(
        mut self,
        startup: crate::controlled_startup::Startup,
    ) -> Result<Self> {
        let inverse = self
            .0
            .inverse_startup
            .as_ref()
            .context("FORBIDDEN: normal verification requires inverse grant")?;
        let original = self
            .0
            .startup
            .as_ref()
            .context("FORBIDDEN: original grant missing")?;
        ensure!(
            self.0.units.contains(&startup.unit()?)
                && startup.unit()? != original.unit()?
                && startup.unit()? != inverse.unit()?
                && startup.request_path()? != original.request_path()?
                && startup.request_path()? != inverse.request_path()?,
            "FORBIDDEN: independent allowlisted normal verification profile required"
        );
        Arc::get_mut(&mut self.0)
            .expect("configure before sharing recovery")
            .normal_startup = Some(startup);
        Ok(self)
    }
    pub fn with_forward_normal_profile(mut self, path: PathBuf) -> Result<Self> {
        let profile = forward_normal::Profile::new(path)?;
        let normal = self.0.normal_startup.as_ref().context("FORBIDDEN: normal startup grant required")?;
        profile.inputs(&normal.authority_sha256()?)?;
        Arc::get_mut(&mut self.0).expect("configure before sharing recovery").forward_normal = Some(profile);
        Ok(self)
    }
    /// Optional separate format grant for the retained baseline, never a downgrade of uploads.
    pub fn with_normal_snapshot_validator(
        mut self,
        validator: crate::snapshot_validation::Validator,
    ) -> Result<Self> {
        ensure!(
            self.0.normal_startup.is_some(),
            "FORBIDDEN: normal validator requires independent startup grant"
        );
        Arc::get_mut(&mut self.0)
            .expect("configure before sharing recovery")
            .normal_validator = Some(validator);
        Ok(self)
    }
    pub fn with_health_profile(mut self, path: PathBuf) -> Result<Self> {
        ensure!(
            self.0.normal_startup.is_some(),
            "FORBIDDEN: health requires independent normal startup grant"
        );
        let profile = health::Profile::new(path)?;
        Arc::get_mut(&mut self.0)
            .expect("configure before sharing recovery")
            .health = Some(profile);
        Ok(self)
    }
    pub fn with_completion_profile(mut self, path: PathBuf) -> Result<Self> {
        ensure!(
            self.0.health.is_some(),
            "FORBIDDEN: completion requires explicit health profile"
        );
        let profile = completion::Profile::new(path)?;
        Arc::get_mut(&mut self.0)
            .expect("configure before sharing recovery")
            .completion = Some(profile);
        Ok(self)
    }
    pub fn with_ordinary_profile(mut self, path: PathBuf) -> Result<Self> {
        ensure!(
            self.0.completion.is_some(),
            "FORBIDDEN: ordinary handoff requires explicit completion profile"
        );
        let profile = ordinary_profile::Profile::runtime(path,self.0.state_root.clone())?;
        Arc::get_mut(&mut self.0)
            .expect("configure before sharing recovery")
            .ordinary = Some(profile);
        Ok(self)
    }
    pub fn with_ordinary_snapshot_validator(
        mut self,
        validator: crate::snapshot_validation::Validator,
    ) -> Result<Self> {
        ensure!(
            self.0.ordinary.is_some(),
            "FORBIDDEN: ordinary validator requires independent profile grant"
        );
        Arc::get_mut(&mut self.0)
            .expect("configure before sharing recovery")
            .ordinary_validator = Some(validator);
        Ok(self)
    }
    fn startup_parameters(&self, j: &Journal) -> Result<Vec<(String, String)>> {
        self.0
            .validator
            .as_ref()
            .context("missing Java validator")?
            .startup_parameters(
                j.snapshot_validation
                    .as_ref()
                    .context("missing Java proof")?,
            )
    }
    fn verify_startup(&self, j: &Journal) -> Result<()> {
        ensure!(
            self.0.startup.is_some() == j.controlled_startup.is_some(),
            "CONFLICT: startup mode changed"
        );
        if let Some(p) = &j.controlled_startup {
            self.0.startup.as_ref().unwrap().verify_prepared(
                p,
                &j.unit,
                &j.id,
                &self.0.root.join(&j.target),
                &j.sha256,
                &self.startup_parameters(j)?,
            )?;
        }
        Ok(())
    }
    fn validate_snapshot(
        &self,
        id: &str,
        sha256: &str,
        expected: Option<&crate::snapshot_validation::Proof>,
    ) -> Result<Option<crate::snapshot_validation::Proof>> {
        self.0
            .validator
            .as_ref()
            .map(|v| v.validate(&self.staging_path(id)?, sha256, expected))
            .transpose()
    }
    fn verification(&self) -> &'static str {
        if self.0.startup.is_some() {
            "controlled-cm-application-only"
        } else if self.0.validator.is_some() {
            "snapshot-format-and-unit-only"
        } else {
            "artifact-and-unit-only"
        }
    }
    pub fn with_execution_database(mut self, path: PathBuf) -> Self {
        Arc::get_mut(&mut self.0)
            .expect("configure before sharing recovery")
            .execution_db = path;
        self
    }
    pub fn enabled(&self) -> bool {
        !self.0.units.is_empty()
    }
    async fn write<T: Send + 'static>(
        &self,
        action: impl FnOnce(&Self) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = Guard::acquire(&this.0.state_root, Subsystem::Recovery)?;
            action(&this)
        })
        .await?
    }
    fn snapshots(&self) -> Result<PathBuf> {
        let relative = self
            .0
            .snapshots
            .strip_prefix("/")
            .unwrap_or(&self.0.snapshots);
        let mut path = self.0.root.clone();
        for component in relative.components() {
            ensure!(
                matches!(component, Component::Normal(_)),
                "FORBIDDEN: snapshot path component"
            );
            path.push(component);
            let info = fs::symlink_metadata(&path)?;
            ensure!(
                info.is_dir() && info.mode() & 0o022 == 0,
                "FORBIDDEN: unsafe snapshot directory"
            );
        }
        Ok(path)
    }
    fn persist(&self, journal: &Journal) -> Result<()> {
        durable::json(&self.0.state.join("transaction.json"), journal)
    }
    fn journal(&self) -> Result<Option<Journal>> {
        let path = self.0.state.join("transaction.json");
        if !path.exists() {
            ensure!(
                !ordinary_command_evidence(&self.0.state)?,
                "CONFLICT: handoff evidence without recovery journal; preserve state"
            );
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(
            &durable::read(&path, 1 << 20)?.0,
        )?))
    }
    fn staging_path(&self, id: &str) -> Result<PathBuf> {
        ensure!(safe_name(id), "INVALID_ARGUMENT: upload id");
        Ok(self.0.state.join("staging").join(id))
    }
    pub async fn upload(&self, id: &str, data: &str) -> Result<Value> {
        use base64::Engine;
        ensure!(self.enabled(), "FORBIDDEN: recovery is not configured");
        let id = id.to_owned();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: base64 payload"))?;
        ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= LIMIT_BYTES,
            "INVALID_ARGUMENT: artifact size"
        );
        self.write(move |this| {
            if let Some(journal) = this.journal()? {
                ensure!(
                    journal.state.settled(),
                    "CONFLICT: unresolved recovery transaction"
                );
            }
            let path = this.staging_path(&id)?;
            ensure!(!path.exists(), "CONFLICT: upload id already staged");
            let mut count = 0;
            let mut total = 0;
            for entry in fs::read_dir(this.0.state.join("staging"))? {
                let entry = entry?;
                let info = fs::symlink_metadata(entry.path())?;
                ensure!(info.is_file(), "CONFLICT: unsafe staging entry");
                count += 1;
                total += info.len();
            }
            ensure!(
                count < LIMIT_FILES && total + bytes.len() as u64 <= LIMIT_TOTAL,
                "RESOURCE_EXHAUSTED: staging quota"
            );
            durable::publish_new(&path, &bytes, FileMetadata::private())?;
            Ok(json!({"uploadId":id,"size":bytes.len(),"sha256":durable::hash(&bytes)}))
        })
        .await
    }
    fn inventory(&self) -> Result<Vec<SnapshotFile>> {
        let dir = self.snapshots()?;
        let mut files = Vec::new();
        let mut total = 0;
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("CONFLICT: non-UTF8 snapshot name"))?;
            if name == ".recovery-retained" {
                snapshot_set::retained_directory(&entry.path())?;
                continue;
            }
            ensure!(safe_name(&name), "CONFLICT: unsafe snapshot entry name");
            let (bytes, metadata) = durable::read(&entry.path(), LIMIT_BYTES)?;
            total += bytes.len() as u64;
            ensure!(
                files.len() < LIMIT_FILES && total <= LIMIT_TOTAL,
                "RESOURCE_EXHAUSTED: snapshot backup quota"
            );
            files.push(SnapshotFile {
                name,
                size: bytes.len() as u64,
                sha256: durable::hash(&bytes),
                metadata,
            });
        }
        files.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(files)
    }
    fn next_snapshot_id(base: &[SnapshotFile]) -> Result<u64> {
        let mut max = 0;
        for file in base {
            if let Some(text) = file
                .name
                .strip_prefix("snapshot_")
                .and_then(|s| s.strip_suffix(".xml"))
            {
                let id = text
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("CONFLICT: invalid snapshot ID"))?;
                max = max.max(id);
            }
        }
        ensure!(
            max < i64::MAX as u64,
            "RESOURCE_EXHAUSTED: snapshot ID exhausted"
        );
        Ok(max + 1)
    }
    fn unit(&self, unit: &str) -> Result<(bool, u32)> {
        let output = crate::process::run(
            &self.0.systemctl,
            &["show", unit, "--property=LoadState,ActiveState,MainPID"],
            None,
            Duration::from_secs(5),
        )?;
        ensure!(output.status.success(), "INTERNAL: unit status unavailable");
        let text = String::from_utf8(output.stdout)?;
        let value = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
        };
        ensure!(
            value("LoadState") == Some("loaded"),
            "FORBIDDEN: recovery unit is not loaded"
        );
        let state = value("ActiveState").context("INTERNAL: missing unit state")?;
        ensure!(
            matches!(state, "active" | "inactive" | "failed"),
            "CONFLICT: recovery unit is transitioning"
        );
        let pid = value("MainPID")
            .context("INTERNAL: missing unit pid")?
            .parse::<u32>()?;
        Ok((state == "active", pid))
    }
    fn command(&self, action: &str, unit: &str) -> Result<()> {
        let output = crate::process::run(
            &self.0.systemctl,
            &[action, unit],
            None,
            Duration::from_secs(30),
        )?;
        ensure!(
            output.status.success(),
            "INTERNAL: fixed unit action failed"
        );
        Ok(())
    }
    fn stop(&self, unit: &str) -> Result<()> {
        self.command("stop", unit)?;
        let (active, pid) = self.unit(unit)?;
        ensure!(
            !active && pid == 0,
            "CONFLICT: recovery unit did not stop exclusively"
        );
        Ok(())
    }
    fn stopped(&self, unit: &str) -> Result<()> {
        let (active, pid) = self.unit(unit)?;
        ensure!(
            !active && pid == 0,
            "CONFLICT: recovery unit restarted externally"
        );
        Ok(())
    }
    fn start(&self, unit: &str) -> Result<()> {
        self.command("start", unit)?;
        ensure!(self.unit(unit)?.0, "INTERNAL: unit failed to become active");
        Ok(())
    }
    pub async fn prepare(&self, id: &str, sha256: &str, unit: &str) -> Result<Value> {
        ensure!(self.enabled(), "FORBIDDEN: recovery is not configured");
        ensure!(
            sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "INVALID_ARGUMENT: expected SHA256"
        );
        let (id, sha256, unit) = (id.to_owned(), sha256.to_lowercase(), unit.to_owned());
        self.write(move|this| {
              let previous=this.journal()?;
              if let Some(j)=&previous {ensure!(j.state.settled(),"CONFLICT: unresolved recovery transaction");}
            ensure!(this.0.units.contains(&unit),"FORBIDDEN: recovery unit not allowed");
            let bytes=durable::read(&this.staging_path(&id)?,LIMIT_BYTES)?.0;ensure!(durable::hash(&bytes)==sha256,"CONFLICT: staged payload hash mismatch");
            let snapshot_validation=this.validate_snapshot(&id,&sha256,None)?;
            let base=this.inventory()?;let next=Self::next_snapshot_id(&base)?;let dir=this.snapshots()?;
            let target=dir.join(format!("snapshot_{next}.xml"));
            let owner=FileMetadata::from_fs(&fs::symlink_metadata(&dir)?);
            let metadata=FileMetadata{mode:0o600,..owner};
            let transaction_id=format!("rec-{}",uuid::Uuid::new_v4());
            let mut j=Journal{schema_version:2,id:transaction_id.clone(),state:State::Validated,upload_id:id,sha256,size:bytes.len() as u64,
                unit:unit.clone(),target:target.strip_prefix(&this.0.root)?.to_string_lossy().into_owned(),backup_dir:format!("backups/{transaction_id}"),
                confirm_token:uuid::Uuid::new_v4().to_string(),started_at:now(),error:None,base,backup_ready:false,
                was_active:this.unit(&unit)?.0,target_metadata:Some(metadata),snapshot_validation,
                controlled_startup:None,controlled_issued:false,cm_application:None,inverse:None,normal_boot:None,health:None,completion:None,ordinary:None};
            if let Some(startup)=&this.0.startup {
                j.controlled_startup=Some(startup.prepare(&unit,&j.id,&target,&j.sha256,&this.startup_parameters(&j)?,metadata)?);
            }
              if let Some(previous)=&previous {this.archive_ordinary_journal(previous)?;}
              this.persist(&j)?;
            Ok(json!({"transactionId":j.id,"state":j.state,"unit":j.unit,"size":j.size,"confirmToken":j.confirm_token,
                "verification":this.verification(),"snapshotValidation":j.snapshot_validation.map(|p|p.report),"kuraRecoveryVerified":false}))
        }).await
    }
    fn state(&self, j: &mut Journal, state: State) -> Result<()> {
        j.state = state;
        self.persist(j)
    }
    async fn pending_executions(&self) -> Result<()> {
        self.pending_executions_for(None).await
    }
    async fn pending_executions_for(
        &self,
        command: Option<&yofc_management_protocol::v1::ReadCommand>,
    ) -> Result<()> {
        use sqlx::{Connection, sqlite::SqliteConnectOptions};
        let path = &self.0.execution_db;
        if !path.exists() {
            ensure!(
                command.is_none(),
                "CONFLICT: missing durable remote admission"
            );
            return Ok(());
        }
        let info = fs::symlink_metadata(path)?;
        ensure!(
            info.is_file() && info.nlink() == 1,
            "CONFLICT: unsafe execution database"
        );
        let mut db = sqlx::SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(path)
                .read_only(true)
                .create_if_missing(false),
        )
        .await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='executions')",
        )
        .fetch_one(&mut db)
        .await?;
        if exists {
            let except = if let Some(command) = command {
                use prost::Message;
                use sha2::{Digest, Sha256};
                ensure!(
                    matches!(command.operation, 21 | 22 | 29) && command.valid_payload(),
                    "INVALID_ARGUMENT"
                );
                let admitted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions WHERE command_id=? AND operation=? AND idempotency_key=? AND request_hash=? AND state='RUNNING' AND result IS NULL)")
                    .bind(&command.command_id).bind(command.operation).bind(&command.idempotency_key)
                    .bind(format!("{:x}", Sha256::digest(command.encode_to_vec()))).fetch_one(&mut db).await?;
                ensure!(
                    admitted,
                    "CONFLICT: remote handoff requires its exact durable admission"
                );
                command.command_id.as_str()
            } else {
                ""
            };
            let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions WHERE command_id<>? AND state IN ('RUNNING','UNKNOWN') AND operation NOT IN (1,2,3,4,8,9,11,15,20,23))").bind(except).fetch_one(&mut db).await?;
            ensure!(!pending, "CONFLICT: unresolved side-effect execution");
        } else {
            ensure!(
                command.is_none(),
                "CONFLICT: missing durable remote admission"
            );
        }
        Ok(())
    }
    pub async fn execute(&self, id: &str, token: &str) -> Result<Value> {
        ensure!(self.enabled(), "FORBIDDEN: recovery is not configured");
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move|this| {
            let mut j=this.journal()?.context("CONFLICT: no transaction")?;
            ensure!(j.id==id && j.confirm_token==token,"FORBIDDEN: recovery transaction/token");
            ensure!(j.schema_version==2 && j.state==State::Validated,"CONFLICT: recovery transaction state");
            let payload=durable::read(&this.staging_path(&j.upload_id)?,LIMIT_BYTES)?.0;
            ensure!(durable::hash(&payload)==j.sha256,"CONFLICT: staged payload changed");
            ensure!(this.inventory()?==j.base,"CONFLICT: snapshot baseline drifted");
            ensure!(this.0.validator.is_some()==j.snapshot_validation.is_some(),"CONFLICT: snapshot validator mode changed");
            ensure!(this.validate_snapshot(&j.upload_id,&j.sha256,j.snapshot_validation.as_ref())?==j.snapshot_validation,"CONFLICT: snapshot validation changed since prepare");
            this.verify_startup(&j)?;
            match this.run_transaction(&mut j,&payload) {
                Ok(())=>Ok(json!({"transactionId":j.id,"state":j.state,"recoveryId":j.id,"target":j.target,"unit":j.unit,
                    "verification":this.verification(),"snapshotValidation":j.snapshot_validation.as_ref().map(|p|&p.report),"kuraRecoveryVerified":false})),
                Err(error)=>{j.error=Some(error.to_string());this.compensate(&mut j)?;this.persist(&j)?;
                    anyhow::bail!("recovery failed (compensated or requires recovery; {:?})",j.state)}
            }
        }).await
    }
    fn run_transaction(&self, j: &mut Journal, payload: &[u8]) -> Result<()> {
        self.verify_startup(j)?;
        self.state(j, State::Stopping)?;
        self.stop(&j.unit)?;
        ensure!(
            self.validate_snapshot(&j.upload_id, &j.sha256, j.snapshot_validation.as_ref())?
                == j.snapshot_validation,
            "CONFLICT: snapshot validation changed after stop"
        );
        ensure!(
            self.inventory()? == j.base,
            "CONFLICT: snapshot baseline drifted after stop"
        );
        let backup = self.0.state.join(&j.backup_dir);
        durable::directory(&backup)?;
        for file in &j.base {
            let (bytes, metadata) =
                durable::read(&self.snapshots()?.join(&file.name), LIMIT_BYTES)?;
            ensure!(
                durable::hash(&bytes) == file.sha256 && metadata == file.metadata,
                "CONFLICT: snapshot drift during backup"
            );
            durable::write(&backup.join(&file.name), &bytes, FileMetadata::private())?;
        }
        durable::json(
            &backup.join("manifest.json"),
            &Manifest {
                schema_version: 2,
                files: j.base.clone(),
            },
        )?;
        durable::sync_directory(backup.parent().unwrap())?;
        j.backup_ready = true;
        self.state(j, State::BackedUp)?;
        self.stopped(&j.unit)?;
        ensure!(
            self.inventory()? == j.base,
            "CONFLICT: snapshot drift before commit"
        );
        self.state(j, State::Committing)?;
        durable::publish_new(
            &self.0.root.join(&j.target),
            payload,
            j.target_metadata
                .context("CONFLICT: target metadata missing")?,
        )?;
        self.verify_startup(j)?;
        self.state(j, State::Starting)?;
        if let Some(p) = j.controlled_startup.clone() {
            // Persist intent before publication. A crash here must not invoke snapshot-only compensation.
            j.controlled_issued = true;
            self.persist(j)?;
            self.0.startup.as_ref().unwrap().publish(
                &p,
                &j.id,
                &self.0.root.join(&j.target),
                &j.sha256,
                &self.startup_parameters(j)?,
                j.target_metadata.context("missing owner")?,
            )?;
        }
        self.start(&j.unit)?;
        self.state(j, State::Verifying)?;
        let (placed, metadata) = durable::read(&self.0.root.join(&j.target), LIMIT_BYTES)?;
        ensure!(
            durable::hash(&placed) == j.sha256 && Some(metadata) == j.target_metadata,
            "CONFLICT: placed snapshot drifted"
        );
        if let Some(p) = &j.controlled_startup {
            let proof = self.0.startup.as_ref().unwrap().application(
                p,
                &j.id,
                &j.sha256,
                j.target_metadata.context("missing owner")?,
            )?;
            ensure!(
                self.unit(&j.unit)?.0,
                "CONFLICT: Kura stopped after CM application"
            );
            self.verify_startup(j)?;
            let (after, after_metadata) = durable::read(&self.0.root.join(&j.target), LIMIT_BYTES)?;
            ensure!(
                durable::hash(&after) == j.sha256 && Some(after_metadata) == j.target_metadata,
                "CONFLICT: candidate changed during CM startup"
            );
            j.cm_application = Some(proof);
            // CM is applied, but bridge/business and explicit completion have not been accepted.
            // Keep the upload, candidate, startup request and global write barrier intact.
            return self.state(j, State::AwaitingCompletion);
        }
        durable::json(
            &self.0.state.join("receipts").join(format!("{}.json", j.id)),
            &json!({"schema":"yofc.agent.recovery.v2","recoveryId":j.id,
            "unit":j.unit,"snapshot":j.target,"sha256":j.sha256,"size":j.size,"finishedAtUnixMs":now(),"verification":self.verification(),"snapshotValidation":j.snapshot_validation.as_ref().map(|p|&p.report),"kuraRecoveryVerified":false}),
        )?;
        self.state(j, State::Succeeded)?;
        if let Err(error) = durable::remove(&self.staging_path(&j.upload_id)?) {
            tracing::warn!(%error,"completed artifact remains staged");
        }
        Ok(())
    }
    fn compensate(&self, j: &mut Journal) -> Result<()> {
        if j.controlled_issued {
            // A snapshot rollback cannot undo CM mutations. Stop, retain all evidence, require CM-aware compensation.
            let stopped = self.stop(&j.unit);
            j.state = State::RecoveryRequired;
            j.error = Some(if stopped.is_ok() {
                "Controlled Kura startup issued; explicit CM compensation or completion required"
                    .into()
            } else {
                "Controlled Kura startup issued; stop failed, explicit operator recovery required"
                    .into()
            });
            return self.persist(j);
        }
        let previous = j.state;
        self.state(j, State::Compensating)?;
        let result: Result<()> = (|| {
            ensure!(
                j.schema_version == 2,
                "CONFLICT: legacy recovery requires manual inspection"
            );
            ensure!(
                self.0.units.contains(&j.unit),
                "FORBIDDEN: recovery unit no longer configured"
            );
            if j.backup_ready {
                self.stop(&j.unit)?;
                let backup = self.0.state.join(&j.backup_dir);
                let manifest: Manifest = serde_json::from_slice(
                    &durable::read(&backup.join("manifest.json"), 1 << 20)?.0,
                )?;
                ensure!(
                    manifest.schema_version == 2 && manifest.files == j.base,
                    "CONFLICT: backup manifest changed"
                );
                let dir = self.snapshots()?;
                let target = self.0.root.join(&j.target);
                // Validate the complete live directory before deleting or restoring anything.
                for file in self.inventory()? {
                    if let Some(old) = j.base.iter().find(|old| old.name == file.name) {
                        ensure!(
                            file == *old,
                            "CONFLICT: original snapshot changed; preserve for operator"
                        );
                    } else {
                        ensure!(
                            dir.join(&file.name) == target
                                && file.sha256 == j.sha256
                                && Some(file.metadata) == j.target_metadata,
                            "CONFLICT: unknown or drifted snapshot; preserve for operator"
                        );
                    }
                }
                for file in &manifest.files {
                    ensure!(safe_name(&file.name), "CONFLICT: backup file name");
                    let bytes = durable::read(&backup.join(&file.name), LIMIT_BYTES)?.0;
                    ensure!(
                        bytes.len() as u64 == file.size && durable::hash(&bytes) == file.sha256,
                        "CONFLICT: backup data changed"
                    );
                }
                self.stopped(&j.unit)?;
                if target.exists() {
                    durable::remove(&target)?;
                }
                for file in &manifest.files {
                    let path = dir.join(&file.name);
                    if !path.exists() {
                        durable::publish_new(
                            &path,
                            &durable::read(&backup.join(&file.name), LIMIT_BYTES)?.0,
                            file.metadata,
                        )?;
                    }
                }
            } else {
                ensure!(
                    !matches!(
                        previous,
                        State::Committing | State::Starting | State::Verifying
                    ),
                    "CONFLICT: backup was never proven durable"
                );
            }
            if j.was_active && !self.unit(&j.unit)?.0 {
                self.start(&j.unit)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => j.state = State::Failed,
            Err(error) => {
                j.state = State::RecoveryRequired;
                j.error = Some(format!("compensation incomplete: {error:#}"));
            }
        }
        self.persist(j)
    }
    pub async fn recover(&self) -> Result<()> {
        self.write(|this| {
            if let Some(mut j) = this.journal()? {
                if j.ordinary.is_some() {
                    return this.recover_ordinary(&mut j);
                }
                if j.completion.is_some() {
                    return this.recover_completion(&mut j);
                }
                if j.health.is_some() {
                    return this.recover_health(&mut j);
                }
                if j.normal_boot.is_some() {
                    return this.recover_normal_boot(&mut j);
                }
                if j.inverse
                    .as_ref()
                    .and_then(|i| i.snapshot_set.as_ref())
                    .is_some()
                {
                    return this.recover_snapshot_set(&mut j);
                }
                if let Some(inverse) = j.inverse.clone() {
                    // An inverse intent is never retried. A fully applied inverse remains nonterminal.
                    let proof: Result<()> = (|| {
                        ensure!(
                            j.state == State::AwaitingCompensationCompletion && inverse.issued,
                            "CONFLICT: inverse interrupted; retain state"
                        );
                        this.verify_inverse(&j, &inverse, true)?;
                        let actual = this
                            .0
                            .inverse_startup
                            .as_ref()
                            .context("inverse profile missing")?
                            .application(
                                &inverse.startup,
                                &inverse.id,
                                &inverse.sha256,
                                j.target_metadata.context("inverse owner missing")?,
                            )?;
                        ensure!(
                            Some(actual) == inverse.application
                                && this.unit(&inverse.unit)?.0
                                && !this.unit(&j.unit)?.0,
                            "CONFLICT: inverse evidence/unit changed"
                        );
                        Ok(())
                    })();
                    if proof.is_err() {
                        this.retain_inverse_failure(&mut j)?;
                    }
                    ensure!(
                        j.state == State::AwaitingCompensationCompletion,
                        "CONFLICT: inverse requires explicit operator action"
                    );
                    return Ok(());
                }
                ensure!(
                    j.state != State::RecoveryRequired,
                    "CONFLICT: recovery requires explicit operator action"
                );
                if j.controlled_issued && !j.state.settled() {
                    if j.state == State::AwaitingCompletion {
                        let proof: Result<()> = (|| {
                            this.verify_startup(&j)?;
                            let startup =
                                this.0.startup.as_ref().context("missing startup grant")?;
                            let actual = startup.application(
                                j.controlled_startup
                                    .as_ref()
                                    .context("missing startup request")?,
                                &j.id,
                                &j.sha256,
                                j.target_metadata.context("missing owner")?,
                            )?;
                            ensure!(
                                Some(actual) == j.cm_application && this.unit(&j.unit)?.0,
                                "CONFLICT: pending CM evidence changed"
                            );
                            let (bytes, metadata) =
                                durable::read(&this.0.root.join(&j.target), LIMIT_BYTES)?;
                            ensure!(
                                durable::hash(&bytes) == j.sha256
                                    && Some(metadata) == j.target_metadata,
                                "CONFLICT: pending candidate drifted"
                            );
                            Ok(())
                        })();
                        if proof.is_err() {
                            this.compensate(&mut j)?;
                        }
                    } else {
                        this.compensate(&mut j)?;
                    }
                    ensure!(
                        j.state != State::RecoveryRequired,
                        "CONFLICT: controlled recovery requires explicit operator action"
                    );
                    return Ok(());
                }
                if !j.state.settled() {
                    let receipt = this.0.state.join("receipts").join(format!("{}.json", j.id));
                    if receipt.exists() {
                        // The durable receipt is a completion decision. Never undo
                        // it because of a crash before the final journal marker.
                        let result: Result<()> = (|| {
                            let value: Value =
                                serde_json::from_slice(&durable::read(&receipt, 1 << 20)?.0)?;
                            ensure!(
                                value["schema"] == "yofc.agent.recovery.v2"
                                    && value["recoveryId"] == j.id
                                    && value["sha256"] == j.sha256
                                    && value["snapshot"] == j.target,
                                "CONFLICT: recovery receipt changed"
                            );
                            if let Some(proof) = &j.snapshot_validation {
                                ensure!(
                                    value["snapshotValidation"]
                                        == serde_json::to_value(&proof.report)?
                                        && value["verification"] == "snapshot-format-and-unit-only"
                                        && value["kuraRecoveryVerified"] == false,
                                    "CONFLICT: snapshot validation receipt changed"
                                );
                            }
                            let (bytes, metadata) =
                                durable::read(&this.0.root.join(&j.target), LIMIT_BYTES)?;
                            ensure!(
                                durable::hash(&bytes) == j.sha256
                                    && Some(metadata) == j.target_metadata
                                    && this.unit(&j.unit)?.0,
                                "CONFLICT: completed recovery drifted"
                            );
                            Ok(())
                        })();
                        match result {
                            Ok(()) => j.state = State::Succeeded,
                            Err(error) => {
                                j.state = State::RecoveryRequired;
                                j.error = Some(error.to_string());
                            }
                        }
                        this.persist(&j)?;
                    } else {
                        this.compensate(&mut j)?;
                    }
                }
            }
            Ok(())
        })
        .await
    }
    fn source_application(&self, j: &Journal) -> Result<crate::controlled_startup::Application> {
        ensure!(j.controlled_issued, "CONFLICT: no controlled source");
        self.verify_startup(j)?;
        let expected = j
            .cm_application
            .as_ref()
            .context("CONFLICT: exact source application unavailable")?;
        ensure!(
            expected.compensation.is_some(),
            "CONFLICT: legacy application has no inverse authorization"
        );
        let actual = self
            .0
            .startup
            .as_ref()
            .context("source profile missing")?
            .application(
                j.controlled_startup
                    .as_ref()
                    .context("source request missing")?,
                &j.id,
                &j.sha256,
                j.target_metadata.context("source owner missing")?,
            )?;
        ensure!(&actual == expected, "CONFLICT: source application drifted");
        let (bytes, metadata) =
            durable::read(&self.retained_snapshot_path(j, &j.target)?, LIMIT_BYTES)?;
        ensure!(
            durable::hash(&bytes) == j.sha256 && Some(metadata) == j.target_metadata,
            "CONFLICT: source candidate drifted"
        );
        Ok(actual)
    }
    fn inverse_payload(&self, j: &Journal) -> Result<Vec<u8>> {
        let source = j
            .controlled_startup
            .as_ref()
            .context("source request missing")?;
        let (bytes, metadata) = durable::read(
            &PathBuf::from(format!("{}.cm-backup.aes", source.receipt_path.display())),
            LIMIT_BYTES,
        )?;
        ensure!(
            metadata.mode & 0o077 == 0
                && metadata.uid == j.target_metadata.context("owner missing")?.uid,
            "CONFLICT: inverse backup owner"
        );
        ensure!(
            durable::hash(&bytes) == self.source_proof(j)?.backup_sha256(),
            "CONFLICT: inverse source backup drifted"
        );
        Ok(bytes)
    }
    fn verify_inverse_source_anchor(&self, j: &Journal, inverse: &Inverse) -> Result<()> {
        if j.inverse.is_some() {
            let anchor = durable::read(
                &self
                    .0
                    .state
                    .join("receipts")
                    .join(format!("{}.inverse-source.json", inverse.id)),
                1 << 20,
            )?
            .0;
            ensure!(
                durable::hash(&anchor) == inverse.source_journal_sha256,
                "CONFLICT: inverse source journal anchor drifted"
            );
            let source: Journal = serde_json::from_slice(&anchor)?;
            ensure!(
                source.id == j.id
                    && source.controlled_startup == j.controlled_startup
                    && source.cm_application == inverse.source_application
                    && source.controlled_issued == j.controlled_issued
                    && (inverse.source_partial.is_none()
                        || source.state == State::RecoveryRequired
                            && source.controlled_issued
                            && source.inverse.is_none())
                    && source.target == j.target
                    && source.sha256 == j.sha256
                    && source.base == j.base
                    && source.target_metadata == j.target_metadata,
                "CONFLICT: inverse source journal identity drifted"
            );
        }
        Ok(())
    }
    fn verify_inverse(&self, j: &Journal, inverse: &Inverse, placed: bool) -> Result<()> {
        self.verify_inverse_source_anchor(j, inverse)?;
        ensure!(
            self.source_proof(j)? == inverse.source_proof()?,
            "CONFLICT: inverse source changed"
        );
        ensure!(
            self.0.units.contains(&j.unit) && self.0.units.contains(&inverse.unit),
            "FORBIDDEN: inverse units no longer allowed"
        );
        let mut expected = inverse.base.clone();
        if placed {
            let (bytes, metadata) = durable::read(&self.0.root.join(&inverse.target), LIMIT_BYTES)?;
            ensure!(
                durable::hash(&bytes) == inverse.sha256 && Some(metadata) == j.target_metadata,
                "CONFLICT: inverse candidate drifted"
            );
            expected.push(SnapshotFile {
                name: self
                    .0
                    .root
                    .join(&inverse.target)
                    .file_name()
                    .context("inverse file name")?
                    .to_str()
                    .context("inverse encoding")?
                    .into(),
                size: bytes.len() as u64,
                sha256: inverse.sha256.clone(),
                metadata,
            });
            expected.sort_by(|a, b| a.name.cmp(&b.name));
        }
        ensure!(
            self.inventory()? == expected,
            "CONFLICT: inverse snapshot baseline drifted"
        );
        let startup = self
            .0
            .inverse_startup
            .as_ref()
            .context("FORBIDDEN: inverse profile disabled")?;
        startup.verify_prepared(
            &inverse.startup,
            &inverse.unit,
            &inverse.id,
            &self.0.root.join(&inverse.target),
            &inverse.sha256,
            &inverse.parameters,
        )?;
        ensure!(
            durable::hash(&self.inverse_payload(j)?) == inverse.sha256,
            "CONFLICT: inverse payload changed"
        );
        let mut parameters = self.startup_parameters(j)?;
        for (key, value) in &mut parameters {
            if key == "snapshot.mode" {
                *value = "aes-gcm".into();
            }
        }
        let source = j
            .controlled_startup
            .as_ref()
            .context("source request missing")?;
        let proof = inverse.source_proof()?;
        parameters.extend([
            (
                "compensation.source.receipt".into(),
                source
                    .receipt_path
                    .to_str()
                    .context("source encoding")?
                    .into(),
            ),
            (
                "compensation.source.receipt.sha256".into(),
                proof.receipt_sha256().to_owned(),
            ),
            (
                "compensation.source.plan.sha256".into(),
                proof.plan_sha256()?.to_owned(),
            ),
        ]);
        ensure!(
            parameters == inverse.parameters,
            "CONFLICT: inverse parameters drifted"
        );
        Ok(())
    }
    fn retain_inverse_failure(&self, j: &mut Journal) -> Result<()> {
        let a = self.stop(&j.unit);
        let b = match &j.inverse {
            Some(i) => self.stop(&i.unit),
            None => Ok(()),
        };
        let c = match &j.normal_boot {
            Some(p) => self.stop(&p.unit),
            None => Ok(()),
        };
        j.state = State::RecoveryRequired;
        let phase = if j.normal_boot.as_ref().is_some_and(|p|p.source == normal_boot::SourceKind::AppliedForward) { "Applied-forward normal" } else { "Inverse" };
        j.error = Some(if a.is_ok() && b.is_ok() && c.is_ok() {
            format!("{phase} requires explicit inspection/completion; all evidence retained")
        } else { format!("{phase} stop failed; explicit operator action required") });
        self.persist(j)
    }
    pub async fn prepare_compensation(&self, id: &str, token: &str) -> Result<Value> {
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move |this| {
            let mut j = this.journal()?.context("CONFLICT: no source transaction")?;
            ensure!(
                j.id == id && j.confirm_token == token,
                "FORBIDDEN: source transaction/token"
            );
            ensure!(
                matches!(j.state, State::AwaitingCompletion | State::RecoveryRequired)
                    && j.inverse.is_none() && j.normal_boot.is_none(),
                "CONFLICT: source cannot prepare another inverse"
            );
            let startup = this
                .0
                .inverse_startup
                .as_ref()
                .context("FORBIDDEN: inverse profile disabled")?;
            let source_proof = this.source_proof(&j)?;
            let base = this.inventory()?;
            let mut expected = j.base.clone();
            let metadata = j.target_metadata.context("source owner missing")?;
            expected.push(SnapshotFile {
                name: this
                    .0
                    .root
                    .join(&j.target)
                    .file_name()
                    .context("source name")?
                    .to_str()
                    .context("source encoding")?
                    .into(),
                size: j.size,
                sha256: j.sha256.clone(),
                metadata,
            });
            expected.sort_by(|a, b| a.name.cmp(&b.name));
            ensure!(base == expected, "CONFLICT: source snapshot set drifted");
            let payload = this.inverse_payload(&j)?;
            ensure!(
                base.len() < LIMIT_FILES
                    && base.iter().map(|f| f.size).sum::<u64>() + payload.len() as u64
                        <= LIMIT_TOTAL,
                "RESOURCE_EXHAUSTED: inverse snapshot quota"
            );
            let source_journal = serde_json::to_vec(&j)?;
            let sha256 = durable::hash(&payload);
            let target = this
                .snapshots()?
                .join(format!("snapshot_{}.xml", Self::next_snapshot_id(&base)?));
            let inverse_id = format!("rec-{}", uuid::Uuid::new_v4());
            let unit = startup.unit()?;
            ensure!(
                this.0.units.contains(&unit) && unit != j.unit,
                "FORBIDDEN: inverse unit"
            );
            this.stopped(&unit)?;
            let mut parameters = this.startup_parameters(&j)?;
            for (key, value) in &mut parameters {
                if key == "snapshot.mode" {
                    *value = "aes-gcm".into();
                }
            }
            let source = j
                .controlled_startup
                .as_ref()
                .context("source request missing")?;
            parameters.extend([
                (
                    "compensation.source.receipt".into(),
                    source
                        .receipt_path
                        .to_str()
                        .context("source encoding")?
                        .into(),
                ),
                (
                    "compensation.source.receipt.sha256".into(),
                    source_proof.receipt_sha256().to_owned(),
                ),
                (
                    "compensation.source.plan.sha256".into(),
                    source_proof.plan_sha256()?.to_owned(),
                ),
            ]);
            let prepared =
                startup.prepare(&unit, &inverse_id, &target, &sha256, &parameters, metadata)?;
            let token = uuid::Uuid::new_v4().to_string();
            let inverse = Inverse {
                id: inverse_id.clone(),
                confirm_token: token.clone(),
                unit: unit.clone(),
                target: target
                    .strip_prefix(&this.0.root)?
                    .to_str()
                    .context("target encoding")?
                    .into(),
                sha256: sha256.clone(),
                base,
                startup: prepared,
                parameters,
                source_application: match &source_proof { source::Source::Applied(value) => Some(value.clone()), _ => None },
                source_partial: match &source_proof { source::Source::Partial(value) => Some(value.clone()), _ => None },
                source_journal_sha256: durable::hash(&source_journal),
                issued: false,
                application: None,
                snapshot_set: None,
            };
            this.verify_inverse(&j, &inverse, false)?;
            // A create-only source journal anchor survives any later transaction-journal update.
            durable::publish_new(
                &this
                    .0
                    .state
                    .join("receipts")
                    .join(format!("{}.inverse-source.json", inverse_id)),
                &source_journal,
                FileMetadata::private(),
            )?;
            j.inverse = Some(inverse);
            this.state(&mut j, State::CompensationPrepared)?;
            Ok(
                json!({"transactionId":inverse_id,"sourceTransactionId":j.id,"state":j.state,
                "confirmToken":token,"unit":unit,"sha256":sha256,"sourceStatus":source_proof.status(),"kuraRecoveryVerified":false}),
            )
        })
        .await
    }
    pub async fn execute_compensation(&self, id: &str, token: &str) -> Result<Value> {
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move |this| {
            let mut j = this.journal()?.context("CONFLICT: no inverse transaction")?;
            let mut inverse = j.inverse.clone().context("CONFLICT: no prepared inverse")?;
            ensure!(inverse.id == id && inverse.confirm_token == token, "FORBIDDEN: inverse transaction/token");
            ensure!(j.state == State::CompensationPrepared && !inverse.issued, "CONFLICT: inverse already attempted");
            this.verify_inverse(&j,&inverse,false)?;
            let result: Result<()> = (|| {
                this.state(&mut j,State::Compensating)?;
                this.stop(&j.unit)?;
                this.stopped(&inverse.unit)?;
                this.verify_inverse(&j,&inverse,false)?;
                // Persist intent before any inverse publication; a crash never auto-resends.
                inverse.issued = true; j.inverse = Some(inverse.clone()); this.persist(&j)?;
                let metadata = j.target_metadata.context("source owner missing")?;
                durable::publish_new(&this.0.root.join(&inverse.target),&this.inverse_payload(&j)?,metadata)?;
                this.verify_inverse(&j,&inverse,true)?;
                let startup = this.0.inverse_startup.as_ref().context("inverse profile missing")?;
                startup.publish(&inverse.startup,&inverse.id,&this.0.root.join(&inverse.target),
                    &inverse.sha256,&inverse.parameters,metadata)?;
                this.stopped(&j.unit)?;
                this.start(&inverse.unit)?;
                let application = startup.application(&inverse.startup,&inverse.id,&inverse.sha256,metadata)?;
                ensure!(application.compensation.is_some(), "CONFLICT: inverse proof incomplete");
                this.verify_inverse(&j,&inverse,true)?;
                ensure!(this.unit(&inverse.unit)?.0 && !this.unit(&j.unit)?.0, "CONFLICT: inverse unit state changed");
                inverse.application = Some(application); j.inverse = Some(inverse.clone());
                this.state(&mut j,State::AwaitingCompensationCompletion)
            })();
            if result.is_err() { this.retain_inverse_failure(&mut j)?;
                anyhow::bail!("CONFLICT: inverse incomplete; retained RECOVERY_REQUIRED; query status, do not resend"); }
            Ok(json!({"transactionId":inverse.id,"sourceTransactionId":j.id,"state":j.state,
                "target":inverse.target,"unit":inverse.unit,"kuraRecoveryVerified":false,
                "verification":"controlled-cm-compensation-only","awaitsExplicitCompletion":true}))
        }).await
    }

    pub async fn rollback(&self, id: &str, token: &str) -> Result<Value> {
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move |this| {
            let mut j = this
                .journal()?
                .context("CONFLICT: no recovery transaction")?;
            ensure!(
                j.id == id && j.confirm_token == token,
                "FORBIDDEN: recovery transaction/token"
            );
            ensure!(
                !j.state.settled(),
                "CONFLICT: recovery transaction already settled"
            );
            if j.inverse.is_some() {
                this.retain_inverse_failure(&mut j)?;
            } else {
                this.compensate(&mut j)?;
            }
            Ok(json!({"transactionId":j.id,"state":j.state}))
        })
        .await
    }
    pub async fn status(&self) -> Result<Value> {
        let this = self.clone();
        tokio::task::spawn_blocking(move|| {
            let j=this.journal()?;let staged=fs::read_dir(this.0.state.join("staging"))?.count();
            Ok(json!({"enabled":this.enabled(),"recoverableUnits":this.0.units,"snapshotDirectory":this.0.snapshots,"stagedUploads":staged,
                "verification":this.verification(),"kuraRecoveryVerified":false,
                "transaction":j.map(|j|json!({"id":j.id,"state":j.state,"unit":j.unit,"target":j.target,"sha256":j.sha256,"startedAtUnixMs":j.started_at,"error":j.error,"normalBootVerified":false,"normalBoot":j.normal_boot.as_ref().map(normal_boot::Plan::status),"health":j.health.as_ref().map(health::Plan::status),"completion":j.completion.as_ref().map(completion::Plan::status),"ordinary":j.ordinary.as_ref().map(ordinary::Plan::status),"cmApplication":j.cm_application,"awaitsExplicitCompletion":matches!(j.state,State::AwaitingCompletion|State::AwaitingCompensationCompletion|State::AwaitingSnapshotCompletion|State::AwaitingNormalBootCompletion|State::AwaitingHealthCompletion|State::CompletionPrepared|State::CommittingCompletion|State::OrdinaryPrepared|State::StoppingOrdinary|State::StartingOrdinary|State::VerifyingOrdinary),"cmCompensation":j.inverse.map(|i|json!({"id":i.id,"unit":i.unit,"target":i.target,"sha256":i.sha256,"issued":i.issued,"sourceStatus":i.source_proof().map(|s|s.status()).unwrap_or("UNVERIFIED"),"application":i.application,"snapshotSet":i.snapshot_set.map(|p|json!({"id":p.id,"issued":p.issued,"applied":p.applied,"receiptSha256":p.receipt_sha256}))}))}))}))
        }).await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("recovery/partial_source_tests.rs");

    pub(super) struct TempDir(pub(super) PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture(script_results: Vec<(String, i32)>) -> (Recovery, TempDir, PathBuf) {
        let dir = std::env::temp_dir().join(format!("rec-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(dir.join("state")).unwrap();
        fs::create_dir_all(dir.join("opt/kura/user/snapshots")).unwrap();
        // A recording fake systemctl whose results the test scripts per call.
        let script = dir.join("fake-systemctl");
        let log = dir.join("systemctl.log");
        let state = dir.join("unit.state");
        fs::write(&state, "active\n").unwrap();
        let mut body = format!("#!/bin/sh\necho \"$@\" >> {log:?}\n");
        for (pattern, code) in &script_results {
            body.push_str(&format!(
                "if [ \"$1\" = '{}' ]; then exit {}; fi\n",
                pattern, code
            ));
        }
        body.push_str(&format!("case \"$1\" in\n stop) printf inactive > {state:?};;\n start) printf active > {state:?};;\n show) s=$(cat {state:?}); echo LoadState=loaded; echo ActiveState=$s; if [ \"$s\" = active ]; then echo MainPID=123; else echo MainPID=0; fi;;\nesac\n"));
        body.push_str("exit 0\n");
        fs::write(&script, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let recovery = Recovery::open(
            dir.clone(),
            dir.join("state"),
            vec!["kura-probe.service".into()],
            PathBuf::from("opt/kura/user/snapshots"),
            Some(script.clone()),
        )
        .unwrap();
        (recovery, TempDir(dir), script)
    }

    pub(super) fn calls(dir: &TempDir) -> Vec<String> {
        let log = dir.0.join("systemctl.log");
        if !log.exists() {
            return Vec::new();
        }
        fs::read_to_string(log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    async fn upload_b64(recovery: &Recovery, id: &str, payload: &[u8]) -> String {
        use base64::Engine;
        recovery
            .upload(
                id,
                &base64::engine::general_purpose::STANDARD.encode(payload),
            )
            .await
            .unwrap()
            .to_string()
    }

    fn java_validator(dir: &TempDir) -> crate::snapshot_validation::Validator {
        let jar = dir.0.join("validator.jar");
        fs::write(&jar, b"test Java bundle contract").unwrap();
        fs::create_dir(dir.0.join("lib")).unwrap();
        fs::write(dir.0.join("lib/library.jar"), b"library").unwrap();
        let java = dir.0.join("java");
        let script = r#"#!/usr/bin/python3
import sys,json,hashlib,pathlib,os
root=pathlib.Path(__ROOT__)
with (root/'java.calls').open('a') as f:f.write('validate\n')
a=sys.argv; data=pathlib.Path(a[a.index('--input')+1]).read_bytes()
if data==b'bad':
 print('private-canary',file=sys.stderr);sys.exit(2)
report={'schema':1,'artifactSha256':hashlib.sha256(data).hexdigest(),'mode':'plain','configurationCount':1,'factoryCount':0,'propertyCount':1,'passwordValueCount':0,'authenticatedPasswordCount':0,'legacyPasswordCount':0,'keyAuthenticated':False,'fullRecoveryVerified':False}
if (root/'response.json').exists():report.update(json.loads((root/'response.json').read_text()))
print(json.dumps(report))
"#.replace("__ROOT__", &serde_json::to_string(&dir.0).unwrap());
        fs::write(&java, script).unwrap();
        fs::set_permissions(&java, fs::Permissions::from_mode(0o700)).unwrap();
        let config = dir.0.join("validator.json");
        fs::write(
            &config,
            serde_json::to_vec(&json!({"schema":1,"java":java,"jar":jar,
            "mode":"plain","passwordPolicy":"authenticated","key":{"kind":"default"}}))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        crate::snapshot_validation::Validator::new(config).unwrap()
    }
    pub(super) async fn prepared_java(recovery: &Recovery) -> Value {
        let uploaded: Value =
            serde_json::from_str(&upload_b64(recovery, "java-up", b"format-fixture").await)
                .unwrap();
        recovery
            .prepare(
                "java-up",
                uploaded["sha256"].as_str().unwrap(),
                "kura-probe.service",
            )
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn java_validation_proof_is_durable_and_rechecked_before_and_after_stop() {
        let (recovery, dir, _) = fixture(Vec::new());
        let validator = java_validator(&dir);
        let recovery = recovery.with_snapshot_validator(validator);
        let prepared = prepared_java(&recovery).await;
        assert_eq!(prepared["verification"], "snapshot-format-and-unit-only");
        assert_eq!(
            prepared["snapshotValidation"]["fullRecoveryVerified"],
            false
        );
        let proof = recovery.journal().unwrap().unwrap().snapshot_validation;
        assert!(proof.is_some());
        let done = recovery
            .execute(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(done["state"], "SUCCEEDED");
        assert_eq!(done["kuraRecoveryVerified"], false);
        assert_eq!(
            fs::read_to_string(dir.0.join("java.calls"))
                .unwrap()
                .lines()
                .count(),
            3
        );
        assert!(
            !recovery
                .status()
                .await
                .unwrap()
                .to_string()
                .contains("configuration_digest")
        );
    }
    #[tokio::test]
    async fn invalid_java_input_retains_staging_without_unit_action_or_transaction() {
        let (recovery, dir, _) = fixture(Vec::new());
        let validator = java_validator(&dir);
        let recovery = recovery.with_snapshot_validator(validator);
        let uploaded: Value =
            serde_json::from_str(&upload_b64(&recovery, "bad-up", b"bad").await).unwrap();
        let error = recovery
            .prepare(
                "bad-up",
                uploaded["sha256"].as_str().unwrap(),
                "kura-probe.service",
            )
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("private-canary"));
        assert!(calls(&dir).is_empty());
        assert!(recovery.journal().unwrap().is_none());
        assert!(dir.0.join("state/recovery/staging/bad-up").exists());
    }
    #[tokio::test]
    async fn changed_java_bundle_is_refused_before_second_launch_or_stop() {
        for file in ["validator.jar", "lib/library.jar", "java", "validator.json"] {
            let (recovery, dir, _) = fixture(Vec::new());
            let validator = java_validator(&dir);
            let recovery = recovery.with_snapshot_validator(validator);
            let prepared = prepared_java(&recovery).await;
            use std::io::Write;
            std::fs::OpenOptions::new()
                .append(true)
                .open(dir.0.join(file))
                .unwrap()
                .write_all(b"\nchanged")
                .unwrap();
            assert!(
                recovery
                    .execute(
                        prepared["transactionId"].as_str().unwrap(),
                        prepared["confirmToken"].as_str().unwrap()
                    )
                    .await
                    .is_err()
            );
            assert_eq!(
                fs::read_to_string(dir.0.join("java.calls"))
                    .unwrap()
                    .lines()
                    .count(),
                1
            );
            assert!(!calls(&dir).iter().any(|c| c.starts_with("stop ")));
            assert_eq!(recovery.journal().unwrap().unwrap().state, State::Validated);
        }
    }
    #[tokio::test]
    async fn lost_key_after_stop_compensates_without_publishing_and_preserves_staging() {
        let (recovery, dir, script) = fixture(Vec::new());
        let _validator = java_validator(&dir);
        let key = dir.0.join("key");
        fs::write(&key, b"0123456789abcdef").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let config = dir.0.join("validator.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        value["key"] = json!({"kind":"file","path":key});
        fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
        let validator = crate::snapshot_validation::Validator::new(config).unwrap();
        let recovery = recovery.with_snapshot_validator(validator);
        let prepared = prepared_java(&recovery).await;
        let original = fs::read_to_string(&script).unwrap();
        fs::write(
            &script,
            original.replace(
                "stop) printf",
                &format!("stop) chmod 0644 {:?}; printf", key),
            ),
        )
        .unwrap();
        assert!(
            recovery
                .execute(
                    prepared["transactionId"].as_str().unwrap(),
                    prepared["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        assert_eq!(recovery.journal().unwrap().unwrap().state, State::Failed);
        assert!(calls(&dir).iter().any(|c| c.starts_with("start ")));
        assert_eq!(
            fs::read_dir(dir.0.join("opt/kura/user/snapshots"))
                .unwrap()
                .count(),
            0
        );
        assert!(dir.0.join("state/recovery/staging/java-up").exists());
    }
    #[tokio::test]
    async fn invalid_or_overclaiming_java_reports_cannot_authorize_stop() {
        for report in [
            json!({"artifactSha256":"00"}),
            json!({"fullRecoveryVerified":true}),
            json!({"configurationCount":0}),
            json!({"legacyPasswordCount":1}),
            json!({"keyAuthenticated":true}),
            json!({"extra":"private-canary"}),
        ] {
            let (recovery, dir, _) = fixture(Vec::new());
            let validator = java_validator(&dir);
            let recovery = recovery.with_snapshot_validator(validator);
            fs::write(
                dir.0.join("response.json"),
                serde_json::to_vec(&report).unwrap(),
            )
            .unwrap();
            let uploaded: Value =
                serde_json::from_str(&upload_b64(&recovery, "java-up", b"fixture").await).unwrap();
            assert!(
                recovery
                    .prepare(
                        "java-up",
                        uploaded["sha256"].as_str().unwrap(),
                        "kura-probe.service"
                    )
                    .await
                    .is_err()
            );
            assert!(calls(&dir).is_empty());
        }
    }

    #[tokio::test]
    #[ignore = "requires explicit real Java tool and real Kura snapshot; unit control is a mock"]
    async fn actual_java_adapter_validates_real_snapshot_through_transaction() {
        let config = PathBuf::from(
            std::env::var("YOFC_TEST_RECOVERY_VALIDATOR").expect("explicit validator config"),
        );
        let snapshot = PathBuf::from(
            std::env::var("YOFC_TEST_RECOVERY_SNAPSHOT").expect("explicit real snapshot"),
        );
        let original = fs::read(&snapshot).unwrap();
        let (recovery, dir, _) = fixture(Vec::new());
        let validator = crate::snapshot_validation::Validator::new(config).unwrap();
        let recovery = recovery.with_snapshot_validator(validator);
        let uploaded: Value =
            serde_json::from_str(&upload_b64(&recovery, "real-java", &original).await).unwrap();
        let prepared = recovery
            .prepare(
                "real-java",
                uploaded["sha256"].as_str().unwrap(),
                "kura-probe.service",
            )
            .await
            .unwrap();
        assert!(
            prepared["snapshotValidation"]["configurationCount"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(prepared["verification"], "snapshot-format-and-unit-only");
        let done = recovery
            .execute(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(done["state"], "SUCCEEDED");
        assert_eq!(done["kuraRecoveryVerified"], false);
        assert_eq!(original, fs::read(snapshot).unwrap());
        let receipt = dir
            .0
            .join("state/recovery/receipts")
            .join(format!("{}.json", done["recoveryId"].as_str().unwrap()));
        let receipt: Value = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
        assert_eq!(
            receipt["snapshotValidation"],
            prepared["snapshotValidation"]
        );
        println!(
            "retained actual-Java/mock-unit fixture: {}",
            dir.0.display()
        );
        std::mem::forget(dir);
    }

    #[tokio::test]
    async fn changed_java_completion_receipt_blocks_without_undoing_committed_candidate() {
        let (recovery, dir, _) = fixture(Vec::new());
        let validator = java_validator(&dir);
        let recovery = recovery.with_snapshot_validator(validator);
        let prepared = prepared_java(&recovery).await;
        recovery
            .execute(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        let mut journal = recovery.journal().unwrap().unwrap();
        journal.state = State::Verifying;
        recovery.persist(&journal).unwrap();
        let path = recovery
            .0
            .state
            .join("receipts")
            .join(format!("{}.json", journal.id));
        let original = fs::read(&path).unwrap();
        let calls_before = calls(&dir);
        recovery.recover().await.unwrap();
        assert_eq!(recovery.journal().unwrap().unwrap().state, State::Succeeded);
        journal.state = State::Verifying;
        recovery.persist(&journal).unwrap();
        let mut receipt: Value = serde_json::from_slice(&original).unwrap();
        receipt["snapshotValidation"]["configurationCount"] = json!(2);
        durable::json(&path, &receipt).unwrap();
        recovery.recover().await.unwrap();
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        assert!(dir.0.join(&journal.target).exists());
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|c| c.starts_with("stop "))
                .count(),
            calls_before
                .iter()
                .filter(|c| c.starts_with("stop "))
                .count()
        );
        assert!(
            recovery
                .prepare(
                    "next",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "kura-probe.service"
                )
                .await
                .is_err()
        );
        use base64::Engine;
        assert!(
            recovery
                .upload(
                    "blocked-upload",
                    &base64::engine::general_purpose::STANDARD.encode(b"blocked")
                )
                .await
                .is_err()
        );
        assert!(!dir.0.join("state/recovery/staging/blocked-upload").exists());
    }

    #[tokio::test]
    async fn full_lifecycle_places_next_snapshot_id_and_backs_up() {
        let (recovery, dir, _script) = fixture(Vec::new());
        fs::write(
            dir.0.join("opt/kura/user/snapshots/snapshot_7.xml"),
            b"old-7",
        )
        .unwrap();
        let payload = b"<snapshot version=\"new\"/>";
        let uploaded: Value =
            serde_json::from_str(&upload_b64(&recovery, "up-1", payload).await).unwrap();
        let sha = uploaded["sha256"].as_str().unwrap().to_string();
        let prepared = recovery
            .prepare("up-1", &sha, "kura-probe.service")
            .await
            .unwrap();
        assert_eq!(prepared["state"], "VALIDATED");
        let done = recovery
            .execute(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(done["state"], "SUCCEEDED");
        assert!(done["target"].as_str().unwrap().ends_with("snapshot_8.xml"));
        let placed = fs::read(dir.0.join("opt/kura/user/snapshots/snapshot_8.xml")).unwrap();
        assert_eq!(placed, payload);
        assert!(
            dir.0
                .join("state/recovery/backups")
                .read_dir()
                .map(|mut d| d.next().is_some())
                .unwrap_or(false),
            "backup directory recorded"
        );
        let calls = calls(&dir);
        assert!(calls.iter().any(|c| c.contains("start kura-probe.service")));
        let status = recovery.status().await.unwrap();
        assert_eq!(status["transaction"]["state"], "SUCCEEDED");
    }

    #[tokio::test]
    async fn hash_mismatch_unknown_unit_and_double_prepare_refused() {
        let (recovery, _dir, _script) = fixture(Vec::new());
        let uploaded: Value =
            serde_json::from_str(&upload_b64(&recovery, "up-2", b"payload").await).unwrap();
        let sha = uploaded["sha256"].as_str().unwrap().to_string();
        assert!(
            recovery
                .prepare("up-2", &format!("0{}", &sha[1..]), "kura-probe.service")
                .await
                .is_err()
        );
        assert!(
            recovery
                .prepare("up-2", &sha, "other.service")
                .await
                .is_err()
        );
        // Disabled when no units are configured.
        let disabled = Recovery::open(
            std::env::temp_dir().join(format!("rec-x-{}", uuid::Uuid::new_v4())),
            std::env::temp_dir().join(format!("rec-x-{}", uuid::Uuid::new_v4())),
            Vec::new(),
            PathBuf::from("opt/x"),
            None,
        )
        .unwrap();
        assert!(disabled.upload("u", "YQ==").await.is_err());
    }

    #[tokio::test]
    async fn stop_failure_compensates_without_touching_snapshots() {
        // First systemctl call (stop) fails.
        let (recovery, dir, _script) = fixture(vec![("stop".into(), 1)]);
        let payload = b"candidate";
        let uploaded: Value =
            serde_json::from_str(&upload_b64(&recovery, "up-3", payload).await).unwrap();
        let prepared = recovery
            .prepare(
                "up-3",
                uploaded["sha256"].as_str().unwrap(),
                "kura-probe.service",
            )
            .await
            .unwrap();
        let error = recovery
            .execute(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("compensated"), "{error}");
        let status = recovery.status().await.unwrap();
        assert_eq!(status["transaction"]["state"], "FAILED");
        assert!(
            !dir.0
                .join("opt/kura/user/snapshots/snapshot_1.xml")
                .exists()
        );
    }

    #[tokio::test]
    async fn interrupted_transaction_is_compensated_at_startup() {
        let (recovery, dir, _) = fixture(Vec::new());
        let payload = b"half";
        let uploaded: Value =
            serde_json::from_str(&upload_b64(&recovery, "up-4", payload).await).unwrap();
        recovery
            .prepare(
                "up-4",
                uploaded["sha256"].as_str().unwrap(),
                "kura-probe.service",
            )
            .await
            .unwrap();
        let mut j = recovery.journal().unwrap().unwrap();
        let backup = dir.0.join("state/recovery").join(&j.backup_dir);
        durable::directory(&backup).unwrap();
        durable::json(
            &backup.join("manifest.json"),
            &Manifest {
                schema_version: 2,
                files: j.base.clone(),
            },
        )
        .unwrap();
        j.backup_ready = true;
        j.state = State::Committing;
        recovery.persist(&j).unwrap();
        durable::publish_new(&dir.0.join(&j.target), payload, j.target_metadata.unwrap()).unwrap();
        recovery.recover().await.unwrap();
        assert_eq!(
            recovery.status().await.unwrap()["transaction"]["state"],
            "FAILED"
        );
        assert!(!dir.0.join(&j.target).exists());
    }
    async fn interrupted_fixture() -> (Recovery, TempDir, Journal) {
        let (recovery, dir, _) = fixture(Vec::new());
        let original = dir.0.join("opt/kura/user/snapshots/snapshot_7.xml");
        fs::write(&original, b"original").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o640)).unwrap();
        let upload: Value =
            serde_json::from_str(&upload_b64(&recovery, "crash", b"candidate").await).unwrap();
        recovery
            .prepare(
                "crash",
                upload["sha256"].as_str().unwrap(),
                "kura-probe.service",
            )
            .await
            .unwrap();
        let mut j = recovery.journal().unwrap().unwrap();
        let backup = recovery.0.state.join(&j.backup_dir);
        durable::directory(&backup).unwrap();
        for file in &j.base {
            durable::write(
                &backup.join(&file.name),
                &fs::read(original.with_file_name(&file.name)).unwrap(),
                FileMetadata::private(),
            )
            .unwrap();
        }
        durable::json(
            &backup.join("manifest.json"),
            &Manifest {
                schema_version: 2,
                files: j.base.clone(),
            },
        )
        .unwrap();
        j.backup_ready = true;
        j.state = State::Committing;
        recovery.persist(&j).unwrap();
        durable::publish_new(
            &dir.0.join(&j.target),
            b"candidate",
            j.target_metadata.unwrap(),
        )
        .unwrap();
        (recovery, dir, j)
    }
    #[tokio::test]
    async fn compensation_preserves_unknown_files_and_blocks_new_prepare_until_operator_retry() {
        let (recovery, dir, j) = interrupted_fixture().await;
        let foreign = dir.0.join("opt/kura/user/snapshots/snapshot_99.xml");
        fs::write(&foreign, b"external").unwrap();
        recovery.recover().await.unwrap();
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        assert_eq!(fs::read(&foreign).unwrap(), b"external");
        assert!(dir.0.join(&j.target).exists());
        assert_eq!(
            fs::read_to_string(dir.0.join("unit.state")).unwrap(),
            "inactive"
        );
        assert!(
            recovery
                .prepare("crash", &j.sha256, "kura-probe.service")
                .await
                .is_err()
        );
        fs::remove_file(foreign).unwrap();
        let result = recovery.rollback(&j.id, &j.confirm_token).await.unwrap();
        assert_eq!(result["state"], "FAILED");
        assert!(!dir.0.join(&j.target).exists());
        assert_eq!(
            fs::read_to_string(dir.0.join("unit.state")).unwrap(),
            "active"
        );
    }
    #[tokio::test]
    async fn compensation_checks_all_backups_before_deleting_candidate_and_preserves_metadata() {
        let (recovery, dir, j) = interrupted_fixture().await;
        let old = dir.0.join("opt/kura/user/snapshots/snapshot_7.xml");
        fs::remove_file(&old).unwrap();
        let backup = recovery.0.state.join(&j.backup_dir).join("snapshot_7.xml");
        fs::write(&backup, b"corrupt").unwrap();
        recovery.recover().await.unwrap();
        assert!(dir.0.join(&j.target).exists());
        assert!(!old.exists());
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        fs::write(&backup, b"original").unwrap();
        recovery.rollback(&j.id, &j.confirm_token).await.unwrap();
        let (bytes, metadata) = durable::read(&old, 32).unwrap();
        assert_eq!(bytes, b"original");
        assert_eq!(metadata, j.base[0].metadata);
    }
    #[tokio::test]
    async fn drifted_candidate_is_never_removed_and_completion_receipt_is_not_undone() {
        let (recovery, dir, j) = interrupted_fixture().await;
        fs::write(dir.0.join(&j.target), b"administrator edit").unwrap();
        recovery.recover().await.unwrap();
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        assert_eq!(
            fs::read(dir.0.join(&j.target)).unwrap(),
            b"administrator edit"
        );
        let (recovery, dir, _) = interrupted_fixture().await;
        let mut j = recovery.journal().unwrap().unwrap();
        j.state = State::Verifying;
        recovery.persist(&j).unwrap();
        durable::json(&recovery.0.state.join("receipts").join(format!("{}.json",j.id)),&json!({"schema":"yofc.agent.recovery.v2","recoveryId":j.id,"sha256":j.sha256,"snapshot":j.target})).unwrap();
        recovery.recover().await.unwrap();
        assert_eq!(recovery.journal().unwrap().unwrap().state, State::Succeeded);
        assert!(dir.0.join(&j.target).exists());
    }
    #[tokio::test]
    async fn slow_system_action_keeps_async_queries_responsive() {
        let (recovery, dir, script) = fixture(Vec::new());
        let text = fs::read_to_string(&script)
            .unwrap()
            .replace(" stop) printf", " stop) sleep 1; printf");
        fs::write(&script, text).unwrap();
        let upload: Value =
            serde_json::from_str(&upload_b64(&recovery, "slow", b"candidate").await).unwrap();
        let prepared = recovery
            .prepare(
                "slow",
                upload["sha256"].as_str().unwrap(),
                "kura-probe.service",
            )
            .await
            .unwrap();
        let worker = recovery.clone();
        let task = tokio::spawn(async move {
            worker
                .execute(
                    prepared["transactionId"].as_str().unwrap(),
                    prepared["confirmToken"].as_str().unwrap(),
                )
                .await
        });
        // Wait for the actual blocking phase, not a fixed scheduler delay.
        // Every status query must still meet the original responsiveness bound.
        let value = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let value = tokio::time::timeout(Duration::from_millis(200), recovery.status())
                    .await
                    .unwrap()
                    .unwrap();
                if value["transaction"]["state"] == "STOPPING" {
                    break value;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(value["transaction"]["state"], "STOPPING");
        task.await.unwrap().unwrap();
        drop(dir);
    }
    fn controlled_fixture() -> (Recovery, TempDir) {
        let (recovery, dir, script) = fixture(Vec::new());
        let validator = java_validator(&dir);
        let request = dir.0.join("startup/request.properties");
        durable::directory(request.parent().unwrap()).unwrap();
        let receipts = dir.0.join("application");
        durable::directory(&receipts).unwrap();
        let pinned = dir.0.join("profile");
        fs::write(&pinned, b"fixed startup profile").unwrap();
        let config = dir.0.join("startup.json");
        durable::json(&config,&json!({"schema":1,"unit":"kura-probe.service","requestPath":request,
            "receiptDirectory":receipts,"timeoutSeconds":1,"profileFiles":[{"path":pinned,"sha256":durable::hash(b"fixed startup profile")}]})).unwrap();
        // Test-only fake unit emits the exact Java receipt contract. Real Kura is validated separately.
        let hook = dir.0.join("emit-receipt.py");
        fs::write(&hook,format!(r#"import pathlib,hashlib,os
root=pathlib.Path({root})
p=root/'startup/request.properties'
if p.exists() and not (root/'no-receipt').exists():
 d=dict(line.split('=',1) for line in p.read_text().splitlines());r=pathlib.Path(d['receipt.path'])
 backup=b'encrypted-CM-contract';pathlib.Path(str(r)+'.cm-backup.aes').write_bytes(backup)
 pathlib.Path(str(r)+'.bundle-levels').write_text('schema=1\n22=5\n')
 ident='rec-00000000-0000-0000-0000-000000000000' if (root/'wrong-id').exists() else d['restore.id']
 r.write_text('schema=1\nstatus=CM_APPLIED\nrestore.id='+ident+'\nsnapshot.sha256='+d['snapshot.sha256']+'\nfullRecoveryVerified=false\nbusinessHealth=UNVERIFIED\nbackup.sha256='+hashlib.sha256(backup).hexdigest()+'\nreplaced.count=1\nreplaced.0=cGlk\ncreated.count=0\ndeleted.count=0\n')
 for f in [r,pathlib.Path(str(r)+'.cm-backup.aes'),pathlib.Path(str(r)+'.bundle-levels')]:os.chmod(f,0o600)
"#,root=serde_json::to_string(&dir.0).unwrap())).unwrap();
        let body = fs::read_to_string(&script).unwrap();
        fs::write(
            &script,
            body.replace(
                " start) printf active",
                &format!(" start) /usr/bin/python3 {hook:?}; printf active"),
            ),
        )
        .unwrap();
        let startup = crate::controlled_startup::Startup::new(config).unwrap();
        (
            recovery
                .with_snapshot_validator(validator)
                .with_controlled_startup(startup)
                .unwrap(),
            dir,
        )
    }
    #[tokio::test]
    async fn controlled_application_is_nonterminal_durable_and_does_not_replay_on_agent_restart() {
        let (recovery, dir) = controlled_fixture();
        let prepared = prepared_java(&recovery).await;
        let result = recovery
            .execute(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(result["state"], "AWAITING_COMPLETION");
        assert_eq!(result["kuraRecoveryVerified"], false);
        let j = recovery.journal().unwrap().unwrap();
        assert!(j.controlled_issued && j.cm_application.is_some());
        assert!(recovery.staging_path(&j.upload_id).unwrap().exists());
        assert!(
            !recovery
                .0
                .state
                .join("receipts")
                .join(format!("{}.json", j.id))
                .exists()
        );
        assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
        let calls_before = calls(&dir);
        recovery.recover().await.unwrap();
        assert_eq!(
            calls(&dir)
                .into_iter()
                .filter(|c| !c.starts_with("show "))
                .collect::<Vec<_>>(),
            calls_before
                .into_iter()
                .filter(|c| !c.starts_with("show "))
                .collect::<Vec<_>>()
        );
        assert!(recovery.upload("blocked", "eA==").await.is_err());
        let original = fs::read(dir.0.join(&j.target)).unwrap();
        recovery.rollback(&j.id, &j.confirm_token).await.unwrap();
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        assert_eq!(fs::read(dir.0.join(&j.target)).unwrap(), original);
        assert!(j.controlled_startup.unwrap().request_path.exists());
    }
    #[tokio::test]
    async fn controlled_missing_or_wrong_receipt_stops_and_preserves_cm_candidate_and_request() {
        for marker in ["no-receipt", "wrong-id"] {
            let (recovery, dir) = controlled_fixture();
            fs::write(dir.0.join(marker), b"x").unwrap();
            let p = prepared_java(&recovery).await;
            assert!(
                recovery
                    .execute(
                        p["transactionId"].as_str().unwrap(),
                        p["confirmToken"].as_str().unwrap()
                    )
                    .await
                    .is_err()
            );
            let j = recovery.journal().unwrap().unwrap();
            assert_eq!(j.state, State::RecoveryRequired);
            assert!(dir.0.join(&j.target).exists());
            assert!(j.controlled_startup.unwrap().request_path.exists());
            assert!(!recovery.unit(&j.unit).unwrap().0);
            let previous = calls(&dir);
            assert!(recovery.recover().await.is_err());
            assert_eq!(calls(&dir), previous);
        }
    }
    #[tokio::test]
    async fn controlled_profile_drift_prevents_stop_and_crash_after_publication_never_uses_snapshot_compensation()
     {
        let (recovery, dir) = controlled_fixture();
        let p = prepared_java(&recovery).await;
        fs::write(dir.0.join("profile"), b"drift").unwrap();
        let previous = calls(&dir);
        assert!(
            recovery
                .execute(
                    p["transactionId"].as_str().unwrap(),
                    p["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        assert_eq!(calls(&dir), previous);
        fs::write(dir.0.join("profile"), b"fixed startup profile").unwrap();
        let mut j = recovery.journal().unwrap().unwrap();
        j.state = State::Starting;
        j.controlled_issued = true;
        recovery.persist(&j).unwrap();
        assert!(recovery.recover().await.is_err());
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        assert!(!recovery.unit(&j.unit).unwrap().0);
    }
    #[tokio::test]
    async fn controlled_changed_backup_on_agent_restart_blocks_and_retains_receipt() {
        let (recovery, dir) = controlled_fixture();
        let p = prepared_java(&recovery).await;
        recovery
            .execute(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        let j = recovery.journal().unwrap().unwrap();
        let req = j.controlled_startup.unwrap();
        let receipt = fs::read(&req.receipt_path).unwrap();
        fs::write(
            format!("{}.cm-backup.aes", req.receipt_path.display()),
            b"changed",
        )
        .unwrap();
        assert!(recovery.recover().await.is_err());
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        assert_eq!(fs::read(req.receipt_path).unwrap(), receipt);
        assert!(dir.0.join(j.target).exists());
    }
    #[tokio::test]
    #[ignore = "requires explicit retained fixture and native IDEA controlled Kura startup"]
    async fn actual_controlled_kura_startup_with_explicit_fixture() {
        let file = PathBuf::from(
            std::env::var("YOFC_TEST_CONTROLLED_KURA").expect("explicit fixture JSON"),
        );
        let spec: Value = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
        let path = |key: &str| PathBuf::from(spec[key].as_str().expect("fixture path"));
        let unit = spec["unit"].as_str().unwrap();
        let validator =
            crate::snapshot_validation::Validator::new(path("validatorConfig")).unwrap();
        let startup = crate::controlled_startup::Startup::new(path("startupConfig")).unwrap();
        let recovery = Recovery::open(
            "/".into(),
            path("state"),
            vec![unit.into()],
            path("snapshots"),
            Some(path("systemctl")),
        )
        .unwrap()
        .with_snapshot_validator(validator)
        .with_controlled_startup(startup)
        .unwrap();
        assert!(
            recovery.journal().unwrap().is_none(),
            "never replay a retained transaction"
        );
        let data = fs::read(path("payload")).unwrap();
        upload_b64(&recovery, "native-kura-input", &data).await;
        let prepared = recovery
            .prepare("native-kura-input", &durable::hash(&data), unit)
            .await
            .unwrap();
        durable::json(&path("preparedRecord"), &prepared).unwrap();
        let done = recovery
            .execute(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(done["state"], "AWAITING_COMPLETION");
        assert_eq!(done["kuraRecoveryVerified"], false);
        let j = recovery.journal().unwrap().unwrap();
        assert!(j.cm_application.is_some());
        assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
        recovery.recover().await.unwrap();
        assert!(recovery.upload("blocked", "eA==").await.is_err());
        durable::json(&path("resultRecord"),&json!({"done":done,"status":recovery.status().await.unwrap(),"realJava":true,
            "nativeKuraStartupExternallyVerified":true,"agentRestartEvidenceRecheck":true,"globalWriteBlocked":true,
            "unitAdapter":"test-only native IDEA coordination, not systemd","fullRecoveryVerified":false})).unwrap();
    }
    #[tokio::test]
    async fn controlled_compensation_evidence_is_exact_and_drift_stays_blocked() {
        for suffix in [".cm-applied.aes", ".cm-intended.aes", ".cm-plan.properties"] {
            let (recovery, dir) = controlled_fixture();
            let hook = dir.0.join("emit-receipt.py");
            let mut script = fs::read_to_string(&hook).unwrap();
            script.push_str(r#"
if p.exists() and not (root/'no-receipt').exists():
 applied=b'actual CM ciphertext';intended=b'intended CM ciphertext'
 pathlib.Path(str(r)+'.cm-applied.aes').write_bytes(applied)
 pathlib.Path(str(r)+'.cm-intended.aes').write_bytes(intended)
 pathlib.Path(str(r)+'.cm-plan.properties').write_text('schema=1\nrestore.id='+d['restore.id']+'\nsnapshot.sha256='+d['snapshot.sha256']+'\nbackup.sha256='+hashlib.sha256(backup).hexdigest()+'\nintended.sha256='+hashlib.sha256(intended).hexdigest()+'\n')
 r.write_text(r.read_text()+'applied.sha256='+hashlib.sha256(applied).hexdigest()+'\n')
 for ext in ['.cm-applied.aes','.cm-intended.aes','.cm-plan.properties']:os.chmod(pathlib.Path(str(r)+ext),0o600)
"#);
            fs::write(hook, script).unwrap();
            let p = prepared_java(&recovery).await;
            recovery
                .execute(
                    p["transactionId"].as_str().unwrap(),
                    p["confirmToken"].as_str().unwrap(),
                )
                .await
                .unwrap();
            let j = recovery.journal().unwrap().unwrap();
            assert!(j.cm_application.as_ref().unwrap().compensation.is_some());
            let req = j.controlled_startup.unwrap();
            let receipt = fs::read(&req.receipt_path).unwrap();
            fs::write(
                format!("{}{suffix}", req.receipt_path.display()),
                b"changed",
            )
            .unwrap();
            assert!(recovery.recover().await.is_err());
            assert_eq!(
                recovery.journal().unwrap().unwrap().state,
                State::RecoveryRequired
            );
            assert_eq!(fs::read(req.receipt_path).unwrap(), receipt);
            assert!(dir.0.join(j.target).exists());
        }
    }
    pub(super) fn inverse_fixture() -> (Recovery, TempDir) {
        let (mut recovery, dir) = controlled_fixture();
        let hook = dir.0.join("emit-receipt.py");
        let mut body = fs::read_to_string(&hook).unwrap()
            .replace("import pathlib,hashlib,os", "import pathlib,hashlib,os,sys")
            .replace("p=root/'startup/request.properties'", "p=root/('inverse/request.properties' if len(sys.argv)>1 else 'startup/request.properties')");
        body.push_str(r#"
if p.exists() and not (root/'no-receipt').exists():
 applied=b'actual CM ciphertext';intended=b'intended CM ciphertext'
 pathlib.Path(str(r)+'.cm-applied.aes').write_bytes(applied)
 pathlib.Path(str(r)+'.cm-intended.aes').write_bytes(intended)
 pathlib.Path(str(r)+'.cm-plan.properties').write_text('schema=1\nrestore.id='+d['restore.id']+'\nsnapshot.sha256='+d['snapshot.sha256']+'\nbackup.sha256='+hashlib.sha256(backup).hexdigest()+'\nintended.sha256='+hashlib.sha256(intended).hexdigest()+'\n')
 r.write_text(r.read_text()+'applied.sha256='+hashlib.sha256(applied).hexdigest()+'\n')
 for ext in ['.cm-applied.aes','.cm-intended.aes','.cm-plan.properties']:os.chmod(pathlib.Path(str(r)+ext),0o600)
"#);
        fs::write(hook, body).unwrap();
        let script = dir.0.join("fake-systemctl");
        fs::write(&script, format!(r#"#!/usr/bin/python3
import pathlib,sys,subprocess
root=pathlib.Path({root});action,unit=sys.argv[1:3];p=root/(unit+'.state')
with (root/'systemctl.log').open('a') as f:f.write(' '.join(sys.argv[1:])+'\n')
if action=='stop':p.write_text('inactive')
if action=='start':
 args=['/usr/bin/python3',str(root/'emit-receipt.py')]
 if unit=='kura-inverse.service':args.append('inverse')
 subprocess.run(args,check=True);p.write_text('active')
if action=='show':
 active=p.exists() and p.read_text()=='active'
 print('LoadState=loaded\nActiveState='+('active' if active else 'inactive')+'\nMainPID='+('123' if active else '0'))
"#,root=serde_json::to_string(&dir.0).unwrap())).unwrap();
        fs::write(dir.0.join("kura-probe.service.state"), "active").unwrap();
        durable::directory(&dir.0.join("inverse")).unwrap();
        let config = dir.0.join("inverse.json");
        let pinned = dir.0.join("profile");
        durable::json(&config,&json!({"schema":1,"unit":"kura-inverse.service",
            "requestPath":dir.0.join("inverse/request.properties"),"receiptDirectory":dir.0.join("application"),
            "timeoutSeconds":1,"profileFiles":[{"path":pinned,"sha256":durable::hash(b"fixed startup profile")}]})).unwrap();
        Arc::get_mut(&mut recovery.0)
            .unwrap()
            .units
            .push("kura-inverse.service".into());
        (
            recovery
                .with_inverse_startup(crate::controlled_startup::Startup::new(config).unwrap())
                .unwrap(),
            dir,
        )
    }
    async fn forward_for_inverse(recovery: &Recovery) -> Value {
        let p = prepared_java(recovery).await;
        recovery
            .execute(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        p
    }
    #[tokio::test]
    async fn inverse_is_separately_authorized_nonterminal_and_reopens_without_replay() {
        let (recovery, dir) = inverse_fixture();
        let p = forward_for_inverse(&recovery).await;
        let j = recovery.journal().unwrap().unwrap();
        let request = j.controlled_startup.as_ref().unwrap().request_path.clone();
        let original = fs::read(&request).unwrap();
        let before = calls(&dir);
        assert!(
            recovery
                .prepare_compensation(p["transactionId"].as_str().unwrap(), "wrong")
                .await
                .is_err()
        );
        assert_eq!(calls(&dir), before);
        let inverse = recovery
            .prepare_compensation(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(inverse["transactionId"], p["transactionId"]);
        assert!(!dir.0.join("inverse/request.properties").exists());
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|c| c.starts_with("start "))
                .count(),
            1
        );
        assert!(
            recovery
                .execute_compensation(
                    inverse["transactionId"].as_str().unwrap(),
                    p["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        let done = recovery
            .execute_compensation(
                inverse["transactionId"].as_str().unwrap(),
                inverse["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(done["state"], "AWAITING_COMPENSATION_COMPLETION");
        assert_eq!(done["kuraRecoveryVerified"], false);
        assert_eq!(original, fs::read(&request).unwrap());
        let manifest = fs::read_to_string(dir.0.join("inverse/request.properties")).unwrap();
        assert!(manifest.contains("snapshot.mode=aes-gcm\n"));
        assert!(manifest.contains("compensation.source.plan.sha256="));
        let oldcalls = calls(&dir);
        recovery.recover().await.unwrap();
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|c| c.starts_with("start "))
                .count(),
            oldcalls.iter().filter(|c| c.starts_with("start ")).count()
        );
        assert!(
            recovery
                .execute_compensation(
                    inverse["transactionId"].as_str().unwrap(),
                    inverse["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        assert!(recovery.upload("blocked", "eA==").await.is_err());
        let status = recovery.status().await.unwrap();
        assert_eq!(status["transaction"]["awaitsExplicitCompletion"], true);
        assert!(status.to_string().find("confirm_token").is_none());
    }
    #[tokio::test]
    async fn inverse_source_or_snapshot_drift_rejects_before_publication_or_unit_action() {
        for drift in ["source", "snapshot", "anchor"] {
            let (recovery, dir) = inverse_fixture();
            let p = forward_for_inverse(&recovery).await;
            let inverse = recovery
                .prepare_compensation(
                    p["transactionId"].as_str().unwrap(),
                    p["confirmToken"].as_str().unwrap(),
                )
                .await
                .unwrap();
            let j = recovery.journal().unwrap().unwrap();
            if drift == "source" {
                fs::write(
                    format!(
                        "{}.cm-applied.aes",
                        j.controlled_startup
                            .as_ref()
                            .unwrap()
                            .receipt_path
                            .display()
                    ),
                    b"drift",
                )
                .unwrap();
            } else if drift == "anchor" {
                fs::write(
                    recovery.0.state.join("receipts").join(format!(
                        "{}.inverse-source.json",
                        inverse["transactionId"].as_str().unwrap()
                    )),
                    b"drift",
                )
                .unwrap();
            } else {
                fs::write(
                    dir.0.join("opt/kura/user/snapshots/foreign.xml"),
                    b"foreign",
                )
                .unwrap();
            }
            let before = calls(&dir);
            assert!(
                recovery
                    .execute_compensation(
                        inverse["transactionId"].as_str().unwrap(),
                        inverse["confirmToken"].as_str().unwrap()
                    )
                    .await
                    .is_err()
            );
            assert_eq!(before, calls(&dir));
            assert!(!dir.0.join("inverse/request.properties").exists());
            assert!(!dir.0.join(&j.inverse.as_ref().unwrap().target).exists());
        }
    }
    #[tokio::test]
    async fn inverse_crash_intent_stops_both_units_and_never_resends() {
        let (recovery, dir) = inverse_fixture();
        let p = forward_for_inverse(&recovery).await;
        let inverse = recovery
            .prepare_compensation(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        let mut j = recovery.journal().unwrap().unwrap();
        j.inverse.as_mut().unwrap().issued = true;
        j.state = State::Compensating;
        recovery.persist(&j).unwrap();
        assert!(recovery.recover().await.is_err());
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        assert!(calls(&dir).iter().any(|c| c == "stop kura-probe.service"));
        assert!(calls(&dir).iter().any(|c| c == "stop kura-inverse.service"));
        assert!(!dir.0.join("inverse/request.properties").exists());
        assert!(
            recovery
                .execute_compensation(
                    inverse["transactionId"].as_str().unwrap(),
                    inverse["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        assert!(recovery.upload("blocked", "eA==").await.is_err());
    }
    #[tokio::test]
    async fn inverse_disabled_and_legacy_application_cannot_gain_authorization() {
        let (recovery, _dir) = controlled_fixture();
        let p = forward_for_inverse(&recovery).await;
        assert!(
            recovery
                .prepare_compensation(
                    p["transactionId"].as_str().unwrap(),
                    p["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        let (recovery, dir) = inverse_fixture();
        let p = forward_for_inverse(&recovery).await;
        let mut j = recovery.journal().unwrap().unwrap();
        j.cm_application.as_mut().unwrap().compensation = None;
        recovery.persist(&j).unwrap();
        assert!(
            recovery
                .prepare_compensation(
                    p["transactionId"].as_str().unwrap(),
                    p["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        assert!(!dir.0.join("inverse/request.properties").exists());
    }
    #[tokio::test]
    #[ignore = "requires a fresh explicit fixture and two native IDEA startup configurations"]
    async fn actual_inverse_kura_startup_with_explicit_fixture() {
        let spec: Value = serde_json::from_slice(
            &fs::read(std::env::var("YOFC_TEST_INVERSE_KURA").expect("explicit new fixture"))
                .unwrap(),
        )
        .unwrap();
        let path = |key: &str| PathBuf::from(spec[key].as_str().expect("fixture path"));
        let unit = spec["unit"].as_str().unwrap();
        let inverse_unit = spec["inverseUnit"].as_str().unwrap();
        let mut units = vec![unit.into(), inverse_unit.into()];
        if let Some(normal) = spec["normalUnit"].as_str() {
            units.push(normal.into());
        }
        if let Some(ordinary) = spec["ordinaryUnit"].as_str() {
            units.push(ordinary.into());
        }
        let recovery = Recovery::open(
            "/".into(),
            path("state"),
            units,
            path("snapshots"),
            Some(path("systemctl")),
        )
        .unwrap()
        .with_snapshot_validator(
            crate::snapshot_validation::Validator::new(path("validatorConfig")).unwrap(),
        )
        .with_controlled_startup(
            crate::controlled_startup::Startup::new(path("startupConfig")).unwrap(),
        )
        .unwrap()
        .with_inverse_startup(
            crate::controlled_startup::Startup::new(path("inverseStartupConfig")).unwrap(),
        )
        .unwrap();
        let recovery = if spec.get("normalUnit").is_some() {
            recovery
                .with_normal_startup(
                    crate::controlled_startup::Startup::new(path("normalStartupConfig")).unwrap(),
                )
                .unwrap()
        } else {
            recovery
        };
        let recovery = if spec.get("normalValidatorConfig").is_some() {
            recovery
                .with_normal_snapshot_validator(
                    crate::snapshot_validation::Validator::new(path("normalValidatorConfig"))
                        .unwrap(),
                )
                .unwrap()
        } else {
            recovery
        };
        let recovery = if spec.get("healthConfig").is_some() {
            recovery.with_health_profile(path("healthConfig")).unwrap()
        } else {
            recovery
        };
        let recovery = if spec.get("completionConfig").is_some() {
            recovery
                .with_completion_profile(path("completionConfig"))
                .unwrap()
        } else {
            recovery
        };
        let recovery = if spec.get("ordinaryStartupConfig").is_some() {
            recovery
                .with_ordinary_profile(path("ordinaryStartupConfig"))
                .unwrap()
                .with_ordinary_snapshot_validator(
                    crate::snapshot_validation::Validator::new(path("ordinaryValidatorConfig"))
                        .unwrap(),
                )
                .unwrap()
        } else {
            recovery
        };
        let mut local =
            crate::local::Local::new(unsafe { libc::geteuid() }, unsafe { libc::geteuid() });
        local.recovery = Some(recovery.clone());
        let server = if spec.get("socket").is_some() {
            let listener = local.listen(&path("socket")).await.unwrap();
            Some(tokio::spawn(local.clone().serve(listener)))
        } else {
            None
        };
        assert!(
            recovery.journal().unwrap().is_none(),
            "never replay a retained transaction"
        );
        let data = fs::read(path("payload")).unwrap();
        upload_b64(&recovery, "native-inverse-input", &data).await;
        let prepared = recovery
            .prepare("native-inverse-input", &durable::hash(&data), unit)
            .await
            .unwrap();
        durable::json(&path("preparedRecord"), &prepared).unwrap();
        let done = recovery
            .execute(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(done["state"], "AWAITING_COMPLETION");
        recovery.recover().await.unwrap();
        durable::json(&path("resultRecord"), &done).unwrap();
        durable::publish_new(
            &path("beforeInverse"),
            b"forward proven; await native browser verification",
            FileMetadata::private(),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(300);
        while !path("continueInverse").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "explicit new-fixture continuation missing"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let inverse = recovery
            .prepare_compensation(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        durable::json(&path("inversePreparedRecord"), &inverse).unwrap();
        let done = recovery
            .execute_compensation(
                inverse["transactionId"].as_str().unwrap(),
                inverse["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(done["state"], "AWAITING_COMPENSATION_COMPLETION");
        recovery.recover().await.unwrap();
        assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
        assert!(recovery.upload("blocked", "eA==").await.is_err());
        durable::json(&path("inverseResultRecord"),&json!({"done":done,"status":recovery.status().await.unwrap(),"realJava":true,"nativeUnitAdapter":"test-only IDEA coordination; not systemd","fullRecoveryVerified":false})).unwrap();
        if spec.get("snapshotSetResultRecord").is_some() {
            durable::publish_new(
                &path("beforeSnapshotSet"),
                b"inverse proven; await original GWT verification",
                FileMetadata::private(),
            )
            .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(300);
            while !path("continueSnapshotSet").exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "new fixture snapshot continuation missing"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let set = recovery
                .prepare_snapshot_set(
                    inverse["transactionId"].as_str().unwrap(),
                    inverse["confirmToken"].as_str().unwrap(),
                )
                .await
                .unwrap();
            durable::json(&path("snapshotSetPreparedRecord"), &set).unwrap();
            let done = recovery
                .execute_snapshot_set(
                    set["transactionId"].as_str().unwrap(),
                    set["confirmToken"].as_str().unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(done["state"], "AWAITING_SNAPSHOT_COMPLETION");
            recovery.recover().await.unwrap();
            assert!(recovery.upload("snapshot-blocked", "eA==").await.is_err());
            assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
            durable::json(&path("snapshotSetResultRecord"),&json!({"done":done,"status":recovery.status().await.unwrap(),"actualKuraCmInverse":true,"normalBootVerified":false})).unwrap();
            if spec.get("normalResultRecord").is_some() {
                let normal = recovery
                    .prepare_normal_boot(
                        set["transactionId"].as_str().unwrap(),
                        set["confirmToken"].as_str().unwrap(),
                    )
                    .await
                    .unwrap();
                durable::json(&path("normalPreparedRecord"), &normal).unwrap();
                let done = recovery
                    .execute_normal_boot(
                        normal["transactionId"].as_str().unwrap(),
                        normal["confirmToken"].as_str().unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(done["state"], "AWAITING_NORMAL_BOOT_COMPLETION");
                recovery.recover().await.unwrap();
                assert!(recovery.upload("normal-blocked", "eA==").await.is_err());
                assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
                durable::json(&path("normalResultRecord"),&json!({"done":done,"status":recovery.status().await.unwrap(),"ordinaryLoadPath":true,"normalBootVerified":false})).unwrap();
                if spec.get("healthResultRecord").is_some() {
                    let deadline = std::time::Instant::now() + Duration::from_secs(60);
                    while local.call("kura.configuration.list").await.is_err() {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "actual bridge readiness"
                        );
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    durable::publish_new(
                        &path("beforeHealth"),
                        b"normal source and bridge proven; await GWT check",
                        FileMetadata::private(),
                    )
                    .unwrap();
                    let deadline = std::time::Instant::now() + Duration::from_secs(300);
                    while !path("continueHealth").exists() {
                        assert!(std::time::Instant::now() < deadline);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    let prepared = recovery
                        .prepare_health(
                            normal["transactionId"].as_str().unwrap(),
                            normal["confirmToken"].as_str().unwrap(),
                        )
                        .await
                        .unwrap();
                    durable::json(&path("healthPreparedRecord"), &prepared).unwrap();
                    let done = recovery
                        .execute_health(
                            prepared["transactionId"].as_str().unwrap(),
                            prepared["confirmToken"].as_str().unwrap(),
                            local.clone(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(done["state"], "AWAITING_HEALTH_COMPLETION");
                    recovery.recover().await.unwrap();
                    assert!(recovery.upload("health-blocked", "eA==").await.is_err());
                    assert!(
                        Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err()
                    );
                    durable::json(&path("healthResultRecord"),&json!({"done":done,"status":recovery.status().await.unwrap(),"actualJavaUdsBridge":true,"fullRecoveryVerified":false})).unwrap();
                    durable::publish_new(
                        &path("beforeHealthBrowser"),
                        b"selected business verified; await final browser evidence",
                        FileMetadata::private(),
                    )
                    .unwrap();
                    let deadline = std::time::Instant::now() + Duration::from_secs(300);
                    while !path("finishHealthBrowser").exists() {
                        assert!(std::time::Instant::now() < deadline);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    if spec.get("completionConfig").is_some() {
                        let approved = recovery
                            .prepare_completion(
                                prepared["transactionId"].as_str().unwrap(),
                                prepared["confirmToken"].as_str().unwrap(),
                            )
                            .await
                            .unwrap();
                        durable::json(&path("completionPreparedRecord"), &approved).unwrap();
                        let committed = recovery
                            .execute_completion(
                                approved["transactionId"].as_str().unwrap(),
                                approved["confirmToken"].as_str().unwrap(),
                                local.clone(),
                            )
                            .await
                            .unwrap();
                        assert_eq!(committed["writeReleaseCommitted"], true);
                        assert_eq!(committed["kuraReleaseReplyVerified"], true);
                        assert_eq!(committed["kuraRecoveryVerified"], false);
                        recovery.recover().await.unwrap();
                        assert!(
                            Guard::acquire(&recovery.0.state_root, Subsystem::Configuration)
                                .is_ok()
                        );
                        durable::json(&path("completionResultRecord"),&json!({"committed":committed,"status":recovery.status().await.unwrap(),"actualJavaUdsRelease":true})).unwrap();
                        durable::publish_new(
                            &path("beforeCompletionBrowser"),
                            b"durable completion committed; await ordinary GWT write",
                            FileMetadata::private(),
                        )
                        .unwrap();
                        let deadline = std::time::Instant::now() + Duration::from_secs(300);
                        while !path("finishCompletionBrowser").exists() {
                            assert!(std::time::Instant::now() < deadline);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        recovery.recover().await.unwrap();
                        assert_eq!(
                            recovery.journal().unwrap().unwrap().state,
                            State::CompletedApprovedChecks
                        );
                        assert!(
                            Guard::acquire(&recovery.0.state_root, Subsystem::Configuration)
                                .is_ok()
                        );
                        durable::json(&path("postCompletionRecord"),&json!({"status":recovery.status().await.unwrap(),"postWriteReopenPassed":true})).unwrap();
                        if spec.get("ordinaryStartupConfig").is_some() {
                            let p = recovery
                                .prepare_ordinary(
                                    approved["transactionId"].as_str().unwrap(),
                                    approved["confirmToken"].as_str().unwrap(),
                                )
                                .await
                                .unwrap();
                            durable::json(&path("ordinaryPreparedRecord"), &p).unwrap();
                            if spec.get("ordinaryCancellationRecord").is_some() {
                                // The external native driver uses the real administrative UDS.
                                // Keep the approved parent JVM alive for cancellation checks.
                                let expires = p["expiresAtUnixMs"].as_u64().unwrap();
                                tokio::time::sleep(Duration::from_millis(
                                    expires.saturating_sub(now()) + 100,
                                ))
                                .await;
                                recovery.recover().await.unwrap();
                                assert_eq!(
                                    recovery.journal().unwrap().unwrap().state,
                                    State::OrdinaryPrepared
                                );
                                durable::json(
                                    &path("ordinaryExpiryCheckedRecord"),
                                    &json!({"expired":true,"state":"ORDINARY_PREPARED"}),
                                )
                                .unwrap();
                                let deadline = std::time::Instant::now() + Duration::from_secs(600);
                                while !path("finishOrdinaryCancellation").exists() {
                                    assert!(std::time::Instant::now() < deadline);
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                                assert_eq!(
                                    recovery.journal().unwrap().unwrap().state,
                                    State::OrdinaryCancelled
                                );
                                recovery.recover().await.unwrap();
                                assert!(
                                    Guard::acquire(
                                        &recovery.0.state_root,
                                        Subsystem::Configuration
                                    )
                                    .is_ok()
                                );
                                durable::json(
                                    &path("ordinaryCancellationRecord"),
                                    &json!({"status":recovery.status().await.unwrap(),
                                        "actualJavaUdsParent":true,"actualAdministrativeUds":true,
                                        "nativeUnitAdapter":"test-only IDEA coordination; not systemd",
                                        "fullRecoveryVerified":false}),
                                )
                                .unwrap();
                                if let Some(server) = server {
                                    server.abort();
                                }
                                return;
                            }
                            let deadline = std::time::Instant::now() + Duration::from_secs(300);
                            while !path("continueOrdinary").exists() {
                                assert!(std::time::Instant::now() < deadline);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                            let result = recovery
                                .execute_ordinary(
                                    p["transactionId"].as_str().unwrap(),
                                    p["confirmToken"].as_str().unwrap(),
                                    local.clone(),
                                )
                                .await
                                .unwrap();
                            assert_eq!(result["ordinaryUnitHandedOff"], true);
                            recovery.recover().await.unwrap();
                            assert!(
                                Guard::acquire(&recovery.0.state_root, Subsystem::Configuration)
                                    .is_ok()
                            );
                            durable::json(
                                &path("ordinaryResultRecord"),
                                &json!({"result":result,"status":recovery.status().await.unwrap()}),
                            )
                            .unwrap();
                            let deadline = std::time::Instant::now() + Duration::from_secs(300);
                            while !path("finishOrdinaryBrowser").exists() {
                                assert!(std::time::Instant::now() < deadline);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        }
        if let Some(server) = server {
            server.abort();
        }
    }
    #[tokio::test]
    #[ignore = "requires retained explicit snapshot-set source, independent baseline grant and IDEA normal startup"]
    async fn actual_guarded_normal_startup_from_explicit_snapshot_set() {
        let spec: Value = serde_json::from_slice(
            &fs::read(std::env::var("YOFC_TEST_NORMAL_KURA").expect("explicit source fixture"))
                .unwrap(),
        )
        .unwrap();
        let path = |key: &str| PathBuf::from(spec[key].as_str().expect("fixture path"));
        let units = ["unit", "inverseUnit", "normalUnit"]
            .map(|k| spec[k].as_str().unwrap().to_owned())
            .to_vec();
        let recovery = Recovery::open(
            "/".into(),
            path("state"),
            units,
            path("snapshots"),
            Some(path("systemctl")),
        )
        .unwrap()
        .with_snapshot_validator(
            crate::snapshot_validation::Validator::new(path("validatorConfig")).unwrap(),
        )
        .with_controlled_startup(
            crate::controlled_startup::Startup::new(path("startupConfig")).unwrap(),
        )
        .unwrap()
        .with_inverse_startup(
            crate::controlled_startup::Startup::new(path("inverseStartupConfig")).unwrap(),
        )
        .unwrap()
        .with_normal_startup(
            crate::controlled_startup::Startup::new(path("normalStartupConfig")).unwrap(),
        )
        .unwrap()
        .with_normal_snapshot_validator(
            crate::snapshot_validation::Validator::new(path("normalValidatorConfig")).unwrap(),
        )
        .unwrap();
        let j = recovery.journal().unwrap().expect("retained source");
        assert_eq!(j.state, State::AwaitingSnapshotCompletion);
        assert!(j.normal_boot.is_none(), "never replay normal verification");
        recovery.recover().await.unwrap();
        let original = recovery.inventory().unwrap();
        let set: Value =
            serde_json::from_slice(&fs::read(path("snapshotSetPreparedRecord")).unwrap()).unwrap();
        let prepared = recovery
            .prepare_normal_boot(
                set["transactionId"].as_str().unwrap(),
                set["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        durable::json(&path("normalPreparedRecord"), &prepared).unwrap();
        let done = recovery
            .execute_normal_boot(
                prepared["transactionId"].as_str().unwrap(),
                prepared["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(done["state"], "AWAITING_NORMAL_BOOT_COMPLETION");
        recovery.recover().await.unwrap();
        assert_eq!(recovery.inventory().unwrap(), original);
        assert!(recovery.upload("normal-blocked", "eA==").await.is_err());
        assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
        durable::json(&path("normalResultRecord"),&json!({"done":done,"status":recovery.status().await.unwrap(),"normalBootVerified":false,
            "originalActiveFilesUnchanged":true,"newContinuationOnly":true,"forwardInverseSnapshotSetNotReplayed":true})).unwrap();
    }
    async fn snapshot_ready_fixture() -> (Recovery, TempDir, Value) {
        let (recovery, dir) = inverse_fixture();
        for (name, bytes) in [
            ("snapshot_7.xml", b"baseline-seven".as_slice()),
            (
                "snapshot_3.xml.bad",
                b"retained damaged original".as_slice(),
            ),
            ("notes.txt", b"original non-snapshot entry".as_slice()),
        ] {
            let p = dir.0.join("opt/kura/user/snapshots").join(name);
            fs::write(&p, bytes).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o640)).unwrap();
        }
        let p = forward_for_inverse(&recovery).await;
        let inverse = recovery
            .prepare_compensation(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        recovery
            .execute_compensation(
                inverse["transactionId"].as_str().unwrap(),
                inverse["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        (recovery, dir, inverse)
    }
    async fn normal_ready_fixture() -> (Recovery, TempDir, Value) {
        let (mut recovery, dir, inverse) = snapshot_ready_fixture().await;
        let set = recovery
            .prepare_snapshot_set(
                inverse["transactionId"].as_str().unwrap(),
                inverse["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        recovery
            .execute_snapshot_set(
                set["transactionId"].as_str().unwrap(),
                set["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        durable::directory(&dir.0.join("normal")).unwrap();
        let hook = dir.0.join("normal-receipt.py");
        fs::write(&hook,format!(r#"import pathlib,hashlib,os
root=pathlib.Path({root});p=root/'normal/request.properties'
d=dict(line.split('=',1) for line in p.read_text().splitlines());r=pathlib.Path(d['receipt.path'])
observed=b'exact authenticated CM observation';pathlib.Path(str(r)+'.cm-observed.aes').write_bytes(observed)
pathlib.Path(str(r)+'.bundle-levels').write_text('schema=1\n22=5\n')
source='0'*64 if (root/'wrong-normal-source').exists() else d['verification.source.receipt.sha256']
r.write_text('schema=1\nstatus=NORMAL_BOOT_ADMITTED\nrestore.id='+d['restore.id']+'\nsnapshot.sha256='+d['snapshot.sha256']+'\nsource.receipt.sha256='+source+'\nsource.applied.sha256='+d['verification.source.applied.sha256']+'\nobserved.sha256='+hashlib.sha256(observed).hexdigest()+'\nfullRecoveryVerified=false\nnormalBootVerified=false\nbusinessHealth=UNVERIFIED\n')
for suffix in ['', '.cm-observed.aes','.bundle-levels']:os.chmod(pathlib.Path(str(r)+suffix),0o600)
"#,root=serde_json::to_string(&dir.0).unwrap())).unwrap();
        let script = dir.0.join("fake-systemctl");
        let body = fs::read_to_string(&script).unwrap();
        fs::write(&script,body.replace("args=['/usr/bin/python3',str(root/'emit-receipt.py')]","args=['/usr/bin/python3',str(root/('normal-receipt.py' if unit=='kura-normal.service' else 'emit-receipt.py'))]" )).unwrap();
        durable::json(&dir.0.join("normal.json"),&json!({"schema":1,"unit":"kura-normal.service",
            "requestPath":dir.0.join("normal/request.properties"),"receiptDirectory":dir.0.join("application"),"timeoutSeconds":1,
            "profileFiles":[{"path":dir.0.join("profile"),"sha256":durable::hash(b"fixed startup profile")}]})).unwrap();
        Arc::get_mut(&mut recovery.0)
            .unwrap()
            .units
            .push("kura-normal.service".into());
        (recovery, dir, set)
    }
    fn grant_normal(recovery: Recovery, dir: &TempDir) -> Recovery {
        recovery
            .with_normal_startup(
                crate::controlled_startup::Startup::new(dir.0.join("normal.json")).unwrap(),
            )
            .unwrap()
    }
    async fn prepare_normal(recovery: &Recovery, set: &Value) -> Value {
        recovery
            .prepare_normal_boot(
                set["transactionId"].as_str().unwrap(),
                set["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn guarded_normal_start_requires_independent_grant_and_remains_nonterminal_without_replay()
     {
        let (recovery, dir, set) = normal_ready_fixture().await;
        let before = calls(&dir);
        assert!(
            recovery
                .prepare_normal_boot(
                    set["transactionId"].as_str().unwrap(),
                    set["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|c| c.starts_with("start "))
                .count(),
            before.iter().filter(|c| c.starts_with("start ")).count()
        );
        let recovery = grant_normal(recovery, &dir);
        let p = prepare_normal(&recovery, &set).await;
        assert!(
            recovery
                .execute_normal_boot(
                    p["transactionId"].as_str().unwrap(),
                    set["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        let files = recovery.inventory().unwrap();
        let done = recovery
            .execute_normal_boot(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(done["state"], "AWAITING_NORMAL_BOOT_COMPLETION");
        assert_eq!(done["normalBootVerified"], false);
        assert_eq!(recovery.inventory().unwrap(), files);
        let before = calls(&dir);
        recovery.recover().await.unwrap();
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|c| c.starts_with("start "))
                .count(),
            before.iter().filter(|c| c.starts_with("start ")).count()
        );
        assert!(recovery.upload("blocked", "eA==").await.is_err());
        assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
        assert!(
            recovery
                .execute_normal_boot(
                    p["transactionId"].as_str().unwrap(),
                    p["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        let s = recovery.status().await.unwrap();
        assert_eq!(s["transaction"]["normalBoot"]["normalBootVerified"], false);
    }
    #[tokio::test]
    async fn guarded_normal_drift_before_start_preserves_files_and_never_starts() {
        for drift in ["anchor", "base", "profile", "source"] {
            let (recovery, dir, set) = normal_ready_fixture().await;
            let recovery = grant_normal(recovery, &dir);
            let p = prepare_normal(&recovery, &set).await;
            let j = recovery.journal().unwrap().unwrap();
            let normal = j.normal_boot.as_ref().unwrap();
            let path = match drift {
                "anchor" => recovery
                    .0
                    .state
                    .join("receipts")
                    .join(format!("{}.normal-source.json", normal.id)),
                "base" => normal.target.clone(),
                "profile" => dir.0.join("profile"),
                _ => j.inverse.as_ref().unwrap().startup.receipt_path.clone(),
            };
            fs::write(path, b"drift").unwrap();
            let before = calls(&dir);
            assert!(
                recovery
                    .execute_normal_boot(
                        p["transactionId"].as_str().unwrap(),
                        p["confirmToken"].as_str().unwrap()
                    )
                    .await
                    .is_err()
            );
            assert_eq!(
                calls(&dir)
                    .iter()
                    .filter(|c| c.starts_with("start "))
                    .count(),
                before.iter().filter(|c| c.starts_with("start ")).count()
            );
            assert!(!normal.startup.request_path.exists());
            assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
        }
    }
    #[tokio::test]
    async fn guarded_normal_interruption_and_wrong_source_stop_all_units_without_resend() {
        for wrong_source in [false, true] {
            let (recovery, dir, set) = normal_ready_fixture().await;
            let recovery = grant_normal(recovery, &dir);
            let p = prepare_normal(&recovery, &set).await;
            if wrong_source {
                fs::write(dir.0.join("wrong-normal-source"), b"yes").unwrap();
                assert!(
                    recovery
                        .execute_normal_boot(
                            p["transactionId"].as_str().unwrap(),
                            p["confirmToken"].as_str().unwrap()
                        )
                        .await
                        .is_err()
                );
            } else {
                let mut j = recovery.journal().unwrap().unwrap();
                j.normal_boot.as_mut().unwrap().issued = true;
                recovery.state(&mut j, State::StartingNormalBoot).unwrap();
                assert!(recovery.recover().await.is_err());
            }
            let j = recovery.journal().unwrap().unwrap();
            assert_eq!(j.state, State::RecoveryRequired);
            recovery.stopped(&j.unit).unwrap();
            recovery.stopped(&j.inverse.as_ref().unwrap().unit).unwrap();
            recovery
                .stopped(&j.normal_boot.as_ref().unwrap().unit)
                .unwrap();
            let before = calls(&dir);
            assert!(recovery.recover().await.is_err());
            assert_eq!(
                calls(&dir)
                    .iter()
                    .filter(|c| c.starts_with("start "))
                    .count(),
                before.iter().filter(|c| c.starts_with("start ")).count()
            );
        }
    }
    #[tokio::test]
    async fn normal_baseline_format_grant_is_independent_pinned_and_never_changes_upload_policy() {
        let (recovery, dir, set) = normal_ready_fixture().await;
        let recovery = grant_normal(recovery, &dir);
        let original = fs::read(dir.0.join("validator.json")).unwrap();
        let mut config: Value = serde_json::from_slice(&original).unwrap();
        config["passwordPolicy"] = json!("legacy");
        let path = dir.0.join("normal-validator.json");
        durable::json(&path, &config).unwrap();
        let recovery = recovery
            .with_normal_snapshot_validator(
                crate::snapshot_validation::Validator::new(path.clone()).unwrap(),
            )
            .unwrap();
        let prepared = prepare_normal(&recovery, &set).await;
        assert_eq!(fs::read(dir.0.join("validator.json")).unwrap(), original);
        let j = recovery.journal().unwrap().unwrap();
        let normal = j.normal_boot.unwrap();
        assert!(
            normal
                .parameters
                .iter()
                .any(|(k, v)| k == "password.policy" && v == "legacy")
        );
        config["passwordPolicy"] = json!("authenticated");
        durable::json(&path, &config).unwrap();
        let before = calls(&dir);
        assert!(
            recovery
                .execute_normal_boot(
                    prepared["transactionId"].as_str().unwrap(),
                    prepared["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|c| c.starts_with("start "))
                .count(),
            before.iter().filter(|c| c.starts_with("start ")).count()
        );
    }
    pub(super) async fn health_ready_fixture() -> (Recovery, TempDir, Value) {
        let (recovery, dir, set) = normal_ready_fixture().await;
        let recovery = grant_normal(recovery, &dir);
        let normal = prepare_normal(&recovery, &set).await;
        recovery
            .execute_normal_boot(
                normal["transactionId"].as_str().unwrap(),
                normal["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        durable::json(&dir.0.join("health.json"),&json!({"schema":1,"componentPids":["pid"],"checkIds":["business.check"],"validForSeconds":300})).unwrap();
        (recovery, dir, normal)
    }
    pub(super) fn grant_health(recovery: Recovery, dir: &TempDir) -> Recovery {
        recovery
            .with_health_profile(dir.0.join("health.json"))
            .unwrap()
    }
    pub(super) async fn health_bridge(
        recovery: &Recovery,
        drift: &str,
    ) -> (crate::local::Local, tokio::task::JoinHandle<()>) {
        let local =
            crate::local::Local::new(unsafe { libc::geteuid() }, unsafe { libc::geteuid() });
        let mut rx = local.install_test_bridge(&["kura.recovery.verify"]).await;
        let j = recovery.journal().unwrap().unwrap();
        let app = recovery.normal_application(&j, j.normal_boot.as_ref().unwrap().source).unwrap();
        let count = app.replaced + app.created;
        let peer = local.clone();
        let drift = drift.to_owned();
        let task = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let p = frame.params.as_ref().unwrap();
                let mut report = json!({"schema":1,"recoveryId":p["recoveryId"],"snapshotSha256":p["snapshotSha256"],"nonce":p["nonce"],
                    "processId":123,"frameworkStartLevel":5,"normalLoad":true,"ordinaryWritesBlocked":true,"cmMatched":true,
                    "managedConfigurationCount":count,"sourceConfigurationCount":count,"materializedSelfPids":[],"propertyCount":2,"configurationServiceAvailable":true,
                    "components":[{"pid":"pid","registered":true}],"checks":[{"id":"business.check","passed":true}]});
                match drift.as_str() {
                    "pid" => report["processId"] = json!(999),
                    "nonce" => report["nonce"] = json!("0".repeat(64)),
                    "cm" => report["cmMatched"] = json!(false),
                    "business" => report["checks"][0]["passed"] = json!(false),
                    "extra" => report["secret"] = json!("forbidden"),
                    _ => {}
                }
                peer.complete_pending(&frame.request_id, Some(report), None);
            }
        });
        (local, task)
    }
    #[tokio::test]
    async fn health_requires_independent_profile_and_retains_all_gates_after_selected_success() {
        let (recovery, dir, normal) = health_ready_fixture().await;
        assert!(
            recovery
                .prepare_health(
                    normal["transactionId"].as_str().unwrap(),
                    normal["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        let recovery = grant_health(recovery, &dir);
        let p = recovery
            .prepare_health(
                normal["transactionId"].as_str().unwrap(),
                normal["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        let (local, task) = health_bridge(&recovery, "").await;
        assert!(
            recovery
                .execute_health(
                    p["transactionId"].as_str().unwrap(),
                    normal["confirmToken"].as_str().unwrap(),
                    local.clone()
                )
                .await
                .is_err()
        );
        let done = recovery
            .execute_health(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap(),
                local.clone(),
            )
            .await
            .unwrap();
        assert_eq!(done["state"], "AWAITING_HEALTH_COMPLETION");
        assert_eq!(done["kuraRecoveryVerified"], false);
        assert_eq!(done["ordinaryWritesBlocked"], true);
        recovery.recover().await.unwrap();
        assert!(recovery.upload("blocked", "eA==").await.is_err());
        assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
        assert!(
            recovery
                .execute_health(
                    p["transactionId"].as_str().unwrap(),
                    p["confirmToken"].as_str().unwrap(),
                    local.clone()
                )
                .await
                .is_err()
        );
        let old = recovery.0.state.join("receipts").join(format!(
            "{}.health.json",
            p["transactionId"].as_str().unwrap()
        ));
        let bytes = fs::read(&old).unwrap();
        let next = recovery
            .prepare_health(
                normal["transactionId"].as_str().unwrap(),
                normal["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(next["transactionId"], p["transactionId"]);
        assert_eq!(fs::read(old).unwrap(), bytes);
        task.abort();
    }
    #[tokio::test]
    async fn wrong_process_challenge_cm_or_business_and_unexpected_fields_never_gain_health() {
        for drift in ["pid", "nonce", "cm", "business", "extra"] {
            let (recovery, dir, normal) = health_ready_fixture().await;
            let recovery = grant_health(recovery, &dir);
            let p = recovery
                .prepare_health(
                    normal["transactionId"].as_str().unwrap(),
                    normal["confirmToken"].as_str().unwrap(),
                )
                .await
                .unwrap();
            let (local, task) = health_bridge(&recovery, drift).await;
            assert!(
                recovery
                    .execute_health(
                        p["transactionId"].as_str().unwrap(),
                        p["confirmToken"].as_str().unwrap(),
                        local
                    )
                    .await
                    .is_err()
            );
            let j = recovery.journal().unwrap().unwrap();
            assert_eq!(j.state, State::RecoveryRequired);
            let status = recovery.status().await.unwrap();
            assert_eq!(
                status["transaction"]["health"]["selectedChecksVerified"],
                false
            );
            if drift == "cm" {
                assert_eq!(
                    status["transaction"]["health"]["report"]["cmMatched"],
                    false
                );
            }
            if drift == "business" {
                assert_eq!(
                    status["transaction"]["health"]["report"]["checks"][0]["passed"],
                    false
                );
            }
            if drift == "extra" {
                assert!(status["transaction"]["health"]["report"].is_null());
            }

            recovery.stopped(&j.unit).unwrap();
            recovery.stopped(&j.inverse.as_ref().unwrap().unit).unwrap();
            recovery
                .stopped(&j.normal_boot.as_ref().unwrap().unit)
                .unwrap();
            assert!(recovery.upload("blocked", "eA==").await.is_err());
            task.abort();
        }
    }
    #[tokio::test]
    async fn health_profile_drift_is_rejected_before_attempt_and_interruption_never_reissues_bridge_call()
     {
        let (recovery, dir, normal) = health_ready_fixture().await;
        let recovery = grant_health(recovery, &dir);
        let p = recovery
            .prepare_health(
                normal["transactionId"].as_str().unwrap(),
                normal["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        let prior = fs::read(dir.0.join("health.json")).unwrap();
        fs::write(dir.0.join("health.json"), b"changed").unwrap();
        let before = calls(&dir);
        assert!(
            recovery
                .execute_health(
                    p["transactionId"].as_str().unwrap(),
                    p["confirmToken"].as_str().unwrap(),
                    crate::local::Local::new(0, 0)
                )
                .await
                .is_err()
        );
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|c| c.starts_with("stop "))
                .count(),
            before.iter().filter(|c| c.starts_with("stop ")).count()
        );
        fs::write(dir.0.join("health.json"), prior).unwrap();
        let mut value = serde_json::to_value(recovery.journal().unwrap().unwrap()).unwrap();
        value["state"] = json!("VERIFYING_HEALTH");
        value["health"]["issued"] = json!(true);
        let j: Journal = serde_json::from_value(value).unwrap();
        recovery.persist(&j).unwrap();
        assert!(recovery.recover().await.is_err());
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
    }
    #[tokio::test]
    async fn health_receipt_drift_on_reopen_retains_proof_and_stops_without_restarting() {
        let (recovery, dir, normal) = health_ready_fixture().await;
        let recovery = grant_health(recovery, &dir);
        let p = recovery
            .prepare_health(
                normal["transactionId"].as_str().unwrap(),
                normal["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        let (local, task) = health_bridge(&recovery, "").await;
        recovery
            .execute_health(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap(),
                local,
            )
            .await
            .unwrap();
        let receipt = recovery.0.state.join("receipts").join(format!(
            "{}.health.json",
            p["transactionId"].as_str().unwrap()
        ));
        fs::write(&receipt, b"changed").unwrap();
        let before = calls(&dir);
        assert!(recovery.recover().await.is_err());
        assert_eq!(fs::read(receipt).unwrap(), b"changed");
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|c| c.starts_with("start "))
                .count(),
            before.iter().filter(|c| c.starts_with("start ")).count()
        );
        task.abort();
    }
    #[tokio::test]
    async fn guarded_normal_reopen_proof_drift_stops_and_retains_nonterminal_state() {
        let (recovery, dir, set) = normal_ready_fixture().await;
        let recovery = grant_normal(recovery, &dir);
        let p = prepare_normal(&recovery, &set).await;
        recovery
            .execute_normal_boot(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        let j = recovery.journal().unwrap().unwrap();
        let normal = j.normal_boot.as_ref().unwrap();
        fs::write(
            PathBuf::from(format!(
                "{}.cm-observed.aes",
                normal.startup.receipt_path.display()
            )),
            b"drift",
        )
        .unwrap();
        let before = calls(&dir);
        assert!(recovery.recover().await.is_err());
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        assert!(normal.startup.request_path.exists());
        recovery.stopped(&normal.unit).unwrap();
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|c| c.starts_with("start "))
                .count(),
            before.iter().filter(|c| c.starts_with("start ")).count()
        );
        assert!(recovery.upload("blocked", "eA==").await.is_err());
    }
    #[tokio::test]
    async fn snapshot_set_restores_all_original_files_and_retains_both_candidates_without_write_release()
     {
        let (recovery, dir, inverse) = snapshot_ready_fixture().await;
        let before = recovery.journal().unwrap().unwrap();
        let original = before.base.clone();
        let before_calls = calls(&dir);
        let p = recovery
            .prepare_snapshot_set(
                inverse["transactionId"].as_str().unwrap(),
                inverse["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovery.inventory().unwrap().len(), 5);
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|x| x.starts_with("stop "))
                .count(),
            before_calls
                .iter()
                .filter(|x| x.starts_with("stop "))
                .count()
        );
        assert!(
            recovery
                .execute_snapshot_set(
                    p["transactionId"].as_str().unwrap(),
                    inverse["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
        let done = recovery
            .execute_snapshot_set(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(done["state"], "AWAITING_SNAPSHOT_COMPLETION");
        assert_eq!(done["normalBootVerified"], false);
        assert_eq!(done["restoredFileCount"], 3);
        assert_eq!(done["retainedCandidateCount"], 2);
        assert_eq!(recovery.inventory().unwrap(), original);
        let after = recovery.journal().unwrap().unwrap();
        let plan = after
            .inverse
            .as_ref()
            .unwrap()
            .snapshot_set
            .as_ref()
            .unwrap();
        let archive = recovery.snapshot_archive(plan).unwrap();
        assert_eq!(fs::read_dir(&archive).unwrap().count(), 2);
        for (target, sha) in [
            (&before.target, &before.sha256),
            (
                &before.inverse.as_ref().unwrap().target,
                &before.inverse.as_ref().unwrap().sha256,
            ),
        ] {
            assert!(!dir.0.join(target).exists());
            let p = archive.join(PathBuf::from(target).file_name().unwrap());
            assert_eq!(durable::hash(&fs::read(&p).unwrap()), *sha);
            assert_eq!(
                FileMetadata::from_fs(&fs::metadata(p).unwrap()),
                before.target_metadata.unwrap()
            );
        }
        let oldcalls = calls(&dir);
        recovery.recover().await.unwrap();
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|x| x.starts_with("start "))
                .count(),
            oldcalls.iter().filter(|x| x.starts_with("start ")).count()
        );
        assert!(recovery.upload("blocked", "eA==").await.is_err());
        assert!(Guard::acquire(&recovery.0.state_root, Subsystem::Configuration).is_err());
        let status = recovery.status().await.unwrap();
        assert_eq!(status["transaction"]["awaitsExplicitCompletion"], true);
        assert_eq!(
            status["transaction"]["cmCompensation"]["snapshotSet"]["applied"],
            true
        );
        assert!(
            recovery
                .execute_snapshot_set(
                    p["transactionId"].as_str().unwrap(),
                    p["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn snapshot_set_source_backup_live_and_anchor_drift_are_refused_before_stop_or_move() {
        for drift in ["backup", "live", "source", "anchor"] {
            let (recovery, dir, inverse) = snapshot_ready_fixture().await;
            let p = recovery
                .prepare_snapshot_set(
                    inverse["transactionId"].as_str().unwrap(),
                    inverse["confirmToken"].as_str().unwrap(),
                )
                .await
                .unwrap();
            let j = recovery.journal().unwrap().unwrap();
            let path = match drift {
                "backup" => recovery.0.state.join(&j.backup_dir).join("snapshot_7.xml"),
                "live" => dir.0.join("opt/kura/user/snapshots/snapshot_7.xml"),
                "source" => PathBuf::from(format!(
                    "{}.cm-applied.aes",
                    j.inverse.as_ref().unwrap().startup.receipt_path.display()
                )),
                _ => recovery.0.state.join("receipts").join(format!(
                    "{}.snapshot-source.json",
                    p["transactionId"].as_str().unwrap()
                )),
            };
            fs::write(path, b"drift must remain for operator").unwrap();
            let before = calls(&dir);
            assert!(
                recovery
                    .execute_snapshot_set(
                        p["transactionId"].as_str().unwrap(),
                        p["confirmToken"].as_str().unwrap()
                    )
                    .await
                    .is_err()
            );
            assert_eq!(before, calls(&dir));
            assert!(dir.0.join(&j.target).exists());
            assert!(dir.0.join(&j.inverse.as_ref().unwrap().target).exists());
            assert_eq!(
                fs::read_dir(
                    recovery.snapshots().unwrap().join(
                        &j.inverse
                            .as_ref()
                            .unwrap()
                            .snapshot_set
                            .as_ref()
                            .unwrap()
                            .archive_dir
                    )
                )
                .unwrap()
                .count(),
                0
            );
        }
    }
    #[tokio::test]
    async fn snapshot_set_crash_between_atomic_move_and_journal_stays_blocked_without_replaying() {
        let (recovery, dir, inverse) = snapshot_ready_fixture().await;
        let p = recovery
            .prepare_snapshot_set(
                inverse["transactionId"].as_str().unwrap(),
                inverse["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        let mut j = recovery.journal().unwrap().unwrap();
        let plan = j.inverse.as_mut().unwrap().snapshot_set.as_mut().unwrap();
        plan.issued = true;
        let archive = recovery.snapshot_archive(plan).unwrap();
        j.state = State::RestoringSnapshotSet;
        recovery.persist(&j).unwrap();
        let original = dir.0.join(&j.target);
        let retained = archive.join(original.file_name().unwrap());
        durable::move_new(&original, &retained).unwrap();
        // A crash here predates the per-file journal marker. Neither file location is inferred as completion.
        let bytes = fs::read(&retained).unwrap();
        assert!(recovery.recover().await.is_err());
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        assert_eq!(bytes, fs::read(&retained).unwrap());
        assert!(!original.exists());
        assert!(dir.0.join(&j.inverse.as_ref().unwrap().target).exists());
        assert!(recovery.upload("blocked", "eA==").await.is_err());
        assert!(
            recovery
                .execute_snapshot_set(
                    p["transactionId"].as_str().unwrap(),
                    p["confirmToken"].as_str().unwrap()
                )
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn snapshot_set_reopen_drift_preserves_archives_and_does_not_restart_or_release() {
        let (recovery, dir, inverse) = snapshot_ready_fixture().await;
        let p = recovery
            .prepare_snapshot_set(
                inverse["transactionId"].as_str().unwrap(),
                inverse["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        recovery
            .execute_snapshot_set(
                p["transactionId"].as_str().unwrap(),
                p["confirmToken"].as_str().unwrap(),
            )
            .await
            .unwrap();
        let j = recovery.journal().unwrap().unwrap();
        let plan = j.inverse.as_ref().unwrap().snapshot_set.as_ref().unwrap();
        let archive = recovery.snapshot_archive(plan).unwrap();
        let files = fs::read_dir(&archive)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                (p.clone(), fs::read(p).unwrap())
            })
            .collect::<Vec<_>>();
        fs::write(
            dir.0.join("opt/kura/user/snapshots/unknown.xml"),
            b"foreign",
        )
        .unwrap();
        let before = calls(&dir);
        assert!(recovery.recover().await.is_err());
        assert_eq!(
            recovery.journal().unwrap().unwrap().state,
            State::RecoveryRequired
        );
        assert_eq!(
            calls(&dir)
                .iter()
                .filter(|x| x.starts_with("start "))
                .count(),
            before.iter().filter(|x| x.starts_with("start ")).count()
        );
        for (p, bytes) in files {
            assert_eq!(bytes, fs::read(p).unwrap());
        }
        assert_eq!(
            fs::read(dir.0.join("opt/kura/user/snapshots/unknown.xml")).unwrap(),
            b"foreign"
        );
    }
    #[test]
    fn retained_move_never_overwrites_and_preserves_exact_file_metadata() {
        let (_recovery, dir, _) = fixture(Vec::new());
        let source = dir.0.join("from");
        let target = dir.0.join("to");
        fs::write(&source, b"source").unwrap();
        fs::write(&target, b"other").unwrap();
        assert!(durable::move_new(&source, &target).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"source");
        assert_eq!(fs::read(&target).unwrap(), b"other");
        let dest = dir.0.join("retained");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
        let metadata = FileMetadata::from_fs(&fs::metadata(&source).unwrap());
        durable::move_new(&source, &dest).unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(&dest).unwrap(), b"source");
        assert_eq!(
            FileMetadata::from_fs(&fs::metadata(dest).unwrap()),
            metadata
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a new explicit Parallels fixture and actual systemd mount sandbox"]
    fn actual_retention_under_distinct_sandbox_mounts_with_explicit_fixture() {
        let root = PathBuf::from(
            std::env::var("YOFC_TEST_RETENTION_SANDBOX").expect("explicit new fixture"),
        );
        let state = root.join("state");
        let snapshots = root.join("snapshots");
        let info = fs::read_to_string("/proc/self/mountinfo").unwrap();
        let mount = |path: &std::path::Path| {
            info.lines()
                .find_map(|l| {
                    let fields = l.split_whitespace().collect::<Vec<_>>();
                    (fields.len() > 4 && fields[4] == path.to_str().unwrap())
                        .then(|| fields[0].to_owned())
                })
                .expect("explicit sandbox mount missing")
        };
        let state_mount = mount(&state);
        let snapshot_mount = mount(&snapshots);
        assert_ne!(state_mount, snapshot_mount);
        assert!(
            !state.join("result.json").exists(),
            "never replay retained sandbox fixture"
        );
        let source = snapshots.join("snapshot-probe.xml");
        durable::publish_new(
            &source,
            b"exact retained sandbox bytes",
            FileMetadata::private(),
        )
        .unwrap();
        let metadata = FileMetadata::from_fs(&fs::metadata(&source).unwrap());
        let cross = state.join("cross-mount-probe.xml");
        assert!(durable::move_new(&source, &cross).is_err());
        assert!(source.exists() && !cross.exists());
        let archive = snapshots.join(".recovery-retained");
        durable::directory(&archive).unwrap();
        durable::publish_new(
            &archive.join("owner"),
            b"yofc.agent.snapshot-retention.v1\n",
            FileMetadata::private(),
        )
        .unwrap();
        snapshot_set::retained_directory(&archive).unwrap();
        let retained = archive.join("snapshot-probe.xml");
        durable::move_new(&source, &retained).unwrap();
        assert!(!source.exists());
        assert_eq!(
            fs::read(&retained).unwrap(),
            b"exact retained sandbox bytes"
        );
        assert_eq!(
            metadata,
            FileMetadata::from_fs(&fs::metadata(retained).unwrap())
        );
        durable::publish_new(&state.join("result.json"),&serde_json::to_vec(&json!({"status":"passed","actualSystemdSandbox":true,"distinctMounts":true,"crossMountRefused":true,"sameSnapshotMountRetentionVerified":true,"metadataPreserved":true,"javaKuraVerified":false})).unwrap(),FileMetadata::private()).unwrap();
    }
    #[tokio::test]
    #[ignore = "requires a fresh full Kura ordinary observer fixture and native IDEA startup"]
    async fn actual_ordinary_observer_with_explicit_fixture() {
        let spec: Value = serde_json::from_slice(
            &fs::read(
                std::env::var("YOFC_TEST_ORDINARY_OBSERVER")
                    .expect("new explicit observer fixture"),
            )
            .unwrap(),
        )
        .unwrap();
        let path = |key: &str| PathBuf::from(spec[key].as_str().unwrap());
        assert!(
            !path("result").exists(),
            "never replay a closed observer fixture"
        );
        let uid = unsafe { libc::geteuid() };
        let local = crate::local::Local::new(uid, uid);
        let listener = local.listen(&path("socket")).await.unwrap();
        let server = tokio::spawn(local.clone().serve(listener));
        durable::publish_new(
            &path("awaitingNative"),
            b"new observer only; no recovery request or write",
            FileMetadata::private(),
        )
        .unwrap();
        let id = format!("handoff-{}", uuid::Uuid::new_v4());
        let nonce = durable::hash(uuid::Uuid::new_v4().as_bytes());
        let digest = durable::hash(&fs::read(path("snapshot")).unwrap());
        let params = json!({"handoffId":id,"profileId":spec["profileId"],"nonce":nonce,"snapshotSha256":digest,"componentPids":["org.eclipse.kura.management.revisionFixture","business.keep","business.remove"],"checkIds":["fixture.live-business"]});
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        let mut waiting = 0;
        let mut provider_wait = false;
        let final_report = loop {
            assert!(
                std::time::Instant::now() < deadline,
                "observer readiness deadline"
            );
            match local.ordinary_verification(params.clone()).await {
                Ok((report, instance, epoch)) => {
                    assert_eq!(report["schema"], 2);
                    assert_eq!(report["handoffId"], id);
                    assert_eq!(report["profileId"], spec["profileId"]);
                    assert_eq!(report["nonce"], nonce);
                    assert_eq!(report["approvedSnapshotSha256"], digest);
                    assert_eq!(report["ordinaryLoad"], true);
                    if report["ready"] == true {
                        assert!(
                            report["checks"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .all(|c| c["passed"] == true),
                            "a ready business failure must not be polled into success"
                        );
                        assert!(
                            provider_wait,
                            "explicit missing-provider observation required"
                        );
                        break json!({"report":report,"agentInstanceId":instance,"bridgeEpoch":epoch});
                    }
                    assert!(
                        report["checks"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|c| c["passed"] == false)
                    );
                    waiting += 1;
                    let all_registered = report["components"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|c| c["registered"] == true);
                    let missing = report["providers"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|p| p["available"] == false);
                    if all_registered
                        && missing
                        && path("businessProof").exists()
                        && !path("publicationGate").exists()
                    {
                        let proof: Value =
                            serde_json::from_slice(&fs::read(path("businessProof")).unwrap())
                                .unwrap();
                        assert_eq!(proof["status"], "passed");
                        provider_wait = true;
                        durable::publish_new(
                            &path("publicationGate"),
                            b"declared application initialization complete; publish health service",
                            FileMetadata::private(),
                        )
                        .unwrap();
                    }
                }
                Err("KURA_UNAVAILABLE" | "UNSUPPORTED" | "TIMEOUT") => {}
                Err(code) => panic!("unexpected read-only observer error {code}"),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        durable::json(&path("result"),&json!({"status":"passed","scope":"selected-ordinary-startup-readiness","kuraRecoveryVerified":false,"notReadyReads":waiting,"providerAbsenceObserved":provider_wait,"businessFailuresRetried":false,"observation":final_report})).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(300);
        while !path("finishBrowser").exists() {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        server.abort();
        let _ = server.await;
    }
}
