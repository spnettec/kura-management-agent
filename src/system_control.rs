//! Fixed Kura service control. A reboot is a durable asynchronous operation;
//! neither a disconnect nor a subsequent arbitrary PID proves its outcome.
mod grant;
mod outcome;
#[cfg(test)]
mod tests;
mod verification;

use crate::{
    durable::{self, FileMetadata},
    system_change::Guard,
};
use anyhow::{Context, Result, ensure};
use grant::Config;
pub(crate) use grant::Unit;
pub(crate) use grant::StopPolicy;
use outcome::{Binding, Decision};

pub(crate) fn operation(method: &str) -> Option<i32> {
    Some(match method {
        "service.status" => 23,
        "service.restart.prepare" => 24,
        "service.restart" => 25,
        "system.reboot.prepare" => 26,
        "system.reboot" => 27,
        "system.control.cancel" => 28,
        _ => return None,
    })
}
pub(crate) fn seal_profile(request: &Path, output: &Path) -> Result<Value> {
    grant::seal(request, output, Path::new("/usr/bin/systemctl"))
}
/// Shared read-only fixed-unit identity observation. This never enters the
/// generic restart/reboot transaction or bypasses its admission guard.
pub(crate) fn inspect_unit(systemctl:&Path,name:&str)->Result<Unit> {
    Native{root:PathBuf::new(),config:PathBuf::new(),systemctl:systemctl.into(),
        systemd_run:PathBuf::new(),boot_id:PathBuf::new()}.unit(name)
}
pub(crate) fn inspect_stop_policy(systemctl:&Path,config:&crate::recovery::ordinary_profile::Config)->Result<StopPolicy> {
    grant::inspect_ordinary_stop(systemctl,config)
}
#[cfg(test)]
pub(crate) fn inspect_runtime_inputs(root:&Path,config:&Path,systemctl:&Path)->Result<Value> {
    let native=Native{root:root.into(),config:config.into(),systemctl:systemctl.into(),systemd_run:PathBuf::new(),boot_id:PathBuf::new()};
    let (grant,raw,_,profile)=native.inputs()?;
    Ok(json!({"unit":grant.unit,"sourceGrantSha256":durable::hash(&raw),"profile":profile}))
}
pub(crate) fn inspect_stopped_unit(systemctl:&Path,name:&str)->Result<Unit> {
    let unit=inspect_unit(systemctl,name)?;
    ensure!(unit.stopped(),"CONFLICT: fixed startup unit has not stopped");
    if systemctl==Path::new("/usr/bin/systemctl") && cfg!(target_os="linux") {
        let cgroup=PathBuf::from("/sys/fs/cgroup/system.slice").join(name);
        match fs::symlink_metadata(&cgroup) {
            Ok(metadata)=>{
                ensure!(metadata.is_dir(),"CONFLICT: stopped unit cgroup is not a directory");
                let events=fs::read_to_string(cgroup.join("cgroup.events"))?;
                ensure!(events.lines().filter(|line|*line=="populated 0").count()==1
                    && !events.lines().any(|line|line=="populated 1")
                    && fs::read_to_string(cgroup.join("cgroup.procs"))?.trim().is_empty(),
                    "CONFLICT: fixed stopped unit cgroup remains populated");
            }
            Err(error) if error.kind()==std::io::ErrorKind::NotFound=>{},
            Err(error)=>return Err(error.into()),
        }
    }
    Ok(unit)
}
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use yofc_management_protocol::v1::{
    ErrorCode, ReadCommand, SystemControlAction, TaskResult, TaskState,
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn canonical(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|u| u.to_string() == s)
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path.parent().context("system control evidence parent")?)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "CONFLICT: private system control directory required"
    );
    let (v, m) = durable::read(path, limit)?;
    ensure!(
        m.mode == 0o600 && m.uid == unsafe { libc::geteuid() },
        "CONFLICT: private system control evidence required"
    );
    Ok(v)
}
pub(crate) fn orphan_evidence(state: &Path) -> Result<bool> {
    for name in ["commands", "receipts", "history"] {
        let p = state.join(name);
        let m = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        ensure!(
            m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "CONFLICT: unsafe system control evidence directory"
        );
        if fs::read_dir(p)?.next().is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(crate) fn validate_retained(root: &Path) -> Result<()> {
    Native {
        root: root.into(),
        config: PathBuf::new(),
        systemctl: PathBuf::new(),
        systemd_run: PathBuf::new(),
        boot_id: PathBuf::new(),
    }
    .journal()?;
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum State {
    Prepared,
    Issuing,
    AwaitingBoot,
    VerifyingApplication,
    Completed,
    Cancelled,
    RecoveryRequired,
}
impl State {
    fn settled(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Restart,
    Reboot,
}
impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::Restart => "service.restart",
            Self::Reboot => "system.reboot",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Snapshot {
    name: String,
    sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    schema: u32,
    id: String,
    token: String,
    state: State,
    action: Action,
    config_sha256: String,
    definition_sha256: String,
    unit: String,
    before: Unit,
    before_boot_id: String,
    expires_at: u64,
    profile: Option<crate::recovery::ControlProfile>,
    snapshots: Vec<Snapshot>,
    probe: Option<crate::ordinary_observation::Spec>,
    issued_command: Option<Binding>,
    issued: bool,
    issued_at: Option<u64>,
    request_accepted: bool,
    scheduled_unit: Option<String>,
    after: Option<Unit>,
    after_boot_id: Option<String>,
    observation: Option<Value>,
    outcome: Option<Decision>,
    receipt_sha256: Option<String>,
    error: Option<String>,
    #[serde(default)]
    command_decisions: BTreeMap<String, String>,
}
impl Journal {
    fn status(&self) -> Value {
        json!({"id":self.id,"state":self.state,"action":self.action.name(),"unit":self.unit,
        "profileId":self.profile.as_ref().map(|p|&p.profile_id),"profileDigest":self.profile.as_ref().map(|p|&p.profile_digest),"approvedSnapshotSha256":self.probe.as_ref().map(|p|&p.snapshot_sha256),
        "componentPids":self.profile.as_ref().map(|p|&p.component_pids),"checkIds":self.profile.as_ref().map(|p|&p.check_ids),
        "issued":self.issued,"requestAccepted":self.request_accepted,"before":self.before,"beforeBootId":self.before_boot_id,
        "after":self.after,"afterBootId":self.after_boot_id,"expiresAtUnixMs":self.expires_at,
        "applicationVerificationConfigured":self.profile.is_some(),"scope":if self.profile.is_some(){"administrator-selected-checks"}else{"system-process-only"},
        "kuraRecoveryVerified":false,"normalBootVerified":false,"error":self.error})
    }
}
#[derive(Clone)]
struct Native {
    root: PathBuf,
    config: PathBuf,
    systemctl: PathBuf,
    systemd_run: PathBuf,
    boot_id: PathBuf,
}
#[derive(Clone)]
pub(crate) struct Control {
    native: Arc<Native>,
    db: SqlitePool,
}
impl Native {
    fn state(&self) -> PathBuf {
        self.root.join("system-control")
    }
    fn path(&self) -> PathBuf {
        self.state().join("transaction.json")
    }
    fn file(&self, id: &str, suffix: &str) -> PathBuf {
        self.state().join("receipts").join(format!("{id}{suffix}"))
    }
    fn journal(&self) -> Result<Option<Journal>> {
        match fs::symlink_metadata(self.path()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ensure!(
                    !orphan_evidence(&self.state())?,
                    "CONFLICT: system control journal missing; preserve evidence"
                );
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
        let j: Journal = serde_json::from_slice(&private(&self.path(), 1 << 20)?)?;
        ensure!(
            j.schema == 1
                && j.id.strip_prefix("system-").is_some_and(canonical)
                && canonical(&j.token)
                && hash(&j.config_sha256)
                && hash(&j.definition_sha256),
            "CONFLICT: system control journal identity"
        );
        let raw = private(&self.file(&j.id, ".config.json"), 512 << 10)?;
        let c: Config = serde_json::from_slice(&raw)?;
        c.bounds()?;
        ensure!(
            durable::hash(&raw) == j.config_sha256
                && c.unit == j.unit
                && c.unit_definition_sha256 == j.definition_sha256,
            "CONFLICT: original system grant changed"
        );
        self.validate_links(&j)?;
        if j.state == State::Completed {
            let receipt = private(&self.file(&j.id, ".completed.json"), 1 << 20)?;
            let result = Self::final_decision(&j)?;
            ensure!(
                j.receipt_sha256.as_ref() == Some(&durable::hash(&receipt))
                    && j.outcome.as_ref() == Some(&result)
                    && receipt == serde_json::to_vec(&result)?,
                "CONFLICT: completed system evidence changed"
            );
        }
        Ok(Some(j))
    }
    fn persist(&self, j: &Journal) -> Result<()> {
        durable::json(&self.path(), j)
    }
    fn boot(&self) -> Result<String> {
        let id = fs::read_to_string(&self.boot_id)?.trim().to_owned();
        ensure!(canonical(&id), "CONFLICT: actual boot ID unavailable");
        Ok(id)
    }
    fn command(&self, args: &[&str], timeout: Duration) -> Result<String> {
        let o = crate::process::run(&self.systemctl, args, None, timeout)?;
        ensure!(
            o.status.success(),
            "OUTCOME_UNKNOWN: fixed systemd command failed or uncertain"
        );
        Ok(String::from_utf8(o.stdout)?)
    }
    fn lock(&self) -> Result<Guard> {
        crate::system_change::Guard::acquire(
            &self.root,
            crate::system_change::Subsystem::SystemControl,
        )
    }
    fn settlement_lock(&self) -> Result<Guard> {
        durable::directory(&self.root)?;
        Guard::native_boot_lock(&self.root.join("system-change.lock"))
    }
    fn archive(&self, j: &Journal) -> Result<()> {
        ensure!(
            j.state.settled(),
            "CONFLICT: unresolved system control transaction"
        );
        let bytes = private(&self.path(), 1 << 20)?;
        ensure!(
            serde_json::from_slice::<Value>(&bytes)? == serde_json::to_value(j)?,
            "CONFLICT: changed system control history"
        );
        let p = self.state().join("history").join(format!("{}.json", j.id));
        if p.exists() {
            ensure!(
                private(&p, 1 << 20)? == bytes,
                "CONFLICT: system control history changed"
            );
        } else {
            durable::publish_new(&p, &bytes, FileMetadata::private())?;
        }
        Ok(())
    }
    fn prepare(&self, action: Action, binding: Option<&Binding>) -> Result<Value> {
        let _lease = self.lock()?;
        let old = self.journal()?;
        if let Some(j) = &old {
            ensure!(
                j.state.settled(),
                "CONFLICT: unresolved system control transaction"
            );
        }
        let (c, raw, definition, profile) = self.inputs()?;
        ensure!(
            match action {
                Action::Restart => c.allow_restart,
                Action::Reboot => c.allow_reboot,
            },
            "FORBIDDEN: system action has no local grant"
        );
        ensure!(
            fs::read_dir(self.state().join("commands"))?.count() < 256,
            "RESOURCE_EXHAUSTED: retained system command evidence quota"
        );
        let before = self.unit(&c.unit)?;
        ensure!(
            matches!(
                before.active_state.as_str(),
                "active" | "inactive" | "failed"
            ),
            "CONFLICT: mapped service is transitioning"
        );
        if action == Action::Reboot {
            ensure!(
                before.unit_file_state == "enabled",
                "CONFLICT: mapped Kura boot entry is not enabled"
            );
        }
        let snapshots = if profile.is_some() {
            self.snapshots(&c)?
        } else {
            Vec::new()
        };
        let probe = profile.as_ref().map(|p| crate::ordinary_observation::Spec {
            id: format!("handoff-{}", uuid::Uuid::new_v4()),
            profile_id: p.profile_id.clone(),
            nonce: durable::hash(uuid::Uuid::new_v4().as_bytes()),
            snapshot_sha256: snapshots.last().unwrap().sha256.clone(),
            component_pids: p.component_pids.clone(),
            check_ids: p.check_ids.clone(),
        });
        let mut j = Journal {
            schema: 1,
            id: format!("system-{}", uuid::Uuid::new_v4()),
            token: uuid::Uuid::new_v4().to_string(),
            state: State::Prepared,
            action,
            config_sha256: durable::hash(&raw),
            definition_sha256: definition,
            unit: c.unit.clone(),
            before,
            before_boot_id: self.boot()?,
            expires_at: now() + c.confirmation_seconds * 1000,
            profile,
            snapshots,
            probe,
            issued_command: None,
            issued: false,
            issued_at: None,
            request_accepted: false,
            scheduled_unit: None,
            after: None,
            after_boot_id: None,
            observation: None,
            outcome: None,
            receipt_sha256: None,
            error: None,
            command_decisions: BTreeMap::new(),
        };
        let value = Self::prepare_value(&j);
        if let Some(old) = &old {
            self.archive(old)?;
        }
        durable::publish_new(
            &self.file(&j.id, ".config.json"),
            &raw,
            FileMetadata::private(),
        )?;
        self.record(&mut j, binding, Decision::success(value.clone()))?;
        self.persist(&j)?;
        Ok(value)
    }
    fn cancel(&self, action: &SystemControlAction, binding: Option<&Binding>) -> Result<Value> {
        let _lease = self.settlement_lock()?;
        let mut j = self.journal()?.context("NOT_FOUND")?;
        ensure!(
            j.id == action.transaction_id && j.token == action.confirmation_token,
            "FORBIDDEN: original system plan/token required"
        );
        ensure!(
            j.state == State::Prepared && !j.issued,
            "CONFLICT: issued or settled system plan cannot be cancelled"
        );
        j.state = State::Cancelled;
        let value = j.status();
        self.record(&mut j, binding, Decision::success(value.clone()))?;
        self.persist(&j)?;
        Ok(value)
    }
    fn begin(
        &self,
        action: &SystemControlAction,
        kind: Action,
        binding: Option<&Binding>,
    ) -> Result<(Guard, Journal, Config)> {
        let lease = self.lock()?;
        let mut j = self.journal()?.context("NOT_FOUND")?;
        ensure!(
            j.id == action.transaction_id && j.token == action.confirmation_token,
            "FORBIDDEN: original system plan/token required"
        );
        ensure!(
            j.state == State::Prepared && !j.issued && j.action == kind && now() < j.expires_at,
            "CONFLICT: expired, different or issued system plan"
        );
        let (c, raw, definition, profile) = self.inputs()?;
        ensure!(
            durable::hash(&raw) == j.config_sha256
                && definition == j.definition_sha256
                && serde_json::to_value(&profile)? == serde_json::to_value(&j.profile)?
                && self.unit(&j.unit)? == j.before
                && self.boot()? == j.before_boot_id,
            "CONFLICT: mapped service/grant/boot identity changed"
        );
        if j.profile.is_some() {
            ensure!(
                serde_json::to_value(self.snapshots(&c)?)? == serde_json::to_value(&j.snapshots)?,
                "CONFLICT: snapshots changed after review"
            );
        }
        j.issued = true;
        j.issued_command = binding.cloned();
        j.issued_at = Some(now());
        j.state = State::Issuing;
        if kind == Action::Reboot {
            j.scheduled_unit = Some(format!(
                "yofc-system-reboot-{}.service",
                j.id.strip_prefix("system-").unwrap()
            ));
        }
        self.persist(&j)?;
        let issued = (|| -> Result<()> {
            if kind == Action::Restart {
                self.command(
                    &["restart", &j.unit],
                    Duration::from_secs(c.restart_timeout_seconds),
                )?;
                let after = self.unit(&j.unit)?;
                ensure!(
                    after.running()
                        && after.invocation_id != j.before.invocation_id
                        && self.boot()? == j.before_boot_id,
                    "OUTCOME_UNKNOWN: restart process identity unproven"
                );
                j.after = Some(after);
                j.after_boot_id = Some(j.before_boot_id.clone());
                j.state = State::VerifyingApplication;
            } else {
                let scheduled = j.scheduled_unit.as_ref().unwrap();
                let output = crate::process::run(
                    &self.systemd_run,
                    &[
                        &format!("--unit={scheduled}"),
                        "--on-active=5s",
                        "--timer-property=AccuracySec=1s",
                        "--property=Type=oneshot",
                        "/usr/bin/systemctl",
                        "--no-wall",
                        "reboot",
                    ],
                    None,
                    Duration::from_secs(10),
                )?;
                ensure!(
                    output.status.success(),
                    "OUTCOME_UNKNOWN: reboot scheduling uncertain"
                );
                j.state = State::AwaitingBoot;
            }
            j.request_accepted = true;
            self.persist(&j)
        })();
        if let Err(e) = issued {
            j.state = State::RecoveryRequired;
            j.error = Some(
                "System action may have been issued; preserve evidence and never retry".into(),
            );
            let _ = self.persist(&j);
            return Err(e.context("OUTCOME_UNKNOWN: system action outcome unproven"));
        }
        Ok((lease, j, c))
    }
}
impl Control {
    pub(crate) fn new(root: PathBuf, config: PathBuf, db: SqlitePool) -> Result<Self> {
        let n = Native {
            root,
            config,
            systemctl: "/usr/bin/systemctl".into(),
            systemd_run: "/usr/bin/systemd-run".into(),
            boot_id: "/proc/sys/kernel/random/boot_id".into(),
        };
        ensure!(
            n.config.is_absolute(),
            "FORBIDDEN: absolute local system control grant required"
        );
        durable::directory(&n.state())?;
        for name in ["commands", "receipts", "history"] {
            durable::directory(&n.state().join(name))?;
        }
        Ok(Self {
            native: Arc::new(n),
            db,
        })
    }
    pub(crate) fn capabilities(&self) -> Result<Vec<String>> {
        let mut v = vec!["system.control.v1".into()];
        let Ok((c, _, _, _)) = self.native.inputs() else {
            return Ok(v);
        };
        if c.allow_restart {
            v.push("service.restart.v1".into());
        }
        if c.allow_reboot {
            v.push("system.reboot.v1".into());
        }
        Ok(v)
    }
    async fn admission(&self, command: Option<&ReadCommand>, cancel: bool) -> Result<()> {
        use prost::Message;
        let excluded = if let Some(c) = command {
            let row:Option<(i32,String,String,String,bool)>=sqlx::query_as("SELECT operation,idempotency_key,request_hash,state,result IS NULL FROM executions WHERE command_id=?").bind(&c.command_id).fetch_optional(&self.db).await?;
            ensure!(
                row == Some((
                    c.operation,
                    c.idempotency_key.clone(),
                    durable::hash(&c.encode_to_vec()),
                    "RUNNING".into(),
                    true
                )),
                "CONFLICT: exact running system admission required"
            );
            c.command_id.as_str()
        } else {
            ""
        };
        if !cancel {
            let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions WHERE command_id<>? AND state IN ('RUNNING','UNKNOWN') AND operation NOT IN (1,2,3,4,8,9,11,15,20,23))").bind(excluded).fetch_one(&self.db).await?;
            ensure!(!pending, "CONFLICT: unresolved admitted system operation");
        }
        Ok(())
    }
    pub(crate) async fn request(
        &self,
        operation: i32,
        action: Option<SystemControlAction>,
        command: Option<&ReadCommand>,
        local: crate::local::Local,
    ) -> Result<Value> {
        ensure!(
            matches!(operation, 23..=28)
                && matches!(operation, 25 | 27 | 28) == action.is_some()
                && action.as_ref().is_none_or(|a| a.valid()),
            "INVALID_ARGUMENT"
        );
        if let Some(c) = command {
            ensure!(
                c.operation == operation && c.valid_payload() && c.system_control_action == action,
                "INVALID_ARGUMENT"
            );
            if operation == 27 {
                ensure!(
                    c.expires_at_unix_ms as i128 >= i128::from(now()) + 15000,
                    "CONFLICT: reboot admission has insufficient remaining lifetime"
                );
            }
        }
        if operation == 23 {
            let n = self.native.clone();
            return tokio::task::spawn_blocking(move||{
                let journal=n.journal();let journal_readable=journal.is_ok();let transaction=journal.ok().flatten().map(|j|{
                    if j.state==State::Completed {j.outcome.as_ref().map(|r|r.value.clone()).unwrap_or_else(||j.status())} else {j.status()}
                });
                let inputs=n.inputs();
                match inputs {
                    Ok((c,_,_,_))=>Ok(json!({"configured":true,"configurationState":if journal_readable{"READY"}else{"RECOVERY_REQUIRED"},"journalReadable":journal_readable,
                        "unit":n.unit(&c.unit).ok(),"bootId":n.boot().ok(),"allowRestart":c.allow_restart && journal_readable,"allowReboot":c.allow_reboot && journal_readable,"transaction":transaction,"kuraRecoveryVerified":false,"normalBootVerified":false})),
                    Err(_)=>Ok(json!({"configured":true,"configurationState":"RECOVERY_REQUIRED","journalReadable":journal_readable,"unit":null,"bootId":n.boot().ok(),
                        "allowRestart":false,"allowReboot":false,"transaction":transaction,"kuraRecoveryVerified":false,"normalBootVerified":false})),
                }
            }).await?;
        }
        let _local_write = if command.is_none() {
            Some(local.configuration_write_lock.clone().lock_owned().await)
        } else {
            None
        };
        self.admission(command, operation == 28).await?;
        let binding = command.map(Binding::from_command).transpose()?;
        let n = self.native.clone();
        match operation {
            24 | 26 => {
                tokio::task::spawn_blocking(move || {
                    n.prepare(
                        if operation == 24 {
                            Action::Restart
                        } else {
                            Action::Reboot
                        },
                        binding.as_ref(),
                    )
                })
                .await?
            }
            28 => {
                tokio::task::spawn_blocking(move || n.cancel(&action.unwrap(), binding.as_ref()))
                    .await?
            }
            _ => {
                let (lease, mut j, c) = tokio::task::spawn_blocking(move || {
                    n.begin(
                        &action.unwrap(),
                        if operation == 25 {
                            Action::Restart
                        } else {
                            Action::Reboot
                        },
                        binding.as_ref(),
                    )
                })
                .await??;
                if operation == 27 {
                    drop(lease);
                    return Ok(j.status());
                }
                let result = self.native.verify_and_complete(&mut j, &c, &local).await;
                drop(lease);
                result
            }
        }
    }
    pub(crate) async fn observe_pending(&self, local: crate::local::Local) -> Result<()> {
        self.native.observe_pending(local).await
    }
}
