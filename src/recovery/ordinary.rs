//! An explicit transition to a pre-provisioned ordinary unit. The permanent
//! launcher has no recovery request and remains independent of the agent.
use super::ordinary_profile::{Config, Profile};
use super::*;
mod cancel;
pub(super) mod outcome;

use crate::ordinary_observation::Report;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Observation {
    report: Report,
    agent_instance_id: String,
    bridge_epoch: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Plan {
    pub id: String,
    confirm_token: String,
    pub unit: String,
    profile_id: String,
    profile_digest: String,
    grant_sha256: String,
    source_sha256: String,
    baseline: Vec<SnapshotFile>,
    highest: String,
    highest_sha256: String,
    validation: crate::snapshot_validation::Proof,
    old_normal_pid: u32,
    expires_at: u64,
    nonce: String,
    issued: bool,
    observation: Option<Observation>,
    receipt_sha256: Option<String>,
    verified: bool,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    command_decisions: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued_command: Option<outcome::Binding>,
    #[serde(default, skip_serializing_if = "is_false")]
    cancelled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cancel_command: Option<outcome::Binding>,
}
fn is_false(value: &bool) -> bool {
    !value
}
fn ordinary_eligible(j: &Journal) -> bool {
    (j.state == State::CompletedApprovedChecks && j.ordinary.is_none())
        || (j.state == State::OrdinaryCancelled
            && j.ordinary
                .as_ref()
                .is_some_and(|p| p.cancelled && !p.issued))
}
pub(crate) fn validate_cancelled_retained(state: &std::path::Path) -> Result<()> {
    let path = state.join("transaction.json");
    if path.exists() {
        let bytes = durable::read(&path, 1 << 20)?.0;
        let value: Value = serde_json::from_slice(&bytes)?;
        if value["state"] == "ORDINARY_CANCELLED" {
            let private = outcome::private(&path)?;
            ensure!(private == bytes, "CONFLICT: cancellation journal changed");
            let j: Journal = serde_json::from_slice(&bytes)?;
            cancel::validate(state, &j, true)?;
        }
    }
    Ok(())
}
impl Plan {
    pub(super) fn status(&self) -> Value {
        let mut value = json!({"id":self.id,"unit":self.unit,"profileId":self.profile_id,"issued":self.issued,
            "ordinaryUnitHandedOff":self.verified,"scope":"administrator-selected-checks","kuraRecoveryVerified":false,
            "report":self.observation.as_ref().map(|o|&o.report)});
        if self.cancelled {
            value["cancelled"] = json!(true);
        }
        value
    }
}
impl Recovery {
    pub(crate) fn ordinary_handoff_configured(&self) -> bool {
        self.enabled() && self.0.ordinary.is_some()
    }
    /// The bound center may only prepare the current, already committed local
    /// completion. It cannot choose a parent, launcher, unit, path or check.
    pub(crate) async fn remote_ordinary(
        &self,
        command: &yofc_management_protocol::v1::ReadCommand,
        local: crate::local::Local,
    ) -> Result<Value> {
        ensure!(self.ordinary_handoff_configured(), "UNSUPPORTED");
        ensure!(
            matches!(command.operation, 20..=22 | 29) && command.valid_payload(),
            "INVALID_ARGUMENT"
        );
        let before = self.ordinary_remote_status().await?;
        if command.operation == 20 {
            return Ok(before);
        }
        let result = if command.operation == 21 {
            let this = self.clone();
            let (id, token) = tokio::task::spawn_blocking(move || {
                let j = this.journal()?.context("CONFLICT: no completed recovery")?;
                ensure!(ordinary_eligible(&j), "CONFLICT: no eligible completion");
                let p = j.completion.context("CONFLICT: no approved completion")?;
                Ok::<_, anyhow::Error>((p.id, p.confirm_token))
            })
            .await??;
            self.prepare_ordinary_for(&id, &token, Some(command)).await
        } else if command.operation == 29 {
            let a = command.ordinary_handoff_action.as_ref().unwrap();
            self.cancel_ordinary_for(&a.transaction_id, &a.confirmation_token, Some(command))
                .await
        } else {
            let action = command.ordinary_handoff_action.as_ref().unwrap();
            self.execute_ordinary_for(
                &action.transaction_id,
                &action.confirmation_token,
                local,
                Some(command),
            )
            .await
        };
        match result {
            Ok(mut value) => {
                let after = self
                    .ordinary_remote_status()
                    .await
                    .map_err(|_| anyhow::anyhow!("OUTCOME_UNKNOWN: handoff decision unreadable"))?;
                value["state"] = after["state"].clone();
                value["normalBootVerified"] = json!(false);
                Ok(value)
            }
            Err(error) => match self.ordinary_remote_status().await {
                Ok(after) if after == before => Err(error),
                _ => anyhow::bail!("OUTCOME_UNKNOWN: handoff decision changed or is unproven"),
            },
        }
    }
    async fn ordinary_remote_status(&self) -> Result<Value> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let j = this.journal()?;
            if let Some(j) = &j && j.state == State::OrdinaryCancelled {
                cancel::validate(&this.0.state, j, true)?;
            }
            Ok(json!({"state":j.as_ref().map(|j|j.state),
                "canPrepare":j.as_ref().is_some_and(ordinary_eligible),
                "completionId":j.as_ref().and_then(|j|j.completion.as_ref().map(|p|&p.id)),
                "ordinary":j.as_ref().and_then(|j|j.ordinary.as_ref().map(Plan::status)),
                "scope":"administrator-selected-checks","normalBootVerified":false,"kuraRecoveryVerified":false}))
        }).await?
    }
    fn ordinary_file(&self, p: &Plan, suffix: &str) -> PathBuf {
        self.0
            .state
            .join("receipts")
            .join(format!("{}{suffix}", p.id))
    }
    fn ordinary_validator(&self) -> Result<&crate::snapshot_validation::Validator> {
        self.0
            .ordinary_validator
            .as_ref()
            .or(self.0.validator.as_ref())
            .context("FORBIDDEN: ordinary snapshot validator disabled")
    }
    fn ordinary_unit_definition(&self, c: &Config) -> Result<()> {
        let output = crate::process::run(
            &self.0.systemctl,
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
            "CONFLICT: ordinary unit definition unavailable"
        );
        Profile::declaration(c, &String::from_utf8(output.stdout)?)?;
        Ok(())
    }
    fn ordinary_parent(&self, j: &Journal) -> Result<()> {
        let mut completed = j
            .completion
            .clone()
            .context("CONFLICT: approved completion missing")?;
        self.completion_final(j, &mut completed)?;
        ensure!(completed.completed, "CONFLICT: parent release unproven");
        Ok(())
    }
    fn ordinary_archive(&self, j: &Journal, p: &Plan) -> Result<Config> {
        let c = self.ordinary_archive_inputs(j, p)?;
        self.ordinary_parent(j)?;
        Ok(c)
    }
    /// Immutable inputs only. Receipt queries must never complete a parent
    /// transaction, inspect live units or call a business provider.
    fn ordinary_archive_inputs(&self, j: &Journal, p: &Plan) -> Result<Config> {
        outcome::archived_inputs(&self.0.state, j, p)
    }
    fn ordinary_current(&self, j: &Journal, p: &Plan, fresh: bool) -> Result<Config> {
        let c = self.ordinary_archive(j, p)?;
        ensure!(
            !fresh || now() < p.expires_at,
            "CONFLICT: handoff approval expired"
        );
        let (_, digest, _) = self
            .0
            .ordinary
            .as_ref()
            .context("FORBIDDEN: ordinary handoff disabled")?
            .inputs()?;
        ensure!(
            digest == p.profile_digest,
            "CONFLICT: ordinary grant changed"
        );
        self.ordinary_unit_definition(&c)?;
        Ok(c)
    }
    fn ordinary_source_files(&self, p: &Plan, allow_new: bool) -> Result<()> {
        let current = self.inventory()?;
        if allow_new {
            ensure!(
                p.baseline.iter().all(|f| current.contains(f)),
                "CONFLICT: ordinary source files changed"
            );
        } else {
            ensure!(
                current == p.baseline,
                "CONFLICT: ordinary source inventory changed"
            );
        }
        Ok(())
    }
    fn ordinary_preflight(&self, j: &Journal, p: &Plan) -> Result<Config> {
        self.ordinary_preflight_with_deadline(j, p, true)
    }
    fn ordinary_preflight_with_deadline(
        &self,
        j: &Journal,
        p: &Plan,
        fresh: bool,
    ) -> Result<Config> {
        self.validate_ordinary_commands(j, p)?;
        let c = self.ordinary_current(j, p, fresh)?;
        self.ordinary_source_files(p, false)?;
        self.ordinary_validator()?.validate(
            &self.snapshots()?.join(&p.highest),
            &p.highest_sha256,
            Some(&p.validation),
        )?;
        self.stopped(&p.unit)?;
        self.stopped(&j.unit)?;
        if let Some(inverse) = &j.inverse { self.stopped(&inverse.unit)?; }
        else {
            ensure!(j.normal_boot.as_ref().is_some_and(|n|n.source == normal_boot::SourceKind::AppliedForward), "CONFLICT: inverse source missing");
            if let Some(inverse) = &self.0.inverse_startup { self.stopped(&inverse.unit()?)?; }
        }
        let normal = &j.normal_boot.as_ref().context("normal source")?.unit;
        let (active, pid) = self.unit(normal)?;
        ensure!(
            (p.old_normal_pid == 0 && !active && pid == 0) || (active && pid == p.old_normal_pid),
            "CONFLICT: normal process changed before handoff"
        );
        Ok(c)
    }
    fn ordinary_report(&self, p: &Plan, c: &Config, r: &Report, pid: u32) -> Result<()> {
        crate::ordinary_observation::Spec {
            id: p.id.clone(),
            profile_id: p.profile_id.clone(),
            nonce: p.nonce.clone(),
            snapshot_sha256: p.highest_sha256.clone(),
            component_pids: c.component_pids.clone(),
            check_ids: c.check_ids.clone(),
        }
        .validate(r, pid)
    }
    fn ordinary_receipt_body(&self, p: &Plan) -> Result<Vec<u8>> {
        let mut value = json!({"schema":"yofc.agent.ordinary-handoff.v1","handoffId":p.id,
            "unit":p.unit,"profileId":p.profile_id,"profileDigest":p.profile_digest,"sourceJournalSha256":p.source_sha256,
            "snapshotSha256":p.highest_sha256,"snapshotValidation":p.validation.report,"observation":p.observation,
            "status":"ORDINARY_ACTIVE_APPROVED_CHECKS","scope":"administrator-selected-checks","kuraRecoveryVerified":false});
        if let Some(binding) = &p.issued_command {
            value["issuedCommand"] = serde_json::to_value(binding)?;
        }
        Ok(serde_json::to_vec(&value)?)
    }
    fn ordinary_failure(&self, j: &mut Journal) -> Result<()> {
        let p = j.ordinary.clone().context("ordinary plan missing")?;
        self.state(j, State::RecoveryRequired)?;
        let mut failure = None;
        let mut units = vec![j.unit.clone(), j.normal_boot.as_ref().context("normal source")?.unit.clone(), p.unit];
        if let Some(inverse) = &j.inverse { units.insert(1, inverse.unit.clone()); }
        for unit in units {
            if let Err(e) = self.stop(&unit) {
                failure = Some(e);
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }
    pub(super) fn recover_ordinary(&self, j: &mut Journal) -> Result<()> {
        if j.state == State::RecoveryRequired
            && j.ordinary
                .as_ref()
                .is_some_and(|p| p.cancelled && !p.issued)
        {
            anyhow::bail!("CONFLICT: cancellation requires explicit recovery; preserve state");
        }
        if matches!(
            j.state,
            State::CancellingOrdinary | State::OrdinaryCancelled
        ) {
            return self.recover_ordinary_cancel(j);
        }
        let mut p = j.ordinary.clone().context("ordinary plan missing")?;
        if self.validate_ordinary_commands(j, &p).is_err() {
            self.ordinary_failure(j)?;
            anyhow::bail!("CONFLICT: ordinary command evidence changed; preserve state");
        }
        if !p.issued && j.state == State::OrdinaryPrepared {
            if self.ordinary_preflight_with_deadline(j, &p, false).is_ok() {
                return Ok(());
            }
        } else {
            let proof: Result<()> = (|| {
                let c = self.ordinary_archive(j, &p)?;
                let observed = p
                    .observation
                    .as_ref()
                    .context("ordinary observation missing")?;
                self.ordinary_report(&p, &c, &observed.report, observed.report.process_id)?;
                ensure!(
                    p.issued
                        && observed.report.ready
                        && observed.report.checks.iter().all(|c| c.passed),
                    "CONFLICT: interrupted ordinary verification"
                );
                let path = self.ordinary_file(&p, ".ordinary.json");
                let (bytes, m) = durable::read(&path, 1 << 20)?;
                ensure!(
                    m.mode & 0o077 == 0
                        && m.uid == unsafe { libc::geteuid() }
                        && bytes == self.ordinary_receipt_body(&p)?
                        && p.receipt_sha256
                            .as_ref()
                            .is_none_or(|h| h == &durable::hash(&bytes)),
                    "CONFLICT: ordinary receipt changed"
                );
                std::fs::File::open(&path)?.sync_all()?;
                durable::sync_directory(path.parent().context("receipt parent")?)?;
                p.receipt_sha256 = Some(durable::hash(&bytes));
                p.verified = true;
                Ok(())
            })();
            if proof.is_ok() {
                j.ordinary = Some(p);
                j.error = None;
                return self.state(j, State::OrdinaryActiveApprovedChecks);
            }
        }
        self.ordinary_failure(j)?;
        anyhow::bail!("CONFLICT: ordinary handoff unproven; do not repeat start")
    }
    pub async fn prepare_ordinary(&self, id: &str, token: &str) -> Result<Value> {
        self.prepare_ordinary_for(id, token, None).await
    }
    async fn prepare_ordinary_for(
        &self,
        id: &str,
        token: &str,
        command: Option<&yofc_management_protocol::v1::ReadCommand>,
    ) -> Result<Value> {
        self.pending_executions_for(command).await?;
        let binding = command.map(outcome::Binding::from_command).transpose()?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move |this| {
            let mut j = this.journal()?.context("CONFLICT: no completed recovery")?;
            let completed = j
                .completion
                .as_ref()
                .context("CONFLICT: no approved completion")?;
            ensure!(
                completed.id == id && completed.confirm_token == token,
                "FORBIDDEN: completion transaction/token"
            );
            if j.state == State::OrdinaryCancelled {
                cancel::validate(&this.0.state, &j, true)?;
                this.archive_ordinary_journal(&j)?;
                let p = j.ordinary.as_ref().unwrap();
                j = serde_json::from_slice(&outcome::private(
                    &this.ordinary_file(p, ".ordinary-source.json"),
                )?)?;
            }
            ensure!(
                j.state == State::CompletedApprovedChecks && j.ordinary.is_none(),
                "CONFLICT: ordinary handoff cannot be prepared"
            );
            this.ordinary_parent(&j)?;
            let (c, digest, grant) = this
                .0
                .ordinary
                .as_ref()
                .context("FORBIDDEN: ordinary handoff disabled")?
                .inputs()?;
            let normal = j.normal_boot.as_ref().context("normal source")?;
            let mut predecessors = vec![j.unit.clone()];
            if let Some(inverse) = &j.inverse { predecessors.push(inverse.unit.clone()); }
            else {
                ensure!(normal.source == normal_boot::SourceKind::AppliedForward, "CONFLICT: inverse source missing");
                if let Some(inverse) = &this.0.inverse_startup { predecessors.push(inverse.unit()?); }
            }
            ensure!(
                this.0.units.contains(&c.unit)
                    && !predecessors.contains(&c.unit) && normal.unit != c.unit,
                "FORBIDDEN: independent allowlisted ordinary unit required"
            );
            this.stopped(&c.unit)?;
            for unit in &predecessors { this.stopped(unit)?; }
            this.ordinary_unit_definition(&c)?;
            let (active, pid) = this.unit(&normal.unit)?;
            ensure!(active || pid == 0, "CONFLICT: normal process transitioning");
            let baseline = this.inventory()?;
            let mut candidates = Vec::new();
            for file in &baseline {
                if let Some(number) = file
                    .name
                    .strip_prefix("snapshot_")
                    .and_then(|s| s.strip_suffix(".xml"))
                {
                    let value = number.parse::<u64>().context("CONFLICT: snapshot name")?;
                    ensure!(
                        format!("snapshot_{value}.xml") == file.name,
                        "CONFLICT: ambiguous snapshot name"
                    );
                    candidates.push((value, file));
                }
            }
            candidates.sort_by_key(|c| c.0);
            let highest = candidates
                .last()
                .context("CONFLICT: no ordinary source snapshot")?
                .1;
            let validation = this.ordinary_validator()?.validate(
                &this.snapshots()?.join(&highest.name),
                &highest.sha256,
                None,
            )?;
            let highest_name = highest.name.clone();
            let highest_sha = highest.sha256.clone();
            let source = serde_json::to_vec(&j)?;
            ensure!(source.len() <= 1 << 20, "CONFLICT: ordinary source quota");
            let mut p = Plan {
                id: format!("handoff-{}", uuid::Uuid::new_v4()),
                confirm_token: uuid::Uuid::new_v4().to_string(),
                unit: c.unit.clone(),
                profile_id: c.profile_id.clone(),
                profile_digest: digest,
                grant_sha256: durable::hash(&grant),
                source_sha256: durable::hash(&source),
                baseline,
                highest: highest_name,
                highest_sha256: highest_sha,
                validation,
                old_normal_pid: if active { pid } else { 0 },
                expires_at: now() + c.valid_for_seconds * 1000,
                nonce: durable::hash(uuid::Uuid::new_v4().as_bytes()),
                issued: false,
                observation: None,
                receipt_sha256: None,
                verified: false,
                command_decisions: Default::default(),
                issued_command: None,
                cancelled: false,
                cancel_command: None,
            };
            durable::publish_new(
                &this.ordinary_file(&p, ".ordinary-source.json"),
                &source,
                FileMetadata::private(),
            )?;
            durable::publish_new(
                &this.ordinary_file(&p, ".ordinary-grant.json"),
                &grant,
                FileMetadata::private(),
            )?;
            this.ordinary_preflight(&j, &p)?;
            let value = Self::ordinary_prepare_value(&p, &c);
            if let Some(binding) = binding {
                this.record_ordinary_command(&j.id, &mut p, binding, &value)?;
            }
            j.ordinary = Some(p);
            this.state(&mut j, State::OrdinaryPrepared)?;
            Ok(value)
        })
        .await
    }
    pub async fn execute_ordinary(
        &self,
        id: &str,
        token: &str,
        local: crate::local::Local,
    ) -> Result<Value> {
        self.execute_ordinary_for(id, token, local, None).await
    }
    async fn execute_ordinary_for(
        &self,
        id: &str,
        token: &str,
        local: crate::local::Local,
        command: Option<&yofc_management_protocol::v1::ReadCommand>,
    ) -> Result<Value> {
        self.pending_executions_for(command).await?;
        let binding = command.map(outcome::Binding::from_command).transpose()?;
        let (id, token) = (id.to_owned(), token.to_owned());
        let runtime = tokio::runtime::Handle::current();
        self.write(move|this|{
            let mut j=this.journal()?.context("CONFLICT: no recovery")?;let mut p=j.ordinary.clone().context("CONFLICT: ordinary handoff not prepared")?;
            ensure!(p.id==id && p.confirm_token==token,"FORBIDDEN: ordinary transaction/token");
            ensure!(j.state==State::OrdinaryPrepared && !p.issued,"CONFLICT: ordinary start already attempted");let c=this.ordinary_preflight(&j,&p)?;
            let result:Result<()>=(||{
                p.issued=true;p.issued_command=binding.clone();j.ordinary=Some(p.clone());this.state(&mut j,State::StoppingOrdinary)?;
                this.stop(&j.unit)?;
                if let Some(inverse) = &j.inverse { this.stop(&inverse.unit)?; }
                this.stop(&j.normal_boot.as_ref().context("normal source")?.unit)?;
                this.stopped(&p.unit)?;this.ordinary_source_files(&p,false)?;
                this.ordinary_validator()?.validate(&this.snapshots()?.join(&p.highest),&p.highest_sha256,Some(&p.validation))?;
                  this.ordinary_current(&j,&p,true)?;this.state(&mut j,State::StartingOrdinary)?;this.command("start",&p.unit)?;
                let(active,pid)=this.unit(&p.unit)?;ensure!(active && pid>0 && pid!=p.old_normal_pid,"CONFLICT: ordinary process identity");
                this.state(&mut j,State::VerifyingOrdinary)?;
                let params=json!({"handoffId":p.id,"profileId":p.profile_id,"nonce":p.nonce,"snapshotSha256":p.highest_sha256,
                    "componentPids":c.component_pids,"checkIds":c.check_ids});
                runtime.block_on(async {
                    let deadline=std::time::Instant::now()+Duration::from_secs(c.timeout_seconds);
                    loop {
                        ensure!(std::time::Instant::now()<deadline,"CONFLICT: ordinary readiness timed out");
                        ensure!(this.unit(&p.unit)?==(true,pid),"CONFLICT: ordinary process changed");
                        match local.ordinary_verification(params.clone()).await {
                            Ok((value,instance,epoch))=>{
                                let report:Report=serde_json::from_value(value)?;this.ordinary_report(&p,&c,&report,pid)?;
                                let ready=report.ready;let passed=report.checks.iter().all(|c|c.passed);
                                p.observation=Some(Observation{report,agent_instance_id:instance,bridge_epoch:epoch});
                                ensure!(p.observation.as_ref().unwrap().report.schema==2,"CONFLICT: ordinary observer requires provider-readiness schema 2");
                                ensure!(p.observation.as_ref().unwrap().report.providers.iter().all(|provider|!provider.available || provider.unique),"CONFLICT: duplicate ordinary health provider");
                                if ready {ensure!(passed,"CONFLICT: ordinary business checks failed");break;}
                            },
                            Err("KURA_UNAVAILABLE"|"UNSUPPORTED"|"TIMEOUT")=>{},
                            Err(code)=>anyhow::bail!("CONFLICT: ordinary bridge observation {code}"),
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }Ok::<(),anyhow::Error>(())
                })?;
                  this.ordinary_current(&j,&p,true)?;this.ordinary_source_files(&p,true)?;ensure!(this.unit(&p.unit)?==(true,pid),"CONFLICT: observed ordinary unit changed");
                if let Some(binding)=binding {let value=Self::ordinary_execute_value(&p);this.record_ordinary_command(&j.id,&mut p,binding,&value)?;}
                j.ordinary=Some(p.clone());this.persist(&j)?;
                let body=this.ordinary_receipt_body(&p)?;durable::publish_new(&this.ordinary_file(&p,".ordinary.json"),&body,FileMetadata::private())?;
                p.receipt_sha256=Some(durable::hash(&body));p.verified=true;j.ordinary=Some(p.clone());this.state(&mut j,State::OrdinaryActiveApprovedChecks)
            })();
            if result.is_err(){j.ordinary=Some(p);j.error=Some("Ordinary handoff unproven; inspect retained typed observation and unit logs".into());this.persist(&j)?;
                if this.recover_ordinary(&mut j).is_err(){anyhow::bail!("CONFLICT: ordinary handoff unproven; preserve state and never repeat start");}}
            Ok(j.ordinary.as_ref().unwrap().status())
        }).await
    }
}
