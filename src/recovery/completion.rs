//! Explicit administrator-approved completion. The receipt commits a scoped
//! write release, never a claim of complete component or hardware validation.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone)]
pub(super) struct Profile(PathBuf);
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Config {
    schema: u32,
    scope: String,
    release_ordinary_writes: bool,
    health_grant_sha256: String,
    maximum_observation_age_seconds: u64,
    valid_for_seconds: u64,
}
impl Config {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == 1
                && self.scope == "administrator-selected-checks"
                && self.release_ordinary_writes
                && is_hash(&self.health_grant_sha256)
                && (60..=600).contains(&self.valid_for_seconds)
                && (1..=600).contains(&self.maximum_observation_age_seconds),
            "FORBIDDEN: explicit bounded administrator completion approval required"
        );
        Ok(())
    }
}
fn is_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn private(path: &std::path::Path, limit: u64) -> Result<Vec<u8>> {
    let (bytes, metadata) = durable::read(path, limit)?;
    ensure!(
        metadata.mode & 0o077 == 0 && metadata.uid == unsafe { libc::geteuid() },
        "CONFLICT: completion evidence owner"
    );
    Ok(bytes)
}
impl Profile {
    pub(super) fn new(path: PathBuf) -> Result<Self> {
        let p = Self(path);
        p.inputs()?;
        Ok(p)
    }
    fn inputs(&self) -> Result<(Config, Vec<u8>)> {
        ensure!(
            self.0.is_absolute(),
            "FORBIDDEN: absolute completion grant required"
        );
        let bytes = private(&self.0, 32 << 10)?;
        let parent = fs::symlink_metadata(self.0.parent().context("completion grant parent")?)?;
        ensure!(
            parent.is_dir() && parent.mode() & 0o022 == 0,
            "FORBIDDEN: private completion grant required"
        );
        let c: Config = serde_json::from_slice(&bytes)?;
        c.validate()?;
        Ok((c, bytes))
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Plan {
    pub id: String,
    pub(super) confirm_token: String,
    source_sha256: String,
    profile_sha256: String,
    selected: health::Plan,
    normal_id: String,
    normal_sha256: String,
    pid: u32,
    nonce: String,
    not_after: u64,
    issued: bool,
    decision_sha256: Option<String>,
    java_receipt_sha256: Option<String>,
    pub(super) completed: bool,
    #[serde(default)]
    release_reply_verified: bool,
}
impl Plan {
    pub(super) fn status(&self) -> Value {
        json!({"id":self.id,"issued":self.issued,"scope":"administrator-selected-checks",
            "writeReleaseCommitted":self.completed,"kuraRecoveryVerified":false,
            "normalBootVerified":false,"agentWritesBlocked":!self.completed,"kuraReleaseReplyVerified":self.release_reply_verified,
            "awaitsExplicitCompletion":!self.completed})
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Reply {
    schema: u32,
    completion_id: String,
    recovery_id: String,
    snapshot_sha256: String,
    decision_sha256: String,
    receipt_sha256: String,
    process_id: u32,
    write_release_committed: bool,
    kura_recovery_verified: bool,
    pre_release_health: health::Report,
}
impl Recovery {
    fn complete_file(&self, p: &Plan, suffix: &str) -> PathBuf {
        self.0
            .state
            .join("receipts")
            .join(format!("{}{suffix}", p.id))
    }
    fn java_release_path(&self, j: &Journal) -> Result<PathBuf> {
        Ok(PathBuf::from(format!(
            "{}.write-release.properties",
            j.normal_boot
                .as_ref()
                .context("normal source")?
                .startup
                .receipt_path
                .display()
        )))
    }
    fn completion_source(&self, j: &Journal, p: &Plan) -> Result<Config> {
        ensure!(
            p.id.strip_prefix("complete-")
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
                && is_hash(&p.nonce),
            "CONFLICT: completion identity"
        );
        let bytes = private(&self.complete_file(p, ".source.json"), 1 << 20)?;
        ensure!(
            durable::hash(&bytes) == p.source_sha256,
            "CONFLICT: completion source changed"
        );
        let source: Journal = serde_json::from_slice(&bytes)?;
        let strip = |j: &Journal| -> Result<Value> {
            let mut v = serde_json::to_value(j)?;
            for k in ["state", "error", "completion", "ordinary"] {
                v.as_object_mut().context("journal object")?.remove(k);
            }
            Ok(v)
        };
        ensure!(
            source.state == State::AwaitingHealthCompletion
                && source.completion.is_none()
                && strip(&source)? == strip(j)?
                && serde_json::to_value(source.health.as_ref().context("source health")?)?
                    == serde_json::to_value(&p.selected)?,
            "CONFLICT: completion source identity changed"
        );
        let grant = private(&self.complete_file(p, ".grant.json"), 32 << 10)?;
        ensure!(
            durable::hash(&grant) == p.profile_sha256,
            "CONFLICT: completion grant archive changed"
        );
        let config: Config = serde_json::from_slice(&grant)?;
        config.validate()?;
        ensure!(
            config.health_grant_sha256 == p.selected.profile_sha256,
            "CONFLICT: health grant not approved"
        );
        let health = private(
            &self
                .0
                .state
                .join("receipts")
                .join(format!("{}.health.json", p.selected.id)),
            1 << 20,
        )?;
        ensure!(
            Some(durable::hash(&health)) == p.selected.receipt_sha256,
            "CONFLICT: approved health receipt changed"
        );
        let normal = j.normal_boot.as_ref().context("normal source")?;
        let evidence = p.selected.evidence.as_ref().context("health evidence")?;
        ensure!(
            p.selected.verified
                && normal.id == p.normal_id
                && normal.sha256 == p.normal_sha256
                && evidence.report.process_id == p.pid,
            "CONFLICT: completion normal source"
        );
        Ok(config)
    }
    fn completion_pending(&self, j: &Journal, p: &Plan) -> Result<()> {
        let config = self.completion_source(j, p)?;
        let (_, bytes) = self
            .0
            .completion
            .as_ref()
            .context("FORBIDDEN: completion disabled")?
            .inputs()?;
        ensure!(
            durable::hash(&bytes) == p.profile_sha256
                && now() < p.not_after
                && p.selected.fresh()
                && p.selected
                    .requested_at
                    .is_some_and(|at| now() >= at
                        && now() - at <= config.maximum_observation_age_seconds * 1000),
            "CONFLICT: completion approval or health became stale"
        );
        let current_health = self
            .0
            .health
            .as_ref()
            .context("health disabled")?
            .inputs()?
            .1;
        ensure!(
            current_health == config.health_grant_sha256,
            "CONFLICT: approved health grant changed"
        );
        ensure!(
            self.verify_health_source(j, &p.selected)? == p.pid,
            "CONFLICT: approved process changed"
        );
        Ok(())
    }
    fn completion_decision(&self, p: &Plan) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"schema":"yofc.agent.write-release-authorization.v1",
            "completionId":p.id,"sourceJournalSha256":p.source_sha256,"policySha256":p.profile_sha256,
            "healthId":p.selected.id,"healthReceiptSha256":p.selected.receipt_sha256,
            "normalId":p.normal_id,"snapshotSha256":p.normal_sha256,"processId":p.pid,"nonce":p.nonce,
            "notAfterUnixMillis":p.not_after,"scope":"administrator-selected-checks","kuraRecoveryVerified":false}),
        )?)
    }
    fn release_fields(&self, p: &Plan) -> Result<BTreeMap<String, String>> {
        let report = &p
            .selected
            .evidence
            .as_ref()
            .context("health evidence")?
            .report;
        let hash_names = |names: &Vec<String>| durable::hash(names.join("\0").as_bytes());
        Ok(BTreeMap::from([
            ("schema".into(), "yofc.kura.write-release.v1".into()),
            ("status".into(), "ORDINARY_WRITES_RELEASE_COMMITTED".into()),
            ("scope".into(), "administrator-selected-checks".into()),
            ("completion.id".into(), p.id.clone()),
            ("recovery.id".into(), p.normal_id.clone()),
            ("snapshot.sha256".into(), p.normal_sha256.clone()),
            (
                "decision.sha256".into(),
                durable::hash(&self.completion_decision(p)?),
            ),
            (
                "health.receipt.sha256".into(),
                p.selected
                    .receipt_sha256
                    .clone()
                    .context("health receipt")?,
            ),
            ("policy.sha256".into(), p.profile_sha256.clone()),
            ("nonce".into(), p.nonce.clone()),
            ("process.id".into(), p.pid.to_string()),
            (
                "source.count".into(),
                report
                    .source_configuration_count
                    .context("source count")?
                    .to_string(),
            ),
            (
                "managed.count".into(),
                report.managed_configuration_count.to_string(),
            ),
            ("property.count".into(), report.property_count.to_string()),
            (
                "components.sha256".into(),
                hash_names(&p.selected.component_pids),
            ),
            ("checks.sha256".into(), hash_names(&p.selected.check_ids)),
            (
                "additional.grant.sha256".into(),
                hash_names(&p.selected.additional_self_pids),
            ),
            (
                "additional.observed.sha256".into(),
                hash_names(&report.materialized_self_pids),
            ),
            ("kuraRecoveryVerified".into(), "false".into()),
        ]))
    }
    fn java_release_receipt(&self, j: &Journal, p: &Plan) -> Result<String> {
        let (bytes, metadata) = durable::read(&self.java_release_path(j)?, 32 << 10)?;
        ensure!(
            metadata.mode & 0o077 == 0
                && metadata.uid == j.target_metadata.context("normal owner")?.uid,
            "CONFLICT: write release receipt owner"
        );
        let fields = self.release_fields(p)?;
        let expected = fields
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect::<String>();
        ensure!(
            bytes == expected.as_bytes(),
            "CONFLICT: write release receipt changed"
        );
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.java_release_path(j)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        ensure!(
            FileMetadata::from_fs(&file.metadata()?) == metadata,
            "CONFLICT: release receipt replaced"
        );
        file.sync_all()?;
        durable::sync_directory(path.parent().context("release receipt parent")?)?;
        let (again, after) = durable::read(&path, 32 << 10)?;
        ensure!(
            again == bytes && after == metadata,
            "CONFLICT: release receipt changed during sync"
        );
        Ok(durable::hash(&bytes))
    }
    pub(super) fn completion_final(&self, j: &Journal, p: &mut Plan) -> Result<()> {
        self.completion_source(j, p)?;
        let decision = private(&self.complete_file(p, ".decision.json"), 32 << 10)?;
        ensure!(
            p.issued
                && decision == self.completion_decision(p)?
                && Some(durable::hash(&decision)) == p.decision_sha256,
            "CONFLICT: release authorization missing"
        );
        let receipt = self.java_release_receipt(j, p)?;
        ensure!(
            p.java_receipt_sha256.as_ref().is_none_or(|h| h == &receipt),
            "CONFLICT: committed release changed"
        );
        p.java_receipt_sha256 = Some(receipt);
        let final_body = serde_json::to_vec(
            &json!({"schema":"yofc.agent.write-release-completion.v1","completionId":p.id,
            "decisionSha256":p.decision_sha256,"javaReceiptSha256":p.java_receipt_sha256,"scope":"administrator-selected-checks",
            "writeReleaseCommitted":true,"kuraRecoveryVerified":false,"normalBootVerified":false}),
        )?;
        let path = self.complete_file(p, ".completed.json");
        if path.exists() {
            ensure!(
                private(&path, 32 << 10)? == final_body,
                "CONFLICT: final completion receipt changed"
            );
        } else {
            durable::publish_new(&path, &final_body, FileMetadata::private())?;
        }
        p.completed = true;
        Ok(())
    }
    pub(super) fn recover_completion(&self, j: &mut Journal) -> Result<()> {
        let mut p = j.completion.clone().context("completion plan missing")?;
        // A durable Java decision is authoritative even if the agent died before its final journal marker.
        // This reads receipts only; it never repeats a release, starts a unit or compares mutable post-release CM/snapshots.
        if self.completion_final(j, &mut p).is_err() {
            self.retain_inverse_failure(j)?;
            anyhow::bail!("CONFLICT: completion unproven; never resend");
        }
        j.completion = Some(p);
        self.state(j, State::CompletedApprovedChecks)
    }
    pub async fn prepare_completion(&self, id: &str, token: &str) -> Result<Value> {
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move|this|{
            let mut j=this.journal()?.context("CONFLICT: no recovery")?;
            let selected=j.health.clone().context("CONFLICT: no health observation")?;
            ensure!(selected.id==id && selected.confirm_token==token,"FORBIDDEN: health transaction/token");
            ensure!(j.state==State::AwaitingHealthCompletion && j.completion.is_none(),"CONFLICT: completion cannot be prepared");
            this.recover_health(&mut j)?;
            let (config,grant)=this.0.completion.as_ref().context("FORBIDDEN: completion disabled")?.inputs()?;
            ensure!(selected.profile_sha256==config.health_grant_sha256,"FORBIDDEN: health policy not approved");
            let normal=j.normal_boot.as_ref().context("normal source")?;
            let source=serde_json::to_vec(&j)?;ensure!(source.len()<=1<<20,"CONFLICT: source quota");
            let mut p=Plan{id:format!("complete-{}",uuid::Uuid::new_v4()),confirm_token:uuid::Uuid::new_v4().to_string(),source_sha256:durable::hash(&source),
                profile_sha256:durable::hash(&grant),pid:selected.evidence.as_ref().context("health evidence")?.report.process_id,
                selected,normal_id:normal.id.clone(),normal_sha256:normal.sha256.clone(),nonce:durable::hash(uuid::Uuid::new_v4().as_bytes()),
                not_after:now()+config.valid_for_seconds*1000,issued:false,decision_sha256:None,java_receipt_sha256:None,completed:false,release_reply_verified:false};
            durable::publish_new(&this.complete_file(&p,".source.json"),&source,FileMetadata::private())?;
            durable::publish_new(&this.complete_file(&p,".grant.json"),&grant,FileMetadata::private())?;
            this.completion_pending(&j,&p)?;
            match fs::symlink_metadata(this.java_release_path(&j)?) {
                Err(error) if error.kind()==std::io::ErrorKind::NotFound => {},
                _=>anyhow::bail!("CONFLICT: retained release receipt"),
            }
            let token=p.confirm_token.clone();let id=p.id.clone();p.issued=false;j.completion=Some(p);this.state(&mut j,State::CompletionPrepared)?;
            Ok(json!({"transactionId":id,"confirmToken":token,"state":j.state,"scope":"administrator-selected-checks","kuraRecoveryVerified":false}))
        }).await
    }
    pub async fn execute_completion(
        &self,
        id: &str,
        token: &str,
        local: crate::local::Local,
    ) -> Result<Value> {
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        let runtime = tokio::runtime::Handle::current();
        self.write(move|this|{
            let mut j=this.journal()?.context("CONFLICT: no recovery")?;
            let mut p=j.completion.clone().context("CONFLICT: completion not prepared")?;
            ensure!(p.id==id && p.confirm_token==token,"FORBIDDEN: completion transaction/token");
            ensure!(j.state==State::CompletionPrepared && !p.issued,"CONFLICT: completion already attempted");
            this.completion_pending(&j,&p)?;
            let result:Result<()>=(||{
                p.issued=true;j.completion=Some(p.clone());this.state(&mut j,State::CommittingCompletion)?;
                let decision=this.completion_decision(&p)?;durable::publish_new(&this.complete_file(&p,".decision.json"),&decision,FileMetadata::private())?;
                p.decision_sha256=Some(durable::hash(&decision));j.completion=Some(p.clone());this.persist(&j)?;
                let old=&p.selected.evidence.as_ref().unwrap().report;
                let params=json!({"challenge":{"recoveryId":p.normal_id,"snapshotSha256":p.normal_sha256,"nonce":p.nonce,
                    "componentPids":p.selected.component_pids,"checkIds":p.selected.check_ids,"additionalSelfPids":p.selected.additional_self_pids},
                    "completionId":p.id,"decisionSha256":p.decision_sha256,"healthReceiptSha256":p.selected.receipt_sha256,
                    "policySha256":p.profile_sha256,"notAfterUnixMillis":p.not_after,
                    "bounds":{"sourceCount":old.source_configuration_count,"managedCount":old.managed_configuration_count,
                        "propertyCount":old.property_count,"materializedSelfPids":old.materialized_self_pids}});
                let value=runtime.block_on(local.recovery_completion(params)).map_err(|code|anyhow::anyhow!(code))?;
                let reply:Reply=serde_json::from_value(value)?;
                let fresh=&reply.pre_release_health;let mut wanted=serde_json::to_value(old)?;wanted["nonce"]=json!(p.nonce);
                ensure!(reply.schema==1 && reply.completion_id==p.id && reply.recovery_id==p.normal_id && reply.snapshot_sha256==p.normal_sha256
                    && Some(reply.decision_sha256)==p.decision_sha256 && reply.process_id==p.pid && reply.write_release_committed
                    && !reply.kura_recovery_verified && serde_json::to_value(fresh)?==wanted,"CONFLICT: write release response changed");
                let receipt=this.java_release_receipt(&j,&p)?;ensure!(receipt==reply.receipt_sha256,"CONFLICT: release receipt/response mismatch");
                p.release_reply_verified=true;p.java_receipt_sha256=Some(receipt);this.completion_final(&j,&mut p)?;j.completion=Some(p.clone());this.state(&mut j,State::CompletedApprovedChecks)
            })();
            if result.is_err() {
                // A lost response must not undo a committed Java decision. Reconcile the exact local receipt, never resend.
                if this.completion_final(&j,&mut p).is_ok() {
                    j.completion=Some(p.clone());this.state(&mut j,State::CompletedApprovedChecks)?;
                } else { this.retain_inverse_failure(&mut j)?;anyhow::bail!("CONFLICT: write release outcome unproven; inspect without resending"); }
            }
            Ok(p.status())
        }).await
    }
}
