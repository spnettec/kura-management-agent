//! Separate read-only observations of one active guarded Kura process. Passing
//! selected checks never releases writes or certifies the full recovery goal.
use super::*;
use std::collections::BTreeSet;

#[derive(Clone)]
pub(super) struct Profile(PathBuf);
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Config {
    schema: u32,
    component_pids: Vec<String>,
    check_ids: Vec<String>,
    #[serde(default = "default_framework_start_level")]
    framework_start_level: u32,
    #[serde(default)]
    additional_self_pids: Vec<String>,
    valid_for_seconds: u64,
}
fn default_framework_start_level() -> u32 {
    5
}
fn is_default_framework_start_level(level: &u32) -> bool {
    *level == default_framework_start_level()
}
impl Profile {
    pub(super) fn new(path: PathBuf) -> Result<Self> {
        let this = Self(path);
        this.inputs()?;
        Ok(this)
    }
    pub(super) fn inputs(&self) -> Result<(Config, String)> {
        ensure!(
            self.0.is_absolute(),
            "FORBIDDEN: absolute health grant required"
        );
        let (bytes, metadata) = durable::read(&self.0, 32 << 10)?;
        let parent = fs::symlink_metadata(self.0.parent().context("health grant parent")?)?;
        ensure!(
            metadata.mode & 0o077 == 0
                && (metadata.uid == 0 || metadata.uid == unsafe { libc::geteuid() })
                && parent.is_dir()
                && parent.mode() & 0o022 == 0,
            "FORBIDDEN: private health grant required"
        );
        let config: Config = serde_json::from_slice(&bytes)?;
        ensure!(
            config.schema == 1
                && (60..=600).contains(&config.valid_for_seconds)
                && (5..=9).contains(&config.framework_start_level),
            "FORBIDDEN: health grant bounds"
        );
        for (values, required) in [
            (&config.component_pids, true),
            (&config.check_ids, true),
            (&config.additional_self_pids, false),
        ] {
            let mut unique = BTreeSet::new();
            ensure!(
                (!required || !values.is_empty()) && values.len() <= 32,
                "FORBIDDEN: nonempty selected health conditions required"
            );
            for value in values {
                ensure!(
                    !value.trim().is_empty()
                        && value.len() <= 512
                        && !value.chars().any(char::is_control)
                        && unique.insert(value),
                    "FORBIDDEN: ambiguous health condition"
                );
            }
        }
        Ok((config, durable::hash(&bytes)))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ComponentState {
    pub(super) pid: String,
    pub(super) registered: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct CheckState {
    pub(super) id: String,
    pub(super) passed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Report {
    pub(super) schema: u32,
    pub(super) recovery_id: String,
    pub(super) snapshot_sha256: String,
    pub(super) nonce: String,
    pub(super) process_id: u32,
    pub(super) framework_start_level: u32,
    pub(super) normal_load: bool,
    pub(super) ordinary_writes_blocked: bool,
    pub(super) cm_matched: bool,
    pub(super) managed_configuration_count: u32,
    pub(super) property_count: u32,
    pub(super) configuration_service_available: bool,
    pub(super) components: Vec<ComponentState>,
    pub(super) checks: Vec<CheckState>,
    #[serde(default)]
    pub(super) source_configuration_count: Option<u32>,
    #[serde(default)]
    pub(super) materialized_self_pids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct FixedMainRequest {
    pub(crate) restore_id: String,
    pub(crate) receipt_sha256: String,
    component_pids: Vec<String>,
    check_ids: Vec<String>,
    #[serde(default)]
    additional_self_pids: Vec<String>,
}

impl FixedMainRequest {
    pub(crate) fn validate(&self) -> std::result::Result<(), &'static str> {
        if !crate::core_validation::restore_id(&self.restore_id)
            || self.receipt_sha256.len() != 64
            || !self
                .receipt_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("INVALID_ARGUMENT");
        }
        for (entries, mandatory) in [
            (&self.component_pids, true),
            (&self.check_ids, true),
            (&self.additional_self_pids, false),
        ] {
            if entries.len() > 32
                || mandatory && entries.is_empty()
                || entries.iter().collect::<BTreeSet<_>>().len() != entries.len()
                || entries.iter().any(|entry| {
                    entry.trim().is_empty()
                        || entry.len() > 512
                        || entry.chars().any(char::is_control)
                })
            {
                return Err("INVALID_ARGUMENT");
            }
        }
        Ok(())
    }

    pub(crate) fn challenge(&self, snapshot: &Value, nonce: &str) -> Value {
        json!({"recoveryId":self.restore_id,"snapshotSha256":snapshot,"nonce":nonce,
               "componentPids":self.component_pids,"checkIds":self.check_ids,
               "additionalSelfPids":self.additional_self_pids})
    }

    pub(crate) fn report(
        &self,
        raw: &Value,
        proof: &Value,
        nonce: &str,
        guarded: bool,
    ) -> std::result::Result<bool, &'static str> {
        let report: Report = serde::Deserialize::deserialize(raw).map_err(|_| "CONFLICT")?;
        if report.schema != 1
            || report.recovery_id != self.restore_id
            || report.nonce != nonce
            || Some(report.snapshot_sha256.as_str()) != proof["snapshotSha256"].as_str()
            || Some(u64::from(report.process_id)) != proof["invocation"]["pid"].as_u64()
            || report.framework_start_level != 6
            || report.normal_load != guarded
            || !report.ordinary_writes_blocked
            || report
                .source_configuration_count
                .is_none_or(|count| !(1..=4096).contains(&count))
            || report.managed_configuration_count > 4096
            || report.property_count > 65536
            || !report
                .components
                .iter()
                .map(|item| &item.pid)
                .eq(self.component_pids.iter())
            || !report
                .checks
                .iter()
                .map(|item| &item.id)
                .eq(self.check_ids.iter())
            || report
                .materialized_self_pids
                .iter()
                .any(|pid| !self.additional_self_pids.contains(pid))
        {
            return Err("CONFLICT");
        }
        Ok(report.cm_matched
            && report.configuration_service_available
            && report.components.iter().all(|item| item.registered)
            && report.checks.iter().all(|item| item.passed))
    }
}

#[cfg(test)]
mod fixed_main_tests {
    use super::*;

    #[test]
    fn applied_health_rejects_other_processes_and_reports_failed_checks() {
        let id = "rec-11111111-1111-4111-8111-111111111111";
        let digest = "a".repeat(64);
        let nonce = "b".repeat(64);
        let request: FixedMainRequest = serde_json::from_value(json!({
            "restoreId":id, "receiptSha256":digest, "componentPids":["demo"], "checkIds":["probe"]
        }))
        .unwrap();
        assert!(request.validate().is_ok());
        let proof = json!({"snapshotSha256":digest,"invocation":{"pid":222}});
        let mut report = json!({"schema":1,"recoveryId":id,"snapshotSha256":digest,"nonce":nonce,
            "processId":222,"frameworkStartLevel":6,"normalLoad":false,"ordinaryWritesBlocked":true,
            "cmMatched":true,"managedConfigurationCount":1,"propertyCount":1,"configurationServiceAvailable":true,
            "components":[{"pid":"demo","registered":true}],"checks":[{"id":"probe","passed":true}],
            "sourceConfigurationCount":1,"materializedSelfPids":[]});
        assert_eq!(request.report(&report, &proof, &nonce, false), Ok(true));
        report["checks"][0]["passed"] = json!(false);
        assert_eq!(request.report(&report, &proof, &nonce, false), Ok(false));
        report["normalLoad"] = json!(true);
        assert_eq!(request.report(&report, &proof, &nonce, false), Err("CONFLICT"));
        assert_eq!(request.report(&report, &proof, &nonce, true), Ok(false));
        report["checks"][0]["passed"] = json!(true);
        assert_eq!(request.report(&report, &proof, &nonce, true), Ok(true));
        report["ordinaryWritesBlocked"] = json!(false);
        assert_eq!(request.report(&report, &proof, &nonce, true), Err("CONFLICT"));
        report["ordinaryWritesBlocked"] = json!(true);
        report["normalLoad"] = json!(false);
        report["processId"] = json!(223);
        assert_eq!(request.report(&report, &proof, &nonce, false), Err("CONFLICT"));
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Evidence {
    pub(super) report: Report,
    pub(super) agent_instance_id: String,
    pub(super) bridge_epoch: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Plan {
    pub id: String,
    pub(super) confirm_token: String,
    pub(super) source_journal_sha256: String,
    pub(super) profile_sha256: String,
    pub(super) component_pids: Vec<String>,
    pub(super) check_ids: Vec<String>,
    #[serde(
        default = "default_framework_start_level",
        skip_serializing_if = "is_default_framework_start_level"
    )]
    pub(super) framework_start_level: u32,
    #[serde(default)]
    pub(super) additional_self_pids: Vec<String>,
    pub(super) valid_for_seconds: u64,
    pub(super) nonce: String,
    pub(super) issued: bool,
    #[serde(default)]
    pub(super) verified: bool,
    pub(super) requested_at: Option<u64>,
    pub(super) evidence: Option<Evidence>,
    pub(super) receipt_sha256: Option<String>,
}
impl Plan {
    pub(super) fn fresh(&self) -> bool {
        self.verified
            && self.evidence.is_some()
            && self
                .requested_at
                .is_some_and(|at| now() >= at && now() - at <= self.valid_for_seconds * 1000)
    }
    pub(super) fn status(&self) -> Value {
        json!({"id":self.id,"issued":self.issued,"selectedChecksVerified":self.verified,
            "observationWithinValidityWindow":self.fresh(),"requestedAtUnixMs":self.requested_at,"validForSeconds":self.valid_for_seconds,
            "normalBootVerified":false,"kuraRecoveryVerified":false,"awaitsExplicitCompletion":true,
            "report":self.evidence.as_ref().map(|e|&e.report)})
    }
}
impl Recovery {
    fn health_receipt(&self, p: &Plan) -> PathBuf {
        self.0
            .state
            .join("receipts")
            .join(format!("{}.health.json", p.id))
    }
    fn health_source(&self, p: &Plan) -> PathBuf {
        self.0
            .state
            .join("receipts")
            .join(format!("{}.health-source.json", p.id))
    }
    fn verify_health_base(&self, j: &Journal) -> Result<u32> {
        let normal = j
            .normal_boot
            .as_ref()
            .context("CONFLICT: guarded normal startup missing")?;
        ensure!(
            normal.issued && normal.admission.is_some(),
            "CONFLICT: guarded normal admission not proven"
        );
        self.verify_normal(j, normal)?;
        ensure!(
            Some(self.normal_admission(j, normal)?) == normal.admission,
            "CONFLICT: guarded normal receipt changed"
        );
        let (active, pid) = self.unit(&normal.unit)?;
        ensure!(
            active && pid > 0,
            "CONFLICT: guarded normal process inactive"
        );
        Ok(pid)
    }
    pub(super) fn verify_health_source(&self, j: &Journal, p: &Plan) -> Result<u32> {
        ensure!(
            p.id.strip_prefix("health-")
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok()),
            "CONFLICT: health identity"
        );
        let (config, sha) = self
            .0
            .health
            .as_ref()
            .context("FORBIDDEN: health checks disabled")?
            .inputs()?;
        ensure!(
            sha == p.profile_sha256
                && config.component_pids == p.component_pids
                && config.check_ids == p.check_ids
                && config.framework_start_level == p.framework_start_level
                && config.additional_self_pids == p.additional_self_pids
                && config.valid_for_seconds == p.valid_for_seconds,
            "CONFLICT: health grant changed"
        );
        let bytes = durable::read(&self.health_source(p), 1 << 20)?.0;
        ensure!(
            durable::hash(&bytes) == p.source_journal_sha256,
            "CONFLICT: health source anchor changed"
        );
        let source: Journal = serde_json::from_slice(&bytes)?;
        ensure!(
            matches!(
                source.state,
                State::AwaitingNormalBootCompletion | State::AwaitingHealthCompletion
            ),
            "CONFLICT: health source state"
        );
        let strip = |j: &Journal| -> Result<Value> {
            let mut value = serde_json::to_value(j)?;
            for key in ["state", "error", "health", "completion", "ordinary"] {
                value.as_object_mut().context("journal object")?.remove(key);
            }
            Ok(value)
        };
        ensure!(
            strip(&source)? == strip(j)?,
            "CONFLICT: health source identity changed"
        );
        self.verify_health_base(j)
    }
    fn health_receipt_body(&self, j: &Journal, p: &Plan) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"schema":"yofc.agent.recovery-health.v1","transactionId":p.id,
            "sourceTransactionId":j.id,"normalTransactionId":j.normal_boot.as_ref().unwrap().id,
            "status":"SELECTED_BUSINESS_VERIFIED","requestedAtUnixMs":p.requested_at,
            "validForSeconds":p.valid_for_seconds,"evidence":p.evidence,"normalBootVerified":false,
            "kuraRecoveryVerified":false,"awaitsExplicitCompletion":true}),
        )?)
    }
    pub(super) fn recover_health(&self, j: &mut Journal) -> Result<()> {
        let p = j.health.clone().context("health plan missing")?;
        let proof: Result<()> = (|| {
            ensure!(
                j.state == State::AwaitingHealthCompletion && p.issued && p.verified,
                "CONFLICT: health verification interrupted"
            );
            let pid = self.verify_health_source(j, &p)?;
            let evidence = p.evidence.as_ref().context("health evidence missing")?;
            ensure!(
                evidence.report.process_id == pid
                    && evidence.report.framework_start_level == p.framework_start_level,
                "CONFLICT: health process or framework level changed"
            );
            let (bytes, metadata) = durable::read(&self.health_receipt(&p), 1 << 20)?;
            ensure!(
                metadata.mode & 0o077 == 0
                    && metadata.uid == unsafe { libc::geteuid() }
                    && Some(durable::hash(&bytes)) == p.receipt_sha256
                    && bytes == self.health_receipt_body(j, &p)?,
                "CONFLICT: health receipt changed"
            );
            Ok(())
        })();
        if proof.is_err() {
            self.retain_inverse_failure(j)?;
        }
        ensure!(
            j.state == State::AwaitingHealthCompletion,
            "CONFLICT: health verification requires explicit inspection"
        );
        Ok(())
    }
    pub async fn prepare_health(&self, id: &str, token: &str) -> Result<Value> {
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move|this|{
            let mut j=this.journal()?.context("CONFLICT: no recovery transaction")?;
            let normal=j.normal_boot.as_ref().context("CONFLICT: no normal startup")?;
            ensure!(normal.id==id && normal.confirm_token==token,"FORBIDDEN: normal transaction/token");
            ensure!(matches!(j.state,State::AwaitingNormalBootCompletion|State::AwaitingHealthCompletion),"CONFLICT: health cannot be prepared");
            if j.health.is_some(){this.recover_health(&mut j)?;}else{this.verify_health_base(&j)?;}
            let (config,profile_sha256)=this.0.health.as_ref().context("FORBIDDEN: health checks disabled")?.inputs()?;
            let source=serde_json::to_vec(&j)?;ensure!(source.len()<=1<<20,"CONFLICT: health source quota");
            let id=format!("health-{}",uuid::Uuid::new_v4());
            let plan=Plan{id:id.clone(),confirm_token:uuid::Uuid::new_v4().to_string(),source_journal_sha256:durable::hash(&source),
                profile_sha256,component_pids:config.component_pids,check_ids:config.check_ids,
                framework_start_level:config.framework_start_level,additional_self_pids:config.additional_self_pids,valid_for_seconds:config.valid_for_seconds,
                nonce:durable::hash(uuid::Uuid::new_v4().as_bytes()),issued:false,verified:false,requested_at:None,evidence:None,receipt_sha256:None};
            durable::publish_new(&this.health_source(&plan),&source,FileMetadata::private())?;
            this.verify_health_source(&j,&plan)?;let token=plan.confirm_token.clone();j.health=Some(plan);this.state(&mut j,State::HealthPrepared)?;
            Ok(json!({"transactionId":id,"confirmToken":token,"state":j.state,"kuraRecoveryVerified":false}))
        }).await
    }
    pub async fn execute_health(
        &self,
        id: &str,
        token: &str,
        local: crate::local::Local,
    ) -> Result<Value> {
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        let runtime = tokio::runtime::Handle::current();
        self.write(move|this|{
            let mut j=this.journal()?.context("CONFLICT: no recovery transaction")?;
            let mut plan=j.health.clone().context("CONFLICT: health not prepared")?;
            ensure!(plan.id==id && plan.confirm_token==token,"FORBIDDEN: health transaction/token");
            ensure!(j.state==State::HealthPrepared && !plan.issued,"CONFLICT: health already attempted");
            let pid=this.verify_health_source(&j,&plan)?;
            let result:Result<()>=(||{
                this.state(&mut j,State::VerifyingHealth)?;plan.issued=true;plan.requested_at=Some(now());
                j.health=Some(plan.clone());this.persist(&j)?;
                let normal=j.normal_boot.as_ref().unwrap();
                let challenge=json!({"recoveryId":normal.id,"snapshotSha256":normal.sha256,"nonce":plan.nonce,
                    "componentPids":plan.component_pids,"checkIds":plan.check_ids,"additionalSelfPids":plan.additional_self_pids});
                let (value,instance,epoch)=runtime.block_on(local.recovery_verification(challenge)).map_err(|code|anyhow::anyhow!(code))?;
                let report:Report=serde_json::from_value(value)?;
                let application=this.normal_application(&j,normal.source)?;
                ensure!(report.schema==1 && report.recovery_id==normal.id && report.snapshot_sha256==normal.sha256
                    && report.nonce==plan.nonce && report.process_id==pid && report.property_count<=65536
                    && report.managed_configuration_count<=4096
                    && report.components.iter().map(|c|c.pid.clone()).collect::<Vec<_>>()==plan.component_pids
                    && report.checks.iter().map(|c|c.id.clone()).collect::<Vec<_>>()==plan.check_ids
                    && report.materialized_self_pids.iter().all(|pid|plan.additional_self_pids.contains(pid))
                    && report.materialized_self_pids.iter().collect::<BTreeSet<_>>().len()==report.materialized_self_pids.len(),
                    "CONFLICT: health response identity or shape not proven");
                let conditions=report.framework_start_level==plan.framework_start_level && report.normal_load && report.ordinary_writes_blocked
                    && report.cm_matched && report.configuration_service_available
                    && report.source_configuration_count==Some(application.replaced+application.created)
                    && report.managed_configuration_count==application.replaced+application.created+report.materialized_self_pids.len() as u32
                    && report.components.iter().all(|c|c.registered) && report.checks.iter().all(|c|c.passed);
                // Retain a typed, source-matching failed observation for inspection. It never gains verified status.
                plan.evidence=Some(Evidence{report,agent_instance_id:instance,bridge_epoch:epoch});
                j.health=Some(plan.clone());this.persist(&j)?;
                ensure!(conditions,"CONFLICT: selected business conditions not proven");plan.verified=true;
                ensure!(this.verify_health_source(&j,&plan)?==pid && plan.fresh(),"CONFLICT: health evidence became stale");
                let receipt=this.health_receipt_body(&j,&plan)?;
                durable::publish_new(&this.health_receipt(&plan),&receipt,FileMetadata::private())?;
                plan.receipt_sha256=Some(durable::hash(&receipt));j.health=Some(plan.clone());this.state(&mut j,State::AwaitingHealthCompletion)
            })();
            if result.is_err(){this.retain_inverse_failure(&mut j)?;
                anyhow::bail!("CONFLICT: health unproven; preserve state and query without resending");}
            Ok(json!({"transactionId":plan.id,"state":j.state,"selectedChecksVerified":true,"ordinaryWritesBlocked":true,
                "normalBootVerified":false,"kuraRecoveryVerified":false,"awaitsExplicitCompletion":true}))
        }).await
    }
}
