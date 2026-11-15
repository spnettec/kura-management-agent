//! A third fixed startup grant admits the ordinary Kura load path while all
//! ordinary writes remain gated. Admission is not business health or completion.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SourceKind {
    #[default]
    Inverse,
    AppliedForward,
}
impl SourceKind {
    fn is_inverse(&self) -> bool {
        *self == Self::Inverse
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Plan {
    #[serde(default, skip_serializing_if = "SourceKind::is_inverse")]
    pub(super) source: SourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    forward_grant_sha256: Option<String>,
    pub id: String,
    pub(super) confirm_token: String,
    pub unit: String,
    pub(super) target: PathBuf,
    pub(super) sha256: String,
    metadata: FileMetadata,
    source_journal_sha256: String,
    validation: crate::snapshot_validation::Proof,
    pub(super) parameters: Vec<(String, String)>,
    pub(super) startup: crate::controlled_startup::Prepared,
    pub issued: bool,
    pub admission: Option<crate::controlled_startup::NormalAdmission>,
}
impl Plan {
    pub(super) fn status(&self) -> Value {
        json!({"id":self.id,"unit":self.unit,"issued":self.issued,"admission":self.admission,
            "normalSource":self.source,"normalBootVerified":false,"businessHealth":"UNVERIFIED","awaitsExplicitCompletion":true})
    }
}
impl Recovery {
    fn normal_validator(&self) -> Result<&crate::snapshot_validation::Validator> {
        self.0
            .normal_validator
            .as_ref()
            .or(self.0.validator.as_ref())
            .context("normal validator disabled")
    }
    fn verify_normal_base(&self, j: &Journal, source: SourceKind) -> Result<()> {
        if source == SourceKind::AppliedForward {
            ensure!(
                j.inverse.is_none() && j.backup_ready,
                "CONFLICT: ambiguous applied-forward source"
            );
            self.source_application(j)?;
            let mut expected = j.base.clone();
            let candidate = self.0.root.join(&j.target);
            expected.push(SnapshotFile {
                name: candidate
                    .file_name()
                    .context("forward name")?
                    .to_str()
                    .context("forward name encoding")?
                    .into(),
                size: j.size,
                sha256: j.sha256.clone(),
                metadata: j.target_metadata.context("forward metadata missing")?,
            });
            expected.sort_by(|a, b| a.name.cmp(&b.name));
            ensure!(
                self.inventory()? == expected,
                "CONFLICT: applied-forward snapshot set drifted"
            );
            if j.normal_boot.as_ref().is_some_and(|p| p.issued) {
                self.stopped(&j.unit)?;
            }
            if let Some(inverse) = &self.0.inverse_startup {
                self.stopped(&inverse.unit()?)?;
            }
            return Ok(());
        }
        let inverse = j.inverse.as_ref().context("CONFLICT: inverse missing")?;
        let set = inverse
            .snapshot_set
            .as_ref()
            .context("CONFLICT: snapshot set missing")?;
        ensure!(
            set.issued && set.applied,
            "CONFLICT: snapshot set not applied"
        );
        self.verify_snapshot_set(j, set, true)?;
        let receipt = durable::read(&self.snapshot_receipt(set), 1 << 20)?.0;
        ensure!(
            Some(durable::hash(&receipt)) == set.receipt_sha256,
            "CONFLICT: snapshot receipt changed"
        );
        self.stopped(&j.unit)?;
        self.stopped(&inverse.unit)?;
        Ok(())
    }
    pub(super) fn normal_application<'a>(
        &self,
        j: &'a Journal,
        source: SourceKind,
    ) -> Result<&'a crate::controlled_startup::Application> {
        let application = match source {
            SourceKind::Inverse => j.inverse.as_ref().and_then(|i| i.application.as_ref()),
            SourceKind::AppliedForward => j.cm_application.as_ref(),
        }
        .context("CONFLICT: exact normal source application missing")?;
        ensure!(
            application.compensation.is_some(),
            "CONFLICT: exact normal source CM evidence missing"
        );
        Ok(application)
    }
    fn normal_parameters(
        &self,
        j: &Journal,
        proof: &crate::snapshot_validation::Proof,
        source: SourceKind,
    ) -> Result<Vec<(String, String)>> {
        let application = self.normal_application(j, source)?;
        let receipt = match source {
            SourceKind::Inverse => {
                &j.inverse
                    .as_ref()
                    .context("inverse source missing")?
                    .startup
                    .receipt_path
            }
            SourceKind::AppliedForward => {
                &j.controlled_startup
                    .as_ref()
                    .context("forward source missing")?
                    .receipt_path
            }
        };
        let mut values = self.normal_validator()?.startup_parameters(proof)?;
        values.extend([
            ("verification.mode".into(), "normal-read-only".into()),
            (
                "verification.source.receipt".into(),
                receipt.to_str().context("source encoding")?.into(),
            ),
            (
                "verification.source.receipt.sha256".into(),
                application.receipt_sha256.clone(),
            ),
            (
                "verification.source.applied.sha256".into(),
                application
                    .compensation
                    .as_ref()
                    .unwrap()
                    .applied_sha256
                    .clone(),
            ),
        ]);
        Ok(values)
    }
    pub(super) fn verify_normal(&self, j: &Journal, p: &Plan) -> Result<()> {
        self.verify_normal_base(j, p.source)?;
        if p.source == SourceKind::AppliedForward {
            let normal = self
                .0
                .normal_startup
                .as_ref()
                .context("normal startup missing")?;
            let (sha, _) = self
                .0
                .forward_normal
                .as_ref()
                .context("FORBIDDEN: applied-forward normal startup disabled")?
                .inputs(&normal.authority_sha256()?)?;
            let archived = durable::read(
                &self
                    .0
                    .state
                    .join("receipts")
                    .join(format!("{}.forward-normal-grant.json", p.id)),
                32 << 10,
            )?
            .0;
            ensure!(
                p.forward_grant_sha256.as_deref() == Some(sha.as_str())
                    && durable::hash(&archived) == sha,
                "CONFLICT: applied-forward normal approval changed"
            );
        } else {
            ensure!(
                p.forward_grant_sha256.is_none(),
                "CONFLICT: unexpected forward authority"
            );
        }
        let bytes = durable::read(
            &self
                .0
                .state
                .join("receipts")
                .join(format!("{}.normal-source.json", p.id)),
            1 << 20,
        )?
        .0;
        ensure!(
            durable::hash(&bytes) == p.source_journal_sha256,
            "CONFLICT: normal source anchor changed"
        );
        let source: Journal = serde_json::from_slice(&bytes)?;
        ensure!(
            source.state
                == (if p.source == SourceKind::Inverse {
                    State::AwaitingSnapshotCompletion
                } else {
                    State::AwaitingCompletion
                })
                && source.normal_boot.is_none(),
            "CONFLICT: invalid normal source state"
        );
        let strip = |value: &Journal| -> Result<Value> {
            let mut v = serde_json::to_value(value)?;
            for key in [
                "state",
                "error",
                "normal_boot",
                "health",
                "completion",
                "ordinary",
            ] {
                v.as_object_mut().context("journal object")?.remove(key);
            }
            Ok(v)
        };
        ensure!(
            strip(j)? == strip(&source)?,
            "CONFLICT: normal source identity changed"
        );
        ensure!(
            self.0.units.contains(&p.unit)
                && p.unit != j.unit
                && j.inverse
                    .as_ref()
                    .is_none_or(|inverse| p.unit != inverse.unit),
            "FORBIDDEN: independent normal unit no longer allowed"
        );
        let (bytes, metadata) = durable::read(&p.target, LIMIT_BYTES)?;
        ensure!(
            durable::hash(&bytes) == p.sha256 && metadata == p.metadata,
            "CONFLICT: normal artifact changed"
        );
        let validator = self.normal_validator()?;
        ensure!(
            validator.validate(&p.target, &p.sha256, Some(&p.validation))? == p.validation
                && self.normal_parameters(j, &p.validation, p.source)? == p.parameters,
            "CONFLICT: normal validator/authority drift"
        );
        self.0
            .normal_startup
            .as_ref()
            .context("FORBIDDEN: normal startup disabled")?
            .verify_prepared(
                &p.startup,
                &p.unit,
                &p.id,
                &p.target,
                &p.sha256,
                &p.parameters,
            )
    }
    pub(super) fn normal_admission(
        &self,
        j: &Journal,
        p: &Plan,
    ) -> Result<crate::controlled_startup::NormalAdmission> {
        let application = self.normal_application(j, p.source)?;
        self.0
            .normal_startup
            .as_ref()
            .context("normal startup disabled")?
            .normal_admission(
                &p.startup,
                &p.id,
                &p.sha256,
                &application.receipt_sha256,
                &application.compensation.as_ref().unwrap().applied_sha256,
                p.metadata,
            )
    }
    pub(super) fn recover_normal_boot(&self, j: &mut Journal) -> Result<()> {
        let plan = j.normal_boot.clone().context("normal plan missing")?;
        let proof: Result<()> = (|| {
            ensure!(
                j.state == State::AwaitingNormalBootCompletion && plan.issued,
                "CONFLICT: normal startup interrupted"
            );
            self.verify_normal(j, &plan)?;
            ensure!(
                Some(self.normal_admission(j, &plan)?) == plan.admission
                    && self.unit(&plan.unit)?.0,
                "CONFLICT: normal admission or unit changed"
            );
            Ok(())
        })();
        if proof.is_err() {
            self.retain_inverse_failure(j)?;
        }
        ensure!(
            j.state == State::AwaitingNormalBootCompletion,
            "CONFLICT: normal startup requires explicit inspection"
        );
        Ok(())
    }
    fn prepare_normal_plan(&self, j: &mut Journal, source: SourceKind) -> Result<Value> {
        self.verify_normal_base(j, source)?;
        let startup = self
            .0
            .normal_startup
            .as_ref()
            .context("FORBIDDEN: normal startup disabled")?;
        let unit = startup.unit()?;
        self.stopped(&unit)?;
        let candidates = self.inventory()?;
        for file in &candidates {
            if let Some(text) = file
                .name
                .strip_prefix("snapshot_")
                .and_then(|s| s.strip_suffix(".xml"))
            {
                let number = text
                    .parse::<i64>()
                    .context("CONFLICT: noncanonical normal snapshot")?;
                ensure!(
                    number >= 0 && file.name == format!("snapshot_{number}.xml"),
                    "CONFLICT: ambiguous normal snapshot filename"
                );
            }
        }
        let file = candidates
            .iter()
            .filter_map(|f| {
                f.name
                    .strip_prefix("snapshot_")
                    .and_then(|s| s.strip_suffix(".xml"))
                    .and_then(|n| n.parse::<i64>().ok())
                    .map(|n| (n, f))
            })
            .max_by_key(|(n, _)| *n)
            .context("CONFLICT: normal snapshot required")?
            .1;
        let target = self.snapshots()?.join(&file.name);
        if source == SourceKind::AppliedForward {
            ensure!(
                target == self.0.root.join(&j.target) && file.sha256 == j.sha256,
                "CONFLICT: forward candidate is not the ordinary startup snapshot"
            );
        }
        let validation = self.normal_validator()?.validate(
            &target,
            &file.sha256,
            if self.0.normal_validator.is_some() {
                None
            } else {
                j.snapshot_validation.as_ref()
            },
        )?;
        let parameters = self.normal_parameters(j, &validation, source)?;
        let id = format!("rec-{}", uuid::Uuid::new_v4());
        let prepared = startup.prepare(
            &unit,
            &id,
            &target,
            &file.sha256,
            &parameters,
            file.metadata,
        )?;
        let anchor = serde_json::to_vec(j)?;
        durable::publish_new(
            &self
                .0
                .state
                .join("receipts")
                .join(format!("{id}.normal-source.json")),
            &anchor,
            FileMetadata::private(),
        )?;
        let forward_grant_sha256 = if source == SourceKind::AppliedForward {
            let (sha, bytes) = self
                .0
                .forward_normal
                .as_ref()
                .context("FORBIDDEN: applied-forward normal disabled")?
                .inputs(&startup.authority_sha256()?)?;
            durable::publish_new(
                &self
                    .0
                    .state
                    .join("receipts")
                    .join(format!("{id}.forward-normal-grant.json")),
                &bytes,
                FileMetadata::private(),
            )?;
            Some(sha)
        } else {
            None
        };
        let plan = Plan {
            source,
            forward_grant_sha256,
            id: id.clone(),
            confirm_token: uuid::Uuid::new_v4().to_string(),
            unit,
            target,
            sha256: file.sha256.clone(),
            metadata: file.metadata,
            source_journal_sha256: durable::hash(&anchor),
            validation,
            parameters,
            startup: prepared,
            issued: false,
            admission: None,
        };
        self.verify_normal(j, &plan)?;
        let token = plan.confirm_token.clone();
        j.normal_boot = Some(plan);
        self.state(j, State::NormalBootPrepared)?;
        Ok(
            json!({"transactionId":id,"confirmToken":token,"state":j.state,"normalSource":source,"normalBootVerified":false,"kuraRecoveryVerified":false}),
        )
    }
    pub async fn prepare_normal_boot(&self, id: &str, token: &str) -> Result<Value> {
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move |this| {
            let mut j = this
                .journal()?
                .context("CONFLICT: no recovery transaction")?;
            let set = j
                .inverse
                .as_ref()
                .and_then(|i| i.snapshot_set.as_ref())
                .context("CONFLICT: no snapshot set")?;
            ensure!(
                set.id == id && set.confirm_token == token,
                "FORBIDDEN: snapshot transaction/token"
            );
            ensure!(
                j.state == State::AwaitingSnapshotCompletion && j.normal_boot.is_none(),
                "CONFLICT: normal startup cannot be prepared"
            );
            this.prepare_normal_plan(&mut j, SourceKind::Inverse)
        })
        .await
    }
    pub async fn prepare_applied_normal_boot(&self, id: &str, token: &str) -> Result<Value> {
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move |this| {
            let mut j = this
                .journal()?
                .context("CONFLICT: no recovery transaction")?;
            ensure!(
                this.0.forward_normal.is_some(),
                "FORBIDDEN: applied-forward normal startup disabled"
            );
            ensure!(
                j.id == id && j.confirm_token == token,
                "FORBIDDEN: forward transaction/token"
            );
            ensure!(
                j.state == State::AwaitingCompletion
                    && j.inverse.is_none()
                    && j.normal_boot.is_none(),
                "CONFLICT: applied-forward normal startup cannot be prepared"
            );
            this.prepare_normal_plan(&mut j, SourceKind::AppliedForward)
        })
        .await
    }
    pub async fn execute_normal_boot(&self, id: &str, token: &str) -> Result<Value> {
        self.pending_executions().await?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move |this| {
            let mut j=this.journal()?.context("CONFLICT: no recovery transaction")?;
            let mut plan=j.normal_boot.clone().context("CONFLICT: normal startup not prepared")?;
            ensure!(plan.id==id && plan.confirm_token==token,"FORBIDDEN: normal transaction/token");
            ensure!(j.state==State::NormalBootPrepared && !plan.issued,"CONFLICT: normal startup already attempted");
            this.verify_normal(&j,&plan)?;this.stopped(&plan.unit)?;
            let result:Result<()>=(|| {
                this.state(&mut j,State::StartingNormalBoot)?;
                if plan.source == SourceKind::AppliedForward { this.stop(&j.unit)?; }
                this.verify_normal(&j,&plan)?;this.stopped(&plan.unit)?;
                plan.issued=true;j.normal_boot=Some(plan.clone());this.persist(&j)?;
                this.0.normal_startup.as_ref().unwrap().publish(&plan.startup,&plan.id,&plan.target,&plan.sha256,&plan.parameters,plan.metadata)?;
                this.start(&plan.unit)?;
                plan.admission=Some(this.normal_admission(&j,&plan)?);
                this.verify_normal(&j,&plan)?;
                ensure!(this.unit(&plan.unit)?.0,"CONFLICT: admitted normal unit inactive");
                j.normal_boot=Some(plan.clone());this.state(&mut j,State::AwaitingNormalBootCompletion)
            })();
            if result.is_err(){this.retain_inverse_failure(&mut j)?;
                anyhow::bail!("CONFLICT: normal startup unproven; retain and query, do not resend");}
            Ok(json!({"transactionId":plan.id,"state":j.state,"normalBootVerified":false,"kuraRecoveryVerified":false,
                "guardedNormalLoadAdmitted":true,"businessHealth":"UNVERIFIED","awaitsExplicitCompletion":true}))
        }).await
    }
}
