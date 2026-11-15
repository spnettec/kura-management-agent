//! Explicit abandonment of an unissued handoff. This never invokes a unit or a
//! business provider. The committed cancellation retains its approved parent.
use super::*;

pub(super) fn value(p: &Plan) -> Value {
    json!({"id":p.id,"unit":p.unit,"profileId":p.profile_id,"state":"ORDINARY_CANCELLED",
        "cancelled":true,"issued":false,"ordinaryUnitHandedOff":false,
        "scope":"administrator-selected-checks","kuraRecoveryVerified":false,"normalBootVerified":false})
}
fn receipt(p: &Plan) -> Result<Vec<u8>> {
    serde_json::to_vec(
        &json!({"schema":"yofc.agent.ordinary-cancel.v1","result":value(p),
        "sourceJournalSha256":p.source_sha256,"grantSha256":p.grant_sha256,
        "profileDigest":p.profile_digest,"cancellationCommand":p.cancel_command}),
    )
    .map_err(Into::into)
}
pub(super) fn validate(root: &std::path::Path, j: &Journal, committed: bool) -> Result<Vec<u8>> {
    ensure!(
        if committed {
            j.state == State::OrdinaryCancelled
        } else {
            matches!(
                j.state,
                State::OrdinaryCancelled | State::CancellingOrdinary
            )
        },
        "CONFLICT: cancellation not committed"
    );
    let p = j
        .ordinary
        .as_ref()
        .context("CONFLICT: no cancelled handoff")?;
    ensure!(
        p.cancelled
            && !p.issued
            && !p.verified
            && p.issued_command.is_none()
            && p.observation.is_none(),
        "CONFLICT: issued or verified handoff cannot be cancelled"
    );
    outcome::archived_inputs(root, j, p)?;
    outcome::validate_commands(root, j, p)?;
    if let Some(binding) = &p.cancel_command {
        ensure!(
            p.command_decisions.contains_key(&binding.command_id),
            "CONFLICT: unlinked cancellation command"
        );
    }
    let path = root
        .join("receipts")
        .join(format!("{}.ordinary-cancel.json", p.id));
    let bytes = outcome::private(&path)?;
    ensure!(
        bytes == receipt(p)?
            && if committed {
                p.receipt_sha256.as_ref() == Some(&durable::hash(&bytes))
            } else {
                p.receipt_sha256
                    .as_ref()
                    .is_none_or(|h| h == &durable::hash(&bytes))
            },
        "CONFLICT: cancellation receipt changed"
    );
    Ok(bytes)
}
impl Recovery {
    pub async fn cancel_ordinary(&self, id: &str, token: &str) -> Result<Value> {
        let before = self.ordinary_remote_status().await?;
        match self.cancel_ordinary_for(id, token, None).await {
            Ok(value) => Ok(value),
            Err(error) => match self.ordinary_remote_status().await {
                Ok(after) if before == after => Err(error),
                _ => {
                    anyhow::bail!("OUTCOME_UNKNOWN: cancellation decision changed or is unreadable")
                }
            },
        }
    }
    pub(super) async fn cancel_ordinary_for(
        &self,
        id: &str,
        token: &str,
        command: Option<&yofc_management_protocol::v1::ReadCommand>,
    ) -> Result<Value> {
        self.pending_executions_for(command).await?;
        let binding = command.map(outcome::Binding::from_command).transpose()?;
        let (id, token) = (id.to_owned(), token.to_owned());
        self.write(move |this| {
            let mut j = this.journal()?.context("CONFLICT: no ordinary handoff")?;
            let mut p = j
                .ordinary
                .clone()
                .context("CONFLICT: no prepared ordinary handoff")?;
            ensure!(
                p.id == id && p.confirm_token == token,
                "FORBIDDEN: ordinary cancellation transaction/token"
            );
            ensure!(
                j.state == State::OrdinaryPrepared
                    && !p.issued
                    && !p.cancelled
                    && p.issued_command.is_none(),
                "CONFLICT: only an unissued prepared handoff can be cancelled"
            );
            this.ordinary_archive_inputs(&j, &p)?;
            this.validate_ordinary_commands(&j, &p)?;
            // No expiry/current-unit checks: expiry revokes execution authority,
            // not the authority to abandon a plan that never issued an action.
            p.cancelled = true;
            p.cancel_command = binding.clone();
            j.ordinary = Some(p.clone());
            this.state(&mut j, State::CancellingOrdinary)?;
            let result = value(&p);
            if let Some(binding) = binding {
                this.record_ordinary_command(&j.id, &mut p, binding, &result)?;
            }
            j.ordinary = Some(p.clone());
            this.persist(&j)?;
            let body = receipt(&p)?;
            durable::publish_new(
                &this.ordinary_file(&p, ".ordinary-cancel.json"),
                &body,
                FileMetadata::private(),
            )?;
            p.receipt_sha256 = Some(durable::hash(&body));
            j.ordinary = Some(p);
            this.state(&mut j, State::OrdinaryCancelled)?;
            Ok(result)
        })
        .await
    }
    pub(super) fn recover_ordinary_cancel(&self, j: &mut Journal) -> Result<()> {
        match validate(&self.0.state, j, j.state == State::OrdinaryCancelled) {
            Ok(bytes) => {
                if j.state == State::OrdinaryCancelled {
                    return Ok(());
                }
                let p = j.ordinary.as_ref().unwrap();
                let path = self.ordinary_file(p, ".ordinary-cancel.json");
                fs::File::open(&path)?.sync_all()?;
                durable::sync_directory(path.parent().context("cancellation receipt parent")?)?;
                j.ordinary.as_mut().unwrap().receipt_sha256 = Some(durable::hash(&bytes));
                self.state(j, State::OrdinaryCancelled)
            }
            Err(error) => {
                // Preserve an uncertain non-action; never stop/start a healthy
                // parent as compensation for failure to persist cancellation.
                j.error = Some(
                    "Ordinary cancellation unproven; preserve evidence and do not retry".into(),
                );
                self.state(j, State::RecoveryRequired)?;
                Err(error)
            }
        }
    }
}
