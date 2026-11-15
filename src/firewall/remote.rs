//! Remote authority is separate from a Kura UID/session owner. Only transport
//! constructs connection witnesses; no action payload can assert connectivity.
use super::*;
use prost::Message;
use sha2::{Digest, Sha256};
use yofc_management_protocol::v1::{ErrorCode, Operation, ReadCommand, TaskResult, TaskState};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    authority: String,
    command_id: String,
    command_hash: String,
    connection: String,
    applied_at_ms: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActionBinding {
    command_id: String,
    command_hash: String,
    operation: i32,
    new_connection_proved: bool,
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn command_hash(command: &ReadCommand) -> String {
    hash(&command.encode_to_vec())
}
fn connection_time(session: &str) -> Result<u64> {
    let mut parts = session.splitn(3, ':');
    let at = parts
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0);
    let nonce = parts.next().and_then(|v| uuid::Uuid::parse_str(v).ok());
    ensure!(
        at.is_some() && nonce.is_some(),
        "FORBIDDEN: authenticated connection required"
    );
    Ok(at.unwrap())
}
fn valid_authority(authority: &str) -> bool {
    authority.len() == 64
        && authority
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Firewall {
    fn remote_path(&self, identity: &str) -> PathBuf {
        self.0
            .state
            .join("remote-history")
            .join(format!("{}.json", hash(identity.as_bytes())))
    }
    pub(super) fn archive_remote(&self, j: &Journal) -> Result<()> {
        let Some(binding) = &j.remote_binding else {
            return Ok(());
        };
        ensure!(
            j.state.settled(),
            "CONFLICT: remote firewall transaction active"
        );
        for identity in [&binding.command_id, &j.id] {
            let path = self.remote_path(identity);
            if path.try_exists()? {
                let saved = durable::read(&path, LIMIT)?.0;
                ensure!(
                    saved == serde_json::to_vec(j)?,
                    "CONFLICT: remote history differs"
                );
            } else {
                durable::directory(path.parent().unwrap())?;
                durable::publish_new(
                    &path,
                    &serde_json::to_vec(j)?,
                    durable::FileMetadata::private(),
                )?;
            }
        }
        Ok(())
    }
    fn remote_original(&self, identity: &str) -> Result<Option<(Journal, Vec<u8>)>> {
        for path in [
            self.0.state.join("transaction.json"),
            self.remote_path(identity),
        ] {
            if !path.try_exists()? {
                continue;
            }
            let bytes = durable::read(&path, LIMIT)?.0;
            let j: Journal = serde_json::from_slice(&bytes)?;
            if j.id == identity
                || j.remote_binding
                    .as_ref()
                    .is_some_and(|b| b.command_id == identity)
            {
                return Ok(Some((j, bytes)));
            }
        }
        Ok(None)
    }
    fn remote_projection(&self, j: &Journal, token: bool) -> Result<Value> {
        let mut value = json!({"id":j.id,"state":j.state,"deadlineUnixMs":j.deadline_ms,
            "revision":if j.state==State::Committed {j.old.revision+1} else {j.old.revision},
            "requestId":j.request_id,"newManagementConnectionRequired":true,
            "newManagementConnectionVerified":j.state==State::Committed && j.remote_actions.iter().any(|a|a.operation==32 && a.new_connection_proved)});
        if token {
            value["confirmationToken"] = json!(j.token);
            value["candidate"] = serde_json::to_value(&j.candidate)?;
        }
        Ok(value)
    }
    pub(crate) async fn remote_request(
        &self,
        command: &ReadCommand,
        authority: &str,
        connection: &str,
        grant: bool,
    ) -> Result<Value> {
        ensure!(grant, "UNSUPPORTED: remote firewall disabled");
        ensure!(
            valid_authority(authority),
            "FORBIDDEN: remote authority required"
        );
        ensure!(
            command.valid_payload() && uuid::Uuid::parse_str(&command.command_id).is_ok(),
            "INVALID_ARGUMENT: firewall command"
        );
        if command.operation == Operation::FirewallView as i32 {
            let view_authority = authority.to_owned();
            let view_connection = connection.to_owned();
            return self.observe(move |this| {
                let confirmed=this.confirmed()?;
                let candidate=confirmed.kura_policy()?;
                let journal=this.journal()?;
                let ready=journal.as_ref().is_some_and(|j|j.state==State::WaitConfirm && j.remote_binding.as_ref().is_some_and(|b|b.authority==view_authority && b.applied_at_ms>0 && b.connection!=view_connection && connection_time(&view_connection).is_ok_and(|at|at>b.applied_at_ms)));
                let transaction=journal.as_ref().map(|j|json!({"id":j.id,"state":j.state,"deadlineUnixMs":j.deadline_ms,
                    "revision":if j.state==State::Committed {j.old.revision+1} else {j.old.revision},"currentRevision":confirmed.revision,"requestId":j.request_id}));
                // The remote view has its own lease digest. A later transaction,
                // including rollback to the same values, invalidates old drafts.
                let source=hash(&serde_json::to_vec(&json!({"confirmed":confirmed,"journal":journal}))?);
                Ok(json!({"schemaVersion":1,"revision":confirmed.revision,"sourceDigest":source,
                    "initialized":confirmed.text.is_some(),"projectable":candidate.is_some(),"candidate":candidate,
                    "writeEnabled":this.0.write_enabled,"confirmationReady":ready,"transaction":transaction}))
            }).await;
        }

        let connected_at = connection_time(connection)?;
        let command = command.clone();
        let authority = authority.to_owned();
        let connection = connection.to_owned();
        self.write(move |this| {
            let mut entered = false;
            let result = (|| -> Result<Value> {
                match Operation::try_from(command.operation)? {
                    Operation::FirewallPrepare => {
                        ensure!(this.0.write_enabled, "FORBIDDEN: firewall writes disabled");
                        ensure!(
                            this.remote_original(&command.command_id)?.is_none(),
                            "OUTCOME_UNKNOWN: query original firewall command"
                        );
                        let change = command.firewall_change.as_ref().unwrap();
                        let candidate: model::KuraPolicy =
                            serde_json::from_slice(&change.candidate_json).map_err(|_| {
                                anyhow::anyhow!("INVALID_ARGUMENT: firewall candidate")
                            })?;
                        let candidate = VersionedCandidate::from(candidate);
                        let text = candidate.render()?;
                        let old = this.confirmed()?;
                        ensure!(
                            old.revision == change.expected_revision
                                && hash(&serde_json::to_vec(
                                    &json!({"confirmed":old,"journal":this.journal()?})
                                )?) == change.source_digest,
                            "CONFLICT: stale confirmed firewall view"
                        );
                        let mut j = this.prepare_inner(
                            candidate,
                            text,
                            change.confirm_seconds as u64,
                            command.command_id.clone(),
                            None,
                        )?;
                        j.remote_binding = Some(Binding {
                            authority,
                            command_id: command.command_id.clone(),
                            command_hash: command_hash(&command),
                            connection,
                            applied_at_ms: 0,
                        });
                        this.persist("transaction.json", &j)?; // bind before applying
                        entered = true;
                        this.apply_inner(&mut j)?;
                        j.remote_binding.as_mut().unwrap().applied_at_ms = now();
                        this.persist("transaction.json", &j)?;
                        this.remote_projection(&j, true)
                    }
                    Operation::FirewallConfirm | Operation::FirewallRollback => {
                        let confirm = command.operation == Operation::FirewallConfirm as i32;
                        ensure!(
                            !confirm || this.0.write_enabled,
                            "FORBIDDEN: firewall writes disabled"
                        );
                        let action = command.firewall_action.as_ref().unwrap();
                        let mut j = this
                            .journal()?
                            .context("CONFLICT: no firewall transaction")?;
                        let b = j
                            .remote_binding
                            .as_ref()
                            .context("FORBIDDEN: not a remote transaction")?;
                        ensure!(
                            b.authority == authority
                                && j.id == action.transaction_id
                                && j.token == action.confirmation_token,
                            "FORBIDDEN: firewall authority or action token"
                        );
                        ensure!(
                            !j.state.settled()
                                && !j
                                    .remote_actions
                                    .iter()
                                    .any(|a| a.operation == command.operation),
                            "CONFLICT: firewall action already issued"
                        );
                        if confirm {
                            ensure!(
                                j.state == State::WaitConfirm && now() < j.deadline_ms,
                                "CONFLICT: firewall state or deadline"
                            );
                            ensure!(
                                b.applied_at_ms > 0
                                    && connected_at > b.applied_at_ms
                                    && connection != b.connection,
                                "FORBIDDEN: new authenticated management connection required"
                            );
                        }
                        j.remote_actions.push(ActionBinding {
                            command_id: command.command_id.clone(),
                            command_hash: command_hash(&command),
                            operation: command.operation,
                            new_connection_proved: confirm,
                        });
                        this.persist("transaction.json", &j)?; // action identity before any side effect
                        entered = true;
                        if confirm {
                            this.verify(Some(&j.candidate_text))?;
                            j.confirmed_decision = true;
                            j.state = State::Confirming;
                            this.persist("transaction.json", &j)?;
                            this.commit(&mut j)?;
                        } else {
                            this.rollback_inner(&mut j)?;
                        }
                        this.remote_projection(&j, false)
                    }
                    _ => anyhow::bail!("UNSUPPORTED: remote firewall operation"),
                }
            })();
            if entered && result.is_err() {
                anyhow::bail!(
                    "OUTCOME_UNKNOWN: firewall action interrupted; query original command"
                )
            }
            result
        })
        .await
    }
    /// Reads durable domain evidence only: no nft, repair, expiry or dispatch.
    pub(crate) async fn prove_remote(
        &self,
        command: &ReadCommand,
        authority: &str,
    ) -> Result<Option<TaskResult>> {
        let command = command.clone();
        let authority = authority.to_owned();
        self.observe(move |this| {
            if !matches!(command.operation,31..=33) || !command.valid_payload() || !valid_authority(&authority) {return Ok(None)}
            let identity=command.firewall_action.as_ref().map(|v|v.transaction_id.as_str()).unwrap_or(&command.command_id);
            let Some((j,bytes))=this.remote_original(identity)? else {return Ok(None)};
            let Some(b)=&j.remote_binding else {return Ok(None)};
            if b.authority!=authority {return Ok(None)}
            let committed=j.state==State::Committed && j.confirmed_decision;
            let rolled_back=j.state==State::RolledBack && !j.confirmed_decision;
            let prepared=j.state==State::WaitConfirm && b.applied_at_ms>0 && now()<j.deadline_ms;
            let prepare=command.operation==31;
            let matched=if prepare {
                b.command_id==command.command_id && b.command_hash==command_hash(&command) && (prepared||committed||rolled_back)
            } else {
                j.remote_actions.iter().any(|a| a.command_id==command.command_id && a.command_hash==command_hash(&command)
                    && a.operation==command.operation && ((command.operation==32 && (committed||rolled_back) && a.new_connection_proved) || (command.operation==33 && rolled_back)))
            };
            if !matched {return Ok(None)}
            let succeeded=match command.operation {31=>!rolled_back,32=>committed,33=>rolled_back,_=>false};
            let mut value=this.remote_projection(&j,prepare && succeeded)?;
            value["reconciliation"]=json!({"source":"firewall.remote.journal.v1","commandId":command.command_id,
                "transactionId":j.id,"operation":command.operation,"requestSha256":command_hash(&command),"journalSha256":hash(&bytes),"observedAtUnixMs":now()});
            Ok(Some(TaskResult{command_id:command.command_id,state:if succeeded{TaskState::Succeeded}else{TaskState::Failed}as i32,
                error:if succeeded{ErrorCode::Unspecified}else{ErrorCode::Conflict}as i32,result_json:serde_json::to_vec(&value)?}))
        }).await
    }
}
