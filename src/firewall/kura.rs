//! Registered Kura UID contract. An owner secret belongs to one authenticated
//! UI session. Neither a new connection nor an outcome query replays a write.
use super::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Binding {
    uid: u32,
    owner_digest: String,
    input_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Change {
    owner_key: String,
    expected_revision: u64,
    source_digest: String,
    confirm_seconds: u64,
    candidate: model::KuraCandidate,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Outcome {
    original_request_id: String,
    change: Change,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Action {
    owner_key: String,
    id: String,
    token: String,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn request_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)),
        "INVALID_ARGUMENT: request ID"
    );
    Ok(())
}
fn owner(key: &str) -> Result<String> {
    ensure!(
        key.len() == 64 && key.bytes().all(|c| c.is_ascii_hexdigit()),
        "INVALID_ARGUMENT: owner key"
    );
    Ok(digest(key.as_bytes()))
}
impl Change {
    fn binding(&self, uid: u32) -> Result<Binding> {
        ensure!(
            (30..=300).contains(&self.confirm_seconds),
            "INVALID_ARGUMENT: confirmation window"
        );
        ensure!(
            self.source_digest.len() == 64
                && self.source_digest.bytes().all(|c| c.is_ascii_hexdigit()),
            "INVALID_ARGUMENT: source digest"
        );
        self.candidate.compile()?;
        Ok(Binding {
            uid,
            owner_digest: owner(&self.owner_key)?,
            input_digest: digest(&serde_json::to_vec(self)?),
        })
    }
}
impl Firewall {
    fn history_path(&self, uid: u32, request: &str) -> PathBuf {
        self.0.state.join("kura-history").join(format!(
            "{}.json",
            digest(format!("{uid}:{request}").as_bytes())
        ))
    }
    pub(super) fn archive_kura(&self, journal: &Journal) -> Result<()> {
        if let Some(binding) = &journal.kura_binding {
            ensure!(
                journal.state.settled(),
                "CONFLICT: active firewall transaction"
            );
            let path = self.history_path(binding.uid, &journal.request_id);
            if path.exists() {
                let retained: Journal = serde_json::from_slice(&durable::read(&path, LIMIT)?.0)?;
                ensure!(
                    serde_json::to_vec(&retained)? == serde_json::to_vec(journal)?,
                    "CONFLICT: retained firewall outcome differs"
                );
            } else {
                durable::directory(path.parent().unwrap())?;
                durable::json(&path, journal)?;
            }
        }
        Ok(())
    }
    fn original(&self, uid: u32, request: &str) -> Result<Option<Journal>> {
        if let Some(j) = self.journal()?
            && j.request_id == request
            && j.kura_binding.as_ref().is_some_and(|b| b.uid == uid)
        {
            return Ok(Some(j));
        }
        let path = self.history_path(uid, request);
        if !path.exists() {
            return Ok(None);
        }
        let j: Journal = serde_json::from_slice(&durable::read(&path, LIMIT)?.0)?;
        ensure!(
            j.request_id == request && j.kura_binding.as_ref().is_some_and(|b| b.uid == uid),
            "CONFLICT: retained firewall outcome identity"
        );
        Ok(Some(j))
    }
    fn projection(&self, j: &Journal, owned: bool) -> Result<Value> {
        let mut value = json!({"id":j.id,"state":j.state,"deadlineUnixMs":j.deadline_ms,
            "revision":if j.state == State::Committed { j.old.revision + 1 } else { j.old.revision },
            "currentRevision":self.confirmed()?.revision,"requestId":j.request_id});
        if owned {
            value["confirmationToken"] = json!(j.token);
        }
        Ok(value)
    }
    pub(super) async fn observe<T: Send + 'static>(
        &self,
        action: impl FnOnce(&Self) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = Guard::observe_shared(&this.0.root, std::time::Duration::from_secs(1))?;
            action(&this)
        })
        .await?
    }
    pub(crate) async fn kura_request(
        &self,
        method: String,
        params: Value,
        request: String,
        uid: u32,
        write_grant: bool,
    ) -> Result<Value> {
        match method.as_str() {
            "firewall.kura.view" => {
                ensure!(
                    params == json!({}) || params.is_null(),
                    "INVALID_ARGUMENT: view fields"
                );
                self.observe(move |this| {
                    let confirmed = this.confirmed()?;
                    let candidate = match &confirmed.candidate {
                        Some(VersionedCandidate::V3(value)) if Some(value.compile()?.text) == confirmed.text => Some(value.clone()),
                        _ => None,
                    };
                    let transaction = this.journal()?.as_ref().map(|j| this.projection(j, false)).transpose()?;
                    Ok(json!({"schemaVersion":1,"revision":confirmed.revision,
                        "sourceDigest":digest(&serde_json::to_vec(&confirmed)?),"initialized":confirmed.text.is_some(),
                        "projectable":candidate.is_some(),"candidate":candidate,
                        "writeEnabled":this.0.write_enabled && write_grant,"transaction":transaction}))
                }).await
            }
            "firewall.kura.prepare" => {
                ensure!(
                    write_grant && self.0.write_enabled,
                    "FORBIDDEN: Kura firewall write grant disabled"
                );
                request_id(&request)?;
                let change: Change = serde_json::from_value(params)
                    .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: firewall change"))?;
                let binding = change.binding(uid)?;
                let candidate = VersionedCandidate::V3(change.candidate.clone());
                let text = candidate.render()?;
                self.write(move |this| {
                    // Even an identical duplicate is never an apply retry.
                    ensure!(
                        this.original(uid, &request)?.is_none(),
                        "OUTCOME_UNKNOWN: query the original request"
                    );
                    let old = this.confirmed()?;
                    ensure!(
                        old.revision == change.expected_revision
                            && digest(&serde_json::to_vec(&old)?) == change.source_digest,
                        "CONFLICT: stale confirmed firewall view"
                    );
                    let mut j = this.prepare_inner(
                        candidate,
                        text,
                        change.confirm_seconds,
                        request,
                        Some(binding),
                    )?;
                    this.apply_inner(&mut j)?;
                    this.projection(&j, true)
                })
                .await
            }
            "firewall.kura.outcome" => {
                let input: Outcome = serde_json::from_value(params)
                    .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: outcome fields"))?;
                request_id(&input.original_request_id)?;
                let binding = input.change.binding(uid)?;
                self.observe(move |this| {
                    let j = this
                        .original(uid, &input.original_request_id)?
                        .context("OUTCOME_UNKNOWN: no durable original outcome")?;
                    let retained = j
                        .kura_binding
                        .as_ref()
                        .context("OUTCOME_UNKNOWN: no owner binding")?;
                    ensure!(
                        retained.uid == binding.uid
                            && retained.owner_digest == binding.owner_digest,
                        "FORBIDDEN: transaction owner"
                    );
                    ensure!(
                        retained.input_digest == binding.input_digest,
                        "CONFLICT: original input differs"
                    );
                    this.projection(&j, true)
                })
                .await
            }
            "firewall.kura.confirm" | "firewall.kura.rollback" => {
                let confirm = method == "firewall.kura.confirm";
                // Revoking a grant does not remove explicit compensation.
                ensure!(
                    !confirm || (write_grant && self.0.write_enabled),
                    "FORBIDDEN: Kura firewall write grant disabled"
                );
                let input: Action = serde_json::from_value(params)
                    .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: action fields"))?;
                let owner_digest = owner(&input.owner_key)?;
                self.write(move |this| {
                    let mut j = this.journal()?.context("CONFLICT: no transaction")?;
                    let b = j
                        .kura_binding
                        .as_ref()
                        .context("FORBIDDEN: not a Kura transaction")?;
                    ensure!(
                        b.uid == uid
                            && b.owner_digest == owner_digest
                            && j.id == input.id
                            && j.token == input.token,
                        "FORBIDDEN: transaction owner or token"
                    );
                    if confirm {
                        ensure!(
                            j.state == State::WaitConfirm && now() < j.deadline_ms,
                            "CONFLICT: transaction state or deadline"
                        );
                        this.verify(Some(&j.candidate_text))?;
                        j.confirmed_decision = true;
                        j.state = State::Confirming;
                        this.persist("transaction.json", &j)?;
                        this.commit(&mut j)?;
                    } else {
                        ensure!(!j.state.settled(), "CONFLICT: transaction state");
                        this.rollback_inner(&mut j)?;
                    }
                    this.projection(&j, false)
                })
                .await
            }
            _ => anyhow::bail!("UNSUPPORTED: Kura firewall method"),
        }
    }
}
