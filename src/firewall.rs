//! Own-table nftables transactions. Persistence, bounded child execution and
//! system-change admission are shared with network and recovery.
mod kura;
mod legacy;
mod original;
pub(crate) use original::layout_draft as original_layout_draft;
pub(crate) fn original_forwarding_families(value:&serde_json::Value)->anyhow::Result<(bool,bool)> {
    let candidate:model::ExactKuraCandidate=serde_json::from_value(value.clone())?;
    Ok(candidate.forwarding_families())
}

pub(crate) use legacy::legacy_model_snapshot;
pub(crate) use kura::legacy_import_policy_digest;
pub(crate) use legacy::observe_legacy_kernel;
#[cfg(test)]
pub(crate) use legacy::fixture_observe as fixture_legacy_kernel;
pub(crate) use kura::core_confirmed_witness;
pub(crate) use kura::validate_legacy_source_rules;
pub(crate) use kura::validate_core_projection;
pub(crate) use kura::require_original_static_rules;
pub(crate) use kura::initialized_kernel_source;
#[cfg(test)]
pub(crate) use kura::seed_confirmed_core_fixture;
#[cfg(test)]
pub(crate) use kura::confirmed_kernel_fixture;
mod model;
pub(crate) use model::normalize_native_rule;
mod remote;
#[cfg(test)]
mod remote_contract_tests;
use crate::{
    durable,
    system_change::{Guard, Subsystem},
};
use anyhow::{Context, Result, ensure};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::{fs, path::Path};
use std::{
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const TABLE: &str = "yofc_kura";
const LIMIT: u64 = 1 << 20;
#[derive(Clone)]
pub struct Firewall(Arc<Engine>);
struct Engine {
    root: PathBuf,
    state: PathBuf,
    write_enabled: bool,
    nft: PathBuf,
    #[cfg(test)]
    fake: Mutex<FakeNft>,
    #[cfg(test)]
    real: std::sync::atomic::AtomicBool,
}
#[cfg(test)]
struct FakeNft {
    invocations:usize,
    ruleset: Value,
    table: Option<Value>,
    checked: Vec<String>,
    missing: usize,
    fail_apply: bool,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub protocol: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_v4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_v6: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    policy: String,
    rules: Vec<Rule>,
}
// Untagged preserves the exact shape of retained v1 journals. Version 2 has an
// explicit version and address family; an invalid versioned request cannot
// become v1. V3 carries the structured Kura compatibility rule surface.
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum VersionedCandidate {
    V4(model::ExactKuraCandidate),
    V3(model::KuraCandidate),
    V2(model::Candidate),
    V1(Candidate),
}
impl VersionedCandidate {
    fn render(&self) -> Result<String> {
        match self {
            Self::V1(value) => render(&value.policy, &value.rules),
            Self::V2(value) => Ok(value.compile()?.text),
            Self::V3(value) => Ok(value.compile()?.text),
                Self::V4(value) => Ok(value.compile()?.text),
        }
    }
    fn policy(&self) -> &str {
        match self {
            Self::V1(value) => &value.policy,
            Self::V2(value) => value.input_policy.as_str(),
            Self::V3(_) | Self::V4(_) => "per-family",
        }
    }
}
impl From<model::KuraPolicy> for VersionedCandidate {
    fn from(value: model::KuraPolicy) -> Self {
        match value {
            model::KuraPolicy::V4(value) => Self::V4(value),
            model::KuraPolicy::V3(value) => Self::V3(value),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Confirmed {
    revision: u64,
    text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate: Option<VersionedCandidate>,
}
impl Confirmed {
    fn kura_policy(&self) -> Result<Option<model::KuraPolicy>> {
        let policy = match &self.candidate {
            Some(VersionedCandidate::V4(value)) => model::KuraPolicy::V4(value.clone()),
            Some(VersionedCandidate::V3(value)) => model::KuraPolicy::V3(value.clone()),
            _ => return Ok(None),
        };
        Ok((Some(policy.compile()?.text) == self.text).then_some(policy))
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum State {
    Prepared,
    Applying,
    WaitConfirm,
    Confirming,
    Committed,
    RollingBack,
    RolledBack,
    RecoveryRequired,
}
impl State {
    fn settled(self) -> bool {
        matches!(self, Self::Committed | Self::RolledBack)
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    id: String,
    state: State,
    old: Confirmed,
    candidate_text: String,
    candidate: VersionedCandidate,
    deadline_ms: u64,
    token: String,
    request_id: String,
    #[serde(default)]
    confirmed_decision: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kura_binding: Option<kura::Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_binding: Option<remote::Binding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    remote_actions: Vec<remote::ActionBinding>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn prefix(source: &str, v6: bool) -> Result<String> {
    let (address, length) = source
        .split_once('/')
        .map(|(a, l)| (a, Some(l)))
        .unwrap_or((source, None));
    let address: IpAddr = address
        .parse()
        .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: source prefix"))?;
    ensure!(
        address.is_ipv6() == v6,
        "INVALID_ARGUMENT: source address family"
    );
    let maximum = if v6 { 128 } else { 32 };
    let length = length
        .map(str::parse::<u32>)
        .transpose()
        .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: source prefix"))?
        .unwrap_or(maximum);
    ensure!(length <= maximum, "INVALID_ARGUMENT: source prefix length");
    let network = match address {
        IpAddr::V4(ip) => IpAddr::V4(
            (u32::from(ip)
                & if length == 0 {
                    0
                } else {
                    u32::MAX << (32 - length)
                })
            .into(),
        ),
        IpAddr::V6(ip) => IpAddr::V6(
            (u128::from(ip)
                & if length == 0 {
                    0
                } else {
                    u128::MAX << (128 - length)
                })
            .into(),
        ),
    };
    Ok(format!("{network}/{length}"))
}
pub fn render(policy: &str, rules: &[Rule]) -> Result<String> {
    ensure!(
        matches!(policy, "drop" | "accept"),
        "INVALID_ARGUMENT: firewall policy"
    );
    ensure!(
        rules.len() <= 256,
        "RESOURCE_EXHAUSTED: too many firewall rules"
    );
    let mut text = format!(
        "destroy table inet {TABLE}\ntable inet {TABLE} {{\n  chain input {{\n    type filter hook input priority filter; policy {policy};\n"
    );
    text.push_str("    ct state established,related accept comment \"yofc baseline\"\n    iifname \"lo\" accept comment \"yofc baseline\"\n");
    for rule in rules {
        ensure!(
            matches!(rule.protocol.as_str(), "tcp" | "udp") && rule.port != 0,
            "INVALID_ARGUMENT: firewall protocol/port"
        );
        for (source, family) in [(&rule.source_v4, "ip"), (&rule.source_v6, "ip6")] {
            if let Some(source) = source {
                let source = prefix(source, family == "ip6")?;
                text.push_str(&format!(
                    "    {family} saddr {source} {} dport {} accept comment \"yofc managed\"\n",
                    rule.protocol, rule.port
                ));
            }
        }
        if rule.source_v4.is_none() && rule.source_v6.is_none() {
            text.push_str(&format!(
                "    {} dport {} accept comment \"yofc managed\"\n",
                rule.protocol, rule.port
            ));
        }
    }
    text.push_str("  }\n}\n");
    Ok(text)
}
fn managed_count(text: &str) -> usize {
    text.matches("\"yofc managed\"").count()
}

impl Firewall {
    #[cfg(test)]
    pub(crate) fn test_backend_invocations(&self)->usize {self.0.fake.lock().unwrap().invocations}
    fn forwarding_ready(&self, candidate: &VersionedCandidate) -> Result<()> {
        let (ipv4, ipv6) = match candidate {
            VersionedCandidate::V1(_) => return Ok(()),
            VersionedCandidate::V2(candidate) => candidate.forwarding_families(),
            VersionedCandidate::V3(candidate) => candidate.forwarding_families(),
            VersionedCandidate::V4(candidate) => candidate.forwarding_families(),
        };
        #[cfg(test)]
        if !self.0.real.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        for (required, path) in [
            (ipv4, "/proc/sys/net/ipv4/ip_forward"),
            (ipv6, "/proc/sys/net/ipv6/conf/all/forwarding"),
        ] {
            if required {
                ensure!(
                    std::fs::read_to_string(path).is_ok_and(|v| v.trim() == "1"),
                    "FORBIDDEN: requested address family forwarding is not enabled by the system owner"
                );
            }
        }
        Ok(())
    }
    pub fn open(root: PathBuf, nft: Option<PathBuf>) -> Result<Self> {
        durable::directory(&root)?;
        let state = root.join("firewall");
        durable::directory(&state)?;
        // Create the shared lock during engine setup, before read-only queries.
        drop(Guard::observe(&root)?);
        Ok(Self(Arc::new(Engine {
            root,
            state,
            write_enabled: false,
            nft: nft.unwrap_or_else(|| "/usr/sbin/nft".into()),
            #[cfg(test)]
            fake: Mutex::new(FakeNft {
                invocations:0,
                ruleset: json!({"nftables":[]}),
                table: None,
                checked: vec![],
                missing: 0,
                fail_apply: false,
            }),
            #[cfg(test)]
            real: std::sync::atomic::AtomicBool::new(false),
        })))
    }
    #[cfg(test)]
    pub(crate) fn test_ruleset(&self, value: Value) {
        self.0.fake.lock().unwrap().ruleset = value;
    }
    pub fn enable_writes(mut self, enabled: bool) -> Self {
        Arc::get_mut(&mut self.0)
            .expect("configure before sharing firewall")
            .write_enabled = enabled;
        self
    }
    async fn write<T: Send + 'static>(
        &self,
        action: impl FnOnce(&Self) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = Guard::acquire(&this.0.root, Subsystem::Firewall)?;
            action(&this)
        })
        .await?
    }
    /// Original queries and pre-dispatch cancellation remain available when
    /// an NM write grant is disabled. No native effect is dispatched here.
    pub(crate) async fn imported_remote_cancel(&self,value:Value,
        principal:crate::nm::handover::initialization::producer::principal::RemotePrincipal)->Result<Value> {
        let this=self.clone();
        tokio::task::spawn_blocking(move|| {
            let _guard=Guard::observe(&this.0.root)?;
            crate::nm::handover::initialization::producer::cancel_remote(&this.0.root,&principal,
                serde_json::from_value(value).context("INVALID_ARGUMENT: original remote cancellation")?)
        }).await?
    }
    pub(crate) async fn imported_metadata_request(&self,method:String,value:Value,uid:u32)->Result<Value> {
        let this=self.clone();
        tokio::task::spawn_blocking(move|| {
            let _guard=Guard::observe(&this.0.root)?;
            use crate::nm::handover::initialization::{self,producer};
            match method.as_str() {
                  "firewall.kura.imported.view"=>{
                      ensure!(value==json!({}),"INVALID_ARGUMENT: imported view fields");
                      initialization::core_view(&this.0.root)?.context("UNSUPPORTED: original imported initialization required")
                  },
                  "firewall.kura.imported.remote.outcome"|"firewall.kura.imported.remote.source.outcome"=>{
                      let receipt=if method.ends_with(".source.outcome") {
                          producer::observation::outcome(&this.0.root,uid,serde_json::from_value(value).context("INVALID_ARGUMENT: original source observation outcome")?)?
                      } else {
                          initialization::original_native_outcome(&this.0.root,uid,serde_json::from_value(value).context("INVALID_ARGUMENT: imported original outcome")?,
                              ||Ok(serde_json::from_str(&this.run_nft(&["-j","-p","list","ruleset"],None)?)?))?
                      };
                      let evidence=producer::original_evidence(&this.0.root,uid,&receipt)?;
                      Ok(json!({"receipt":receipt,"decisionEvidence":evidence}))
                  },
                "firewall.kura.imported.source.outcome"=>producer::observation::outcome(&this.0.root,uid,
                    serde_json::from_value(value).context("INVALID_ARGUMENT: original source observation outcome")?),
                "firewall.kura.imported.outcome"=>initialization::original_native_outcome(&this.0.root,uid,
                    serde_json::from_value(value).context("INVALID_ARGUMENT: imported original outcome")?,
                    ||Ok(serde_json::from_str(&this.run_nft(&["-j","-p","list","ruleset"],None)?)?)),
                "firewall.kura.imported.cancel"=>producer::cancel(&this.0.root,uid,
                    serde_json::from_value(value).context("INVALID_ARGUMENT: imported cancellation")?),
                "firewall.kura.imported.recover"=>{
                    ensure!(value.is_null()||value==json!({}),"INVALID_ARGUMENT: imported recovery fields");
                    initialization::recover_imported_transaction(&this.0.root)?.context("UNSUPPORTED: original imported initialization required")
                },
                _=>anyhow::bail!("UNSUPPORTED: imported metadata method"),
            }
        }).await?
    }
    fn run_nft(&self, args: &[&str], input: Option<&str>) -> Result<String> {
        #[cfg(test)]
        {self.0.fake.lock().unwrap().invocations+=1;}
        #[cfg(test)]
        if !self.0.real.load(std::sync::atomic::Ordering::Relaxed) {
            let mut fake = self.0.fake.lock().unwrap();
            let command = args.join(" ");
            if let Some(text) = input {
                fake.checked.push(text.into());
                if command.contains("-f") && !command.contains("-c") {
                    ensure!(!fake.fail_apply, "INTERNAL: injected nft failure");
                    fake.table = if text.contains(&format!("table inet {TABLE} {{")) {
                        Some(fake_table(text))
                    } else {
                        None
                    };
                }
            }
            if command.contains("list ruleset") {
                return Ok(fake.ruleset.to_string());
            }
            if command.contains("list table") {
                let mut table = fake.table.clone().context("INTERNAL: table absent")?;
                if fake.missing > 0 {
                    let entries = table["nftables"].as_array_mut().unwrap();
                    let mut remaining = fake.missing;
                    entries.retain(|e| {
                        if remaining > 0 && e["rule"]["comment"] == "yofc managed" {
                            remaining -= 1;
                            false
                        } else {
                            true
                        }
                    });
                }
                return Ok(table.to_string());
            }
            return Ok(String::new());
        }
        let output = crate::process::run(
            &self.0.nft,
            args,
            input.map(str::as_bytes),
            Duration::from_secs(10),
        )?;
        ensure!(
            output.status.success(),
            "INTERNAL: nft command failed ({} diagnostic bytes)",
            output.stderr.len()
        );
        Ok(String::from_utf8(output.stdout)?)
    }
    fn journal(&self) -> Result<Option<Journal>> {
        let path = self.0.state.join("transaction.json");
        if !path.exists() {
            return Ok(None);
        }
        let bytes=durable::read(&path,LIMIT)?.0;
        let value:Value=serde_json::from_slice(&bytes)?;
        ensure!(value.get("backend").is_none(),"UNSUPPORTED: typed firewall journal requires its own backend");
        Ok(Some(serde_json::from_slice(&bytes)?))
    }
    fn confirmed(&self) -> Result<Confirmed> {
        match std::fs::symlink_metadata(self.0.state.join("imported-confirmed.json")) {
            Ok(_)=>anyhow::bail!("UNSUPPORTED: imported policy requires its original-layout update coordinator"),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(e.into()),
        }
        let path = self.0.state.join("confirmed.json");
        if !path.exists() {
            return Ok(Confirmed {
                revision: 0,
                text: None,
                candidate: None,
            });
        }
        Ok(serde_json::from_slice(&durable::read(&path, LIMIT)?.0)?)
    }
    fn persist(&self, name: &str, value: &impl Serialize) -> Result<()> {
        durable::json(&self.0.state.join(name), value)
    }
    fn foreign_writers(&self) -> Result<Vec<String>> {
        let value: Value = serde_json::from_str(&self.run_nft(&["-j", "list", "ruleset"], None)?)?;
        let values = value["nftables"]
            .as_array()
            .context("INTERNAL: ruleset format")?;
        let owned_nm = crate::nm::ownership::recognizes(&self.0.root, &value)?;
        Ok(values
            .iter()
            .filter_map(|entry| {
                let table = &entry["table"];
                let name = table["name"].as_str()?;
                let managed = table["family"] == "inet"
                    && (name == TABLE || (name == "yofc_nm" && owned_nm));
                (!managed).then(|| name.to_owned())
            })
            .collect())
    }
    fn verify(&self, text: Option<&str>) -> Result<usize> {
        let args = if text.is_some_and(model::is_versioned) {
            vec!["-j", "-p", "list", "table", "inet", TABLE]
        } else {
            vec!["-j", "list", "table", "inet", TABLE]
        };
        let result = self.run_nft(&args, None);
        if text.is_none() {
            ensure!(result.is_err(), "CONFLICT: own table still present");
            // A failed list-table command alone cannot prove absence (EPERM,
            // timeout and transport errors must remain failures).
            let value: Value =
                serde_json::from_str(&self.run_nft(&["-j", "list", "ruleset"], None)?)?;
            let entries = value["nftables"]
                .as_array()
                .context("INTERNAL: ruleset format")?;
            ensure!(
                !entries
                    .iter()
                    .any(|e| e["table"]["family"] == "inet" && e["table"]["name"] == TABLE),
                "CONFLICT: own table still present"
            );
            return Ok(0);
        }
        let value: Value = serde_json::from_str(&result?)?;
        let entries = value["nftables"]
            .as_array()
            .context("INTERNAL: table format")?;
        // Compare semantic expressions, chain policy and table identity. Counters,
        // handles and metainfo are deliberately excluded from the comparison.
        let actual = if model::is_versioned(text.unwrap()) {
            model::semantic_table(entries)
        } else {
            semantic_table(entries)
        };
        let expected = expected_table(text.unwrap())?;
        if !actual.as_ref().is_ok_and(|v| v == &expected) {
            // Rollback may remove the rejected table. Preserve its exact kernel
            // observation first, using a new file for every failed comparison.
            self.persist(
                &format!("readback-mismatch-{}.json", uuid::Uuid::new_v4()),
                &json!({"observedAtMs":now(),"expected":expected,"kernel":value,
                    "semanticError":actual.err().map(|e|e.to_string())}),
            )?;
            anyhow::bail!("CONFLICT: firewall read-back mismatch");
        }
        Ok(managed_count(text.unwrap()))
    }
    fn apply_text(&self, text: Option<&str>) -> Result<()> {
        self.run_nft(
            &["-f", "-"],
            Some(text.unwrap_or("destroy table inet yofc_kura\n")),
        )?;
        Ok(())
    }
    pub async fn status(&self) -> Result<Value> {
        let this = self.clone();
        tokio::task::spawn_blocking(move|| {
            let confirmed=this.confirmed()?;let writers=this.foreign_writers()?;let journal=this.journal()?;
            let applied=this.run_nft(&["-j","list","table","inet",TABLE],None).ok().and_then(|s|serde_json::from_str::<Value>(&s).ok())
                .and_then(|v|v["nftables"].as_array().map(|a|a.iter().filter(|e|e["rule"]["comment"]=="yofc managed").count())).unwrap_or(0);
            Ok(json!({"writeEnabled":this.0.write_enabled,"table":TABLE,"revision":confirmed.revision,"confirmedManagedRules":confirmed.text.as_deref().map(managed_count).unwrap_or(0),
                "appliedManagedRules":applied,"detectedWriters":writers,"transaction":journal.map(|j|json!({"id":j.id,"state":j.state,"deadlineMs":j.deadline_ms,"managedRules":managed_count(&j.candidate_text)}))}))
        }).await?
    }
    pub async fn prepare(
        &self,
        candidate: Value,
        seconds: u64,
        request_id: String,
    ) -> Result<Value> {
        ensure!(
            self.0.write_enabled,
            "FORBIDDEN: firewall writes are not configured"
        );
        let candidate: VersionedCandidate = serde_json::from_value(candidate)
            .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: firewall candidate"))?;
        ensure!(
            (30..=300).contains(&seconds),
            "INVALID_ARGUMENT: confirmation window"
        );
        let text = candidate.render()?;
        self.write(move |this| {
            let j = this.prepare_inner(candidate, text, seconds, request_id, None)?;
            Ok(json!({"id":j.id,"state":j.state,"managedRules":managed_count(&j.candidate_text),"policy":j.candidate.policy(),"token":j.token}))
        }).await
    }
    fn prepare_inner(
        &self,
        candidate: VersionedCandidate,
        text: String,
        seconds: u64,
        request_id: String,
        kura_binding: Option<kura::Binding>,
    ) -> Result<Journal> {
        if let Some(j) = self.journal()? {
            ensure!(j.state.settled(), "CONFLICT: firewall transaction active");
            self.archive_kura(&j)?;
            self.archive_remote(&j)?;
        }
        ensure!(
            self.foreign_writers()?.is_empty(),
            "FORBIDDEN: foreign firewall managers present"
        );
        self.forwarding_ready(&candidate)?;
        let old = self.confirmed()?;
        self.verify(old.text.as_deref())?;
        self.run_nft(&["-c", "-f", "-"], Some(&text))?;
        let j = Journal {
            id: format!("fw-{}", uuid::Uuid::new_v4()),
            state: State::Prepared,
            old,
            candidate_text: text,
            candidate,
            deadline_ms: now() + seconds * 1000,
            token: format!("{:016x}{:016x}", OsRng.next_u64(), OsRng.next_u64()),
            request_id,
            confirmed_decision: false,
            kura_binding,
            remote_binding: None,
            remote_actions: Vec::new(),
        };
        self.persist("transaction.json", &j)?;
        Ok(j)
    }
    fn apply_inner(&self, j: &mut Journal) -> Result<()> {
        ensure!(
            j.state == State::Prepared && now() < j.deadline_ms,
            "CONFLICT: transaction state or deadline"
        );
        ensure!(
            self.foreign_writers()?.is_empty(),
            "FORBIDDEN: foreign firewall managers present"
        );
        self.forwarding_ready(&j.candidate)?;
        j.state = State::Applying;
        self.persist("transaction.json", j)?;
        if let Err(error) = self
            .apply_text(Some(&j.candidate_text))
            .and_then(|_| self.verify(Some(&j.candidate_text)))
        {
            let _ = self.rollback_inner(j);
            return Err(error);
        }
        j.state = State::WaitConfirm;
        self.persist("transaction.json", j)
    }
    pub async fn apply(&self) -> Result<Value> {
        ensure!(
            self.0.write_enabled,
            "FORBIDDEN: firewall writes are not configured"
        );
        self.write(|this| {
            let mut j = this.journal()?.context("CONFLICT: no transaction")?;
            ensure!(j.remote_binding.is_none(), "FORBIDDEN: remote transaction requires its original command");
            this.apply_inner(&mut j)?;
            Ok(json!({"id":j.id,"state":j.state,"appliedManagedRules":managed_count(&j.candidate_text),"deadlineMs":j.deadline_ms}))
        }).await
    }
    fn commit(&self, j: &mut Journal) -> Result<()> {
        self.forwarding_ready(&j.candidate)?;
        ensure!(
            self.foreign_writers()?.is_empty(),
            "FORBIDDEN: foreign firewall managers present"
        );
        self.apply_text(Some(&j.candidate_text))?;
        self.verify(Some(&j.candidate_text))?;
        let revision = j
            .old
            .revision
            .checked_add(1)
            .context("RESOURCE_EXHAUSTED: firewall revision")?;
        self.persist(
            "confirmed.json",
            &Confirmed {
                revision,
                text: Some(j.candidate_text.clone()),
                candidate: Some(j.candidate.clone()),
            },
        )?;
        j.state = State::Committed;
        self.persist("transaction.json", j)
    }
    pub async fn confirm(&self, token: &str) -> Result<Value> {
        ensure!(
            self.0.write_enabled,
            "FORBIDDEN: firewall writes are not configured"
        );
        let token = token.to_owned();
        self.write(move |this| {
            let mut j = this.journal()?.context("CONFLICT: no transaction")?;
            ensure!(
                j.remote_binding.is_none(),
                "FORBIDDEN: remote confirmation requires a new authenticated connection"
            );
            ensure!(
                j.state == State::WaitConfirm && now() < j.deadline_ms,
                "CONFLICT: transaction state or deadline"
            );
            ensure!(j.token == token, "FORBIDDEN: token");
            this.verify(Some(&j.candidate_text))?;
            j.confirmed_decision = true;
            j.state = State::Confirming;
            this.persist("transaction.json", &j)?;
            this.commit(&mut j)?;
            Ok(json!({"id":j.id,"state":j.state,"revision":this.confirmed()?.revision}))
        })
        .await
    }
    fn rollback_inner(&self, j: &mut Journal) -> Result<()> {
        ensure!(
            !j.confirmed_decision,
            "CONFLICT: confirmation already decided"
        );
        j.state = State::RollingBack;
        self.persist("transaction.json", j)?;
        ensure!(
            self.foreign_writers()?.is_empty(),
            "FORBIDDEN: foreign firewall managers present"
        );
        self.apply_text(j.old.text.as_deref())?;
        self.verify(j.old.text.as_deref())?;
        self.persist("confirmed.json", &j.old)?;
        j.state = State::RolledBack;
        self.persist("transaction.json", j)
    }
    pub async fn rollback(&self, token: &str) -> Result<Value> {
        let token = token.to_owned();
        self.write(move |this| {
            let mut j = this.journal()?.context("CONFLICT: no transaction")?;
            ensure!(!j.state.settled(), "CONFLICT: transaction state");
            ensure!(j.token == token, "FORBIDDEN: token");
            this.rollback_inner(&mut j)?;
            Ok(json!({"id":j.id,"state":j.state}))
        })
        .await
    }
    pub async fn recover(&self) -> Result<()> {
        // Original imported metadata adjudication takes the same exclusive
        // system lock, but does not request a new backend-writer admission.
        let this=self.clone();
        let imported=tokio::task::spawn_blocking(move || {
            let _guard=Guard::observe(&this.0.root)?;
            crate::nm::handover::initialization::recover_imported_transaction(&this.0.root)
        }).await??;
        if imported.is_some() {return Ok(());}
        self.write(|this| {
            if let Some(mut j) = this.journal()? {
                let confirmed = this.confirmed()?;
                // Recognize a completed legacy decision written before its final marker.
                if !j.state.settled()
                    && (j.confirmed_decision
                        || (confirmed.revision == j.old.revision.saturating_add(1)
                            && confirmed.text.as_deref() == Some(&j.candidate_text)))
                {
                    j.confirmed_decision = true;
                    this.commit(&mut j)?;
                } else if !j.state.settled() {
                    this.rollback_inner(&mut j)?;
                }
            }
            Ok(())
        })
        .await
    }
    pub async fn expire(&self) -> Result<()> {
        // Imported expiry is scheduled by Nm through its original one-shot
        // producer. The private commit/rollback path below reapplies a ruleset.
        if crate::nm::handover::initialization::owns_firewall_domain(&self.0.root)? {
            return Ok(());
        }
        // Do not contend with a still executing writer just to inspect its deadline.
        let Some(j) = self.journal()? else {
            return Ok(());
        };
        if j.state.settled()
            || (j.state != State::RollingBack && !j.confirmed_decision && now() < j.deadline_ms)
        {
            return Ok(());
        }
        self.write(|this| {
            let mut j = this.journal()?.context("CONFLICT: no transaction")?;
            if j.confirmed_decision {
                this.commit(&mut j)
            } else if !j.state.settled() {
                this.rollback_inner(&mut j)
            } else {
                Ok(())
            }
        })
        .await
    }
}

// A deliberately narrow parser for our own generated grammar. No input reaches
// nft unless render() has parsed every address and bounded every other field.
fn expected_table(text: &str) -> Result<Value> {
    if model::is_versioned(text) {
        return model::expected_table(text);
    }
    let policy = if text.contains("policy drop;") {
        "drop"
    } else if text.contains("policy accept;") {
        "accept"
    } else {
        anyhow::bail!("CONFLICT: invalid confirmed firewall grammar")
    };
    let mut rules = vec![
        json!({"comment":"yofc baseline","expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}),
        json!({"comment":"yofc baseline","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"accept":null}]}),
    ];
    for line in text
        .lines()
        .filter(|line| line.contains("\"yofc managed\""))
    {
        let words: Vec<_> = line.split_whitespace().collect();
        let mut expr = Vec::new();
        let mut i = 0;
        if matches!(words.first(), Some(&"ip") | Some(&"ip6")) {
            ensure!(words.len() >= 10, "CONFLICT: invalid confirmed rule");
            let canonical = prefix(words[2], words[0] == "ip6")?;
            let (address, length) = canonical
                .split_once('/')
                .context("CONFLICT: source prefix")?;
            let length = length.parse::<u32>()?;
            // nft JSON represents /32 and /128 as scalar host addresses.
            let right = if length == if words[0] == "ip" { 32 } else { 128 } {
                json!(address)
            } else {
                json!({"prefix":{"addr":address,"len":length}})
            };
            expr.push(json!({"match":{"op":"==","left":{"payload":{"protocol":words[0],"field":"saddr"}},"right":right}}));
            i = 3;
        }
        ensure!(
            words.get(i + 1) == Some(&"dport")
                && matches!(words.get(i), Some(&"tcp") | Some(&"udp")),
            "CONFLICT: invalid confirmed rule"
        );
        expr.push(json!({"match":{"op":"==","left":{"payload":{"protocol":words[i],"field":"dport"}},"right":words[i+2].parse::<u16>()?}}));
        expr.push(json!({"accept":null}));
        rules.push(json!({"comment":"yofc managed","expr":expr}));
    }
    Ok(json!({"family":"inet","table":TABLE,"chain":"input","policy":policy,"rules":rules}))
}
fn semantic_table(entries: &[Value]) -> Result<Value> {
    ensure!(
        entries.iter().filter(|v| v.get("table").is_some()).count() == 1,
        "CONFLICT: unexpected firewall tables"
    );
    let table = entries
        .iter()
        .find_map(|v| v.get("table"))
        .context("CONFLICT: table missing")?;
    ensure!(
        table["name"] == TABLE && table["family"] == "inet",
        "CONFLICT: wrong firewall table"
    );
    let chains: Vec<_> = entries.iter().filter_map(|v| v.get("chain")).collect();
    ensure!(
        chains.len() == 1
            && chains[0]["name"] == "input"
            && chains[0]["hook"] == "input"
            && chains[0]["type"] == "filter"
            && chains[0]["prio"] == 0,
        "CONFLICT: unexpected firewall chain"
    );
    let rules: Vec<_> = entries
        .iter()
        .filter_map(|v| v.get("rule"))
        .map(|r| json!({"comment":r["comment"],"expr":r["expr"]}))
        .collect();
    Ok(
        json!({"family":"inet","table":TABLE,"chain":"input","policy":chains[0]["policy"],"rules":rules}),
    )
}
#[cfg(test)]
fn fake_table(text: &str) -> Value {
    if model::is_versioned(text) {
        return model::fake_table(text);
    }
    let semantic = expected_table(text).unwrap();
    let mut entries = vec![
        json!({"table":{"family":"inet","name":TABLE}}),
        json!({"chain":{"family":"inet","table":TABLE,"name":"input","type":"filter","hook":"input","prio":0,"policy":semantic["policy"]}}),
    ];
    for rule in semantic["rules"].as_array().unwrap() {
        let mut r = rule.clone();
        r["chain"] = json!("input");
        entries.push(json!({"rule":r}));
    }
    json!({"nftables":entries})
}
#[cfg(test)]
fn fake_table_with(managed: usize) -> Value {
    let rules = (0..managed)
        .map(|_| Rule {
            protocol: "tcp".into(),
            port: 22,
            source_v4: None,
            source_v6: None,
        })
        .collect::<Vec<_>>();
    fake_table(&render("drop", &rules).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn kura_parallel_observations_share_lock_without_admitting_writes() {
        use std::os::fd::AsRawFd;
        let (fw, dir) = fixture();
        // Hold a real OS shared observation across all requests. This makes the
        // old exclusive/nonblocking read failure deterministic, not a race.
        let reader = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.0.join("system-change.lock"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(reader.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
            0
        );
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let fw = fw.clone();
            jobs.spawn(async move { kura_call(&fw, "view", json!({}), "read", false).await });
        }
        let mut results = Vec::new();
        while let Some(result) = jobs.join_next().await {
            results.push(result.unwrap());
        }
        assert!(Guard::acquire(&dir.0, Subsystem::Firewall).is_err());
        drop(reader);
        for result in results {
            let view = result.unwrap();
            assert_eq!(view["revision"], 0);
            assert_eq!(view["projectable"], false);
        }
        assert!(!dir.0.join("firewall/transaction.json").exists());
    }

    async fn kura_call(
        fw: &Firewall,
        method: &str,
        params: Value,
        request: &str,
        grant: bool,
    ) -> Result<Value> {
        fw.kura_request(
            format!("firewall.kura.{method}"),
            params,
            request.into(),
            1000,
            grant,
        )
        .await
    }
    async fn kura_change(fw: &Firewall) -> Value {
        let view = kura_call(fw, "view", json!({}), "view", true)
            .await
            .unwrap();
        json!({"ownerKey":"a".repeat(64),"expectedRevision":view["revision"],"sourceDigest":view["sourceDigest"],
            "confirmSeconds":60,"candidate":model::fixture_kura_candidate()})
    }
    #[tokio::test]
    async fn kura_outcome_survives_new_admin_journal_and_never_replays() {
        let (fw, dir) = fixture();
        let change = kura_change(&fw).await;
        let prepared = kura_call(&fw, "prepare", change.clone(), "kura-first", true)
            .await
            .unwrap();
        assert_eq!(prepared["state"], "WAIT_CONFIRM");
        assert!(
            kura_call(&fw, "prepare", change.clone(), "kura-first", true)
                .await
                .is_err()
        );
        let action = json!({"ownerKey":change["ownerKey"],"id":prepared["id"],"token":prepared["confirmationToken"]});
        kura_call(&fw, "confirm", action, "confirm", true)
            .await
            .unwrap();
        let view = kura_call(&fw, "view", json!({}), "read", false)
            .await
            .unwrap();
        assert_eq!(view["revision"], 1);
        assert_eq!(view["candidate"], change["candidate"]);
        assert_eq!(view["writeEnabled"], false);
        assert!(
            !view
                .to_string()
                .contains(prepared["confirmationToken"].as_str().unwrap())
        );
        let admin = fw
            .prepare(
                json!({"policy":"accept","rules":[]}),
                60,
                "next-admin".into(),
            )
            .await
            .unwrap();
        let original = json!({"originalRequestId":"kura-first","change":change});
        let before = fs::read(dir.0.join("firewall/transaction.json")).unwrap();
        let writes = fw.0.fake.lock().unwrap().checked.len();
        let outcome = kura_call(&fw, "outcome", original.clone(), "outcome", false)
            .await
            .unwrap();
        assert_eq!(outcome["state"], "COMMITTED");
        assert_eq!(outcome["id"], prepared["id"]);
        assert_eq!(fw.0.fake.lock().unwrap().checked.len(), writes);
        assert_eq!(
            fs::read(dir.0.join("firewall/transaction.json")).unwrap(),
            before
        );
        let mut wrong = original.clone();
        wrong["change"]["ownerKey"] = json!("b".repeat(64));
        assert!(
            kura_call(&fw, "outcome", wrong, "wrong-owner", false)
                .await
                .unwrap_err()
                .to_string()
                .starts_with("FORBIDDEN")
        );
        let mut wrong = original;
        wrong["change"]["confirmSeconds"] = json!(61);
        assert!(
            kura_call(&fw, "outcome", wrong, "wrong-input", false)
                .await
                .unwrap_err()
                .to_string()
                .starts_with("CONFLICT")
        );
        fw.rollback(admin["token"].as_str().unwrap()).await.unwrap();
    }
    #[tokio::test]
    async fn kura_disabled_stale_owner_and_revoked_grant_are_enforced() {
        let (fw, _dir) = fixture();
        let change = kura_change(&fw).await;
        assert!(
            kura_call(&fw, "prepare", change.clone(), "disabled", false)
                .await
                .unwrap_err()
                .to_string()
                .starts_with("FORBIDDEN")
        );
        let mut stale = change.clone();
        stale["expectedRevision"] = json!(9);
        assert!(
            kura_call(&fw, "prepare", stale, "stale", true)
                .await
                .unwrap_err()
                .to_string()
                .starts_with("CONFLICT")
        );
        let tx = kura_call(&fw, "prepare", change.clone(), "actual", true)
            .await
            .unwrap();
        let action =
            json!({"ownerKey":change["ownerKey"],"id":tx["id"],"token":tx["confirmationToken"]});
        let mut wrong = action.clone();
        wrong["ownerKey"] = json!("b".repeat(64));
        assert!(
            kura_call(&fw, "rollback", wrong, "wrong", true)
                .await
                .unwrap_err()
                .to_string()
                .starts_with("FORBIDDEN")
        );
        assert!(
            kura_call(&fw, "confirm", action.clone(), "revoked", false)
                .await
                .unwrap_err()
                .to_string()
                .starts_with("FORBIDDEN")
        );
        assert_eq!(
            kura_call(&fw, "rollback", action, "compensate", false)
                .await
                .unwrap()["state"],
            "ROLLED_BACK"
        );
        let absent = json!({"originalRequestId":"never-written","change":change});
        assert!(
            kura_call(&fw, "outcome", absent, "absent", false)
                .await
                .unwrap_err()
                .to_string()
                .starts_with("OUTCOME_UNKNOWN")
        );
    }
    #[tokio::test]
    async fn kura_read_observations_remain_available_during_recovery_required() {
        let (fw, dir) = fixture();
        let change = kura_change(&fw).await;
        let tx = kura_call(&fw, "prepare", change.clone(), "original", true)
            .await
            .unwrap();
        durable::directory(&dir.0.join("recovery")).unwrap();
        durable::json(
            &dir.0.join("recovery/transaction.json"),
            &json!({"state":"RECOVERY_REQUIRED"}),
        )
        .unwrap();
        let before = fs::read(dir.0.join("firewall/transaction.json")).unwrap();
        let writes = fw.0.fake.lock().unwrap().checked.len();
        assert_eq!(
            kura_call(&fw, "view", json!({}), "view", true)
                .await
                .unwrap()["transaction"]["id"],
            tx["id"]
        );
        let original = json!({"originalRequestId":"original","change":change});
        assert_eq!(
            kura_call(&fw, "outcome", original, "query", false)
                .await
                .unwrap()["state"],
            "WAIT_CONFIRM"
        );
        assert!(
            kura_call(&fw, "prepare", kura_change(&fw).await, "blocked", true)
                .await
                .is_err()
        );
        assert_eq!(fw.0.fake.lock().unwrap().checked.len(), writes);
        assert_eq!(
            fs::read(dir.0.join("firewall/transaction.json")).unwrap(),
            before
        );
    }
    #[tokio::test]
    async fn kura_v3_is_durable_and_rolls_back_to_both_older_versions_without_replay() {
        let (firewall, dir) = fixture();
        for (index, value) in [
            json!({"policy":"accept","rules":[]}),
            model::fixture_candidate(),
            model::fixture_kura_candidate(),
        ]
        .into_iter()
        .enumerate()
        {
            let prepared = firewall
                .prepare(value, 60, format!("version-{index}"))
                .await
                .unwrap();
            firewall.apply().await.unwrap();
            firewall
                .confirm(prepared["token"].as_str().unwrap())
                .await
                .unwrap();
        }
        let confirmed = firewall.confirmed().unwrap();
        assert_eq!(confirmed.revision, 3);
        let retained = fs::read(dir.0.join("firewall/transaction.json")).unwrap();
        let journal: Journal = serde_json::from_slice(&retained).unwrap();
        assert!(matches!(journal.candidate, VersionedCandidate::V3(_)));
        let writes = firewall.0.fake.lock().unwrap().checked.len();
        let reopened = Firewall::open(dir.0.clone(), None)
            .unwrap()
            .enable_writes(true);
        reopened.0.fake.lock().unwrap().table = firewall.0.fake.lock().unwrap().table.clone();
        reopened.recover().await.unwrap();
        assert!(reopened.0.fake.lock().unwrap().checked.is_empty());
        assert_eq!(
            fs::read(dir.0.join("firewall/transaction.json")).unwrap(),
            retained
        );
        assert_eq!(firewall.0.fake.lock().unwrap().checked.len(), writes);
        for value in [
            json!({"policy":"drop","rules":[]}),
            model::fixture_candidate(),
        ] {
            let prepared = reopened
                .prepare(value, 60, "older-unconfirmed".into())
                .await
                .unwrap();
            reopened.apply().await.unwrap();
            reopened
                .rollback(prepared["token"].as_str().unwrap())
                .await
                .unwrap();
            assert_eq!(reopened.confirmed().unwrap().text, confirmed.text);
            assert_eq!(reopened.confirmed().unwrap().revision, 3);
        }
        let journal_before = fs::read(dir.0.join("firewall/transaction.json")).unwrap();
        let mut invalid = model::fixture_kura_candidate();
        invalid["nat"][0]["automatic"] = json!(true);
        assert!(
            reopened
                .prepare(invalid, 60, "invalid".into())
                .await
                .is_err()
        );
        assert_eq!(
            fs::read(dir.0.join("firewall/transaction.json")).unwrap(),
            journal_before
        );
    }

    #[tokio::test]
    async fn v2_nat_confirmation_recovery_and_bidirectional_v1_rollback_preserve_revisions() {
        let (firewall, dir) = fixture();
        let old = firewall
            .prepare(json!({"policy":"accept","rules":[]}), 60, "legacy".into())
            .await
            .unwrap();
        firewall.apply().await.unwrap();
        firewall
            .confirm(old["token"].as_str().unwrap())
            .await
            .unwrap();
        let legacy = firewall.confirmed().unwrap();
        let new = firewall
            .prepare(model::fixture_candidate(), 60, "nat-first".into())
            .await
            .unwrap();
        firewall.apply().await.unwrap();
        firewall
            .rollback(new["token"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(firewall.confirmed().unwrap().text, legacy.text);
        let new = firewall
            .prepare(model::fixture_candidate(), 60, "nat-second".into())
            .await
            .unwrap();
        firewall.apply().await.unwrap();
        firewall
            .confirm(new["token"].as_str().unwrap())
            .await
            .unwrap();
        let confirmed = firewall.confirmed().unwrap();
        assert_eq!(confirmed.revision, 2);
        let retained: Journal =
            serde_json::from_slice(&fs::read(dir.0.join("firewall/transaction.json")).unwrap())
                .unwrap();
        assert!(matches!(retained.candidate, VersionedCandidate::V2(_)));
        let _legacy = firewall
            .prepare(
                json!({"policy":"drop","rules":[]}),
                60,
                "legacy-unconfirmed".into(),
            )
            .await
            .unwrap();
        firewall.apply().await.unwrap();
        firewall.recover().await.unwrap();
        assert_eq!(firewall.confirmed().unwrap().text, confirmed.text);
        assert_eq!(firewall.confirmed().unwrap().revision, 2);
        assert_eq!(firewall.verify(confirmed.text.as_deref()).unwrap(), 5);
        assert_eq!(
            firewall.journal().unwrap().unwrap().state,
            State::RolledBack
        );
    }

    struct TempDir(std::path::PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (Firewall, TempDir) {
        let dir = std::env::temp_dir().join(format!("fw-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let firewall = Firewall::open(dir.clone(), None)
            .unwrap()
            .enable_writes(true);
        (firewall, TempDir(dir))
    }

    #[tokio::test]
    async fn writes_are_disabled_until_explicitly_configured() {
        let root = std::env::temp_dir().join(format!("fw-off-{}", uuid::Uuid::new_v4()));
        let firewall = Firewall::open(root.clone(), None).unwrap();
        assert_eq!(firewall.status().await.unwrap()["writeEnabled"], false);
        assert!(
            firewall
                .prepare(json!({"policy":"accept","rules":[]}), 60, "off".into())
                .await
                .unwrap_err()
                .to_string()
                .starts_with("FORBIDDEN")
        );
        assert!(firewall.journal().unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    fn rules() -> Vec<Rule> {
        vec![
            Rule {
                protocol: "tcp".into(),
                port: 22,
                source_v4: None,
                source_v6: None,
            },
            Rule {
                protocol: "tcp".into(),
                port: 443,
                source_v4: Some("10.0.0.0/8".into()),
                source_v6: Some("fd00::/8".into()),
            },
        ]
    }

    fn self_real(firewall: &Firewall) -> &std::sync::atomic::AtomicBool {
        &firewall.0.real
    }

    /// Real-nftables integration: run only where /usr/sbin/nft exists.
    /// `cargo test real_nft -- --ignored` inside a Linux staged source tree.
    #[tokio::test]
    #[ignore]
    async fn real_nft_lifecycle_applies_confirms_and_rolls_back() {
        if !Path::new("/usr/sbin/nft").exists() {
            eprintln!("no /usr/sbin/nft; skipping");
            return;
        }
        let dir = std::env::temp_dir().join(format!("fw-real-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let firewall = Firewall::open(dir.clone(), None)
            .unwrap()
            .enable_writes(true);
        self_real(&firewall).store(true, std::sync::atomic::Ordering::Relaxed);
        // Foreign managers on this host must be detected, not silently managed.
        let status = firewall.status().await.unwrap();
        println!("detected writers: {:?}", status["detectedWriters"]);
        assert!(status["detectedWriters"].as_array().unwrap().is_empty());
        let view = firewall
            .prepare(
                json!({"policy": "accept", "rules": rules()}),
                60,
                "real".into(),
            )
            .await
            .unwrap();
        assert_eq!(view["managedRules"], 3);
        let applied = firewall.apply().await.unwrap();
        assert_eq!(applied["appliedManagedRules"], 3);
        let listed = std::process::Command::new("/usr/sbin/nft")
            .args(["list", "table", "inet", "yofc_kura"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&listed.stdout);
        assert!(text.contains("ip saddr 10.0.0.0/8 tcp dport 443 accept"));
        assert!(text.contains("ip6 saddr fd00::/8 tcp dport 443 accept"));
        let journal: Journal = serde_json::from_str(
            &fs::read_to_string(dir.join("firewall/transaction.json")).unwrap(),
        )
        .unwrap();
        firewall.confirm(&journal.token).await.unwrap();
        // A second transaction rolls the table back to the committed ruleset.
        firewall
            .prepare(
                json!({"policy": "drop", "rules": rules()[..1].to_vec()}),
                30,
                "real2".into(),
            )
            .await
            .unwrap();
        let journal2: Journal = serde_json::from_str(
            &fs::read_to_string(dir.join("firewall/transaction.json")).unwrap(),
        )
        .unwrap();
        firewall.rollback(&journal2.token).await.unwrap();
        let after = std::process::Command::new("/usr/sbin/nft")
            .args(["list", "table", "inet", "yofc_kura"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&after.stdout);
        assert_eq!(
            text.matches("yofc managed").count(),
            3,
            "rollback restored the committed ruleset"
        );
        // Public-token flow for nft's scalar representation of full host prefixes.
        let host=firewall.prepare(json!({"policy":"accept","rules":[{"protocol":"tcp","port":18080,"source_v4":"192.0.2.1","source_v6":"2001:db8::1/128"}]}),60,"host-prefixes".into()).await.unwrap();
        assert_eq!(firewall.apply().await.unwrap()["appliedManagedRules"], 2);
        firewall
            .rollback(host["token"].as_str().unwrap())
            .await
            .unwrap();
        // Cleanup: destroy the own table and remove the state directory.
        std::process::Command::new("/usr/sbin/nft")
            .args(["destroy", "table", "inet", "yofc_kura"])
            .output()
            .unwrap();
        let gone = std::process::Command::new("/usr/sbin/nft")
            .args(["list", "table", "inet", "yofc_kura"])
            .output()
            .unwrap();
        assert!(!gone.status.success(), "table destroyed");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn nft_host_prefixes_follow_the_kernel_json_scalar_contract() {
        let text = render(
            "accept",
            &[Rule {
                protocol: "tcp".into(),
                port: 18080,
                source_v4: Some("192.0.2.1".into()),
                source_v6: Some("2001:db8::1/128".into()),
            }],
        )
        .unwrap();
        let expected = expected_table(&text).unwrap();
        assert_eq!(
            expected["rules"][2]["expr"][0]["match"]["right"],
            "192.0.2.1"
        );
        assert_eq!(
            expected["rules"][3]["expr"][0]["match"]["right"],
            "2001:db8::1"
        );
        assert_eq!(
            expected_table(&text.replace("192.0.2.1/32", "192.0.2.1")).unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn render_is_explicit_about_families_and_policy() {
        let text = render("drop", &rules()).unwrap();
        assert!(text.contains("table inet yofc_kura"));
        assert!(text.contains("policy drop;"));
        assert!(text.contains("ct state established,related accept"));
        assert!(text.contains("ip saddr 10.0.0.0/8 tcp dport 443 accept"));
        assert!(text.contains("ip6 saddr fd00::/8 tcp dport 443 accept"));
        assert_eq!(managed_count(&text), 3);
        assert!(render("reject", &[]).is_err());
        assert!(
            render(
                "drop",
                &[Rule {
                    protocol: "sctp".into(),
                    port: 1,
                    source_v4: None,
                    source_v6: None
                }]
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn prepare_apply_confirm_lifecycle_persists_and_read_back() {
        let (firewall, _dir) = fixture();
        let view = firewall
            .prepare(
                json!({"policy": "drop", "rules": rules()}),
                60,
                "req-1".into(),
            )
            .await
            .unwrap();
        assert_eq!(view["state"], "PREPARED");
        assert_eq!(view["managedRules"], 3);
        // Foreign writers are checked and refused before any candidate exists.
        {
            let mut fake = firewall.0.fake.lock().unwrap();
            fake.ruleset =
                json!({"nftables": [{"table": {"family": "ip", "name": "ufw-firewall"}}]});
        }
        assert!(
            firewall
                .prepare(json!({"policy": "drop", "rules": []}), 60, "req-x".into())
                .await
                .is_err()
        );
        {
            let mut fake = firewall.0.fake.lock().unwrap();
            fake.ruleset = json!({"nftables":[]});
            fake.table = Some(fake_table_with(3));
        }
        let applied = firewall.apply().await.unwrap();
        assert_eq!(applied["state"], "WAIT_CONFIRM");
        let token = view["token"].as_str().unwrap().to_owned();
        let confirmed = firewall.confirm(&token).await.unwrap();
        assert_eq!(confirmed["state"], "COMMITTED");
        let status = firewall.status().await.unwrap();
        assert_eq!(status["revision"], 1);
        assert_eq!(status["confirmedManagedRules"], 3);
        assert_eq!(status["appliedManagedRules"], 3);
    }

    #[tokio::test]
    async fn read_back_mismatch_is_refused_instead_of_reported_applied() {
        let (firewall, _dir) = fixture();
        firewall
            .prepare(
                json!({"policy": "drop", "rules": rules()}),
                60,
                "req-2".into(),
            )
            .await
            .unwrap();
        {
            let mut fake = firewall.0.fake.lock().unwrap();
            fake.missing = 2;
        }
        let error = firewall.apply().await.unwrap_err();
        assert!(error.to_string().contains("read-back mismatch"), "{error}");
    }

    #[tokio::test]
    async fn rollback_restores_previous_ruleset_and_recovers_unconfirmed() {
        let (firewall, _dir) = fixture();
        // Commit an initial ruleset.
        firewall
            .prepare(json!({"policy": "drop", "rules": []}), 60, "a".into())
            .await
            .unwrap();
        {
            let mut fake = firewall.0.fake.lock().unwrap();
            fake.table = Some(fake_table_with(0));
        }
        firewall.apply().await.unwrap();
        let token_a = serde_json::from_str::<Journal>(
            &fs::read_to_string(firewall.0.state.join("transaction.json")).unwrap(),
        )
        .unwrap()
        .token;
        firewall.confirm(&token_a).await.unwrap();
        // Second transaction rolls back to the first ruleset.
        firewall
            .prepare(
                json!({"policy": "accept", "rules": rules()}),
                30,
                "b".into(),
            )
            .await
            .unwrap();
        {
            let mut fake = firewall.0.fake.lock().unwrap();
            fake.table = Some(fake_table_with(0));
        }
        let token_b = serde_json::from_str::<Journal>(
            &fs::read_to_string(firewall.0.state.join("transaction.json")).unwrap(),
        )
        .unwrap()
        .token;
        let rolled = firewall.rollback(&token_b).await.unwrap();
        assert_eq!(rolled["state"], "ROLLED_BACK");
        // Startup recovery rolls back a WAIT_CONFIRM transaction.
        firewall
            .prepare(json!({"policy": "drop", "rules": rules()}), 30, "c".into())
            .await
            .unwrap();
        {
            let mut fake = firewall.0.fake.lock().unwrap();
            fake.table = Some(fake_table_with(3));
        }
        firewall.apply().await.unwrap();
        firewall.recover().await.unwrap();
        let journal: Journal = serde_json::from_str(
            &fs::read_to_string(firewall.0.state.join("transaction.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(journal.state, State::RolledBack);
        // Expiry rolls back an unconfirmed transaction.
        firewall
            .prepare(json!({"policy": "drop", "rules": rules()}), 30, "d".into())
            .await
            .unwrap();
        firewall.apply().await.unwrap();
        let mut journal: Journal = serde_json::from_str(
            &fs::read_to_string(firewall.0.state.join("transaction.json")).unwrap(),
        )
        .unwrap();
        journal.deadline_ms = 0;
        fs::write(
            firewall.0.state.join("transaction.json"),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        firewall.expire().await.unwrap();
        let journal: Journal = serde_json::from_str(
            &fs::read_to_string(firewall.0.state.join("transaction.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(journal.state, State::RolledBack);
    }
    #[test]
    fn source_prefixes_are_parsed_and_canonicalized_before_generating_nft() {
        assert_eq!(prefix("192.0.2.129/24", false).unwrap(), "192.0.2.0/24");
        assert_eq!(prefix("fd00::1234/64", true).unwrap(), "fd00::/64");
        for (value, v6) in [
            ("1.2.3.4\n}; flush ruleset; table inet x {", false),
            ("10.0.0.1/33", false),
            ("fd00::/129", true),
            ("fd00::", false),
            ("1.2.3.4", true),
            ("1.2.3.4/8/8", false),
        ] {
            assert!(prefix(value, v6).is_err(), "{value}");
        }
    }
    #[tokio::test]
    async fn durable_confirmation_and_failed_rollback_are_completed_after_restart() {
        let (firewall, _dir) = fixture();
        let view = firewall
            .prepare(
                json!({"policy":"accept","rules":[]}),
                60,
                "confirm-crash".into(),
            )
            .await
            .unwrap();
        firewall.apply().await.unwrap();
        let mut j = firewall.journal().unwrap().unwrap();
        j.confirmed_decision = true;
        j.state = State::Confirming;
        firewall.persist("transaction.json", &j).unwrap();
        firewall.recover().await.unwrap();
        assert_eq!(firewall.journal().unwrap().unwrap().state, State::Committed);
        assert_eq!(firewall.confirmed().unwrap().revision, 1);
        let commands = firewall.0.fake.lock().unwrap().checked.len();
        firewall.recover().await.unwrap();
        assert_eq!(
            firewall.0.fake.lock().unwrap().checked.len(),
            commands,
            "a settled journal is not a new write authorization"
        );
        assert!(!view["token"].as_str().unwrap().is_empty());
        let view = firewall
            .prepare(
                json!({"policy":"drop","rules":[]}),
                60,
                "rollback-failure".into(),
            )
            .await
            .unwrap();
        firewall.apply().await.unwrap();
        firewall.0.fake.lock().unwrap().fail_apply = true;
        assert!(
            firewall
                .rollback(view["token"].as_str().unwrap())
                .await
                .is_err()
        );
        assert_eq!(
            firewall.journal().unwrap().unwrap().state,
            State::RollingBack
        );
        assert!(
            firewall
                .prepare(
                    json!({"policy":"accept","rules":[]}),
                    60,
                    "must-block".into()
                )
                .await
                .is_err()
        );
        firewall.0.fake.lock().unwrap().fail_apply = false;
        firewall.recover().await.unwrap();
        assert_eq!(
            firewall.journal().unwrap().unwrap().state,
            State::RolledBack
        );
        assert_eq!(firewall.confirmed().unwrap().revision, 1);
    }
    fn v4_candidate() -> Value {
        let mut value:Value=serde_json::from_slice(include_bytes!("firewall/fixtures/v3-kura-candidate.json")).unwrap();
        value["schemaVersion"]=json!(4);
        value["ipv4"]["outputPolicy"]=json!("drop");
        value["ipv6"]["outputPolicy"]=json!("accept");
        value
    }
    #[tokio::test]
    async fn v4_local_durable_policy_preserves_output_and_rolls_back_across_v3_without_reissue() {
        let (fw,dir)=fixture();
        let v3=model::fixture_kura_candidate();
        let tx=fw.prepare(v3,60,"old-v3".into()).await.unwrap();fw.apply().await.unwrap();fw.confirm(tx["token"].as_str().unwrap()).await.unwrap();
        let original=fw.confirmed().unwrap().text;
        let v4=v4_candidate();
        let mut change=kura_change(&fw).await;change["candidate"]=v4.clone();
        let tx=kura_call(&fw,"prepare",change.clone(),"new-v4",true).await.unwrap();
        let checked=fw.0.fake.lock().unwrap().checked.len();
        assert_eq!(kura_call(&fw,"outcome",json!({"originalRequestId":"new-v4","change":change}),"query",false).await.unwrap()["state"],"WAIT_CONFIRM");
        assert_eq!(fw.0.fake.lock().unwrap().checked.len(),checked);
        kura_call(&fw,"rollback",json!({"ownerKey":"a".repeat(64),"id":tx["id"],"token":tx["confirmationToken"]}),"rollback",false).await.unwrap();
        assert_eq!(fw.confirmed().unwrap().text,original);
        let mut change=kura_change(&fw).await;change["candidate"]=v4.clone();
        let tx=kura_call(&fw,"prepare",change,"commit-v4",true).await.unwrap();
        kura_call(&fw,"confirm",json!({"ownerKey":"a".repeat(64),"id":tx["id"],"token":tx["confirmationToken"]}),"confirm",true).await.unwrap();
        let view=kura_call(&fw,"view",json!({}),"view",false).await.unwrap();
        assert_eq!(view["candidate"]["schemaVersion"],4);assert_eq!(view["candidate"]["ipv4"]["outputPolicy"],"drop");assert_eq!(view["candidate"]["ipv6"]["outputPolicy"],"accept");
        let confirmed_bytes=fs::read(dir.0.join("firewall/confirmed.json")).unwrap();
        let tx_bytes=fs::read(dir.0.join("firewall/transaction.json")).unwrap();
        let reopened=Firewall::open(dir.0.clone(),None).unwrap().enable_writes(true);
        reopened.0.fake.lock().unwrap().table=fw.0.fake.lock().unwrap().table.clone();reopened.recover().await.unwrap();
        assert!(reopened.0.fake.lock().unwrap().checked.is_empty());assert_eq!(fs::read(dir.0.join("firewall/transaction.json")).unwrap(),tx_bytes);assert_eq!(fs::read(dir.0.join("firewall/confirmed.json")).unwrap(),confirmed_bytes);
        let original_v4=reopened.confirmed().unwrap().text;
        let old=reopened.prepare(model::fixture_kura_candidate(),60,"rollback-to-v4".into()).await.unwrap();reopened.apply().await.unwrap();reopened.rollback(old["token"].as_str().unwrap()).await.unwrap();
        assert_eq!(reopened.confirmed().unwrap().text,original_v4);
        assert_eq!(serde_json::to_value(reopened.confirmed().unwrap().candidate.unwrap()).unwrap(),serde_json::to_value(serde_json::from_value::<model::ExactKuraCandidate>(v4).unwrap()).unwrap());
    }
    #[tokio::test]
    async fn v4_missing_mixed_or_wrong_schema_output_never_enters_a_transaction() {
        let (fw,dir)=fixture();let original=v4_candidate();
        for defect in ["missing4","missing6","wrongVersion","null","extra"] {
            let mut value=original.clone();match defect {
                "missing4"=>{value["ipv4"].as_object_mut().unwrap().remove("outputPolicy");},
                "missing6"=>{value["ipv6"].as_object_mut().unwrap().remove("outputPolicy");},
                "wrongVersion"=>value["schemaVersion"]=json!(3),
                "null"=>value["ipv4"]["outputPolicy"]=Value::Null,
                "extra"=>value["ipv6"]["expression"]=json!("accept"),_=>unreachable!(),
            }
            let mut change=kura_change(&fw).await;change["candidate"]=value;
            assert!(kura_call(&fw,"prepare",change,defect,true).await.is_err(),"{defect}");
            assert!(!dir.0.join("firewall/transaction.json").exists());assert!(fw.0.fake.lock().unwrap().checked.is_empty());
        }
    }

}
