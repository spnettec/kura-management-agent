//! The joint NM/firewall coordinator writer. Every backend side effect happens
//! after a durable per-action pre-intent under one exclusive system-change
//! guard held with the NM owner kind; lost results stay UNKNOWN and recovery
//! is an adjudication over the original intent plus fresh observation.
use super::*;
use crate::system_change::{Guard, Subsystem};
use prost::Message;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use yofc_management_protocol::v1::{ErrorCode, Operation, ReadCommand, TaskResult, TaskState};
pub(super) mod settlement;

pub(super) const NAT_TABLE: &str = "yofc_nm";
const NAT_COMMENT: &str = "yofc nm auto";
const CONNECTION: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const MANAGER: &str = "org.freedesktop.NetworkManager";
const LIMIT: u64 = 1 << 20;
const PROFILE_ACTION: &str = "profile";
const CHECKPOINT_ACTION: &str = "checkpoint";
const FIREWALL_ACTION: &str = "firewall";

pub(super) struct Coordinator {
    source: Nm,
    root: PathBuf,
    nft: PathBuf,
    #[cfg(test)]
    fake: std::sync::Mutex<FakeNft>,
    #[cfg(test)]
    real: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
#[derive(Default)]
struct FakeNft {
    table: Option<Value>,
    fail_apply: bool,
    writes: usize,
    lose_reply: bool,
    readbacks: std::collections::VecDeque<Value>,
    pause_before_nat: bool,
    forwarding_blocked: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PrepareInput {
    source_digest: String,
    confirm_seconds: u64,
    changes: Value,
    nat: Option<NatSet>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct NatSet {
    wan: String,
    lan: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TokenInput {
    token: String,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl Coordinator {
    pub(super) fn new(mut source: Nm, root: &Path) -> Result<Self> {
        source.engine = None;
        for name in ["nm", "nm/intents", "nm/receipts", "nm/history", "nm/remote-history"] {
            crate::durable::directory(&root.join(name))?;
        }
        Ok(Self {
            source,
            root: root.into(),
            nft: PathBuf::from("/usr/sbin/nft"),
            #[cfg(test)]
            fake: std::sync::Mutex::new(FakeNft::default()),
            #[cfg(test)]
            real: std::sync::atomic::AtomicBool::new(false),
        })
    }
    pub(super) fn capture_source(&self, deadline: Instant) -> Result<(Value, Vec<Device>)> {
        let forwarding = self.ipv4_forwarding()?;
        let nat = self.observed_nat(deadline)?;
        let marker = ownership::marker(&self.root)?;
        let firewall = self.firewall_binding()?;
        let (mut source, devices) = self.source.capture(deadline)?;
        let rechecked_nat = self.observed_nat(deadline)?;
        ensure!(settlement::nat_equal(nat.as_ref(), rechecked_nat.as_ref())
            && marker == ownership::marker(&self.root)? && firewall == self.firewall_binding()?
            && forwarding == self.ipv4_forwarding()?,
            "CONFLICT: joint NM/NAT/firewall source changed during observation");
        ensure!(Instant::now() < deadline, "TIMEOUT: joint NM observation deadline");
        source["sourceDigest"] = json!(digest(&json!({
            "profiles":source["sourceDigest"],"automaticNat":nat,
            "natOwnership":marker,"firewall":firewall,"ipv4Forwarding":forwarding,
        }))?);
        Ok((source, devices))
    }
    fn ipv4_forwarding(&self) -> Result<bool> {
        #[cfg(test)]
        if !self.real.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(!self.fake.lock().unwrap().forwarding_blocked);
        }
        let value=std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("UNSUPPORTED: IPv4 forwarding state unavailable")?;
        match value.trim() {
            "0"=>Ok(false),"1"=>Ok(true),
            _=>anyhow::bail!("CONFLICT: invalid IPv4 forwarding state"),
        }
    }
    pub(super) fn require_forwarding(&self, nat: Option<&NatSet>) -> Result<()> {
        ensure!(nat.is_none() || self.ipv4_forwarding()?,
            "FORBIDDEN: automatic NAT requires IPv4 forwarding enabled by the system owner");
        Ok(())
    }
    fn journal_path(&self) -> PathBuf {
        self.root.join("nm/transaction.json")
    }
    fn intent_path(&self, operation: uuid::Uuid, action: Option<&str>) -> PathBuf {
        let name = match action {
            None => format!("{operation}.json"),
            Some(action) => format!("{operation}.{action}.json"),
        };
        self.root.join("nm/intents").join(name)
    }
    fn receipt_path(&self, operation: uuid::Uuid) -> PathBuf {
        self.root.join("nm/receipts").join(format!("{operation}.json"))
    }
    fn journal(&self) -> Result<Option<transaction::Journal>> {
        let path = self.journal_path();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(
            &crate::durable::read(&path, LIMIT)?.0,
        )?))
    }
    fn save(&self, journal: &transaction::Journal) -> Result<()> {
        crate::durable::json(&self.journal_path(), journal)
    }
    fn write<T>(&self, action: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        let _guard = Guard::acquire(&self.root, Subsystem::Nm)?;
        action(self)
    }
    fn publish_main_intent(
        &self,
        operation: uuid::Uuid,
        source_digest: &str,
        candidate_digest: &str,
        nm_identity: &BusBinding,
        nat_before: &Value,
        nat_target: &Value,
    ) -> Result<String> {
        let intent = transaction::IntentHeader {
            schema_version: 1,
            operation_id: operation,
            source_digest: source_digest.into(),
            candidate_digest: candidate_digest.into(),
            nm_identity: Some(nm_identity.clone()),
            nat_before: Some(nat_before.clone()),
            nat_target: Some(nat_target.clone()),
        };
        let bytes = serde_json::to_vec(&intent)?;
        crate::durable::publish_new(
            &self.intent_path(operation, None),
            &bytes,
            crate::durable::FileMetadata::private(),
        )?;
        Ok(crate::durable::hash(&bytes))
    }
    fn publish_action_intent(
        &self,
        journal: &mut transaction::Journal,
        action: &str,
        payload: &Value,
    ) -> Result<()> {
        ensure!(
            !journal
                .action_intents
                .iter()
                .any(|record| record.action == action),
            "CONFLICT: NM action intent already recorded"
        );
        let bytes = serde_json::to_vec(payload)?;
        crate::durable::publish_new(
            &self.intent_path(journal.operation_id, Some(action)),
            &bytes,
            crate::durable::FileMetadata::private(),
        )?;
        journal.action_intents.push(transaction::ActionIntent {
            action: action.into(),
            sha256: crate::durable::hash(&bytes),
        });
        self.save(journal)
    }
    fn verify_action_intent(
        &self,
        journal: &transaction::Journal,
        action: &str,
    ) -> Result<Value> {
        let record = journal
            .action_intents
            .iter()
            .find(|record| record.action == action)
            .context("CONFLICT: NM action intent missing")?;
        let (bytes, meta) = crate::durable::read(
            &self.intent_path(journal.operation_id, Some(action)),
            LIMIT,
        )?;
        ensure!(
            meta.uid == unsafe { libc::geteuid() } && meta.mode == 0o600,
            "FORBIDDEN: unsafe NM action intent"
        );
        ensure!(
            crate::durable::hash(&bytes) == record.sha256,
            "CONFLICT: NM action intent changed"
        );
        Ok(serde_json::from_slice(&bytes)?)
    }
    fn finish(&self, journal: &mut transaction::Journal, state: transaction::State) -> Result<()> {
        let receipt = transaction::Receipt {
            schema_version: 1,
            operation_id: journal.operation_id,
            source_digest: journal.source_digest.clone(),
            candidate_digest: journal.candidate_digest.clone(),
            intent_sha256: journal.intent_sha256.clone(),
            state: state.clone(),
        };
        let bytes = serde_json::to_vec(&receipt)?;
        let receipt_path = self.receipt_path(journal.operation_id);
        match std::fs::symlink_metadata(&receipt_path) {
            Ok(_) => {
                use std::io::Read;
                use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
                let mut file = std::fs::OpenOptions::new().read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(&receipt_path)?;
                let metadata = file.metadata()?;
                ensure!(metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= LIMIT
                    && metadata.uid() == unsafe {libc::geteuid()} && metadata.mode() & 0o777 == 0o600,
                    "OUTCOME_UNKNOWN: unsafe existing NM terminal receipt");
                let mut existing = Vec::new();
                std::io::Read::by_ref(&mut file).take(LIMIT + 1).read_to_end(&mut existing)?;
                ensure!(existing == bytes, "OUTCOME_UNKNOWN: existing NM terminal receipt differs");
                file.sync_all()?;
                crate::durable::sync_directory(receipt_path.parent().unwrap())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::durable::publish_new(&receipt_path, &bytes, crate::durable::FileMetadata::private())?;
            }
            Err(error) => return Err(error.into()),
        }
        let receipt_sha256 = crate::durable::hash(&bytes);
        if state == transaction::State::Committed {
            let payload = self.verify_action_intent(journal, FIREWALL_ACTION)?;
            let nat: Option<NatSet> = serde_json::from_value(payload["nat"].clone())?;
            ownership::publish(&self.root, journal, receipt_sha256.clone(), nat)?;
        }
        journal.state = state;
        journal.terminal_receipt_sha256 = Some(receipt_sha256);
        self.save(journal)
    }
    /// Read-only view of the firewall owner's current authority. The
    /// coordinator never mutates it; it only detects foreign progress.
    fn firewall_binding(&self) -> Result<transaction::FirewallBinding> {
        let transaction = self.root.join("firewall/transaction.json");
        let journal_settled = if transaction.exists() {
            let (bytes, meta) = crate::durable::read(&transaction, LIMIT)?;
            ensure!(
                meta.uid == unsafe { libc::geteuid() } && meta.mode == 0o600,
                "FORBIDDEN: unsafe firewall journal"
            );
            let value: Value = serde_json::from_slice(&bytes)?;
            ensure!(
                value["state"].as_str().is_some(),
                "CONFLICT: firewall journal state"
            );
            matches!(value["state"].as_str(), Some("COMMITTED") | Some("ROLLED_BACK"))
        } else {
            true
        };
        let confirmed = self.root.join("firewall/confirmed.json");
        let (revision, digest) = if confirmed.exists() {
            let (bytes, meta) = crate::durable::read(&confirmed, LIMIT)?;
            ensure!(
                meta.uid == unsafe { libc::geteuid() } && meta.mode == 0o600,
                "FORBIDDEN: unsafe firewall confirmed state"
            );
            let value: Value = serde_json::from_slice(&bytes)?;
            ensure!(value["revision"].is_u64(), "CONFLICT: firewall revision");
            (
                value["revision"].as_u64().unwrap(),
                crate::durable::hash(&bytes),
            )
        } else {
            (0, String::new())
        };
        Ok(transaction::FirewallBinding {
            revision,
            confirmed_sha256: digest,
            journal_settled,
        })
    }
    fn ensure_firewall_binding(&self, journal: &transaction::Journal) -> Result<()> {
        let recorded = journal
            .firewall_binding
            .clone()
            .context("CONFLICT: NM firewall binding missing")?;
        ensure!(
            self.firewall_binding()? == recorded,
            "CONFLICT: firewall owner changed during NM transaction"
        );
        Ok(())
    }
    fn input(&self, journal: &transaction::Journal) -> Result<PrepareInput> {
        serde_json::from_value(
            journal
                .input
                .clone()
                .context("CONFLICT: NM proposal missing")?,
        )
        .map_err(|_| anyhow::anyhow!("CONFLICT: NM proposal"))
    }
    /// Fresh two-pass observation bound to the recorded source digest; the
    /// typed candidate is recompiled deterministically from the durable input.
    fn recompile(
        &self,
        journal: &transaction::Journal,
        deadline: Instant,
    ) -> Result<Vec<preview::DetachedCandidate>> {
        let (source, devices) = self.capture_source(deadline)?;
        ensure!(
            source["sourceDigest"] == journal.source_digest,
            "CONFLICT: NM source changed since prepare"
        );
        let input = self.input(journal)?;
        let proposal = preview::Preview::parse(json!({
            "sourceDigest": journal.source_digest,
            "changes": input.changes,
        }))?;
        let (candidate, detached) = proposal.compile_detached(&source, &devices)?;
        ensure!(
            candidate["candidateDigest"] == journal.candidate_digest,
            "CONFLICT: NM candidate changed"
        );
        Ok(detached)
    }
    fn checkpoints(&self, deadline: Instant) -> Result<Vec<String>> {
        let identity = self.source.identity(deadline)?;
        let value = self.source.property(
            &identity.service_owner,
            super::ROOT,
            super::NAME,
            "Checkpoints",
            "ao",
            deadline,
        )?;
        value
            .as_array()
            .context("CONFLICT: NM checkpoint list")?
            .iter()
            .map(|path| {
                path.as_str()
                    .map(str::to_string)
                    .context("CONFLICT: NM checkpoint path")
            })
            .collect()
    }
    fn call(
        &self,
        owner: &str,
        path: &str,
        interface: &str,
        method: &str,
        arguments: &[Value],
        deadline: Instant,
    ) -> Result<Value> {
        ensure!(Instant::now() < deadline, "TIMEOUT: NM write deadline");
        let expected_server_guid = if matches!(method, "CheckpointCreate" | "Update2" | "Reapply" | "CheckpointRollback" | "CheckpointDestroy") {
            let journal = self.journal()?.context("CONFLICT: NM mutation journal missing")?;
            let expected = journal.nm_identity.as_ref().context("CONFLICT: original NM bus binding missing")?;
            let observed = self.source.binding(deadline)?;
            ensure!(observed.identity == expected.identity && observed.identity.service_owner == owner,
                "CONFLICT: original NM service instance changed");
            Some(observed.server_guid)
        } else {
            self.source.wire.server_guid(deadline)?
        };
        self.source.wire.call(
            &BusCall {
                destination: owner.into(),
                path: path.into(),
                interface: interface.into(),
                method: method.into(),
                arguments: arguments.to_vec(),
                  expected_server_guid,
            },
            deadline,
        )
    }
    fn owner(&self, deadline: Instant) -> Result<String> {
        Ok(self.source.identity(deadline)?.service_owner)
    }
    fn profile_version(&self, owner: &str, path: &str, deadline: Instant) -> Result<u64> {
        // property() already unwraps the D-Bus variant.
        self.source
            .property(owner, path, CONNECTION, "VersionId", "t", deadline)?
            .as_u64()
            .filter(|v| *v > 0)
            .context("CONFLICT: NM profile version token")
    }
    fn profile_settings(&self, owner: &str, path: &str, deadline: Instant) -> Result<Value> {
        Ok(fields(
            self.call(owner, path, CONNECTION, "GetSettings", &[], deadline)?,
            "a{sa{sv}}",
            1,
        )?
        .remove(0))
    }
    /// Bind the edited fields to a recorded candidate or original read set.
    /// Unrelated defaults may be normalized by NetworkManager.
    fn verify_edited_fields(
        &self,
        readback: &Value,
        profile: &Value,
        edited: &Value,
    ) -> Result<()> {
        let surface = edited
            .as_object()
            .context("CONFLICT: NM profile intent edit surface")?;
        for (group, keys) in surface {
            let keys = keys.as_array().context("CONFLICT: NM profile intent edit keys")?;
            for key in keys {
                let key = key.as_str().context("CONFLICT: NM profile intent edit key")?;
                let expected = &profile["settings"][group][key];
                let actual = &readback[&group][key];
                // NM drops empty container defaults on roundtrip; an absent key
                // equals an explicitly empty one.
                // NM omits properties whose effective value is the type's
                // default (false, 0, empty container). A missing readback with
                // a default-valued expectation is the intended state.
                let data = &expected["data"];
                // -1 on metrics/priorities means "choose automatically", which
                // NM stores as absent.
                let default_valued = data.is_null()
                    || data.as_bool() == Some(false)
                    || data.as_i64().is_some_and(|v| v == 0 || v == -1)
                    || data.as_array().is_some_and(|v| v.is_empty());
                let empty_absent = default_valued && actual.is_null();
                ensure!(
                    (!expected.is_null() && actual == expected) || empty_absent,
                    "CONFLICT: NM profile readback mismatch on {group}/{key}: expected {} got {}",
                    serde_json::to_string(expected).unwrap_or_default(),
                    serde_json::to_string(actual).unwrap_or_default()
                );
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NAT rendering and kernel read-back
// ---------------------------------------------------------------------------
/// The exact property surface a typed change touches. NM roundtrips the whole
/// profile and may drop untouched defaults, so the write verification binds to
/// this edited surface instead of a whole-profile digest.
fn edited_surface(changes: &Value) -> Result<Value> {
    let rows = changes.as_array().context("CONFLICT: NM proposal changes")?;
    let mut out = serde_json::Map::new();
    for change in rows {
        let interface = change["interface"].as_str().context("CONFLICT: NM proposal interface")?;
        let mut surface = serde_json::Map::new();
        for family in ["ipv4", "ipv6"] {
            if change[family].is_null() {
                continue;
            }
            let mut keys = vec![
                json!("method"),
                json!("address-data"),
                json!("dns"),
                json!("ignore-auto-dns"),
                json!("ignore-auto-routes"),
            ];
            if !change[family]["gateway"].is_null() {
                keys.push(json!("gateway"));
            }
            if !change[family]["wanPriority"].is_null() {
                keys.push(json!("route-metric"));
                keys.push(json!("dns-priority"));
            }
            surface.insert(family.into(), Value::Array(keys));
        }
        if !change["ethernet"].is_null() {
            surface.insert(
                "ethernet".into(),
                json!(["mtu", "accept-all-mac-addresses"]),
            );
        }
        out.insert(interface.into(), Value::Object(surface));
    }
    Ok(Value::Object(out))
}
fn strip_empty_edited(mut settings: Value, edited: &Value) -> Value {
    let Some(surface) = edited.as_object() else {
        return settings;
    };
    for (group, keys) in surface {
        let Some(keys) = keys.as_array() else { continue };
        let Some(map) = settings.get_mut(group).and_then(|v| v.as_object_mut()) else {
            continue;
        };
        for key in keys {
            let Some(key) = key.as_str() else { continue };
            let empty = map
                .get(key)
                .and_then(|v| v["data"].as_array())
                .is_some_and(|v| v.is_empty());
            if empty {
                map.remove(key);
            }
        }
    }
    settings
}
fn render_nat(wan: &str, lan: &[String]) -> String {
    let mut text = format!(
        "destroy table inet {NAT_TABLE}\ntable inet {NAT_TABLE} {{\n  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n"
    );
    for interface in lan {
        text.push_str(&format!(
            "    iifname \"{interface}\" oifname \"{wan}\" masquerade comment \"{NAT_COMMENT}\"\n"
        ));
    }
    text.push_str("  }\n}\n");
    text
}
fn rule_pair(rule: &Value) -> Result<(Option<String>, Option<String>, Option<String>)> {
    let mut input = None;
    let mut output = None;
    // The kernel keeps the comment at rule level (expr-level comments are
    // accepted for compatibility with older dumps).
    let mut comment = rule["comment"].as_str().map(str::to_string);
    for expression in rule["expr"]
        .as_array()
        .context("CONFLICT: NAT kernel readback")?
    {
        if let Some(key) = expression["match"]["left"]["meta"]["key"].as_str() {
            let right = expression["match"]["right"].as_str().map(str::to_string);
            match key {
                "iifname" => input = right,
                "oifname" => output = right,
                _ => {}
            }
        }
        if comment.is_none()
            && let Some(text) = expression["comment"]["text"].as_str()
        {
            comment = Some(text.into());
        }
    }
    Ok((input, output, comment))
}
impl Coordinator {
    fn run_nft(&self, args: &[&str], input: Option<&str>) -> Result<String> {
        self.run_nft_until(args,input,Instant::now()+Duration::from_secs(10))
    }
    pub(super) fn run_nft_until(&self, args: &[&str], input: Option<&str>, deadline: Instant) -> Result<String> {
        ensure!(Instant::now() < deadline,"TIMEOUT: automatic NAT command deadline");
        #[cfg(test)]
        if !self.real.load(std::sync::atomic::Ordering::Relaxed) {
            let mut fake = self.fake.lock().unwrap();
            if let Some(text) = input {
                  fake.writes += 1;
                ensure!(!fake.fail_apply, "INTERNAL: injected nft failure");
                if text.contains(&format!("table inet {NAT_TABLE} {{")) {
                    fake.table = Some(fake_table(text));
                } else {
                    fake.table = None;
                }
                  ensure!(!fake.lose_reply, "TIMEOUT: injected nft reply loss after effect");
            }
            let command = args.join(" ");
            if command.contains("list ruleset") {
                return Ok(fake
                    .table
                    .clone()
                    .unwrap_or_else(|| json!({"nftables":[]}))
                    .to_string());
            }
            if command.contains("list table") {
                if let Some(value) = fake.readbacks.pop_front() {return Ok(value.to_string());}
                let table = fake.table.clone().context("INTERNAL: table absent")?;
                return Ok(table.to_string());
            }
            return Ok(String::new());
        }
        let output = crate::process::run(
            &self.nft,
            args,
            input.map(str::as_bytes),
            deadline.checked_duration_since(Instant::now()).filter(|duration| !duration.is_zero())
                .context("TIMEOUT: automatic NAT command deadline")?.min(Duration::from_secs(10)),
        )?;
        ensure!(
            output.status.success(),
            "INTERNAL: nft command failed ({} diagnostic bytes)",
            output.stderr.len()
        );
        Ok(String::from_utf8(output.stdout)?)
    }
    fn apply_text(&self, text: &str, deadline: Instant) -> Result<()> {
        self.run_nft_until(&["-f", "-"], Some(text), deadline)?;
        Ok(())
    }
    /// Removing the coordinator's own NAT table. A destroy of an already
    /// absent table fails on real nftables; absence is then proven by the
    /// readback, which stays the authoritative gate.
    fn verify_nat(&self, expected: Option<&NatSet>) -> Result<()> {
        let Some(expected) = expected else {
            // Absence must be proven against the whole ruleset; a failed
            // list-table command alone cannot distinguish EPERM from absence.
            let result = self.run_nft(&["-j", "list", "table", "inet", NAT_TABLE], None);
            ensure!(result.is_err(), "CONFLICT: own NAT table still present");
            let value: Value =
                serde_json::from_str(&self.run_nft(&["-j", "list", "ruleset"], None)?)?;
            ensure!(
                !value["nftables"]
                    .as_array()
                    .context("INTERNAL: ruleset format")?
                    .iter()
                    .any(|e| e["table"]["family"] == "inet" && e["table"]["name"] == NAT_TABLE),
                "CONFLICT: own NAT table still present"
            );
            return Ok(());
        };
        let value: Value =
            serde_json::from_str(&self.run_nft(&["-j", "list", "table", "inet", NAT_TABLE], None)?)?;
        let actual = settlement::parse_nat(&value)?;
        ensure!(settlement::nat_equal(Some(&actual), Some(expected)), "CONFLICT: NAT readback mismatch");
        Ok(())
    }
}
#[cfg(test)]
fn fake_table(text: &str) -> Value {
    let mut entries = Vec::new();
    for line in text.lines() {
        let Some((before, comment)) = line.split_once("comment \"") else {
            continue;
        };
        let comment = comment.trim_end_matches('"').to_string();
        let mut exprs = Vec::new();
        for key in ["iifname", "oifname"] {
            if let Some(rest) = before.split_once(&format!("{key} \"")) {
                let interface = rest.1.split('"').next().unwrap_or_default().to_string();
                    exprs.push(json!({"match":{"op":"==","left":{"meta":{"key":key}},"right":interface}}));
            }
        }
        exprs.push(json!({"masquerade":null}));
        entries.push(json!({"rule":{"family":"inet","table":NAT_TABLE,"chain":"postrouting","comment":comment,"expr":exprs}}));
    }
    let mut all = vec![
        json!({"metainfo":{"json_schema_version":1}}),
        json!({"table":{"family":"inet","name":NAT_TABLE}}),
        json!({"chain":{"family":"inet","table":NAT_TABLE,"name":"postrouting","type":"nat","hook":"postrouting","prio":100,"policy":"accept"}}),
    ];
    all.extend(entries);
    json!({"nftables": all})
}

// ---------------------------------------------------------------------------
// Proposal and archive
// ---------------------------------------------------------------------------
impl Coordinator {
    fn ensure_nat_baseline(&self, journal: &transaction::Journal, deadline: Instant) -> Result<()> {
        let baseline = journal.nat_before.as_ref().context("CONFLICT: NAT baseline missing")?;
        ownership::ensure_baseline(&self.root, baseline)?;
        let before: Option<NatSet> = serde_json::from_value(baseline["nat"].clone())?;
        let live = self.observed_nat(deadline)?;
        ensure!(settlement::nat_equal(live.as_ref(), before.as_ref()),
            "CONFLICT: automatic NAT changed since preparation");
        Ok(())
    }
    fn validate_nat(&self, nat: &NatSet, devices: &[Device]) -> Result<()> {
        let configured = &self.source.config.interfaces;
        let valid = |name: &str| {
            configured.iter().any(|c| c == name)
                && !name.is_empty()
                && name.len() <= 15
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        };
        ensure!(valid(&nat.wan), "INVALID_ARGUMENT: NAT upstream interface");
        ensure!(
            !nat.lan.is_empty() && nat.lan.len() <= 16,
            "INVALID_ARGUMENT: NAT downstream bounds"
        );
        let mut unique = std::collections::BTreeSet::new();
        for interface in &nat.lan {
            ensure!(
                valid(interface) && interface != &nat.wan && unique.insert(interface),
                "INVALID_ARGUMENT: NAT downstream interface"
            );
        }
        for name in std::iter::once(&nat.wan).chain(nat.lan.iter()) {
            let device = devices
                .iter()
                .find(|d| &d.interface == name)
                .context("FORBIDDEN: NAT interface not observed")?;
            ensure!(
                device.managed && device.state == 100 && device.active_profile.is_some(),
                "UNSUPPORTED: NAT interface needs an active managed profile"
            );
        }
        Ok(())
    }
    pub(super) fn prepare(&self, value: Value) -> Result<Value> {
        self.write(|this| this.prepare_inner(value))
    }
    fn prepare_inner(&self, value: Value) -> Result<Value> {
        // The admission reader fails closed on malformed evidence of any kind;
        // this caller is the NM owner, so unresolved state reaches the next
        // check and is refused there with its original identity intact.
        transaction::admission(&self.root)?;
        if self.journal()?.is_some() {
            anyhow::bail!(
                "OUTCOME_UNKNOWN: an NM transaction already exists; query status, settle or archive it"
            );
        }
        let nat_provided = value.get("nat").is_some();
        let mut input: PrepareInput = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: NM coordinator proposal"))?;
        ensure!(
            (30..=300).contains(&input.confirm_seconds),
            "INVALID_ARGUMENT: confirmation window"
        );
        // The writer minimum is the version-id contract, not the preview's
        // observation minimum.
        let deadline = Instant::now() + Duration::from_secs(20);
        let (source, devices) = self.capture_source(deadline)?;
        ensure!(
            source["sourceDigest"] == input.source_digest,
            "CONFLICT: NM source changed since observation"
        );
        let version = source["source"]["version"]
            .as_str()
            .context("CONFLICT: NM version")?;
        let mut parts = version.split('.');
        let major = parts
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            .context("UNSUPPORTED: NM version")?;
        let minor = parts
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            .context("UNSUPPORTED: NM version")?;
        ensure!(
            (major, minor) >= (1, 44),
            "UNSUPPORTED: NM write needs version 1.44 or newer"
        );
        let proposal = preview::Preview::parse(json!({
            "sourceDigest": input.source_digest,
            "changes": input.changes,
        }))?;
        let (candidate, detached) = proposal.compile_detached(&source, &devices)?;
        ensure!(
            detached.iter().all(|d| d.version_id > 0),
            "CONFLICT: NM profile version token"
        );
        if let Some(nat) = &input.nat {
            self.validate_nat(nat, &devices)?;
        }
        let candidate_digest = candidate["candidateDigest"]
            .as_str()
            .context("CONFLICT: NM candidate digest")?
            .to_string();
          let binding = self.source.binding(deadline)?;
          let captured_identity: Identity = serde_json::from_value(source["source"]["identity"].clone())?;
          ensure!(binding.identity == captured_identity, "CONFLICT: NM service changed after observation");
        let operation = uuid::Uuid::new_v4();
          let previous_nat = self.observed_nat(deadline)?;
          if let Some(previous) = &previous_nat {self.validate_nat(previous, &devices)?;}
          let nat_before = ownership::capture(&self.root, previous_nat.as_ref())?;
          if !nat_provided { input.nat = previous_nat; }
          self.require_forwarding(input.nat.as_ref())?;
          let nat_target = json!({"nat":input.nat});
        let intent_sha256 =
              self.publish_main_intent(operation, &input.source_digest, &candidate_digest, &binding, &nat_before, &nat_target)?;
        let mut journal = transaction::Journal::new(
            operation,
            input.source_digest.clone(),
            candidate_digest,
            intent_sha256,
            transaction::State::Prepared,
        );
        journal.token = Some(format!("{:016x}{:016x}", OsRng.next_u64(), OsRng.next_u64()));
          journal.nm_identity = Some(binding);
          journal.nat_before = Some(nat_before);
        journal.firewall_binding = Some(self.firewall_binding()?);
        journal.pre_existing_checkpoints = self.checkpoints(deadline)?;
        journal.input = Some(json!({
            "sourceDigest": input.source_digest,
            "confirmSeconds": input.confirm_seconds,
            "changes": input.changes,
            "nat": input.nat,
        }));
        self.save(&journal)?;
        Ok(json!({
            "schemaVersion":1,"backend":"NetworkManager",
            "operationId":operation.hyphenated().to_string(),
            "state":serde_json::to_value(&journal.state)?,
            "token":journal.token,
            "writeEnabled":true,"prepared":false,"requiresAdoption":true,
            "candidateDigest":journal.candidate_digest,
        }))
    }
    /// Explicitly retain a settled transaction's evidence under nm/history so
    /// a new proposal can start. Never runs on unresolved or malformed state.
    pub(super) fn archive(&self) -> Result<Value> {
        self.write(|this| {
            transaction::admission(&this.root)?;
            let Some(journal) = this.journal()? else {
                anyhow::bail!("CONFLICT: no NM transaction to archive");
            };
            ensure!(
                journal.state.terminal(),
                "OUTCOME_UNKNOWN: unresolved NM transaction; recover it first"
            );
            let history = this.root.join("nm/history");
            crate::durable::directory(&history)?;
            let operation = journal.operation_id;
            for record in &journal.action_intents {
                let source = this.intent_path(operation, Some(&record.action));
                if source.exists() {
                    crate::durable::move_new(
                        &source,
                        &history.join(format!("{operation}.{}.intent.json", record.action)),
                    )?;
                }
            }
            let main = this.intent_path(operation, None);
            if main.exists() {
                crate::durable::move_new(
                    &main,
                    &history.join(format!("{operation}.intent.json")),
                )?;
            }
            let receipt = this.receipt_path(operation);
            if receipt.exists() {
                crate::durable::move_new(
                    &receipt,
                    &history.join(format!("{operation}.receipt.json")),
                )?;
            }
            this.archive_remote(&journal)?;
            crate::durable::move_new(
                &this.journal_path(),
                &history.join(format!("{operation}.journal.json")),
            )?;
            Ok(json!({"archived": operation.hyphenated().to_string()}))
        })
    }
}

// ---------------------------------------------------------------------------
// Apply stages
// ---------------------------------------------------------------------------
impl Coordinator {
    pub(super) fn apply(&self) -> Result<Value> {
        self.write(|this| this.apply_inner())
    }
    fn apply_inner(&self) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut journal = self.journal()?.context("CONFLICT: no NM transaction")?;
        // A retained dispatch intent cannot prove whether its call reached NM
        // (or nft). Only an intent published within this invocation may proceed
        // to its first dispatch. Re-entry must adjudicate the original journal.
        ensure!(
            !matches!(
                journal.state,
                transaction::State::CheckpointIntent
                    | transaction::State::ProfileIntent
                    | transaction::State::FirewallIntent
            ),
            "OUTCOME_UNKNOWN: NM action intent retained; query original operation"
        );
        loop {
            match journal.state {
                transaction::State::Prepared => {
                    self.input(&journal)?;
                    self.ensure_nat_baseline(&journal, deadline)?;
                    self.ensure_firewall_binding(&journal)?;
                    let input = self.input(&journal)?;
                    self.require_forwarding(input.nat.as_ref())?;
                    // Bind rollback to the fresh, source-checked edit set. An
                    // empty NM device array would checkpoint every interface.
                    let detached = self.recompile(&journal, deadline)?;
                    let mut devices: Vec<_> = detached.iter().map(|d| d.device_path.clone()).collect();
                    devices.sort();
                    devices.dedup();
                    ensure!(!devices.is_empty(), "CONFLICT: NM checkpoint devices missing");
                    let payload = json!({"schemaVersion":1,
                        "operationId":journal.operation_id.hyphenated().to_string(),
                        "action":CHECKPOINT_ACTION,"timeoutSeconds":input.confirm_seconds,
                        "devices":devices,
                        "profiles":settlement::profile_rows(&detached, &input.changes)?});
                    self.publish_action_intent(&mut journal, CHECKPOINT_ACTION, &payload)?;
                    journal.state = transaction::State::CheckpointIntent;
                    self.save(&journal)?;
                }
                transaction::State::CheckpointIntent => {
                    let payload = self.verify_action_intent(&journal, CHECKPOINT_ACTION)?;
                    self.require_forwarding(self.input(&journal)?.nat.as_ref())?;
                    let seconds = payload["timeoutSeconds"]
                        .as_u64()
                        .context("CONFLICT: NM checkpoint intent")?;
                    let devices = payload["devices"]
                        .as_array()
                        .filter(|devices| !devices.is_empty())
                        .context("CONFLICT: NM checkpoint devices missing")?;
                    for device in devices {
                        object_path(device, "Devices")?;
                    }
                    self.ensure_firewall_binding(&journal)?;
                    let owner = self.owner(deadline)?;
                    ensure!(
                        self.checkpoints(deadline)? == journal.pre_existing_checkpoints,
                        "CONFLICT: unexpected NM checkpoint appeared"
                    );
                    let values = fields(
                        self.call(
                            &owner,
                            super::ROOT,
                            MANAGER,
                            "CheckpointCreate",
                            &[
                                json!({"type":"ao","data":devices}),
                                json!({"type":"u","data":seconds}),
                                // NM >= 1.24 takes a flags word; zero keeps the
                                // documented rollback-only behavior.
                                json!({"type":"u","data":0}),
                            ],
                            deadline,
                        )?,
                        "o",
                        1,
                    )?;
                    let path = object_path(&values[0], "Checkpoint")?;
                    journal.checkpoint_path = Some(path);
                    journal.deadline_ms = Some(now() + seconds.saturating_mul(1000));
                    journal.state = transaction::State::CheckpointCreated;
                    self.save(&journal)?;
                }
                transaction::State::CheckpointCreated => {
                    ensure!(
                        self.checkpoints(deadline)?
                            .iter()
                            .any(|p| Some(p) == journal.checkpoint_path.as_ref()),
                        "CONFLICT: NM checkpoint disappeared"
                    );
                    self.ensure_firewall_binding(&journal)?;
                    let detached = self.recompile(&journal, deadline)?;
                    let input_changes = self.input(&journal)?.changes;
                    let payload = json!({"schemaVersion":1,
                        "operationId":journal.operation_id.hyphenated().to_string(),
                        "action":PROFILE_ACTION,
                        "profiles":settlement::profile_rows(&detached, &input_changes)?});
                    self.publish_action_intent(&mut journal, PROFILE_ACTION, &payload)?;
                    journal.state = transaction::State::ProfileIntent;
                    self.save(&journal)?;
                }
                transaction::State::ProfileIntent => {
                    let payload = self.verify_action_intent(&journal, PROFILE_ACTION)?;
                    self.ensure_firewall_binding(&journal)?;
                    let owner = self.owner(deadline)?;
                    let profiles = payload["profiles"]
                        .as_array()
                        .context("CONFLICT: NM profile intent")?
                        .clone();
                    for profile in &profiles {
                        let path = profile["profilePath"]
                            .as_str()
                            .context("CONFLICT: NM profile intent path")?;
                        let device = profile["devicePath"]
                            .as_str()
                            .context("CONFLICT: NM profile intent device")?;
                        let version = profile["versionId"]
                            .as_u64()
                            .filter(|v| *v > 0)
                            .context("CONFLICT: NM profile intent version")?;
                        // The checkpoint may legitimately have re-written
                        // NM-managed metadata (netplan integrations rewrite the
                        // profile timestamp on re-activation), so the compare-
                        // and-set token is re-read here, after the checkpoint,
                        // while the user-facing content must still bind to the
                        // durable intent exactly.
                        let cas = self.profile_version(&owner, path, deadline)?;
                        ensure!(
                            cas >= version,
                            "CONFLICT: NM profile version moved backwards since intent"
                        );
                        let live = self.profile_settings(&owner, path, deadline)?;
                        ensure!(
                            settings_digest(&live)?
                                == profile["sourceSha256"]
                                    .as_str()
                                    .context("CONFLICT: NM profile intent digest")?,
                            "CONFLICT: NM profile content changed since intent"
                        );
                        // The busctl boundary cannot prove non-dispatch from an
                        // opaque error. Issue each mutation once; even a no-op
                        // or a missing version increment must never cause a
                        // second Update2/Reapply.
                        let payload_settings = strip_empty_edited(
                            profile["settings"].clone(),
                            &profile["edited"],
                        );
                        self.call(
                            &owner,
                            path,
                            CONNECTION,
                            "Update2",
                            &[
                                json!({"type":"a{sa{sv}}","data":payload_settings}),
                                json!({"type":"u","data":0}),
                                json!({"type":"a{sv}","data":{"version-id":{"type":"t","data":cas}}}),
                            ],
                            deadline,
                        ).map_err(|_| anyhow::anyhow!(
                            "OUTCOME_UNKNOWN: NM profile update response unconfirmed"
                        ))?;
                        self.call(
                            &owner,
                            device,
                            DEVICE,
                            "Reapply",
                            &[
                                json!({"type":"a{sa{sv}}","data":profile["applied"]}),
                                json!({"type":"t","data":profile["appliedVersion"]}),
                                json!({"type":"u","data":0}),
                            ],
                            deadline,
                        ).map_err(|_| anyhow::anyhow!(
                            "OUTCOME_UNKNOWN: NM reapply response unconfirmed"
                        ))?;
                        let observed_version = self.profile_version(&owner, path, deadline)
                            .map_err(|_| anyhow::anyhow!("OUTCOME_UNKNOWN: NM profile version readback unavailable"))?;
                        ensure!(
                            observed_version >= cas,
                            "OUTCOME_UNKNOWN: NM profile version moved backwards after dispatch"
                        );
                        let readback = self.profile_settings(&owner, path, deadline)
                            .map_err(|_| anyhow::anyhow!("OUTCOME_UNKNOWN: NM profile readback unavailable"))?;
                        self.verify_edited_fields(&readback, profile, &profile["edited"])
                            .map_err(|_| anyhow::anyhow!("OUTCOME_UNKNOWN: NM profile readback mismatch"))?;
                    }
                    journal.state = transaction::State::ProfileApplied;
                    self.save(&journal)?;
                }
                transaction::State::ProfileApplied => {
                    #[cfg(test)]
                    ensure!(!self.fake.lock().unwrap().pause_before_nat,"TIMEOUT: fixture pause after profile acknowledgement");
                    ensure!(now() < journal.deadline_ms.unwrap_or(0)
                        && self.checkpoints(deadline)?.iter().any(|path| Some(path) == journal.checkpoint_path.as_ref()),
                        "OUTCOME_UNKNOWN: NM checkpoint expired before automatic NAT; adjudicate original operation");
                    self.ensure_firewall_binding(&journal)?;
                    let input = self.input(&journal)?;
                    self.ensure_nat_baseline(&journal, deadline)?;
                    self.require_forwarding(input.nat.as_ref())?;
                    let before: Option<NatSet> = serde_json::from_value(journal.nat_before.as_ref()
                        .context("CONFLICT: NAT baseline missing")?["nat"].clone())?;
                    let applies = !settlement::nat_equal(before.as_ref(), input.nat.as_ref());
                    let text = if !applies {String::new()} else {match &input.nat {
                        Some(nat) => render_nat(&nat.wan, &nat.lan),
                        None => format!("destroy table inet {NAT_TABLE}\n"),
                    }};
                    let payload = json!({"schemaVersion":1,
                        "operationId":journal.operation_id.hyphenated().to_string(),
                        "action":FIREWALL_ACTION,"table":NAT_TABLE,"applies":applies,
                        "text":text,"textSha256":crate::durable::hash(text.as_bytes()),
                        "nat":input.nat});
                    self.publish_action_intent(&mut journal, FIREWALL_ACTION, &payload)?;
                    journal.state = transaction::State::FirewallIntent;
                    self.save(&journal)?;
                }
                transaction::State::FirewallIntent => {
                    let payload = self.verify_action_intent(&journal, FIREWALL_ACTION)?;
                    let applies = payload["applies"]
                        .as_bool()
                        .context("CONFLICT: NM firewall intent")?;
                    let text = payload["text"]
                        .as_str()
                        .context("CONFLICT: NM firewall intent text")?;
                    ensure!(
                        crate::durable::hash(text.as_bytes())
                            == payload["textSha256"]
                                .as_str()
                                .context("CONFLICT: NM firewall intent digest")?,
                        "CONFLICT: NM firewall intent digest"
                    );
                    let nat: Option<NatSet> = serde_json::from_value(payload["nat"].clone())
                        .map_err(|_| anyhow::anyhow!("CONFLICT: NM firewall intent NAT"))?;
                    self.ensure_firewall_binding(&journal)?;
                    self.ensure_nat_baseline(&journal, deadline)?;
                    self.bound_owner(&mut journal, deadline)?;
                    self.require_forwarding(nat.as_ref())?;
                    if applies {
                        self.apply_text(text, deadline).map_err(|_| anyhow::anyhow!(
                            "OUTCOME_UNKNOWN: automatic NAT response unconfirmed"))?;
                    }
                    self.verify_nat(nat.as_ref()).map_err(|_| anyhow::anyhow!(
                        "OUTCOME_UNKNOWN: automatic NAT readback unconfirmed"))?;
                    self.bound_owner(&mut journal, deadline)?;
                    journal.state = transaction::State::WaitConfirm;
                    self.save(&journal)?;
                }
                transaction::State::WaitConfirm => break,
                _ => anyhow::bail!("CONFLICT: NM transaction state"),
            }
        }
        Ok(json!({"operationId":journal.operation_id.hyphenated().to_string(),
            "state":serde_json::to_value(&journal.state)?,
            "deadlineUnixMs":journal.deadline_ms}))
    }
}

// ---------------------------------------------------------------------------
// Decision and recovery
// ---------------------------------------------------------------------------
impl Coordinator {
    pub(super) fn confirm(&self, value: Value) -> Result<Value> {
        self.write(|this| this.confirm_inner(value))
    }
    fn confirm_inner(&self, value: Value) -> Result<Value> {
        let input: TokenInput = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: NM confirmation"))?;
        self.confirm_with(&input.token)
    }
    fn confirm_with(&self, token: &str) -> Result<Value> {
        let mut journal = self.journal()?.context("CONFLICT: no NM transaction")?;
        ensure!(journal.state == transaction::State::WaitConfirm, "CONFLICT: NM transaction state");
        ensure!(now() < journal.deadline_ms.unwrap_or(0), "CONFLICT: NM confirmation window expired");
        ensure!(journal.token.as_deref() == Some(token), "FORBIDDEN: token");
        self.confirm_settle(&mut journal, Instant::now() + Duration::from_secs(20))
    }
    pub(super) fn rollback(&self, value: Value) -> Result<Value> {
        self.write(|this| this.rollback_inner(value))
    }
    fn rollback_inner(&self, value: Value) -> Result<Value> {
        let input: TokenInput = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: NM rollback"))?;
        self.rollback_with(&input.token)
    }
    fn rollback_with(&self, token: &str) -> Result<Value> {
        let mut journal = self.journal()?.context("CONFLICT: no NM transaction")?;
        ensure!(
            !journal.state.terminal() && journal.state != transaction::State::RecoveryRequired,
            "CONFLICT: NM transaction state"
        );
        ensure!(
            !journal.confirmed_decision,
            "CONFLICT: confirmation already decided"
        );
        ensure!(journal.token.as_deref() == Some(token), "FORBIDDEN: token");
        self.rollback_running(&mut journal)?;
        Ok(json!({"operationId":journal.operation_id.hyphenated().to_string(),
            "state":serde_json::to_value(&journal.state)?}))
    }
    /// Restore original profile fields and the captured owned NAT baseline.
    /// Fresh readback must prove both before a terminal receipt is written.
    fn rollback_running(&self, journal: &mut transaction::Journal) -> Result<()> {
        self.rollback_settle(journal, Instant::now() + Duration::from_secs(20))
    }
    /// Adjudicate original intents; never replay an unknown forward write.
    pub(super) fn recover(&self) -> Result<Value> {
        self.write(|this| this.recover_settle())
    }
    pub(super) fn status(&self) -> Result<Value> {
        let journal = self.journal()?;
        let admission = match transaction::admission(&self.root) {
            Ok(true) => "settled",
            Ok(false) => "unresolved",
            Err(_) => "invalid",
        };
        Ok(json!({
            "schemaVersion":1,"backend":"NetworkManager","writeEnabled":true,
            "admission":admission,
            "transaction": journal.as_ref().map(|j| json!({
                "operationId":j.operation_id.hyphenated().to_string(),
                "state":serde_json::to_value(&j.state).unwrap_or(json!(null)),
                "deadlineUnixMs":j.deadline_ms,
                "confirmedDecision":j.confirmed_decision,
                "sourceDigest":j.source_digest,"candidateDigest":j.candidate_digest,
            })),
        }))
    }
}


// ---------------------------------------------------------------------------
// Remote authority. Separate from a Kura UID/session owner; only the transport
// constructs connection witnesses, and confirmations require a new affected
// management connection established after the transaction was applied.
// ---------------------------------------------------------------------------
fn remote_hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn command_hash(command: &ReadCommand) -> String {
    remote_hash(&command.encode_to_vec())
}
fn connection_time(session: &str) -> Result<u64> {
    let mut parts = session.splitn(3, ':');
    let at = parts
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0);
    let nonce = parts
        .next()
        .and_then(|v| uuid::Uuid::parse_str(v).ok());
    ensure!(
        at.is_some() && nonce.is_some(),
        "FORBIDDEN: authenticated connection required"
    );
    Ok(at.unwrap())
}
pub(super) fn valid_authority(authority: &str) -> bool {
    authority.len() == 64
        && authority
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Coordinator {
    fn remote_path(&self, identity: &str) -> PathBuf {
        self.root
            .join("nm/remote-history")
            .join(format!("{}.json", remote_hash(identity.as_bytes())))
    }
    fn archive_remote(&self, journal: &transaction::Journal) -> Result<()> {
        let Some(binding) = &journal.remote_binding else {
            return Ok(());
        };
        ensure!(
            journal.state.terminal(),
            "CONFLICT: remote NM transaction active"
        );
        for identity in [&binding.command_id, &journal.operation_id.hyphenated().to_string()] {
            let path = self.remote_path(identity);
            if path.try_exists()? {
                let saved = crate::durable::read(&path, LIMIT)?.0;
                ensure!(
                    saved == serde_json::to_vec(journal)?,
                    "CONFLICT: remote history differs"
                );
            } else {
                crate::durable::publish_new(
                    &path,
                    &serde_json::to_vec(journal)?,
                    crate::durable::FileMetadata::private(),
                )?;
            }
        }
        Ok(())
    }
    fn remote_original(&self, identity: &str) -> Result<Option<(transaction::Journal, Vec<u8>)>> {
        for path in [self.journal_path(), self.remote_path(identity)] {
            if !path.try_exists()? {
                continue;
            }
            let bytes = crate::durable::read(&path, LIMIT)?.0;
            let journal: transaction::Journal = serde_json::from_slice(&bytes)?;
            if journal.operation_id.hyphenated().to_string() == identity
                || journal
                    .remote_binding
                    .as_ref()
                    .is_some_and(|b| b.command_id == identity)
            {
                return Ok(Some((journal, bytes)));
            }
        }
        Ok(None)
    }
    fn remote_projection(
        &self,
        journal: &transaction::Journal,
        token: bool,
    ) -> Result<Value> {
        let mut value = json!({
            "id":journal.operation_id.hyphenated().to_string(),
            "operationId":journal.operation_id.hyphenated().to_string(),
            "state":serde_json::to_value(&journal.state)?,
            "deadlineUnixMs":journal.deadline_ms,
            "requestId":journal.remote_binding.as_ref().map(|b|b.command_id.clone()),
            "newManagementConnectionRequired":true,
            "newManagementConnectionVerified":journal.state == transaction::State::Committed
                && journal.remote_actions.iter().any(|a| a.operation == Operation::NmConfirm as i32 && a.new_connection_proved),
        });
        if token {
            value["confirmationToken"] = json!(journal.token);
            value["candidateDigest"] = json!(journal.candidate_digest);
        }
        Ok(value)
    }
    fn observe<T>(&self, action: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        let _guard = Guard::observe_shared(&self.root, Duration::from_secs(2))?;
        action(self)
    }
    /// Read-only remote view: fresh source digest for a subsequent proposal
    /// plus the transaction and confirmation readiness projection.
    fn remote_view(&self, authority: &str, connection: &str) -> Result<Value> {
        ensure!(valid_authority(authority), "FORBIDDEN: remote authority required");
        self.observe(|this| {
            let deadline = Instant::now() + Duration::from_secs(10);
            let (source, _) = this.capture_source(deadline)?;
            let journal = this.journal()?;
            let view_authority = authority.to_string();
            let view_connection = connection.to_string();
            let ready = journal.as_ref().is_some_and(|j| {
                j.state == transaction::State::WaitConfirm
                    && j.remote_binding.as_ref().is_some_and(|b| {
                        b.authority == view_authority
                            && b.applied_at_ms > 0
                            && b.connection != view_connection
                            && connection_time(&view_connection)
                                .is_ok_and(|at| at > b.applied_at_ms)
                    })
            });
            Ok(json!({
                "schemaVersion":1,"backend":"NetworkManager","writeEnabled":true,
                "sourceDigest":source["sourceDigest"],
                "candidateDigest":journal.as_ref().map(|j|j.candidate_digest.clone()),
                "confirmationReady":ready,
                "transaction":journal.as_ref().map(|j| json!({
                    "id":j.operation_id.hyphenated().to_string(),
                    "state":serde_json::to_value(&j.state).unwrap_or(json!(null)),
                    "deadlineUnixMs":j.deadline_ms,
                })),
            }))
        })
    }
    pub(super) fn remote_request(
        &self,
        command: &ReadCommand,
        authority: &str,
        connection: &str,
        grant: bool,
    ) -> Result<Value> {
        ensure!(grant, "UNSUPPORTED: remote NM writes disabled");
        ensure!(
            valid_authority(authority),
            "FORBIDDEN: remote authority required"
        );
        ensure!(
            command.valid_payload() && uuid::Uuid::parse_str(&command.command_id).is_ok(),
            "INVALID_ARGUMENT: NM command"
        );
        if command.operation == Operation::NmView as i32 {
            return self.remote_view(authority, connection);
        }
        let connected_at = connection_time(connection)?;
        let command = command.clone();
        let authority = authority.to_owned();
        let connection = connection.to_owned();
        self.write(move |this| {
            let mut entered = false;
            let result = (|| -> Result<Value> {
                match Operation::try_from(command.operation)? {
                    Operation::NmPrepare => {
                        ensure!(
                            this.remote_original(&command.command_id)?.is_none(),
                            "OUTCOME_UNKNOWN: query original NM command"
                        );
                        let change = command.nm_change.as_ref().unwrap();
                        let change = yofc_management_protocol::nm::Change::from_wire(change)
                            .context("INVALID_ARGUMENT: NM proposal")?;
                        let input = change.coordinator_input();
                        let prepared = this.prepare_inner(input)?;
                        let mut journal = this.journal()?.context("CONFLICT: NM journal")?;
                        journal.remote_binding = Some(transaction::RemoteBinding {
                            authority: authority.clone(),
                            command_id: command.command_id.clone(),
                            command_hash: command_hash(&command),
                            connection: connection.clone(),
                            applied_at_ms: 0,
                        });
                        this.save(&journal)?; // bind before applying
                        entered = true;
                        this.apply_inner()?;
                        let mut journal = this.journal()?.context("CONFLICT: NM journal")?;
                        journal.remote_binding.as_mut().unwrap().applied_at_ms = now();
                        this.save(&journal)?;
                        let mut projection = this.remote_projection(&journal, true)?;
                        projection["operationId"] = prepared["operationId"].clone();
                        Ok(projection)
                    }
                    Operation::NmConfirm | Operation::NmRollback => {
                        let confirm = command.operation == Operation::NmConfirm as i32;
                        let action = command.nm_action.as_ref().unwrap();
                        let journal = this.journal()?.context("CONFLICT: no NM transaction")?;
                        let binding = journal
                            .remote_binding
                            .as_ref()
                            .context("FORBIDDEN: not a remote NM transaction")?;
                        ensure!(
                            binding.authority == authority
                                && journal.operation_id.hyphenated().to_string() == action.operation_id
                                && journal.token.as_deref() == Some(action.confirmation_token.as_str()),
                            "FORBIDDEN: NM authority or action token"
                        );
                        ensure!(
                            !journal.state.terminal()
                                && !journal.remote_actions.iter().any(|a| {
                                    a.command_id == command.command_id
                                        && a.operation == command.operation
                                }),
                            "CONFLICT: NM action already issued"
                        );
                        if confirm {
                            ensure!(
                                journal.state == transaction::State::WaitConfirm
                                    && now() < journal.deadline_ms.unwrap_or(0),
                                "CONFLICT: NM state or deadline"
                            );
                            ensure!(
                                binding.applied_at_ms > 0
                                    && connected_at > binding.applied_at_ms
                                    && connection != binding.connection,
                                "FORBIDDEN: new authenticated management connection required"
                            );
                        }
                        let mut journal = this.journal()?.context("CONFLICT: NM journal")?;
                        journal.remote_actions.push(transaction::RemoteAction {
                            command_id: command.command_id.clone(),
                            command_hash: command_hash(&command),
                            operation: command.operation,
                            new_connection_proved: confirm,
                        });
                        this.save(&journal)?; // action identity before any side effect
                        entered = true;
                        if confirm {
                            this.confirm_with(&action.confirmation_token)?;
                        } else {
                            this.rollback_with(&action.confirmation_token)?;
                        }
                        let journal = this.journal()?.context("CONFLICT: NM journal")?;
                        this.archive_remote(&journal)?;
                        this.remote_projection(&journal, false)
                    }
                    _ => anyhow::bail!("UNSUPPORTED: remote NM operation"),
                }
            })();
            if entered && result.is_err() {
                anyhow::bail!(
                    "OUTCOME_UNKNOWN: NM action interrupted; query original command"
                )
            }
            result
        })
    }
    /// Reads durable domain evidence only: no NM, nft, repair, expiry or
    /// dispatch. Lost results are adjudicated by the original command identity.
    pub(super) fn prove_remote(
        &self,
        command: &ReadCommand,
        authority: &str,
    ) -> Result<Option<TaskResult>> {
        let command = command.clone();
        let authority = authority.to_owned();
        self.observe(move |this| {
            if !matches!(command.operation, 34..=37)
                || !command.valid_payload()
                || !valid_authority(&authority)
            {
                return Ok(None);
            }
            let identity = command
                .nm_action
                .as_ref()
                .map(|v| v.operation_id.as_str())
                .unwrap_or(&command.command_id);
            let Some((journal, bytes)) = this.remote_original(identity)? else {
                return Ok(None);
            };
            let Some(binding) = &journal.remote_binding else {
                return Ok(None);
            };
            if binding.authority != authority {
                return Ok(None);
            }
            let committed = journal.state == transaction::State::Committed && journal.confirmed_decision;
            let rolled_back = journal.state == transaction::State::RolledBack && !journal.confirmed_decision;
            // A Cancelled prepare means the apply never went out; the original
            // command resolves to a definite failure so the operator can retry.
            let cancelled_prepare = journal.state == transaction::State::Cancelled;
            let prepared = journal.state == transaction::State::WaitConfirm
                && binding.applied_at_ms > 0
                && now() < journal.deadline_ms.unwrap_or(0);
            let prepare = command.operation == 35;
            let matched = if prepare {
                binding.command_id == command.command_id
                    && binding.command_hash == command_hash(&command)
                    && (prepared || committed || rolled_back || cancelled_prepare)
            } else {
                journal.remote_actions.iter().any(|a| {
                    a.command_id == command.command_id
                        && a.command_hash == command_hash(&command)
                        && a.operation == command.operation
                        && ((command.operation == 36 && (committed || rolled_back) && a.new_connection_proved)
                            || (command.operation == 37 && rolled_back))
                })
            };
            if !matched {
                return Ok(None);
            }
            let succeeded = match command.operation {
                35 => !rolled_back && !cancelled_prepare,
                36 => committed,
                37 => rolled_back,
                _ => false,
            };
            let mut value = this.remote_projection(&journal, prepare && succeeded)?;
            value["reconciliation"] = json!({"source":"nm.coordinator.journal.v1",
                "commandId":command.command_id,
                "operationId":journal.operation_id.hyphenated().to_string(),
                "operation":command.operation,
                "requestSha256":command_hash(&command),
                "journalSha256":remote_hash(&bytes),
                "observedAtUnixMs":now()});
            Ok(Some(TaskResult {
                command_id: command.command_id.clone(),
                state: if succeeded { TaskState::Succeeded } else { TaskState::Failed } as i32,
                error: if succeeded { ErrorCode::Unspecified } else { ErrorCode::Conflict } as i32,
                result_json: serde_json::to_vec(&value)?,
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;

    struct FakeWire {
        calls: Mutex<Vec<(String, String, String, String)>>,
        checkpoint_arguments: Mutex<Vec<Vec<Value>>>,
        script: Mutex<VecDeque<Value>>,
        updated: Mutex<Vec<Value>>,
        version: Mutex<u64>,
        checkpoints: Mutex<Vec<String>>,
        checkpoint_devices: Mutex<BTreeMap<String, Vec<String>>>,
        checkpoint_created: Mutex<BTreeMap<String, i64>>,
        bus_id: Mutex<String>,
        owner: Mutex<String>,
        applied: Mutex<Option<Value>>,
        applied_version: Mutex<u64>,
        fail_update2: Mutex<bool>,
        noop_update2: Mutex<bool>,
        lose_update2_reply: Mutex<bool>,
        fail_reapply: Mutex<bool>,
        fail_rollback: Mutex<bool>,
        lose_rollback_reply: Mutex<bool>,
    }
    impl FakeWire {
        fn foreign_checkpoint(&self, id: u32, devices: &[u32], created: i64) -> String {
            let path = format!("{ROOT}/Checkpoint/{id}");
            self.checkpoint_devices.lock().unwrap().insert(
                path.clone(), devices.iter().map(|id| format!("{ROOT}/Devices/{id}")).collect(),
            );
            self.checkpoint_created.lock().unwrap().insert(path.clone(), created);
            self.checkpoints.lock().unwrap().push(path.clone());
            path
        }
        fn forget_owned_checkpoint(&self, rollback: bool) {
            let path = format!("{ROOT}/Checkpoint/9");
            self.checkpoints.lock().unwrap().retain(|p| p != &path);
            self.checkpoint_devices.lock().unwrap().remove(&path);
            self.checkpoint_created.lock().unwrap().remove(&path);
            if rollback {
                self.updated.lock().unwrap().clear();
                *self.applied.lock().unwrap() = None;
            }
        }
        fn observation(&self, devices: &[(&str, u32, u32)]) {
            let profile_version = *self.version.lock().unwrap();
            let applied_version = *self.applied_version.lock().unwrap();
            let mut script = self.script.lock().unwrap();
            script.push_back(reply("v", json!([value("s", json!("1.46.0"))])));
            for _ in 0..2 {
                for (name, device_id, profile_id) in devices {
                    script.push_back(reply("o", json!([format!("{ROOT}/Devices/{device_id}")])));
                    script.push_back(reply(
                        "a{sv}",
                        json!([{
                            "Interface":value("s",json!(name)),
                            "Managed":value("b",json!(true)),
                            "DeviceType":value("u",json!(1)),
                            "State":value("u",json!(100)),
                            "ActiveConnection":value("o",json!(format!("{ROOT}/ActiveConnection/{device_id}"))),
                        }]),
                    ));
                    script.push_back(reply("a{sa{sv}}t", json!([settings(), applied_version])));
                    script.push_back(reply(
                        "v",
                        json!([value("o", json!(format!("{ROOT}/Settings/{profile_id}")))]),
                    ));
                    script.push_back(reply(
                        "a{sv}",
                        json!([{"Flags":value("u",json!(0)),"Unsaved":value("b",json!(false)),"VersionId":value("t",json!(profile_version))}]),
                    ));
                }
            }
        }
    }
    impl Wire for FakeWire {
        fn server_guid(&self, _: Instant) -> Result<Option<String>> {
            Ok(Some("c".repeat(32)))
        }
        fn call(&self, call: &BusCall, _: Instant) -> Result<Value> {
            self.calls.lock().unwrap().push((
                call.destination.clone(),
                call.path.clone(),
                call.interface.clone(),
                call.method.clone(),
            ));
              if matches!(call.method.as_str(), "CheckpointCreate" | "Update2" | "Reapply" | "CheckpointRollback" | "CheckpointDestroy") {
                  ensure!(call.expected_server_guid.as_deref() == Some("c".repeat(32).as_str()), "CONFLICT: missing server authentication binding");
                  ensure!(call.destination == *self.owner.lock().unwrap(), "CONFLICT: stale NM unique destination");
              }
            match call.method.as_str() {
                "GetId" => Ok(reply("s", json!([self.bus_id.lock().unwrap().clone()]))),
                "GetNameOwner" => Ok(reply("s", json!([self.owner.lock().unwrap().clone()]))),
                "Get" => {
                    let key = call.arguments[1]["data"].as_str().unwrap_or("");
                    match key {
                        "VersionId" => {
                            let v = *self.version.lock().unwrap();
                            Ok(reply("v", json!([value("t", json!(v))])))
                        }
                        "Checkpoints" => {
                            let cps = self.checkpoints.lock().unwrap().clone();
                            Ok(reply("v", json!([value("ao", json!(cps))])))
                        }
                        _ => self
                            .script
                            .lock()
                            .unwrap()
                            .pop_front()
                            .context("UNSUPPORTED: NM source unavailable"),
                    }
                }
                "GetAll" if call.path.starts_with(&format!("{ROOT}/Checkpoint/")) => {
                    ensure!(self.checkpoints.lock().unwrap().contains(&call.path), "CONFLICT: checkpoint absent");
                    let devices = self.checkpoint_devices.lock().unwrap().get(&call.path).cloned().context("CONFLICT: checkpoint devices absent")?;
                    let created = *self.checkpoint_created.lock().unwrap().get(&call.path).context("CONFLICT: checkpoint timestamp absent")?;
                    Ok(reply("a{sv}", json!([{
                        "Devices":value("ao", json!(devices)),
                        "Created":value("x", json!(created)),
                        "RollbackTimeout":value("u", json!(60)),
                    }])))
                }
                "GetAll" | "GetDeviceByIpIface" | "GetAppliedConnection" => {
                    let mut frame = self.script.lock().unwrap().pop_front().context("UNSUPPORTED: NM source unavailable")?;
                    if call.method == "GetAppliedConnection" {
                        if let Some(applied) = self.applied.lock().unwrap().clone() {
                            frame = reply("a{sa{sv}}t", json!([applied, *self.applied_version.lock().unwrap()]));
                        }
                    } else if call.method == "GetAll" && !frame["data"][0]["VersionId"].is_null() {
                        frame["data"][0]["VersionId"] = value("t", json!(*self.version.lock().unwrap()));
                    }
                    Ok(frame)
                }
                "GetSettings" => {
                    // Computed, never queued: before any Update2 NM reports the
                    // source settings, afterwards the applied candidate.
                    let updated = self.updated.lock().unwrap();
                    if updated.is_empty() {
                        Ok(reply("a{sa{sv}}", json!([settings()])))
                    } else {
                        Ok(reply(
                            "a{sa{sv}}",
                            json!([updated.last().cloned().unwrap()]),
                        ))
                    }
                }
                "Update2" => {
                    if *self.fail_update2.lock().unwrap() {
                        anyhow::bail!("INTERNAL: injected update failure");
                    }
                    if *self.noop_update2.lock().unwrap() {
                        return Ok(reply("a{sv}", json!([{}])));
                    }
                    self.updated
                        .lock()
                        .unwrap()
                        .push(call.arguments[0]["data"].clone());
                    *self.version.lock().unwrap() += 1;
                    if *self.lose_update2_reply.lock().unwrap() {
                        anyhow::bail!("TIMEOUT: injected reply loss after update");
                    }
                    Ok(reply("a{sv}", json!([{}])))
                }
                "Reapply" => {
                    if *self.fail_reapply.lock().unwrap() {
                        anyhow::bail!("TIMEOUT: injected reapply reply loss");
                    }
                    *self.applied.lock().unwrap() = Some(call.arguments[0]["data"].clone());
                    *self.applied_version.lock().unwrap() += 1;
                    Ok(reply("a{sv}", json!([{}])))
                }
                "CheckpointCreate" => {
                    self.checkpoint_arguments.lock().unwrap().push(call.arguments.clone());
                    let path = format!("{ROOT}/Checkpoint/9");
                    let devices: Vec<String> = serde_json::from_value(call.arguments[0]["data"].clone())?;
                    self.checkpoint_devices.lock().unwrap().insert(path.clone(), devices);
                    self.checkpoint_created.lock().unwrap().insert(path.clone(), 1000);
                    self.checkpoints.lock().unwrap().push(path.clone());
                    Ok(reply("o", json!([path])))
                }
                "CheckpointRollback" | "CheckpointDestroy" => {
                    ensure!(call.path == ROOT && call.interface == MANAGER && call.arguments.len() == 1 && call.arguments[0]["type"] == "o", "CONFLICT: checkpoint manager call grammar");
                    let path = call.arguments[0]["data"].as_str().context("CONFLICT: checkpoint argument")?;
                    ensure!(self.checkpoints.lock().unwrap().contains(&path.to_string()), "CONFLICT: checkpoint absent");
                    if call.method == "CheckpointRollback" {
                        ensure!(!*self.fail_rollback.lock().unwrap(), "TIMEOUT: injected ambiguous rollback failure");
                        let scopes = self.checkpoint_devices.lock().unwrap().clone();
                        let times = self.checkpoint_created.lock().unwrap().clone();
                        let own = scopes.get(path).context("CONFLICT: checkpoint scope")?;
                        let created = *times.get(path).context("CONFLICT: checkpoint creation")?;
                        self.checkpoints.lock().unwrap().retain(|p| p != path && !(times.get(p).is_some_and(|t| *t > created) && scopes.get(p).is_some_and(|scope| scope.iter().any(|d| own.contains(d)))));
                        self.updated.lock().unwrap().clear();
                        *self.applied.lock().unwrap() = None;
                        ensure!(!*self.lose_rollback_reply.lock().unwrap(), "TIMEOUT: injected rollback reply loss");
                        Ok(reply("a{su}", json!([{}])))
                    } else {
                        self.checkpoints.lock().unwrap().retain(|p| p != path);
                        Ok(Value::Null)
                    }
                }
                _ => anyhow::bail!("UNSUPPORTED: unexpected NM call {}", call.method),
            }
        }
    }
    fn reply(signature: &str, data: Value) -> Value {
        json!({"type":signature,"data":data})
    }
    fn value(signature: &str, data: Value) -> Value {
        json!({"type":signature,"data":data})
    }
    fn settings() -> Value {
        json!({"connection":{"uuid":value("s",json!("12345678-1234-4123-8123-123456789abc")),
            "type":value("s",json!("802-3-ethernet")),
            "id":value("s",json!("private-profile-label"))},"ipv4":{"method":value("s",json!("auto"))}})
    }
    struct Fixture {
        root: std::path::PathBuf,
        engine: Arc<Coordinator>,
        wire: Arc<FakeWire>,
        digest: Option<String>,
        devices: Vec<(&'static str, u32, u32)>,
    }
    impl Fixture {
        fn new(interfaces: &[&str], devices: &[(&'static str, u32, u32)]) -> Self {
            let root = std::env::temp_dir().join(format!("nm-writer-{}", uuid::Uuid::new_v4()));
            crate::durable::directory(&root).unwrap();
            let wire = Arc::new(FakeWire {
                calls: Mutex::new(Vec::new()),
                checkpoint_arguments: Mutex::new(Vec::new()),
                script: Mutex::new(VecDeque::new()),
                updated: Mutex::new(Vec::new()),
                version: Mutex::new(7),
                checkpoints: Mutex::new(Vec::new()),
                checkpoint_devices: Mutex::new(BTreeMap::new()),
                checkpoint_created: Mutex::new(BTreeMap::new()),
                bus_id: Mutex::new("a".repeat(32)),
                owner: Mutex::new(":1.7".into()),
                applied: Mutex::new(None),
                applied_version: Mutex::new(1),
                fail_update2: Mutex::new(false),
                noop_update2: Mutex::new(false),
                lose_update2_reply: Mutex::new(false),
                fail_reapply: Mutex::new(false),
                fail_rollback: Mutex::new(false),
                lose_rollback_reply: Mutex::new(false),
            });
            let nm = Nm::for_test(
                json!({"schemaVersion":1,"interfaces":interfaces,"writeEnabled":true}),
                wire.clone(),
                &root,
            )
            .unwrap();
            Self {
                engine: nm.engine.clone().unwrap(),
                wire,
                root,
                digest: None,
                devices: devices.to_vec(),
            }
        }
        fn observe(&self) {
            self.wire.observation(&self.devices);
        }
        fn source_digest(&mut self) -> String {
            if let Some(digest) = &self.digest {
                return digest.clone();
            }
            self.observe();
            let (view, _) = self.engine.capture_source(Instant::now() + Duration::from_secs(5)).unwrap();
            let digest = view["sourceDigest"].as_str().unwrap().to_string();
            self.digest = Some(digest.clone());
            digest
        }
        fn prepare(&mut self, nat: Option<Value>) -> Result<Value> {
            let digest = self.source_digest();
            self.observe();
            let input = json!({
                "sourceDigest":digest,
                "confirmSeconds":60,
                "changes":[{"interface":"eth0","ipv4":{"method":"manual",
                    "addresses":[{"address":"192.0.2.10","prefix":24}],
                    "gateway":"192.0.2.1","dns":["192.0.2.53"],
                    "ignoreAutoDns":true,"ignoreAutoRoutes":false,"wanPriority":30}}],
                "nat":nat,
            });
            self.engine.prepare(input)
        }
        fn apply(&mut self) -> Result<Value> {
            // Fresh source checks run before checkpoint creation and again
            // before publishing the profile-write intent.
            self.observe();
            self.observe();
            self.engine.apply()
        }
        fn prepare_noop(&mut self) {
            let digest = self.source_digest();
            self.observe();
            self.engine.prepare(json!({
                "sourceDigest":digest,"confirmSeconds":60,"nat":null,
                "changes":[{"interface":"eth0","ipv4":{"method":"auto",
                    "addresses":[],"gateway":null,"dns":[],
                    "ignoreAutoDns":false,"ignoreAutoRoutes":false,"wanPriority":-1}}],
            })).unwrap();
        }
        fn call_count(&self, method: &str) -> usize {
            self.wire.calls.lock().unwrap().iter().filter(|call| call.3 == method).count()
        }
        fn journal_state(&self) -> String {
            let bytes = crate::durable::read(&self.root.join("nm/transaction.json"), 1 << 20)
                .unwrap()
                .0;
            serde_json::from_slice::<Value>(&bytes).unwrap()["state"]
                .as_str()
                .unwrap()
                .to_string()
        }
        fn journal(&self) -> transaction::Journal {
            let bytes = crate::durable::read(&self.root.join("nm/transaction.json"), 1 << 20)
                .unwrap()
                .0;
            serde_json::from_slice(&bytes).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn forwarding_contract_disabled_nat_rejected_before_intent_or_checkpoint() {
        let mut f=Fixture::new(&["eth0","eth1"], &[("eth0",4,3),("eth1",5,4)]);
        f.engine.fake.lock().unwrap().forwarding_blocked=true;
        let result=f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]})));
        assert!(result.is_err_and(|e|e.to_string().starts_with("FORBIDDEN")),"NAT cannot become a durable candidate without system forwarding");
        assert!(!f.root.join("nm/transaction.json").exists());
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn forwarding_contract_change_invalidates_source_and_blocks_prepared_apply() {
        let mut f=Fixture::new(&["eth0","eth1"], &[("eth0",4,3),("eth1",5,4)]);
        f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]}))).unwrap();
        f.engine.fake.lock().unwrap().forwarding_blocked=true;
        assert!(f.apply().is_err(),"forwarding changed after prepare must not create a checkpoint");
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn forwarding_contract_disabled_no_nat_remains_supported() {
        let mut f=Fixture::new(&["eth0"], &[("eth0",4,3)]);
        f.engine.fake.lock().unwrap().forwarding_blocked=true;
        f.prepare(None).unwrap();f.apply().unwrap();
        assert_eq!(f.journal_state(),"WAIT_CONFIRM");assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn forwarding_contract_drop_before_confirm_keeps_original_checkpoint() {
        let mut f=Fixture::new(&["eth0","eth1"], &[("eth0",4,3),("eth1",5,4)]);
        let plan=f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]}))).unwrap();f.apply().unwrap();
        f.engine.fake.lock().unwrap().forwarding_blocked=true;f.observe();f.observe();
        assert!(f.engine.confirm(json!({"token":plan["token"]})).is_err(),"disabled forwarding cannot be confirmed as working NAT");
        assert_eq!(f.call_count("CheckpointDestroy"),0);
    }
    #[test]
    fn forwarding_contract_is_part_of_the_joint_source_lease() {
        let mut f=Fixture::new(&["eth0"], &[("eth0",4,3)]);let original=f.source_digest();
        f.engine.fake.lock().unwrap().forwarding_blocked=true;f.observe();
        let (current,_)=f.engine.capture_source(Instant::now()+Duration::from_secs(5)).unwrap();
        assert_ne!(original,current["sourceDigest"]);
    }

    #[tokio::test]
    async fn readonly_remote_contract_disabled_writer_preserves_original_pending_status() {
        let mut f=Fixture::new(&["eth0"], &[("eth0",4,3)]);let prepared=f.prepare(None).unwrap();
        let observer=Nm::for_test(json!({"schemaVersion":1,"interfaces":["eth0"],"writeEnabled":false}),f.wire.clone(),&f.root).unwrap();
        let command=ReadCommand{command_id:uuid::Uuid::new_v4().to_string(),operation:34,..Default::default()};
        let before=std::fs::read(f.engine.journal_path()).unwrap();f.observe();
        let view=observer.remote_request(&command,&"a".repeat(64),"observer-session",true).await.unwrap();
        assert_eq!(view["transaction"]["id"],prepared["operationId"]);assert_eq!(view["transaction"]["state"],"PREPARED");
        assert!(view["transaction"]["deadlineUnixMs"].is_null());assert_eq!(view["confirmationReady"],false);
        assert!(!view.to_string().contains(prepared["token"].as_str().unwrap()));
        assert_eq!(std::fs::read(f.engine.journal_path()).unwrap(),before);
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        let journal=f.journal();std::fs::write(f.engine.intent_path(journal.operation_id,None),b"changed").unwrap();f.observe();
        assert!(observer.remote_request(&command,&"a".repeat(64),"observer-session",true).await.is_err());
        assert_eq!(std::fs::read(f.engine.journal_path()).unwrap(),before);
    }
    #[test]
    #[cfg(target_os="linux")]
    fn forwarding_contract_native_read_matches_kernel_without_mutation() {
        let f=Fixture::new(&["eth0"], &[("eth0",4,3)]);
        let before=std::fs::read("/proc/sys/net/ipv4/ip_forward").unwrap();
        f.engine.real.store(true,std::sync::atomic::Ordering::Relaxed);
        assert_eq!(f.engine.ipv4_forwarding().unwrap(),std::str::from_utf8(&before).unwrap().trim()=="1");
        assert_eq!(std::fs::read("/proc/sys/net/ipv4/ip_forward").unwrap(),before);
        assert_eq!(f.call_count("CheckpointCreate"),0);
    }

    fn confirmed_nat_fixture() -> Fixture {
        confirmed_nat_fixture_for(json!({"wan":"eth0","lan":["eth1"]}))
    }
    fn confirmed_nat_fixture_for(nat: Value) -> Fixture {
        let mut f = Fixture::new(&["eth0", "eth1"], &[("eth0",4,3),("eth1",5,4)]);
        let digest = f.source_digest();f.observe();
        let view = f.engine.prepare(json!({"sourceDigest":digest,"confirmSeconds":60,
            "changes":[{"interface":"eth0","ethernet":{"mtu":0,"acceptAllMacAddresses":-1}}],
            "nat":nat})).unwrap();
        f.apply().unwrap();
        f.observe();f.observe();
        assert_eq!(f.engine.confirm(json!({"token":view["token"]})).unwrap()["state"],"COMMITTED");
        f
    }

    #[test]
    fn nat_ownership_contract_unknown_existing_table_cannot_be_adopted_by_proposal() {
        let mut f = Fixture::new(&["eth0", "eth1"], &[("eth0",4,3),("eth1",5,4)]);
        let table = fake_table(&render_nat("eth0", &["eth1".into()]));
        f.engine.fake.lock().unwrap().table = Some(table.clone());
        let result = f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]})));
        assert!(result.is_err(), "same names and comments do not prove an owned NAT baseline");
        assert_eq!(f.engine.fake.lock().unwrap().table.as_ref(),Some(&table));
        assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        assert_eq!(f.call_count("CheckpointCreate"),0);
    }

    #[test]
    fn nat_ownership_contract_disabling_confirmed_nat_is_an_explicit_joint_change() {
        let mut f = confirmed_nat_fixture();
        f.engine.archive().unwrap();
        f.digest = None;
        let view = f.prepare(None).unwrap();
        assert_eq!(f.apply().unwrap()["state"],"WAIT_CONFIRM");
        assert!(f.engine.fake.lock().unwrap().table.is_none());
        f.observe();f.observe();
        assert_eq!(f.engine.confirm(json!({"token":view["token"]})).unwrap()["state"],"COMMITTED");
        assert!(f.engine.fake.lock().unwrap().table.is_none());
    }

    #[tokio::test]
    async fn nat_ownership_contract_manual_firewall_accepts_proven_automatic_nat_only() {
        let f = confirmed_nat_fixture();
        let original = f.engine.fake.lock().unwrap().table.clone().unwrap();
        let firewall = crate::firewall::Firewall::open(f.root.clone(),None).unwrap().enable_writes(true);
        firewall.test_ruleset(original.clone());
        let view = firewall.prepare(json!({"policy":"accept","rules":[]}),60,"manual-after-owned-nat".into()).await.unwrap();
        assert_eq!(view["state"],"PREPARED");
        assert_eq!(f.engine.fake.lock().unwrap().table.as_ref(),Some(&original));
        assert_eq!(f.engine.fake.lock().unwrap().writes,1);
        firewall.rollback(view["token"].as_str().unwrap()).await.unwrap();
        assert_eq!(firewall.status().await.unwrap()["detectedWriters"],json!([]));
        let mut foreign = original.clone();
        foreign["nftables"].as_array_mut().unwrap().push(json!({"table":{"family":"inet","name":"foreign"}}));
        firewall.test_ruleset(foreign);
        assert!(firewall.prepare(json!({"policy":"accept","rules":[]}),60,"manual-with-foreign".into()).await.is_err());
        assert_eq!(f.engine.fake.lock().unwrap().table.as_ref(),Some(&original));
    }

    #[test]
    fn nat_ownership_contract_receipt_publication_before_journal_can_be_adjudicated() {
        let f = confirmed_nat_fixture();
        let mut journal = f.journal();
        journal.state = transaction::State::ConfirmDecided;
        journal.terminal_receipt_sha256 = None;
        f.engine.save(&journal).unwrap();
        let writes = f.engine.fake.lock().unwrap().writes;
        let destroys = f.call_count("CheckpointDestroy");
        f.observe();
        assert_eq!(f.engine.recover().unwrap()["state"],"COMMITTED");
        assert_eq!(f.engine.fake.lock().unwrap().writes,writes);
        assert_eq!(f.call_count("CheckpointDestroy"),destroys);
        assert!(transaction::admission(&f.root).unwrap());
    }

    #[test]
    fn nat_ownership_contract_omitted_nat_preserves_the_confirmed_policy() {
        let mut f = confirmed_nat_fixture();
        let original = f.engine.fake.lock().unwrap().table.clone();
        f.engine.archive().unwrap();f.digest = None;
        let digest = f.source_digest();f.observe();
        let view = f.engine.prepare(json!({"sourceDigest":digest,"confirmSeconds":60,
            "changes":[{"interface":"eth0","ethernet":{"mtu":0,"acceptAllMacAddresses":-1}}]})).unwrap();
        assert_eq!(f.apply().unwrap()["state"],"WAIT_CONFIRM");
        assert_eq!(f.engine.fake.lock().unwrap().table,original);
        assert_eq!(f.engine.fake.lock().unwrap().writes,1);
        assert_eq!(f.journal().input.unwrap()["nat"],json!({"wan":"eth0","lan":["eth1"]}));
        f.observe();
        assert_eq!(f.engine.rollback(json!({"token":view["token"]})).unwrap()["state"],"ROLLED_BACK");
        assert_eq!(f.engine.fake.lock().unwrap().table,original);
        assert_eq!(f.engine.fake.lock().unwrap().writes,1);
    }

    #[test]
    fn nat_ownership_contract_target_drift_is_blocked_by_shared_admission() {
        let mut f = Fixture::new(&["eth0","eth1"],&[("eth0",4,3),("eth1",5,4)]);
        f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]}))).unwrap();
        let mut journal = f.journal();journal.input.as_mut().unwrap()["nat"] = Value::Null;
        f.engine.save(&journal).unwrap();
        assert!(transaction::admission(&f.root).is_err());
        assert!(f.apply().is_err());
        assert_eq!(f.call_count("CheckpointCreate"),0);
        assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }

    #[tokio::test]
    async fn nat_ownership_contract_pending_nm_reserves_the_manual_firewall_writer() {
        let mut f = Fixture::new(&["eth0","eth1"],&[("eth0",4,3),("eth1",5,4)]);
        f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]}))).unwrap();
        let firewall = crate::firewall::Firewall::open(f.root.clone(),None).unwrap().enable_writes(true);
        let error = firewall.prepare(json!({"policy":"accept","rules":[]}),60,"blocked-by-joint-nm".into()).await.unwrap_err();
        assert!(error.to_string().contains("unresolved joint NM"),"{error}");
        assert!(firewall.status().await.unwrap()["transaction"].is_null());
        assert_eq!(f.call_count("CheckpointCreate"),0);
        assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }

    #[test]
    fn nat_ownership_contract_kernel_drift_is_refused_before_checkpoint() {
        let mut f = Fixture::new(&["eth0","eth1"],&[("eth0",4,3),("eth1",5,4)]);
        f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]}))).unwrap();
        let foreign = fake_table(&render_nat("eth0",&["eth1".into()]));
        f.engine.fake.lock().unwrap().table = Some(foreign.clone());
        assert!(f.apply().is_err());
        assert_eq!(f.call_count("CheckpointCreate"),0);
        assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        assert_eq!(f.engine.fake.lock().unwrap().table.as_ref(),Some(&foreign));
    }

    #[tokio::test]
    async fn nat_ownership_contract_changed_proof_or_rule_never_bypasses_foreign_writer_gate() {
        for variant in ["record","receipt","kernel"] {
            let f = confirmed_nat_fixture();
            let mut snapshot = f.engine.fake.lock().unwrap().table.clone().unwrap();
            if variant == "kernel" {
                snapshot["nftables"][2]["chain"]["hook"] = json!("prerouting");
            } else if variant == "record" {
                let path = f.root.join("nm/nat-confirmed.json");
                let mut value: Value = serde_json::from_slice(&crate::durable::read(&path,LIMIT).unwrap().0).unwrap();
                value["receiptSha256"] = json!("f".repeat(64));crate::durable::json(&path,&value).unwrap();
            } else {
                let path = f.engine.receipt_path(f.journal().operation_id);
                std::fs::rename(&path,path.with_extension("kept")).unwrap();
            }
            let firewall = crate::firewall::Firewall::open(f.root.clone(),None).unwrap().enable_writes(true);
            firewall.test_ruleset(snapshot);
            assert!(firewall.prepare(json!({"policy":"accept","rules":[]}),60,"changed-proof".into()).await.is_err(),"{variant}");
            assert_eq!(f.engine.fake.lock().unwrap().writes,1);
            assert_eq!(f.journal().state,transaction::State::Committed);
        }
    }

    #[test]
    fn nat_ownership_contract_receipt_before_pointer_can_be_adjudicated_without_dispatch() {
        let f = confirmed_nat_fixture();
        let path = f.root.join("nm/nat-confirmed.json");
        std::fs::rename(&path,path.with_extension("kept")).unwrap();
        let mut journal = f.journal();journal.state = transaction::State::ConfirmDecided;
        journal.terminal_receipt_sha256 = None;f.engine.save(&journal).unwrap();
        let destroys = f.call_count("CheckpointDestroy");f.observe();
        assert_eq!(f.engine.recover().unwrap()["state"],"COMMITTED");
        assert_eq!(f.call_count("CheckpointDestroy"),destroys);
        assert_eq!(f.engine.fake.lock().unwrap().writes,1);
        assert!(path.is_file());
    }

    #[test]
    fn nat_ownership_contract_conflicting_terminal_receipt_is_retained_without_resend() {
        let mut f = Fixture::new(&["eth0","eth1"],&[("eth0",4,3),("eth1",5,4)]);
        let view = f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]}))).unwrap();
        f.apply().unwrap();let receipt = f.engine.receipt_path(f.journal().operation_id);
        crate::durable::publish_new(&receipt,b"conflicting-receipt",crate::durable::FileMetadata::private()).unwrap();
        f.observe();f.observe();
        assert!(f.engine.confirm(json!({"token":view["token"]})).unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
        let destroys = f.call_count("CheckpointDestroy");f.observe();
        assert!(f.engine.recover().unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
        assert_eq!(f.call_count("CheckpointDestroy"),destroys);
        assert_eq!(f.engine.fake.lock().unwrap().writes,1);
        assert_eq!(crate::durable::read(&receipt,LIMIT).unwrap().0,b"conflicting-receipt");
        assert!(!f.root.join("nm/nat-confirmed.json").exists());
    }

    #[test]
    fn nat_ownership_contract_owner_proof_drift_blocks_confirm_and_compensation() {
        let mut f = confirmed_nat_fixture();
        f.engine.archive().unwrap();f.digest = None;
        let digest = f.source_digest();f.observe();
        let view = f.engine.prepare(json!({"sourceDigest":digest,"confirmSeconds":60,
            "changes":[{"interface":"eth0","ethernet":{"mtu":0,"acceptAllMacAddresses":-1}}]})).unwrap();
        f.apply().unwrap();
        let path = f.root.join("nm/nat-confirmed.json");
        let mut owner:Value = serde_json::from_slice(&crate::durable::read(&path,LIMIT).unwrap().0).unwrap();
        owner["receiptSha256"] = json!("f".repeat(64));crate::durable::json(&path,&owner).unwrap();
        let destroys = f.call_count("CheckpointDestroy");
        assert!(f.engine.confirm(json!({"token":view["token"]})).is_err());
        assert!(f.engine.rollback(json!({"token":view["token"]})).is_err());
        assert_eq!(f.call_count("CheckpointDestroy"),destroys);
        assert_eq!(f.call_count("CheckpointRollback"),0);
        assert_eq!(f.engine.fake.lock().unwrap().writes,1);
    }

    #[test]
    fn nat_ownership_contract_source_lease_includes_automatic_nat_policy() {
        let mut f = confirmed_nat_fixture();
        f.engine.archive().unwrap();f.digest = None;
        let old = f.source_digest();f.observe();
        let change = json!([{"interface":"eth0","ethernet":{"mtu":0,"acceptAllMacAddresses":-1}}]);
        let view = f.engine.prepare(json!({"sourceDigest":old,"confirmSeconds":60,
            "changes":change,"nat":{"wan":"eth1","lan":["eth0"]}})).unwrap();
        f.apply().unwrap();f.observe();f.observe();
        f.engine.confirm(json!({"token":view["token"]})).unwrap();f.engine.archive().unwrap();
        let writes = f.engine.fake.lock().unwrap().writes;
        f.observe();
        let result = f.engine.prepare(json!({"sourceDigest":old,"confirmSeconds":60,
            "changes":change,"nat":{"wan":"eth0","lan":["eth1"]}}));
        assert!(result.is_err(),"a NAT-only policy change must invalidate an earlier source lease");
        assert_eq!(f.engine.fake.lock().unwrap().writes,writes);
    }

    #[test]
    fn nat_ownership_contract_writer_inspection_exposes_the_same_joint_source_lease() {
        let f = Fixture::new(&["eth0","eth1"],&[("eth0",4,3),("eth1",5,4)]);
        let mut reader = f.engine.source.clone();reader.engine = Some(f.engine.clone());
        f.observe();let view = reader.snapshot(Instant::now()+Duration::from_secs(5)).unwrap();
        f.observe();let direct = f.engine.capture_source(Instant::now()+Duration::from_secs(5)).unwrap().0;
        assert_eq!(view["sourceDigest"],direct["sourceDigest"]);
        f.observe();let plain = f.engine.source.capture(Instant::now()+Duration::from_secs(5)).unwrap().0;
        assert_ne!(view["sourceDigest"],plain["sourceDigest"]);
        assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }

    #[test]
    fn nat_ownership_contract_joint_capture_is_bounded_and_rejects_nat_read_drift() {
        let f = Fixture::new(&["eth0","eth1"],&[("eth0",4,3),("eth1",5,4)]);
        assert!(f.engine.capture_source(Instant::now()-Duration::from_millis(1)).err().unwrap().to_string().starts_with("TIMEOUT"));
        let first = fake_table(&render_nat("eth0",&["eth1".into()]));
        let second = fake_table(&render_nat("eth1",&["eth0".into()]));
        f.engine.fake.lock().unwrap().readbacks.extend([first,second]);f.observe();
        let error = f.engine.capture_source(Instant::now()+Duration::from_secs(5)).err().unwrap();
        assert!(error.to_string().contains("joint NM/NAT/firewall source changed"),"{error}");
        assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }

    #[test]
    fn nat_ownership_contract_source_lease_includes_the_manual_firewall_revision() {
        let mut f = Fixture::new(&["eth0","eth1"],&[("eth0",4,3),("eth1",5,4)]);
        let old = f.source_digest();crate::durable::directory(&f.root.join("firewall")).unwrap();
        crate::durable::json(&f.root.join("firewall/confirmed.json"),&json!({"revision":1,"text":null})).unwrap();
        f.observe();
        assert!(f.engine.prepare(json!({"sourceDigest":old,"confirmSeconds":60,
            "changes":[{"interface":"eth0","ethernet":{"mtu":1500,"acceptAllMacAddresses":-1}}]})).is_err());
        assert_eq!(f.call_count("CheckpointCreate"),0);
        assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }

    #[test]
    fn nat_ownership_contract_expired_profile_ack_cannot_start_a_late_nat_write() {
        let mut f = Fixture::new(&["eth0","eth1"],&[("eth0",4,3),("eth1",5,4)]);
        f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]}))).unwrap();
        f.engine.fake.lock().unwrap().pause_before_nat = true;
        assert!(f.apply().is_err());assert_eq!(f.journal().state,transaction::State::ProfileApplied);
        let mut journal = f.journal();journal.deadline_ms=Some(now()-1000);f.engine.save(&journal).unwrap();
        f.wire.forget_owned_checkpoint(true);f.engine.fake.lock().unwrap().pause_before_nat = false;
        assert!(f.apply().is_err(),"acknowledged profiles do not authorize NAT after checkpoint expiry");
        assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        assert!(f.engine.fake.lock().unwrap().table.is_none());
    }

    #[test]
    fn prepare_persists_identity_and_refuses_any_existing_transaction() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let view = f.prepare(None).unwrap();
        assert_eq!(view["state"], "PREPARED");
        assert!(view["token"].as_str().is_some());
        assert_eq!(view["candidateDigest"].as_str().unwrap().len(), 64);
        let bytes = crate::durable::read(&f.root.join("nm/transaction.json"), 1 << 20).unwrap().0;
        let journal: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(journal["state"], "PREPARED");
        assert_eq!(journal["schemaVersion"], 1);
        let operation = journal["operationId"].as_str().unwrap();
        let intent = crate::durable::read(
            &f.root.join(format!("nm/intents/{operation}.json")),
            1 << 20,
        )
        .unwrap();
        assert_eq!(crate::durable::hash(&intent.0), journal["intentSha256"]);
        assert_eq!(f.journal_state(), "PREPARED");
        let error = f.prepare(None).unwrap_err();
        assert!(error.to_string().starts_with("OUTCOME_UNKNOWN"), "{error}");
    }

    #[test]
    fn apply_uses_checkpoint_version_id_cas_reapply_and_composes_nat() {
        let mut f = Fixture::new(&["eth0", "eth1"], &[("eth0", 4, 3), ("eth1", 5, 4)]);
        f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]}))).unwrap();
        let view = f.apply().unwrap();
        assert_eq!(view["state"], "WAIT_CONFIRM");
        assert_eq!(f.journal_state(), "WAIT_CONFIRM");
        let journal = f.journal();
        assert!(journal.deadline_ms.is_some());
        assert!(journal.checkpoint_path.as_deref().unwrap().ends_with("/Checkpoint/9"));
        assert_eq!(journal.action_intents.len(), 3);
        for action in ["checkpoint", "profile", "firewall"] {
            assert!(journal.action_intents.iter().any(|a| a.action == action));
        }
        // CAS: Update2 carried the observed version-id, never zero.
        let update2 = f
            .wire
            .calls
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.3 == "Update2")
            .cloned()
            .unwrap();
        assert_eq!(update2.2, "org.freedesktop.NetworkManager.Settings.Connection");
        assert!(f.wire.calls.lock().unwrap().iter().any(|c| c.3 == "Reapply"));
        // NAT table applied with the masquerade pair and kernel readback.
        let fake = f.engine.fake.lock().unwrap();
        let table = fake.table.clone().unwrap();
        let rules: Vec<&Value> = table["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| !e["rule"].is_null())
            .collect();
        assert_eq!(rules.len(), 1);
        assert!(table.to_string().contains("\"yofc nm auto\""));
        drop(fake);
    }

    #[test]
    fn checkpoint_scope_includes_only_changed_interfaces() {
        let mut f = Fixture::new(&["eth0", "eth1"], &[("eth0", 4, 3), ("eth1", 5, 4)]);
        f.prepare(None).unwrap();
        f.apply().unwrap();
        let arguments = f.wire.checkpoint_arguments.lock().unwrap();
        assert_eq!(arguments.len(), 1);
        assert_eq!(arguments[0][0], json!({"type":"ao","data":[format!("{ROOT}/Devices/4")]}));
        assert_eq!(arguments[0][1], json!({"type":"u","data":60}));
        assert_eq!(arguments[0][2], json!({"type":"u","data":0}));
    }

    #[test]
    fn checkpoint_scope_source_drift_is_refused_before_create() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        // The same interface now resolves to a different device object.
        f.wire.observation(&[("eth0", 6, 3)]);
        let error = f.engine.apply().unwrap_err();
        assert!(error.to_string().starts_with("CONFLICT"), "{error}");
        assert!(f.wire.checkpoint_arguments.lock().unwrap().is_empty());
        assert_eq!(f.journal_state(), "PREPARED");
    }

    #[test]
    fn checkpoint_scope_empty_legacy_intent_is_refused_before_create() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        let mut journal = f.journal();
        let payload = json!({"schemaVersion":1,
            "operationId":journal.operation_id.hyphenated().to_string(),
            "action":CHECKPOINT_ACTION,"timeoutSeconds":60,"devices":[]});
        f.engine.publish_action_intent(&mut journal, CHECKPOINT_ACTION, &payload).unwrap();
        journal.state = transaction::State::CheckpointIntent;
        f.engine.save(&journal).unwrap();
        let error = f.engine.apply().unwrap_err();
        assert!(f.wire.checkpoint_arguments.lock().unwrap().is_empty());
        assert!(error.to_string().starts_with("OUTCOME_UNKNOWN"), "{error}");
        assert_eq!(f.journal_state(), "CHECKPOINT_INTENT");
    }

    #[test]
    fn dispatch_contract_opaque_update_failure_is_not_reissued() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        *f.wire.fail_update2.lock().unwrap() = true;
        let error = f.apply().unwrap_err();
        assert_eq!(f.call_count("Update2"), 1);
        assert_eq!(f.call_count("Reapply"), 0);
        assert!(error.to_string().starts_with("OUTCOME_UNKNOWN"), "{error}");
        assert_eq!(f.journal_state(), "PROFILE_INTENT");
        assert!(!transaction::admission(&f.root).unwrap());
    }

    #[test]
    fn dispatch_contract_lost_update_reply_is_not_definitive_failure() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        *f.wire.lose_update2_reply.lock().unwrap() = true;
        let error = f.apply().unwrap_err();
        assert_eq!(f.wire.updated.lock().unwrap().len(), 1);
        assert_eq!(f.call_count("Update2"), 1);
        assert_eq!(f.call_count("Reapply"), 0);
        assert!(error.to_string().starts_with("OUTCOME_UNKNOWN"), "{error}");
        assert_eq!(f.journal_state(), "PROFILE_INTENT");
    }

    #[test]
    fn dispatch_contract_lost_reapply_reply_never_reissues_noop_update() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare_noop();
        *f.wire.noop_update2.lock().unwrap() = true;
        *f.wire.fail_reapply.lock().unwrap() = true;
        let error = f.apply().unwrap_err();
        assert_eq!(f.call_count("Update2"), 1);
        assert_eq!(f.call_count("Reapply"), 1);
        assert!(error.to_string().starts_with("OUTCOME_UNKNOWN"), "{error}");
        assert_eq!(f.journal_state(), "PROFILE_INTENT");
    }

    #[test]
    fn dispatch_contract_acknowledged_noop_does_not_need_version_increment() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare_noop();
        *f.wire.noop_update2.lock().unwrap() = true;
        let result = f.apply();
        assert_eq!(f.call_count("Update2"), 1);
        assert_eq!(f.call_count("Reapply"), 1);
        assert_eq!(*f.wire.version.lock().unwrap(), 7);
        assert_eq!(result.unwrap()["state"], "WAIT_CONFIRM");
    }

    #[test]
    fn dispatch_noop_confirm_contract_does_not_need_version_increment() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare_noop();
        *f.wire.noop_update2.lock().unwrap() = true;
        f.apply().unwrap();
        let token = f.journal().token.unwrap();
        f.observe();
        f.observe();
        let result = f.engine.confirm(json!({"token":token}));
        assert_eq!(f.call_count("Update2"), 1);
        assert_eq!(f.call_count("Reapply"), 1);
        assert_eq!(*f.wire.version.lock().unwrap(), 7);
        assert_eq!(result.unwrap()["state"], "COMMITTED");
        assert_eq!(f.journal_state(), "COMMITTED");
    }

    #[test]
    fn dispatch_noop_confirm_contract_rejects_regression_and_changed_content() {
        for version_regressed in [true, false] {
            let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
            f.prepare_noop();
            *f.wire.noop_update2.lock().unwrap() = true;
            f.apply().unwrap();
            if version_regressed {
                *f.wire.version.lock().unwrap() = 6;
            } else {
                let mut changed = settings();
                changed["ipv4"]["method"] = value("s", json!("manual"));
                f.wire.updated.lock().unwrap().push(changed);
            }
            let token = f.journal().token.unwrap();
            f.observe();
            let error = f.engine.confirm(json!({"token":token})).unwrap_err();
            assert!(error.to_string().starts_with("CONFLICT"), "{error}");
            assert_eq!(f.journal_state(), "WAIT_CONFIRM");
            assert_eq!(f.call_count("CheckpointDestroy"), 0);
            assert_eq!(f.call_count("Update2"), 1);
            assert_eq!(f.call_count("Reapply"), 1);
        }
    }

    #[test]
    fn dispatch_contract_retained_profile_intent_cannot_restart_forward_writes() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        *f.wire.fail_update2.lock().unwrap() = true;
        f.apply().unwrap_err();
        let count = f.call_count("Update2");
        let intent = std::fs::read(f.engine.intent_path(f.journal().operation_id, Some(PROFILE_ACTION))).unwrap();
        *f.wire.fail_update2.lock().unwrap() = false;
        let result = f.engine.apply();
        assert_eq!(f.call_count("Update2"), count);
        assert_eq!(f.call_count("Reapply"), 0);
        assert!(result.unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
        assert_eq!(f.journal_state(), "PROFILE_INTENT");
        assert_eq!(std::fs::read(f.engine.intent_path(f.journal().operation_id, Some(PROFILE_ACTION))).unwrap(), intent);
    }

    #[test]
    fn checkpoint_recovery_contract_reapply_carries_candidate_not_source() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        f.apply().unwrap();
        assert_eq!(f.wire.applied.lock().unwrap().as_ref().unwrap()["ipv4"]["method"]["data"], "manual");
        let intent = f.engine.verify_action_intent(&f.journal(),PROFILE_ACTION).unwrap();
        assert_eq!(intent["profiles"][0]["sourceApplied"]["ipv4"]["method"]["data"], "auto");
        assert_eq!(intent["profiles"][0]["applied"]["ipv4"]["method"]["data"], "manual");
    }

    #[test]
    fn checkpoint_recovery_contract_does_not_delete_nat_it_never_changed() {
        let mut f = confirmed_nat_fixture_for(json!({"wan":"eth1","lan":["eth0"]}));
        let original = f.engine.fake.lock().unwrap().table.clone().unwrap();
        f.engine.archive().unwrap();f.digest = None;
        f.prepare(Some(json!({"wan":"eth1","lan":["eth0"]}))).unwrap();
        *f.wire.fail_update2.lock().unwrap() = true;
        f.apply().unwrap_err();
        f.observe();
        assert_eq!(f.engine.recover().unwrap()["state"], "ROLLED_BACK");
        let fake = f.engine.fake.lock().unwrap();
        assert_eq!(fake.table.as_ref(), Some(&original));
        assert_eq!(fake.writes, 1);
    }

    #[test]
    fn checkpoint_recovery_contract_expiry_restores_prior_nat_not_just_absence() {
        let mut f = confirmed_nat_fixture_for(json!({"wan":"eth1","lan":["eth0"]}));
        let original = f.engine.fake.lock().unwrap().table.clone().unwrap();
        f.engine.archive().unwrap();f.digest = None;
        f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]}))).unwrap();
        f.apply().unwrap();
        let mut journal = f.journal();journal.deadline_ms = Some(now()-1000);f.engine.save(&journal).unwrap();
        f.wire.forget_owned_checkpoint(true);
        f.observe();
        assert_eq!(f.engine.recover().unwrap()["state"], "ROLLED_BACK");
        let fake = f.engine.fake.lock().unwrap();
        assert_eq!(fake.table.as_ref(), Some(&original));
        assert_eq!(fake.writes, 3);
    }

    #[test]
    fn checkpoint_recovery_contract_ambiguous_rollback_is_not_reissued() {
        let mut f = Fixture::new(&["eth0"], &[("eth0",4,3)]);
        f.prepare(None).unwrap();
        *f.wire.fail_update2.lock().unwrap() = true;
        f.apply().unwrap_err();
        *f.wire.fail_rollback.lock().unwrap() = true;
        assert!(f.engine.recover().unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
        *f.wire.fail_rollback.lock().unwrap() = false;
        assert!(f.engine.recover().unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
        assert_eq!(f.call_count("CheckpointRollback"),1);
        f.wire.forget_owned_checkpoint(true);
        f.observe();
        assert_eq!(f.engine.recover().unwrap()["state"], "ROLLED_BACK");
        assert_eq!(f.call_count("CheckpointRollback"),1);
    }

    #[test]
    fn checkpoint_recovery_contract_lost_nat_restore_reply_is_read_back_without_resend() {
        let mut f = confirmed_nat_fixture_for(json!({"wan":"eth1","lan":["eth0"]}));
        let original = f.engine.fake.lock().unwrap().table.clone().unwrap();
        f.engine.archive().unwrap();f.digest = None;
        f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]}))).unwrap();
        f.apply().unwrap();
        let mut journal = f.journal();journal.deadline_ms = Some(now()-1000);f.engine.save(&journal).unwrap();
        f.wire.forget_owned_checkpoint(true);
        f.engine.fake.lock().unwrap().lose_reply = true;
        f.observe();
        assert!(f.engine.recover().unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
        f.engine.fake.lock().unwrap().lose_reply = false;
        f.observe();
        assert_eq!(f.engine.recover().unwrap()["state"], "ROLLED_BACK");
        let fake = f.engine.fake.lock().unwrap();assert_eq!(fake.writes,3);assert_eq!(fake.table.as_ref(),Some(&original));
    }

    #[test]
    fn checkpoint_recovery_contract_nat_rejects_disabled_or_foreign_lifetime_table() {
        let f = Fixture::new(&["eth0", "eth1"], &[("eth0",4,3),("eth1",5,4)]);
        let expected = NatSet {wan:"eth0".into(),lan:vec!["eth1".into()]};
        for flags in [json!("dormant"),json!(["dormant"]),json!("owner"),json!(["owner","persist"])] {
            let mut table = fake_table(&render_nat(&expected.wan,&expected.lan));
            table["nftables"][1]["table"]["flags"] = flags.clone();
            f.engine.fake.lock().unwrap().table = Some(table);
            assert!(f.engine.verify_nat(Some(&expected)).is_err(), "flags {flags} accepted");
        }
    }

    fn mark_confirm_decided(f: &Fixture) {
        let mut journal = f.journal();
        journal.confirmed_decision = true;
        journal.state = transaction::State::ConfirmDecided;
        f.engine.save(&journal).unwrap();
    }

    #[test]
    fn checkpoint_recovery_contract_unknown_create_does_not_claim_foreign_checkpoint() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        let mut journal = f.journal();
        let payload = json!({"schemaVersion":1,"operationId":journal.operation_id.to_string(),
            "action":CHECKPOINT_ACTION,"timeoutSeconds":60,"devices":[format!("{ROOT}/Devices/4")]});
        f.engine.publish_action_intent(&mut journal, CHECKPOINT_ACTION, &payload).unwrap();
        journal.state = transaction::State::CheckpointIntent;
        f.engine.save(&journal).unwrap();
        let foreign = f.wire.foreign_checkpoint(40, &[4], 2000);
        let result = f.engine.recover();
        assert_eq!(f.call_count("CheckpointRollback"), 0);
        assert_eq!(f.call_count("CheckpointDestroy"), 0);
        assert!(f.wire.checkpoints.lock().unwrap().contains(&foreign));
        assert_eq!(result.unwrap()["state"], "RECOVERY_REQUIRED");
    }

    #[test]
    fn checkpoint_recovery_contract_service_restart_cannot_reuse_an_owned_path() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        *f.wire.fail_update2.lock().unwrap() = true;
        f.apply().unwrap_err();
        *f.wire.owner.lock().unwrap() = ":1.9".into();
        let result = f.engine.recover();
        assert_eq!(f.call_count("CheckpointRollback"), 0);
        assert_eq!(f.call_count("CheckpointDestroy"), 0);
        assert_eq!(result.unwrap()["state"], "RECOVERY_REQUIRED");
    }

    #[test]
    fn checkpoint_recovery_contract_newer_overlapping_foreign_checkpoint_is_not_destroyed() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        *f.wire.fail_update2.lock().unwrap() = true;
        f.apply().unwrap_err();
        let foreign = f.wire.foreign_checkpoint(40, &[4], 2000);
        let result = f.engine.recover();
        assert!(f.wire.checkpoints.lock().unwrap().contains(&foreign));
        assert_eq!(f.call_count("CheckpointRollback"), 0);
        assert_eq!(result.unwrap()["state"], "RECOVERY_REQUIRED");
    }

    #[test]
    fn checkpoint_recovery_contract_legacy_identity_absence_cannot_compensate() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        *f.wire.fail_update2.lock().unwrap() = true;
        f.apply().unwrap_err();
        let mut journal = serde_json::to_value(f.journal()).unwrap();
        let path = f.engine.intent_path(f.journal().operation_id, None);
        let mut intent: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        intent.as_object_mut().unwrap().remove("nmIdentity");
        let bytes = serde_json::to_vec(&intent).unwrap();
        std::fs::write(path, &bytes).unwrap();
        journal.as_object_mut().unwrap().remove("nmIdentity");
        journal["intentSha256"] = json!(crate::durable::hash(&bytes));
        crate::durable::json(&f.engine.journal_path(), &journal).unwrap();
        let result = f.engine.recover();
        assert_eq!(f.call_count("CheckpointRollback"), 0);
        assert_eq!(result.unwrap()["state"], "RECOVERY_REQUIRED");
    }

    #[test]
    fn checkpoint_recovery_contract_owned_rollback_preserves_unrelated_foreign_checkpoint() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        *f.wire.fail_update2.lock().unwrap() = true;
        f.apply().unwrap_err();
        let foreign = f.wire.foreign_checkpoint(40, &[5], 2000);
        f.observe();
        let view = f.engine.recover().unwrap();
        assert_eq!(view["state"], "ROLLED_BACK");
        assert!(f.wire.checkpoints.lock().unwrap().contains(&foreign));
        assert_eq!(f.call_count("CheckpointRollback"), 1);
        assert!(transaction::admission(&f.root).unwrap());
    }

    #[test]
    fn checkpoint_recovery_contract_expired_after_confirm_decision_is_not_committed() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        f.apply().unwrap();
        mark_confirm_decided(&f);
        f.wire.forget_owned_checkpoint(true);
        f.observe();
        let view = f.engine.recover().unwrap();
        assert_eq!(view["state"], "RECOVERY_REQUIRED");
        assert!(!transaction::admission(&f.root).unwrap());
    }

    #[test]
    fn checkpoint_recovery_contract_lost_destroy_ack_can_commit_matching_live_candidate() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        f.apply().unwrap();
        mark_confirm_decided(&f);
        f.wire.forget_owned_checkpoint(false);
        f.observe();
        let view = f.engine.recover().unwrap();
        assert_eq!(view["state"], "COMMITTED");
        assert_eq!(f.call_count("Update2"), 1);
        assert_eq!(f.call_count("Reapply"), 1);
        assert_eq!(f.call_count("CheckpointDestroy"), 0);
    }

    #[test]
    fn checkpoint_recovery_contract_stored_only_match_cannot_commit_wrong_applied_state() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        f.apply().unwrap();
        mark_confirm_decided(&f);
        f.wire.forget_owned_checkpoint(false);
        *f.wire.applied.lock().unwrap() = Some(settings());
        f.observe();
        assert_eq!(f.engine.recover().unwrap()["state"], "RECOVERY_REQUIRED");
    }

    #[test]
    fn checkpoint_recovery_contract_changed_profile_object_cannot_be_committed() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        f.apply().unwrap();
        mark_confirm_decided(&f);
        f.wire.forget_owned_checkpoint(false);
        f.wire.observation(&[("eth0", 4, 99)]);
        assert_eq!(f.engine.recover().unwrap()["state"], "RECOVERY_REQUIRED");
    }

    #[test]
    fn checkpoint_recovery_contract_confirm_checks_applied_before_destroy() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let prepared = f.prepare(None).unwrap();
        f.apply().unwrap();
        *f.wire.applied.lock().unwrap() = Some(settings());
        f.observe();
        let result = f.engine.confirm(json!({"token":prepared["token"]}));
        assert_eq!(f.call_count("CheckpointDestroy"), 0);
        assert!(result.is_err());
        assert_eq!(f.journal_state(), "WAIT_CONFIRM");
    }

    #[test]
    fn checkpoint_recovery_contract_nat_semantic_readback_is_required() {
        let mut f = Fixture::new(&["eth0", "eth1"], &[("eth0", 4, 3), ("eth1", 5, 4)]);
        f.prepare(Some(json!({"wan":"eth0","lan":["eth1"]}))).unwrap();
        f.apply().unwrap();
        mark_confirm_decided(&f);
        f.wire.forget_owned_checkpoint(false);
        f.engine.fake.lock().unwrap().table.as_mut().unwrap()["nftables"][2]["chain"]["hook"] = json!("prerouting");
        f.observe();
        assert_eq!(f.engine.recover().unwrap()["state"], "RECOVERY_REQUIRED");
    }

    #[test]
    fn checkpoint_recovery_contract_nat_rejects_semantically_different_rules() {
        let f = Fixture::new(&["eth0", "eth1"], &[("eth0", 4, 3), ("eth1", 5, 4)]);
        let expected = NatSet {wan:"eth0".into(),lan:vec!["eth1".into()]};
        let valid = fake_table(&render_nat(&expected.wan, &expected.lan));
        for variant in 0..6 {
            let mut bad = valid.clone();
            match variant {
                0 => bad["nftables"][2]["chain"]["hook"] = json!("prerouting"),
                1 => bad["nftables"][2]["chain"]["type"] = json!("filter"),
                2 => bad["nftables"][2]["chain"]["prio"] = json!(0),
                3 => bad["nftables"][3]["rule"]["expr"][2] = json!({"accept":null}),
                4 => bad["nftables"][3]["rule"]["expr"][0]["match"]["op"] = json!("!="),
                _ => {let duplicate = bad["nftables"][3].clone();bad["nftables"].as_array_mut().unwrap().push(duplicate);},
            }
            f.engine.fake.lock().unwrap().table = Some(bad);
            assert!(f.engine.verify_nat(Some(&expected)).is_err(), "variant {variant} accepted");
        }
        f.engine.fake.lock().unwrap().table = Some(valid);
        f.engine.verify_nat(Some(&expected)).unwrap();
    }

    #[test]
    fn update2_version_id_argument_binds_the_observed_profile_version() {
        // Direct grammar check: the third Update2 argument repeats version-id
        // with the explicit variant type, and never zero.
        let args = vec![
            json!({"type":"a{sa{sv}}","data":{"ipv4":{"method":{"type":"s","data":"manual"}}}}),
            json!({"type":"u","data":0}),
            json!({"type":"a{sv}","data":{"version-id":{"type":"t","data":7}}}),
        ];
        let mut tokens = Vec::new();
        for argument in &args {
            let kind = argument["type"].as_str().unwrap();
            tokens.extend(dbus_tokens(kind, &argument["data"]).unwrap());
        }
        let signature: String = args.iter().map(|a| a["type"].as_str().unwrap()).collect();
        assert_eq!(signature, "a{sa{sv}}ua{sv}");
        let joined = tokens.join(" ");
        assert!(joined.contains("version-id t 7"), "{joined}");
        assert!(!joined.contains('"'), "{joined}");
    }

    #[test]
    fn confirm_destroys_checkpoint_writes_receipt_and_admission_settles() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let view = f.prepare(None).unwrap();
        f.apply().unwrap();
        let token = view["token"].as_str().unwrap().to_string();
        f.observe();
        let error = f.engine.confirm(json!({"token":"wrong"})).unwrap_err();
        assert!(error.to_string().starts_with("FORBIDDEN"), "{error}");
        f.observe();
        let confirmed = f.engine.confirm(json!({"token":token})).unwrap();
        assert_eq!(confirmed["state"], "COMMITTED");
        assert_eq!(f.journal_state(), "COMMITTED");
        let journal = f.journal();
        assert!(journal.confirmed_decision);
        assert!(journal.terminal_receipt_sha256.is_some());
        let operation = journal.operation_id.hyphenated().to_string();
        let receipt = crate::durable::read(
            &f.root.join(format!("nm/receipts/{operation}.json")),
            1 << 20,
        )
        .unwrap();
        assert_eq!(crate::durable::hash(&receipt.0), journal.terminal_receipt_sha256.unwrap());
        assert!(transaction::admission(&f.root).unwrap());
        assert!(f.wire.checkpoints.lock().unwrap().is_empty());
    }

    #[test]
    fn rollback_restores_the_recorded_source_and_clears_nat() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let view = f.prepare(Some(json!({"wan":"eth0","lan":["eth0"]}))).unwrap_err();
        assert!(view.to_string().starts_with("INVALID_ARGUMENT"), "{view}");
        let view = f.prepare(None).unwrap();
        f.apply().unwrap();
        let token = view["token"].as_str().unwrap().to_string();
        f.observe();
        f.engine.rollback(json!({"token":token})).unwrap();
        assert_eq!(f.journal_state(), "ROLLED_BACK");
        assert!(transaction::admission(&f.root).unwrap());
        let fake = f.engine.fake.lock().unwrap();
        assert!(fake.table.is_none());
    }

    #[test]
    fn expiry_marks_rolled_back_when_nm_matches_source_or_recovery_when_not() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        f.apply().unwrap();
        // NM rolled the checkpoint back at the deadline: no checkpoint alive,
        // profiles back at the source.
        f.wire.forget_owned_checkpoint(true);
        let mut journal = f.journal();
        journal.deadline_ms = Some(now().saturating_sub(1000));
        crate::durable::json(&f.root.join("nm/transaction.json"), &journal).unwrap();
        f.observe();
        let view = f.engine.recover().unwrap();
        assert_eq!(view["action"], "expired-rollback");
        assert_eq!(f.journal_state(), "ROLLED_BACK");
        assert!(transaction::admission(&f.root).unwrap());

        // A contradicting source observation must fail closed instead.
        let mut g = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        g.prepare(None).unwrap();
        g.apply().unwrap();
        g.wire.checkpoints.lock().unwrap().clear();
        // The candidate settings remain applied: NM did NOT roll back, which
        // contradicts the expired checkpoint and must fail closed.
        let mut journal = g.journal();
        journal.deadline_ms = Some(now().saturating_sub(1000));
        crate::durable::json(&g.root.join("nm/transaction.json"), &journal).unwrap();
        // Push an observation whose version differs from the recorded digest.
        {
            let mut script = g.wire.script.lock().unwrap();
            script.push_back(reply("v", json!([value("s", json!("1.47.0"))])));
            for _ in 0..2 {
                script.push_back(reply("o", json!([format!("{ROOT}/Devices/4")])));
                script.push_back(reply(
                    "a{sv}",
                    json!([{
                        "Interface":value("s",json!("eth0")),
                        "Managed":value("b",json!(true)),
                        "DeviceType":value("u",json!(1)),
                        "State":value("u",json!(100)),
                        "ActiveConnection":value("o",json!(format!("{ROOT}/ActiveConnection/4"))),
                    }]),
                ));
                script.push_back(reply("a{sa{sv}}t", json!([settings(), 1])));
                script.push_back(reply("v", json!([value("o", json!(format!("{ROOT}/Settings/3")))])));
                script.push_back(reply(
                    "a{sv}",
                    json!([{"Flags":value("u",json!(0)),"Unsaved":value("b",json!(false)),"VersionId":value("t",json!(7))}]),
                ));
            }
        }
        let view = g.engine.recover().unwrap();
        assert_eq!(view["state"], "RECOVERY_REQUIRED");
        assert_eq!(g.journal_state(), "RECOVERY_REQUIRED");
        assert!(!transaction::admission(&g.root).unwrap());
    }

    #[test]
    fn writer_refuses_nm_versions_below_the_1_44_write_contract() {
        let f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        // Observation with an old daemon version still prepares a digest, but
        // the writer minimum is 1.44, not the preview observation minimum.
        {
            let mut script = f.wire.script.lock().unwrap();
            script.clear();
            script.push_back(reply("v", json!([value("s", json!("1.42.0"))])));
            for _ in 0..2 {
                script.push_back(reply("o", json!([format!("{ROOT}/Devices/4")])));
                script.push_back(reply(
                    "a{sv}",
                    json!([{
                        "Interface":value("s",json!("eth0")),
                        "Managed":value("b",json!(true)),
                        "DeviceType":value("u",json!(1)),
                        "State":value("u",json!(100)),
                        "ActiveConnection":value("o",json!(format!("{ROOT}/ActiveConnection/4"))),
                    }]),
                ));
                script.push_back(reply("a{sa{sv}}t", json!([settings(), 1])));
                script.push_back(reply("v", json!([value("o", json!(format!("{ROOT}/Settings/3")))])));
                script.push_back(reply(
                    "a{sv}",
                    json!([{"Flags":value("u",json!(0)),"Unsaved":value("b",json!(false)),"VersionId":value("t",json!(7))}]),
                ));
            }
        }
        let digest = f.engine.capture_source(Instant::now()+Duration::from_secs(5)).unwrap().0["sourceDigest"]
            .as_str().unwrap().to_string();
        // Prepare performs its own capture; replay the old-version observation.
        f.observe();
        // The observation() helper always pushes 1.46.0; swap it for 1.42.0.
        {
            let mut script = f.wire.script.lock().unwrap();
            let old = script.pop_front().unwrap();
            assert_eq!(old["data"][0]["data"], "1.46.0");
            script.push_front(reply("v", json!([value("s", json!("1.42.0"))])));
        }
        let input = json!({
            "sourceDigest":digest,"confirmSeconds":60,
            "changes":[{"interface":"eth0","ipv4":{"method":"auto","addresses":[],
                "gateway":null,"dns":[],"ignoreAutoDns":false,"ignoreAutoRoutes":false,"wanPriority":-1}}],
            "nat":null,
        });
        let error = f.engine.prepare(input).unwrap_err();
        assert!(error.to_string().starts_with("UNSUPPORTED"), "{error}");
        assert!(!f.root.join("nm/transaction.json").exists());
    }

    #[test]
    fn foreign_firewall_progress_fails_the_decision_closed() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let view = f.prepare(None).unwrap();
        f.apply().unwrap();
        let token = view["token"].as_str().unwrap().to_string();
        // The firewall owner moved on after the NM intent bound it.
        crate::durable::directory(&f.root.join("firewall")).unwrap();
        crate::durable::json(
            &f.root.join("firewall/confirmed.json"),
            &json!({"revision":4,"text":null,"candidate":null}),
        )
        .unwrap();
        f.observe();
        let error = f.engine.confirm(json!({"token":token})).unwrap_err();
        assert!(error.to_string().starts_with("CONFLICT"), "{error}");
        assert_eq!(f.journal_state(), "WAIT_CONFIRM");
    }

    #[test]
    fn interrupted_profile_write_recovers_through_the_alive_checkpoint() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        f.prepare(None).unwrap();
        *f.wire.fail_update2.lock().unwrap() = true;
        let error = f.apply();
        assert!(error.is_err(), "injected update failure must surface");
        assert_eq!(f.journal_state(), "PROFILE_INTENT");
        // Admission keeps every other writer blocked while unresolved.
        assert!(!transaction::admission(&f.root).unwrap());
        f.observe();
        let view = f.engine.recover().unwrap();
        assert_eq!(view["action"], "checkpoint-rollback");
        assert_eq!(f.journal_state(), "ROLLED_BACK");
        assert!(transaction::admission(&f.root).unwrap());
    }

    // ---- remote authority contracts (protocol operations 34..=37) ----
    fn remote_command(operation: i32) -> yofc_management_protocol::v1::ReadCommand {
        yofc_management_protocol::v1::ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation,
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            expires_at_unix_ms: i64::MAX,
            ..Default::default()
        }
    }
    fn remote_authority() -> String {
        "b".repeat(64)
    }
    fn remote_connection(at: u128) -> String {
        format!("{at}:{}:test-center-epoch", uuid::Uuid::new_v4())
    }
    fn nm_change_wire(digest: &str) -> yofc_management_protocol::v1::NmChange {
        yofc_management_protocol::nm::Change {
            source_digest: digest.to_string(),
            confirm_seconds: 60,
            changes: json!([{"interface":"eth0","ipv4":{"method":"manual",
                "addresses":[{"address":"192.0.2.10","prefix":24}],
                "gateway":"192.0.2.1","dns":["192.0.2.53"],
                "ignoreAutoDns":true,"ignoreAutoRoutes":false,"wanPriority":30}}]),
            nat: None,
        }
        .to_wire()
        .unwrap()
    }

    #[test]
    fn remote_view_prepares_and_confirms_only_on_a_new_management_connection() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let digest = f.source_digest();
        f.observe();
        let authority = remote_authority();
        let applied_session = remote_connection(1);
        let view = f
            .engine
            .remote_request(&remote_command(34), &authority, &applied_session, true)
            .unwrap();
        assert_eq!(view["sourceDigest"], digest);
        assert_eq!(view["confirmationReady"], false);
        let mut prepare = remote_command(35);
        prepare.nm_change = Some(nm_change_wire(&digest));
        // Prepare and apply perform three fresh source captures.
        f.observe();
        f.observe();
        f.observe();
        let prepared = f
            .engine
            .remote_request(&prepare, &authority, &applied_session, true)
            .unwrap();
        assert_eq!(prepared["state"], "WAIT_CONFIRM");
        assert_eq!(prepared["newManagementConnectionVerified"], false);
        let token = prepared["confirmationToken"].as_str().unwrap().to_string();
        let operation_id = prepared["id"].as_str().unwrap().to_string();
        let mut confirm = remote_command(36);
        confirm.nm_action = Some(yofc_management_protocol::v1::NmAction {
            operation_id: operation_id.clone(),
            confirmation_token: token,
        });
        // The very same connection that applied the transaction can never
        // confirm it; a token alone does not prove a new affected connection.
        let error = f
            .engine
            .remote_request(&confirm, &authority, &applied_session, true)
            .unwrap_err();
        assert!(
            error.to_string().contains("new authenticated management connection"),
            "{error}"
        );
        assert_eq!(f.journal_state(), "WAIT_CONFIRM");
        // A new, later connection proves the affected party reconnected.
        let new_session = remote_connection(now() as u128 + 5_000);
        f.observe();
        f.observe();
        f.engine
            .remote_request(&confirm, &authority, &new_session, true)
            .unwrap();
        assert_eq!(f.journal_state(), "COMMITTED");
        let journal = f.journal();
        assert!(journal.remote_actions.iter().any(|a| a.operation == 36 && a.new_connection_proved));
        assert!(transaction::admission(&f.root).unwrap());
    }

    #[test]
    fn remote_prepare_rejects_duplicate_original_commands_and_foreign_authority() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let digest = f.source_digest();
        let authority = remote_authority();
        let session = remote_connection(1);
        let mut prepare = remote_command(35);
        prepare.nm_change = Some(nm_change_wire(&digest));
        // Prepare and apply perform three fresh source captures.
        f.observe();
        f.observe();
        f.observe();
        f.engine
            .remote_request(&prepare, &authority, &session, true)
            .unwrap();
        f.observe();
        let error = f
            .engine
            .remote_request(&prepare, &authority, &session, true)
            .unwrap_err();
        assert!(error.to_string().starts_with("OUTCOME_UNKNOWN"), "{error}");
        // A transaction already exists; a second command cannot start.
        let mut other = remote_command(35);
        other.nm_change = Some(nm_change_wire(&digest));
        f.observe();
        let error = f
            .engine
            .remote_request(&other, &authority, &session, true)
            .unwrap_err();
        assert!(error.to_string().starts_with("OUTCOME_UNKNOWN"), "{error}");
        // A foreign (but well-formed) authority may read the view; it can
        // never act on the transaction.
        let foreign_view = f
            .engine
            .remote_request(&remote_command(34), &"c".repeat(64), &session, true)
            .unwrap();
        assert_eq!(foreign_view["confirmationReady"], false);
        let mut foreign_confirm = remote_command(36);
        foreign_confirm.nm_action = Some(yofc_management_protocol::v1::NmAction {
            operation_id: f.journal().operation_id.hyphenated().to_string(),
            confirmation_token: f.journal().token.unwrap_or_default(),
        });
        let error = f
            .engine
            .remote_request(&foreign_confirm, &"c".repeat(64), &session, true)
            .unwrap_err();
        assert!(error.to_string().starts_with("FORBIDDEN"), "{error}");
        // Without the remote grant the whole family is unsupported.
        let error = f
            .engine
            .remote_request(&remote_command(34), &authority, &session, false)
            .unwrap_err();
        assert!(error.to_string().starts_with("UNSUPPORTED"), "{error}");
    }

    #[test]
    fn remote_rollback_never_requires_a_new_connection_and_deduplicates_actions() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let digest = f.source_digest();
        let authority = remote_authority();
        let session = remote_connection(1);
        let mut prepare = remote_command(35);
        prepare.nm_change = Some(nm_change_wire(&digest));
        // Prepare and apply perform three fresh source captures.
        f.observe();
        f.observe();
        f.observe();
        let prepared = f
            .engine
            .remote_request(&prepare, &authority, &session, true)
            .unwrap();
        let token = prepared["confirmationToken"].as_str().unwrap().to_string();
        let operation_id = prepared["id"].as_str().unwrap().to_string();
        let mut rollback = remote_command(37);
        rollback.nm_action = Some(yofc_management_protocol::v1::NmAction {
            operation_id,
            confirmation_token: token,
        });
        // Rollback verifies the restored source with a fresh observation.
        f.observe();
        f.engine
            .remote_request(&rollback, &authority, &session, true)
            .unwrap();
        assert_eq!(f.journal_state(), "ROLLED_BACK");
        // A duplicate rollback command is refused and proves nothing new.
        let error = f
            .engine
            .remote_request(&rollback, &authority, &session, true)
            .unwrap_err();
        assert!(error.to_string().starts_with("CONFLICT"), "{error}");
        assert!(transaction::admission(&f.root).unwrap());
    }

    #[test]
    fn prove_remote_adjudicates_by_original_command_identity() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let digest = f.source_digest();
        let authority = remote_authority();
        let session = remote_connection(1);
        // Unknown before anything exists.
        assert!(f.engine.prove_remote(&remote_command(35), &authority).unwrap().is_none());
        let mut prepare = remote_command(35);
        prepare.nm_change = Some(nm_change_wire(&digest));
        // Prepare and apply perform three fresh source captures.
        f.observe();
        f.observe();
        f.observe();
        let prepared = f
            .engine
            .remote_request(&prepare, &authority, &session, true)
            .unwrap();
        // Prepared and waiting: the original prepare command proves success.
        let proof = f.engine.prove_remote(&prepare, &authority).unwrap().unwrap();
        assert_eq!(proof.state, TaskState::Succeeded as i32);
        assert_eq!(proof.command_id, prepare.command_id);
        assert!(String::from_utf8(proof.result_json.clone()).unwrap().contains("nm.coordinator.journal.v1"));
        // Foreign authority learns nothing.
        assert!(f.engine.prove_remote(&prepare, &"c".repeat(64)).unwrap().is_none());
        let token = prepared["confirmationToken"].as_str().unwrap().to_string();
        let operation_id = prepared["id"].as_str().unwrap().to_string();
        let mut confirm = remote_command(36);
        confirm.nm_action = Some(yofc_management_protocol::v1::NmAction {
            operation_id,
            confirmation_token: token,
        });
        let new_session = remote_connection(now() as u128 + 5_000);
        f.observe();
        f.observe();
        f.engine
            .remote_request(&confirm, &authority, &new_session, true)
            .unwrap();
        let proof = f.engine.prove_remote(&confirm, &authority).unwrap().unwrap();
        assert_eq!(proof.state, TaskState::Succeeded as i32);
        // After the settle, the original prepare still proves with the
        // committed outcome.
        let proof = f.engine.prove_remote(&prepare, &authority).unwrap().unwrap();
        assert_eq!(proof.state, TaskState::Succeeded as i32);
    }

    #[test]
    fn interrupted_remote_prepare_leaves_unknown_and_blocks_everything() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let digest = f.source_digest();
        let authority = remote_authority();
        let session = remote_connection(1);
        let mut prepare = remote_command(35);
        prepare.nm_change = Some(nm_change_wire(&digest));
        *f.wire.fail_update2.lock().unwrap() = true;
        f.observe();
        f.observe();
        f.observe();
        let error = f
            .engine
            .remote_request(&prepare, &authority, &session, true)
            .unwrap_err();
        assert!(error.to_string().starts_with("OUTCOME_UNKNOWN"), "{error}");
        assert_eq!(f.journal_state(), "PROFILE_INTENT");
        assert!(!transaction::admission(&f.root).unwrap());
        // The original command cannot be proven until the operator settles it.
        assert!(f.engine.prove_remote(&prepare, &authority).unwrap().is_none());
        // Recovery rolls the alive checkpoint back and settles the evidence.
        f.observe();
        let view = f.engine.recover().unwrap();
        assert_eq!(view["action"], "checkpoint-rollback");
        assert_eq!(f.journal_state(), "ROLLED_BACK");
        // Now the original command proves with a FAILED outcome (rolled back).
        let proof = f.engine.prove_remote(&prepare, &authority).unwrap().unwrap();
        assert_eq!(proof.state, TaskState::Failed as i32);
    }

    #[test]
    fn archive_requires_a_settled_receipt_and_retains_history() {
        let mut f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let view = f.prepare(None).unwrap();
        let error = f.engine.archive().unwrap_err();
        assert!(error.to_string().starts_with("OUTCOME_UNKNOWN"), "{error}");
        f.apply().unwrap();
        let token = view["token"].as_str().unwrap().to_string();
        f.observe();
        f.observe();
        f.engine.confirm(json!({"token":token})).unwrap();
        let operation = f.journal().operation_id.hyphenated().to_string();
        f.engine.archive().unwrap();
        assert!(!f.root.join("nm/transaction.json").exists());
        assert!(f.root.join(format!("nm/history/{operation}.journal.json")).exists());
        assert!(f.root.join(format!("nm/history/{operation}.intent.json")).exists());
        assert!(f.root.join(format!("nm/history/{operation}.receipt.json")).exists());
        assert!(transaction::admission(&f.root).unwrap());
        // A new proposal can start after the explicit archive.
        f.digest = None;
        f.prepare(None).unwrap();
    }
}


#[cfg(test)]
mod real_remote_confirm_tests {
    use super::*;

    /// Real-NM remote authority validation, executed inside the isolated VM
    /// tree (`cargo test real_remote -- --ignored`): the production Busctl
    /// wire drives remote_request against the running NetworkManager, and the
    /// connection witnesses prove that the connection which applied a
    /// transaction can never confirm it while a later, different management
    /// connection can.
    #[tokio::test]
    #[ignore = "requires real NetworkManager on Linux; explicit isolated VM run only"]
    async fn real_nm_remote_confirm_requires_a_new_management_connection() {
        if !cfg!(target_os = "linux") || !Path::new("/usr/bin/busctl").is_file() {
            eprintln!("no real NM backend; skipping");
            return;
        }
        let root = std::env::temp_dir().join(format!("nm-real-remote-{}", uuid::Uuid::new_v4()));
        crate::durable::directory(&root).unwrap();
        let wire: Arc<dyn Wire> = Arc::new(Busctl { address: None });
        let nm = Nm::for_test(
            json!({"schemaVersion":1,"interfaces":["eth0"],"writeEnabled":true}),
            wire.clone(),
            &root,
        )
        .unwrap();
        let engine = nm.engine.clone().unwrap();
        let authority = "b".repeat(64);
        // The applying connection predates the apply; the confirming one is
        // minted after it, which is exactly what the transport witnesses.
        let old_connection = format!("{}:{}:real-vm-apply", now() - 60_000, uuid::Uuid::new_v4());
        // Read-only view first: the proposal binds to this digest.
        let view = engine
            .remote_request(&remote_command(34), &authority, &old_connection, true)
            .unwrap();
        let digest = view["sourceDigest"].as_str().unwrap().to_string();
        assert_eq!(digest.len(), 64);
        let mut prepare = remote_command(35);
        prepare.nm_change = Some(nm_change_wire(&digest));
        let prepared = engine
            .remote_request(&prepare, &authority, &old_connection, true)
            .unwrap();
        assert_eq!(prepared["state"], "WAIT_CONFIRM");
        assert_eq!(prepared["newManagementConnectionVerified"], false);
        let token = prepared["confirmationToken"].as_str().unwrap().to_string();
        let operation_id = prepared["id"].as_str().unwrap().to_string();
        let mut confirm = remote_command(36);
        confirm.nm_action = Some(yofc_management_protocol::v1::NmAction {
            operation_id,
            confirmation_token: token,
        });
        // The applying connection can never confirm its own transaction.
        let error = engine
            .remote_request(&confirm, &authority, &old_connection, true)
            .unwrap_err();
        assert!(
            error.to_string().contains("new authenticated management connection"),
            "{error}"
        );
        let journal = engine.journal().unwrap().unwrap();
        assert_eq!(journal.state, transaction::State::WaitConfirm);
        // A new, later connection proves the affected party reconnected; the
        // commit then verifies and writes the receipt.
        let new_connection = format!("{}:{}:real-vm-confirm", now() + 5_000, uuid::Uuid::new_v4());
        let confirmed = engine
            .remote_request(&confirm, &authority, &new_connection, true)
            .unwrap();
        assert_eq!(confirmed["state"], "COMMITTED");
        assert_eq!(confirmed["newManagementConnectionVerified"], true);
        assert!(transaction::admission(&root).unwrap());
        engine.archive().unwrap();
        // Revert the harmless edit with a remote prepare + remote rollback on
        // the same authority: rollback never demands a new connection.
        let view2 = engine
            .remote_request(&remote_command(34), &authority, &new_connection, true)
            .unwrap();
        let digest2 = view2["sourceDigest"].as_str().unwrap().to_string();
        let revert = yofc_management_protocol::nm::Change {
            source_digest: digest2,
            confirm_seconds: 60,
            changes: json!([{"interface":"eth0","ipv4":{"method":"auto","addresses":[],
                "gateway":null,"dns":[],"ignoreAutoDns":false,"ignoreAutoRoutes":false,
                "wanPriority":-1}}]),
            nat: None,
        }
        .to_wire()
        .unwrap();
        let mut prepare2 = remote_command(35);
        prepare2.nm_change = Some(revert);
        let prepared2 = engine
            .remote_request(&prepare2, &authority, &new_connection, true)
            .unwrap();
        assert_eq!(prepared2["state"], "WAIT_CONFIRM");
        let token2 = prepared2["confirmationToken"].as_str().unwrap().to_string();
        let operation_id2 = prepared2["id"].as_str().unwrap().to_string();
        let mut rollback = remote_command(37);
        rollback.nm_action = Some(yofc_management_protocol::v1::NmAction {
            operation_id: operation_id2,
            confirmation_token: token2,
        });
        let rolled = engine
            .remote_request(&rollback, &authority, &new_connection, true)
            .unwrap();
        assert_eq!(rolled["state"], "ROLLED_BACK");
        assert!(transaction::admission(&root).unwrap());
        engine.archive().unwrap();
        std::fs::remove_dir_all(root).unwrap();
        eprintln!("real remote confirm/rollback validation passed");
    }

    fn remote_command(operation: i32) -> yofc_management_protocol::v1::ReadCommand {
        yofc_management_protocol::v1::ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation,
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            expires_at_unix_ms: i64::MAX,
            ..Default::default()
        }
    }
    fn nm_change_wire(digest: &str) -> yofc_management_protocol::v1::NmChange {
        yofc_management_protocol::nm::Change {
            source_digest: digest.to_string(),
            confirm_seconds: 60,
            changes: json!([{"interface":"eth0","ipv4":{"method":"auto","addresses":[],
                "gateway":null,"dns":[],"ignoreAutoDns":false,"ignoreAutoRoutes":false,
                "wanPriority":30}}]),
            nat: None,
        }
        .to_wire()
        .unwrap()
    }
}
