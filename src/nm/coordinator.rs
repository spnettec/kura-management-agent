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
mod delegation;
pub(in crate::nm) mod imported;

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
    role_source:Option<Arc<dyn roles::Source>>,
    handover:handover::Store,
    startup_profile:PathBuf,
    startup_systemctl:PathBuf,
    #[cfg(test)]
    fake: std::sync::Mutex<FakeNft>,
    #[cfg(test)]
    real: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
#[derive(Default)]
struct FakeNft {
    table: Option<Value>,
    kernel_policy: Option<Value>,
    legacy_kernel: Option<[String;4]>,
    native_kernel: Option<Value>,
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
pub(super) use super::nat::NatSet;
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
    pub(super) fn new(source: Nm, root: &Path) -> Result<Self> {
        for name in ["nm", "nm/intents", "nm/receipts", "nm/history", "nm/remote-history"] {
            crate::durable::directory(&root.join(name))?;
        }
        Ok(Self::observer(source, root))
    }

    pub(super) fn observer(mut source: Nm, root: &Path) -> Self {
        source.engine = None;
        source.ownership_observer = None;
        Self {
            source,
            root: root.into(),
            nft: PathBuf::from("/usr/sbin/nft"),
            role_source:None,
            handover:handover::Store::new(root),
            startup_profile:PathBuf::from("/etc/kura-management-agent/nm-ownership-profile.json"),
            startup_systemctl:PathBuf::from("/usr/bin/systemctl"),
            #[cfg(test)]
            fake: std::sync::Mutex::new(FakeNft::default()),
            #[cfg(test)]
            real: std::sync::atomic::AtomicBool::new(false),
        }
    }
    pub(super) fn set_role_source(&mut self,source:Arc<dyn roles::Source>) {self.role_source=Some(source);}
    fn read_roles(&self,deadline:Instant)->Result<Option<roles::Observation>> {
        if let Some(active)=self.handover.active()? {return Ok(Some(active.baseline.roles));}
        if let Some(source)=&self.role_source {return source.raw(deadline).map(Some);}
        #[cfg(test)]
        if !self.real.load(std::sync::atomic::Ordering::Relaxed) {return Ok(None);}
        anyhow::bail!("UNSUPPORTED: authenticated Kura role authority is not configured")
    }
    pub(super) fn ensure_role_binding(&self,journal:&transaction::Journal,deadline:Instant)->Result<()> {
        if let Some(binding)=&journal.delegation_binding {
            let active=self.handover.active()?.context("FORBIDDEN: original delegation is not active")?;
            ensure!(&active.binding==binding,"CONFLICT: delegation changed since preparation");
        }
        // Legacy immutable intents have no role/delegation fields. Their original
        // compensation/confirmation remains possible; admission checks the actual
        // intent hash before this method, so stripping fields cannot bypass it.
        if journal.role_binding.is_none() {return Ok(());}
        ensure!(self.read_roles(deadline)?==journal.role_binding,"CONFLICT: Kura role authority changed since preparation");Ok(())
    }
    pub(super) fn capture_source(&self, deadline: Instant) -> Result<(Value, Vec<Device>)> {
        let delegation=self.handover.active()?;
        let role_binding=self.read_roles(deadline)?;
        let forwarding = self.ipv4_forwarding()?;
        let nat = self.observed_nat(deadline)?;
        let marker = ownership::marker(&self.root)?;
        let firewall = self.firewall_binding()?;
        let (mut source, devices) = self.source.capture(deadline)?;
        if let Some(active)=&delegation {active.baseline.validate_current(&self.source.config.interfaces,&devices)?;}
        let rechecked_nat = self.observed_nat(deadline)?;
        ensure!(settlement::nat_equal(nat.as_ref(), rechecked_nat.as_ref())
            && marker == ownership::marker(&self.root)? && firewall == self.firewall_binding()?
            && forwarding == self.ipv4_forwarding()? && role_binding == self.read_roles(deadline)?
            && delegation==self.handover.active()?,
            "CONFLICT: joint NM/NAT/firewall source changed during observation");
        ensure!(Instant::now() < deadline, "TIMEOUT: joint NM observation deadline");
        source["sourceDigest"] = json!(digest(&json!({
            "profiles":source["sourceDigest"],"automaticNat":nat,
            "natOwnership":marker,"firewall":firewall,"ipv4Forwarding":forwarding,"kuraRoles":role_binding,
            "delegation":delegation.as_ref().map(|active|&active.binding),
        }))?);
        source["roleObservation"]=serde_json::to_value(role_binding)?;
        source["delegationBinding"]=serde_json::to_value(delegation.map(|active|active.binding))?;
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
    fn publish_main_intent(&self, intent: &transaction::IntentHeader) -> Result<String> {
        let bytes = serde_json::to_vec(intent)?;
        crate::durable::publish_new(
            &self.intent_path(intent.operation_id, None),
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
        if let Some(source)=handover::initialization::confirmed_source(&self.root,None)? {
            return Ok(transaction::FirewallBinding{revision:source["revision"].as_str().and_then(|v|v.parse().ok()).context("CONFLICT: imported firewall revision")?,
                confirmed_sha256:source["confirmedSha256"].as_str().context("CONFLICT: imported firewall source digest")?.into(),journal_settled:source["journalSettled"].as_bool().context("CONFLICT: imported firewall journal state")?});
        }
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
#[cfg(test)]
fn render_nat(wan:&str,lan:&[String])->String {NatSet::Legacy{wan:wan.into(),lan:lan.to_vec()}.render().unwrap()}
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
                let mut ruleset=fake.kernel_policy.clone().unwrap_or_else(||json!({"nftables":[]}));
                if let Some(table)=&fake.table {
                    ruleset["nftables"].as_array_mut().unwrap().extend(table["nftables"].as_array().unwrap().iter().cloned());
                }
                return Ok(ruleset.to_string());
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
        let pairs=nat.pairs()?;
        let names:std::collections::BTreeSet<_>=pairs.iter().flat_map(|pair|[&pair.wan,&pair.lan]).collect();
        ensure!(names.iter().all(|name|valid(name)),"FORBIDDEN: NAT endpoint not configured");
        for name in names {
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
        let delegation=self.handover.active()?;
        // Existing fake-backend transaction fixtures start after writer admission;
        // production and real-backend tests must prove an explicit active lease.
        #[cfg(test)]
        let fake_backend=!self.real.load(std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(test))]
        let fake_backend=false;
        ensure!(fake_backend || delegation.is_some(),"FORBIDDEN: explicit NM delegation is required for a new proposal");
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
          let role_binding:Option<roles::Observation>=serde_json::from_value(source["roleObservation"].clone())?;
          let delegation_binding:Option<handover::Binding>=serde_json::from_value(source["delegationBinding"].clone())?;
          ensure!(delegation_binding==delegation.as_ref().map(|active|active.binding.clone()),"CONFLICT: delegation changed during preparation");
          if let Some(binding)=&role_binding {
              let resolved=devices.iter().map(|d|(d.interface.clone(),d.interface.clone())).collect();
              let owned=self.source.config.interfaces.iter().cloned().collect();
              let expected=binding.roles.automatic_nat(&resolved,&owned)?;
              let proposed=input.nat.as_ref().map(NatSet::pairs).transpose()?.unwrap_or_default();
              ensure!(proposed==expected,"FORBIDDEN: NAT proposal differs from authoritative Kura roles; use a joint role change");
          }
          self.require_forwarding(input.nat.as_ref())?;
          let nat_target = json!({"nat":input.nat});
        let intent_sha256 = self.publish_main_intent(&transaction::IntentHeader {
            schema_version:1,operation_id:operation,source_digest:input.source_digest.clone(),
            candidate_digest:candidate_digest.clone(),nm_identity:Some(binding.clone()),
            nat_before:Some(nat_before.clone()),nat_target:Some(nat_target),
            role_binding:role_binding.clone(),delegation_binding:delegation_binding.clone(),
        })?;
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
          journal.role_binding=role_binding;
          journal.delegation_binding=delegation_binding;
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
                    self.ensure_role_binding(&journal,deadline)?;
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
                    self.ensure_role_binding(&journal,deadline)?;
                    self.ensure_nat_baseline(&journal, deadline)?;
                    self.require_forwarding(input.nat.as_ref())?;
                    let before: Option<NatSet> = serde_json::from_value(journal.nat_before.as_ref()
                        .context("CONFLICT: NAT baseline missing")?["nat"].clone())?;
                    let applies = !settlement::nat_equal(before.as_ref(), input.nat.as_ref());
                    let text = if !applies {String::new()} else {match &input.nat {
                        Some(nat) => nat.render()?,
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
                    self.ensure_role_binding(&journal,deadline)?;
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
    mod native_factory;

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
            Self::at_root(root, interfaces, devices)
        }
        fn at_root(root: PathBuf, interfaces: &[&str], devices: &[(&'static str, u32, u32)]) -> Self {
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
        fn ownership_source_digest(&mut self)->String {
            let backend=self.source_digest();let deadline=Instant::now()+Duration::from_secs(5);
            let observed=self.engine.read_roles(deadline).unwrap().unwrap();
            let firewall=self.engine.role_source.as_ref().unwrap().firewall_source(&observed,deadline).unwrap();
            let fence=self.engine.handover.observe_firewall_fence().unwrap();
            handover::Baseline::bind_pair_source(&backend,Some(&firewall),Some(&fence)).unwrap()
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

    #[cfg(target_os="linux")]
    include!("coordinator/bootstrap_fixture.rs");

    const EXPORT_STORED_FIREWALL_DRIFT: u8 = 11;
    struct RoleSource {value:Mutex<Option<roles::Observation>>}
    struct ExportSource {value:Mutex<roles::Observation>,root:PathBuf,exports:std::sync::atomic::AtomicUsize,mode:u8,
        owner_reads:std::sync::atomic::AtomicUsize,association_reads:std::sync::atomic::AtomicUsize,offline:std::sync::atomic::AtomicBool,
        startup_mode:std::sync::atomic::AtomicU8,drain_reads:std::sync::atomic::AtomicUsize,owner_marker:Mutex<PathBuf>}
    impl roles::Source for ExportSource {
        fn firewall_source(&self,observed:&roles::Observation,deadline:Instant)->Result<roles::FirewallSource> {
            ensure!(&self.raw(deadline)?==observed,"CONFLICT: fixture network source changed");
            let mut value=roles::fixture_firewall_source(observed).parameters()?;
            if self.mode==EXPORT_STORED_FIREWALL_DRIFT && self.exports.load(std::sync::atomic::Ordering::Relaxed)>0 {
                value["families"][0]["revision"]=json!(format!("stored:{}","c".repeat(64)));
            }
            roles::FirewallSource::new(observed.agent_instance,observed.bridge_epoch,observed,value)
        }
        fn raw(&self,_:Instant)->Result<roles::Observation> {
            ensure!(!self.offline.load(std::sync::atomic::Ordering::Relaxed) && (self.mode!=2 || self.exports.load(std::sync::atomic::Ordering::Relaxed)==0),"KURA_UNAVAILABLE: original exporter stopped");
            Ok(self.value.lock().unwrap().clone())
        }
        fn read(&self,deadline:Instant)->Result<roles::Observation> {
            let _guard=Guard::observe_shared(&self.root,Duration::from_secs(1))?;
            self.drain_reads.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
            ensure!(self.startup_mode.load(std::sync::atomic::Ordering::Relaxed)!=15,"CONFLICT: fixture participating writer has not drained");self.raw(deadline)
        }
        fn export(&self,id:uuid::Uuid,source:&roles::Observation,firewall:&roles::FirewallSource,nonce:&str,_:Instant)->Result<Value> {
            firewall.require(source)?;
            use std::sync::atomic::Ordering;
            self.exports.fetch_add(1,Ordering::Relaxed);
            // This acquisition proves the controller released the OS guard
            // while the reverse registered-Kura callback is awaited.
            let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
            if self.mode==2 {anyhow::bail!("OUTCOME_UNKNOWN: synthetic lost export before any received chunk");}
            handover::template::Transfer::new(&self.root).deposit(json!({"operationId":id,"revision":source.roles.revision,
                "depositToken":nonce,"templateSha256":crate::durable::hash(b"AAAA-BBBB"),"chunkIndex":0,"chunkCount":1,"ciphertextChunk":"AAAA-BBBB"}),source.agent_instance,source.bridge_epoch)?;
            if self.mode==3 {let mut changed=self.value.lock().unwrap();changed.roles.revision="changed-after-export".into();}
              if self.mode==250 {
                  let marker=self.owner_marker.lock().unwrap().with_file_name("firewall-owner-agent");
                  crate::durable::publish_new(&marker,b"changed-during-original-export",crate::durable::FileMetadata::private())?;
              }
            if self.mode==1 {anyhow::bail!("OUTCOME_UNKNOWN: synthetic lost final Java reply");}
            Ok(json!({"stored":true}))
        }
        fn owner(&self,_:Instant)->Result<roles::Owner> {
            ensure!(!self.offline.load(std::sync::atomic::Ordering::Relaxed),"KURA_UNAVAILABLE: fixture Core stopped");
            self.owner_reads.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
            let _guard=Guard::observe_shared(&self.root,Duration::from_secs(1))?;
            let view=handover::Store::relocated(&self.root,self.owner_marker.lock().unwrap().clone())
                .mirror("network.nm.template.confirmed",json!({}))?;
            let firewall=crate::firewall::core_confirmed_witness(&self.root)?;
            let current=self.value.lock().unwrap();let mut reply=json!({"schemaVersion":2,"pid":roles::PID,
                "operationId":view["operationId"],"planSha256":view["planSha256"],"mirrorSha256":view["templateSha256"],"roles":view["roles"],
                "firewall":{"schemaVersion":1,"pids":[roles::FIREWALL_V4_PID,roles::FIREWALL_V6_PID],
                    "revision":firewall.revision.to_string(),"sourceDigest":firewall.source_digest}});
            if self.mode==4 || self.startup_mode.load(std::sync::atomic::Ordering::Relaxed)==8 {reply["planSha256"]=json!("f".repeat(64));}
            match self.startup_mode.load(std::sync::atomic::Ordering::Relaxed) {
                16=>reply["firewall"]["sourceDigest"]=json!("f".repeat(64)),
                17=>reply["firewall"]["revision"]=json!((firewall.revision+1).to_string()),
                18=>{reply["schemaVersion"]=json!(1);reply.as_object_mut().unwrap().remove("firewall");},
                _=>{},
            }
            // Model a newly authenticated Kura registration after controlled
            // restart, not a caller-supplied readiness or epoch parameter.
            roles::Owner::new(current.agent_instance,current.bridge_epoch+u64::from(self.startup_mode.load(std::sync::atomic::Ordering::Relaxed)==9),reply)
        }
        fn owner_still_registered(&self,_:&roles::Owner,_:Instant)->Result<()> {
            ensure!(self.mode!=5 && self.startup_mode.load(std::sync::atomic::Ordering::Relaxed)!=14,"CONFLICT: fixture owner registration replaced");Ok(())
        }
        fn association(&self,spec:&roles::StartupSpec,_:Instant)->Result<roles::StartupAssociation> {
            ensure!(!self.offline.load(std::sync::atomic::Ordering::Relaxed),"KURA_UNAVAILABLE: fixture JVM stopped");
            self.association_reads.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
            let _guard=Guard::observe_shared(&self.root,Duration::from_secs(1))?;
            let config=crate::recovery::ordinary_profile::Profile::runtime(self.root.join("ordinary-profile.json"),self.root.clone())?.inspect()?.config;
            let started=std::fs::read_to_string(self.root.join("unit-state"))?.contains("MainPID=5432");
            let current=self.value.lock().unwrap();
            let mut value=json!({"schemaVersion":1,"operationId":spec.operation_id,"planSha256":spec.plan_sha256,"nonce":spec.nonce,
                "observerInstanceId":if started{"55555555-5555-4555-8555-555555555555"}else{"44444444-4444-4444-8444-444444444444"},
                "profileId":config.profile_id,"processId":if started{5432}else{4321},"frameworkStartLevel":6,"ordinaryLoad":true});
            match self.mode {4=>value["planSha256"]=json!("f".repeat(64)),6=>value["processId"]=json!(4322),
                7=>value["profileId"]=json!("profile-55555555-5555-4555-8555-555555555555"),8=>value["frameworkStartLevel"]=json!(4),
                9=>value["ordinaryLoad"]=json!(false),_=>{}}
            let mode=self.startup_mode.load(std::sync::atomic::Ordering::Relaxed);
            match mode {
                1=>value["processId"]=json!(4321),2=>value["profileId"]=json!("profile-66666666-6666-4666-8666-666666666666"),
                3=>value["observerInstanceId"]=json!("44444444-4444-4444-8444-444444444444"),4=>value["frameworkStartLevel"]=json!(4),
                5=>value["ordinaryLoad"]=json!(false),6=>value["nonce"]=json!("e".repeat(64)),_=>{},
            }
            let observed=roles::StartupAssociation::new(current.agent_instance,current.bridge_epoch+u64::from(mode==7),value)?;drop(current);
            if self.mode==10 {self.value.lock().unwrap().roles.revision="changed-during-jvm-association".into();}
            if mode==10 {self.value.lock().unwrap().roles.revision="changed-during-terminal-witness".into();}
            if mode==11 {self.value.lock().unwrap().bridge_epoch+=1;}
            if mode==12 {let config=crate::recovery::ordinary_profile::Profile::runtime(self.root.join("ordinary-profile.json"),self.root.clone())?.inspect()?.config;
                crate::durable::write(&config.jvm_args_path,&std::fs::read(&config.jvm_args_path)?,crate::durable::FileMetadata::private())?;}
            if mode==13 {let path=self.root.join("unit-state");let text=std::fs::read_to_string(&path)?.replace("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","cccccccccccccccccccccccccccccccc");crate::durable::write(&path,text.as_bytes(),crate::durable::FileMetadata::private())?;}
            Ok(observed)
        }
        fn association_still_registered(&self,_:&roles::StartupAssociation,_:Instant)->Result<()> {
            ensure!(self.mode!=5,"CONFLICT: fixture startup registration replaced");Ok(())
        }
    }
    fn export_fixture(mode:u8)->(Fixture,Arc<ExportSource>) {
        let f=Fixture::new(&["eth0"],&[("eth0",4,3)]);
        crate::firewall::seed_confirmed_core_fixture(&f.root).unwrap();
        f.engine.fake.lock().unwrap().kernel_policy=Some(crate::firewall::confirmed_kernel_fixture(&f.root).unwrap());
        let parent=f.root.join("installed-owner");crate::durable::directory(&parent).unwrap();
        let marker=parent.join("network-owner-agent");
        let store=handover::Store::relocated(&f.root,marker.clone());
        export_fixture_at(f,mode,marker,store)
    }
    fn export_fixture_at(mut f:Fixture,mode:u8,marker:PathBuf,store:handover::Store)->(Fixture,Arc<ExportSource>) {
        let source=Arc::new(ExportSource{value:Mutex::new(roles::Observation::new(uuid::Uuid::new_v4(),1,json!({
            "schemaVersion":1,"pid":roles::PID,"revision":"paired-export-original",
            "interfaces":[{"id":"eth0","type":"ETHERNET","ipv4Status":"netIPv4StatusEnabledWAN","natEnabled":null}]})).unwrap()),
            root:f.root.clone(),exports:std::sync::atomic::AtomicUsize::new(0),mode,
            owner_reads:std::sync::atomic::AtomicUsize::new(0),association_reads:std::sync::atomic::AtomicUsize::new(0),offline:std::sync::atomic::AtomicBool::new(false),
            startup_mode:std::sync::atomic::AtomicU8::new(0),drain_reads:std::sync::atomic::AtomicUsize::new(0),owner_marker:Mutex::new(marker)});
        let engine=Arc::get_mut(&mut f.engine).unwrap();engine.handover=store;
        engine.set_role_source(source.clone());(f,source)
    }
    #[test]
    fn template_controller_original_prepare_and_lost_final_reply_share_one_export_and_plan() {
        for mode in [0,1] {
            let (mut f,source)=export_fixture(mode);let digest=f.ownership_source_digest();for _ in 0..4 {f.observe();}
            let id=uuid::Uuid::new_v4();let input=json!({"operationId":id,"sourceDigest":digest});
            let prepared=f.engine.ownership_request("network.nm.ownership.prepare",input.clone(),"local-uid:fixture").unwrap();
            assert_eq!(prepared["state"],"PREPARED");assert!(prepared["confirmationToken"].is_string());
            assert!(f.engine.ownership_request("network.nm.ownership.prepare",input,"local-uid:fixture").is_err());
            let original=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").unwrap();
            assert_eq!(original["confirmationToken"],prepared["confirmationToken"]);
            assert!(f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"other-actor").is_err());
            let status=f.engine.ownership_request("network.nm.ownership.status",json!({}),"local-uid:fixture").unwrap();
            assert!(!status.to_string().contains(prepared["confirmationToken"].as_str().unwrap()));
            assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);
            assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
            assert!(!f.root.join("installed-owner/network-owner-agent").exists());
            assert_eq!(f.engine.ownership_request("network.nm.ownership.cancel",json!({"operationId":id}),"local-uid:fixture").unwrap()["state"],"CANCELLED");
            assert!(Guard::acquire(&f.root,Subsystem::Network).is_ok());
        }
    }
    #[test]
    fn template_controller_incomplete_original_query_never_calls_java_export_a_second_time() {
        let (mut f,source)=export_fixture(2);let digest=f.ownership_source_digest();for _ in 0..2 {f.observe();}
        let id=uuid::Uuid::new_v4();
        assert!(f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":digest}),"local-uid:fixture").is_err());
        assert!(f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":digest}),"local-uid:fixture")
            .unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
        for _ in 0..2 {assert!(f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").is_err());}
        assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);
        assert!(Guard::acquire(&f.root,Subsystem::Nm).is_err());
        assert_eq!(f.engine.ownership_request("network.nm.ownership.cancel",json!({"operationId":id}),"local-uid:fixture").unwrap()["state"],"CANCELLED");
        assert!(Guard::acquire(&f.root,Subsystem::Network).is_ok());assert_eq!(f.call_count("CheckpointCreate"),0);
    }
    #[test]
    fn template_controller_source_change_after_export_refuses_the_plan_without_any_fence() {
        let (mut f,source)=export_fixture(3);let digest=f.ownership_source_digest();for _ in 0..4 {f.observe();}
        let id=uuid::Uuid::new_v4();
        assert!(f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":digest}),"local-uid:fixture").unwrap_err().to_string().contains("source changed"));
        assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);
        assert_eq!(f.engine.handover.status().unwrap()["state"],"UNMANAGED");
        assert!(!f.root.join("installed-owner/network-owner-agent").exists());assert_eq!(f.call_count("CheckpointCreate"),0);
    }
    fn fenced_owner_fixture(mode:u8)->(Fixture,Arc<ExportSource>,Value) {
        fence_fixture(export_fixture(mode))
    }
    fn fence_fixture((mut f,source):(Fixture,Arc<ExportSource>))->(Fixture,Arc<ExportSource>,Value) {
        let digest=f.ownership_source_digest();for _ in 0..4 {f.observe();}
        let id=uuid::Uuid::new_v4();let plan=f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":digest}),"local-uid:fixture").unwrap();
        let confirmation=json!({"operationId":id,"confirmationToken":plan["confirmationToken"]});for _ in 0..2 {f.observe();}
        assert_eq!(f.engine.ownership_request("network.nm.ownership.fence",confirmation.clone(),"local-uid:fixture").unwrap()["state"],"FENCED");
        (f,source,confirmation)
    }
    fn historical_fenced_owner_fixture()->(Fixture,Arc<ExportSource>,Value) {
        // A new unit fixture in the historical schema3 format,not a new plan
        // admitted through the modern paired-fence endpoint.
        let (mut f,source)=export_fixture(0);let backend=f.source_digest();for _ in 0..4{f.observe();}
        let deadline=Instant::now()+Duration::from_secs(5);let roles=source.value.lock().unwrap().clone();
        let firewall=roles::Source::firewall_source(source.as_ref(),&roles,deadline).unwrap();
        let (observed,devices)=f.engine.capture_source(deadline).unwrap();assert_eq!(observed["sourceDigest"],backend);
        let baseline=handover::Baseline{source_digest:handover::Baseline::bind_source(&backend,Some(&firewall)).unwrap(),roles:roles.clone(),
            profiles:devices.iter().map(handover::ProfileBinding::observe).collect::<Result<Vec<_>>>().unwrap(),
            firewall_digest:digest(&serde_json::to_value(f.engine.firewall_binding().unwrap()).unwrap()).unwrap(),
            automatic_nat:serde_json::to_value(f.engine.observed_nat(deadline).unwrap()).unwrap(),firewall_source:Some(firewall.clone()),native_transfer:None,firewall_fence:None};
        let id=uuid::Uuid::new_v4();let transfer=handover::template::Transfer::new(&f.root);
        let nonce=transfer.start(id,"local-uid:fixture".into(),baseline.clone()).unwrap();
        roles::Source::export(source.as_ref(),id,&roles,&firewall,&nonce,deadline).unwrap();
        let (binding,_)=transfer.ready(id,"local-uid:fixture").unwrap();
        let plan=f.engine.handover.seed_historical_fenced_plan_fixture(id,"local-uid:fixture".into(),baseline,binding).unwrap();
        (f,source,json!({"operationId":id,"confirmationToken":plan["confirmationToken"]}))
    }
    #[test]
    fn ownership_source_preview_is_explicit_readonly_and_old_network_digest_cannot_admit_a_new_plan() {
        let (mut f,source)=export_fixture(0);let backend=f.source_digest();
        source.offline.store(true,std::sync::atomic::Ordering::Relaxed);
        assert_eq!(f.engine.ownership_request("network.nm.ownership.status",json!({}),"local-uid:fixture").unwrap()["state"],"UNMANAGED");
        assert!(f.engine.ownership_request("network.nm.ownership.status",json!({"includePreparationSource":true}),"local-uid:fixture").is_err());
        source.offline.store(false,std::sync::atomic::Ordering::Relaxed);
        for _ in 0..4{f.observe();}
        let preview=f.engine.ownership_request("network.nm.ownership.status",json!({"includePreparationSource":true}),"local-uid:fixture").unwrap();
        assert_ne!(preview["preparationSource"]["sourceDigest"],backend);
        assert_eq!(preview["preparationSource"]["firewallSource"]["backendPolicyObserved"],false);
        assert!(!f.root.join("nm-template/transaction.json").exists());assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),0);
        for _ in 0..4{f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":uuid::Uuid::new_v4(),"sourceDigest":backend}),"local-uid:fixture").is_err());
        assert!(!f.root.join("nm-template/transaction.json").exists());assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),0);
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn an_unowned_firewall_without_a_registered_model_refuses_preparation() {
        let f = Fixture::new(&["eth0"], &[("eth0", 4, 3)]);
        let parent = f.root.join("installed-owner");
        crate::durable::directory(&parent).unwrap();
        let marker = parent.join("network-owner-agent");
        let store = handover::Store::relocated(&f.root, marker.clone());
        let (f, source) = export_fixture_at(f, 0, marker, store);
        f.observe();
        let error = f.engine.ownership_request("network.nm.ownership.status",
            json!({"includePreparationSource":true}), "local-uid:0").unwrap_err();
        assert!(error.to_string().starts_with("UNSUPPORTED: preparing an unowned firewall"), "{error:#}");
        assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(!f.root.join("nm-template").exists());
    }
    #[tokio::test]
    async fn read_only_ownership_observer_does_not_admit_writes_or_create_writer_records() {
        let (fixture, source) = export_fixture(0);
        let scope = fixture.root.join("read-only-owner-observation");
        crate::durable::directory(&scope).unwrap();
        let nm = Nm::for_test(
            json!({"schemaVersion":1,"interfaces":["eth0"],"writeEnabled":false}),
            fixture.wire.clone(),
            &scope,
        ).unwrap().with_role_source(source.clone()).unwrap();
        let actor = "local-uid:0";
        let status = "network.nm.ownership.status";
        assert_eq!(nm.ownership_request(status.into(), json!({}), actor.into()).await.unwrap()["state"], "UNMANAGED");
        let invalid = json!({"includePreparationSource":true,"includeLegacyKernelSource":true});
        assert!(nm.ownership_request(status.into(), invalid, actor.into()).await.unwrap_err().to_string()
            .contains("select one ownership source review"));
        for operation in ["prepare", "original", "cancel", "fence", "activate", "startup.start"] {
            let error = nm.ownership_request(format!("network.nm.ownership.{operation}"), json!({}), actor.into())
                .await.unwrap_err();
            assert!(error.to_string().contains("NM writes are not configured"), "{operation}: {error}");
        }
        for directory in ["nm", "nm-template", "nm-ownership"] {
            assert!(!scope.join(directory).exists(), "{directory}");
        }
        assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(fixture.call_count("CheckpointCreate"), 0);
        assert_eq!(fixture.call_count("Update2"), 0);
    }
    #[test]
    fn original_firewall_fence_drift_during_once_only_export_never_admits_a_plan_or_exports_again() {
        let (mut f,source)=export_fixture(250);let digest=f.ownership_source_digest();let id=uuid::Uuid::new_v4();for _ in 0..4{f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":digest}),"local-uid:fixture").is_err());
        let cipher=f.root.join(format!("nm-template/{id}.chunk-0.cipher"));let bytes=std::fs::read(&cipher).unwrap();
        let firewall=f.root.join("installed-owner/firewall-owner-agent");let fence_bytes=std::fs::read(&firewall).unwrap();
        for _ in 0..4{f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").is_err());
        assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);assert_eq!(std::fs::read(cipher).unwrap(),bytes);
        assert_eq!(std::fs::read(firewall).unwrap(),fence_bytes);assert!(!f.root.join("nm-ownership/transaction.json").exists());
        assert!(!f.root.join("installed-owner/network-owner-agent").exists());assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn original_prepared_pair_query_retains_its_source_and_ciphertext_after_the_reviewed_firewall_barrier_disappears() {
        let (mut f,source)=export_fixture(0);let firewall=f.root.join("installed-owner/firewall-owner-agent");
        crate::durable::publish_new(&firewall,b"retained original barrier",crate::durable::FileMetadata::private()).unwrap();
        let digest=f.ownership_source_digest();let id=uuid::Uuid::new_v4();for _ in 0..4{f.observe();}
        let plan=f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":digest}),"local-uid:fixture").unwrap();
        let intent=f.root.join(format!("nm-ownership/{id}.intent.json"));let before=std::fs::read(&intent).unwrap();
        let cipher=f.root.join(format!("nm-template/{id}.chunk-0.cipher"));let cipher_before=std::fs::read(&cipher).unwrap();
        std::fs::remove_file(&firewall).unwrap();
        let original=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").unwrap();
        assert_eq!(original["state"],"PREPARED");assert_eq!(original["confirmationToken"],plan["confirmationToken"]);
        for _ in 0..4{f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.fence",json!({"operationId":id,"confirmationToken":plan["confirmationToken"]}),"local-uid:fixture").is_err());
        assert_eq!(std::fs::read(intent).unwrap(),before);assert_eq!(std::fs::read(cipher).unwrap(),cipher_before);
        assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);assert!(!firewall.exists());
        assert!(!f.root.join("installed-owner/network-owner-agent").exists());assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn original_firewall_source_drift_after_the_once_only_export_never_fences_or_exports_again() {
        let (mut f,source)=export_fixture(EXPORT_STORED_FIREWALL_DRIFT);let digest=f.ownership_source_digest();let id=uuid::Uuid::new_v4();for _ in 0..4{f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":digest}),"local-uid:fixture").is_err());
        let file=f.root.join(format!("nm-template/{id}.chunk-0.cipher"));let bytes=std::fs::read(&file).unwrap();
        for _ in 0..4{f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").is_err());
        assert_eq!(std::fs::read(file).unwrap(),bytes);assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);
        assert_eq!(f.engine.handover.status().unwrap()["state"],"UNMANAGED");assert!(!f.root.join("installed-owner/network-owner-agent").exists());
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn complete_legacy_kernel_review_needs_no_confirmed_nft_policy_and_never_exports_fences_or_prepares() {
        let (f,source)=export_fixture(0);
        std::fs::remove_file(f.root.join("firewall/confirmed.json")).unwrap();
        let v4="*filter\n:INPUT DROP [1:2]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:input-kura - [0:0]\n-A INPUT -j input-kura\n-A input-kura -p icmp -j ACCEPT\n-A input-kura -m comment --comment \"keep additional rule\" -j RETURN\nCOMMIT\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -o wan0 -j MASQUERADE\nCOMMIT\n*mangle\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -j MARK --set-mark 1\nCOMMIT\n".to_string();
        let v6="*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -p ipv6-icmp -j DROP\nCOMMIT\n".to_string();
        {let mut fake=f.engine.fake.lock().unwrap();fake.kernel_policy=None;fake.legacy_kernel=Some([v4.clone(),v6.clone(),v4,v6]);}
        for _ in 0..4{f.observe();}
        let preview=f.engine.ownership_request("network.nm.ownership.status",json!({"includeLegacyKernelSource":true}),"local-uid:fixture").unwrap();
        let view=&preview["legacyKernelReview"];
        assert_eq!(view["reviewKind"],"legacy.kernel.source.v1");assert_eq!(view["preparationReady"],false);
        assert_eq!(view["firewallKernel"]["sourceKind"],"iptables.current.unowned.v1");
        assert_eq!(view["firewallKernel"]["snapshot"]["ipv4"]["tables"].as_array().unwrap().len(),3);
        assert_eq!(view["firewallKernel"]["snapshot"]["ipv4"]["tables"][2]["rules"][0]["specification"],"-j MARK --set-mark 1");
        assert_eq!(view["firewallSource"]["backendPolicyObserved"],false);
        assert!(view.get("sourceDigest").is_none() && view["reviewDigest"].as_str().unwrap().len()==64);
        assert!(!f.root.join("firewall/confirmed.json").exists());
        for _ in 0..4{f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":uuid::Uuid::new_v4(),"sourceDigest":view["reviewDigest"]}),"local-uid:fixture").is_err());
        source.offline.store(true,std::sync::atomic::Ordering::Relaxed);
        assert_eq!(f.engine.ownership_request("network.nm.ownership.status",json!({}),"local-uid:fixture").unwrap()["state"],"UNMANAGED");
        assert!(f.engine.ownership_request("network.nm.ownership.status",json!({"includeLegacyKernelSource":true,"includePreparationSource":true}),"local-uid:fixture")
            .unwrap_err().to_string().starts_with("INVALID_ARGUMENT"));
        assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),0);
        assert!(!f.root.join("nm-template/transaction.json").exists() && !f.root.join("installed-owner/network-owner-agent").exists());
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn legacy_origin_controller_review_is_read_only_and_rechecks_the_original_model() {
        struct OriginalModel {roles:roles::Observation,value:Value,reads:std::sync::atomic::AtomicUsize,drift:bool}
        impl roles::Source for OriginalModel {
            fn read(&self,_:Instant)->Result<roles::Observation> {anyhow::bail!("UNSUPPORTED: model read is not a paired drain")}
            fn raw(&self,_:Instant)->Result<roles::Observation> {Ok(self.roles.clone())}
            fn firewall_source(&self,observed:&roles::Observation,_:Instant)->Result<roles::FirewallSource> {
                roles::Origin::new(observed.agent_instance,observed.bridge_epoch,observed,self.value.clone())?.stored(observed)
            }
            fn firewall_origin(&self,observed:&roles::Observation,_:Instant)->Result<Option<roles::Origin>> {
                let mut value=self.value.clone();if self.drift&&self.reads.fetch_add(1,std::sync::atomic::Ordering::SeqCst)>0 {value["families"][0]["allowIcmp"]=json!(true);}
                Ok(Some(roles::Origin::new(observed.agent_instance,observed.bridge_epoch,observed,value)?))
            }
        }
        for drift in [false,true] {
            let mut f=Fixture::new(&["eth0","lan0","wan0"],&[("eth0",4,3),("lan0",4,3),("wan0",4,3)]);
            let (roles,origin,_,_)=handover::native::classify::fixture();let native=handover::native::classify::raw_fixture();
            let source=Arc::new(OriginalModel{roles,value:origin.parameters().unwrap(),reads:std::sync::atomic::AtomicUsize::new(0),drift});
            Arc::get_mut(&mut f.engine).unwrap().set_role_source(source);
            // Deliberately unavailable compatibility view: a raw-native review
            // must not invoke it or synthesize an empty projection.
            {let mut fake=f.engine.fake.lock().unwrap();fake.native_kernel=Some(native);fake.legacy_kernel=None;}
            for _ in 0..4 {f.observe();}
            let result=f.engine.ownership_request("network.nm.ownership.status",json!({"includeLegacyKernelSource":true}),"local-uid:fixture");
            if drift {assert!(result.unwrap_err().to_string().starts_with("CONFLICT"));}
            else {let result=result.unwrap();assert_eq!(result["legacyKernelReview"]["reviewKind"],"legacy.raw.source.v1");assert_eq!(result["legacyKernelReview"]["classification"]["unselectedRuleCount"],4);assert_eq!(result["legacyKernelReview"]["classification"]["preparationReady"],false);}
            assert!(!f.root.join("firewall/confirmed.json").exists());assert!(f.engine.handover.active().unwrap().is_none());
            assert!(!f.root.join("nm-template/transaction.json").exists());assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        }
    }
    #[test]
    fn legacy_review_cannot_reopen_an_original_preparation_or_change_its_ciphertext() {
        let (mut f,source)=export_fixture(0);let digest=f.ownership_source_digest();for _ in 0..4{f.observe();}
        let id=uuid::Uuid::new_v4();let plan=f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":digest}),"local-uid:fixture").unwrap();
        let file=f.root.join(format!("nm-template/{id}.chunk-0.cipher"));let before=std::fs::read(&file).unwrap();
        source.offline.store(true,std::sync::atomic::Ordering::Relaxed);
        let error=f.engine.ownership_request("network.nm.ownership.status",json!({"includeLegacyKernelSource":true}),"local-uid:fixture").unwrap_err();
        assert!(!error.to_string().contains("fixture not configured"));
        let original=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").unwrap();
        assert_eq!(original["confirmationToken"],plan["confirmationToken"]);assert_eq!(original["state"],"PREPARED");
        assert_eq!(std::fs::read(file).unwrap(),before);assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);
        assert!(!f.root.join("installed-owner/network-owner-agent").exists());assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn kernel_policy_source_refuses_missing_drifted_or_foreign_rules_before_template_export() {
        for variant in 0..3 {
            let (mut f,source)=export_fixture(0);let digest=f.ownership_source_digest();for _ in 0..4{f.observe();}
            let preview=f.engine.ownership_request("network.nm.ownership.status",json!({"includePreparationSource":true}),"local-uid:fixture").unwrap();
            assert_eq!(preview["preparationSource"]["firewallKernel"]["sourceKind"],"nft.current.confirmed.v1");
            assert_eq!(preview["preparationSource"]["firewallKernel"]["policy"]["ipv6"]["allowIcmp"],true);
            {let mut fake=f.engine.fake.lock().unwrap();match variant {
                0=>fake.kernel_policy=None,
                1=>{let entries=fake.kernel_policy.as_mut().unwrap()["nftables"].as_array_mut().unwrap();
                    entries.iter_mut().find(|entry|!entry["chain"]["policy"].is_null()).unwrap()["chain"]["policy"]=json!("drop");},
                _=>fake.kernel_policy.as_mut().unwrap()["nftables"].as_array_mut().unwrap().push(json!({"table":{"family":"ip","name":"filter"}})),
            }}
            for _ in 0..4{f.observe();}
            assert!(f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":uuid::Uuid::new_v4(),"sourceDigest":digest}),"local-uid:fixture").is_err());
            assert!(!f.root.join("nm-template/transaction.json").exists());assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),0);
            assert_eq!(f.engine.handover.status().unwrap()["state"],"UNMANAGED");assert!(!f.root.join("installed-owner/network-owner-agent").exists());
            assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        }
    }
    #[test]
    fn kernel_policy_drift_blocks_new_fence_but_preserves_original_plan_queries_and_ciphertext() {
        let (mut f,source)=export_fixture(0);let digest=f.ownership_source_digest();for _ in 0..4{f.observe();}
        let id=uuid::Uuid::new_v4();let plan=f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":digest}),"local-uid:fixture").unwrap();
        let cipher=f.root.join(format!("nm-template/{id}.chunk-0.cipher"));let before=std::fs::read(&cipher).unwrap();
        f.engine.fake.lock().unwrap().kernel_policy.as_mut().unwrap()["nftables"].as_array_mut().unwrap().push(json!({"table":{"family":"inet","name":"foreign"}}));
        for _ in 0..4{f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.fence",json!({"operationId":id,"confirmationToken":plan["confirmationToken"]}),"local-uid:fixture").is_err());
        source.offline.store(true,std::sync::atomic::Ordering::Relaxed);
        let query=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").unwrap();
        assert_eq!(query["state"],"PREPARED");assert_eq!(query["confirmationToken"],plan["confirmationToken"]);
        assert_eq!(f.engine.ownership_request("network.nm.ownership.status",json!({}),"local-uid:fixture").unwrap()["state"],"PREPARED");
        assert_eq!(std::fs::read(cipher).unwrap(),before);assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);
        assert!(!f.root.join("installed-owner/network-owner-agent").exists());assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn kernel_policy_drift_after_startup_completion_never_publishes_a_new_owner_lease() {
        let (f,source,request)=completed_startup_fixture();
        f.engine.fake.lock().unwrap().kernel_policy.as_mut().unwrap()["nftables"].as_array_mut().unwrap().push(json!({"table":{"family":"inet","name":"foreign"}}));
        for _ in 0..4{f.observe();}
        let error=f.engine.ownership_request("network.nm.ownership.activate",json!({"operationId":request["operationId"],"confirmationToken":request["confirmationToken"]}),"local-uid:fixture").unwrap_err();
        assert!(error.to_string().contains("foreign kernel"),"{error}");
        assert!(f.engine.handover.active().unwrap().is_none());assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);
        assert_eq!(f.engine.fake.lock().unwrap().writes,0);assert_eq!(f.call_count("CheckpointCreate"),0);
    }
    #[test]
    fn kernel_policy_nat_observation_requires_the_actual_committed_original_receipt() {
        let f=confirmed_nat_fixture();crate::firewall::seed_confirmed_core_fixture(&f.root).unwrap();
        let mut kernel=crate::firewall::confirmed_kernel_fixture(&f.root).unwrap();
        let table=f.engine.fake.lock().unwrap().table.clone().unwrap();kernel["nftables"].as_array_mut().unwrap().extend(table["nftables"].as_array().unwrap().iter().cloned());
        let before_writes=f.engine.fake.lock().unwrap().writes;let before=std::fs::read(f.root.join("nm/nat-confirmed.json")).unwrap();
        let observed=crate::firewall::initialized_kernel_source(&f.root,&kernel).unwrap();
        assert_eq!(observed["automaticNatAuthority"]["ownership"]["operationId"],f.journal().operation_id.to_string());
        assert_eq!(std::fs::read(f.root.join("nm/nat-confirmed.json")).unwrap(),before);
        let receipt=f.engine.receipt_path(f.journal().operation_id);std::fs::write(&receipt,b"tampered-original").unwrap();
        assert!(crate::firewall::initialized_kernel_source(&f.root,&kernel).is_err());
        assert_eq!(std::fs::read(receipt).unwrap(),b"tampered-original");assert_eq!(f.engine.fake.lock().unwrap().writes,before_writes);
    }
    #[test]
    fn actual_owner_controller_refuses_every_new_activation_without_a_terminal_startup_child() {
        let (f,source,confirmation)=fenced_owner_fixture(0);for _ in 0..2 {f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.activate",confirmation.clone(),"local-uid:fixture").unwrap_err().to_string().contains("terminal startup receipt"));
        assert!(f.engine.ownership_request("network.nm.ownership.activate",confirmation.clone(),"local-uid:fixture").is_err());
        let original=json!({"operationId":confirmation["operationId"]});
        assert_eq!(f.engine.ownership_request("network.nm.ownership.original",original,"local-uid:fixture").unwrap()["state"],"FENCED");
        assert_eq!(source.owner_reads.load(std::sync::atomic::Ordering::Relaxed),0);assert!(f.engine.handover.active().unwrap().is_none());
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);
        assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn actual_owner_controller_refuses_wrong_plan_replaced_registration_or_backend_drift_before_lease() {
        for mode in [8,14,0] {
            let (f,source,confirmation)=completed_startup_fixture();source.startup_mode.store(mode,std::sync::atomic::Ordering::Relaxed);
            if mode==0 {*f.wire.version.lock().unwrap()+=1;}
            for _ in 0..2 {f.observe();}
            assert!(f.engine.ownership_request("network.nm.ownership.activate",confirmation,"local-uid:fixture").is_err());
            assert_eq!(f.engine.handover.status().unwrap()["state"],"FENCED");assert!(f.engine.handover.active().unwrap().is_none());
            assert!(!f.root.join("nm-ownership/confirmed.json").exists());
        }
    }
    #[test]
    fn delegation_endpoints_refuse_missing_managed_scope_before_any_export_or_fence() {
        for status in ["netIPv4StatusEnabledWAN","netIPv4StatusEnabledLAN","netIPv4StatusL2Only","netIPv4StatusDisabled"] {
            let (mut f,source)=export_fixture(0);
            let mut value=serde_json::to_value(source.value.lock().unwrap().roles.clone()).unwrap();
            value["interfaces"].as_array_mut().unwrap().push(json!({"id":"eth1","type":"ETHERNET","ipv4Status":status,"natEnabled":true}));
            source.value.lock().unwrap().roles=roles::ConfigurationRoles::parse(value).unwrap();
            let digest=f.ownership_source_digest();for _ in 0..4 {f.observe();}
            let outcome=f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":uuid::Uuid::new_v4(),"sourceDigest":digest}),"local-uid:fixture");
            assert!(outcome.is_err(),"an unadopted managed CM interface must refuse the whole original preparation");
            assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),0);
            assert_eq!(f.engine.handover.status().unwrap()["state"],"UNMANAGED");
            assert!(!f.root.join("nm-template/transaction.json").exists());
            assert!(!f.root.join("installed-owner/network-owner-agent").exists());
            assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        }
    }
    #[test]
    fn delegation_endpoints_refuse_cm_type_alias_before_any_export_or_fence() {
        let (mut f,source)=export_fixture(0);
        let mut value=serde_json::to_value(source.value.lock().unwrap().roles.clone()).unwrap();value["interfaces"][0]["type"]=json!("MODEM");
        source.value.lock().unwrap().roles=roles::ConfigurationRoles::parse(value).unwrap();
        let digest=f.ownership_source_digest();for _ in 0..4 {f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":uuid::Uuid::new_v4(),"sourceDigest":digest}),"local-uid:fixture").is_err(),
            "an Ethernet backend name cannot attest a logical modem solely by sharing its ID");
        assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),0);assert_eq!(f.engine.handover.status().unwrap()["state"],"UNMANAGED");
        assert!(!f.root.join("installed-owner/network-owner-agent").exists());assert_eq!(f.call_count("CheckpointCreate"),0);
    }
    #[test]
    fn actual_owner_original_query_settles_only_existing_original_lease_and_receipt_without_republishing() {
        for missing_receipt in [false,true] {
            let (f,source,confirmation)=historical_fenced_owner_fixture();for _ in 0..2 {f.observe();}
            let owner=roles::Source::owner(source.as_ref(),Instant::now()+Duration::from_secs(5)).unwrap();
            {let _guard=Guard::acquire(&f.root,Subsystem::NmOwnership).unwrap();
                f.engine.handover.seed_legacy_owner_fixture(confirmation["confirmationToken"].as_str().unwrap(),"local-uid:fixture",owner,|_|Ok(())).unwrap();}
            let id=confirmation["operationId"].as_str().unwrap();let path=f.root.join("nm-ownership/transaction.json");
            let mut journal:Value=serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            journal["state"]=json!("LEASE_INTENT");journal["receiptSha256"]=Value::Null;
            crate::durable::json(&path,&journal).unwrap();
            let lease=f.root.join("nm-ownership").join(format!("{id}.lease.json"));let before=std::fs::read(&lease).unwrap();
            let receipt=f.root.join("nm-ownership").join(format!("{id}.receipt.json"));
            if missing_receipt {std::fs::remove_file(&receipt).unwrap();}
            for _ in 0..2 {f.observe();}
            let result=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture");
            if missing_receipt {assert!(result.unwrap_err().to_string().contains("OUTCOME_UNKNOWN"));assert!(!receipt.exists());}
            else {assert_eq!(result.unwrap()["state"],"COMMITTED");}
            assert_eq!(std::fs::read(&lease).unwrap(),before);assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);
            assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);
        }
    }
    #[test]
    fn historical_single_fence_cannot_gain_a_fresh_owner_or_new_startup_challenge() {
        let (f,source,request)=historical_fenced_owner_fixture();let journal=f.root.join("nm-ownership/transaction.json");
        let before=std::fs::read(&journal).unwrap();let owner_reads=source.owner_reads.load(std::sync::atomic::Ordering::Relaxed);
        assert!(f.engine.ownership_request("network.nm.ownership.activate",request.clone(),"local-uid:fixture").unwrap_err().to_string().starts_with("UNSUPPORTED"));
        assert_eq!(std::fs::read(journal).unwrap(),before);assert_eq!(source.owner_reads.load(std::sync::atomic::Ordering::Relaxed),owner_reads);
        assert!(!f.root.join("installed-owner/firewall-owner-agent").exists());assert!(!f.root.join(format!("nm-ownership/{}.lease.json",request["operationId"].as_str().unwrap())).exists());
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn actual_owner_original_query_uncertain_backend_keeps_unknown_wire_code_and_original_receipts() {
        for legacy in [true,false] {for changed_nm_owner in [false,true] {
            let (f,source,request)=if legacy{historical_fenced_owner_fixture()}else{completed_startup_fixture()};
            if legacy {
                let owner=roles::Source::owner(source.as_ref(),Instant::now()+Duration::from_secs(5)).unwrap();
                let _guard=Guard::acquire(&f.root,Subsystem::NmOwnership).unwrap();
                f.engine.handover.seed_legacy_owner_fixture(request["confirmationToken"].as_str().unwrap(),"local-uid:fixture",owner,|_|Ok(())).unwrap();
            }else {
                for _ in 0..4{f.observe();}
                f.engine.ownership_request("network.nm.ownership.activate",json!({"operationId":request["operationId"],"confirmationToken":request["confirmationToken"]}),"local-uid:fixture").unwrap();
            }
            let path=f.root.join("nm-ownership/transaction.json");let mut journal:Value=serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            journal["state"]=json!("LEASE_INTENT");journal["receiptSha256"]=Value::Null;crate::durable::json(&path,&journal).unwrap();
            let id=request["operationId"].as_str().unwrap();let paths=[path,f.root.join(format!("nm-ownership/{id}.lease.json")),f.root.join(format!("nm-ownership/{id}.receipt.json"))];
            let before=paths.iter().map(|path|std::fs::read(path).unwrap()).collect::<Vec<_>>();
            let owner_reads=source.owner_reads.load(std::sync::atomic::Ordering::Relaxed);
            // Core protocol availability is independent of the actual NM backend.
            // Missing source frames or a replaced D-Bus service identity must
            // prevent acknowledgement even with complete historical receipts.
            if changed_nm_owner {for _ in 0..4{f.observe();}*f.wire.owner.lock().unwrap()=":1.9".into();}
            else {f.wire.script.lock().unwrap().clear();}
            let error=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").unwrap_err();
            assert_eq!(crate::network::error_code(&error),"OUTCOME_UNKNOWN","original lease intent remains unresolved: {error}");
            for (path,bytes) in paths.iter().zip(before) {assert_eq!(std::fs::read(path).unwrap(),bytes);}
            assert_eq!(source.owner_reads.load(std::sync::atomic::Ordering::Relaxed),owner_reads);
            assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        }}
    }
    #[test]
    fn actual_startup_preparation_joins_the_original_fenced_operation_without_dispatch_or_activation() {
        let (mut f,_,confirmation)=fenced_owner_fixture(0);
        let installed=handover::startup::tests::install(&f.root);
        let args_before=std::fs::read(&installed.args).unwrap();let profile_before=std::fs::read(&installed.profile).unwrap();
        let engine=Arc::get_mut(&mut f.engine).unwrap();engine.startup_profile=installed.profile.clone();engine.startup_systemctl=installed.systemctl.clone();
        for _ in 0..2 {f.observe();}
        let proposed=f.engine.ownership_request("network.nm.ownership.startup.prepare",confirmation.clone(),"local-uid:fixture").unwrap();
        assert_eq!(proposed["operationId"],confirmation["operationId"]);assert_eq!(proposed["executionAvailable"],false);
        assert_eq!(proposed["startupFilesChanged"],false);assert_ne!(proposed["confirmationToken"],confirmation["confirmationToken"]);
        let public=f.engine.ownership_request("network.nm.ownership.status",json!({}),"local-uid:fixture").unwrap();
        assert!(public["startup"]["confirmationToken"].is_null());assert!(!public.to_string().contains("fixture-secret-must-not-leak"));
        let original=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":confirmation["operationId"]}),"local-uid:fixture").unwrap();
        assert_eq!(original["startup"],proposed);
        assert!(f.engine.ownership_request("network.nm.ownership.startup.prepare",confirmation.clone(),"other-actor").is_err());
        let mut injected=confirmation.clone();injected["profilePath"]=json!("/untrusted/caller-profile");
        assert!(f.engine.ownership_request("network.nm.ownership.startup.prepare",injected,"local-uid:fixture").is_err());
        for _ in 0..2 {f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.activate",confirmation,"local-uid:fixture").unwrap_err().to_string().contains("prepared startup"));
        assert_eq!(f.engine.handover.status().unwrap()["state"],"FENCED");assert!(f.engine.handover.active().unwrap().is_none());
        assert_eq!(std::fs::read(&installed.args).unwrap(),args_before);assert_eq!(std::fs::read(&installed.profile).unwrap(),profile_before);
        let calls=std::fs::read_to_string(installed.calls).unwrap();assert_eq!(calls.lines().count(),6);assert!(calls.lines().all(|line|line.starts_with("show ")));
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    fn startup_association_fixture(mode:u8)->(Fixture,Arc<ExportSource>,Value) {
        let (mut f,source,confirmation)=fenced_owner_fixture(mode);let installed=handover::startup::tests::install(&f.root);
        let engine=Arc::get_mut(&mut f.engine).unwrap();engine.startup_profile=installed.profile;engine.startup_systemctl=installed.systemctl;
        for _ in 0..2 {f.observe();}
        let prepared=f.engine.ownership_request("network.nm.ownership.startup.prepare",confirmation.clone(),"local-uid:fixture").unwrap();
        let mut request=confirmation;request["startupConfirmationToken"]=prepared["confirmationToken"].clone();(f,source,request)
    }
    #[test]
    fn startup_association_controller_binds_current_registered_jvm_and_retains_one_read_only_original_receipt() {
        for rebound in [false,true] {
            let (f,source,request)=startup_association_fixture(0);
            if rebound {let mut current=source.value.lock().unwrap();current.agent_instance=uuid::Uuid::new_v4();current.bridge_epoch=2;}
            for _ in 0..4 {f.observe();}
            let observed=f.engine.ownership_request("network.nm.ownership.startup.verify",request.clone(),"local-uid:fixture").unwrap();
            assert_eq!(observed["state"],"OLD_JVM_ASSOCIATED");assert_eq!(observed["oldJvmAssociationVerified"],true);
            assert_eq!(observed["executionAvailable"],false);assert_eq!(observed["unitActionsIssued"],false);
            let reads=source.association_reads.load(std::sync::atomic::Ordering::Relaxed);assert_eq!(reads,1);assert_eq!(source.owner_reads.load(std::sync::atomic::Ordering::Relaxed),0);
            let id=request["operationId"].as_str().unwrap();let proof=f.root.join(format!("nm-ownership/{id}.startup-old-jvm.json"));let before=std::fs::read(&proof).unwrap();
            let calls=std::fs::read(f.root.join("systemctl-calls")).unwrap();
            let query=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").unwrap();assert_eq!(query["startup"],observed);
            for _ in 0..2 {f.observe();}
            assert_eq!(f.engine.ownership_request("network.nm.ownership.startup.verify",request,"local-uid:fixture").unwrap(),observed);
            assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),reads);assert_eq!(std::fs::read(proof).unwrap(),before);
            assert_eq!(std::fs::read(f.root.join("systemctl-calls")).unwrap(),calls);assert!(f.engine.handover.active().unwrap().is_none());
            assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        }
    }
    #[test]
    fn startup_association_controller_refuses_wrong_jvm_profile_context_role_or_registration_before_receipt() {
        for mode in [4,5,6,7,8,9,10] {
            let (f,_,request)=startup_association_fixture(mode);for _ in 0..4 {f.observe();}
            assert!(f.engine.ownership_request("network.nm.ownership.startup.verify",request.clone(),"local-uid:fixture").is_err());
            let id=request["operationId"].as_str().unwrap();assert!(!f.root.join(format!("nm-ownership/{id}.startup-old-jvm.json")).exists());
            assert_eq!(f.engine.handover.status().unwrap()["startup"]["oldJvmAssociationVerified"],false);assert!(f.engine.handover.active().unwrap().is_none());
            assert!(std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().all(|line|line.starts_with("show ")));
            assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);
        }
    }
    #[test]
    fn startup_association_refuses_caller_authority_and_mismatched_original_tokens_without_a_jvm_read() {
        let (f,source,request)=startup_association_fixture(0);
        for (field,value) in [("confirmationToken",json!("f".repeat(32))),("startupConfirmationToken",json!("e".repeat(32))),
            ("processId",json!(4321)),("profileId",json!("caller-profile")),("ready",json!(true))] {
            let mut wrong=request.clone();wrong[field]=value;for _ in 0..2 {f.observe();}
            assert!(f.engine.ownership_request("network.nm.ownership.startup.verify",wrong,"local-uid:fixture").is_err());
        }
        for _ in 0..2 {f.observe();}
        assert!(f.engine.ownership_request("network.nm.ownership.startup.verify",request.clone(),"local-uid:other").is_err());
        let id=request["operationId"].as_str().unwrap();assert!(!f.root.join(format!("nm-ownership/{id}.startup-old-jvm.json")).exists());
        assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        assert!(std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().all(|line|line.starts_with("show ")));
    }
    #[test]
    fn startup_files_controller_publishes_the_original_stopped_generation_with_kura_off_and_retains_original_queries() {
        let (f,source,request)=startup_files_fixture();let config:crate::recovery::ordinary_profile::Config=serde_json::from_slice(&std::fs::read(f.root.join("ordinary-profile.json")).unwrap()).unwrap();
        let args=std::fs::read(&config.jvm_args_path).unwrap();let grant=std::fs::read(f.root.join("ordinary-profile.json")).unwrap();for _ in 0..4{f.observe();}
        let published=f.engine.ownership_request("network.nm.ownership.startup.publish",request.clone(),"local-uid:fixture").unwrap();
        assert_eq!(published["state"],"FILES_PUBLISHED");assert_eq!(published["startupFilesChanged"],true);assert_eq!(published["systemAdoptionVerified"],false);assert_eq!(published["publication"]["profileSelectionCommitted"],false);
        assert_ne!(std::fs::read(&config.jvm_args_path).unwrap(),args);assert_eq!(std::fs::read(f.root.join("ordinary-profile.json")).unwrap(),grant);
        let calls=std::fs::read(f.root.join("systemctl-calls")).unwrap();for _ in 0..2{f.observe();}
        assert_eq!(f.engine.ownership_request("network.nm.ownership.startup.publish",request.clone(),"local-uid:fixture").unwrap(),published);
        let original=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":request["operationId"]}),"local-uid:fixture").unwrap();assert_eq!(original["startup"],published);
        assert_eq!(std::fs::read(f.root.join("systemctl-calls")).unwrap(),calls);assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),2);
        assert_eq!(String::from_utf8(calls).unwrap().lines().filter(|line|!line.starts_with("show ")).collect::<Vec<_>>(),vec!["stop yofc-kura-fixture.service"]);
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);assert!(f.engine.handover.active().unwrap().is_none());
    }
    #[test]
    fn file_recovery_controller_restores_original_arguments_with_kura_off_and_keeps_all_other_writers_fenced() {
        let (f,source,mut request)=startup_files_fixture();for _ in 0..4{f.observe();}
        f.engine.ownership_request("network.nm.ownership.startup.publish",request.clone(),"local-uid:fixture").unwrap();
        handover::startup::tests::enable_job_at(&f.root);request["recoveryId"]=json!(uuid::Uuid::new_v4());for _ in 0..4{f.observe();}
        let review=f.engine.ownership_request("network.nm.ownership.startup.recovery.prepare",request.clone(),"local-uid:fixture").unwrap();
        assert_eq!(review["state"],"PREPARED");let original_request=request.clone();request["recoveryConfirmationToken"]=review["confirmationToken"].clone();for _ in 0..4{f.observe();}
        let restored=f.engine.ownership_request("network.nm.ownership.startup.recovery.execute",request.clone(),"local-uid:fixture").unwrap();
        assert_eq!(restored["state"],"ARGUMENTS_RESTORED");assert_eq!(restored["systemAdoptionVerified"],false);
        let config:crate::recovery::ordinary_profile::Config=serde_json::from_slice(&std::fs::read(f.root.join("ordinary-profile.json")).unwrap()).unwrap();
        let bytes=std::fs::read(&config.jvm_args_path).unwrap();assert!(config.profile_files.iter().any(|pin|pin.path==config.jvm_args_path && pin.sha256==crate::durable::hash(&bytes)));
        let calls=std::fs::read(f.root.join("systemctl-calls")).unwrap();
        // No backend or JVM fixture responses are queued: original recovery
        // receipt reads and repeated execute must not perform fresh admission.
        assert_eq!(f.engine.ownership_request("network.nm.ownership.startup.recovery.original",original_request,"local-uid:fixture").unwrap(),restored);
        assert_eq!(f.engine.ownership_request("network.nm.ownership.startup.recovery.execute",request.clone(),"local-uid:fixture").unwrap(),restored);
        assert_eq!(std::fs::read(f.root.join("systemctl-calls")).unwrap(),calls);
        for kind in [Subsystem::Recovery,Subsystem::SystemControl,Subsystem::OrdinaryBoot,Subsystem::Nm,Subsystem::Firewall]{assert!(Guard::acquire(&f.root,kind).is_err());}
        assert!(f.engine.handover.active().unwrap().is_none());assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),2);
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        assert_eq!(String::from_utf8(calls).unwrap().lines().filter(|line|!line.starts_with("show ")).collect::<Vec<_>>(),vec!["stop yofc-kura-fixture.service"]);
    }
    #[test]
    fn file_recovery_controller_refuses_caller_paths_tokens_actor_and_changed_backend_before_its_own_intent() {
        for invalid in ["actor","parent-token","child-token","recovery-token","path","ready","source"] {
            let (f,_,mut request)=startup_files_fixture();for _ in 0..4{f.observe();}
            f.engine.ownership_request("network.nm.ownership.startup.publish",request.clone(),"local-uid:fixture").unwrap();
            handover::startup::tests::enable_job_at(&f.root);request["recoveryId"]=json!(uuid::Uuid::new_v4());for _ in 0..4{f.observe();}
            let review=f.engine.ownership_request("network.nm.ownership.startup.recovery.prepare",request.clone(),"local-uid:fixture").unwrap();
            request["recoveryConfirmationToken"]=review["confirmationToken"].clone();
            match invalid {
                "parent-token"=>request["confirmationToken"]=json!("e".repeat(32)),"child-token"=>request["startupConfirmationToken"]=json!("f".repeat(32)),
                "recovery-token"=>request["recoveryConfirmationToken"]=json!("a".repeat(32)),"path"=>request["backupPath"]=json!("/caller/backup"),
                "ready"=>request["stopped"]=json!(true),"source"=>f.engine.fake.lock().unwrap().forwarding_blocked=true,_=>{},
            }
            for _ in 0..4{f.observe();}
            assert!(f.engine.ownership_request("network.nm.ownership.startup.recovery.execute",request.clone(),if invalid=="actor"{"local-uid:other"}else{"local-uid:fixture"}).is_err());
            assert!(!f.root.join(format!("nm-ownership/{}.startup-recovery-{}.intent.json",request["operationId"].as_str().unwrap(),request["recoveryId"].as_str().unwrap())).exists());
            assert!(f.engine.handover.active().unwrap().is_none());assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        }
    }
    fn startup_files_fixture()->(Fixture,Arc<ExportSource>,Value) {
        stop_fixture(fenced_owner_fixture(0))
    }
    fn stop_fixture((mut f,source,confirmation):(Fixture,Arc<ExportSource>,Value))->(Fixture,Arc<ExportSource>,Value) {
        let mut installed=handover::startup::tests::install(&f.root);
        handover::startup::tests::place_arguments_in_home(&mut installed);handover::startup::tests::enable_stop(&installed,"success");
        let engine=Arc::get_mut(&mut f.engine).unwrap();engine.startup_profile=installed.profile;engine.startup_systemctl=installed.systemctl;
        for _ in 0..2{f.observe();}
        let prepared=f.engine.ownership_request("network.nm.ownership.startup.prepare",confirmation.clone(),"local-uid:fixture").unwrap();let mut request=confirmation;request["startupConfirmationToken"]=prepared["confirmationToken"].clone();
        for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.verify",request.clone(),"local-uid:fixture").unwrap();
        for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.stop",request.clone(),"local-uid:fixture").unwrap();
        Arc::get_mut(&mut f.engine).unwrap().role_source=None;(f,source,request)
    }
    fn started_startup_fixture()->(Fixture,Arc<ExportSource>,Value) {
        start_fixture(startup_files_fixture())
    }
    fn start_fixture((mut f,source,request):(Fixture,Arc<ExportSource>,Value))->(Fixture,Arc<ExportSource>,Value) {
        for _ in 0..4 {f.observe();}
        f.engine.ownership_request("network.nm.ownership.startup.publish",request.clone(),"local-uid:fixture").unwrap();
        handover::startup::tests::enable_start_at(&f.root,"success");for _ in 0..4 {f.observe();}
        f.engine.ownership_request("network.nm.ownership.startup.start",request.clone(),"local-uid:fixture").unwrap();
        source.value.lock().unwrap().bridge_epoch+=1;Arc::get_mut(&mut f.engine).unwrap().set_role_source(source.clone());(f,source,request)
    }
    fn completed_startup_fixture()->(Fixture,Arc<ExportSource>,Value) {
        complete_fixture(started_startup_fixture())
    }
    fn complete_fixture((f,source,request):(Fixture,Arc<ExportSource>,Value))->(Fixture,Arc<ExportSource>,Value) {
        for _ in 0..4 {f.observe();}
        let verified=f.engine.ownership_request("network.nm.ownership.startup.complete",request.clone(),"local-uid:fixture").unwrap();
        assert_eq!(verified["state"],"STARTUP_VERIFIED");assert_eq!(verified["systemAdoptionVerified"],false);(f,source,request)
    }
    #[test]
    fn startup_terminal_controller_uses_fresh_jvm_core_and_drain_then_rechecks_them_before_a_new_versioned_lease() {
        let (mut f,source,request)=completed_startup_fixture();
        assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),3);assert_eq!(source.owner_reads.load(std::sync::atomic::Ordering::Relaxed),1);
        assert_eq!(source.drain_reads.load(std::sync::atomic::Ordering::Relaxed),2);
        for kind in [Subsystem::Recovery,Subsystem::SystemControl,Subsystem::OrdinaryBoot,Subsystem::Nm] {assert!(Guard::acquire(&f.root,kind).is_err());}
        // A legitimate fresh agent/bridge registration of the same JVM must
        // reauthenticate instead of rewriting its historical completion receipt.
        {let mut value=source.value.lock().unwrap();value.agent_instance=uuid::Uuid::new_v4();value.bridge_epoch=3;}
        for _ in 0..4 {f.observe();}
        let confirmation=json!({"operationId":request["operationId"],"confirmationToken":request["confirmationToken"]});
        assert_eq!(f.engine.ownership_request("network.nm.ownership.activate",confirmation,"local-uid:fixture").unwrap()["state"],"COMMITTED");
        let id=request["operationId"].as_str().unwrap();let lease:Value=serde_json::from_slice(&std::fs::read(f.root.join(format!("nm-ownership/{id}.lease.json"))).unwrap()).unwrap();
        assert_eq!(lease["schemaVersion"],4);assert_eq!(lease["startupReceiptSha256"],crate::durable::hash(&std::fs::read(f.root.join(format!("nm-ownership/{id}.startup-completion.json"))).unwrap()));
        assert_eq!(lease["firewallMarker"]["sha256"],crate::durable::hash(&std::fs::read(f.root.join("installed-owner/firewall-owner-agent")).unwrap()));
        assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),4);assert_eq!(source.owner_reads.load(std::sync::atomic::Ordering::Relaxed),2);
        assert_eq!(source.drain_reads.load(std::sync::atomic::Ordering::Relaxed),4);
        source.offline.store(true,std::sync::atomic::Ordering::Relaxed);Arc::get_mut(&mut f.engine).unwrap().role_source=None;
        std::fs::remove_file(f.root.join("unit-state")).unwrap();std::fs::remove_file(f.root.join("unit-definition")).unwrap();f.observe();
        assert!(f.engine.capture_source(Instant::now()+Duration::from_secs(5)).is_ok());
        assert_eq!(std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().filter(|line|!line.starts_with("show ")).collect::<Vec<_>>(),
            vec!["stop yofc-kura-fixture.service","start yofc-kura-fixture.service"]);
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn startup_terminal_controller_refuses_old_or_wrong_jvm_context_registration_core_drain_and_changes_during_observation() {
        for mode in 1..=18 {
            let (f,source,request)=started_startup_fixture();source.startup_mode.store(mode,std::sync::atomic::Ordering::Relaxed);for _ in 0..4 {f.observe();}
            assert!(f.engine.ownership_request("network.nm.ownership.startup.complete",request.clone(),"local-uid:fixture").is_err(),"invalid witness mode {mode}");
            let id=request["operationId"].as_str().unwrap();assert!(!f.root.join(format!("nm-ownership/{id}.startup-completion.json")).exists());
            assert!(f.engine.handover.active().unwrap().is_none());assert!(!f.root.join(format!("nm-ownership/{id}.lease.json")).exists());
            assert_eq!(std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().filter(|line|line.starts_with("start ")).count(),1);
            assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        }
    }
    #[test]
    fn startup_terminal_current_witnesses_are_required_again_after_historical_completion_before_each_new_activation() {
        for mode in [1,3,7,9,10,11,12,13,15,16,17,18] {
            let (f,source,request)=completed_startup_fixture();source.startup_mode.store(mode,std::sync::atomic::Ordering::Relaxed);for _ in 0..4{f.observe();}
            let confirmation=json!({"operationId":request["operationId"],"confirmationToken":request["confirmationToken"]});
            assert!(f.engine.ownership_request("network.nm.ownership.activate",confirmation,"local-uid:fixture").is_err(),"stale completion cannot replace fresh mode {mode}");
            assert!(f.engine.handover.active().unwrap().is_none());assert!(!f.root.join(format!("nm-ownership/{}.lease.json",request["operationId"].as_str().unwrap())).exists());
            assert_eq!(std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().filter(|line|line.starts_with("start ")).count(),1);
        }
    }
    #[test]
    fn startup_terminal_original_queries_acknowledge_only_existing_proof_and_never_recreate_acknowledged_missing_receipts() {
        for missing in [false,true] {
            let (mut f,source,request)=completed_startup_fixture();let id=request["operationId"].as_str().unwrap();let receipt=f.root.join(format!("nm-ownership/{id}.startup-completion.json"));let raw=std::fs::read(&receipt).unwrap();
            if missing {std::fs::remove_file(&receipt).unwrap();}else{
                let path=f.root.join(format!("nm-ownership/{id}.startup-journal.json"));let mut value:Value=serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();value.as_object_mut().unwrap().remove("completionReceiptSha256");crate::durable::json(&path,&value).unwrap();
            }
            Arc::get_mut(&mut f.engine).unwrap().role_source=None;std::fs::remove_file(f.root.join("unit-state")).unwrap();
            let calls=std::fs::read(f.root.join("systemctl-calls")).unwrap();for _ in 0..4 {f.observe();}
            let outcome=f.engine.ownership_request("network.nm.ownership.startup.complete",request,"local-uid:fixture");
            if missing {assert!(outcome.unwrap_err().to_string().contains("OUTCOME_UNKNOWN"));assert!(!receipt.exists());}
            else {assert_eq!(outcome.unwrap()["state"],"STARTUP_VERIFIED");assert_eq!(std::fs::read(receipt).unwrap(),raw);}
            assert_eq!(std::fs::read(f.root.join("systemctl-calls")).unwrap(),calls);assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),3);
        }
    }
    #[test]
    fn startup_terminal_refuses_caller_readiness_wrong_tokens_and_unproven_start_without_new_service_actions() {
        for invalid in ["actor","parent-token","child-token","ready","processId","missing-start","missing-completion"] {
            let (f,source,request)=if invalid=="missing-completion"{completed_startup_fixture()}else{started_startup_fixture()};let mut wrong=request.clone();
            match invalid {
                "parent-token"=>wrong["confirmationToken"]=json!("e".repeat(32)),"child-token"=>wrong["startupConfirmationToken"]=json!("f".repeat(32)),
                "ready"=>wrong["ready"]=json!(true),"processId"=>wrong["processId"]=json!(5432),
                "missing-start"|"missing-completion"=>{let suffix=if invalid=="missing-start"{"startup-start-receipt"}else{"startup-completion"};std::fs::remove_file(f.root.join(format!("nm-ownership/{}.{suffix}.json",request["operationId"].as_str().unwrap()))).unwrap();},_=>{},
            }
            let calls=std::fs::read(f.root.join("systemctl-calls")).unwrap();let reads=source.association_reads.load(std::sync::atomic::Ordering::Relaxed);for _ in 0..4 {f.observe();}
            assert!(f.engine.ownership_request("network.nm.ownership.startup.complete",wrong,if invalid=="actor"{"local-uid:other"}else{"local-uid:fixture"}).is_err());
            assert_eq!(std::fs::read(f.root.join("systemctl-calls")).unwrap(),calls);assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),reads);
            assert!(f.engine.handover.active().unwrap().is_none());
        }
    }
    #[test]
    fn startup_terminal_original_new_lease_recovery_retains_its_startup_binding_and_never_republishes_missing_evidence() {
        for missing in ["none","completion","child"] {
            let (f,_,request)=completed_startup_fixture();for _ in 0..4 {f.observe();}
            f.engine.ownership_request("network.nm.ownership.activate",json!({"operationId":request["operationId"],"confirmationToken":request["confirmationToken"]}),"local-uid:fixture").unwrap();
            let id=request["operationId"].as_str().unwrap();let path=f.root.join("nm-ownership/transaction.json");let mut journal:Value=serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();journal["state"]=json!("LEASE_INTENT");journal["receiptSha256"]=Value::Null;crate::durable::json(&path,&journal).unwrap();
            let lease=f.root.join(format!("nm-ownership/{id}.lease.json"));let raw=std::fs::read(&lease).unwrap();let completion=f.root.join(format!("nm-ownership/{id}.startup-completion.json"));
            if missing=="completion" {std::fs::remove_file(&completion).unwrap();}
            if missing=="child" {for suffix in ["startup-plan","startup-journal"] {std::fs::remove_file(f.root.join(format!("nm-ownership/{id}.{suffix}.json"))).unwrap();}}
            for _ in 0..4 {f.observe();}let result=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture");
            if missing!="none" {assert!(result.unwrap_err().to_string().contains("OUTCOME_UNKNOWN"));
                if missing=="completion" {assert!(!completion.exists());}else{assert!(!f.root.join(format!("nm-ownership/{id}.startup-plan.json")).exists());assert!(!f.root.join(format!("nm-ownership/{id}.startup-journal.json")).exists());}
            }else{assert_eq!(result.unwrap()["state"],"COMMITTED");}
            assert_eq!(std::fs::read(lease).unwrap(),raw);assert_eq!(std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().filter(|line|line.starts_with("start ")).count(),1);
        }
    }
    #[test]
    fn original_published_lease_receipts_remain_queryable_without_a_new_core_protocol_or_service_dispatch() {
        for legacy in [true,false] {
            let (mut f,source,request)=if legacy{historical_fenced_owner_fixture()}else{completed_startup_fixture()};
            if legacy {
                let owner=roles::Source::owner(source.as_ref(),Instant::now()+Duration::from_secs(5)).unwrap();
                let mut value=serde_json::to_value(owner).unwrap();value.as_object_mut().unwrap().remove("firewall");
                let historical:roles::Owner=serde_json::from_value(value).unwrap();
                let _guard=Guard::acquire(&f.root,Subsystem::NmOwnership).unwrap();
                f.engine.handover.seed_legacy_owner_fixture(request["confirmationToken"].as_str().unwrap(),"local-uid:fixture",historical,|_|Ok(())).unwrap();
            }else {
                for _ in 0..4{f.observe();}
                f.engine.ownership_request("network.nm.ownership.activate",json!({"operationId":request["operationId"],"confirmationToken":request["confirmationToken"]}),"local-uid:fixture").unwrap();
            }
            let id=request["operationId"].as_str().unwrap();let journal=f.root.join("nm-ownership/transaction.json");
            let mut value:Value=serde_json::from_slice(&std::fs::read(&journal).unwrap()).unwrap();
            value["state"]=json!("LEASE_INTENT");value["receiptSha256"]=Value::Null;crate::durable::json(&journal,&value).unwrap();
            let lease=f.root.join(format!("nm-ownership/{id}.lease.json"));let before=std::fs::read(&lease).unwrap();
            let receipt=f.root.join(format!("nm-ownership/{id}.receipt.json"));let receipt_before=std::fs::read(&receipt).unwrap();
            let owner_reads=source.owner_reads.load(std::sync::atomic::Ordering::Relaxed);
            source.offline.store(true,std::sync::atomic::Ordering::Relaxed);Arc::get_mut(&mut f.engine).unwrap().role_source=None;
            for _ in 0..4{f.observe();}
            assert_eq!(f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").unwrap()["state"],"COMMITTED");
            assert_eq!(std::fs::read(lease).unwrap(),before);assert_eq!(std::fs::read(receipt).unwrap(),receipt_before);
            assert_eq!(source.owner_reads.load(std::sync::atomic::Ordering::Relaxed),owner_reads);
            assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        }
    }
    #[test]
    fn startup_terminal_missing_original_lease_remains_unknown_for_legacy_and_new_receipts_without_recreating_or_redispatching() {
        for legacy in [true,false] {
            let (f,source,request)=if legacy{historical_fenced_owner_fixture()}else{completed_startup_fixture()};
            if legacy {
                let owner=roles::Source::owner(source.as_ref(),Instant::now()+Duration::from_secs(5)).unwrap();
                let _guard=Guard::acquire(&f.root,Subsystem::NmOwnership).unwrap();
                f.engine.handover.seed_legacy_owner_fixture(request["confirmationToken"].as_str().unwrap(),"local-uid:fixture",owner,|_|Ok(())).unwrap();
            }else{
                for _ in 0..4 {f.observe();}
                f.engine.ownership_request("network.nm.ownership.activate",json!({"operationId":request["operationId"],"confirmationToken":request["confirmationToken"]}),"local-uid:fixture").unwrap();
            }
            let id=request["operationId"].as_str().unwrap();let path=f.root.join("nm-ownership/transaction.json");let mut journal:Value=serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();journal["state"]=json!("LEASE_INTENT");journal["receiptSha256"]=Value::Null;crate::durable::json(&path,&journal).unwrap();
            let lease=f.root.join(format!("nm-ownership/{id}.lease.json"));std::fs::remove_file(&lease).unwrap();
            let receipt=f.root.join(format!("nm-ownership/{id}.receipt.json"));let receipt_bytes=std::fs::read(&receipt).unwrap();let journal_bytes=std::fs::read(&path).unwrap();
            for _ in 0..4 {f.observe();}
            let error=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").unwrap_err();
            assert!(error.to_string().starts_with("OUTCOME_UNKNOWN"),"missing original lease must remain UNKNOWN,legacy={legacy}: {error}");
            assert!(!lease.exists());assert_eq!(std::fs::read(receipt).unwrap(),receipt_bytes);assert_eq!(std::fs::read(path).unwrap(),journal_bytes);
            assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
            if !legacy {assert_eq!(std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().filter(|line|line.starts_with("start ")).count(),1);}
        }
    }
    #[test]
    fn startup_start_controller_uses_the_original_published_generation_with_kura_off_and_keeps_all_other_writers_fenced() {
        let (f,source,request)=startup_files_fixture();for _ in 0..4 {f.observe();}
        f.engine.ownership_request("network.nm.ownership.startup.publish",request.clone(),"local-uid:fixture").unwrap();
        handover::startup::tests::enable_start_at(&f.root,"success");for _ in 0..4{f.observe();}
        let started=f.engine.ownership_request("network.nm.ownership.startup.start",request.clone(),"local-uid:fixture").unwrap();
        assert_eq!(started["state"],"STARTED");assert_eq!(started["systemAdoptionVerified"],false);assert_eq!(started["start"]["freshCoreOwnerAndDrainRequired"],true);
        assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),2);assert_eq!(source.owner_reads.load(std::sync::atomic::Ordering::Relaxed),0);
        let calls=std::fs::read(f.root.join("systemctl-calls")).unwrap();for _ in 0..2{f.observe();}
        assert_eq!(f.engine.ownership_request("network.nm.ownership.startup.start",request.clone(),"local-uid:fixture").unwrap(),started);
        let original=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":request["operationId"]}),"local-uid:fixture").unwrap();assert_eq!(original["startup"],started);
        assert_eq!(std::fs::read(f.root.join("systemctl-calls")).unwrap(),calls);
        assert_eq!(String::from_utf8(calls).unwrap().lines().filter(|line|!line.starts_with("show ")).collect::<Vec<_>>(),
            vec!["stop yofc-kura-fixture.service","start yofc-kura-fixture.service"]);
        for kind in [Subsystem::Recovery,Subsystem::SystemControl,Subsystem::OrdinaryBoot,Subsystem::Nm,Subsystem::Firewall] {assert!(Guard::acquire(&f.root,kind).is_err());}
        assert!(f.engine.handover.active().unwrap().is_none());assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn startup_start_controller_refuses_wrong_actor_tokens_extra_fields_and_changed_backend_before_any_start_intent() {
        for invalid in ["actor","parent-token","child-token","path","ready","source"] {
            let (f,source,request)=startup_files_fixture();for _ in 0..4{f.observe();}
            f.engine.ownership_request("network.nm.ownership.startup.publish",request.clone(),"local-uid:fixture").unwrap();
            handover::startup::tests::enable_start_at(&f.root,"success");let mut wrong=request.clone();
            match invalid {
                "parent-token"=>wrong["confirmationToken"]=json!("e".repeat(32)),"child-token"=>wrong["startupConfirmationToken"]=json!("f".repeat(32)),
                "path"=>wrong["profilePath"]=json!("/caller/foreign-profile"),"ready"=>wrong["ready"]=json!(true),
                "source"=>f.engine.fake.lock().unwrap().forwarding_blocked=true,_=>{},
            }
            for _ in 0..4{f.observe();}assert!(f.engine.ownership_request("network.nm.ownership.startup.start",wrong,if invalid=="actor"{"local-uid:other"}else{"local-uid:fixture"}).is_err());
            assert!(!f.root.join(format!("nm-ownership/{}.startup-start-intent.json",request["operationId"].as_str().unwrap())).exists());
            assert!(!std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().any(|line|line.starts_with("start ")));
            assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),2);assert!(f.engine.handover.active().unwrap().is_none());
        }
    }
    fn selected_profile_system_grant(f:&Fixture)->std::path::PathBuf {
        let path=f.root.join("ordinary-profile.json");let c:crate::recovery::ordinary_profile::Config=serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let policy=crate::system_control::inspect_stop_policy(&f.root.join("systemctl-fixture"),&c).unwrap();
        let snapshots=f.root.join("system-control-snapshots");crate::durable::directory(&snapshots).unwrap();
        let system=f.root.join("system-profile.json");
        crate::durable::json(&system,&json!({"schema":1,"unit":c.unit,"unitFile":c.unit_file,"unitDefinitionSha256":policy.definition_sha256,
            "files":c.profile_files.iter().map(|file|json!({"path":file.path,"sha256":file.sha256})).collect::<Vec<_>>(),
            "ordinaryProfile":path,"snapshotDirectory":snapshots,"allowRestart":true,"allowReboot":false,
            "confirmationSeconds":60,"observationSeconds":10,"restartTimeoutSeconds":5})).unwrap();system
    }
    #[test]
    fn selected_profile_consumers_read_one_receipt_bound_generation_without_rewriting_grants_boot_identity_or_granting_pending_writes() {
        let (f,source,request)=startup_files_fixture();let path=f.root.join("ordinary-profile.json");let system=selected_profile_system_grant(&f);let ctl=f.root.join("systemctl-fixture");
        let ordinary_before=std::fs::read(&path).unwrap();let system_before=std::fs::read(&system).unwrap();
        let before=crate::recovery::ordinary_profile::Profile::runtime(path.clone(),f.root.clone()).unwrap().inspect().unwrap();
        let old_profile=before.config.profile_id;let boot_before=crate::recovery::ordinary_boot_profile(&f.root,&path,&ctl).unwrap();
        for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.publish",request.clone(),"local-uid:fixture").unwrap();
        let current=crate::recovery::ordinary_profile::Profile::runtime(path.clone(),f.root.clone()).unwrap().inspect().unwrap();
        assert_ne!(current.config.profile_id,old_profile);assert_eq!(current.config.profile_id,format!("profile-{}",request["operationId"].as_str().unwrap()));assert!(current.selection.is_some());
        assert_eq!(current.origin_sha256,crate::durable::hash(&ordinary_before));
        let control=crate::system_control::inspect_runtime_inputs(&f.root,&system,&ctl).unwrap();assert_eq!(control["profile"]["profileId"],current.config.profile_id);
        assert_eq!(control["profile"]["profileDigest"],current.digest);assert_eq!(control["sourceGrantSha256"],crate::durable::hash(&system_before));
        let boot=crate::recovery::ordinary_boot_profile(&f.root,&path,&ctl).unwrap();assert_eq!(boot.grant_sha256,boot_before.grant_sha256);
        assert_eq!(boot.unit,boot_before.unit);assert_eq!(boot.unit_file,boot_before.unit_file);assert_eq!(boot.install_files,boot_before.install_files);assert_eq!(boot.drop_ins,boot_before.drop_ins);
        assert_eq!(std::fs::read(path).unwrap(),ordinary_before);assert_eq!(std::fs::read(system).unwrap(),system_before);
        for subsystem in [Subsystem::Recovery,Subsystem::SystemControl,Subsystem::OrdinaryBoot] {assert!(Guard::acquire(&f.root,subsystem).is_err());}
        assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),2);assert!(f.engine.handover.active().unwrap().is_none());
        assert_eq!(std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().filter(|line|!line.starts_with("show ")).collect::<Vec<_>>(),vec!["stop yofc-kura-fixture.service"]);
    }
    #[test]
    fn selected_profile_runtime_reopens_pending_material_but_refuses_inputs_and_does_not_fall_back_to_matching_legacy_files() {
        let (f,source,request)=startup_files_fixture();let path=f.root.join("ordinary-profile.json");let system=selected_profile_system_grant(&f);let ctl=f.root.join("systemctl-fixture");
        let token=request["confirmationToken"].as_str().unwrap();let child=request["startupConfirmationToken"].as_str().unwrap();let id=uuid::Uuid::parse_str(request["operationId"].as_str().unwrap()).unwrap();
        let command={let _guard=Guard::acquire(&f.root,Subsystem::NmOwnership).unwrap();f.engine.handover.startup_publication_begin(id,token,"local-uid:fixture",child,&ctl).unwrap()};
        let handover::startup::PublicationStep::Dispatch(command)=command else{panic!("fresh private intent")};drop(command);
        assert!(crate::recovery::ordinary_profile::Profile::new(path.clone()).is_ok(),"the unchanged source bytes alone cannot settle an entered original intent");
        let runtime=crate::recovery::ordinary_profile::Profile::runtime(path.clone(),f.root.clone()).unwrap();assert!(runtime.inputs().err().unwrap().to_string().contains("OUTCOME_UNKNOWN"));
        assert!(crate::system_control::inspect_runtime_inputs(&f.root,&system,&ctl).is_err());assert!(crate::recovery::ordinary_boot_profile(&f.root,&path,&ctl).is_err());
        let original=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").unwrap();assert_eq!(original["startup"]["state"],"PUBLICATION_OUTCOME_UNKNOWN");
        assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),2);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn selected_profile_rejects_changed_origin_receipts_current_file_identity_and_unpaired_system_grant_pins() {
        for invalid in ["origin","receipt","same-body-new-inode","wrong-system-pin","unpaired-system-grant"] {
            let (f,_,request)=startup_files_fixture();let path=f.root.join("ordinary-profile.json");let system=selected_profile_system_grant(&f);let ctl=f.root.join("systemctl-fixture");
            let config:crate::recovery::ordinary_profile::Config=serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.publish",request.clone(),"local-uid:fixture").unwrap();
            match invalid {
                "origin"=>{let target=f.root.join(format!("nm-ownership/{}.startup-profile.json",request["operationId"].as_str().unwrap()));crate::durable::write(&path,&std::fs::read(target).unwrap(),crate::durable::FileMetadata::private()).unwrap();}
                "receipt"=>{std::fs::remove_file(f.root.join(format!("nm-ownership/{}.startup-files-receipt.json",request["operationId"].as_str().unwrap()))).unwrap();}
                "same-body-new-inode"=>{let data=std::fs::read(&config.jvm_args_path).unwrap();crate::durable::write(&config.jvm_args_path,&data,crate::durable::FileMetadata::private()).unwrap();}
                _=>{
                    let mut value:Value=serde_json::from_slice(&std::fs::read(&system).unwrap()).unwrap();
                    if invalid=="wrong-system-pin" {for file in value["files"].as_array_mut().unwrap(){if file["path"]==config.jvm_args_path.to_str().unwrap(){file["sha256"]=json!("a".repeat(64));}}}
                    else {value["ordinaryProfile"]=Value::Null;value["snapshotDirectory"]=Value::Null;}
                    crate::durable::json(&system,&value).unwrap();
                }
            }
            assert!(crate::system_control::inspect_runtime_inputs(&f.root,&system,&ctl).is_err());
            if ["origin","receipt","same-body-new-inode"].contains(&invalid) {
                assert!(crate::recovery::ordinary_profile::Profile::runtime(path.clone(),f.root.clone()).unwrap().inputs().is_err());
                assert!(crate::recovery::ordinary_boot_profile(&f.root,&path,&ctl).is_err());
            }
            assert_eq!(std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().filter(|line|line.starts_with("stop ")).count(),1);
            assert!(!std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().any(|line|line.starts_with("start ")));
        }
    }
    #[test]
    fn startup_files_controller_refuses_another_actor_token_or_caller_path_and_readiness_before_any_file_intent() {
        for invalid in ["actor","parent-token","child-token","path","ready"] {
            let (f,source,request)=startup_files_fixture();let mut wrong=request.clone();match invalid {
                "parent-token"=>wrong["confirmationToken"]=json!("e".repeat(32)),"child-token"=>wrong["startupConfirmationToken"]=json!("f".repeat(32)),
                "path"=>wrong["profilePath"]=json!("/caller/foreign-profile"),"ready"=>wrong["ready"]=json!(true),_=>{},
            }
            let args=f.root.join("ordinary-kura-home/management/ordinary.jvm.args");let before=std::fs::read(&args).unwrap();let calls=std::fs::read(f.root.join("systemctl-calls")).unwrap();
            for _ in 0..4{f.observe();}assert!(f.engine.ownership_request("network.nm.ownership.startup.publish",wrong,if invalid=="actor"{"local-uid:other"}else{"local-uid:fixture"}).is_err());
            let id=request["operationId"].as_str().unwrap();assert!(!f.root.join(format!("nm-ownership/{id}.startup-files-intent.json")).exists());
            assert_eq!(std::fs::read(args).unwrap(),before);assert_eq!(std::fs::read(f.root.join("systemctl-calls")).unwrap(),calls);assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),2);
        }
    }
    #[test]
    fn startup_stop_controller_refreshes_current_jvm_association_then_stops_once_without_startup_file_or_backend_writes() {
        for rebound in [false,true] {
            let (mut f,source,request)=startup_association_fixture(0);handover::startup::tests::enable_stop_at(&f.root,"success");
            let args=std::fs::read(f.root.join("ordinary.jvm.args")).unwrap();let profile=std::fs::read(f.root.join("ordinary-profile.json")).unwrap();
            for _ in 0..4 {f.observe();}
            f.engine.ownership_request("network.nm.ownership.startup.verify",request.clone(),"local-uid:fixture").unwrap();
            if rebound{let mut value=source.value.lock().unwrap();value.agent_instance=uuid::Uuid::new_v4();value.bridge_epoch=2;}
            for _ in 0..4 {f.observe();}
            let stopped=f.engine.ownership_request("network.nm.ownership.startup.stop",request.clone(),"local-uid:fixture").unwrap();
            assert_eq!(stopped["state"],"STOPPED");assert_eq!(stopped["startupFilesChanged"],false);assert_eq!(stopped["systemAdoptionVerified"],false);
            assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),2);assert_eq!(source.owner_reads.load(std::sync::atomic::Ordering::Relaxed),0);
            Arc::get_mut(&mut f.engine).unwrap().role_source=None;
            let calls=std::fs::read(f.root.join("systemctl-calls")).unwrap();for _ in 0..2 {f.observe();}
            assert_eq!(f.engine.ownership_request("network.nm.ownership.startup.stop",request.clone(),"local-uid:fixture").unwrap(),stopped);
            let original=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":request["operationId"]}),"local-uid:fixture").unwrap();assert_eq!(original["startup"],stopped);
            assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),2);assert_eq!(std::fs::read(f.root.join("systemctl-calls")).unwrap(),calls);
            assert_eq!(String::from_utf8(calls).unwrap().lines().filter(|line|line.starts_with("stop ")).count(),1);
            assert_eq!(std::fs::read(f.root.join("ordinary.jvm.args")).unwrap(),args);assert_eq!(std::fs::read(f.root.join("ordinary-profile.json")).unwrap(),profile);
            assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
            assert!(f.engine.handover.active().unwrap().is_none());assert!(!f.root.join("ordinary-kura-home/framework/network-owner-agent").exists());
        }
    }
    #[test]
    fn startup_stop_controller_refuses_unreviewed_or_changed_original_authority_before_dispatch() {
        for invalid in ["unreviewed","roles","unit","policy","actor","child-token","caller-ready"] {
            let (f,source,request)=startup_association_fixture(0);let policy=handover::startup::tests::enable_stop_at(&f.root,"success");
            if invalid!="unreviewed"{for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.verify",request.clone(),"local-uid:fixture").unwrap();}
            let mut wrong=request.clone();
            match invalid {
                "roles"=>source.value.lock().unwrap().roles.revision="changed-after-review".into(),
                "unit"=>{let path=f.root.join("unit-state");let body=std::fs::read_to_string(&path).unwrap().replace("MainPID=4321","MainPID=4322");crate::durable::write(&path,body.as_bytes(),crate::durable::FileMetadata::private()).unwrap();}
                "policy"=>{let body=std::fs::read_to_string(&policy).unwrap().replace("KillMode=control-group","KillMode=process");crate::durable::write(&policy,body.as_bytes(),crate::durable::FileMetadata::private()).unwrap();}
                "child-token"=>wrong["startupConfirmationToken"]=json!("f".repeat(32)),
                "caller-ready"=>wrong["ready"]=json!(true),
                _=>{},
            }
            for _ in 0..4{f.observe();}
            assert!(f.engine.ownership_request("network.nm.ownership.startup.stop",wrong,if invalid=="actor"{"local-uid:other"}else{"local-uid:fixture"}).is_err());
            let id=request["operationId"].as_str().unwrap();assert!(!f.root.join(format!("nm-ownership/{id}.startup-stop-intent.json")).exists());
            assert!(std::fs::read_to_string(f.root.join("systemctl-calls")).unwrap().lines().all(|line|line.starts_with("show ")));
            assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),usize::from(invalid!="unreviewed"));
            assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        }
    }
    #[test]
    fn startup_association_original_prefix_uses_existing_receipt_and_never_recreates_missing_evidence() {
        for missing in [false,true] {
            let (f,source,request)=startup_association_fixture(0);for _ in 0..4 {f.observe();}
            f.engine.ownership_request("network.nm.ownership.startup.verify",request.clone(),"local-uid:fixture").unwrap();
            let id=request["operationId"].as_str().unwrap();let proof=f.root.join(format!("nm-ownership/{id}.startup-old-jvm.json"));
            let journal=f.root.join(format!("nm-ownership/{id}.startup-journal.json"));let original=std::fs::read(&proof).unwrap();
            if missing {std::fs::remove_file(&proof).unwrap();}else{
                let mut value:Value=serde_json::from_slice(&std::fs::read(&journal).unwrap()).unwrap();value["state"]=json!("PREPARED");value.as_object_mut().unwrap().remove("oldAssociationSha256");crate::durable::json(&journal,&value).unwrap();
            }
            for _ in 0..2 {f.observe();}
            let outcome=f.engine.ownership_request("network.nm.ownership.startup.verify",request,"local-uid:fixture");
            if missing {assert!(outcome.unwrap_err().to_string().contains("OUTCOME_UNKNOWN"));assert!(!proof.exists());}
            else {assert_eq!(outcome.unwrap()["oldJvmAssociationVerified"],true);assert_eq!(std::fs::read(proof).unwrap(),original);}
            assert_eq!(source.association_reads.load(std::sync::atomic::Ordering::Relaxed),1);assert_eq!(source.exports.load(std::sync::atomic::Ordering::Relaxed),1);
        }
    }
    impl roles::Source for RoleSource {
        fn read(&self,_deadline:Instant)->Result<roles::Observation> {
            self.value.lock().unwrap().clone().context("KURA_UNAVAILABLE: fixture CM stopped")
        }
    }
    struct UnavailableRoles;
    impl roles::Source for UnavailableRoles {
        fn read(&self,_deadline:Instant)->Result<roles::Observation> {
            anyhow::bail!("KURA_UNAVAILABLE: live role source must not be needed")
        }
    }
    fn delegated_read_fixture() -> Fixture {
        let mut f=Fixture::new(&["eth0"],&[("eth0",4,3)]);
        let parent=f.root.join("installed-owner");crate::durable::directory(&parent).unwrap();
        let engine=Arc::get_mut(&mut f.engine).unwrap();
        engine.handover=handover::Store::relocated(&f.root,parent.join("network-owner-agent"));
        engine.set_role_source(Arc::new(UnavailableRoles));
        f.observe();
        let (snapshot,devices)=f.engine.source.capture(Instant::now()+Duration::from_secs(5)).unwrap();
        let roles=roles::Observation::new(uuid::Uuid::new_v4(),1,json!({
            "schemaVersion":1,"pid":roles::PID,"revision":"delegated-original-cm",
            "interfaces":[{"id":"eth0","type":"ETHERNET","ipv4Status":"netIPv4StatusEnabledWAN","natEnabled":null}]
        })).unwrap();
        let baseline=handover::Baseline {
            source_digest:snapshot["sourceDigest"].as_str().unwrap().into(),roles,
            profiles:devices.iter().map(|device|handover::ProfileBinding {
                interface:device.interface.clone(),profile_uuid:device.active_profile.as_ref().map(|p|p.uuid.clone()),origin_cas:None
            }).collect(),firewall_digest:"b".repeat(64),automatic_nat:Value::Null,native_transfer:None,firewall_fence:None,firewall_source:None,
        };
        let prepared=f.engine.handover.plan(uuid::Uuid::new_v4(),"admin-uid:fixture".into(),baseline.clone()).unwrap();
        let token=prepared["confirmationToken"].as_str().unwrap();
        f.engine.handover.fence(token,"admin-uid:fixture",||Ok(baseline)).unwrap();
        // This is a trusted-proof fixture, not production Core mirror acceptance.
        f.engine.handover.activate(token,"admin-uid:fixture",|_|Ok(())).unwrap();
        f
    }
    #[test]
    fn delegated_source_contract_coordinator_reads_confirmed_roles_with_kura_unavailable() {
        let f=delegated_read_fixture();f.observe();
        let (view,_)=f.engine.capture_source(Instant::now()+Duration::from_secs(5)).unwrap();
        assert_eq!(view["roleObservation"]["roles"]["revision"],"delegated-original-cm");
        assert!(view["delegationBinding"].is_object());
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
    #[test]
    fn delegated_source_contract_profile_and_allowlist_drift_revoke_confirmed_scope() {
        let f=delegated_read_fixture();f.observe();
        let (_,mut devices)=f.engine.source.capture(Instant::now()+Duration::from_secs(5)).unwrap();
        let active=f.engine.handover.active().unwrap().unwrap();
        assert!(active.baseline.validate_current(&f.engine.source.config.interfaces,&devices).is_ok());
        assert!(active.baseline.validate_current(&["eth0".into(),"eth1".into()],&devices).is_err());
        devices[0].active_profile.as_mut().unwrap().uuid=uuid::Uuid::new_v4().to_string();
        assert!(active.baseline.validate_current(&f.engine.source.config.interfaces,&devices).is_err());
        assert_eq!(f.call_count("CheckpointCreate"),0);
    }
    #[test]
    fn delegated_source_contract_broken_receipt_never_falls_back_to_live_cm_or_invents_a_lease() {
        let f=delegated_read_fixture();
        let status=f.engine.handover.status().unwrap();
        let receipt=f.root.join("nm-ownership").join(format!("{}.receipt.json",status["operationId"].as_str().unwrap()));
        std::fs::write(receipt,b"broken original receipt").unwrap();
        assert!(f.engine.capture_source(Instant::now()+Duration::from_secs(5)).is_err());
        assert_eq!(f.call_count("CheckpointCreate"),0);
    }
    #[test]
    fn delegated_source_contract_production_admission_needs_lease_before_any_new_backend_action() {
        let f=Fixture::new(&["eth0"],&[("eth0",4,3)]);
        f.engine.real.store(true,std::sync::atomic::Ordering::Relaxed);
        assert!(f.engine.prepare(json!({})).unwrap_err().to_string().contains("explicit NM delegation"));
        assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);
        assert!(!f.engine.journal_path().exists());
    }
    #[test]
    fn delegated_source_contract_new_intent_binds_lease_and_stripping_it_cannot_masquerade_as_legacy() {
        let mut f=delegated_read_fixture();let source=f.source_digest();f.observe();
        let prepared=f.engine.prepare_inner(json!({"sourceDigest":source,"confirmSeconds":60,"nat":null,
            "changes":[{"interface":"eth0","ethernet":{"mtu":0,"acceptAllMacAddresses":-1}}]})).unwrap();
        let mut journal=f.journal();assert!(journal.delegation_binding.is_some());
        assert!(f.engine.ensure_role_binding(&journal,Instant::now()+Duration::from_secs(2)).is_ok());
        let original=std::fs::read(f.engine.intent_path(journal.operation_id,None)).unwrap();
        journal.delegation_binding=None;f.engine.save(&journal).unwrap();
        assert!(transaction::admission(&f.root).is_err());
        assert_eq!(std::fs::read(f.engine.intent_path(journal.operation_id,None)).unwrap(),original);
        assert!(!prepared["token"].is_null());assert_eq!(f.call_count("CheckpointCreate"),0);
    }
    #[test]
    fn delegated_source_contract_legacy_no_role_wire_and_original_confirmation_or_compensation_survive() {
        for rollback in [false,true] {
            let mut f=Fixture::new(&["eth0"],&[("eth0",4,3)]);let plan=f.prepare(None).unwrap();f.apply().unwrap();
            let wire=std::fs::read(f.engine.journal_path()).unwrap();let journal=f.journal();
            assert!(journal.role_binding.is_none() && journal.delegation_binding.is_none());
            assert_eq!(serde_json::to_vec(&journal).unwrap(),wire);
            let engine=Arc::get_mut(&mut f.engine).unwrap();engine.set_role_source(Arc::new(UnavailableRoles));
            f.observe();
            let result=if rollback {f.engine.rollback(json!({"token":plan["token"]}))}
                else {f.observe();f.engine.confirm(json!({"token":plan["token"]}))};
            assert_eq!(result.unwrap()["state"],if rollback {"ROLLED_BACK"} else {"COMMITTED"});
            assert!(transaction::admission(&f.root).unwrap());
        }
    }
    fn authoritative_fixture()->(Fixture,Arc<RoleSource>) {
        let mut f=Fixture::new(&["eth0","eth1","eth2"],&[("eth0",4,3),("eth1",5,4),("eth2",6,5)]);
        let view=json!({"schemaVersion":1,"pid":roles::PID,"revision":"cm-original-revision","interfaces":[
            {"id":"eth0","type":"ETHERNET","ipv4Status":"netIPv4StatusEnabledWAN","natEnabled":null},
            {"id":"eth2","type":"ETHERNET","ipv4Status":"netIPv4StatusEnabledWAN","natEnabled":false},
            {"id":"eth1","type":"ETHERNET","ipv4Status":"netIPv4StatusEnabledLAN","natEnabled":true}]});
        let source=Arc::new(RoleSource{value:Mutex::new(Some(roles::Observation::new(uuid::Uuid::new_v4(),1,view).unwrap()))});
        Arc::get_mut(&mut f.engine).unwrap().set_role_source(source.clone());(f,source)
    }
    fn two_wan_policy()->Value {json!({"schemaVersion":2,"pairs":[{"lan":"eth1","wan":"eth0"},{"lan":"eth1","wan":"eth2"}]})}
    #[test]
    fn role_authority_contract_caller_cannot_drop_a_wan_or_reverse_a_cm_lan() {
        for proposal in [json!({"wan":"eth0","lan":["eth1"]}),json!({"wan":"eth1","lan":["eth0"]})] {
            let (mut f,_)=authoritative_fixture();
            assert!(f.prepare(Some(proposal)).is_err());assert!(!f.engine.journal_path().exists());
            assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        }
    }
    #[test]
    fn role_authority_contract_multi_wan_is_applied_and_read_back_as_one_owned_policy() {
        let (mut f,_)=authoritative_fixture();let plan=f.prepare(Some(two_wan_policy())).unwrap();
        let journal=f.journal();assert!(journal.role_binding.is_some());assert!(transaction::admission(&f.root).is_ok());
        f.apply().unwrap();assert_eq!(f.journal_state(),"WAIT_CONFIRM");assert_eq!(f.engine.fake.lock().unwrap().writes,1);
        f.observe();f.observe();assert_eq!(f.engine.confirm(json!({"token":plan["token"]})).unwrap()["state"],"COMMITTED");
        assert!(ownership::capture(&f.root,f.engine.observed_nat(Instant::now()+Duration::from_secs(3)).unwrap().as_ref()).is_ok());
    }
    #[test]
    fn role_authority_contract_new_registration_or_cm_revision_invalidates_the_prepared_lease() {
        for registration in [false,true] {
            let (mut f,source)=authoritative_fixture();f.prepare(Some(two_wan_policy())).unwrap();
            let mut observed=source.value.lock().unwrap();let old=observed.as_ref().unwrap();
            let mut value=serde_json::to_value(old).unwrap();
            if registration {value["bridgeEpoch"]=json!(2);} else {value["roles"]["revision"]=json!("new-revision");}
            *observed=Some(serde_json::from_value(value).unwrap());drop(observed);
            assert!(f.apply().is_err());assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        }
    }
    #[test]
    fn role_authority_contract_cm_unavailability_does_not_block_original_compensation() {
        let (mut f,source)=authoritative_fixture();let plan=f.prepare(Some(two_wan_policy())).unwrap();f.apply().unwrap();
        *source.value.lock().unwrap()=None;f.observe();
        assert_eq!(f.engine.rollback(json!({"token":plan["token"]})).unwrap()["state"],"ROLLED_BACK");
        assert!(transaction::admission(&f.root).unwrap());assert!(f.engine.fake.lock().unwrap().table.is_none());
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
        let expected = NatSet::Legacy {wan:"eth0".into(),lan:vec!["eth1".into()]};
        for flags in [json!("dormant"),json!(["dormant"]),json!("owner"),json!(["owner","persist"])] {
            let mut table = fake_table(&expected.render().unwrap());
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
        let expected = NatSet::Legacy {wan:"eth0".into(),lan:vec!["eth1".into()]};
        let valid = fake_table(&expected.render().unwrap());
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
