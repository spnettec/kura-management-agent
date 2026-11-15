//! Explicit NM source observations for the future joint NM/firewall coordinator.
//! No network/checkpoint/profile mutation or fallback backend exists in this module.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

mod coordinator;
pub(crate) mod handover;
mod nat;
pub(crate) mod roles;
pub(crate) mod ownership;
mod bus_guid;
mod preview;
pub(crate) mod transaction;

const NAME: &str = "org.freedesktop.NetworkManager";
const ROOT: &str = "/org/freedesktop/NetworkManager";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
const DBUS: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Config {
    schema_version: u8,
    interfaces: Vec<String>,
    #[serde(default)]
    bus_address: Option<String>,
    /// Observation-only configurations stay false; the coordinator writer is a
    /// separate explicit opt-in and never turns observation into a write grant.
    #[serde(default)]
    write_enabled: bool,
}
impl Config {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && !self.interfaces.is_empty() && self.interfaces.len() <= 16,
            "INVALID_ARGUMENT: NM observation configuration"
        );
        let mut seen = std::collections::BTreeSet::new();
        for name in &self.interfaces {
            ensure!(
                !name.is_empty()
                    && name.len() <= 15
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                    && seen.insert(name),
                "INVALID_ARGUMENT: NM interface allowlist"
            );
        }
        if let Some(address) = &self.bus_address {
            let path = address
                .strip_prefix("unix:path=")
                .context("INVALID_ARGUMENT: fixed local NM bus address required")?;
            ensure!(
                path.starts_with('/')
                    && path.len() <= 200
                    && path
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"/_-.".contains(&c)),
                "INVALID_ARGUMENT: fixed local NM bus address required"
            );
        }
        Ok(())
    }
}

/// One structured D-Bus call. The wire implementation owns the busctl text
/// serialization; tests observe the structured form directly.
pub(super) struct BusCall {
    pub(super) destination: String,
    pub(super) path: String,
    pub(super) interface: String,
    pub(super) method: String,
    pub(super) arguments: Vec<Value>,
    pub(super) expected_server_guid: Option<String>,
}
trait Wire: Send + Sync {
    fn call(&self, call: &BusCall, deadline: Instant) -> Result<Value>;
    fn server_guid(&self, _deadline: Instant) -> Result<Option<String>> {
        Ok(None)
    }
}
// ---------------------------------------------------------------------------
// D-Bus text-grammar serialization. busctl takes arguments in its own text
// format, never JSON. Values are serialized strictly from typed variant values
// that were themselves parsed from NM replies, so nothing is invented here.
// Top-level arguments carry no type prefix (the signature covers them); values
// inside dictionaries of variants repeat their explicit type.
// ---------------------------------------------------------------------------
fn dbus_string(value: &str) -> String {
    // busctl takes each argument as one raw argv token; surrounding quotes are
    // NOT stripped and would become part of the value. Strings with spaces stay
    // a single token, and control characters are rejected by the serializer.
    value.to_string()
}
fn integer(signature: &str, data: &Value) -> Result<String> {
    let fail = || anyhow::anyhow!("CONFLICT: NM integer value for {signature}");
    let (minimum, maximum) = match signature {
        "y" => (0i128, 255),
        "n" => (i16::MIN as i128, i16::MAX as i128),
        "q" => (0, u16::MAX as i128),
        "i" => (i32::MIN as i128, i32::MAX as i128),
        "u" => (0, u32::MAX as i128),
        "x" => (i64::MIN as i128, i64::MAX as i128),
        "t" => (0, u64::MAX as i128),
        _ => anyhow::bail!("INVALID_ARGUMENT: NM integer signature {signature}"),
    };
    let value = match signature {
        "y" | "q" | "u" | "t" => data.as_u64().ok_or_else(fail)? as i128,
        _ => data.as_i64().ok_or_else(fail)? as i128,
    };
    ensure!(
        (minimum..=maximum).contains(&value),
        "CONFLICT: NM integer range for {signature}"
    );
    Ok(value.to_string())
}
/// One complete type from a signature string; arrays consume their element.
fn one_signature(signature: &str) -> Result<&str> {
    let bytes = signature.as_bytes();
    ensure!(!bytes.is_empty(), "INVALID_ARGUMENT: NM signature");
    match bytes[0] {
        b'a' => {
            let element = one_signature(&signature[1..])?;
            Ok(&signature[..1 + element.len()])
        }
        b'(' | b'{' => {
            let mut depth = 0usize;
            for (index, byte) in bytes.iter().enumerate() {
                match byte {
                    b'(' | b'{' => depth += 1,
                    b')' | b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(&signature[..=index]);
                        }
                    }
                    _ => {}
                }
            }
            anyhow::bail!("INVALID_ARGUMENT: NM signature container")
        }
        _ => Ok(&signature[..1]),
    }
}
fn signature_parts(signature: &str) -> Result<Vec<&str>> {
    let mut parts = Vec::new();
    let mut rest = signature;
    while !rest.is_empty() {
        let part = one_signature(rest)?;
        parts.push(part);
        rest = &rest[part.len()..];
    }
    Ok(parts)
}
fn dbus_tokens(signature: &str, data: &Value) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    dbus_tokens_into(signature, data, &mut tokens, 0)?;
    ensure!(
        tokens.iter().map(String::len).sum::<usize>() <= 1_048_576,
        "RESOURCE_EXHAUSTED: NM argument serialization"
    );
    ensure!(
        tokens.iter().all(|t| !t.chars().any(char::is_control)),
        "CONFLICT: NM argument serialization"
    );
    Ok(tokens)
}
fn dbus_tokens_into(
    signature: &str,
    data: &Value,
    tokens: &mut Vec<String>,
    depth: usize,
) -> Result<()> {
    ensure!(depth <= 8, "INVALID_ARGUMENT: NM signature nesting");
    if signature == "s" {
        let value = data.as_str().context("CONFLICT: NM string value")?;
        ensure!(
            !value.chars().any(char::is_control) && value.len() <= 4096,
            "CONFLICT: NM string value"
        );
        tokens.push(dbus_string(value));
        return Ok(());
    }
    if signature == "b" {
        ensure!(data.is_boolean(), "CONFLICT: NM boolean value");
        tokens.push(if data.as_bool().unwrap() { "true" } else { "false" }.into());
        return Ok(());
    }
    if signature == "v" {
        tokens.extend(variant_tokens(data)?);
        return Ok(());
    }
    if matches!(signature, "y" | "n" | "q" | "i" | "u" | "x" | "t") {
        tokens.push(integer(signature, data)?);
        return Ok(());
    }
    if signature == "o" {
        let value = data.as_str().context("CONFLICT: NM object path value")?;
        ensure!(
            value.starts_with('/') && !value.chars().any(char::is_control) && value.len() <= 200,
            "CONFLICT: NM object path value"
        );
        tokens.push(dbus_string(value));
        return Ok(());
    }
    if let Some(element) = signature.strip_prefix('a') {
        if let Some(inner) = element.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            // Dictionary input is a single object: count, then per entry the
            // key and its value. "{sv}" values repeat their explicit type,
            // other value types do not.
            ensure!(inner.starts_with('s'), "INVALID_ARGUMENT: NM signature");
            let value_signature = &inner[1..];
            let map = data.as_object().context("CONFLICT: NM dictionary value")?;
            ensure!(map.len() <= 4096, "RESOURCE_EXHAUSTED: NM dictionary value");
            tokens.push(map.len().to_string());
            for (key, value) in map {
                tokens.push(dbus_string(key));
                if value_signature == "v" {
                    tokens.extend(variant_tokens(value)?);
                } else {
                    dbus_tokens_into(value_signature, value, tokens, depth + 1)?;
                }
            }
            return Ok(());
        }
        let rows = data.as_array().context("CONFLICT: NM array value")?;
        ensure!(rows.len() <= 4096, "RESOURCE_EXHAUSTED: NM array value");
        tokens.push(rows.len().to_string());
        for row in rows {
            dbus_tokens_into(element, row, tokens, depth + 1)?;
        }
        return Ok(());
    }
    if let Some(inner) = signature.strip_prefix('(') {
        let inner = inner.strip_suffix(')').context("INVALID_ARGUMENT: NM signature")?;
        let fields = signature_parts(inner)?;
        let values = data.as_array().context("CONFLICT: NM struct value")?;
        ensure!(values.len() == fields.len(), "CONFLICT: NM struct shape");
        tokens.push("(".into());
        for (field, value) in fields.iter().zip(values) {
            dbus_tokens_into(field, value, tokens, depth + 1)?;
        }
        tokens.push(")".into());
        return Ok(());
    }
    anyhow::bail!("INVALID_ARGUMENT: NM signature {signature}")
}
fn variant_tokens(value: &Value) -> Result<Vec<String>> {
    let signature = value["type"].as_str().context("CONFLICT: NM variant type")?;
    ensure!(
        !signature.is_empty() && signature.len() <= 32,
        "CONFLICT: NM variant type"
    );
    let mut tokens = vec![signature.to_string()];
    dbus_tokens_into(signature, &value["data"], &mut tokens, 0)?;
    Ok(tokens)
}
struct Busctl {
    address: Option<String>,
}
impl Wire for Busctl {
    fn server_guid(&self, deadline: Instant) -> Result<Option<String>> {
        bus_guid::probe(self.address.as_deref(), deadline).map(Some)
    }
    fn call(&self, call: &BusCall, deadline: Instant) -> Result<Value> {
        ensure!(
            cfg!(target_os = "linux") && Path::new("/usr/bin/busctl").is_file(),
            "UNSUPPORTED: NM busctl backend requires Linux"
        );
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .context("TIMEOUT: NM observation deadline")?;
        let timeout = remaining.min(Duration::from_secs(2));
        let mut parts: Vec<String> = ["call", &call.destination, &call.path, &call.interface, &call.method]
            .into_iter()
            .map(String::from)
            .collect();
        // Argument values may look like busctl options (for example "-1" as a
        // route metric); "--" ends option parsing before the signature.
        parts.push("--".into());
        if !call.arguments.is_empty() {
            let mut signature = String::new();
            for argument in &call.arguments {
                signature.push_str(
                    argument["type"]
                        .as_str()
                        .context("CONFLICT: NM argument signature")?,
                );
            }
            parts.push(signature);
            for argument in &call.arguments {
                let kind = argument["type"]
                    .as_str()
                    .context("CONFLICT: NM argument signature")?;
                parts.extend(dbus_tokens(kind, &argument["data"])?);
            }
        }
        let mut command = vec![
            "--json=short".into(),
            "--no-pager".into(),
            "--auto-start=no".into(),
            "--allow-interactive-authorization=no".into(),
            format!("--timeout={}ms", timeout.as_millis().max(1)),
        ];
          command.push(match &call.expected_server_guid {
              Some(guid) => format!("--address={}", bus_guid::pinned_address(self.address.as_deref(), guid)?),
              None => self.address.as_ref().map(|a| format!("--address={a}")).unwrap_or_else(|| "--system".into()),
          });
        command.extend(parts);
        let refs: Vec<_> = command.iter().map(String::as_str).collect();
        // Fixed program, isolated environment and bounded process-group execution.
        // DBUS_SYSTEM_BUS_ADDRESS, loaders and PATH from the agent cannot redirect it.
        let output = crate::process::run_isolated(Path::new("/usr/bin/busctl"), &refs, timeout)?;
        if !output.status.success() {
            // Bounded diagnostics at debug level keep live backend rejections
            // observable without leaking them into caller error codes.
            tracing::debug!(
                stderr = %String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(512)]),
                "NM busctl call failed"
            );
            ensure!(
                output.status.success(),
                "UNSUPPORTED: NM bus source unavailable"
            );
        }
        // Methods without a reply body (CheckpointDestroy) and empty a{sv}
        // replies print nothing; the coordinator ignores those replies, while
        // any caller that parses them still fails closed on the null sentinel.
        if output.stdout.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|_| anyhow::anyhow!("CONFLICT: invalid NM bus reply"))
    }
}

#[derive(Clone)]
pub(crate) struct Nm {
    config: Config,
    wire: Arc<dyn Wire>,
    engine: Option<Arc<coordinator::Coordinator>>,
    observation_root: Option<Arc<std::path::PathBuf>>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Identity {
    bus_id: String,
    service_owner: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BusBinding {
    identity: Identity,
    server_guid: String,
}
#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Profile {
    uuid: String,
    connection_type: String,
    profile_path: String,
    applied_version: u64,
    /// Persistent-profile compare-and-set token from the profile object itself;
    /// never the device applied version and never zero (zero would disable the
    /// Update2 version check entirely).
    version_id: u64,
    applied_sha256: String,
    settings_sha256: String,
    unsaved: bool,
    flags: u32,
    wired_shape: bool,
    requires_adoption: bool,
    #[serde(skip)]
    settings: Value,
    #[serde(skip)]
    applied: Value,
}
#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Device {
    interface: String,
    device_path: String,
    device_type: u32,
    active_connection_path: String,
    managed: bool,
    state: u32,
    active_profile: Option<Profile>,
}

fn shape<T>() -> Result<T> {
    anyhow::bail!("CONFLICT: NM source reply shape")
}
fn fields(value: Value, signature: &str, count: usize) -> Result<Vec<Value>> {
    if value["type"] != signature {
        return shape();
    }
    let data = value["data"]
        .as_array()
        .context("CONFLICT: NM source reply shape")?;
    ensure!(data.len() == count, "CONFLICT: NM source reply shape");
    Ok(data.clone())
}
fn variant<'a>(value: &'a Value, signature: &str) -> Result<&'a Value> {
    ensure!(
        value["type"] == signature,
        "CONFLICT: NM source variant type"
    );
    value
        .get("data")
        .context("CONFLICT: NM source variant data")
}
fn string(value: &Value) -> Result<String> {
    let value = value.as_str().context("CONFLICT: NM source string")?;
    ensure!(
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
        "CONFLICT: NM source string"
    );
    Ok(value.into())
}
fn object_path(value: &Value, section: &str) -> Result<String> {
    let path = string(value)?;
    let prefix = format!("{ROOT}/{section}/");
    let suffix = path
        .strip_prefix(&prefix)
        .context("CONFLICT: NM source object path")?;
    ensure!(
        !suffix.is_empty() && suffix.len() <= 20 && suffix.bytes().all(|b| b.is_ascii_digit()),
        "CONFLICT: NM source object path"
    );
    Ok(path)
}
fn unsigned(value: &Value) -> Result<u32> {
    value
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .context("CONFLICT: NM source unsigned value")
}
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<_, _> = map.iter().collect();
            Value::Object(
                sorted
                    .into_iter()
                    .map(|(k, v)| (k.clone(), canonical(v)))
                    .collect(),
            )
        }
        Value::Array(rows) => Value::Array(rows.iter().map(canonical).collect()),
        _ => value.clone(),
    }
}
fn digest(value: &Value) -> Result<String> {
    Ok(crate::durable::hash(&serde_json::to_vec(&canonical(
        value,
    ))?))
}
/// Digest of a profile/settings payload with NM-managed volatile properties
/// removed. `connection.timestamp` changes whenever the device re-activates
/// (including NM's own checkpoint rollback) without any user-facing change, so
/// it must never participate in the candidate content binding.
fn settings_digest(value: &Value) -> Result<String> {
    let mut copy = value.clone();
    if let Some(connection) = copy
        .get_mut("connection")
        .and_then(|v| v.as_object_mut())
    {
        connection.remove("timestamp");
    }
    digest(&copy)
}
fn profile_string(settings: &Value, key: &str) -> Result<String> {
    string(variant(&settings["connection"][key], "s")?)
}

impl Nm {
    pub(crate) fn open(path: &Path, root: Option<&Path>) -> Result<Self> {
        let (bytes, meta) = crate::durable::read(path, 16384)?;
        ensure!(
            meta.uid == unsafe { libc::geteuid() } && meta.mode == 0o600,
            "FORBIDDEN: private NM configuration required"
        );
        let config: Config = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: NM observation configuration"))?;
        config.validate()?;
        let nm = Self {
            config: config.clone(),
            wire: Arc::new(Busctl {
                address: config.bus_address.clone(),
            }),
            engine: None,
            observation_root: root.map(|p| Arc::new(p.to_owned())),
        };
        let engine = if config.write_enabled {
            let root = root.context("INVALID_ARGUMENT: NM writes require a state root")?;
            Some(Arc::new(coordinator::Coordinator::new(nm.clone(), root)?))
        } else {
            None
        };
        Ok(Self { engine, ..nm })
    }
    pub(crate) fn with_role_source(mut self,source:Arc<dyn roles::Source>)->Result<Self> {
        if let Some(engine)=self.engine.as_mut() {
            Arc::get_mut(engine).context("CONFLICT: configure NM role authority before sharing")?.set_role_source(source);
        }
        Ok(self)
    }
    pub(crate) async fn inspect(&self) -> Result<Value> {
        let this = self.clone();
        let deadline = Instant::now() + Duration::from_secs(5);
        tokio::task::spawn_blocking(move || this.snapshot(deadline)).await?
    }
    pub(crate) async fn preview(&self, value: Value) -> Result<Value> {
        let proposal = preview::Preview::parse(value)?;
        let this = self.clone();
        let deadline = Instant::now() + Duration::from_secs(5);
        tokio::task::spawn_blocking(move || {
            let (source, devices) = this.capture(deadline)?;
            proposal.compile(&source, &devices)
        })
        .await?
    }
    /// Single dispatcher for the local NM methods so every failure keeps its
    /// full domain error for debug observability while callers still get the
    /// stable code.
    pub(crate) async fn dispatch_nm(&self, method: &str, params: Value) -> Result<Value> {
        match method {
            "network.nm.prepare" => self.prepare(params).await,
            "network.nm.apply" => self.apply().await,
            "network.nm.confirm" => self.confirm(params).await,
            "network.nm.rollback" => self.rollback(params).await,
            "network.nm.status" => self.transaction_status().await,
            "network.nm.recover" => self.recover().await,
            "network.nm.archive" => self.archive().await,
            _ => Err(anyhow::anyhow!("UNSUPPORTED: NM method")),
        }
    }
    pub(crate) async fn prepare(&self, value: Value) -> Result<Value> {
        let engine = self.write_engine()?;
        tokio::task::spawn_blocking(move || engine.prepare(value)).await?
    }
    pub(crate) async fn deposit_template(&self,value:Value,instance:uuid::Uuid,epoch:u64)->Result<Value> {
        let engine=self.write_engine()?;
        tokio::task::spawn_blocking(move||engine.deposit_template(value,instance,epoch)).await?
    }
    pub(crate) async fn ownership_request(&self,method:String,value:Value,actor:String)->Result<Value> {
        let engine=self.write_engine()?;
        tokio::task::spawn_blocking(move||engine.ownership_request(&method,value,&actor)).await?
    }
    pub(crate) async fn imported_firewall_request(&self,method:String,value:Value,uid:u32,request:String,write_grant:bool)->Result<Value> {
        let engine=self.write_engine()?;
        tokio::task::spawn_blocking(move||engine.imported_request(&method,value,uid,&request,write_grant)).await?
    }
    pub(crate) async fn imported_firewall_remote_request(&self,method:String,value:Value,
        principal:handover::initialization::producer::principal::RemotePrincipal,write_grant:bool)->Result<Value> {
        let engine=self.write_engine()?;
        tokio::task::spawn_blocking(move||engine.imported_remote_request(&method,value,&principal,write_grant)).await?
    }
    pub(crate) async fn imported_firewall_remote_review(&self,method:String,value:Value,request:String)->Result<Value> {
        let engine=self.write_engine()?;
        tokio::task::spawn_blocking(move||engine.imported_remote_review(&method,value,&request)).await?
    }
    pub(crate) async fn apply(&self) -> Result<Value> {
        let engine = self.write_engine()?;
        tokio::task::spawn_blocking(move || engine.apply()).await?
    }
    pub(crate) async fn confirm(&self, value: Value) -> Result<Value> {
        let engine = self.write_engine()?;
        tokio::task::spawn_blocking(move || engine.confirm(value)).await?
    }
    pub(crate) async fn rollback(&self, value: Value) -> Result<Value> {
        let engine = self.write_engine()?;
        tokio::task::spawn_blocking(move || engine.rollback(value)).await?
    }
    pub(crate) async fn transaction_status(&self) -> Result<Value> {
        let engine = self.write_engine()?;
        tokio::task::spawn_blocking(move || engine.status()).await?
    }
    pub(crate) async fn recover(&self) -> Result<Value> {
        let engine = self.write_engine()?;
        tokio::task::spawn_blocking(move || engine.recover()).await?
    }
    pub(crate) async fn remote_request(
        &self,
        command: &yofc_management_protocol::v1::ReadCommand,
        authority: &str,
        connection: &str,
        grant: bool,
    ) -> Result<Value> {
        if command.operation == yofc_management_protocol::v1::Operation::NmView as i32 && self.engine.is_none() {
            ensure!(grant,"UNSUPPORTED: remote NM channel disabled");
            ensure!(coordinator::valid_authority(authority),"FORBIDDEN: remote authority required");
            ensure!(command.valid_payload() && uuid::Uuid::parse_str(&command.command_id).is_ok(),
                "INVALID_ARGUMENT: NM command");
            let this=self.clone();let deadline=Instant::now()+Duration::from_secs(10);
            return tokio::task::spawn_blocking(move || {
                let _guard=this.observation_root.as_ref().map(|root|
                    crate::system_change::Guard::observe_shared(root,deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(2))))
                    .transpose()?;
                let source=this.snapshot(deadline)?;
                let (candidate,transaction)=this.observation_root.as_ref()
                    .map(|root|transaction::view(root)).transpose()?.unwrap_or((None,None));
                ensure!(Instant::now()<deadline,"TIMEOUT: NM view deadline");
                Ok(json!({"schemaVersion":1,"backend":"NetworkManager","writeEnabled":false,
                    "sourceDigest":source["sourceDigest"],"candidateDigest":candidate,
                    "confirmationReady":false,"transaction":transaction}))
            }).await?;
        }
        let engine = self.write_engine()?;
        let command = command.clone();
        let authority = authority.to_owned();
        let connection = connection.to_owned();
        tokio::task::spawn_blocking(move || engine.remote_request(&command, &authority, &connection, grant)).await?
    }
    pub(crate) async fn prove_remote(
        &self,
        command: &yofc_management_protocol::v1::ReadCommand,
        authority: &str,
    ) -> Result<Option<yofc_management_protocol::v1::TaskResult>> {
        let engine = self.write_engine()?;
        let command = command.clone();
        let authority = authority.to_owned();
        tokio::task::spawn_blocking(move || engine.prove_remote(&command, &authority)).await?
    }
    pub(crate) async fn archive(&self) -> Result<Value> {
        let engine = self.write_engine()?;
        tokio::task::spawn_blocking(move || engine.archive()).await?
    }
    /// Periodic adjudication of expired or interrupted transactions. Without a
    /// configured writer engine this is a no-op.
    pub(crate) async fn expire(&self) -> Result<()> {
        if self.engine.is_none() {
            return Ok(());
        }
        let engine = self.write_engine()?;
        tokio::task::spawn_blocking(move || {
            if engine.expire_imported()? {return Ok(());}
            engine.recover().map(|_| ())
        }).await?
    }
    fn write_engine(&self) -> Result<Arc<coordinator::Coordinator>> {
        self.engine
            .clone()
            .context("UNSUPPORTED: NM writes are not configured")
    }
    #[cfg(test)]
    fn for_test(config: Value, wire: Arc<dyn Wire>, root: &Path) -> Result<Self> {
        let config: Config = serde_json::from_value(config)
            .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: NM observation configuration"))?;
        config.validate()?;
        let nm = Self {
            config: config.clone(),
            wire,
            engine: None,
            observation_root: Some(Arc::new(root.to_owned())),
        };
        let engine = if config.write_enabled {
            Some(Arc::new(coordinator::Coordinator::new(nm.clone(), root)?))
        } else {
            None
        };
        Ok(Self { engine, ..nm })
    }
    fn call(
        &self,
        target: (&str, &str, &str),
        method: &str,
        arguments: &[Value],
        deadline: Instant,
    ) -> Result<Value> {
        self.call_pinned(target, method, arguments, None, deadline)
    }
    fn call_pinned(
        &self,
        target: (&str, &str, &str),
        method: &str,
        arguments: &[Value],
        server_guid: Option<&str>,
        deadline: Instant,
    ) -> Result<Value> {
        let (owner, path, iface) = target;
        ensure!(
            Instant::now() < deadline,
            "TIMEOUT: NM observation deadline"
        );
        self.wire.call(
            &BusCall {
                destination: owner.into(),
                path: path.into(),
                interface: iface.into(),
                method: method.into(),
                arguments: arguments.to_vec(),
                  expected_server_guid: server_guid.map(str::to_owned),
            },
            deadline,
        )
    }
    fn identity(&self, deadline: Instant) -> Result<Identity> {
        let guid = self.wire.server_guid(deadline)?;
        self.identity_on(guid.as_deref(), deadline)
    }
    fn binding(&self, deadline: Instant) -> Result<BusBinding> {
        let guid = self.wire.server_guid(deadline)?.context("UNSUPPORTED: NM bus handshake binding unavailable")?;
        ensure!(guid.len() == 32 && guid.bytes().all(|b| b.is_ascii_hexdigit()), "CONFLICT: NM server GUID");
        let identity = self.identity_on(Some(&guid), deadline)?;
        Ok(BusBinding {identity, server_guid:guid})
    }
    fn identity_on(&self, server_guid: Option<&str>, deadline: Instant) -> Result<Identity> {
        let id = fields(
            self.call_pinned((DBUS, BUS_PATH, DBUS), "GetId", &[], server_guid, deadline)?,
            "s",
            1,
        )?;
        let bus_id = string(&id[0])?;
        ensure!(
            bus_id.len() == 32 && bus_id.bytes().all(|b| b.is_ascii_hexdigit()),
            "CONFLICT: NM bus identity"
        );
        let owner = fields(
            self.call_pinned(
                (DBUS, BUS_PATH, DBUS),
                "GetNameOwner",
                &[json!({"type":"s","data":NAME})],
                server_guid,
                deadline,
            )?,
            "s",
            1,
        )?;
        let service_owner = string(&owner[0])?;
        let parts: Vec<_> = service_owner
            .strip_prefix(':')
            .unwrap_or("")
            .split('.')
            .collect();
        ensure!(
            parts.len() == 2
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
            "CONFLICT: NM unique service owner"
        );
        Ok(Identity {
            bus_id,
            service_owner,
        })
    }
    fn properties(&self, owner: &str, path: &str, iface: &str, deadline: Instant) -> Result<Value> {
        let values = fields(
            self.call(
                (owner, path, PROPERTIES),
                "GetAll",
                &[json!({"type":"s","data":iface})],
                deadline,
            )?,
            "a{sv}",
            1,
        )?;
        ensure!(values[0].is_object(), "CONFLICT: NM property dictionary");
        Ok(values[0].clone())
    }
    fn property(
        &self,
        owner: &str,
        path: &str,
        iface: &str,
        key: &str,
        signature: &str,
        deadline: Instant,
    ) -> Result<Value> {
        let values = fields(
            self.call(
                (owner, path, PROPERTIES),
                "Get",
                &[
                    json!({"type":"s","data":iface}),
                    json!({"type":"s","data":key}),
                ],
                deadline,
            )?,
            "v",
            1,
        )?;
        Ok(variant(&values[0], signature)?.clone())
    }
    fn device(&self, owner: &str, name: &str, deadline: Instant) -> Result<Device> {
        let values = fields(
            self.call(
                (owner, ROOT, NAME),
                "GetDeviceByIpIface",
                &[json!({"type":"s","data":name})],
                deadline,
            )?,
            "o",
            1,
        )?;
        let path = object_path(&values[0], "Devices")?;
        let p = self.properties(
            owner,
            &path,
            "org.freedesktop.NetworkManager.Device",
            deadline,
        )?;
        ensure!(
            string(variant(&p["Interface"], "s")?)? == name,
            "CONFLICT: NM interface changed"
        );
        let managed = variant(&p["Managed"], "b")?
            .as_bool()
            .context("CONFLICT: NM managed state")?;
        let state = unsigned(variant(&p["State"], "u")?)?;
        let device_type = unsigned(variant(&p["DeviceType"], "u")?)?;
        let active = string(variant(&p["ActiveConnection"], "o")?)?;
        let active_profile = if active == "/" {
            ensure!(state != 100, "CONFLICT: NM active source changed");
            None // No active profile is not an empty or writable default profile.
        } else {
            let active = object_path(&json!(active), "ActiveConnection")?;
            let values = fields(
                self.call(
                    (owner, &path, "org.freedesktop.NetworkManager.Device"),
                    "GetAppliedConnection",
                    &[json!({"type":"u","data":0})],
                    deadline,
                )?,
                "a{sa{sv}}t",
                2,
            )?;
            let applied_version = values[1]
                .as_u64()
                .filter(|v| *v > 0)
                .context("CONFLICT: NM applied version")?;
            let applied = &values[0];
            let profile_path = object_path(
                &self.property(
                    owner,
                    &active,
                    "org.freedesktop.NetworkManager.Connection.Active",
                    "Connection",
                    "o",
                    deadline,
                )?,
                "Settings",
            )?;
            let settings = fields(
                self.call(
                    (
                        owner,
                        &profile_path,
                        "org.freedesktop.NetworkManager.Settings.Connection",
                    ),
                    "GetSettings",
                    &[],
                    deadline,
                )?,
                "a{sa{sv}}",
                1,
            )?
            .remove(0);
            let uuid = uuid::Uuid::parse_str(&profile_string(&settings, "uuid")?)
                .context("CONFLICT: NM profile identity")?;
            ensure!(
                uuid::Uuid::parse_str(&profile_string(applied, "uuid")?)? == uuid,
                "CONFLICT: NM active profile changed"
            );
            let connection_type = profile_string(&settings, "type")?;
            ensure!(
                profile_string(applied, "type")? == connection_type,
                "CONFLICT: NM profile type changed"
            );
            let props = self.properties(
                owner,
                &profile_path,
                "org.freedesktop.NetworkManager.Settings.Connection",
                deadline,
            )?;
            let unsaved = variant(&props["Unsaved"], "b")?
                .as_bool()
                .context("CONFLICT: NM profile persistence state")?;
            let flags = unsigned(variant(&props["Flags"], "u")?)?;
            let version_id = variant(&props["VersionId"], "t")?
                .as_u64()
                .filter(|v| *v > 0)
                .context("CONFLICT: NM profile version token")?;
            let supported = device_type == 1
                && connection_type == "802-3-ethernet"
                && [applied, &settings].iter().all(|source| {
                    source.as_object().is_some_and(|map| {
                        map.keys().all(|k| {
                            [
                                "connection",
                                "802-3-ethernet",
                                "ipv4",
                                "ipv6",
                                "proxy",
                                "user",
                                "match",
                                "link",
                            ]
                            .contains(&k.as_str())
                        })
                    })
                });
            Some(Profile {
                uuid: uuid.hyphenated().to_string(),
                connection_type,
                profile_path,
                applied_version,
                version_id,
                // The applied dict carries connection.timestamp, which any
                // re-activation (including checkpoint rollback) rewrites; the
                // volatile-free digest keeps source comparisons stable.
                applied_sha256: settings_digest(applied)?,
                settings_sha256: settings_digest(&settings)?,
                unsaved,
                flags,
                wired_shape: supported,
                requires_adoption: true,
                settings: settings.clone(),
                applied: applied.clone(),
            })
        };
        Ok(Device {
            interface: name.into(),
            device_path: path,
            device_type,
            active_connection_path: active,
            managed,
            state,
            active_profile,
        })
    }
    fn snapshot(&self, deadline: Instant) -> Result<Value> {
        Ok(self.capture(deadline)?.0)
    }
    fn capture(&self, deadline: Instant) -> Result<(Value, Vec<Device>)> {
        if let Some(engine) = &self.engine {return engine.capture_source(deadline);}
        let identity = self.identity(deadline)?;
        let owner = &identity.service_owner;
        let version = string(&self.property(owner, ROOT, NAME, "Version", "s", deadline)?)?;
        let mut devices = Vec::new();
        for name in &self.config.interfaces {
            devices.push(self.device(owner, name, deadline)?);
        }
        let mut rechecked = Vec::new();
        for name in &self.config.interfaces {
            rechecked.push(self.device(owner, name, deadline)?);
        }
        ensure!(
            devices == rechecked,
            "CONFLICT: NM device or profile changed during observation"
        );
        ensure!(
            identity == self.identity(deadline)?,
            "CONFLICT: NM bus or owner changed during observation"
        );
        ensure!(
            Instant::now() < deadline,
            "TIMEOUT: NM observation deadline"
        );
        let source = json!({"identity":identity,"version":version,"devices":&devices});
        // NM-managed version counters (appliedVersion, profile versionId)
        // advance on every re-apply and checkpoint rollback without any
        // user-facing change; the source digest binds content, not counters.
        let mut sanitized = source.clone();
        for device in sanitized["devices"]
            .as_array_mut()
            .context("CONFLICT: NM source devices")?
            .iter_mut()
        {
            if let Some(profile) = device["activeProfile"].as_object_mut() {
                profile.remove("appliedVersion");
                profile.remove("versionId");
            }
        }
        Ok((
            json!({"schemaVersion":1,"backend":"NetworkManager","writeEnabled":false,
            "sourceDigest":digest(&sanitized)?,"source":source}),
            devices,
        ))
    }
}

#[cfg(test)]
mod tests;
