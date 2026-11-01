//! Single writer for managed wired Netplan state. Unconfirmed YAML exists only
//! under /run: a reboot cannot make a candidate the persistent boot default.
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use serde_yaml_ng as serde_yaml;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use yofc_management_protocol::v1::{NetworkAction, NetworkChange, WiredConfig};
mod kura;
mod outcome;
mod takeover;
mod writers;
use takeover::Transfer;

pub fn error_code(error: &anyhow::Error) -> &'static str {
    let text = error.to_string();
    for code in [
        "CONFLICT",
        "FORBIDDEN",
        "INVALID_ARGUMENT",
        "NOT_FOUND",
        "RESOURCE_EXHAUSTED",
        "UNSUPPORTED",
        "TIMEOUT",
    ] {
        if text.starts_with(code) {
            return code;
        }
    }
    "INTERNAL"
}

pub fn diagnostic(error: &anyhow::Error) -> Option<String> {
    // Only our stable, deliberately authored domain errors are public. OS,
    // serializer and subprocess errors can contain private details.
    (error_code(error) != "INTERNAL").then(|| {
        error
            .to_string()
            .chars()
            .filter(|c| !c.is_control())
            .take(512)
            .collect()
    })
}

const FILE: &str = "90-yofc-managed.yaml";
const LIMIT: u64 = 1_048_576;
const TERMINAL: &[&str] = &["COMMITTED", "ROLLED_BACK"];

#[derive(Clone)]
pub struct Network(Arc<Mutex<Engine>>, Arc<Engine>);
#[derive(Clone)]
struct Engine {
    root: PathBuf,
    state: PathBuf,
    allow: Vec<String>,
    netplan: PathBuf,
    allow_virtual: Arc<std::sync::atomic::AtomicBool>,
    _lock: Arc<File>,
    #[cfg(test)]
    fake: bool,
}
#[derive(Clone, Serialize, Deserialize, Default)]
struct Confirmed {
    revision: u64,
    yaml: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    id: String,
    key: String,
    request_hash: String,
    state: String,
    old: Confirmed,
    candidate: String,
    sources: String,
    source_files: BTreeMap<String, Vec<u8>>,
    deadline_ms: u64,
    token: String,
    session: String,
    diagnostic: Option<String>,
    confirmed_decision: bool,
    config: WiredConfig,
    before: Runtime,
    #[serde(default)]
    transfer: Option<Transfer>,
    #[serde(default)]
    writers: Option<writers::Snapshot>,
    #[serde(default)]
    confirmation_command: Option<String>,
    #[serde(default)]
    rollback_command: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, Default)]
struct Runtime {
    addresses: Vec<String>,
    mtu: u32,
    #[serde(default)]
    link_up: Option<bool>,
    #[serde(default)]
    routes: Vec<Value>,
    #[serde(default)]
    global_ipv6: Vec<String>,
    #[serde(default)]
    addresses6: Vec<String>,
}

fn owns_interface(confirmed: &Confirmed, interface: &str) -> Result<bool> {
    let doc: Value = match &confirmed.yaml {
        Some(yaml) => serde_yaml::from_str(yaml)?,
        None => Value::Null,
    };
    Ok(doc["network"]["ethernets"].get(interface).is_some())
}

fn validate_initial_runtime(
    confirmed: &Confirmed,
    interface: &str,
    before: &Runtime,
) -> Result<()> {
    if !owns_interface(confirmed, interface)? {
        ensure!(
            before.addresses.is_empty()
                && before.routes.is_empty()
                && before.global_ipv6.is_empty(),
            "CONFLICT: existing runtime configuration requires explicit takeover"
        );
    }
    Ok(())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file()
            && meta.len() <= LIMIT
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o022 == 0,
        "CONFLICT: unsafe configuration source"
    );
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= LIMIT, "RESOURCE_EXHAUSTED");
    Ok(bytes)
}
fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap();
    let tmp = parent.join(format!(".yofc-{}", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn remove(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
        File::open(path.parent().unwrap())?.sync_all()?;
    }
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o022 == 0,
        "FORBIDDEN: unsafe directory"
    );
    Ok(())
}
fn validate(c: &WiredConfig) -> Result<()> {
    ensure!(
        !c.interface.is_empty()
            && c.interface.len() <= 15
            && c.interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
        "INVALID_ARGUMENT: interface"
    );
    ensure!(
        (576..=9000).contains(&c.mtu)
            && c.dhcp_metric <= 65535
            && c.addresses.len() <= 16
            && c.routes.len() <= 32
            && c.nameservers.len() <= 8
            && c.search_domains.len() <= 8,
        "INVALID_ARGUMENT: bounds"
    );
    ensure!(
        c.dhcp4 || !c.addresses.is_empty(),
        "INVALID_ARGUMENT: DHCP or static address required"
    );
    let mut seen = std::collections::HashSet::new();
    for a in &c.addresses {
        let (ip, prefix) = a
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT: CIDR"))?;
        let ip: Ipv4Addr = ip.parse()?;
        let prefix: u8 = prefix.parse()?;
        ensure!(
            prefix <= 32
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && seen.insert(ip),
            "INVALID_ARGUMENT: address"
        );
    }
    let mut routes = std::collections::HashSet::new();
    for r in &c.routes {
        ensure!(
            r.metric <= 65535 && routes.insert((&r.to, r.metric)),
            "INVALID_ARGUMENT: duplicate route"
        );
        if r.to != "default" {
            let (ip, p) =
                r.to.split_once('/')
                    .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT: route"))?;
            ip.parse::<Ipv4Addr>()?;
            ensure!(p.parse::<u8>()? <= 32, "INVALID_ARGUMENT: prefix");
        }
        let via: Ipv4Addr = r.via.parse()?;
        ensure!(
            !via.is_unspecified() && !via.is_multicast() && !via.is_loopback(),
            "INVALID_ARGUMENT: route gateway"
        );
    }
    for n in &c.nameservers {
        n.parse::<IpAddr>()?;
    }
    for s in &c.search_domains {
        ensure!(
            !s.is_empty()
                && s.len() <= 253
                && s.split('.').all(|p| !p.is_empty()
                    && p.len() <= 63
                    && !p.starts_with('-')
                    && !p.ends_with('-')
                    && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
            "INVALID_ARGUMENT: search domain"
        );
    }
    Ok(())
}
impl Network {
    pub fn open(root: PathBuf, state: PathBuf, allow: Vec<String>) -> Result<Self> {
        private_dir(&state)?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(state.join("coordinator.lock"))?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "CONFLICT: another system writer"
        );
        let engine = Engine {
            root,
            state,
            allow,
            netplan: PathBuf::from("/usr/sbin/netplan"),
            allow_virtual: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            _lock: Arc::new(lock),
            #[cfg(test)]
            fake: false,
        };
        let observer = Arc::new(engine.clone());
        Ok(Self(Arc::new(Mutex::new(engine)), observer))
    }
    pub fn allow_virtual_fixture(&self) {
        self.0
            .lock()
            .unwrap()
            .allow_virtual
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub async fn request(
        &self,
        method: String,
        change: Option<NetworkChange>,
        action: Option<NetworkAction>,
        key: String,
        session: String,
    ) -> Result<Value> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            // Queries read atomic durable snapshots without acquiring the writer lock.
            if method == "network.inspect" {
                return this.1.inspect();
            }
            if method == "network.transaction" {
                let a = action.ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT"))?;
                let j = this
                    .1
                    .journal()?
                    .ok_or_else(|| anyhow::anyhow!("NOT_FOUND"))?;
                ensure!(j.id == a.transaction_id, "NOT_FOUND");
                return Ok(this.1.view(&j));
            }
            let mut e = this
                .0
                .try_lock()
                .map_err(|_| anyhow::anyhow!("CONFLICT: system change in progress"))?;
            match method.as_str() {
                "network.inspect" => e.inspect(),
                "network.prepare" => e.prepare(
                    change.ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT"))?,
                    &key,
                    &session,
                ),
                "network.confirm" | "network.rollback" | "network.transaction" => e.action_bound(
                    &method,
                    action.ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT"))?,
                    &session,
                    Some(&key),
                ),
                _ => bail!("UNSUPPORTED"),
            }
        })
        .await?
    }
    pub async fn recover(&self) -> Result<()> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            this.0
                .lock()
                .map_err(|_| anyhow::anyhow!("INTERNAL"))?
                .recover()
        })
        .await?
    }
    pub async fn expire(&self) -> Result<()> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let Ok(e) = this.0.try_lock() else {
                return Ok(());
            };
            if let Some(j) = e.journal()?
                && j.state == "WAIT_CONFIRM"
                && now() >= j.deadline_ms
            {
                e.rollback(j)?;
            }
            Ok(())
        })
        .await?
    }
}
impl Engine {
    fn ip_json(&self, args: &[&str]) -> Result<Value> {
        self.json_command(Path::new("/usr/sbin/ip"), args)
    }
    fn json_command(&self, program: &Path, args: &[&str]) -> Result<Value> {
        let path = self.state.join(format!("ip-{}.json", Uuid::new_v4()));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        let result = (|| {
            let mut child = Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(file)
                .stderr(Stdio::null())
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(status) = child.try_wait()? {
                    ensure!(status.success(), "INTERNAL: runtime inspection failed");
                    break;
                }
                if Instant::now() >= deadline {
                    child.kill()?;
                    child.wait()?;
                    bail!("TIMEOUT: runtime inspection");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(serde_json::from_slice(&read(&path)?)?)
        })();
        remove(&path)?;
        result
    }
    fn runtime(&self, interface: &str) -> Result<Runtime> {
        #[cfg(test)]
        if self.fake {
            return Ok(Runtime {
                addresses: vec![],
                mtu: 1500,
                link_up: Some(true),
                ..Runtime::default()
            });
        }
        let v = self.ip_json(&["-json", "address", "show", "dev", interface])?;
        let row = v
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| anyhow::anyhow!("NOT_FOUND: interface"))?;
        let addresses = row["addr_info"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|a| a["family"] == "inet")
            .map(|a| {
                format!(
                    "{}/{}",
                    a["local"].as_str().unwrap_or(""),
                    a["prefixlen"].as_u64().unwrap_or(0)
                )
            })
            .collect();
        Ok(Runtime {
            addresses,
            mtu: row["mtu"].as_u64().unwrap_or(0) as u32,
            link_up: Some(
                row["flags"]
                    .as_array()
                    .is_some_and(|flags| flags.iter().any(|v| v == "UP")),
            ),
            routes: self
                .ip_json(&["-json", "-4", "route", "show", "dev", interface])?
                .as_array()
                .cloned()
                .unwrap_or_default(),
            global_ipv6: row["addr_info"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|a| a["family"] == "inet6" && a["scope"] != "link" && a["scope"] != "host")
                .filter_map(|a| a["local"].as_str().map(str::to_owned))
                .collect(),
            addresses6: row["addr_info"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|a| a["family"] == "inet6")
                .map(|a| {
                    format!(
                        "{}/{}",
                        a["local"].as_str().unwrap_or(""),
                        a["prefixlen"].as_u64().unwrap_or(0)
                    )
                })
                .collect(),
        })
    }
    fn verify_candidate(&self, j: &Journal) -> Result<()> {
        #[cfg(test)]
        if self.fake {
            return Ok(());
        }
        let current = self.runtime(&j.config.interface)?;
        ensure!(
            current.mtu == j.config.mtu
                && j.config
                    .addresses
                    .iter()
                    .all(|a| current.addresses.contains(a)),
            "CONFLICT: candidate address or MTU readback"
        );
        if j.config.dhcp4 {
            ensure!(
                !current.addresses.is_empty(),
                "CONFLICT: DHCP lease not available for confirmation"
            );
        }
        let routes = self.ip_json(&["-json", "-4", "route", "show", "dev", &j.config.interface])?;
        for r in &j.config.routes {
            ensure!(
                routes
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|a| a["dst"] == r.to
                        && a["gateway"] == r.via
                        && a["metric"].as_u64().unwrap_or(0) == r.metric as u64),
                "CONFLICT: candidate route readback"
            );
        }
        Ok(())
    }
    fn verify_rollback(&self, j: &Journal) -> Result<()> {
        #[cfg(test)]
        if self.fake {
            return Ok(());
        }
        let current = self.runtime(&j.config.interface)?;
        ensure!(
            current.mtu == j.before.mtu
                && j.before
                    .link_up
                    .is_none_or(|up| current.link_up == Some(up))
                && j.before
                    .addresses
                    .iter()
                    .all(|a| current.addresses.contains(a))
                && j.config
                    .addresses
                    .iter()
                    .filter(|a| !j.before.addresses.contains(a))
                    .all(|a| !current.addresses.contains(a)),
            "CONFLICT: rollback runtime address or MTU readback"
        );
        let routes = self.ip_json(&["-json", "-4", "route", "show", "dev", &j.config.interface])?;
        let old: Value = if let Some(t) = &j.transfer {
            serde_yaml::from_slice(&t.original)?
        } else {
            match &j.old.yaml {
                Some(y) => serde_yaml::from_str(y)?,
                None => Value::Null,
            }
        };
        let old_routes = old["network"]["ethernets"][&j.config.interface]["routes"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for route in &j.config.routes {
            let exists = |v: &Value| {
                v["dst"] == route.to
                    && v["gateway"] == route.via
                    && v["metric"].as_u64().unwrap_or(0) == route.metric as u64
            };
            let previously_configured = old_routes.iter().any(|v| {
                v["to"] == route.to
                    && v["via"] == route.via
                    && v["metric"].as_u64().unwrap_or(0) == route.metric as u64
            });
            ensure!(
                previously_configured || !routes.as_array().into_iter().flatten().any(exists),
                "CONFLICT: candidate route remains after rollback"
            );
        }
        Ok(())
    }
    fn path(&self, dir: &str) -> PathBuf {
        self.root.join(dir).join(FILE)
    }
    fn confirmed(&self) -> Result<Confirmed> {
        let path = self.state.join("confirmed.json");
        if path.exists() {
            Ok(serde_json::from_slice(&read(&path)?)?)
        } else {
            Ok(Confirmed::default())
        }
    }
    fn journal(&self) -> Result<Option<Journal>> {
        let path = self.state.join("transaction.json");
        if path.exists() {
            Ok(Some(serde_json::from_slice(&read(&path)?)?))
        } else {
            Ok(None)
        }
    }
    fn save(&self, j: &Journal) -> Result<()> {
        atomic(
            &self.state.join("transaction.json"),
            &serde_json::to_vec(j)?,
        )
    }
    fn view(&self, j: &Journal) -> Value {
        json!({"id":j.id,"state":j.state,"revision":if j.state=="COMMITTED"{j.old.revision+1}else{j.old.revision},"deadlineUnixMs":j.deadline_ms,"confirmationToken":j.token,"diagnostic":j.diagnostic})
    }
    fn sources(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut map = BTreeMap::new();
        for dir in ["lib/netplan", "etc/netplan", "run/netplan"] {
            let base = self.root.join(dir);
            if !base.exists() {
                continue;
            }
            for entry in fs::read_dir(base)? {
                let path = entry?.path();
                if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
                    continue;
                }
                let relative = format!(
                    "{dir}/{}",
                    path.file_name()
                        .unwrap()
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("CONFLICT"))?
                );
                // Own candidate is checked against the journal separately.
                if relative == format!("run/netplan/{FILE}") {
                    continue;
                }
                ensure!(map.len() < 64, "RESOURCE_EXHAUSTED: too many sources");
                map.insert(relative, read(&path)?);
            }
        }
        ensure!(
            map.values().map(Vec::len).sum::<usize>() <= 131072,
            "RESOURCE_EXHAUSTED: source bytes"
        );
        Ok(map)
    }
    fn digest(s: &BTreeMap<String, Vec<u8>>) -> String {
        hash(&serde_json::to_vec(s).unwrap())
    }
    fn inspect(&self) -> Result<Value> {
        let sources = self.sources()?;
        let mut interfaces = Vec::new();
        let net = self.root.join("sys/class/net");
        if net.exists() {
            for entry in fs::read_dir(net)? {
                let p = entry?.path();
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                let text = |f: &str| {
                    fs::read_to_string(p.join(f))
                        .unwrap_or_default()
                        .trim()
                        .to_owned()
                };
                let runtime = if cfg!(target_os = "linux") {
                    self.runtime(&name)
                        .ok()
                        .map(|v| serde_json::to_value(v).unwrap())
                } else {
                    None
                };
                interfaces.push(json!({"name":name,"mac":text("address"),"carrier":text("carrier"),"mtu":text("mtu"),"physical":p.join("device").exists(),"wired":text("type")=="1" && !p.join("wireless").exists(),"allowed":self.allow.contains(&name),"runtime":runtime}));
            }
        }
        let confirmed = self.confirmed()?;
        Ok(
            json!({"revision":confirmed.revision,"confirmedYaml":confirmed.yaml,"sourceDigest":Self::digest(&sources),"sources":sources.iter().map(|(p,v)|json!({"path":p,"sha256":hash(v)})).collect::<Vec<_>>(),"interfaces":interfaces,"transaction":self.journal()?.map(|j|self.view(&j)),"writeEnabled":!self.allow.is_empty(),"candidateStorage":"volatile-run","confirmSeconds":{"min":30,"max":300}}),
        )
    }
    fn ownership(
        &self,
        sources: &BTreeMap<String, Vec<u8>>,
        c: &WiredConfig,
        confirmed: &Confirmed,
    ) -> Result<()> {
        ensure!(
            self.allow.contains(&c.interface),
            "FORBIDDEN: interface not explicitly delegated"
        );
        let device = self.root.join("sys/class/net").join(&c.interface);
        ensure!(
            device.exists()
                && (self
                    .allow_virtual
                    .load(std::sync::atomic::Ordering::Relaxed)
                    || device.join("device").exists()),
            "UNSUPPORTED: physical wired device required"
        );
        ensure!(
            fs::read_to_string(device.join("type"))?.trim() == "1"
                && !device.join("wireless").exists(),
            "UNSUPPORTED: wired ethernet required"
        );
        let managed = format!("etc/netplan/{FILE}");
        let actual = sources
            .get(&managed)
            .map(|v| String::from_utf8_lossy(v).to_string());
        ensure!(
            actual == confirmed.yaml,
            "CONFLICT: persistent managed file drift or unadopted source"
        );
        for (path, bytes) in sources {
            if path == &managed {
                continue;
            }
            let value: Value = serde_yaml::from_slice(bytes)?;
            let n = &value["network"];
            // Match rules and complex topologies can indirectly own a target.
            for section in ["bridges", "bonds", "vlans", "tunnels", "wifis"] {
                ensure!(
                    n[section].as_object().is_none_or(|m| m.is_empty()),
                    "CONFLICT: topology requires explicit takeover plan"
                );
            }
            if let Some(entries) = n["ethernets"].as_object() {
                for (name, v) in entries {
                    ensure!(
                        name != &c.interface
                            && v.get("match").is_none()
                            && v.get("set-name").is_none(),
                        "CONFLICT: interface has an external or matched writer"
                    );
                }
            }
        }
        Ok(())
    }
    fn candidate(&self, c: &WiredConfig, old: &Confirmed) -> Result<String> {
        let mut doc: Value = match &old.yaml {
            Some(y) => serde_yaml::from_str(y)?,
            None => json!({"network":{"version":2,"ethernets":{}}}),
        };
        let previous = &doc["network"]["ethernets"][&c.interface];
        let mut config = json!({"renderer":"networkd","dhcp4":c.dhcp4,"addresses":c.addresses,"mtu":c.mtu,"optional":c.optional,"nameservers":{"addresses":c.nameservers,"search":c.search_domains},"routes":c.routes.iter().map(|r|json!({"to":r.to,"via":r.via,"metric":r.metric})).collect::<Vec<_>>()});
        if c.dhcp4 {
            config["dhcp4-overrides"] = json!({"route-metric":c.dhcp_metric});
        }
        // IPv6 settings are preserved verbatim; this module never claims to own them.
        for k in [
            "dhcp6",
            "accept-ra",
            "ipv6-privacy",
            "ipv6-mtu",
            "link-local",
        ] {
            if let Some(v) = previous.get(k) {
                config[k] = v.clone();
            }
        }
        if let Some(addresses) = previous["addresses"].as_array() {
            for a in addresses {
                if a.as_str().is_some_and(|s| s.contains(':')) {
                    config["addresses"].as_array_mut().unwrap().push(a.clone());
                }
            }
        }
        if let Some(routes) = previous["routes"].as_array() {
            for r in routes {
                if r["via"].as_str().is_some_and(|s| s.contains(':'))
                    || r["to"].as_str().is_some_and(|s| s.contains(':'))
                {
                    config["routes"].as_array_mut().unwrap().push(r.clone());
                }
            }
        }
        doc["network"]["ethernets"][&c.interface] = config;
        Ok(serde_yaml::to_string(&doc)?)
    }
    fn command(&self, args: &[&str]) -> Result<()> {
        self.execute(&self.netplan, args)
    }
    fn execute(&self, program: &Path, args: &[&str]) -> Result<()> {
        #[cfg(test)]
        if self.fake {
            return Ok(());
        }
        use std::os::unix::process::CommandExt;
        let mut child = Command::new(program)
            .args(args)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait()? {
                ensure!(status.success(), "INTERNAL: network command failed");
                return Ok(());
            }
            if Instant::now() >= deadline {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                };
                child.wait()?;
                bail!("TIMEOUT: network command may have partially applied");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn generate(&self, sources: &BTreeMap<String, Vec<u8>>, yaml: &str) -> Result<()> {
        self.generated_backend(sources, Some(yaml)).map(|_| ())
    }
    fn prepare(&mut self, change: NetworkChange, key: &str, session: &str) -> Result<Value> {
        let request_hash = hash(&serde_json::to_vec(&change)?);
        self.prepare_with(change, key, session, None, request_hash)
    }
    fn deduplicate(&self, key: &str, request_hash: &str) -> Result<Option<Value>> {
        let path = self
            .state
            .join(format!("receipt-{}.json", hash(key.as_bytes())));
        let previous = if path.exists() {
            Some(serde_json::from_slice::<Journal>(&read(&path)?)?)
        } else {
            self.journal()?.filter(|j| j.key == key)
        };
        if let Some(j) = previous {
            ensure!(j.request_hash == request_hash, "CONFLICT: reused key");
            return Ok(Some(self.view(&j)));
        }
        Ok(None)
    }
    fn prepare_with(
        &mut self,
        change: NetworkChange,
        key: &str,
        session: &str,
        transfer: Option<Transfer>,
        request_hash: String,
    ) -> Result<Value> {
        ensure!(
            !key.is_empty() && key.len() <= 64,
            "INVALID_ARGUMENT: idempotency key"
        );
        // Durable deduplication is independent of remote result-cache retention.
        if let Some(view) = self.deduplicate(key, &request_hash)? {
            return Ok(view);
        }
        if let Some(j) = self.journal()? {
            if j.key == key {
                ensure!(j.request_hash == request_hash, "CONFLICT: reused key");
                return Ok(self.view(&j));
            }
            ensure!(
                TERMINAL.contains(&j.state.as_str()),
                "CONFLICT: unresolved system transaction"
            );
            self.receipt(&j)?;
        }
        ensure!(
            !self.path("run/netplan").exists(),
            "CONFLICT: orphaned runtime candidate"
        );
        ensure!(
            fs::read_dir(&self.state)?
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with("receipt-"))
                .count()
                < 8192,
            "RESOURCE_EXHAUSTED: network history retention requires maintenance"
        );
        ensure!(
            (30..=300).contains(&change.confirm_seconds),
            "INVALID_ARGUMENT: confirmation window"
        );
        let c = change
            .config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT: config"))?;
        validate(c).map_err(|e| anyhow::anyhow!("INVALID_ARGUMENT: {e}"))?;
        let old = self.confirmed()?;
        ensure!(
            old.revision == change.expected_revision && old.revision < u64::MAX,
            "CONFLICT: revision"
        );
        let sources = self.sources()?;
        ensure!(
            Self::digest(&sources) == change.source_digest,
            "CONFLICT: source digest"
        );
        if transfer.is_none() {
            self.ownership(&sources, c, &old)?;
        }
        let writers = self.writer_snapshot(&sources, &c.interface)?;
        if let Some(previous) = transfer.as_ref().and_then(|t| t.writers.as_ref()) {
            ensure!(
                previous == &writers,
                "CONFLICT: reviewed backend state changed"
            );
        }
        let before = self.runtime(&c.interface)?;
        if transfer.is_none() {
            validate_initial_runtime(&old, &c.interface, &before)?;
        }
        let candidate = if let Some(t) = &transfer {
            t.candidate.clone()
        } else {
            self.candidate(c, &old)?
        };
        ensure!(candidate.len() <= 65536, "RESOURCE_EXHAUSTED");
        let mut staged = sources.clone();
        if let Some(t) = &transfer {
            staged.insert(t.shadow.clone(), t.normalized.clone());
        }
        self.generate(&staged, &candidate)?;
        ensure!(
            self.writer_snapshot(&sources, &c.interface)? == writers,
            "CONFLICT: backend state changed during validation"
        );
        ensure!(
            Self::digest(&self.sources()?) == change.source_digest,
            "CONFLICT: sources changed during validation"
        );
        let mut j = Journal {
            id: Uuid::new_v4().to_string(),
            key: key.into(),
            request_hash,
            state: "PREPARED".into(),
            old,
            candidate,
            sources: change.source_digest,
            source_files: sources,
            deadline_ms: now() + change.confirm_seconds as u64 * 1000,
            token: Uuid::new_v4().to_string(),
            session: session.into(),
            diagnostic: None,
            confirmed_decision: false,
            config: c.clone(),
            before,
            transfer,
            writers: Some(writers),
            confirmation_command: None,
            rollback_command: None,
        };
        self.save(&j)?;
        j.state = "APPLYING".into();
        self.save(&j)?;
        let result = (|| {
            private_dir(&self.root.join("run/netplan"))?;
            if let Some(t) = &j.transfer {
                atomic(&self.root.join(&t.shadow), &t.normalized)?;
            }
            atomic(&self.path("run/netplan"), j.candidate.as_bytes())?;
            self.command(&["apply"])
        })();
        if let Err(e) = result {
            j.diagnostic = Some(e.to_string());
            return self.rollback(j);
        }
        j.state = "WAIT_CONFIRM".into();
        self.save(&j)?;
        Ok(self.view(&j))
    }
    fn action(&mut self, method: &str, a: NetworkAction, session: &str) -> Result<Value> {
        self.action_bound(method, a, session, None)
    }
    fn action_bound(
        &mut self,
        method: &str,
        a: NetworkAction,
        session: &str,
        command: Option<&str>,
    ) -> Result<Value> {
        let mut j = self
            .journal()?
            .ok_or_else(|| anyhow::anyhow!("NOT_FOUND"))?;
        ensure!(j.id == a.transaction_id, "NOT_FOUND");
        if method == "network.transaction" {
            return Ok(self.view(&j));
        }
        if method == "network.rollback" {
            if j.state == "ROLLED_BACK" {
                return Ok(self.view(&j));
            }
            ensure!(j.state != "COMMITTED", "CONFLICT: already committed");
            j.rollback_command = command.map(str::to_owned);
            return self.rollback(j);
        }
        ensure!(
            j.token == a.confirmation_token && !a.confirmation_token.is_empty(),
            "FORBIDDEN: confirmation token"
        );
        if j.state == "COMMITTED" {
            return Ok(self.view(&j));
        }
        ensure!(j.state == "WAIT_CONFIRM", "CONFLICT: transaction state");
        if now() >= j.deadline_ms {
            return self.rollback(j);
        }
        // A command delivered on the old stream is not proof of a new management path.
        ensure!(
            session == "local-authorized"
                || session == "local-kura"
                || (!session.is_empty() && session != j.session),
            "CONFLICT: reconnect before confirming"
        );
        ensure!(
            Self::digest(&self.transaction_sources(&j)?) == j.sources
                && read(&self.path("run/netplan"))? == j.candidate.as_bytes(),
            "CONFLICT: candidate or source drift"
        );
        self.verify_candidate(&j)?;
        j.state = "COMMITTING".into();
        j.confirmed_decision = true;
        j.confirmation_command = command.map(str::to_owned);
        self.save(&j)?;
        self.commit(j)
    }
    fn commit(&self, mut j: Journal) -> Result<Value> {
        // A durable confirmation decision precedes every persistent system write.
        let result = (|| {
            let mut current = self.transaction_sources(&j)?;
            let mut expected = j.source_files.clone();
            let managed = format!("etc/netplan/{FILE}");
            let current_yaml = current.remove(&managed);
            let old_yaml = expected.remove(&managed);
            ensure!(
                current == expected
                    && (current_yaml == old_yaml
                        || current_yaml.as_deref() == Some(j.candidate.as_bytes())),
                "CONFLICT: source drift after confirmation"
            );
            private_dir(&self.root.join("etc/netplan"))?;
            atomic(&self.path("etc/netplan"), j.candidate.as_bytes())?;
            if let Some(t) = &j.transfer {
                self.normalize_source(t)?;
            }
            atomic(
                &self.state.join("confirmed.json"),
                &serde_json::to_vec(&Confirmed {
                    revision: j.old.revision + 1,
                    yaml: Some(j.candidate.clone()),
                })?,
            )?;
            remove(&self.path("run/netplan"))?;
            if let Some(t) = &j.transfer {
                self.remove_shadow(t)?;
            }
            self.command(&["apply"])?;
            Ok::<_, anyhow::Error>(())
        })();
        match result {
            Ok(()) => {
                j.state = "COMMITTED".into();
                j.diagnostic = None;
            }
            Err(e) => {
                j.state = "RECOVERY_REQUIRED".into();
                j.diagnostic = Some(format!("confirmed commit incomplete: {e}"));
            }
        }
        self.save(&j)?;
        self.receipt(&j)?;
        Ok(self.view(&j))
    }
    fn receipt(&self, j: &Journal) -> Result<()> {
        if TERMINAL.contains(&j.state.as_str()) {
            atomic(
                &self
                    .state
                    .join(format!("receipt-{}.json", hash(j.key.as_bytes()))),
                &serde_json::to_vec(j)?,
            )?;
            // A later transaction must not hide this transaction's durable
            // outcome from query-only receipt reconciliation.
            ensure!(
                Uuid::parse_str(&j.id).is_ok(),
                "INTERNAL: transaction identity"
            );
            atomic(
                &self.state.join(format!("transaction-{}.json", j.id)),
                &serde_json::to_vec(j)?,
            )?;
        }
        Ok(())
    }
    fn rollback(&self, mut j: Journal) -> Result<Value> {
        ensure!(
            !j.confirmed_decision,
            "CONFLICT: confirmation already durably accepted"
        );
        j.state = "ROLLING_BACK".into();
        self.save(&j)?;
        // Persistent files were never changed by PREPARED/APPLYING/WAIT_CONFIRM.
        // Refuse to claim recovery when another writer changed the boot default.
        let result = (|| {
            ensure!(
                Self::digest(&self.transaction_sources(&j)?) == j.sources,
                "CONFLICT: source drift needs operator recovery"
            );
            if self.path("run/netplan").exists() {
                ensure!(
                    read(&self.path("run/netplan"))? == j.candidate.as_bytes(),
                    "CONFLICT: runtime source drift"
                );
                remove(&self.path("run/netplan"))?;
            }
            if let Some(t) = &j.transfer {
                self.remove_shadow(t)?;
            }
            self.command(&["apply"])?;
            ensure!(
                !self.path("run/netplan").exists() && Self::digest(&self.sources()?) == j.sources,
                "CONFLICT: rollback readback"
            );
            // Removing the first .network clears its addresses, but networkd
            // leaves link properties (notably MTU) at their candidate value.
            // Compensate only this previously empty, explicitly delegated link.
            if j.transfer.is_none() && !owns_interface(&j.old, &j.config.interface)? {
                let current = self.runtime(&j.config.interface)?;
                ensure!(
                    current.mtu == j.before.mtu || current.mtu == j.config.mtu,
                    "CONFLICT: external MTU drift during rollback"
                );
                if current.mtu != j.before.mtu {
                    self.execute(
                        Path::new("/usr/sbin/ip"),
                        &[
                            "link",
                            "set",
                            "dev",
                            &j.config.interface,
                            "mtu",
                            &j.before.mtu.to_string(),
                        ],
                    )?;
                }
                if let Some(up) = j.before.link_up
                    && current.link_up != Some(up)
                {
                    self.execute(
                        Path::new("/usr/sbin/ip"),
                        &[
                            "link",
                            "set",
                            "dev",
                            &j.config.interface,
                            if up { "up" } else { "down" },
                        ],
                    )?;
                }
            }
            self.verify_rollback(&j)?;
            Ok::<_, anyhow::Error>(())
        })();
        match result {
            Ok(()) => j.state = "ROLLED_BACK".into(),
            Err(e) => {
                j.state = "RECOVERY_REQUIRED".into();
                j.diagnostic = Some(e.to_string());
            }
        }
        self.save(&j)?;
        self.receipt(&j)?;
        Ok(self.view(&j))
    }
    fn recover(&mut self) -> Result<()> {
        if let Some(j) = self.journal()? {
            if j.confirmed_decision && j.state != "COMMITTED" {
                self.commit(j)?;
            } else if !TERMINAL.contains(&j.state.as_str()) && j.state != "RECOVERY_REQUIRED" {
                self.rollback(j)?;
            }
        } else {
            ensure!(
                !self.path("run/netplan").exists(),
                "CONFLICT: orphaned candidate"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yofc_management_protocol::v1::StaticRoute;
    #[test]
    fn diagnostic_excludes_internal_details_and_bounds_domain_messages() {
        assert!(diagnostic(&anyhow::anyhow!("private source contents")).is_none());
        assert_eq!(
            diagnostic(&anyhow::anyhow!("CONFLICT: foreign backend\nfile")),
            Some("CONFLICT: foreign backendfile".into())
        );
        assert_eq!(
            diagnostic(&anyhow::anyhow!("CONFLICT: {}", "x".repeat(1000)))
                .unwrap()
                .len(),
            512
        );
    }
    struct Fixture {
        path: PathBuf,
        network: Option<Network>,
    }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("yofc-network-{}", Uuid::new_v4()));
            for dir in [
                "etc/netplan",
                "run/netplan",
                "lib/netplan",
                "sys/class/net/test0/device",
            ] {
                fs::create_dir_all(path.join(dir)).unwrap();
            }
            fs::write(path.join("sys/class/net/test0/type"), "1\n").unwrap();
            let mut network =
                Network::open(path.clone(), path.join("state"), vec!["test0".into()]).unwrap();
            network.0.lock().unwrap().fake = true;
            // Keep observation fake too: a real ip(8) fork briefly inherits
            // parallel tests' flock descriptors until exec, disturbing reopen.
            Arc::get_mut(&mut network.1).unwrap().fake = true;
            Self {
                path,
                network: Some(network),
            }
        }
        fn engine(&self) -> std::sync::MutexGuard<'_, Engine> {
            self.network.as_ref().unwrap().0.lock().unwrap()
        }
        fn change(&self) -> NetworkChange {
            let engine = self.engine();
            NetworkChange {
                expected_revision: engine.confirmed().unwrap().revision,
                config: Some(WiredConfig {
                    interface: "test0".into(),
                    dhcp4: false,
                    addresses: vec!["192.0.2.2/24".into()],
                    routes: vec![StaticRoute {
                        to: "default".into(),
                        via: "192.0.2.1".into(),
                        metric: 100,
                    }],
                    nameservers: vec!["192.0.2.53".into()],
                    search_domains: vec!["example.test".into()],
                    mtu: 1500,
                    optional: true,
                    dhcp_metric: 100,
                }),
                confirm_seconds: 120,
                source_digest: Engine::digest(&engine.sources().unwrap()),
            }
        }
        fn reopen(&mut self) {
            drop(self.network.take());
            let n = Network::open(
                self.path.clone(),
                self.path.join("state"),
                vec!["test0".into()],
            )
            .unwrap();
            n.0.lock().unwrap().fake = true;
            self.network = Some(n);
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(self.network.take());
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
    fn action(j: &Value) -> NetworkAction {
        NetworkAction {
            transaction_id: j["id"].as_str().unwrap().into(),
            confirmation_token: j["confirmationToken"].as_str().unwrap().into(),
        }
    }
    #[test]
    fn interrupted_prepare_is_resolved_only_by_its_terminal_business_journal() {
        use yofc_management_protocol::v1::{ReadCommand, TaskState};
        let f = Fixture::new();
        let command = ReadCommand {
            command_id: Uuid::new_v4().to_string(),
            operation: 5,
            network_change: Some(f.change()),
            ..Default::default()
        };
        f.engine()
            .prepare(
                command.network_change.clone().unwrap(),
                &command.command_id,
                "s1",
            )
            .unwrap();
        assert!(f.engine().prove_outcome(&command).unwrap().is_none());
        f.engine().recover().unwrap();
        let before = fs::read(f.path.join("state/transaction.json")).unwrap();
        let proof = f.engine().prove_outcome(&command).unwrap().unwrap();
        assert_eq!(proof.state, TaskState::Failed as i32);
        let value: Value = serde_json::from_slice(&proof.result_json).unwrap();
        assert_eq!(value["state"], "ROLLED_BACK");
        assert_eq!(value["reconciliation"]["journalSha256"], hash(&before));
        assert_eq!(
            fs::read(f.path.join("state/transaction.json")).unwrap(),
            before
        );
        assert_eq!(f.engine().confirmed().unwrap().revision, 0);
        let mut changed = command.clone();
        changed
            .network_change
            .as_mut()
            .unwrap()
            .config
            .as_mut()
            .unwrap()
            .mtu = 1400;
        assert!(f.engine().prove_outcome(&changed).unwrap().is_none());
        changed = command.clone();
        changed.command_id = Uuid::new_v4().to_string();
        assert!(f.engine().prove_outcome(&changed).unwrap().is_none());
        // A newer transaction cannot erase an older prepare's proof.
        let next = f.change();
        f.engine().prepare(next, "newer", "s2").unwrap();
        assert!(f.engine().prove_outcome(&command).unwrap().is_some());
    }
    #[test]
    fn confirmation_proof_survives_crash_and_is_bound_to_the_accepting_command() {
        use yofc_management_protocol::v1::{ReadCommand, TaskState};
        let mut f = Fixture::new();
        let change = f.change();
        let view = f.engine().prepare(change, "prepare", "s1").unwrap();
        let command = ReadCommand {
            command_id: Uuid::new_v4().to_string(),
            operation: 6,
            network_action: Some(action(&view)),
            ..Default::default()
        };
        let mut journal = f.engine().journal().unwrap().unwrap();
        journal.state = "COMMITTING".into();
        journal.confirmed_decision = true;
        journal.confirmation_command = Some(command.command_id.clone());
        f.engine().save(&journal).unwrap();
        assert!(f.engine().prove_outcome(&command).unwrap().is_none());
        f.reopen();
        f.engine().recover().unwrap();
        assert_eq!(
            f.engine().prove_outcome(&command).unwrap().unwrap().state,
            TaskState::Succeeded as i32
        );
        let mut other = command.clone();
        other.command_id = Uuid::new_v4().to_string();
        assert!(f.engine().prove_outcome(&other).unwrap().is_none());
        other = command.clone();
        other.network_action.as_mut().unwrap().confirmation_token = "wrong".into();
        assert!(f.engine().prove_outcome(&other).unwrap().is_none());
        let next = f.change();
        f.engine().prepare(next, "newer", "s3").unwrap();
        assert!(f.engine().prove_outcome(&command).unwrap().is_some());
    }
    #[test]
    fn rollback_proof_does_not_infer_success_for_another_actor_or_legacy_marker() {
        use yofc_management_protocol::v1::{ReadCommand, TaskState};
        let f = Fixture::new();
        let change = f.change();
        let view = f.engine().prepare(change, "prepare", "s1").unwrap();
        let command = ReadCommand {
            command_id: Uuid::new_v4().to_string(),
            operation: 7,
            network_action: Some(action(&view)),
            ..Default::default()
        };
        f.engine()
            .action_bound(
                "network.rollback",
                action(&view),
                "s1",
                Some(&command.command_id),
            )
            .unwrap();
        assert_eq!(
            f.engine().prove_outcome(&command).unwrap().unwrap().state,
            TaskState::Succeeded as i32
        );
        let mut other = command.clone();
        other.command_id = Uuid::new_v4().to_string();
        assert!(f.engine().prove_outcome(&other).unwrap().is_none());
        let mut journal = f.engine().journal().unwrap().unwrap();
        journal.rollback_command = None;
        f.engine().save(&journal).unwrap();
        assert!(f.engine().prove_outcome(&command).unwrap().is_none());
        journal.state = "RECOVERY_REQUIRED".into();
        journal.rollback_command = Some(command.command_id.clone());
        f.engine().save(&journal).unwrap();
        assert!(f.engine().prove_outcome(&command).unwrap().is_none());
    }
    #[tokio::test]
    async fn task_query_closes_interrupted_prepare_without_replaying_the_network_action() {
        use prost::Message;
        use yofc_management_protocol::v1::{ReadCommand, TaskState};
        let f = Fixture::new();
        let path = f.path.join("executions.sqlite");
        let db = crate::transport::database(path.to_str().unwrap())
            .await
            .unwrap();
        let command = ReadCommand {
            command_id: Uuid::new_v4().to_string(),
            operation: 5,
            expires_at_unix_ms: 1,
            idempotency_key: "query-only".into(),
            network_change: Some(f.change()),
            ..Default::default()
        };
        let digest = hash(&command.encode_to_vec());
        crate::journal::claim(&db, &command, &digest).await.unwrap();
        // A crash after the network journal but before the execution receipt.
        f.engine()
            .prepare(
                command.network_change.clone().unwrap(),
                &command.command_id,
                "s1",
            )
            .unwrap();
        crate::journal::initialize(&db).await.unwrap();
        f.engine().recover().unwrap();
        let before = fs::read(f.path.join("state/transaction.json")).unwrap();
        let uid = unsafe { libc::geteuid() };
        let mut local = crate::local::Local::new(uid, uid);
        local.network = f.network.clone();
        let (a, b) = tokio::join!(
            crate::transport::query_receipt(&db, &local, &command.command_id),
            crate::transport::query_receipt(&db, &local, &command.command_id)
        );
        let states = [a.unwrap().state, b.unwrap().state];
        assert!(states.contains(&(TaskState::Failed as i32)));
        assert!(
            states
                .iter()
                .all(|s| *s == TaskState::Failed as i32 || *s == TaskState::Unknown as i32)
        );
        assert_eq!(
            crate::transport::query_receipt(&db, &local, &command.command_id)
                .await
                .unwrap()
                .state,
            TaskState::Failed as i32
        );
        assert_eq!(
            fs::read(f.path.join("state/transaction.json")).unwrap(),
            before
        );
        assert_eq!(f.engine().confirmed().unwrap().revision, 0);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM execution_resolutions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert!(
            crate::journal::claim(&db, &command, &digest)
                .await
                .unwrap()
                .is_some()
        );
        db.close().await;
    }
    #[test]
    fn candidate_confirmation_and_durable_deduplication() {
        let f = Fixture::new();
        let c = f.change();
        let j = f.engine().prepare(c.clone(), "one", "stream1").unwrap();
        assert_eq!(j["state"], "WAIT_CONFIRM");
        assert!(!f.path.join("etc/netplan").join(FILE).exists());
        assert!(f.path.join("run/netplan").join(FILE).exists());
        assert!(
            f.engine()
                .action("network.confirm", action(&j), "stream1")
                .is_err()
        );
        let mut bad = action(&j);
        bad.confirmation_token = "wrong".into();
        assert!(
            f.engine()
                .action("network.confirm", bad, "stream2")
                .is_err()
        );
        let done = f
            .engine()
            .action("network.confirm", action(&j), "stream2")
            .unwrap();
        assert_eq!(done["state"], "COMMITTED");
        assert_eq!(done["revision"], 1);
        assert!(!f.path.join("run/netplan").join(FILE).exists());
        assert_eq!(f.engine().prepare(c, "one", "stream3").unwrap(), done);
        assert_eq!(f.engine().confirmed().unwrap().revision, 1);
    }
    #[test]
    fn timeout_and_restart_leave_persistent_boot_configuration_untouched() {
        let mut f = Fixture::new();
        let c = f.change();
        let j = f.engine().prepare(c, "one", "stream1").unwrap();
        let mut journal = f.engine().journal().unwrap().unwrap();
        journal.deadline_ms = 0;
        f.engine().save(&journal).unwrap();
        assert_eq!(
            f.engine()
                .action("network.confirm", action(&j), "stream2")
                .unwrap()["state"],
            "ROLLED_BACK"
        );
        assert!(!f.path.join("etc/netplan").join(FILE).exists());
        let c = f.change();
        f.engine().prepare(c, "two", "stream1").unwrap();
        // Model a reboot: /run is tmpfs, /etc has never contained the candidate.
        fs::remove_file(f.path.join("run/netplan").join(FILE)).unwrap();
        f.reopen();
        f.engine().recover().unwrap();
        assert_eq!(f.engine().journal().unwrap().unwrap().state, "ROLLED_BACK");
        assert_eq!(f.engine().confirmed().unwrap().revision, 0);
    }
    #[test]
    fn confirmed_decision_is_completed_after_crash() {
        let mut f = Fixture::new();
        let c = f.change();
        f.engine().prepare(c, "one", "stream1").unwrap();
        let mut j = f.engine().journal().unwrap().unwrap();
        j.state = "COMMITTING".into();
        j.confirmed_decision = true;
        f.engine().save(&j).unwrap();
        f.reopen();
        f.engine().recover().unwrap();
        assert_eq!(f.engine().journal().unwrap().unwrap().state, "COMMITTED");
        assert_eq!(f.engine().confirmed().unwrap().revision, 1);
    }
    #[test]
    fn revision_sources_and_external_writers_fail_closed() {
        let f = Fixture::new();
        let mut c = f.change();
        c.expected_revision = 1;
        assert!(
            f.engine()
                .prepare(c, "one", "s")
                .unwrap_err()
                .to_string()
                .contains("revision")
        );
        let c = f.change();
        fs::write(
            f.path.join("etc/netplan/10-other.yaml"),
            "network:\n  version: 2\n  ethernets:\n    test0:\n      dhcp4: true\n",
        )
        .unwrap();
        assert!(
            f.engine()
                .prepare(c, "two", "s")
                .unwrap_err()
                .to_string()
                .contains("digest")
        );
        let c = f.change();
        assert!(
            f.engine()
                .prepare(c, "three", "s")
                .unwrap_err()
                .to_string()
                .contains("writer")
        );
        assert!(!f.path.join("run/netplan").join(FILE).exists());
    }
    #[test]
    fn candidate_drift_requires_operator_recovery() {
        let f = Fixture::new();
        let c = f.change();
        let j = f.engine().prepare(c, "one", "s").unwrap();
        fs::write(f.path.join("run/netplan").join(FILE), "external change").unwrap();
        assert!(
            f.engine()
                .action("network.confirm", action(&j), "s2")
                .is_err()
        );
        assert_eq!(
            f.engine()
                .action("network.rollback", action(&j), "s2")
                .unwrap()["state"],
            "RECOVERY_REQUIRED"
        );
        let c = f.change();
        assert!(f.engine().prepare(c, "two", "s2").is_err());
    }
    #[test]
    fn validation_and_ipv6_preservation() {
        let f = Fixture::new();
        let mut c = f.change().config.unwrap();
        c.mtu = 1;
        assert!(validate(&c).is_err());
        c.mtu = 1500;
        c.addresses = vec!["127.0.0.1/8".into()];
        assert!(validate(&c).is_err());
        c.addresses = vec!["192.0.2.2/24".into()];
        c.routes.push(c.routes[0].clone());
        assert!(validate(&c).is_err());
        c.routes.pop();
        let old=Confirmed{revision:1,yaml:Some("network:\n  version: 2\n  ethernets:\n    test0:\n      dhcp6: true\n      accept-ra: true\n      addresses: ['2001:db8::2/64']\n    other0:\n      dhcp4: true\n".into())};
        let yaml = f.engine().candidate(&c, &old).unwrap();
        let v: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(v["network"]["ethernets"]["test0"]["dhcp6"], true);
        assert_eq!(v["network"]["ethernets"]["other0"]["dhcp4"], true);
        assert!(
            v["network"]["ethernets"]["test0"]["addresses"]
                .as_array()
                .unwrap()
                .contains(&json!("2001:db8::2/64"))
        );
    }
    #[test]
    fn process_lock_and_unsafe_sources_are_rejected() {
        let f = Fixture::new();
        assert!(Network::open(f.path.clone(), f.path.join("state"), vec![]).is_err());
        std::os::unix::fs::symlink("/etc/passwd", f.path.join("etc/netplan/evil.yaml")).unwrap();
        assert!(f.engine().inspect().is_err());
    }

    #[test]
    fn first_interface_rejects_runtime_ownership_and_preserves_legacy_journals() {
        let empty = Confirmed::default();
        let mut before = Runtime {
            mtu: 1500,
            link_up: Some(false),
            ..Runtime::default()
        };
        assert!(validate_initial_runtime(&empty, "test0", &before).is_ok());
        before.addresses.push("192.0.2.40/24".into());
        assert!(validate_initial_runtime(&empty, "test0", &before).is_err());
        before.addresses.clear();
        before
            .routes
            .push(json!({"dst":"default","gateway":"192.0.2.1"}));
        assert!(validate_initial_runtime(&empty, "test0", &before).is_err());
        before.routes.clear();
        before.global_ipv6.push("2001:db8::40".into());
        assert!(validate_initial_runtime(&empty, "test0", &before).is_err());
        let owned = Confirmed {
            revision: 1,
            yaml: Some("network:\n  ethernets:\n    test0: {dhcp4: true}\n".into()),
        };
        assert!(validate_initial_runtime(&owned, "test0", &before).is_ok());
        let legacy: Runtime = serde_json::from_value(json!({"addresses":[], "mtu":1500})).unwrap();
        assert!(legacy.link_up.is_none());
        assert!(legacy.routes.is_empty());
    }

    fn foreign_source(f: &Fixture) -> PathBuf {
        let path = f.path.join("etc/netplan/40-existing.yaml");
        fs::write(&path, "network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    test0:\n      dhcp4: false\n      addresses: [192.0.2.40/24, '2001:db8::40/64']\n      accept-ra: false\n      mtu: 1500\n    other0:\n      dhcp4: true\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        path
    }
    fn takeover_input(f: &Fixture) -> yofc_management_protocol::v1::NetworkTakeover {
        let (_, plan) = f.engine().transfer_plan("test0").unwrap();
        yofc_management_protocol::v1::NetworkTakeover {
            interface: "test0".into(),
            expected_revision: plan["revision"].as_u64().unwrap(),
            source_digest: plan["sourceDigest"].as_str().unwrap().into(),
            plan_digest: plan["planDigest"].as_str().unwrap().into(),
            confirm_seconds: 120,
        }
    }
    #[test]
    fn takeover_keeps_original_boot_source_until_confirmation_and_restart() {
        let mut f = Fixture::new();
        let source = foreign_source(&f);
        let original = read(&source).unwrap();
        let input = takeover_input(&f);
        let j = f
            .engine()
            .prepare_takeover(input.clone(), "take", "stream1")
            .unwrap();
        assert_eq!(j["state"], "WAIT_CONFIRM");
        assert_eq!(read(&source).unwrap(), original);
        assert_eq!(fs::metadata(&source).unwrap().mode() & 0o777, 0o640);
        assert!(f.path.join("run/netplan/40-existing.yaml").exists());
        assert!(!f.path.join("etc/netplan").join(FILE).exists());
        // Volatile overlays disappear before a reboot recovery starts.
        remove(&f.path.join("run/netplan/40-existing.yaml")).unwrap();
        remove(&f.path.join("run/netplan").join(FILE)).unwrap();
        f.reopen();
        f.engine().recover().unwrap();
        assert_eq!(f.engine().journal().unwrap().unwrap().state, "ROLLED_BACK");
        assert_eq!(read(&source).unwrap(), original);
        assert_eq!(
            f.engine()
                .prepare_takeover(input, "take", "stream2")
                .unwrap()["state"],
            "ROLLED_BACK"
        );
    }
    #[test]
    fn takeover_proof_binds_the_reviewed_plan_and_confirmed_command_marker() {
        use yofc_management_protocol::v1::{ReadCommand, TaskState};
        let f = Fixture::new();
        foreign_source(&f);
        let input = takeover_input(&f);
        let prepare = ReadCommand {
            command_id: Uuid::new_v4().to_string(),
            operation: 10,
            network_takeover: Some(input.clone()),
            ..Default::default()
        };
        let view = f
            .engine()
            .prepare_takeover(input, &prepare.command_id, "s1")
            .unwrap();
        let confirm = ReadCommand {
            command_id: Uuid::new_v4().to_string(),
            operation: 6,
            network_action: Some(action(&view)),
            ..Default::default()
        };
        f.engine()
            .action_bound(
                "network.confirm",
                action(&view),
                "s2",
                Some(&confirm.command_id),
            )
            .unwrap();
        for command in [&prepare, &confirm] {
            assert_eq!(
                f.engine().prove_outcome(command).unwrap().unwrap().state,
                TaskState::Succeeded as i32
            );
        }
        let mut changed = prepare;
        changed.network_takeover.as_mut().unwrap().plan_digest = "different".into();
        assert!(f.engine().prove_outcome(&changed).unwrap().is_none());
    }
    #[test]
    fn takeover_confirmation_preserves_other_interfaces_ipv6_and_permissions() {
        let f = Fixture::new();
        let source = foreign_source(&f);
        let input = takeover_input(&f);
        let j = f
            .engine()
            .prepare_takeover(input, "take", "stream1")
            .unwrap();
        assert!(
            f.engine()
                .action("network.confirm", action(&j), "stream1")
                .is_err()
        );
        let result = f
            .engine()
            .action("network.confirm", action(&j), "stream2")
            .unwrap();
        assert_eq!(result["state"], "COMMITTED");
        let normalized: Value = serde_yaml::from_slice(&read(&source).unwrap()).unwrap();
        assert!(normalized["network"]["ethernets"].get("test0").is_none());
        assert_eq!(normalized["network"]["ethernets"]["other0"]["dhcp4"], true);
        let owned: Value =
            serde_yaml::from_str(f.engine().confirmed().unwrap().yaml.as_ref().unwrap()).unwrap();
        assert_eq!(
            owned["network"]["ethernets"]["test0"]["addresses"][1],
            "2001:db8::40/64"
        );
        assert_eq!(owned["network"]["ethernets"]["test0"]["accept-ra"], false);
        assert_eq!(fs::metadata(source).unwrap().mode() & 0o777, 0o640);
        assert!(!f.path.join("run/netplan/40-existing.yaml").exists());
    }
    #[test]
    fn accepted_takeover_completes_across_each_persistent_file_boundary() {
        for normalized in [false, true] {
            let mut f = Fixture::new();
            foreign_source(&f);
            let input = takeover_input(&f);
            f.engine()
                .prepare_takeover(input, "take", "stream1")
                .unwrap();
            let mut j = f.engine().journal().unwrap().unwrap();
            j.confirmed_decision = true;
            j.state = "COMMITTING".into();
            f.engine().save(&j).unwrap();
            atomic(
                &f.path.join("etc/netplan").join(FILE),
                j.candidate.as_bytes(),
            )
            .unwrap();
            if normalized {
                f.engine()
                    .normalize_source(j.transfer.as_ref().unwrap())
                    .unwrap();
            }
            remove(&f.path.join("run/netplan/40-existing.yaml")).unwrap();
            remove(&f.path.join("run/netplan").join(FILE)).unwrap();
            f.reopen();
            f.engine().recover().unwrap();
            assert_eq!(f.engine().journal().unwrap().unwrap().state, "COMMITTED");
            assert_eq!(f.engine().confirmed().unwrap().revision, 1);
        }
    }
    #[test]
    fn stale_takeover_plans_and_external_source_drift_fail_closed() {
        let f = Fixture::new();
        let path = foreign_source(&f);
        let input = takeover_input(&f);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            f.engine()
                .prepare_takeover(input, "stale", "stream1")
                .is_err()
        );
        assert!(f.engine().journal().unwrap().is_none());
        let input = takeover_input(&f);
        let j = f
            .engine()
            .prepare_takeover(input, "take", "stream1")
            .unwrap();
        fs::write(&path, "network: {version: 2}\n").unwrap();
        let result = f
            .engine()
            .action("network.rollback", action(&j), "stream2")
            .unwrap();
        assert_eq!(result["state"], "RECOVERY_REQUIRED");
        assert_eq!(fs::read_to_string(path).unwrap(), "network: {version: 2}\n");
    }
    #[test]
    fn foreign_backend_files_cannot_be_hidden_behind_netplan_names() {
        for relative in [
            "run/systemd/network/10-netplan-test0.network",
            "etc/systemd/network/20-local.network",
            "run/NetworkManager/system-connections/local.nmconnection",
            "usr/lib/systemd/network/01-before-netplan.network",
            "run/systemd/network/10-netplan-test0.network.d/extra.conf",
        ] {
            let f = Fixture::new();
            let path = f.path.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, "[Match]\nName=test0\n").unwrap();
            let change = f.change();
            let error = f
                .engine()
                .prepare(change, "foreign", "stream1")
                .unwrap_err();
            assert!(
                error.to_string().starts_with("CONFLICT:"),
                "{relative}: {error}"
            );
            assert!(f.engine().journal().unwrap().is_none());
            assert_eq!(fs::read_to_string(path).unwrap(), "[Match]\nName=test0\n");
        }
    }
    #[test]
    fn ordinary_transactions_bind_vendor_state_and_preserve_external_drift() {
        let f = Fixture::new();
        let path = f.path.join("usr/lib/systemd/network/80-default.network");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = "[Match]\nName=container-*\n";
        fs::write(&path, original).unwrap();
        let change = f.change();
        let j = f.engine().prepare(change, "ordinary", "stream1").unwrap();
        fs::write(&path, "[Match]\nName=test0\n").unwrap();
        assert!(
            f.engine()
                .action("network.confirm", action(&j), "stream2")
                .unwrap_err()
                .to_string()
                .starts_with("CONFLICT:")
        );
        let result = f
            .engine()
            .action("network.rollback", action(&j), "stream2")
            .unwrap();
        assert_eq!(result["state"], "RECOVERY_REQUIRED");
        assert_eq!(fs::read_to_string(&path).unwrap(), "[Match]\nName=test0\n");
        fs::write(&path, original).unwrap();
        assert_eq!(
            f.engine()
                .action("network.rollback", action(&j), "stream2")
                .unwrap()["state"],
            "ROLLED_BACK"
        );
    }
    #[test]
    fn older_journal_still_checks_foreign_backend_before_recovery() {
        let mut f = Fixture::new();
        let change = f.change();
        f.engine().prepare(change, "old", "stream1").unwrap();
        let mut journal = f.engine().journal().unwrap().unwrap();
        journal.writers = None;
        let mut legacy = serde_json::to_value(&journal).unwrap();
        legacy.as_object_mut().unwrap().remove("writers");
        let legacy: Journal = serde_json::from_value(legacy).unwrap();
        f.engine().save(&legacy).unwrap();
        let path = f.path.join("run/systemd/network/01-foreign.network");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "external\n").unwrap();
        f.reopen();
        f.engine().recover().unwrap();
        assert_eq!(
            f.engine().journal().unwrap().unwrap().state,
            "RECOVERY_REQUIRED"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "external\n");
        fs::remove_file(path).unwrap();
        f.engine()
            .action(
                "network.rollback",
                NetworkAction {
                    transaction_id: journal.id,
                    confirmation_token: journal.token,
                },
                "local-authorized",
            )
            .unwrap();
        assert_eq!(f.engine().journal().unwrap().unwrap().state, "ROLLED_BACK");
    }
    #[tokio::test]
    async fn observations_do_not_wait_for_system_writer() {
        let f = Fixture::new();
        let network = f.network.as_ref().unwrap().clone();
        let (release, held) = std::sync::mpsc::channel();
        let (ready, waiting) = std::sync::mpsc::channel();
        let writer_network = network.clone();
        let writer = std::thread::spawn(move || {
            let _guard = writer_network.0.lock().unwrap();
            ready.send(()).unwrap();
            let _ = held.recv_timeout(Duration::from_secs(5));
        });
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        let snapshot = tokio::time::timeout(
            Duration::from_secs(2),
            network.request(
                "network.inspect".into(),
                None,
                None,
                "read".into(),
                "local-authorized".into(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(snapshot["revision"], 0);
        assert!(
            network
                .request(
                    "network.prepare".into(),
                    None,
                    None,
                    "write".into(),
                    "local-authorized".into()
                )
                .await
                .unwrap_err()
                .to_string()
                .starts_with("CONFLICT")
        );
        release.send(()).unwrap();
        writer.join().unwrap();
    }
}
