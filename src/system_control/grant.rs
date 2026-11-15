use super::*;
use std::collections::BTreeSet;

pub(super) const DECLARATION: &str = "FragmentPath,DropInPaths,ExecStart,ExecStop,Environment,EnvironmentFiles,UnsetEnvironment,NeedDaemonReload,Slice,KillMode,TimeoutStopUSec";
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct File {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Config {
    pub schema: u32,
    pub unit: String,
    pub unit_file: PathBuf,
    pub unit_definition_sha256: String,
    pub files: Vec<File>,
    pub ordinary_profile: Option<PathBuf>,
    pub snapshot_directory: Option<PathBuf>,
    #[serde(default)]
    pub allow_restart: bool,
    #[serde(default)]
    pub allow_reboot: bool,
    pub confirmation_seconds: u64,
    pub observation_seconds: u64,
    pub restart_timeout_seconds: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Unit {
    pub unit: String,
    pub active_state: String,
    pub pid: u32,
    pub invocation_id: String,
    pub control_group: String,
    pub unit_file_state: String,
}
impl Unit {
    pub fn running(&self) -> bool {
        self.active_state == "active"
            && self.pid > 0
            && self.invocation_id.len() == 32
            && self
                .invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.control_group == format!("/system.slice/{}", self.unit)
    }
    pub(crate) fn stopped(&self)->bool {
        self.active_state=="inactive" && self.pid==0
            && (self.control_group.is_empty() || self.control_group==format!("/system.slice/{}",self.unit))
            && (self.invocation_id.is_empty() || (self.invocation_id.len()==32
                && self.invocation_id.bytes().all(|ch|ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))))
    }
}
fn path(p: &Path) -> bool {
    p.is_absolute()
        && p.components().all(|c| {
            matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
        && !p
            .to_string_lossy()
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
}
fn unit(s: &str) -> bool {
    s.ends_with(".service")
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
impl Config {
    pub(super) fn bounds(&self) -> Result<()> {
        ensure!(
            self.schema == 1
                && unit(&self.unit)
                && path(&self.unit_file)
                && hash(&self.unit_definition_sha256)
                && (self.allow_restart || self.allow_reboot)
                && (60..=600).contains(&self.confirmation_seconds)
                && (10..=180).contains(&self.observation_seconds)
                && (5..=180).contains(&self.restart_timeout_seconds)
                && self.ordinary_profile.is_some() == self.snapshot_directory.is_some()
                && self.ordinary_profile.as_ref().is_none_or(|p| path(p))
                && self.snapshot_directory.as_ref().is_none_or(|p| path(p))
                && !self.files.is_empty()
                && self.files.len() <= 512,
            "FORBIDDEN: bounded explicit system control grant required"
        );
        ensure!(
            self.ordinary_profile.is_some()
                || self.unit == "kura.service"
                || self.unit.starts_with("kura-")
                || self.unit.starts_with("yofc-kura-"),
            "FORBIDDEN: only an installed Kura mapping is permitted"
        );
        ensure!(
            !self.unit.contains("management-agent") && !self.unit.contains("management-console"),
            "FORBIDDEN: management services are not Kura targets"
        );
        let mut names = BTreeSet::new();
        for f in &self.files {
            ensure!(
                path(&f.path) && hash(&f.sha256) && names.insert(f.path.clone()),
                "FORBIDDEN: unique pinned service files required"
            );
        }
        ensure!(
            names.contains(&self.unit_file),
            "FORBIDDEN: fixed unit file must be pinned"
        );
        Ok(())
    }
}
fn fields(value: &str) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    for line in value.lines() {
        let (k, v) = line
            .split_once('=')
            .context("CONFLICT: systemd field shape")?;
        ensure!(
            fields.insert(k.to_owned(), v.to_owned()).is_none(),
            "CONFLICT: duplicate systemd field"
        );
    }
    Ok(fields)
}
fn stop_seconds(s: &str) -> Option<f64> {
    let mut total = 0.0;
    for token in s.split_whitespace() {
        let mut found = false;
        for (suffix, factor) in [
            ("min", 60.0),
            ("ms", 0.001),
            ("us", 0.000001),
            ("s", 1.0),
            ("h", 3600.0),
        ] {
            if let Some(n) = token.strip_suffix(suffix) {
                let n = n.parse::<f64>().ok()?;
                if !n.is_finite() || n < 0.0 {
                    return None;
                }
                total += n * factor;
                found = true;
                break;
            }
        }
        if !found {
            return None;
        }
    }
    (total > 0.0 && total <= 180.0).then_some(total)
}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(crate) struct StopPolicy {pub(crate) definition_sha256:String,pub(crate) timeout_seconds:u64}
impl StopPolicy {
    pub(crate) fn validate(&self)->Result<()> {
        ensure!(hash(&self.definition_sha256) && (1..=180).contains(&self.timeout_seconds),"CONFLICT: bounded fixed stop policy required");Ok(())
    }
}
/// The same normalization and pinned cgroup policy serve ordinary system
/// control and original-bound NM startup. No second stop-policy parser.
fn pinned_definition(unit_file:&Path,pins:&BTreeSet<PathBuf>,output:&str)->Result<StopPolicy> {
    let mut f=fields(output)?;
    f.entry("EnvironmentFiles".into()).or_default();
    // systemd255 omits empty ExecStop even with --all.
    f.entry("ExecStop".into()).or_default();
    ensure!(f.get("FragmentPath").map(Path::new)==Some(unit_file)
        && f.get("NeedDaemonReload").map(String::as_str)==Some("no")
        && f.get("Slice").map(String::as_str)==Some("system.slice")
        && f.get("KillMode").map(String::as_str)==Some("control-group"),
        "CONFLICT: fixed bounded cgroup stop policy required");
    let timeout=f.get("TimeoutStopUSec").and_then(|value|stop_seconds(value))
        .context("CONFLICT: fixed bounded cgroup stop policy required")?;
    for key in ["DropInPaths","EnvironmentFiles"] {
        for item in f.get(key).context("CONFLICT: missing effective service field")?.split_whitespace().filter(|s|s.starts_with('/')) {
            ensure!(pins.contains(&PathBuf::from(item)),"CONFLICT: unpinned service drop-in/environment file");
        }
    }
    for key in ["ExecStart","ExecStop"] {
        let value=f.get_mut(key).context("CONFLICT: effective service command unavailable")?;
        if !value.is_empty(){*value=value.split(" ; ignore_errors=").next().unwrap().to_owned();}
    }
    let definition_sha256=durable::hash(f.iter().map(|(key,value)|format!("{key}={value}\n")).collect::<String>().as_bytes());
    Ok(StopPolicy{definition_sha256,timeout_seconds:timeout.ceil() as u64})
}
pub(super) fn inspect_ordinary_stop(systemctl:&Path,c:&crate::recovery::ordinary_profile::Config)->Result<StopPolicy> {
    let output=crate::process::run(systemctl,&["show",&c.unit,"--all",&format!("--property={DECLARATION}")],None,Duration::from_secs(5))?;
    ensure!(output.status.success(),"CONFLICT: effective startup stop policy unavailable");
    let text=String::from_utf8(output.stdout)?;
    let ordinary=text.lines().filter(|line|line.split_once('=').is_some_and(|(key,_)|
        crate::recovery::ordinary_profile::UNIT_FIELDS.split(',').any(|known|known==key))).collect::<Vec<_>>().join("\n");
    crate::recovery::ordinary_profile::Profile::declaration(c,&ordinary)?;
    pinned_definition(&c.unit_file,&c.profile_files.iter().map(|file|file.path.clone()).collect(),&text)
}
pub(super) type Inputs = (
    Config,
    Vec<u8>,
    String,
    Option<crate::recovery::ControlProfile>,
);
impl Native {
    pub(super) fn unit(&self, name: &str) -> Result<Unit> {
        ensure!(unit(name), "FORBIDDEN: fixed unit name required");
        let data = self.command(
            &[
                "show",
                name,
                "--property=LoadState,ActiveState,MainPID,InvocationID,ControlGroup,UnitFileState",
            ],
            Duration::from_secs(5),
        )?;
        let f = fields(&data)?;
        ensure!(
            f.get("LoadState").map(String::as_str) == Some("loaded"),
            "CONFLICT: mapped unit is not loaded"
        );
        let get = |k| {
            f.get(k)
                .cloned()
                .context("CONFLICT: missing fixed unit field")
        };
        let u = Unit {
            unit: name.into(),
            active_state: get("ActiveState")?,
            pid: get("MainPID")?.parse()?,
            invocation_id: get("InvocationID")?,
            control_group: get("ControlGroup")?,
            unit_file_state: get("UnitFileState")?,
        };
        if u.pid > 0 {
            ensure!(
                u.running(),
                "CONFLICT: mapped unit process/cgroup identity unavailable"
            );
            if self.systemctl == Path::new("/usr/bin/systemctl") && cfg!(target_os = "linux") {
                let group = fs::read_to_string(format!("/proc/{}/cgroup", u.pid))?;
                ensure!(
                    group
                        .lines()
                        .any(|s| s == format!("0::{}", u.control_group)),
                    "CONFLICT: PID is outside mapped service cgroup"
                );
                let own = fs::read_to_string("/proc/self/cgroup")?;
                ensure!(
                    !own.lines().any(|s| s == format!("0::{}", u.control_group)),
                    "FORBIDDEN: agent cannot control its own unit"
                );
            }
        }
        Ok(u)
    }
    fn definition(&self, c: &Config) -> Result<String> {
        let output = self.command(
            &[
                "show",
                &c.unit,
                "--all",
                &format!("--property={DECLARATION}"),
            ],
            Duration::from_secs(5),
        )?;
        Ok(pinned_definition(&c.unit_file,&c.files.iter().map(|file|file.path.clone()).collect(),&output)?.definition_sha256)
    }
    pub(super) fn inputs(&self) -> Result<Inputs> {
        let raw = private(&self.config, 512 << 10)?;
        let c: Config = serde_json::from_slice(&raw)?;
        c.bounds()?;
        let material=c.ordinary_profile.as_ref().map(|path|
            crate::recovery::ordinary_profile::Profile::runtime(path.clone(),self.root.clone())?.inspect()).transpose()?;
        if let Some(selection)=material.as_ref().and_then(|material|material.selection.as_ref()) {
            ensure!(selection.unit==c.unit,"FORBIDDEN: selected ordinary material targets another service");
        }
        for file in &c.files {
            let (bytes, m) = durable::read(&file.path, 64 << 20)?;
            let expected=material.as_ref().and_then(|material|material.selection.as_ref())
                .map(|selection|selection.pinned_hash(&file.path,&file.sha256)).transpose()?.unwrap_or_else(||file.sha256.clone());
            ensure!(
                m.uid == unsafe { libc::geteuid() }
                    && m.mode & 0o022 == 0
                    && durable::hash(&bytes) == expected,
                "CONFLICT: fixed service profile file changed"
            );
        }
        let definition = self.definition(&c)?;
        ensure!(
            definition == c.unit_definition_sha256,
            "CONFLICT: effective fixed service definition changed"
        );
        let profile = material
            .map(|material| crate::recovery::ordinary_control_material(material, &self.systemctl))
            .transpose()?;
        ensure!(
            profile.as_ref().is_none_or(|p| p.unit == c.unit),
            "FORBIDDEN: business profile targets another service"
        );
        Ok((c, raw, definition, profile))
    }
    pub(super) fn snapshots(&self, c: &Config) -> Result<Vec<Snapshot>> {
        let root = c
            .snapshot_directory
            .as_ref()
            .context("CONFLICT: approved snapshot directory missing")?;
        for part in root.ancestors() {
            let m = fs::symlink_metadata(part)?;
            ensure!(
                m.is_dir() && m.mode() & 0o022 == 0,
                "CONFLICT: unsafe snapshot source directory"
            );
        }
        let mut values = BTreeMap::new();
        let owner = fs::symlink_metadata(root)?.uid();
        let mut total = 0;
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("CONFLICT: snapshot name"))?;
            if let Some(id) = name
                .strip_prefix("snapshot_")
                .and_then(|s| s.strip_suffix(".xml"))
            {
                let number = id.parse::<u64>()?;
                ensure!(
                    number.to_string() == id,
                    "CONFLICT: canonical snapshot name required"
                );
                let (bytes, m) = durable::read(&entry.path(), 32 << 20)?;
                total += bytes.len();
                ensure!(
                    m.uid == owner && m.mode == 0o600 && total <= 64 << 20,
                    "CONFLICT: private bounded snapshot source required"
                );
                values.insert(
                    number,
                    Snapshot {
                        name,
                        sha256: durable::hash(&bytes),
                    },
                );
                ensure!(
                    values.len() <= 128,
                    "RESOURCE_EXHAUSTED: snapshot source count"
                );
            }
        }
        ensure!(
            !values.is_empty(),
            "CONFLICT: no current snapshot for application verification"
        );
        Ok(values.into_values().collect())
    }
}

pub(super) fn seal(request: &Path, output: &Path, systemctl: &Path) -> Result<Value> {
    ensure!(
        request.is_absolute() && output.is_absolute(),
        "FORBIDDEN: absolute private installation paths required"
    );
    let raw = private(request, 512 << 10)?;
    let mut c: Config = serde_json::from_slice(&raw)?;
    c.bounds()?;
    for file in &c.files {
        let (bytes, m) = durable::read(&file.path, 64 << 20)?;
        ensure!(
            m.uid == unsafe { libc::geteuid() }
                && m.mode & 0o022 == 0
                && durable::hash(&bytes) == file.sha256,
            "CONFLICT: installation profile file changed"
        );
    }
    let n = Native {
        root: PathBuf::new(),
        config: request.into(),
        systemctl: systemctl.into(),
        systemd_run: PathBuf::new(),
        boot_id: PathBuf::new(),
    };
    let target = n.unit(&c.unit)?;
    c.unit_definition_sha256 = n.definition(&c)?;
    let profile = c
        .ordinary_profile
        .as_ref()
        .map(|p| crate::recovery::ordinary_control_profile(p, systemctl))
        .transpose()?;
    ensure!(
        profile.as_ref().is_none_or(|p| p.unit == c.unit),
        "FORBIDDEN: application profile maps another unit"
    );
    let parent = fs::symlink_metadata(output.parent().context("installation grant parent")?)?;
    ensure!(
        parent.is_dir() && parent.uid() == unsafe { libc::geteuid() } && parent.mode() & 0o077 == 0,
        "FORBIDDEN: private owned installation directory required"
    );
    let bytes = serde_json::to_vec_pretty(&c)?;
    durable::publish_new(output, &bytes, FileMetadata::private())?;
    Ok(
        json!({"schema":1,"unit":c.unit,"grantSha256":durable::hash(&bytes),"unitDefinitionSha256":c.unit_definition_sha256,
        "allowRestart":c.allow_restart,"allowReboot":c.allow_reboot,"applicationVerificationConfigured":profile.is_some(),
        "currentUnit":target,"unitStarted":false,"unitEnabled":false,"remoteEnabled":false}),
    )
}
