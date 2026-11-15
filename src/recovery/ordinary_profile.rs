//! Fixed administrator-reviewed ordinary launcher. No commands or paths arrive
//! from the local handoff caller; effective systemd configuration is pinned too.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const UNIT_FIELDS: &str = "FragmentPath,DropInPaths,ExecStart,Environment,EnvironmentFiles,UnsetEnvironment,NeedDaemonReload";
#[derive(Clone)]
pub(super) struct Profile(PathBuf);
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Config {
    pub schema: u32,
    pub profile_id: String,
    pub unit: String,
    pub unit_file: PathBuf,
    pub jvm_args_path: PathBuf,
    #[serde(default)]
    pub unit_definition_sha256: String,
    pub timeout_seconds: u64,
    pub valid_for_seconds: u64,
    pub component_pids: Vec<String>,
    pub check_ids: Vec<String>,
    pub profile_files: Vec<File>,
    #[serde(default)]
    pub launcher_kind: Launcher,
    #[serde(default)]
    pub launcher_script_path: Option<PathBuf>,
}
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Launcher {
    #[default]
    DirectJava,
    PackagedBackground,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct File {
    pub path: PathBuf,
    pub sha256: String,
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn names(values: &[String]) -> Result<()> {
    let mut unique = BTreeSet::new();
    ensure!(
        !values.is_empty() && values.len() <= 32,
        "FORBIDDEN: bounded ordinary conditions required"
    );
    for value in values {
        ensure!(
            !value.trim().is_empty()
                && value.len() <= 512
                && !value.chars().any(char::is_control)
                && unique.insert(value),
            "FORBIDDEN: ambiguous ordinary condition"
        );
    }
    Ok(())
}
fn tokens(bytes: &[u8]) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for line in std::str::from_utf8(bytes)?.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The managed Java launcher deliberately uses one literal argument per line.
        // Unsupported indirection/escaping requires an explicit new profile format.
        let value = if line.starts_with('"') {
            ensure!(
                line.len() >= 2 && line.ends_with('"'),
                "FORBIDDEN: unsupported ordinary JVM argument"
            );
            &line[1..line.len() - 1]
        } else {
            ensure!(
                !line.chars().any(char::is_whitespace),
                "FORBIDDEN: one JVM argument per line required"
            );
            line
        };
        ensure!(
            !value.is_empty()
                && !value.contains(['"', '\\'])
                && !value.chars().any(char::is_control)
                && !value.starts_with('@')
                && !value.contains("kura.recovery.request"),
            "FORBIDDEN: recovery or indirect ordinary argument"
        );
        result.push(value.to_owned());
        ensure!(result.len() <= 2048, "FORBIDDEN: ordinary argument quota");
    }
    Ok(result)
}
impl Profile {
    pub(super) fn new(path: PathBuf) -> Result<Self> {
        let p = Self(path);
        p.inputs()?;
        Ok(p)
    }
    pub(super) fn inputs(&self) -> Result<(Config, String, Vec<u8>)> {
        let raw = crate::controlled_startup::trusted_file(&self.0, 256 << 10)?;
        ensure!(
            fs::symlink_metadata(&self.0)?.mode() & 0o077 == 0,
            "FORBIDDEN: private ordinary grant required"
        );
        Self::checked(raw)
    }
    fn checked(raw: Vec<u8>) -> Result<(Config, String, Vec<u8>)> {
        let c: Config = serde_json::from_slice(&raw)?;
        Self::config(&c)?;
        let mut paths = BTreeSet::new();
        let mut hashes = vec![durable::hash(&raw)];
        let mut total = 0usize;
        for file in &c.profile_files {
            ensure!(
                hash(&file.sha256) && paths.insert(file.path.clone()),
                "FORBIDDEN: ordinary profile inventory"
            );
            let bytes = crate::controlled_startup::trusted_file(&file.path, 256 << 20)?;
            total += bytes.len();
            ensure!(
                total <= 2048usize << 20 && durable::hash(&bytes) == file.sha256,
                "CONFLICT: ordinary profile changed"
            );
            hashes.push(file.sha256.clone());
        }
        ensure!(
            paths.contains(&c.jvm_args_path) && paths.contains(&c.unit_file),
            "FORBIDDEN: ordinary launcher inputs must be pinned"
        );
        if c.launcher_kind == Launcher::PackagedBackground {
            let script = c
                .launcher_script_path
                .as_ref()
                .context("FORBIDDEN: packaged launcher missing")?;
            let generator = script
                .parent()
                .context("launcher parent")?
                .join("gen_config_ini.sh");
            ensure!(
                paths.contains(script) && paths.contains(&generator),
                "FORBIDDEN: packaged launcher and generator must be pinned"
            );
            let body = crate::controlled_startup::trusted_file(script, 64 << 10)?;
            let body = std::str::from_utf8(&body)?;
            ensure!(
                body.contains("# YOFC-KURA-ORDINARY-JVM-ARGS-V1")
                    && body.contains("set -- \"@$KURA_JVM_ARGS_FILE\"")
                    && body.contains("nohup java \"$@\""),
                "FORBIDDEN: supported packaged launcher contract required"
            );
        }
        let args = tokens(&crate::controlled_startup::trusted_file(
            &c.jvm_args_path,
            256 << 10,
        )?)?;
        ensure!(
            args.iter()
                .filter(|a| a.starts_with("-Dkura.management.ordinary.profile.id="))
                .count()
                == 1
                && args.contains(&format!(
                    "-Dkura.management.ordinary.profile.id={}",
                    c.profile_id
                ))
                && args
                    .iter()
                    .filter(|a| a.starts_with("-Dkura.management.ordinary.verification.enabled="))
                    .count()
                    == 1
                && args
                    .iter()
                    .any(|a| a == "-Dkura.management.ordinary.verification.enabled=true"),
            "FORBIDDEN: ordinary observer identity not pinned"
        );
        Ok((c, durable::hash(hashes.join("\n").as_bytes()), raw))
    }
    pub(super) fn config(c: &Config) -> Result<()> {
        ensure!(
            c.schema == 1
                && c.profile_id
                    .strip_prefix("profile-")
                    .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok_and(|id| id.to_string() == s))
                && safe_name(&c.unit)
                && c.unit.ends_with(".service")
                && (1..=180).contains(&c.timeout_seconds)
                && (60..=600).contains(&c.valid_for_seconds)
                && hash(&c.unit_definition_sha256)
                && !c.profile_files.is_empty()
                && c.profile_files.len() <= 512,
            "FORBIDDEN: ordinary grant bounds"
        );
        for path in [&c.jvm_args_path, &c.unit_file] {
            ensure!(
                path.is_absolute()
                    && !path
                        .to_string_lossy()
                        .chars()
                        .any(|ch| ch.is_whitespace() || ch.is_control()),
                "FORBIDDEN: canonical ordinary launcher path required"
            );
        }
        match (c.launcher_kind, &c.launcher_script_path) {
            (Launcher::DirectJava, None) => {}
            (Launcher::PackagedBackground, Some(path)) => {
                ensure!(
                    path.is_absolute()
                        && path
                            .file_name()
                            .is_some_and(|s| s == "start_kura_background.sh")
                        && !path
                            .to_string_lossy()
                            .chars()
                            .any(|c| c.is_whitespace() || c.is_control()),
                    "FORBIDDEN: fixed packaged launcher path required"
                );
            }
            _ => anyhow::bail!("FORBIDDEN: launcher kind/path mismatch"),
        }
        names(&c.component_pids)?;
        names(&c.check_ids)
    }
    pub(super) fn declaration(c: &Config, text: &str) -> Result<String> {
        let digest = Self::definition(c, text)?;
        ensure!(
            digest == c.unit_definition_sha256,
            "CONFLICT: effective ordinary unit changed"
        );
        Ok(digest)
    }
    fn definition(c: &Config, text: &str) -> Result<String> {
        let mut fields = BTreeMap::new();
        for line in text.lines().filter(|l| !l.is_empty()) {
            let (key, value) = line
                .split_once('=')
                .context("CONFLICT: unit declaration format")?;
            ensure!(
                UNIT_FIELDS.split(',').any(|f| f == key)
                    && fields.insert(key.to_owned(), value.to_owned()).is_none(),
                "CONFLICT: unit declaration fields"
            );
        }
        // systemctl omits empty EnvironmentFiles on some supported systemd versions.
        fields.entry("EnvironmentFiles".into()).or_default();
        ensure!(
            fields.len() == UNIT_FIELDS.split(',').count()
                && fields.get("NeedDaemonReload").is_some_and(|s| s == "no")
                && fields
                    .get("FragmentPath")
                    .is_some_and(|s| s == c.unit_file.to_string_lossy().as_ref())
                && fields.get("EnvironmentFiles").is_some_and(String::is_empty),
            "CONFLICT: ordinary unit definition unproven"
        );
        let start = fields.get("ExecStart").context("unit start missing")?;
        ensure!(
            start.matches("argv[]=").count() == 1 && !start.contains("kura.recovery.request"),
            "FORBIDDEN: ordinary unit must not invoke recovery"
        );
        let static_start = start
            .split_once(" ; ignore_errors=")
            .context("CONFLICT: unit start format")?
            .0
            .to_owned();
        let argv = static_start
            .split_once("argv[]=")
            .context("unit argv missing")?
            .1;
        let words = argv.split_whitespace().collect::<Vec<_>>();
        match c.launcher_kind {
            Launcher::DirectJava => {
                let argument = format!("@{}", c.jvm_args_path.display());
                ensure!(
                    words.first().is_some_and(|v| v.ends_with("/java"))
                        && words.iter().filter(|v| v.starts_with('@')).count() == 1
                        && words.contains(&argument.as_str()),
                    "FORBIDDEN: approved direct ordinary Java launcher required"
                );
            }
            Launcher::PackagedBackground => {
                let script = c
                    .launcher_script_path
                    .as_ref()
                    .context("packaged launcher missing")?
                    .to_str()
                    .context("launcher UTF-8")?;
                ensure!(
                    words == ["/bin/sh", script],
                    "FORBIDDEN: fixed packaged background launcher required"
                );
                let binding = format!("KURA_JVM_ARGS_FILE={}", c.jvm_args_path.display());
                let environment = fields
                    .get("Environment")
                    .context("unit environment missing")?
                    .split_whitespace()
                    .collect::<Vec<_>>();
                ensure!(
                    environment
                        .iter()
                        .filter(|s| s.starts_with("KURA_JVM_ARGS_FILE="))
                        .count()
                        == 1
                        && environment.contains(&binding.as_str()),
                    "FORBIDDEN: packaged argument file not bound"
                );
            }
        }
        let unset = fields
            .get("UnsetEnvironment")
            .context("unit unset environment")?
            .split_whitespace()
            .collect::<BTreeSet<_>>();
        if c.launcher_kind == Launcher::PackagedBackground {
            ensure!(
                !unset
                    .iter()
                    .any(|value| value.split('=').next() == Some("KURA_JVM_ARGS_FILE")),
                "FORBIDDEN: packaged argument binding must not be removed"
            );
        }
        for name in ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"] {
            ensure!(
                unset.contains(name),
                "FORBIDDEN: inherited Java arguments must be cleared"
            );
        }
        let paths = c
            .profile_files
            .iter()
            .map(|f| f.path.clone())
            .collect::<BTreeSet<_>>();
        for path in fields
            .get("DropInPaths")
            .context("unit drop-ins missing")?
            .split_whitespace()
        {
            ensure!(
                paths.contains(&PathBuf::from(path)),
                "CONFLICT: unpinned unit drop-in"
            );
        }
        fields.insert("ExecStart".into(), static_start);
        let canonical = fields
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect::<String>();
        Ok(durable::hash(canonical.as_bytes()))
    }
}

/// Offline local installation step. Never starts/enables a unit or mutates agent state.
pub(super) fn seal(
    request: PathBuf,
    output: PathBuf,
    systemctl: &std::path::Path,
) -> Result<Value> {
    let raw = crate::controlled_startup::trusted_file(&request, 256 << 10)?;
    ensure!(
        fs::symlink_metadata(&request)?.mode() & 0o077 == 0,
        "FORBIDDEN: private ordinary installation request required"
    );
    let mut config: Config = serde_json::from_slice(&raw)?;
    let value: Value = serde_json::from_slice(&raw)?;
    ensure!(
        !value
            .as_object()
            .context("INVALID_ARGUMENT: ordinary installation request object")?
            .contains_key("unitDefinitionSha256"),
        "INVALID_ARGUMENT: effective definition is derived during sealing"
    );
    config.unit_definition_sha256 = "0".repeat(64);
    Profile::checked(serde_json::to_vec(&config)?)?;
    let run = |property: &str| -> Result<String> {
        let result = crate::process::run(
            systemctl,
            &[
                "show",
                &config.unit,
                "--all",
                &format!("--property={property}"),
            ],
            None,
            Duration::from_secs(5),
        )?;
        ensure!(
            result.status.success(),
            "CONFLICT: ordinary unit inspection failed"
        );
        Ok(String::from_utf8(result.stdout)?)
    };
    let status = run("LoadState,ActiveState,MainPID")?;
    let fields = status
        .lines()
        .map(|l| l.split_once('=').context("unit state format"))
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        fields.len() == 3
            && fields.get("LoadState") == Some(&"loaded")
            && fields.get("ActiveState") == Some(&"inactive")
            && fields.get("MainPID") == Some(&"0"),
        "CONFLICT: stopped ordinary unit required for installation seal"
    );
    config.unit_definition_sha256 = Profile::definition(&config, &run(UNIT_FIELDS)?)?;
    let body = serde_json::to_vec_pretty(&config)?;
    Profile::checked(body.clone())?;
    ensure!(
        output.is_absolute()
            && output
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "FORBIDDEN: absolute ordinary grant destination required"
    );
    let parent = output.parent().context("grant destination parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir()
            && metadata.mode() & 0o022 == 0
            && metadata.uid() == unsafe { libc::geteuid() },
        "FORBIDDEN: owned private installation directory required"
    );
    durable::publish_new(&output, &body, FileMetadata::private())?;
    Ok(
        json!({"schema":1,"profileId":config.profile_id,"unit":config.unit,"grantSha256":durable::hash(&body),"unitDefinitionSha256":config.unit_definition_sha256,"unitStarted":false,"unitEnabled":false,"launcherKind":config.launcher_kind}),
    )
}
