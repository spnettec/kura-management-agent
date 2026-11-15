//! Contemporaneous OS/JVM observation under the SAME committed owner. Historical
//! startup completion and activation keep their original strict unit binding.
//! This proof is read-only, non-deserializable, and never creates an owner lease.
use super::*;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct Executable {
    path: PathBuf,
    device: u64,
    inode: u64,
    size: u64,
    ctime: i64,
    ctime_nanos: i64,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct Process {
    boot_id: uuid::Uuid,
    pid: u32,
    start_ticks: u64,
    uid: [u32; 4],
    gid: [u32; 4],
    command_line_sha256: String,
    control_group_sha256: String,
    executable: Executable,
}
fn bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("UNSUPPORTED: current kernel process evidence unavailable")?;
    ensure!(
        file.metadata()?.is_file(),
        "CONFLICT: kernel process evidence is not a regular proc file"
    );
    let mut value = Vec::new();
    file.take(limit + 1).read_to_end(&mut value)?;
    ensure!(
        !value.is_empty() && value.len() as u64 <= limit,
        "CONFLICT: kernel process evidence bounds"
    );
    Ok(value)
}
fn text(path: &Path, limit: u64) -> Result<String> {
    String::from_utf8(bytes(path, limit)?).context("CONFLICT: kernel process evidence encoding")
}
fn start_ticks(pid: u32, stat: &str) -> Result<u64> {
    let (prefix, tail) = stat
        .rsplit_once(") ")
        .context("CONFLICT: process stat envelope")?;
    let (observed, _) = prefix
        .split_once(" (")
        .context("CONFLICT: process stat identity")?;
    let fields = tail.split_whitespace().collect::<Vec<_>>();
    ensure!(
        observed.parse::<u32>()? == pid
            && fields.len() >= 20
            && fields[0].len() == 1
            && fields[0].as_bytes()[0].is_ascii_alphabetic()
            && !["Z", "X", "x"].contains(&fields[0]),
        "CONFLICT: mapped process is not live"
    );
    fields[19]
        .parse::<u64>()
        .ok()
        .filter(|v| *v > 0)
        .context("CONFLICT: process start ticks")
}
fn ids(status: &str, key: &str) -> Result<[u32; 4]> {
    let values = status
        .lines()
        .filter_map(|line| line.strip_prefix(key))
        .collect::<Vec<_>>();
    ensure!(values.len() == 1, "CONFLICT: process credential evidence");
    let fields = values[0]
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    fields
        .try_into()
        .map_err(|_| anyhow::anyhow!("CONFLICT: process credential tuple"))
}
impl Process {
    fn read(unit: &crate::system_control::Unit) -> Result<Self> {
        ensure!(
            cfg!(target_os = "linux"),
            "UNSUPPORTED: current runtime OS proof requires Linux procfs"
        );
        Self::at(Path::new("/proc"), unit)
    }
    fn at(proc_root: &Path, unit: &crate::system_control::Unit) -> Result<Self> {
        ensure!(
            unit.running(),
            "CONFLICT: current ordinary service is not running"
        );
        let boot = text(&proc_root.join("sys/kernel/random/boot_id"), 64)?;
        let boot_id = boot.trim().parse::<uuid::Uuid>()?;
        ensure!(
            !boot_id.is_nil() && boot.trim() == boot_id.to_string(),
            "CONFLICT: current boot identity"
        );
        let directory = proc_root.join(unit.pid.to_string());
        let stat = text(&directory.join("stat"), 16_384)?;
        let start = start_ticks(unit.pid, &stat)?;
        let status = text(&directory.join("status"), 65_536)?;
        let group = text(&directory.join("cgroup"), 16_384)?;
        let own = text(&proc_root.join("self/cgroup"), 16_384)?;
        let expected = format!("0::{}", unit.control_group);
        ensure!(
            group.lines().filter(|v| *v == expected).count() == 1
                && !own.lines().any(|v| v == expected),
            "CONFLICT: current process/cgroup is not the mapped independent ordinary unit"
        );
        let exe_path = directory.join("exe");
        let path = fs::read_link(&exe_path)?;
        let metadata = fs::metadata(&exe_path)?;
        ensure!(
            path.is_absolute()
                && path.to_str().is_some_and(|value| value.len() <= 4096)
                && metadata.is_file()
                && metadata.ino() > 0
                && metadata.len() > 0,
            "CONFLICT: current process executable identity"
        );
        let command = bytes(&directory.join("cmdline"), 65_536)?;
        ensure!(
            command.first().is_some_and(|v| *v != 0) && command.last() == Some(&0),
            "CONFLICT: current process command line envelope"
        );
        let process = Self {
            boot_id,
            pid: unit.pid,
            start_ticks: start,
            uid: ids(&status, "Uid:")?,
            gid: ids(&status, "Gid:")?,
            command_line_sha256: durable::hash(&command),
            control_group_sha256: durable::hash(group.as_bytes()),
            executable: Executable {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                size: metadata.len(),
                ctime: metadata.ctime(),
                ctime_nanos: metadata.ctime_nsec(),
            },
        };
        // A PID may disappear or be reused while its other files are read.
        ensure!(
            start_ticks(unit.pid, &text(&directory.join("stat"), 16_384)?)? == start
                && text(&proc_root.join("sys/kernel/random/boot_id"), 64)? == boot,
            "CONFLICT: process or boot changed during current runtime observation"
        );
        Ok(process)
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(in crate::nm) struct Challenge {
    completion: CompletionChallenge,
    original_unit: crate::system_control::Unit,
    completion_receipt_sha256: String,
    selected_profile_sha256: String,
    stop_policy: crate::system_control::StopPolicy,
    process: Process,
}
impl Challenge {
    pub(in crate::nm) fn completion(&self) -> &CompletionChallenge {
        &self.completion
    }
    pub(in crate::nm) fn parameters(&self) -> Value {
        json!({"schemaVersion":1,"scope":"fresh-same-owner-os-unit-jvm-observation",
            "originalStartupReceiptSha256":self.completion_receipt_sha256,
            "selectedProfileSha256":self.selected_profile_sha256,"stopPolicy":self.stop_policy,
            "spec":self.completion.spec.parameters(),"profileId":self.completion.profile_id,
            "originalUnit":self.original_unit,"currentUnit":self.completion.unit,"process":self.process,
            "historicalStartupRewritten":false,"ownerGrant":false})
    }
}
fn collect(
    root: &Path,
    original: &Requirements,
    systemctl: &Path,
    observe: impl Fn(&crate::system_control::Unit) -> Result<Process>,
) -> Result<Challenge> {
    ensure!(
        original.state == State::Committed,
        "FORBIDDEN: current runtime observation requires committed ownership"
    );
    let anchor = completion::runtime_anchor(root, original)?;
    let unit = crate::system_control::inspect_unit(systemctl, &anchor.config.unit)?;
    ensure!(
        unit.unit == anchor.original.unit.unit
            && unit.control_group == anchor.original.unit.control_group,
        "CONFLICT: current runtime is outside the original mapped ordinary service cgroup"
    );
    let process = observe(&unit)?;
    ensure!(
        anchor.stop_policy
            == crate::system_control::inspect_stop_policy(systemctl, &anchor.config)?,
        "CONFLICT: current runtime service definition differs from the original pinned policy"
    );
    ensure!(
        unit == crate::system_control::inspect_unit(systemctl, &anchor.config.unit)?
            && process == observe(&unit)?,
        "CONFLICT: current ordinary unit/process changed during observation"
    );
    let again = completion::runtime_anchor(root, original)?;
    ensure!(
        anchor.receipt_sha256 == again.receipt_sha256
            && anchor.profile_sha256 == again.profile_sha256
            && anchor.original == again.original
            && anchor.stop_policy == again.stop_policy,
        "CONFLICT: original startup anchor changed during current runtime observation"
    );
    Ok(Challenge {
        completion: CompletionChallenge {
            spec: anchor.original.spec.clone(),
            profile_id: anchor.original.profile_id.clone(),
            unit,
        },
        original_unit: anchor.original.unit,
        completion_receipt_sha256: anchor.receipt_sha256,
        selected_profile_sha256: anchor.profile_sha256,
        stop_policy: anchor.stop_policy,
        process,
    })
}
pub(super) fn challenge(
    root: &Path,
    original: &Requirements,
    systemctl: &Path,
) -> Result<Challenge> {
    collect(root, original, systemctl, Process::read)
}
pub(super) fn finish(
    root: &Path,
    original: &Requirements,
    expected: &Challenge,
    witness: &CompletionWitness,
    systemctl: &Path,
) -> Result<String> {
    ensure!(
        challenge(root, original, systemctl)? == *expected,
        "CONFLICT: current runtime changed during fresh Core witnesses"
    );
    completion::runtime_witness(root, original, &expected.completion, witness)
}
#[cfg(test)]
pub(super) fn fixture_challenge(
    root: &Path,
    original: &Requirements,
    systemctl: &Path,
    proc_root: &Path,
) -> Result<Challenge> {
    collect(root, original, systemctl, |unit| {
        Process::at(proc_root, unit)
    })
}
#[cfg(test)]
pub(super) fn fixture_finish(
    root: &Path,
    original: &Requirements,
    expected: &Challenge,
    witness: &CompletionWitness,
    systemctl: &Path,
    proc_root: &Path,
) -> Result<String> {
    ensure!(
        fixture_challenge(root, original, systemctl, proc_root)? == *expected,
        "CONFLICT: synthetic current runtime changed"
    );
    completion::runtime_witness(root, original, &expected.completion, witness)
}
