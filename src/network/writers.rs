//! Attribute backend files to the actual Netplan generator, not their filenames.
//! Vendor state is observed only; local foreign writers require explicit handover.
use super::*;

fn native_generator(libexec: &Path) -> PathBuf {
    let configure = libexec.join("configure");
    if configure.is_file() {
        configure
    } else {
        libexec.join("generate")
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub services: BTreeMap<String, String>,
    vendor: BTreeMap<String, String>,
}

fn backend_name(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|v| v.to_str()),
        Some("network" | "link" | "netdev")
    )
}

fn backend_tree(base: &Path) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    if !base.exists() {
        return Ok(files);
    }
    let mut bytes = 0;
    for entry in fs::read_dir(base)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .unwrap()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("CONFLICT: backend filename"))?
            .to_owned();
        ensure!(
            !name.ends_with(".d"),
            "CONFLICT: backend drop-ins require explicit handover: {name}"
        );
        if !backend_name(&path) {
            continue;
        }
        ensure!(files.len() < 256, "RESOURCE_EXHAUSTED: backend files");
        let content = read(&path)?;
        bytes += content.len();
        ensure!(bytes <= 2_097_152, "RESOURCE_EXHAUSTED: backend bytes");
        files.insert(name, hash(&content));
    }
    Ok(files)
}

fn attributed(
    actual: &BTreeMap<String, String>,
    expected: &[BTreeMap<String, String>],
    recovering: bool,
) -> Result<()> {
    if expected.iter().any(|tree| actual == tree) {
        return Ok(());
    }
    if recovering {
        // A crash inside Netplan generation can leave a mix of our old/new files.
        // Accept only bytes and names attributable to these journaled sources.
        let allowed = actual
            .iter()
            .all(|(name, hash)| expected.iter().any(|t| t.get(name) == Some(hash)));
        let required_present = expected[0]
            .keys()
            .filter(|name| expected.iter().all(|t| t.contains_key(*name)))
            .all(|name| actual.contains_key(name));
        if allowed && required_present {
            return Ok(());
        }
    }
    let suspect = actual
        .iter()
        .find(|(name, hash)| !expected.iter().any(|t| t.get(*name) == Some(*hash)))
        .map(|(name, _)| name.as_str())
        .unwrap_or("missing generated file");
    bail!("CONFLICT: systemd-networkd backend differs from Netplan sources: {suspect}")
}

fn active_backend(
    interface: &str,
    runtime: &Value,
    actual: &BTreeMap<String, String>,
    expected: &[BTreeMap<String, String>],
) -> Result<()> {
    ensure!(
        runtime["NetworkFileDropins"]
            .as_array()
            .is_none_or(|a| a.is_empty()),
        "CONFLICT: active networkd drop-ins"
    );
    if let Some(file) = runtime["NetworkFile"].as_str() {
        let name = file.strip_prefix("/run/systemd/network/").ok_or_else(|| {
            anyhow::anyhow!("CONFLICT: active networkd file is not Netplan: {file}")
        })?;
        ensure!(
            expected.iter().any(|t| t.contains_key(name)),
            "CONFLICT: active networkd file is not attributable: {file}"
        );
    } else {
        // A first-link rollback may already have removed its generated profile
        // before MTU compensation needs operator recovery. Its journaled old
        // source has no profile; the candidate variant must not require one.
        // A profile still on disk without networkd attribution remains a conflict.
        let name = format!("10-netplan-{interface}.network");
        ensure!(
            !actual.contains_key(&name) && expected.iter().any(|t| !t.contains_key(&name)),
            "CONFLICT: generated interface is not configured by networkd"
        );
    }
    Ok(())
}

impl Engine {
    pub(super) fn generated_backend(
        &self,
        sources: &BTreeMap<String, Vec<u8>>,
        candidate: Option<&str>,
    ) -> Result<BTreeMap<String, String>> {
        let staging = self.state.join(format!("staging-{}", Uuid::new_v4()));
        fs::create_dir(&staging)?;
        let result = (|| {
            for (relative, bytes) in sources {
                let path = staging.join(relative);
                fs::create_dir_all(path.parent().unwrap())?;
                atomic(&path, bytes)?;
            }
            if let Some(yaml) = candidate {
                let run = staging.join("run/netplan");
                fs::create_dir_all(&run)?;
                atomic(&run.join(FILE), yaml.as_bytes())?;
            }
            // The Python `netplan generate` wrapper reloads udev and systemd
            // even with --root-dir. systemd then runs the host generators,
            // overwriting the real backend before we can inspect its drift.
            // New Netplan packages split the CLI entry (configure) from the
            // systemd generator (generate), which expects systemd arguments.
            // Use the packaged native entry directly: staging must be read-only
            // with respect to the live host, including its unknown files.
            self.execute(
                &native_generator(Path::new("/usr/libexec/netplan")),
                &["--root-dir", staging.to_str().unwrap()],
            )?;
            backend_tree(&staging.join("run/systemd/network"))
        })();
        fs::remove_dir_all(staging)?;
        result
    }

    fn vendor_backend(&self) -> Result<BTreeMap<String, String>> {
        let mut vendor = BTreeMap::new();
        let distribution = if self.root.join("usr/lib/systemd/network").exists() {
            "usr/lib/systemd/network"
        } else {
            "lib/systemd/network"
        };
        for dir in [distribution, "usr/local/lib/systemd/network"] {
            for (name, content) in backend_tree(&self.root.join(dir))? {
                // Netplan emits 10-netplan-*. Earlier vendor profiles could win
                // even when networkd has not reloaded their newly changed match.
                ensure!(
                    name.as_str() >= "11",
                    "CONFLICT: earlier vendor backend requires handover: {dir}/{name}"
                );
                let path = self.root.join(dir).join(&name);
                let meta = fs::symlink_metadata(&path)?;
                vendor.insert(
                    format!("{dir}/{name}"),
                    format!(
                        "{content}:{}:{}:{}",
                        meta.uid(),
                        meta.gid(),
                        meta.mode() & 0o7777
                    ),
                );
            }
        }
        Ok(vendor)
    }

    fn snapshot_with(
        &self,
        interface: &str,
        expected: &[BTreeMap<String, String>],
        recovering: bool,
    ) -> Result<Snapshot> {
        let services = self.service_snapshot()?;
        for dir in [
            "etc/systemd/network",
            "etc/NetworkManager/system-connections",
            "run/NetworkManager/system-connections",
        ] {
            let path = self.root.join(dir);
            if path.exists() {
                ensure!(
                    fs::read_dir(path)?.next().is_none(),
                    "CONFLICT: unmanaged backend configuration in {dir}"
                );
            }
        }
        let vendor = self.vendor_backend()?;
        let actual = backend_tree(&self.root.join("run/systemd/network"))?;
        attributed(&actual, expected, recovering)?;
        #[cfg(test)]
        if self.fake {
            return Ok(Snapshot { services, vendor });
        }
        let runtime = self.json_command(
            Path::new("/usr/bin/networkctl"),
            &["--json=short", "status", interface],
        )?;
        active_backend(interface, &runtime, &actual, expected)?;
        Ok(Snapshot { services, vendor })
    }

    pub(super) fn writer_snapshot(
        &self,
        sources: &BTreeMap<String, Vec<u8>>,
        interface: &str,
    ) -> Result<Snapshot> {
        let generated = self.generated_backend(sources, None)?;
        self.snapshot_with(interface, &[generated], false)
    }

    pub(super) fn verify_writers(&self, j: &Journal) -> Result<()> {
        let sources = self.sources()?;
        let runtime = if self.path("run/netplan").exists() {
            let bytes = read(&self.path("run/netplan"))?;
            ensure!(
                bytes == j.candidate.as_bytes(),
                "CONFLICT: runtime source drift"
            );
            Some(j.candidate.as_str())
        } else {
            None
        };
        let mut expected = vec![self.generated_backend(&sources, runtime)?];
        let recovering = j.state != "WAIT_CONFIRM";
        if recovering {
            expected.push(self.generated_backend(&j.source_files, None)?);
            let mut candidate_sources = j.source_files.clone();
            if let Some(t) = &j.transfer {
                candidate_sources.insert(t.shadow.clone(), t.normalized.clone());
            }
            expected.push(self.generated_backend(&candidate_sources, Some(&j.candidate))?);
        }
        let current = self.snapshot_with(&j.config.interface, &expected, recovering)?;
        if let Some(previous) = &j.writers {
            ensure!(
                previous == &current,
                "CONFLICT: backend services or vendor files changed"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packaged_native_entry_handles_netplan_26_split() {
        let directory = std::env::temp_dir().join(format!("yofc-native-entry-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("generate"), b"old native CLI").unwrap();
        assert_eq!(native_generator(&directory), directory.join("generate"));
        fs::write(directory.join("configure"), b"new native CLI").unwrap();
        assert_eq!(native_generator(&directory), directory.join("configure"));
        // When both aliases exist, invoking generate as a CLI aborts on 26.04.
        fs::remove_file(directory.join("generate")).unwrap();
        assert_eq!(native_generator(&directory), directory.join("configure"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn first_link_can_return_to_unmanaged_after_partial_rollback() {
        let baseline = BTreeMap::from([("10-netplan-eth0.network".into(), "unchanged".into())]);
        let mut candidate = baseline.clone();
        candidate.insert("10-netplan-first0.network".into(), "candidate".into());
        let variants = [baseline.clone(), candidate.clone()];
        let unmanaged = serde_json::json!({"NetworkFile": null, "NetworkFileDropins": []});
        assert!(attributed(&baseline, &variants, true).is_ok());
        assert!(active_backend("first0", &unmanaged, &baseline, &variants).is_ok());
        // A current candidate cannot be confirmed as an unmanaged link.
        assert!(attributed(&baseline, std::slice::from_ref(&candidate), false).is_err());
        assert!(active_backend("first0", &unmanaged, &baseline, &[candidate.clone()]).is_err());
        // A generated profile still present must have an active networkd owner.
        assert!(active_backend("first0", &unmanaged, &candidate, &variants).is_err());
        let foreign = serde_json::json!({"NetworkFile": "/etc/systemd/network/01-foreign.network"});
        assert!(active_backend("first0", &foreign, &baseline, &variants).is_err());
        let dropin = serde_json::json!({"NetworkFileDropins": ["/run/systemd/network/x.network.d/override.conf"]});
        assert!(active_backend("first0", &dropin, &baseline, &variants).is_err());
    }

    #[test]
    fn generated_filename_does_not_prove_ownership() {
        let original = BTreeMap::from([("10-netplan-eth0.network".into(), "original".into())]);
        let forged = BTreeMap::from([("10-netplan-eth0.network".into(), "external".into())]);
        assert!(attributed(&forged, std::slice::from_ref(&original), false).is_err());
        let mut extra = original.clone();
        extra.insert("01-foreign.network".into(), "external".into());
        assert!(attributed(&extra, std::slice::from_ref(&original), true).is_err());
        assert!(attributed(&BTreeMap::new(), &[original], true).is_err());
    }
    #[test]
    fn partial_owned_generation_is_recoverable_but_not_confirmable() {
        let old = BTreeMap::from([
            ("10-netplan-eth0.network".into(), "unchanged".into()),
            ("10-netplan-test0.network".into(), "old".into()),
        ]);
        let new = BTreeMap::from([
            ("10-netplan-eth0.network".into(), "unchanged".into()),
            ("10-netplan-test0.network".into(), "new".into()),
            ("10-netplan-test0.link".into(), "new-link".into()),
        ]);
        let mut partial = old.clone();
        partial.insert("10-netplan-test0.link".into(), "new-link".into());
        assert!(attributed(&partial, std::slice::from_ref(&new), false).is_err());
        assert!(attributed(&partial, &[old, new], true).is_ok());
    }
}
