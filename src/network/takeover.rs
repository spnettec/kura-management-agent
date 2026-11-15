//! Explicit ownership transfer. Pending normalization is volatile; original
//! persistent bytes and permissions survive every unconfirmed restart.
use super::*;
use yofc_management_protocol::v1::{NetworkTakeover, StaticRoute};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Transfer {
    pub source: String,
    pub shadow: String,
    pub original: Vec<u8>,
    pub normalized: Vec<u8>,
    pub mode: u32,
    pub gid: u32,
    pub services: BTreeMap<String, String>,
    #[serde(default)]
    pub writers: Option<writers::Snapshot>,
    pub candidate: String,
    config: WiredConfig,
}

impl Network {
    pub async fn takeover(
        &self,
        method: String,
        input: NetworkTakeover,
        key: String,
        session: String,
    ) -> Result<Value> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            if method == "network.takeover.plan" {
                ensure!(input.expected_revision == 0 && input.source_digest.is_empty() && input.plan_digest.is_empty() && input.confirm_seconds == 0, "INVALID_ARGUMENT: plan accepts only interface");
                return Ok(match this.1.transfer_plan(&input.interface) {
                    Ok((transfer, view)) => { drop(transfer); view }
                    Err(error) => json!({"eligible":false,"interface":input.interface,"diagnostic":error.to_string()}),
                });
            }
            ensure!(method == "network.takeover.prepare", "UNSUPPORTED");
            let _system = this.system_guard()?;
            let mut engine = this.0.try_lock().map_err(|_| anyhow::anyhow!("CONFLICT: system change in progress"))?;
            engine.prepare_takeover(input, &key, &session)
        }).await?
    }
}

impl Engine {
    pub(super) fn service_snapshot(&self) -> Result<BTreeMap<String, String>> {
        #[cfg(test)]
        if self.fake {
            return Ok(BTreeMap::from([(
                "systemd-networkd.service".into(),
                "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n".into(),
            )]));
        }
        let mut map = BTreeMap::new();
        for unit in [
            "systemd-networkd.service",
            "NetworkManager.service",
            "cloud-init-local.service",
            "cloud-init.service",
            "cloud-init-network.service",
        ] {
            let path = self.state.join(format!("service-{}.txt", Uuid::new_v4()));
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)?;
            let result = (|| {
                let mut child = Command::new("/usr/bin/systemctl")
                    .args([
                        "show",
                        unit,
                        "--property=LoadState,ActiveState,UnitFileState",
                    ])
                    .stdin(Stdio::null())
                    .stdout(file)
                    .stderr(Stdio::null())
                    .spawn()?;
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    if let Some(status) = child.try_wait()? {
                        let text = String::from_utf8(read(&path)?)?;
                        // show reports LoadState=not-found for absent optional units.
                        ensure!(
                            status.success() || text.contains("LoadState=not-found"),
                            "INTERNAL: service inspection"
                        );
                        return Ok(text);
                    }
                    if Instant::now() >= deadline {
                        child.kill()?;
                        child.wait()?;
                        bail!("TIMEOUT: service inspection");
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })();
            remove(&path)?;
            map.insert(unit.into(), result?);
        }
        ensure!(
            map["systemd-networkd.service"]
                .lines()
                .any(|l| l == "ActiveState=active"),
            "CONFLICT: networkd is not active"
        );
        for (unit, state) in &map {
            if unit == "systemd-networkd.service" {
                continue;
            }
            ensure!(
                !state.lines().any(|l| matches!(
                    l,
                    "ActiveState=active"
                        | "ActiveState=activating"
                        | "UnitFileState=enabled"
                        | "UnitFileState=enabled-runtime"
                )),
                "CONFLICT: competing writer {unit}"
            );
        }
        Ok(map)
    }

    pub(super) fn transfer_plan(&self, interface: &str) -> Result<(Transfer, Value)> {
        ensure!(
            !interface.is_empty()
                && interface.len() <= 15
                && interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
            "INVALID_ARGUMENT: interface"
        );
        let old = self.confirmed()?;
        ensure!(
            !owns_interface(&old, interface)?,
            "CONFLICT: already managed"
        );
        ensure!(
            self.journal()?
                .is_none_or(|j| TERMINAL.contains(&j.state.as_str())),
            "CONFLICT: unresolved system transaction"
        );
        ensure!(
            !self.path("run/netplan").exists(),
            "CONFLICT: runtime candidate exists"
        );
        let sources = self.sources()?;
        let mut definitions = vec![];
        for (path, bytes) in &sources {
            let doc: Value = serde_yaml::from_slice(bytes)?;
            if doc["network"]["ethernets"].get(interface).is_some() {
                definitions.push((path.clone(), doc));
            }
        }
        ensure!(
            definitions.len() == 1,
            "CONFLICT: expected one unambiguous source, found {}",
            definitions.len()
        );
        let (source, mut doc) = definitions.pop().unwrap();
        ensure!(
            source.starts_with("etc/netplan/") && source != format!("etc/netplan/{FILE}"),
            "UNSUPPORTED: only an explicit /etc/netplan source can be normalized"
        );
        let original = sources[&source].clone();
        let text = String::from_utf8_lossy(&original).to_lowercase();
        ensure!(
            !source.to_lowercase().contains("cloud")
                && !text.contains("cloud-init")
                && !text.contains("networkmanager"),
            "CONFLICT: generated source requires writer handover"
        );
        let basename = Path::new(&source).file_name().unwrap().to_str().unwrap();
        let shadow = format!("run/netplan/{basename}");
        ensure!(
            !sources.contains_key(&shadow)
                && !sources.contains_key(&format!("lib/netplan/{basename}")),
            "CONFLICT: same-name source shadows require manual resolution"
        );
        let entry = doc["network"]["ethernets"][interface].clone();
        let renderer = entry
            .get("renderer")
            .or_else(|| doc["network"].get("renderer"))
            .and_then(Value::as_str);
        ensure!(
            renderer.is_none_or(|r| r == "networkd"),
            "CONFLICT: renderer is not networkd"
        );
        let fields = entry
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT: ethernet mapping"))?;
        for name in fields.keys() {
            ensure!(
                [
                    "renderer",
                    "dhcp4",
                    "addresses",
                    "routes",
                    "nameservers",
                    "mtu",
                    "optional",
                    "dhcp4-overrides",
                    "dhcp6",
                    "accept-ra",
                    "ipv6-privacy",
                    "ipv6-mtu",
                    "link-local"
                ]
                .contains(&name.as_str()),
                "UNSUPPORTED: takeover field {name}"
            );
        }
        if let Some(overrides) = entry["dhcp4-overrides"].as_object() {
            ensure!(
                overrides.keys().all(|k| k == "route-metric"),
                "UNSUPPORTED: DHCP overrides require explicit mapping"
            );
        }
        let before = self.runtime(interface)?;
        let strings = |v: &Value| -> Result<Vec<String>> {
            v.as_array()
                .into_iter()
                .flatten()
                .map(|s| {
                    s.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow::anyhow!("UNSUPPORTED: non-string address"))
                })
                .collect()
        };
        let mut routes = vec![];
        for route in entry["routes"].as_array().into_iter().flatten() {
            if route["to"].as_str().is_some_and(|v| v.contains(':'))
                || route["via"].as_str().is_some_and(|v| v.contains(':'))
            {
                continue;
            }
            ensure!(
                route.as_object().is_some_and(|r| r
                    .keys()
                    .all(|k| ["to", "via", "metric"].contains(&k.as_str()))),
                "UNSUPPORTED: route requires explicit mapping"
            );
            routes.push(StaticRoute {
                to: route["to"].as_str().unwrap_or("").into(),
                via: route["via"].as_str().unwrap_or("").into(),
                metric: route["metric"].as_u64().unwrap_or(0).try_into()?,
            });
        }
        let config = WiredConfig {
            interface: interface.into(),
            dhcp4: entry["dhcp4"].as_bool().unwrap_or(false),
            addresses: strings(&entry["addresses"])?
                .into_iter()
                .filter(|s| !s.contains(':'))
                .collect(),
            routes,
            nameservers: strings(&entry["nameservers"]["addresses"])?,
            search_domains: strings(&entry["nameservers"]["search"])?,
            mtu: entry["mtu"]
                .as_u64()
                .unwrap_or(before.mtu as u64)
                .try_into()?,
            optional: entry["optional"].as_bool().unwrap_or(false),
            dhcp_metric: entry["dhcp4-overrides"]["route-metric"]
                .as_u64()
                .unwrap_or(100)
                .try_into()?,
        };
        validate(&config)?;
        doc["network"]["ethernets"]
            .as_object_mut()
            .unwrap()
            .remove(interface);
        let normalized = serde_yaml::to_string(&doc)?.into_bytes();
        let mut sanitized = sources.clone();
        sanitized.insert(source.clone(), normalized.clone());
        self.ownership(&sanitized, &config, &old)?;
        let writers = self.writer_snapshot(&sources, interface)?;
        let services = writers.services.clone();
        let metadata = fs::symlink_metadata(self.root.join(&source))?;
        ensure!(
            metadata.mode() & 0o7000 == 0,
            "CONFLICT: unexpected source mode"
        );
        let mut candidate: Value = old
            .yaml
            .as_ref()
            .map(|s| serde_yaml::from_str(s))
            .transpose()?
            .unwrap_or_else(|| json!({"network":{"version":2,"ethernets":{}}}));
        candidate["network"]["ethernets"][interface] = entry.clone();
        candidate["network"]["ethernets"][interface]["renderer"] = json!("networkd");
        let transfer = Transfer {
            source: source.clone(),
            shadow,
            original,
            normalized,
            mode: metadata.mode() & 0o777,
            gid: metadata.gid(),
            services: services.clone(),
            writers: Some(writers),
            candidate: serde_yaml::to_string(&candidate)?,
            config,
        };
        let digest = hash(&serde_json::to_vec(&transfer)?);
        let view = json!({"eligible":true,"interface":interface,"revision":old.revision,"sourceDigest":Self::digest(&sources),"planDigest":digest,"sourcePath":source,"sourceMode":format!("{:04o}",transfer.mode),"sourceGid":transfer.gid,"services":services,"preservedInterface":entry,"preservedOtherInterfaces":doc["network"]["ethernets"].as_object().unwrap().keys().collect::<Vec<_>>(),"originalSha256":hash(&transfer.original),"normalizedSha256":hash(&transfer.normalized),"changesAddresses":false});
        Ok((transfer, view))
    }

    pub(super) fn prepare_takeover(
        &mut self,
        input: NetworkTakeover,
        key: &str,
        session: &str,
    ) -> Result<Value> {
        let request_hash = hash(&serde_json::to_vec(&input)?);
        if let Some(view) = self.deduplicate(key, &request_hash)? {
            return Ok(view);
        }
        let (transfer, plan) = self.transfer_plan(&input.interface)?;
        ensure!(
            plan["revision"] == input.expected_revision
                && plan["sourceDigest"] == input.source_digest
                && plan["planDigest"] == input.plan_digest,
            "CONFLICT: reviewed takeover plan changed"
        );
        // Validate the accepted-confirmation crash window too: both persistent
        // definitions briefly contain the SAME interface values, never a delta.
        self.generate(&self.sources()?, &transfer.candidate)?;
        let change = NetworkChange {
            expected_revision: input.expected_revision,
            config: Some(transfer.config.clone()),
            confirm_seconds: input.confirm_seconds,
            source_digest: input.source_digest,
        };
        self.prepare_with(change, key, session, Some(transfer), request_hash)
    }

    pub(super) fn transaction_sources(&self, j: &Journal) -> Result<BTreeMap<String, Vec<u8>>> {
        self.verify_writers(j)?;
        let mut sources = self.sources()?;
        if let Some(t) = &j.transfer {
            if let Some(bytes) = sources.remove(&t.shadow) {
                ensure!(
                    bytes == t.normalized,
                    "CONFLICT: takeover runtime source drift"
                );
            } else {
                ensure!(
                    j.state != "WAIT_CONFIRM" || j.confirmed_decision,
                    "CONFLICT: takeover runtime source missing"
                );
            }
            let original = sources
                .get_mut(&t.source)
                .ok_or_else(|| anyhow::anyhow!("CONFLICT: takeover source missing"))?;
            ensure!(
                *original == t.original || (j.confirmed_decision && *original == t.normalized),
                "CONFLICT: takeover persistent source drift"
            );
            *original = t.original.clone();
            let metadata = fs::symlink_metadata(self.root.join(&t.source))?;
            ensure!(
                metadata.mode() & 0o777 == t.mode && metadata.gid() == t.gid,
                "CONFLICT: takeover permissions drift"
            );
            let services = self.service_snapshot()?;
            // Older journals predate the classic cloud-init.service probe.
            // Every new probe still enforces the competing-writer policy.
            ensure!(
                t.services
                    .iter()
                    .all(|(unit, state)| services.get(unit) == Some(state)),
                "CONFLICT: backend service state changed"
            );
        }
        Ok(sources)
    }

    pub(super) fn normalize_source(&self, t: &Transfer) -> Result<()> {
        let path = self.root.join(&t.source);
        let parent = path.parent().unwrap();
        let tmp = parent.join(format!(".yofc-{}", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&t.normalized)?;
        ensure!(
            unsafe { libc::fchown(file.as_raw_fd(), u32::MAX, t.gid) } == 0,
            "INTERNAL: preserve source group"
        );
        file.set_permissions(fs::Permissions::from_mode(t.mode))?;
        file.sync_all()?;
        fs::rename(tmp, &path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub(super) fn remove_shadow(&self, t: &Transfer) -> Result<()> {
        let path = self.root.join(&t.shadow);
        if path.exists() {
            ensure!(
                read(&path)? == t.normalized,
                "CONFLICT: takeover runtime source drift"
            );
            remove(&path)?;
        }
        Ok(())
    }
}
