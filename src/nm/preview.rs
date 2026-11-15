//! Pure candidate compilation. Never calls NM, nft, journals, or adoption APIs.
use super::*;
use std::net::IpAddr;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Preview {
    source_digest: String,
    changes: Vec<Change>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Change {
    interface: String,
    ipv4: Option<Ip>,
    ipv6: Option<Ip>,
    ethernet: Option<Ethernet>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Ip {
    method: String,
    addresses: Vec<Address>,
    gateway: Option<String>,
    dns: Vec<String>,
    ignore_auto_dns: bool,
    ignore_auto_routes: bool,
    wan_priority: Option<i32>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Address {
    address: String,
    prefix: u8,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Ethernet {
    mtu: u32,
    accept_all_mac_addresses: i32,
}
fn invalid<T>() -> Result<T> {
    anyhow::bail!("INVALID_ARGUMENT: NM candidate")
}
fn ip(value: &str, v6: bool) -> Result<IpAddr> {
    let ip: IpAddr = value
        .parse()
        .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: NM IP address"))?;
    ensure!(
        ip.is_ipv6() == v6 && !ip.is_unspecified() && !ip.is_multicast(),
        "INVALID_ARGUMENT: NM IP family or address"
    );
    Ok(ip)
}
fn put(map: &mut serde_json::Map<String, Value>, key: &str, signature: &str, data: Value) {
    map.insert(key.into(), json!({"type":signature,"data":data}));
}
impl Ip {
    fn apply(&self, settings: &mut Value, v6: bool) -> Result<()> {
        ensure!(
            ["auto", "manual", "disabled", "link-local"].contains(&self.method.as_str()),
            "INVALID_ARGUMENT: NM IP method"
        );
        ensure!(
            self.addresses.len() <= 16 && self.dns.len() <= 8,
            "INVALID_ARGUMENT: NM IP bounds"
        );
        ensure!(
            self.method != "manual" || !self.addresses.is_empty(),
            "INVALID_ARGUMENT: NM manual address required"
        );
        if matches!(self.method.as_str(), "disabled" | "link-local")
            && (!self.addresses.is_empty() || !self.dns.is_empty() || self.gateway.is_some())
        {
            return invalid();
        }
        ensure!(
            self.gateway.is_none() || !self.addresses.is_empty(),
            "INVALID_ARGUMENT: NM gateway needs static address"
        );
        let mut seen = std::collections::BTreeSet::new();
        let mut addresses = Vec::new();
        for a in &self.addresses {
            let address = ip(&a.address, v6)?;
            ensure!(
                a.prefix <= if v6 { 128 } else { 32 } && seen.insert(address),
                "INVALID_ARGUMENT: NM prefix or duplicate address"
            );
            addresses.push(json!({"address":{"type":"s","data":address.to_string()},"prefix":{"type":"u","data":a.prefix}}));
        }
        let mut dns = Vec::new();
        seen.clear();
        for name in &self.dns {
            let address = ip(name, v6)?;
            ensure!(seen.insert(address), "INVALID_ARGUMENT: NM duplicate DNS");
            dns.push(match address {
                // NM's legacy IPv4 DNS representation is a network-byte-order integer.
                IpAddr::V4(a) => json!(u32::from_ne_bytes(a.octets())),
                IpAddr::V6(a) => json!(a.octets()),
            });
        }
        let key = if v6 { "ipv6" } else { "ipv4" };
        let groups = settings
            .as_object_mut()
            .context("CONFLICT: NM candidate settings")?;
        let map = groups
            .entry(key)
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .context("CONFLICT: NM candidate IP group")?;
        // This family is a complete replacement of these explicit editable fields.
        // Unrelated routes, policy rules, DHCP options and provider properties survive.
        for key in [
            "addresses",
            "address-data",
            "gateway",
            "dns",
            "dns-data",
            "ignore-auto-dns",
            "ignore-auto-routes",
        ] {
            map.remove(key);
        }
        put(map, "method", "s", json!(self.method));
        put(map, "address-data", "aa{sv}", json!(addresses));
        put(map, "dns", if v6 { "aay" } else { "au" }, json!(dns));
        put(map, "ignore-auto-dns", "b", json!(self.ignore_auto_dns));
        put(
            map,
            "ignore-auto-routes",
            "b",
            json!(self.ignore_auto_routes),
        );
        if let Some(gateway) = &self.gateway {
            put(map, "gateway", "s", json!(ip(gateway, v6)?.to_string()));
        }
        if let Some(priority) = self.wan_priority {
            ensure!(
                (-1..i32::MAX).contains(&priority),
                "INVALID_ARGUMENT: NM WAN priority"
            );
            put(
                map,
                "route-metric",
                "x",
                json!(if priority == -1 {
                    -1i64
                } else {
                    i64::from(priority) + 1
                }),
            );
            put(
                map,
                "dns-priority",
                "i",
                json!(if priority == -1 { 0 } else { priority + 1 }),
            );
        }
        Ok(())
    }
}
/// Full detached candidate retained for the coordinator; never serialized into
/// observation responses. `version_id` is the persistent-profile CAS token read
/// from the profile itself, never the device applied version.
pub(super) struct DetachedCandidate {
    pub(super) interface: String,
    pub(super) uuid: String,
    pub(super) profile_path: String,
    pub(super) device_path: String,
    pub(super) version_id: u64,
    pub(super) stored: Value,
    /// Candidate (post-edit) content digest; the Update2 readback binds to it.
    pub(super) stored_sha256: String,
    /// Source (pre-edit, volatile-free) content digest; the pre-write binding
    /// uses it so a checkpoint-induced timestamp rewrite never breaks the CAS.
    pub(super) source_sha256: String,
    /// The complete pre-edit settings; the post-rollback restoration check
    /// binds the edited surface to these values (netplan regenerations change
    /// unrelated defaults, so a whole-profile digest cannot bind).
    pub(super) source_settings: Value,
    pub(super) source_applied: Value,
    pub(super) applied_sha256: String,
    /// NM >= 1.42 Reapply takes the full applied connection plus its version.
    pub(super) applied: Value,
    pub(super) applied_version: u64,
}
impl Preview {
    pub(super) fn parse(value: Value) -> Result<Self> {
        let input: Self = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: NM candidate shape"))?;
        ensure!(
            input.source_digest.len() == 64
                && input
                    .source_digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "INVALID_ARGUMENT: NM source digest"
        );
        ensure!(
            !input.changes.is_empty() && input.changes.len() <= 16,
            "INVALID_ARGUMENT: NM candidate interface bounds"
        );
        let mut seen = std::collections::BTreeSet::new();
        for c in &input.changes {
            ensure!(
                seen.insert(&c.interface)
                    && (c.ipv4.is_some() || c.ipv6.is_some() || c.ethernet.is_some()),
                "INVALID_ARGUMENT: NM duplicate or empty patch"
            );
        }
        Ok(input)
    }
    pub(super) fn compile(&self, source: &Value, devices: &[Device]) -> Result<Value> {
        self.compile_detached(source, devices).map(|(value, _)| value)
    }
    pub(super) fn compile_detached(
        &self,
        source: &Value,
        devices: &[Device],
    ) -> Result<(Value, Vec<DetachedCandidate>)> {
        ensure!(
            source["sourceDigest"] == self.source_digest,
            "CONFLICT: NM candidate source changed"
        );
        let version = source["source"]["version"]
            .as_str()
            .context("CONFLICT: NM version")?;
        let mut parts = version.split('.');
        let major = parts
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .context("UNSUPPORTED: NM version")?;
        let minor = parts
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .context("UNSUPPORTED: NM version")?;
        ensure!(
            (major, minor) >= (1, 40),
            "UNSUPPORTED: NM candidate needs version 1.40 or newer"
        );
        let mut candidates = Vec::new();
        let mut detached = Vec::new();
        for c in &self.changes {
            let device = devices
                .iter()
                .find(|d| d.interface == c.interface)
                .context("FORBIDDEN: NM interface not configured")?;
            let profile = device
                .active_profile
                .as_ref()
                .context("UNSUPPORTED: no active NM profile")?;
            ensure!(
                device.managed
                    && device.state == 100
                    && profile.wired_shape
                    && !profile.unsaved
                    && profile.flags == 0,
                "UNSUPPORTED: NM profile requires a supported persistent wired source"
            );
            let mut stored = profile.settings.clone();
            let mut applied = profile.applied.clone();
            for settings in [&mut stored, &mut applied] {
                if let Some(p) = &c.ipv4 {
                    p.apply(settings, false)?;
                }
                if let Some(p) = &c.ipv6 {
                    p.apply(settings, true)?;
                }
                if let Some(p) = &c.ethernet {
                    ensure!(
                        p.mtu == 0 || (576..=65535).contains(&p.mtu),
                        "INVALID_ARGUMENT: NM MTU"
                    );
                    ensure!(
                        (-1..=1).contains(&p.accept_all_mac_addresses),
                        "INVALID_ARGUMENT: NM promiscuous mode"
                    );
                    if !settings["ipv6"]["method"]["data"]
                        .as_str()
                        .is_some_and(|method| method == "disabled" || method == "ignore")
                    {
                        ensure!(p.mtu == 0 || p.mtu >= 1280, "INVALID_ARGUMENT: NM IPv6 MTU");
                    }
                    let map = settings
                        .as_object_mut()
                        .context("CONFLICT: NM settings")?
                        .entry("802-3-ethernet")
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                        .context("CONFLICT: NM Ethernet group")?;
                    put(map, "mtu", "u", json!(p.mtu));
                    put(
                        map,
                        "accept-all-mac-addresses",
                        "i",
                        json!(p.accept_all_mac_addresses),
                    );
                }
            }
            let stored_sha256 = settings_digest(&stored)?;
            let applied_sha256 = digest(&applied)?;
            detached.push(DetachedCandidate {
                interface: c.interface.clone(),
                uuid: profile.uuid.clone(),
                profile_path: profile.profile_path.clone(),
                device_path: device.device_path.clone(),
                version_id: profile.version_id,
                stored_sha256: stored_sha256.clone(),
                source_sha256: profile.settings_sha256.clone(),
                source_settings: profile.settings.clone(),
                  source_applied: profile.applied.clone(),
                  applied_sha256: applied_sha256.clone(),
                  applied,
                applied_version: profile.applied_version,
                stored,
            });
            candidates.push(json!({"interface":c.interface,"profileUuid":profile.uuid,"appliedVersion":profile.applied_version,"settingsSha256":stored_sha256,"appliedSha256":applied_sha256}));
        }
        let proposal = json!({"sourceDigest":self.source_digest,"changes":self.changes,"candidates":candidates});
        Ok((
            json!({"schemaVersion":1,"backend":"NetworkManager","writeEnabled":false,"prepared":false,"requiresAdoption":true,"candidateDigest":digest(&proposal)?,"proposal":proposal}),
            detached,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn patch(v6: bool) -> Ip {
        serde_json::from_value(json!({"method":"manual","addresses":[{"address":if v6 {"2001:db8::10"} else {"192.0.2.10"},"prefix":if v6 {64} else {24}}],"gateway":if v6 {"2001:db8::1"} else {"192.0.2.1"},"dns":[if v6 {"2001:db8::53"} else {"192.0.2.53"}],"ignoreAutoDns":true,"ignoreAutoRoutes":false,"wanPriority":2147483646})).unwrap()
    }
    #[test]
    fn typed_families_preserve_unedited_fields_and_remove_conflicting_legacy_aliases() {
        for v6 in [false, true] {
            let key = if v6 { "ipv6" } else { "ipv4" };
            let original = json!({key:{"routes":{"type":"aau","data":[[1,2,3,4]]},"provider-extra":{"type":"s","data":"keep-me"},"addresses":{"type":"aau","data":[]},"dns-data":{"type":"as","data":["old"]}},"user":{"data":{"type":"a{ss}","data":{"preserved":"yes"}}}});
            let mut settings = original.clone();
            patch(v6).apply(&mut settings, v6).unwrap();
            assert_eq!(settings[key]["routes"], original[key]["routes"]);
            assert_eq!(
                settings[key]["provider-extra"],
                original[key]["provider-extra"]
            );
            assert_eq!(settings["user"], original["user"]);
            assert!(settings[key].get("addresses").is_none());
            assert!(settings[key].get("dns-data").is_none());
            assert_eq!(settings[key]["address-data"]["type"], "aa{sv}");
            assert_eq!(
                settings[key]["address-data"]["data"][0]["prefix"]["type"],
                "u"
            );
            assert_eq!(
                settings[key]["dns-priority"],
                json!({"type":"i","data":2147483647})
            );
            assert_eq!(
                settings[key]["route-metric"],
                json!({"type":"x","data":2147483647})
            );
            assert_eq!(settings[key]["dns"]["type"], if v6 { "aay" } else { "au" });
            if !v6 {
                assert_eq!(
                    settings[key]["dns"]["data"][0],
                    u32::from_ne_bytes([192, 0, 2, 53])
                );
            }
        }
    }
    #[test]
    fn explicit_empty_clears_addresses_gateway_dns_but_omitted_priority_preserves_policy() {
        let mut p = patch(false);
        p.method = "disabled".into();
        p.addresses.clear();
        p.gateway = None;
        p.dns.clear();
        p.wan_priority = None;
        let mut settings = json!({"ipv4":{"gateway":{"type":"s","data":"old"},"dns-priority":{"type":"i","data":-20}}});
        p.apply(&mut settings, false).unwrap();
        assert!(settings["ipv4"].get("gateway").is_none());
        assert_eq!(settings["ipv4"]["address-data"]["data"], json!([]));
        assert_eq!(settings["ipv4"]["dns"]["data"], json!([]));
        assert_eq!(settings["ipv4"]["dns-priority"]["data"], -20);
    }
    #[test]
    fn malformed_family_prefix_address_dns_method_and_priority_fail_without_changing_source() {
        for case in [
            "family",
            "prefix",
            "gateway",
            "dns",
            "duplicate",
            "priority",
            "method",
            "manual",
            "oversize",
        ] {
            let mut p = patch(false);
            match case {
                "family" => p.addresses[0].address = "2001:db8::1".into(),
                "prefix" => p.addresses[0].prefix = 33,
                "gateway" => p.gateway = Some("0.0.0.0".into()),
                "dns" => p.dns = vec!["dns.example".into()],
                "duplicate" => p.dns.push(p.dns[0].clone()),
                "priority" => p.wan_priority = Some(i32::MAX),
                "method" => p.method = "shared".into(),
                "manual" => p.addresses.clear(),
                _ => p.dns = vec!["192.0.2.1".into(); 9],
            }
            let source = json!({"ipv4":{"untouched":true}});
            let mut detached = source.clone();
            assert!(p.apply(&mut detached, false).is_err(), "{case}");
            assert_eq!(source, json!({"ipv4":{"untouched":true}}));
        }
    }
}

#[cfg(test)]
mod priority_tests {
    use super::*;
    #[test]
    fn automatic_and_minimum_priorities_have_distinct_signed_wire_types() {
        for priority in [-1, 0] {
            let p:Ip=serde_json::from_value(json!({"method":"auto","addresses":[],"gateway":null,"dns":[],"ignoreAutoDns":false,"ignoreAutoRoutes":false,"wanPriority":priority})).unwrap();
            let mut settings = json!({});
            p.apply(&mut settings, false).unwrap();
            assert_eq!(
                settings["ipv4"]["dns-priority"],
                json!({"type":"i","data":if priority == -1 {0} else {1}})
            );
            assert_eq!(
                settings["ipv4"]["route-metric"],
                json!({"type":"x","data":if priority == -1 {-1} else {1}})
            );
        }
    }
}
