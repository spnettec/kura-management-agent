use crate::local::Local;

pub(super) fn advertised(local: &Local) -> Vec<String> {
    let mut capabilities = vec![
        "agent.status".into(),
        "task.reconcile.v1".into(),
        "task.network-outcome.v1".into(),
        "task.configuration-outcome.v1".into(),
        "kura.configuration.list".into(),
        "kura.configuration.get".into(),
        "kura.snapshot.list".into(),
    ];
    if let Some(network) = &local.network {
        capabilities.extend(
            [
                "network.inspect",
                "network.transaction",
                "network.takeover.plan",
            ]
            .map(String::from),
        );
        // A constructed backend with no permitted interfaces is observation
        // only. Do not invite new mutations or imply a write delegation.
        if network.writes_enabled() {
            capabilities.extend(
                [
                    "network.prepare",
                    "network.confirm",
                    "network.rollback",
                    "network.takeover.prepare",
                ]
                .map(String::from),
            );
        }
    }
    if local.configuration_updates_enabled() {
        capabilities.push("kura.configuration.update".into());
    }
    if local.ordinary_boot.is_some() {
        capabilities.push("ordinary.boot.v1".into());
    }
    if local.ordinary_handoff_remote {
        capabilities.push("recovery.ordinary.v1".into());
        capabilities.push("recovery.ordinary.cancel.v1".into());
    }
    if local.system_control_remote
        && let Some(control) = &local.system_control
    {
        capabilities.extend(
            control
                .capabilities()
                .unwrap_or_else(|_| vec!["system.control.v1".into()]),
        );
    }
    if local.snapshots_enabled() {
        capabilities.push("kura.snapshot.write".into());
    }
    if local.firewall_remote && local.firewall.is_some() {
        capabilities.push("firewall.remote.v1".into());
    }
    if local.nm_remote && local.nm.is_some() {
        capabilities.push("nm.remote.v1".into());
    }
    if local.firewall.is_some() {
        capabilities.push(yofc_management_protocol::imported::CAPABILITY.into());
        if super::imported::write_grant(local) && local.nm.is_some() {
            capabilities.push(yofc_management_protocol::imported::WRITE_CAPABILITY.into());
        }
    }
    capabilities
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(capabilities: &[String], name: &str) -> bool {
        capabilities.iter().any(|value| value == name)
    }

    fn scoped_network(interfaces: Vec<String>) -> crate::network::Network {
        let root = std::env::temp_dir().join(format!("kura-capabilities-{}", uuid::Uuid::new_v4()));
        // These tests run in a disposable Linux container. They only create a
        // private coordinator/lock; no system networking commands are invoked.
        crate::network::Network::open(root.clone(), root.join("network"), interfaces).unwrap()
    }

    #[test]
    fn absent_network_and_optional_grants_do_not_advertise_management_writes() {
        let capabilities = advertised(&Local::new(996, 997));
        assert!(contains(&capabilities, "agent.status"));
        assert!(contains(&capabilities, "task.reconcile.v1"));
        assert!(contains(&capabilities, "task.network-outcome.v1"));
        assert!(contains(&capabilities, "kura.configuration.get"));
        assert!(contains(&capabilities, "kura.snapshot.list"));
        assert!(!capabilities.iter().any(|name| name.starts_with("network.")));
        for name in [
            "kura.configuration.update",
            "kura.snapshot.write",
            "firewall.remote.v1",
            "nm.remote.v1",
            "ordinary.boot.v1",
            "recovery.ordinary.v1",
            "system.control.v1",
        ] {
            assert!(!contains(&capabilities, name), "ungranted {name}");
        }
    }

    #[test]
    fn constructed_network_with_empty_scope_only_advertises_observation() {
        let mut local = Local::new(996, 997);
        local.network = Some(scoped_network(vec![]));
        let capabilities = advertised(&local);
        for name in [
            "network.inspect",
            "network.transaction",
            "network.takeover.plan",
        ] {
            assert!(contains(&capabilities, name));
        }
        for name in [
            "network.prepare",
            "network.confirm",
            "network.rollback",
            "network.takeover.prepare",
        ] {
            assert!(
                !contains(&capabilities, name),
                "empty scope advertised {name}"
            );
        }
    }

    #[test]
    fn explicitly_scoped_network_preserves_the_existing_transaction_protocol() {
        let mut local = Local::new(996, 997);
        local.network = Some(scoped_network(vec!["eth0".into()]));
        let capabilities = advertised(&local);
        for name in [
            "network.inspect",
            "network.transaction",
            "network.prepare",
            "network.confirm",
            "network.rollback",
            "network.takeover.plan",
            "network.takeover.prepare",
        ] {
            assert!(contains(&capabilities, name));
        }
        assert!(!contains(&capabilities, "nm.remote.v1"));
        assert!(!contains(&capabilities, "kura.configuration.update"));
    }

    #[test]
    fn explicit_configuration_and_snapshot_grants_remain_independent() {
        let mut local = Local::new(996, 997);
        local.enable_configuration_updates(true);
        assert!(contains(&advertised(&local), "kura.configuration.update"));
        assert!(!contains(&advertised(&local), "kura.snapshot.write"));
        local.enable_configuration_updates(false);
        local.enable_snapshots(true);
        let capabilities = advertised(&local);
        assert!(!contains(&capabilities, "kura.configuration.update"));
        assert!(contains(&capabilities, "kura.snapshot.write"));
        assert!(!capabilities.iter().any(|name| name.starts_with("network.")));
    }
}
