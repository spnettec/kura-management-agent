//! A deliberately smaller, explicitly delegated network API for the registered
//! Kura process. It cannot transfer sources or operate another actor's transaction.
use super::*;
use yofc_management_protocol::v1::StaticRoute;

const SESSION: &str = "local-kura";
const ENTRY_FIELDS: &[&str] = &[
    "renderer",
    "dhcp4",
    "addresses",
    "mtu",
    "optional",
    "nameservers",
    "routes",
    "dhcp4-overrides",
    "dhcp6",
    "accept-ra",
    "ipv6-privacy",
    "ipv6-mtu",
    "link-local",
];

impl Network {
    pub fn validate_kura_delegation(&self, interfaces: &[String]) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for name in interfaces {
            ensure!(
                self.1.allow.contains(name) && seen.insert(name),
                "FORBIDDEN: Kura delegation must be a unique subset of agent interfaces"
            );
        }
        Ok(())
    }

    pub async fn kura_request(
        &self,
        method: String,
        params: Value,
        key: String,
        interfaces: Vec<String>,
    ) -> Result<Value> {
        self.validate_kura_delegation(&interfaces)?;
        ensure!(
            !key.is_empty() && key.len() <= 64,
            "INVALID_ARGUMENT: request ID"
        );
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            if method == "network.kura.view" {
                ensure!(
                    params.is_null() || params == json!({}),
                    "INVALID_ARGUMENT: view parameters"
                );
                return this.1.kura_view(&interfaces);
            }
            if method == "network.kura.transaction" {
                fields(&params, &["transactionId"], "INVALID_ARGUMENT")?;
                let id = params["transactionId"]
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT: transaction ID"))?;
                let action = NetworkAction {
                    transaction_id: id.into(),
                    confirmation_token: String::new(),
                };
                let journal = this.1.kura_journal(&interfaces, &action)?;
                return Ok(this.1.view(&journal));
            }
            let mut engine = this
                .0
                .try_lock()
                .map_err(|_| anyhow::anyhow!("CONFLICT: system change in progress"))?;
            match method.as_str() {
                "network.kura.prepare" => {
                    fields(
                        &params,
                        &[
                            "expectedRevision",
                            "sourceDigest",
                            "confirmSeconds",
                            "config",
                        ],
                        "INVALID_ARGUMENT",
                    )?;
                    fields(
                        &params["config"],
                        &[
                            "interface",
                            "dhcp4",
                            "addresses",
                            "routes",
                            "nameservers",
                            "searchDomains",
                            "mtu",
                            "optional",
                            "dhcpMetric",
                        ],
                        "INVALID_ARGUMENT",
                    )?;
                    for route in params["config"]["routes"].as_array().into_iter().flatten() {
                        fields(route, &["to", "via", "metric"], "INVALID_ARGUMENT")?;
                    }
                    let change: NetworkChange = serde_json::from_value(params)
                        .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: network change"))?;
                    let config = change
                        .config
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT: network config"))?;
                    ensure!(
                        interfaces.contains(&config.interface),
                        "FORBIDDEN: interface delegation"
                    );
                    // Recheck the preserved source even if a caller ignores writable=false.
                    if let Some(yaml) = &engine.confirmed()?.yaml {
                        let doc: Value = serde_yaml::from_str(yaml)?;
                        let entry = &doc["network"]["ethernets"][&config.interface];
                        if !entry.is_null() {
                            entry_config(&config.interface, entry, config.mtu)?;
                        }
                    }
                    // A Kura request ID cannot collide with another actor's durable receipt.
                    let key = hash(format!("{SESSION}:{key}").as_bytes());
                    engine.prepare(change, &key, SESSION)
                }
                "network.kura.confirm" | "network.kura.rollback" => {
                    fields(
                        &params,
                        &["transactionId", "confirmationToken"],
                        "INVALID_ARGUMENT",
                    )?;
                    let action: NetworkAction = serde_json::from_value(params)
                        .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: network action"))?;
                    let journal = engine.kura_journal(&interfaces, &action)?;
                    ensure!(
                        !action.confirmation_token.is_empty()
                            && action.confirmation_token == journal.token,
                        "FORBIDDEN: confirmation token"
                    );
                    let operation = if method == "network.kura.confirm" {
                        "network.confirm"
                    } else {
                        "network.rollback"
                    };
                    engine.action(operation, action, SESSION)
                }
                _ => bail!("UNSUPPORTED"),
            }
        })
        .await?
    }
}

impl Engine {
    fn kura_journal(&self, interfaces: &[String], action: &NetworkAction) -> Result<Journal> {
        let journal = self
            .journal()?
            .ok_or_else(|| anyhow::anyhow!("NOT_FOUND"))?;
        ensure!(journal.id == action.transaction_id, "NOT_FOUND");
        ensure!(
            journal.session == SESSION && interfaces.contains(&journal.config.interface),
            "FORBIDDEN: transaction belongs to another actor or interface"
        );
        Ok(journal)
    }

    fn kura_view(&self, delegated: &[String]) -> Result<Value> {
        let observed = self.inspect()?;
        let confirmed = self.confirmed()?;
        let doc: Value = confirmed
            .yaml
            .as_ref()
            .map(|v| serde_yaml::from_str(v))
            .transpose()?
            .unwrap_or(Value::Null);
        let mut configurations = vec![];
        for (name, entry) in doc["network"]["ethernets"]
            .as_object()
            .into_iter()
            .flatten()
        {
            let mtu = observed["interfaces"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|i| i["name"] == *name)
                .and_then(|i| i["mtu"].as_str())
                .and_then(|v| v.parse().ok())
                .unwrap_or(1500);
            // Original entries stay authoritative in agent storage. Unsupported
            // authentication/NM fields must not enter untyped Kura snapshots.
            let preserved = public_entry(entry);
            let preserved_digest = hash(&serde_json::to_vec(entry)?);
            match entry_config(name, entry, mtu) {
                Ok(config) => configurations.push(json!({"config":config,"preserved":preserved,
                    "preservedDigest":preserved_digest,"writable":delegated.contains(name)})),
                Err(error) => configurations.push(json!({"interface":name,"preserved":preserved,
                    "preservedDigest":preserved_digest,
                    "unmappedFields":entry.as_object().into_iter().flatten().filter(|(k,_)| !ENTRY_FIELDS.contains(&k.as_str())).map(|(k,_)|k).collect::<Vec<_>>(),
                    "writable":false,"error":diagnostic(&error).unwrap_or("UNSUPPORTED: unrepresentable configuration".into())})),
            }
        }
        let interfaces: Vec<Value> = observed["interfaces"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|interface| {
                let mut interface = interface.clone();
                interface["delegated"] = json!(
                    interface["name"]
                        .as_str()
                        .is_some_and(|n| delegated.iter().any(|d| d == n))
                );
                interface
            })
            .collect();
        let transaction = self.journal()?.map(|journal| {
            let own = journal.session == SESSION && delegated.contains(&journal.config.interface);
            let mut view = self.view(&journal);
            view["interface"] = json!(journal.config.interface);
            view["source"] = json!(if journal.session == SESSION {
                "KURA"
            } else {
                "OTHER"
            });
            view["owned"] = json!(own);
            if !own {
                view.as_object_mut().unwrap().remove("confirmationToken");
            }
            view
        });
        Ok(json!({"schemaVersion":1,"revision":confirmed.revision,
            "sourceDigest":observed["sourceDigest"],"configurations":configurations,
            "interfaces":interfaces,"transaction":transaction}))
    }
}

/// Projection of supported IPv4 fields. The authoritative entry is never replaced
/// by this projection, and unknown fields prohibit modification.
fn entry_config(interface: &str, entry: &Value, default_mtu: u32) -> Result<WiredConfig> {
    fields(
        entry,
        &[
            "renderer",
            "dhcp4",
            "addresses",
            "mtu",
            "optional",
            "nameservers",
            "routes",
            "dhcp4-overrides",
            "dhcp6",
            "accept-ra",
            "ipv6-privacy",
            "ipv6-mtu",
            "link-local",
        ],
        "UNSUPPORTED",
    )?;
    ensure!(
        entry.get("renderer").is_none_or(|r| r == "networkd"),
        "UNSUPPORTED: renderer"
    );
    for name in ["dhcp4", "optional"] {
        ensure!(
            entry.get(name).is_none_or(Value::is_boolean),
            "UNSUPPORTED: expected boolean"
        );
    }
    for (value, keys) in [
        (&entry["nameservers"], &["addresses", "search"][..]),
        (&entry["dhcp4-overrides"], &["route-metric"][..]),
    ] {
        if !value.is_null() {
            fields(value, keys, "UNSUPPORTED")?;
        }
    }
    for value in [&entry["mtu"], &entry["dhcp4-overrides"]["route-metric"]] {
        ensure!(
            value.is_null() || value.as_u64().is_some(),
            "UNSUPPORTED: expected unsigned integer"
        );
    }
    ensure!(
        entry["routes"].is_null() || entry["routes"].is_array(),
        "UNSUPPORTED: expected routes array"
    );
    let strings = |value: &Value| -> Result<Vec<String>> {
        if value.is_null() {
            return Ok(vec![]);
        }
        value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("UNSUPPORTED: expected string array"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow::anyhow!("UNSUPPORTED: expected string"))
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
            "UNSUPPORTED: route fields"
        );
        routes.push(StaticRoute {
            to: route["to"].as_str().unwrap_or("").into(),
            via: route["via"].as_str().unwrap_or("").into(),
            metric: match route.get("metric") {
                None => 0,
                Some(v) => v
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("UNSUPPORTED: route metric"))?
                    .try_into()?,
            },
        });
    }
    let config = WiredConfig {
        interface: interface.into(),
        dhcp4: entry["dhcp4"].as_bool().unwrap_or(false),
        addresses: strings(&entry["addresses"])?
            .into_iter()
            .filter(|v| !v.contains(':'))
            .collect(),
        routes,
        nameservers: strings(&entry["nameservers"]["addresses"])?,
        search_domains: strings(&entry["nameservers"]["search"])?,
        mtu: entry["mtu"]
            .as_u64()
            .unwrap_or(default_mtu as u64)
            .try_into()?,
        optional: entry["optional"].as_bool().unwrap_or(false),
        dhcp_metric: entry["dhcp4-overrides"]["route-metric"]
            .as_u64()
            .unwrap_or(100)
            .try_into()?,
    };
    validate(&config)?;
    Ok(config)
}

fn fields(value: &Value, allowed: &[&str], code: &str) -> Result<()> {
    ensure!(
        value
            .as_object()
            .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str()))),
        "{code}: unsupported fields"
    );
    Ok(())
}

fn public_entry(entry: &Value) -> Value {
    let mut result = serde_json::Map::new();
    for (key, value) in entry.as_object().into_iter().flatten() {
        if !ENTRY_FIELDS.contains(&key.as_str()) {
            continue;
        }
        let copy = match key.as_str() {
            "nameservers" => select_fields(value, &["addresses", "search"]),
            "dhcp4-overrides" => select_fields(value, &["route-metric"]),
            "routes" => Value::Array(
                value
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|r| select_fields(r, &["to", "via", "metric"]))
                    .collect(),
            ),
            _ => value.clone(),
        };
        result.insert(key.clone(), copy);
    }
    Value::Object(result)
}
fn select_fields(value: &Value, keys: &[&str]) -> Value {
    Value::Object(
        value
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(k, _)| keys.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        root: PathBuf,
        network: Option<Network>,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("kura-network-{}", Uuid::new_v4()));
            for dir in [
                "etc/netplan",
                "run/netplan",
                "lib/netplan",
                "sys/class/net/test0/device",
            ] {
                fs::create_dir_all(root.join(dir)).unwrap();
            }
            fs::write(root.join("sys/class/net/test0/type"), "1\n").unwrap();
            let mut network =
                Network::open(root.clone(), root.join("state"), vec!["test0".into()]).unwrap();
            network.0.lock().unwrap().fake = true;
            Arc::get_mut(&mut network.1).unwrap().fake = true;
            Self {
                root,
                network: Some(network),
            }
        }
        fn network(&self) -> &Network {
            self.network.as_ref().unwrap()
        }
        fn change(&self) -> Value {
            let view = self.network().1.inspect().unwrap();
            json!({"expectedRevision":view["revision"],"sourceDigest":view["sourceDigest"],"confirmSeconds":120,
                "config":{"interface":"test0","dhcp4":false,"addresses":["192.0.2.2/24"],"routes":[],
                "nameservers":[],"searchDomains":[],"mtu":1500,"optional":true,"dhcpMetric":100}})
        }
        async fn call(&self, method: &str, params: Value) -> Result<Value> {
            self.network()
                .kura_request(
                    method.into(),
                    params,
                    Uuid::new_v4().to_string(),
                    vec!["test0".into()],
                )
                .await
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.network.take();
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[tokio::test]
    async fn explicit_kura_transaction_keeps_candidate_out_of_confirmed_view() {
        let f = Fixture::new();
        let pending = f.call("network.kura.prepare", f.change()).await.unwrap();
        assert_eq!(pending["state"], "WAIT_CONFIRM");
        let view = f.call("network.kura.view", Value::Null).await.unwrap();
        assert_eq!(view["revision"], 0);
        assert_eq!(view["configurations"], json!([]));
        assert_eq!(view["transaction"]["source"], "KURA");
        assert_eq!(view["transaction"]["owned"], true);
        let action =
            json!({"transactionId":pending["id"],"confirmationToken":pending["confirmationToken"]});
        let committed = f.call("network.kura.confirm", action).await.unwrap();
        assert_eq!(committed["state"], "COMMITTED");
        let view = f.call("network.kura.view", Value::Null).await.unwrap();
        assert_eq!(view["revision"], 1);
        assert_eq!(
            view["configurations"][0]["config"]["addresses"],
            json!(["192.0.2.2/24"])
        );
    }

    #[tokio::test]
    async fn kura_cannot_take_over_or_modify_another_actor_transaction() {
        let f = Fixture::new();
        let change: NetworkChange = serde_json::from_value(f.change()).unwrap();
        let j = f
            .network()
            .request(
                "network.prepare".into(),
                Some(change),
                None,
                "remote".into(),
                "remote-epoch".into(),
            )
            .await
            .unwrap();
        let view = f.call("network.kura.view", Value::Null).await.unwrap();
        assert_eq!(view["transaction"]["owned"], false);
        assert!(view["transaction"].get("confirmationToken").is_none());
        for method in [
            "network.kura.transaction",
            "network.kura.confirm",
            "network.kura.rollback",
        ] {
            let mut params = json!({"transactionId":j["id"]});
            if method != "network.kura.transaction" {
                params["confirmationToken"] = j["confirmationToken"].clone();
            }
            let error = f.call(method, params).await.unwrap_err();
            assert_eq!(error_code(&error), "FORBIDDEN");
        }
        assert_eq!(
            error_code(
                &f.call("network.kura.takeover.prepare", Value::Null)
                    .await
                    .unwrap_err()
            ),
            "UNSUPPORTED"
        );
        assert_eq!(
            f.network().1.journal().unwrap().unwrap().state,
            "WAIT_CONFIRM"
        );
    }

    #[tokio::test]
    async fn kura_delegation_and_confirmation_token_are_enforced() {
        let f = Fixture::new();
        assert!(
            f.network()
                .validate_kura_delegation(&["eth0".into()])
                .is_err()
        );
        assert!(
            f.network()
                .validate_kura_delegation(&["test0".into(), "test0".into()])
                .is_err()
        );
        let error = f
            .network()
            .kura_request(
                "network.kura.prepare".into(),
                f.change(),
                "key".into(),
                vec![],
            )
            .await
            .unwrap_err();
        assert_eq!(error_code(&error), "FORBIDDEN");
        assert!(f.network().1.journal().unwrap().is_none());
        let j = f.call("network.kura.prepare", f.change()).await.unwrap();
        assert_eq!(
            error_code(
                &f.call(
                    "network.kura.rollback",
                    json!({"transactionId":j["id"],"confirmationToken":"wrong"})
                )
                .await
                .unwrap_err()
            ),
            "FORBIDDEN"
        );
        let view = f
            .call("network.kura.transaction", json!({"transactionId":j["id"]}))
            .await
            .unwrap();
        assert_eq!(view["state"], "WAIT_CONFIRM");
    }

    #[tokio::test]
    async fn malformed_and_unknown_fields_are_rejected_before_mutation() {
        let f = Fixture::new();
        for params in [
            Value::Null,
            json!({}),
            json!({"transactionId":3}),
            json!({"transactionId":"x","unknown":true}),
        ] {
            assert_eq!(
                error_code(
                    &f.call("network.kura.transaction", params)
                        .await
                        .unwrap_err()
                ),
                "INVALID_ARGUMENT"
            );
        }
        let mut params = f.change();
        params["config"]["unsupported"] = json!(true);
        assert_eq!(
            error_code(&f.call("network.kura.prepare", params).await.unwrap_err()),
            "INVALID_ARGUMENT"
        );
        assert!(f.network().1.journal().unwrap().is_none());
    }

    #[tokio::test]
    async fn kura_receipts_are_separate_and_replays_remain_idempotent() {
        let f = Fixture::new();
        let params = f.change();
        let change: NetworkChange = serde_json::from_value(params.clone()).unwrap();
        let remote = f
            .network()
            .request(
                "network.prepare".into(),
                Some(change),
                None,
                "shared-id".into(),
                "remote-epoch".into(),
            )
            .await
            .unwrap();
        let error = f
            .network()
            .kura_request(
                "network.kura.prepare".into(),
                params,
                "shared-id".into(),
                vec!["test0".into()],
            )
            .await
            .unwrap_err();
        assert_eq!(error_code(&error), "CONFLICT");
        f.network()
            .request(
                "network.rollback".into(),
                None,
                Some(NetworkAction {
                    transaction_id: remote["id"].as_str().unwrap().into(),
                    confirmation_token: String::new(),
                }),
                "rollback".into(),
                "remote-epoch".into(),
            )
            .await
            .unwrap();
        let params = f.change();
        let first = f
            .network()
            .kura_request(
                "network.kura.prepare".into(),
                params.clone(),
                "same-kura-id".into(),
                vec!["test0".into()],
            )
            .await
            .unwrap();
        let second = f
            .network()
            .kura_request(
                "network.kura.prepare".into(),
                params,
                "same-kura-id".into(),
                vec!["test0".into()],
            )
            .await
            .unwrap();
        assert_eq!(first, second);
        assert_ne!(first["id"], remote["id"]);
    }

    #[tokio::test]
    async fn unsupported_confirmed_fields_are_read_only_and_cannot_be_dropped() {
        let f = Fixture::new();
        let yaml = serde_yaml::to_string(&json!({"network":{"version":2,"ethernets":{"test0":{
            "dhcp4":true,"dhcp4-overrides":{"use-dns":false},"ipv6-privacy":true
        }}}}))
        .unwrap();
        atomic(
            &f.root.join("state/confirmed.json"),
            &serde_json::to_vec(&Confirmed {
                revision: 1,
                yaml: Some(yaml.clone()),
            })
            .unwrap(),
        )
        .unwrap();
        atomic(&f.root.join("etc/netplan").join(FILE), yaml.as_bytes()).unwrap();
        let view = f.call("network.kura.view", Value::Null).await.unwrap();
        assert_eq!(view["configurations"][0]["writable"], false);
        assert_eq!(view["configurations"][0]["preserved"]["ipv6-privacy"], true);
        assert_eq!(
            error_code(
                &f.call("network.kura.prepare", f.change())
                    .await
                    .unwrap_err()
            ),
            "UNSUPPORTED"
        );
        assert!(f.network().1.journal().unwrap().is_none());
        assert_eq!(
            fs::read_to_string(f.root.join("etc/netplan").join(FILE)).unwrap(),
            yaml
        );
    }

    #[tokio::test]
    async fn unsupported_authentication_is_not_mirrored_into_kura_snapshots() {
        let f = Fixture::new();
        let yaml = serde_yaml::to_string(&json!({"network":{"version":2,"ethernets":{"test0":{
            "dhcp4":true,"auth":{"password":"fixture-private-password"}
        }}}}))
        .unwrap();
        atomic(
            &f.root.join("state/confirmed.json"),
            &serde_json::to_vec(&Confirmed {
                revision: 1,
                yaml: Some(yaml),
            })
            .unwrap(),
        )
        .unwrap();
        let view = f.call("network.kura.view", Value::Null).await.unwrap();
        assert!(!view.to_string().contains("fixture-private-password"));
        assert_eq!(view["configurations"][0]["unmappedFields"], json!(["auth"]));
        assert_eq!(
            view["configurations"][0]["preservedDigest"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(view["configurations"][0]["writable"], false);
    }
}
