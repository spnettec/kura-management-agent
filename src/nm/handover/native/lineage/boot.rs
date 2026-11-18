//! Check that the acknowledged imported snapshot contains a complete restore
//! image. A new boot uses typed rules and never creates old transfer receipts.
use super::*;

struct Image {
    commands: Vec<Value>,
    table_count: usize,
    chain_count: usize,
    rule_count: usize,
}

fn declaration(key: &Chain, policy: Option<&str>) -> Result<Value> {
    let mut value = json!({"family":key.family,"table":key.table,"name":key.name});
    if let Some(policy) = policy {
        let hook = key.name.to_ascii_lowercase();
        let (kind, priority) = match (key.table.as_str(), hook.as_str()) {
            ("filter", "input" | "output" | "forward") => ("filter", 0),
            ("nat", "prerouting" | "output") => ("nat", -100),
            ("nat", "input" | "postrouting") => ("nat", 100),
            ("mangle", "output") => ("route", -150),
            ("mangle", "prerouting" | "input" | "forward" | "postrouting") => ("filter", -150),
            _ => anyhow::bail!("UNSUPPORTED: imported boot base chain"),
        };
        let policy = match policy {
            "ACCEPT" => "accept",
            "DROP" => "drop",
            _ => anyhow::bail!("UNSUPPORTED: imported boot base policy"),
        };
        value["type"] = json!(kind);
        value["hook"] = json!(hook);
        value["prio"] = json!(priority);
        value["policy"] = json!(policy);
    }
    Ok(value)
}

fn historical_tag(comment: &str, identities: &BTreeSet<&str>) -> bool {
    let Some(text) = comment.strip_prefix("yofc-t-") else {
        return false;
    };
    let mut fields = text.split('-');
    fields.next().is_some_and(|hash| identities.contains(hash))
        && fields.next().is_some_and(|group| group.parse::<usize>().is_ok())
        && fields.next().is_some_and(|index| index.parse::<usize>().is_ok())
        && fields.next().is_none()
}

impl Image {
    fn new(current: &CurrentSource) -> Result<Self> {
        ensure!(current.epoch.is_some(), "UNSUPPORTED: imported boot requires original physical epoch evidence");
        current.require_model()?;
        let draft = crate::firewall::original_layout_draft(
            &current.policy,
            &current.policy,
            &current.prefixes,
            &current.prefixes,
        )?;
        let mut expected = Vec::new();
        let mut commands = Vec::new();
        let mut table_count = 0;
        let mut chain_count = 0;
        for (family, native) in [("ipv4", "ip"), ("ipv6", "ip6")] {
            let layout = &draft["families"][family]["layout"];
            for table in layout["tables"].as_array().context("CONFLICT: original boot tables")? {
                let name = table["name"].as_str().context("CONFLICT: original boot table identity")?;
                let table_object = json!({"table":{"family":native,"name":name}});
                commands.push(json!({"create":table_object}));
                expected.push(table_object);
                table_count += 1;
                for chain in table["chains"].as_array().context("CONFLICT: original boot chains")? {
                    let key = Chain {
                        family: native.into(),
                        table: name.into(),
                        name: chain["name"].as_str().context("CONFLICT: original boot chain identity")?.into(),
                    };
                    let object = json!({"chain":declaration(&key, chain["policy"].as_str())?});
                    commands.push(json!({"add":object}));
                    expected.push(object);
                    chain_count += 1;
                }
            }
        }

        let mut observed = Vec::new();
        let mut retired_tags = BTreeSet::new();
        for entry in &current.snapshot.objects {
            let (kind, value) = entry.as_object().unwrap().iter().next().unwrap();
            if kind == "table" && value["family"] == "inet"
                && value["name"].as_str().is_some_and(|name| current.receipt_tables.contains(name))
            {
                let identity = value["comment"].as_str().and_then(|comment|
                    comment.strip_prefix("yofc native forward ")
                        .or_else(|| comment.strip_prefix("yofc native inverse ")))
                    .filter(|identity| hex(identity, 64))
                    .context("CONFLICT: original imported transfer receipt comment")?;
                retired_tags.insert(identity);
                continue;
            }
            handle(value).context("CONFLICT: original declaration has no physical identity")?;
            observed.push(json!({kind:without_handle(value)}));
        }
        expected.sort_by_key(Value::to_string);
        observed.sort_by_key(Value::to_string);
        ensure!(observed == expected,
            "UNSUPPORTED: original imported boot has unowned or non-model declarations; their owner must supply a separate baseline");

        let model = compiled(&current.policy, &current.prefixes)?;
        let mut rule_count = 0;
        for (key, rows) in &current.snapshot.rules {
            let selected = current.selected.get(key).context("UNSUPPORTED: original imported boot has rules outside the typed model")?;
            let handles = rows.iter().map(handle).collect::<Result<Vec<_>>>()?;
            ensure!(&handles == selected,
                "UNSUPPORTED: original imported boot has unowned rules in a shared chain; their owner must supply a separate baseline");
            for (row, expression) in rows.iter().zip(&model[key]) {
                let mut rule = without_handle(row);
                rule["expr"] = json!(with_counters(expression.clone(), counter_count(row)?)?);
                if rule["comment"].as_str().is_some_and(|comment| historical_tag(comment, &retired_tags)) {
                    rule.as_object_mut().unwrap().remove("comment");
                }
                // The raw writer validates the remaining field set, including comments.
                commands.push(json!({"add":{"rule":rule}}));
                rule_count += 1;
            }
        }
        Ok(Self { commands, table_count, chain_count, rule_count })
    }

    fn batch(&self, generation: u32) -> Value {
        json!({"nftables":self.commands,"expectedGeneration":generation})
    }
}

impl CurrentSource {
    pub(in crate::nm) fn review_boot(&self) -> Result<Value> {
        let image = Image::new(self)?;
        // A future restore binds the live kernel generation before any dispatch.
        // The placeholder is used only for bounded wire validation here.
        let (wire, _) = raw::writer::encode(&image.batch(1))?;
        Ok(json!({"schemaVersion":1,"sourceKind":"nft.imported.boot.review.v1",
            "initializationReceiptSha256":self.anchor,"sourceReceiptSha256":self.receipt,"revision":self.revision,
            "logicalRestoreImageSha256":digest(&json!(image.commands))?,"tables":image.table_count,
            "chains":image.chain_count,"rules":image.rule_count,"wirePreflightBytes":wire.len(),"dispatched":false}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current(shared: bool, ipv6_output_drop: bool) -> CurrentSource {
        let (transfer, observed, policy, prefixes) = super::super::tests::boot_source(shared, ipv6_output_drop);
        let mut current = CurrentSource::from_acknowledged(&"e".repeat(64), 1, policy, prefixes,
            &transfer, &observed, false).unwrap();
        current.bind_epoch(Some(epoch::Epoch::storage_fixture())).unwrap();
        current
    }

    #[test]
    fn imported_boot_image_constructs_original_policies_and_jumps_without_historical_receipts() {
        let current = current(false, false);
        let image = Image::new(&current).unwrap();
        let review = current.review_boot().unwrap();
        assert_eq!(review["tables"], 6);
        assert_eq!(review["chains"], 58);
        assert_eq!(review["rules"], 144);
        assert_eq!(review["dispatched"], false);
        let commands = serde_json::to_string(&image.commands).unwrap();
        assert!(!commands.contains("yofc_fwt_") && !commands.contains("yofc-t-") && !commands.contains("handle"));
        assert_eq!(image.commands.iter().filter(|v| v["add"]["chain"]["type"] == "route").count(), 2);
        assert_eq!(current.review_boot().unwrap(), review);
    }

    #[test]
    fn imported_boot_refuses_shared_or_drifted_layouts_and_unbound_physical_history() {
        let shared = current(true, false);
        assert!(shared.review_boot().unwrap_err().to_string().contains("unowned rules in a shared chain"));
        let base = current(false, false);
        let mut no_epoch = base.clone();
        no_epoch.epoch = None;
        assert!(no_epoch.review_boot().unwrap_err().to_string().contains("original physical epoch"));
        for defect in ["priority", "device", "unknown-table", "unknown-chain", "named-set"] {
            let mut altered = base.clone();
            let objects = &mut altered.snapshot.objects;
            let input = objects.iter_mut().find(|entry| entry["chain"]["name"] == "INPUT"
                && entry["chain"]["family"] == "ip" && entry["chain"]["table"] == "filter").unwrap();
            match defect {
                "priority" => input["chain"]["prio"] = json!(-9),
                "device" => input["chain"]["dev"] = json!("eth0"),
                "unknown-table" => objects.push(json!({"table":{"family":"inet","name":"operator","handle":981}})),
                "unknown-chain" => objects.push(json!({"chain":{"family":"ip","table":"filter","name":"operator","handle":982}})),
                "named-set" => objects.push(json!({"set":{"family":"ip","table":"filter","name":"allowed","handle":983,"elem":[]}})),
                _ => unreachable!(),
            }
            assert!(altered.review_boot().unwrap_err().to_string().contains("unowned or non-model declarations"), "{defect}");
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "requires a fresh disposable Linux namespace and distinct output-drop policy fixture"]
    fn imported_boot_image_kernel_output_drop_roundtrip() {
        use std::time::{Duration, Instant};
        let proof = Path::new("/proof/imported-boot-image-output-drop");
        assert_eq!(fs::read(proof.join("owned")).unwrap(), b"fresh disposable imported boot image with IPv6 output drop\n");
        let original = current(false, true);
        let image = Image::new(&original).unwrap();
        let read = || raw::observe(|| {
            let result = crate::process::run(Path::new("/usr/sbin/nft"),
                &["-j", "-p", "list", "ruleset"], None, Duration::from_secs(10))?;
            ensure!(result.status.success(), "fixture imported kernel observation failed");
            Ok(serde_json::from_slice(&result.stdout)?)
        }, Instant::now() + Duration::from_secs(10)).unwrap();
        let before = Snapshot::read(&read()).unwrap();
        assert!(before.objects.is_empty() && before.rules.is_empty());
        let generation = before.generation.unwrap();
        durable::publish_new(&proof.join("intent"), digest(&image.batch(generation)).unwrap().as_bytes(), FileMetadata::private()).unwrap();
        raw::writer::dispatch(&image.batch(generation), Instant::now() + Duration::from_secs(10)).unwrap();
        let after = Snapshot::read(&read()).unwrap();
        assert_eq!(after.generation, Some(next_generation(generation)));
        let mut rebuilt = original.clone();
        rebuilt.selected = after.rules.iter().map(|(key, rows)|
            (key.clone(), rows.iter().map(|row| handle(row).unwrap()).collect())).collect();
        rebuilt.snapshot = after;
        rebuilt.receipt_tables.clear();
        // Readback through the same ownership/model grammar requires both families,
        // exact base hooks and policies, and the full ordered native payloads.
        let rebuilt_image = Image::new(&rebuilt).unwrap();
        assert_eq!(image.commands, rebuilt_image.commands);
        assert_eq!(rebuilt.snapshot.find_chain(&Chain {family:"ip6".into(),table:"filter".into(),name:"OUTPUT".into()}).unwrap()["policy"], "drop");
        let report = json!({"tables":image.table_count,"chains":image.chain_count,"rules":image.rule_count,
            "kernelGenerationBefore":generation,"kernelGenerationAfter":rebuilt.snapshot.generation,
            "batchSha256":digest(&image.batch(generation)).unwrap(),"syntheticSource":true});
        durable::publish_new(&proof.join("result.json"), &serde_json::to_vec(&report).unwrap(), FileMetadata::private()).unwrap();
        println!("{report}");
    }
}
