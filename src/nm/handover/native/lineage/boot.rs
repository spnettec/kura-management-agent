//! Check that the acknowledged imported snapshot contains a complete restore
//! image. A new boot uses typed rules and never creates old transfer receipts.
use super::*;
mod shared;
pub(crate) use shared::SharedRestore;

struct Image {
    commands: Vec<Value>,
    table_count: usize,
    chain_count: usize,
    rule_count: usize,
    foreign_rule_count: usize,
    declarations: Vec<Value>,
    managed: BTreeMap<Chain, BTreeMap<u64, Value>>,
    shared: bool,
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
        ensure!(expected.iter().all(|value| observed.contains(value)),
            "CONFLICT: original imported boot declarations differ from the typed model");
        let foreign_declarations = observed != expected;

        let model = compiled(&current.policy, &current.prefixes)?;
        let mut rule_count = 0;
        let mut foreign_rule_count = 0;
        let mut managed = BTreeMap::new();
        for (key, rows) in &current.snapshot.rules {
            let selected = current.selected.get(key).map(Vec::as_slice).unwrap_or_default();
            let mut expressions = model.get(key).into_iter().flatten();
            for row in rows {
                let id = handle(row)?;
                if !selected.contains(&id) {
                    foreign_rule_count += 1;
                    continue;
                }
                let expression = expressions.next().context("CONFLICT: original imported boot model order")?;
                let mut rule = without_handle(row);
                rule["expr"] = json!(with_counters(expression.clone(), counter_count(row)?)?);
                if rule["comment"].as_str().is_some_and(|comment| historical_tag(comment, &retired_tags)) {
                    rule.as_object_mut().unwrap().remove("comment");
                }
                // The raw writer validates the remaining field set, including comments.
                commands.push(json!({"add":{"rule":rule}}));
                managed.entry(key.clone()).or_insert_with(BTreeMap::new).insert(id, rule);
                rule_count += 1;
            }
        }
        Ok(Self { commands, table_count, chain_count, rule_count, foreign_rule_count,
            declarations: observed, managed, shared: foreign_declarations || foreign_rule_count != 0 })
    }

    fn batch(&self, generation: u32) -> Value {
        json!({"nftables":self.commands,"expectedGeneration":generation})
    }
}

pub(crate) struct PreparedBoot {
    batch: Value,
    pub generation: u32,
    pub shared: Option<SharedRestore>,
}

impl PreparedBoot {
    pub(crate) fn dispatch(self, deadline: std::time::Instant) -> Result<()> {
        raw::writer::dispatch(&self.batch, deadline)
    }
}

pub(crate) struct BootImage {
    source: CurrentSource,
    image: Image,
    image_sha256: String,
}

impl BootImage {
    pub(in crate::nm) fn new(source: CurrentSource) -> Result<Self> {
        let image = Image::new(&source)?;
        // Keep the original exclusive image digest for existing receipts.
        let image_sha256 = if image.shared {
            digest(&json!({"kind":"shared","source":source.receipt,"managedImage":image.commands}))?
        } else { digest(&json!(image.commands))? };
        Ok(Self { source, image, image_sha256 })
    }

    pub(crate) fn revision(&self) -> u64 { self.source.revision }
    pub(crate) fn source_sha256(&self) -> &str { &self.source.receipt }
    pub(crate) fn initialization_sha256(&self) -> &str { &self.source.anchor }
    pub(crate) fn image_sha256(&self) -> &str { &self.image_sha256 }

    pub(crate) fn forwarding_families(&self) -> Result<(bool, bool)> {
        crate::firewall::original_forwarding_families(&self.source.policy)
    }

    pub(crate) fn require_new_epoch(&self, boot: uuid::Uuid, device: u64, inode: u64) -> Result<()> {
        let epoch = self.source.epoch.as_ref().context("CONFLICT: original imported firewall epoch missing")?;
        ensure!(!epoch.identifies(boot, device, inode), "FORBIDDEN: imported restore requires a new physical epoch");
        Ok(())
    }

    pub(crate) fn observe(read: impl FnOnce() -> Result<Value>, deadline: std::time::Instant) -> Result<Value> {
        raw::observe(read, deadline)
    }

    pub(crate) fn prepare(&self, observed: &Value) -> Result<PreparedBoot> {
        let observed = Snapshot::read(observed)?;
        let generation = observed.generation.context("CONFLICT: imported boot generation missing")?;
        let (batch, shared) = if self.image.shared {
            let batch = self.image.shared_batch(&self.source.snapshot, &observed)?;
            let proof = SharedRestore { baseline_sha256: observed.digest()?, batch_sha256: digest(&batch)? };
            (batch, Some(proof))
        } else {
            ensure!(observed.objects.is_empty() && observed.rules.is_empty(),
                "FORBIDDEN: exclusive imported boot requires an empty network namespace");
            (self.image.batch(generation), None)
        };
        raw::writer::encode(&batch)?;
        Ok(PreparedBoot { batch, generation, shared })
    }

    pub(crate) fn readback(&self, observed: &Value, generation: u32, shared: Option<&SharedRestore>) -> Result<Value> {
        let (canonical, _) = self.check_restored(observed, generation, shared)?;
        Ok(canonical)
    }

    fn check_restored(&self, observed: &Value, generation: u32, shared: Option<&SharedRestore>) -> Result<(Value, CurrentSource)> {
        let mut rebound = self.source.clone();
        let canonical = canonical_source(observed)?;
        let observed = Snapshot::read(&canonical)?;
        ensure!(observed.generation == Some(next_generation(generation)),
            "CONFLICT: imported boot readback is outside its committed generation");
        ensure!(self.image.shared == shared.is_some(), "CONFLICT: imported boot receipt restore mode differs from its parent");
        rebound.selected = if let Some(shared) = shared {
            self.image.shared_readback(&self.source.snapshot, &observed, generation, shared)?
        } else {
            observed.rules.iter().map(|(key, rows)| {
                Ok((key.clone(), rows.iter().map(handle).collect::<Result<Vec<_>>>()?))
            }).collect::<Result<_>>()?
        };
        rebound.receipt_tables.clear();
        rebound.snapshot = observed;
        if shared.is_none() {
            ensure!(Image::new(&rebound)?.commands == self.image.commands,
                "CONFLICT: imported boot readback differs from the exact restore image");
        } else {
            rebound.require_model()?;
        }
        Ok((canonical, rebound))
    }

    pub(in crate::nm) fn rebound(&self, receipt: &crate::firewall::ImportedBootReceipt, receipt_sha256: &str) -> Result<CurrentSource> {
        ensure!(self.initialization_sha256() == receipt.initialization_sha256
            && self.source_sha256() == receipt.source_sha256 && self.revision() == receipt.revision
            && self.image_sha256() == receipt.image_sha256 && hex(receipt_sha256, 64),
            "CONFLICT: imported boot receipt differs from its settled parent policy");
        self.require_new_epoch(receipt.boot_id, receipt.net_device, receipt.net_inode)?;
        let (_, mut current) = self.check_restored(&receipt.readback, receipt.expected_generation, receipt.shared.as_ref())?;
        let epoch = epoch::Epoch::from_boot_receipt(receipt.boot_id, receipt.net_device, receipt.net_inode)?;
        current.receipt = digest(&json!({"schemaVersion":1,"domain":"nft.imported.boot-source.v1",
            "previousSourceSha256":self.source_sha256(),"earlyBootReceiptSha256":receipt_sha256,
            "physicalEpoch":epoch,"kernelSourceSha256":current.snapshot.digest()?}))?;
        current.epoch = Some(epoch);
        Ok(current)
    }

    pub(in crate::nm) fn review(&self) -> Result<Value> {
        // Wire bounds only. Execution uses the live, witnessed generation.
        let (wire, _) = raw::writer::encode(&self.image.batch(1))?;
        Ok(json!({"schemaVersion":1,"sourceKind":"nft.imported.boot.review.v1",
            "initializationReceiptSha256":self.initialization_sha256(),"sourceReceiptSha256":self.source_sha256(),"revision":self.revision(),
            "logicalRestoreImageSha256":self.image_sha256(),"tables":self.image.table_count,
            "chains":self.image.chain_count,"rules":self.image.rule_count,"wirePreflightBytes":wire.len(),"dispatched":false,
            "requiresExternalBaseline":self.image.shared,"foreignRules":self.image.foreign_rule_count}))
    }
}

pub(crate) fn validate_boot_readback(readback: &Value, generation: u32) -> Result<()> {
    ensure!(readback["kernelGeneration"] == next_generation(generation)
        && canonical_source(readback)? == *readback,
        "CONFLICT: imported boot receipt lacks canonical committed kernel evidence");
    Ok(())
}

#[cfg(test)]
impl CurrentSource {
    fn review_boot(&self) -> Result<Value> { BootImage::new(self.clone())?.review() }
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
    fn imported_boot_requires_the_independent_shared_baseline_and_keeps_typed_declarations() {
        let shared = current(true, false);
        let review = shared.review_boot().unwrap();
        assert_eq!(review["requiresExternalBaseline"], true);
        assert_eq!(review["foreignRules"], 2);
        assert!(BootImage::new(shared).unwrap().prepare(&json!({"kernelGeneration":9,"nftables":[],"ruleFingerprints":[]}))
            .err().unwrap().to_string().contains("restored shared firewall declarations differ"));
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
            match defect {
                "priority" | "device" => assert!(altered.review_boot().unwrap_err().to_string().contains("declarations differ from the typed model"), "{defect}"),
                _ => assert_eq!(altered.review_boot().unwrap()["requiresExternalBaseline"], true, "{defect}"),
            }
        }
    }

    #[test]
    fn imported_shared_plan_requires_the_raw_foreign_witness_and_uses_only_new_anchors() {
        let mut source = current(true, false);
        let ip = Chain { family:"ip".into(),table:"filter".into(),name:"input-kura".into() };
        let rows = source.snapshot.rules.get_mut(&ip).unwrap();
        let foreign = rows.remove(0);
        assert_eq!(foreign["handle"], 35);
        rows.insert(2, foreign);
        let mut baseline = source.snapshot.clone();
        baseline.generation = Some(41);
        baseline.objects.retain(|entry| !entry["table"]["name"].as_str().is_some_and(|name| source.receipt_tables.contains(name)));
        baseline.rules.retain(|key, rows| {
            rows.retain(|row| !source.selected.get(key).is_some_and(|list| list.contains(&handle(row).unwrap())));
            !rows.is_empty()
        });
        baseline.fingerprints.retain(|(key,id), _| baseline.rules.get(key).is_some_and(|rows| rows.iter().any(|r| r["handle"] == *id)));
        baseline.payloads.retain(|key, _| baseline.fingerprints.contains_key(key));
        let old = (ip.clone(),35);
        let new = (ip.clone(),1035);
        let renumbered = super::super::tests::replace_handle(&baseline.payloads.remove(&old).unwrap(),1035);
        baseline.rules.get_mut(&ip).unwrap()[0]["handle"] = json!(1035);
        baseline.fingerprints.remove(&old);
        baseline.fingerprints.insert(new.clone(), raw::fixture_fingerprint(&renumbered).sha256);
        baseline.payloads.insert(new, renumbered);
        let image = BootImage::new(source).unwrap();
        let plan = image.prepare(&factory::canonical_source(&baseline)).unwrap();
        assert_eq!(plan.generation, 41);
        assert_eq!(plan.shared.as_ref().unwrap().baseline_sha256, baseline.digest().unwrap());
        let rules = plan.batch["nftables"].as_array().unwrap();
        assert_eq!(rules.len(),144);
        assert!(rules.iter().all(|cmd| cmd["add"]["rule"].is_object() || cmd["insert"]["rule"].is_object()));
        assert_eq!(rules.iter().filter(|cmd| cmd["insert"]["rule"]["handle"] == 1035).count(), 2);

        let identity = baseline.payloads.keys().next().unwrap().clone();
        let mut bytes = raw::decode(&baseline.payloads[&identity]).unwrap();
        bytes.extend(super::super::tests::attribute(11, &[0,0,0,1]));
        let changed = bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let fingerprint = raw::fixture_fingerprint(&changed);
        baseline.payloads.insert(identity.clone(), changed);
        baseline.fingerprints.insert(identity, fingerprint.sha256);
        assert!(image.prepare(&factory::canonical_source(&baseline)).err().unwrap().to_string().contains("raw expression"));
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
