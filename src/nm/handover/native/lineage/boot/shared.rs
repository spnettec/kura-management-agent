//! A shared boot matches the foreign owner's independently restored objects and
//! inserts only the original typed rules at fresh physical anchors.
use super::*;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SharedRestore {
    pub baseline_sha256: String,
    pub batch_sha256: String,
}

fn require_foreign_rule(
    previous: &Snapshot, observed: &Snapshot, key: &Chain, old: &Value, new: &Value,
) -> Result<u64> {
    let old_id = handle(old)?;
    let new_id = handle(new)?;
    let old_payload = previous.payloads.get(&(key.clone(), old_id)).context("CONFLICT: retained foreign rule lacks raw evidence")?;
    let new_payload = observed.payloads.get(&(key.clone(), new_id)).context("CONFLICT: live foreign rule lacks raw evidence")?;
    ensure!(without_handle(old) == without_handle(new) && raw::same_semantics(old_payload, new_payload)?,
        "CONFLICT: restored foreign rule differs from its original order or raw expression");
    Ok(new_id)
}

impl Image {
    fn require_shared_declarations(&self, baseline: &Snapshot) -> Result<()> {
        let mut observed = Vec::new();
        for entry in &baseline.objects {
            let (kind, value) = entry.as_object().unwrap().iter().next().unwrap();
            handle(value).context("CONFLICT: shared boot declaration lacks physical identity")?;
            observed.push(json!({kind:without_handle(value)}));
        }
        observed.sort_by_key(Value::to_string);
        ensure!(observed == self.declarations,
            "CONFLICT: independently restored shared firewall declarations differ from the original baseline");
        Ok(())
    }

    pub(super) fn shared_batch(&self, previous: &Snapshot, baseline: &Snapshot) -> Result<Value> {
        self.require_shared_declarations(baseline)?;
        ensure!(baseline.rules.values().map(Vec::len).sum::<usize>() == self.foreign_rule_count,
            "CONFLICT: independently restored shared firewall does not have the original foreign rules");
        let mut commands = Vec::new();
        for (key, rows) in &previous.rules {
            let managed = self.managed.get(key);
            let mut foreign = baseline.rules.get(key).into_iter().flatten();
            let mut pending = Vec::new();
            for row in rows {
                let id = handle(row)?;
                if let Some(rule) = managed.and_then(|rules| rules.get(&id)) {
                    pending.push(rule.clone());
                } else {
                    let actual = foreign.next().context("CONFLICT: restored foreign rule missing from its original chain")?;
                    let anchor = require_foreign_rule(previous, baseline, key, row, actual)?;
                    for mut rule in pending.drain(..) {
                        rule["handle"] = json!(anchor);
                        commands.push(json!({"insert":{"rule":rule}}));
                    }
                }
            }
            ensure!(foreign.next().is_none(), "CONFLICT: extra independently restored foreign rule in a shared chain");
            commands.extend(pending.into_iter().map(|rule| json!({"add":{"rule":rule}})));
        }
        ensure!(commands.len() == self.rule_count, "CONFLICT: shared boot does not cover the complete original managed selection");
        Ok(json!({"expectedGeneration":baseline.generation.context("CONFLICT: shared boot baseline generation missing")?,"nftables":commands}))
    }

    pub(super) fn shared_readback(
        &self, previous: &Snapshot, observed: &Snapshot, generation: u32, proof: &SharedRestore,
    ) -> Result<BTreeMap<Chain, Vec<u64>>> {
        self.require_shared_declarations(observed)?;
        ensure!(previous.rules.keys().eq(observed.rules.keys()), "CONFLICT: shared boot readback rule chains differ from the original layout");
        let mut baseline = Snapshot {
            objects: observed.objects.clone(), rules: BTreeMap::new(), fingerprints: BTreeMap::new(),
            payloads: BTreeMap::new(), generation: Some(generation),
        };
        let mut selected = BTreeMap::new();
        for (key, old_rows) in &previous.rules {
            let actual_rows = &observed.rules[key];
            ensure!(actual_rows.len() == old_rows.len(), "CONFLICT: shared boot changed the original rule cardinality");
            let managed = self.managed.get(key);
            for (old, actual) in old_rows.iter().zip(actual_rows) {
                let original_handle = handle(old)?;
                if let Some(expected) = managed.and_then(|rules| rules.get(&original_handle)) {
                    let actual_handle = handle(actual)?;
                    let mut metadata = without_handle(actual);
                    metadata.as_object_mut().unwrap().remove("expr");
                    let mut expected_metadata = expected.clone();
                    expected_metadata.as_object_mut().unwrap().remove("expr");
                    ensure!(metadata == expected_metadata && raw::matcher::replacement_matches(
                        &observed.payloads[&(key.clone(), actual_handle)], expected)?,
                        "CONFLICT: shared boot managed rule differs from its exact model or position");
                    selected.entry(key.clone()).or_insert_with(Vec::new).push(actual_handle);
                } else {
                    let actual_handle = require_foreign_rule(previous, observed, key, old, actual)?;
                    let identity = (key.clone(), actual_handle);
                    baseline.rules.entry(key.clone()).or_default().push(actual.clone());
                    baseline.fingerprints.insert(identity.clone(), observed.fingerprints[&identity].clone());
                    baseline.payloads.insert(identity.clone(), observed.payloads[&identity].clone());
                }
            }
        }
        // The semantic comparisons pair across epochs. These two digests also
        // prove that the foreign physical objects survived this dispatch.
        ensure!(baseline.digest()? == proof.baseline_sha256,
            "CONFLICT: shared boot mutated the originally witnessed foreign baseline");
        ensure!(digest(&self.shared_batch(previous, &baseline)?)? == proof.batch_sha256,
            "CONFLICT: shared boot readback differs from the original dispatched batch");
        Ok(selected)
    }
}
