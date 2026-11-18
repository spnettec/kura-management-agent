//! Physical current-source witnesses and original-layout ordinary update plans.
//! A witness is derived from an acknowledged, already authorized Transfer. It is
//! never an owner lease or a replacement for the firewall transaction journal.
use super::*;

type Prefixes = BTreeMap<String, Vec<u8>>;

#[derive(Clone)]
pub(in crate::nm) struct CurrentSource {
    anchor: String,
    revision: u64,
    policy: Value,
    prefixes: Prefixes,
    snapshot: Snapshot,
    selected: BTreeMap<Chain, Vec<u64>>,
    receipt: String,
    epoch: Option<epoch::Epoch>,
    // Derived only from acknowledged native operations,never from table-name patterns.
    receipt_tables: BTreeSet<String>,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm) struct UpdatePlan {
    initialization_receipt_sha256: String,
    source_receipt_sha256: String,
    base_revision: u64,
    target_revision: u64,
    candidate: Value,
    destination_prefixes: Prefixes,
    draft_sha256: String,
    transfer: Transfer,
}

fn compiled(policy: &Value, prefixes: &Prefixes) -> Result<BTreeMap<Chain, Vec<Vec<Value>>>> {
    let draft = crate::firewall::original_layout_draft(policy, policy, prefixes, prefixes)?;
    let mut groups = BTreeMap::new();
    for (family, native) in [("ipv4", "ip"), ("ipv6", "ip6")] {
        let view = classify::compiled_layout(native, &draft["families"][family]["layout"])?;
        for group in view["groups"]
            .as_array()
            .context("CONFLICT: compiled original groups")?
        {
            let key: Chain = serde_json::from_value(group["chain"].clone())?;
            let expressions: Vec<Vec<Value>> =
                serde_json::from_value(group["expressions"].clone())?;
            ensure!(
                groups.insert(key, expressions).is_none(),
                "CONFLICT: duplicate original group"
            );
        }
    }
    Ok(groups)
}

fn counter_count(rule: &Value) -> Result<usize> {
    Ok(rule["expr"]
        .as_array()
        .context("CONFLICT: original counter source")?
        .iter()
        .filter(|v| v.get("counter").is_some())
        .count())
}
fn with_counters(mut expression: Vec<Value>, count: usize) -> Result<Vec<Value>> {
    let at = expression
        .len()
        .checked_sub(1)
        .context("CONFLICT: empty original expression")?;
    for _ in 0..count {
        expression.insert(at, json!({"counter":{"packets":0,"bytes":0}}));
    }
    Ok(expression)
}

impl CurrentSource {
    pub(in crate::nm::handover) fn bind_epoch(&mut self, epoch: Option<epoch::Epoch>) -> Result<()> {
        ensure!(self.epoch.is_none(), "CONFLICT: current native physical epoch is already bound");
        if let Some(value) = &epoch { value.validate()?; }
        self.epoch = epoch;
        Ok(())
    }
    pub(in crate::nm) fn require_epoch(&self, actual: &epoch::Epoch) -> Result<()> {
        self.epoch.as_ref()
            .context("UNSUPPORTED: imported source has no original physical epoch;separate lawful restore required")?
            .require(actual)
    }
    pub(in crate::nm) fn decode_plan(&self, bytes: &[u8]) -> Result<UpdatePlan> {
        let claimed: Value =
            serde_json::from_slice(bytes).context("CONFLICT: imported update plan encoding")?;
        let id = serde_json::from_value(claimed["transfer"]["operationId"].clone())
            .context("CONFLICT: imported update operation")?;
        let prefixes = serde_json::from_value(claimed["destinationPrefixes"].clone())
            .context("CONFLICT: imported update destination prefixes")?;
        let actual = self.plan(id, claimed["candidate"].clone(), prefixes)?;
        ensure!(
            claimed == serde_json::to_value(&actual)?,
            "CONFLICT: imported update plan differs from its actual parent source"
        );
        Ok(actual)
    }
    pub(in crate::nm) fn require_native(&self, value: &Value) -> Result<()> {
        let source = Snapshot::read(&canonical_source(value)?)?;
        ensure!(
            source.digest()? == self.snapshot.digest()?,
            "CONFLICT: imported current native source changed"
        );
        Ok(())
    }
    pub(in crate::nm) fn witness(&self) -> Result<Value> {
        let layout = crate::firewall::original_layout_draft(
            &self.policy,
            &self.policy,
            &self.prefixes,
            &self.prefixes,
        )?;
        Ok(
            json!({"revision":self.revision.to_string(),"sourceDigest":self.receipt,"semanticDigest":self.snapshot.digest()?,
            "currentPolicy":self.policy,"currentDestinationPrefixes":self.prefixes,"currentLayouts":layout["families"]}),
        )
    }
    /// The caller supplies logical metadata from the original initialization or
    /// a settled SAME-domain transaction. Kernel evidence is always adjudicated
    /// here; caller JSON, matching chain names or an old revision cannot seed it.
    pub(in crate::nm) fn from_acknowledged(
        anchor: &str,
        revision: u64,
        policy: Value,
        prefixes: Prefixes,
        transfer: &Transfer,
        observed: &Value,
        inverse: bool,
    ) -> Result<Self> {
        ensure!(
            hex(anchor, 64) && revision > 0,
            "CONFLICT: original current-source anchor"
        );
        let acknowledged = transfer.acknowledge(observed, inverse)?;
        let snapshot = Snapshot::read(&canonical_source(observed)?)?;
        let source = Snapshot::read(&transfer.original)?;
        let identity = transfer.identity()?;
        let mut selected = BTreeMap::new();
        for (index, change) in transfer.rules.iter().enumerate() {
            let expected = if inverse {
                source
                    .rules
                    .get(&change.chain)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|row| {
                        let owned = change.original.contains(&row["handle"].as_u64().unwrap());
                        (row, owned)
                    })
                    .collect()
            } else {
                transfer.expected_rules(&source, index, &identity)?
            };
            let actual = snapshot
                .rules
                .get(&change.chain)
                .cloned()
                .unwrap_or_default();
            ensure!(
                expected.len() == actual.len(),
                "CONFLICT: acknowledged original selection shape"
            );
            let owned = expected
                .iter()
                .zip(&actual)
                .filter(|((_, owned), _)| *owned)
                .map(|(_, row)| handle(row))
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                selected.insert(change.chain.clone(), owned).is_none(),
                "CONFLICT: duplicate acknowledged original chain"
            );
        }
        let receipt = digest(
            &json!({"schemaVersion":1,"domain":"nft.imported.current-source.v1","initializationReceiptSha256":anchor,
            "revision":revision,"policy":policy,"destinationPrefixes":prefixes,"transferIdentity":identity,"inverse":inverse,
            "acknowledgedSemanticSha256":acknowledged,"nativeSourceSha256":snapshot.digest()?,
            "selected":selected.iter().map(|(chain,handles)|json!({"chain":chain,"handles":handles})).collect::<Vec<_>>()}),
        )?;
        let current = Self {
            anchor: anchor.into(),
            revision,
            policy,
            prefixes,
            snapshot,
            selected,
            receipt,
            epoch: None,
            receipt_tables: BTreeSet::from([if inverse {
                transfer.names().1
            } else {
                transfer.names().0
            }]),
        };
        current.require_model()?;
        Ok(current)
    }

    fn require_model(&self) -> Result<()> {
        let model = compiled(&self.policy, &self.prefixes)?;
        ensure!(
            model.keys().eq(self.selected.keys()),
            "CONFLICT: original provenance does not cover the complete model"
        );
        for (key, expressions) in &model {
            let handles = &self.selected[key];
            ensure!(
                handles.len() == expressions.len(),
                "CONFLICT: acknowledged original model rule count"
            );
            let rows = self
                .snapshot
                .rules
                .get(key)
                .context("CONFLICT: acknowledged original chain absent")?;
            for (id, expression) in handles.iter().zip(expressions) {
                let row = rows
                    .iter()
                    .find(|row| row["handle"].as_u64() == Some(*id))
                    .context("CONFLICT: acknowledged original handle absent")?;
                let expression = with_counters(expression.clone(), counter_count(row)?)?;
                ensure!(
                    raw::matcher::model_matches(
                        &self.snapshot.payloads[&(key.clone(), *id)],
                        &key.family,
                        &json!(expression)
                    )?,
                    "CONFLICT: acknowledged original model predicates or counter conditions changed"
                );
            }
        }
        for (family, native) in [("ipv4", "ip"), ("ipv6", "ip6")] {
            for (name, field) in [
                ("INPUT", "inputPolicy"),
                ("FORWARD", "forwardPolicy"),
                ("OUTPUT", "outputPolicy"),
            ] {
                let chain = self.snapshot.find_chain(&Chain {
                    family: native.into(),
                    table: "filter".into(),
                    name: name.into(),
                })?;
                ensure!(
                    chain["policy"] == self.policy[family][field],
                    "CONFLICT: acknowledged original base policy changed"
                );
            }
        }
        Ok(())
    }

    pub(in crate::nm) fn plan(
        &self,
        operation_id: uuid::Uuid,
        candidate: Value,
        prefixes: Prefixes,
    ) -> Result<UpdatePlan> {
        ensure!(
            !operation_id.is_nil(),
            "INVALID_ARGUMENT: explicit original update operation required"
        );
        let target_revision = self
            .revision
            .checked_add(1)
            .context("RESOURCE_EXHAUSTED: original firewall revision")?;
        let draft = crate::firewall::original_layout_draft(
            &self.policy,
            &candidate,
            &self.prefixes,
            &prefixes,
        )?;
        let next = compiled(&candidate, &prefixes)?;
        ensure!(
            next.keys().eq(self.selected.keys()),
            "UNSUPPORTED: original layout declarations cannot change"
        );
        let mut rules = Vec::new();
        for (key, expressions) in next {
            let owned = &self.selected[&key];
            let rows = &self.snapshot.rules[&key];
            ensure!(
                !owned.is_empty(),
                "UNSUPPORTED: original empty provenance requires an authenticated insertion anchor"
            );
            let profile = owned
                .iter()
                .map(|id| {
                    counter_count(
                        rows.iter()
                            .find(|v| v["handle"].as_u64() == Some(*id))
                            .unwrap(),
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            let replacement = expressions
                .into_iter()
                .enumerate()
                .map(|(i, expr)| with_counters(expr, profile[i.min(profile.len() - 1)]))
                .collect::<Result<Vec<_>>>()?;
            rules.push(Rules {
                chain: key,
                original: owned.clone(),
                before: None,
                replacement,
            });
        }
        let mut policies = Vec::new();
        for (family, native) in [("ipv4", "ip"), ("ipv6", "ip6")] {
            for (name, field) in [
                ("INPUT", "inputPolicy"),
                ("FORWARD", "forwardPolicy"),
                ("OUTPUT", "outputPolicy"),
            ] {
                if candidate[family][field] != self.policy[family][field] {
                    policies.push(Policy {
                        chain: Chain {
                            family: native.into(),
                            table: "filter".into(),
                            name: name.into(),
                        },
                        value: candidate[family][field]
                            .as_str()
                            .context("CONFLICT: original target policy")?
                            .into(),
                    });
                }
            }
        }
        let transfer = Transfer {
            operation_id,
            source_digest: self.receipt.clone(),
            source_model_sha256: None,
            original: factory::canonical_source(&self.snapshot),
            rules,
            policies,
        };
        transfer.validate()?;
        transfer.batch(&transfer.original, false)?;
        Ok(UpdatePlan {
            initialization_receipt_sha256: self.anchor.clone(),
            source_receipt_sha256: self.receipt.clone(),
            base_revision: self.revision,
            target_revision,
            candidate,
            destination_prefixes: prefixes,
            draft_sha256: digest(&draft)?,
            transfer,
        })
    }
}

impl UpdatePlan {
    /// Encodes only the original-bound forward/inverse delta. No dispatch here.
    pub(in crate::nm) fn batch(&self, kernel: &Value, inverse: bool) -> Result<Value> {
        let batch = self.transfer.batch(kernel, inverse)?;
        raw::writer::encode(&batch)?;
        Ok(batch)
    }
    pub(in crate::nm) fn original_native(&self) -> &Value {
        &self.transfer.original
    }
    /// Capacity review only. These sizes are not kernel outcomes or ACKs. The
    /// source objects and foreign rules are retained; owned rows reserve native
    /// dump JSON, full raw payload hex and maximum-width counters/handles.
    pub(in crate::nm) fn evidence_bounds(&self) -> Result<(usize, usize)> {
        let original = Snapshot::read(&self.transfer.original)?;
        let identity = self.transfer.identity()?;
        let bound = |inverse: bool| -> Result<usize> {
            let mut objects = original.objects.clone();
            if !inverse {
                for policy in &self.transfer.policies {
                    for entry in &mut objects {
                        if entry.get("chain").is_some_and(|c| {
                            c["family"] == policy.chain.family
                                && c["table"] == policy.chain.table
                                && c["name"] == policy.chain.name
                        }) {
                            entry["chain"]["policy"] = json!(policy.value);
                        }
                    }
                }
            }
            let mut receipt = self.transfer.receipt_for(inverse, &identity);
            receipt["table"]["handle"] = json!(u64::MAX);
            objects.push(receipt);
            let mut size = serde_json::to_vec(&objects)?.len() + 256;
            for (key, rows) in &original.rules {
                let group = self
                    .transfer
                    .rules
                    .iter()
                    .position(|change| &change.chain == key);
                let expected = if let Some(group) = group {
                    if inverse {
                        rows.iter()
                            .map(|row| {
                                (
                                    row.clone(),
                                    self.transfer.rules[group]
                                        .original
                                        .contains(&row["handle"].as_u64().unwrap()),
                                )
                            })
                            .collect()
                    } else {
                        self.transfer.expected_rules(&original, group, &identity)?
                    }
                } else {
                    rows.iter().map(|row| (row.clone(), false)).collect()
                };
                for (mut row, owned) in expected {
                    let old_handle = handle(&row).ok();
                    if owned {
                        row["handle"] = json!(u64::MAX);
                    }
                    if let Some(terms) = row["expr"].as_array_mut() {
                        for term in terms {
                            if let Some(counter) =
                                term.get_mut("counter").and_then(Value::as_object_mut)
                            {
                                for field in ["packets", "bytes"] {
                                    counter.insert(field.into(), json!(u64::MAX));
                                }
                            }
                        }
                    }
                    let raw_bytes = if owned && !inverse {
                        let mut emitted = without_handle(&row);
                        emitted.as_object_mut().unwrap().remove("originalRawRule");
                        let (wire, _) = raw::writer::encode(
                            &json!({"expectedGeneration":1,"nftables":[{"add":{"rule":emitted}}]}),
                        )?;
                        let begin = u32::from_ne_bytes(wire[..4].try_into().unwrap()) as usize;
                        let at = (begin + 3) & !3;
                        let rule_bytes =
                            u32::from_ne_bytes(wire[at..at + 4].try_into().unwrap()) as usize;
                        // Strip netlink framing; GETRULE adds a u64 handle NLA.
                        rule_bytes
                            .checked_sub(16)
                            .and_then(|v| v.checked_add(12))
                            .context("CONFLICT: original one-rule wire size")?
                    } else {
                        original.payloads[&(
                            key.clone(),
                            old_handle.context("CONFLICT: original reserve handle")?,
                        )]
                            .len()
                            / 2
                    };
                    let fingerprint = json!({"family":key.family,"table":key.table,"chain":key.name,
                        "handle":if owned{u64::MAX}else{old_handle.unwrap()},"sha256":"f".repeat(64),"payloadHex":"0".repeat(raw_bytes*2)});
                    let json_bytes = serde_json::to_vec(&json!({"rule":row}))?.len();
                    // Owned JSON expression spelling may differ from the model
                    // while matching the exact emitted raw predicates. Reserve
                    // per-row expansion instead of multiplying the whole batch,
                    // which double-counts preserved source and inverse raw hex.
                    let row_bytes = if owned {
                        json_bytes.max(raw_bytes * 4 + 256)
                    } else {
                        json_bytes
                    };
                    size = size
                        .checked_add(row_bytes + serde_json::to_vec(&fingerprint)?.len() + 2)
                        .context("RESOURCE_EXHAUSTED: native evidence reserve")?;
                }
            }
            Ok(size)
        };
        Ok((bound(false)?, bound(true)?))
    }

    pub(in crate::nm) fn acknowledge(&self, kernel: &Value, inverse: bool) -> Result<String> {
        self.transfer.acknowledge(kernel, inverse)
    }
    pub(in crate::nm) fn settled_source(
        &self,
        parent: &CurrentSource,
        kernel: &Value,
        inverse: bool,
    ) -> Result<CurrentSource> {
        ensure!(
            self.initialization_receipt_sha256 == parent.anchor
                && self.source_receipt_sha256 == parent.receipt
                && self.base_revision == parent.revision
                && parent.revision.checked_add(1) == Some(self.target_revision),
            "CONFLICT: imported plan has a different parent source"
        );
        let (revision, policy, prefixes) = if inverse {
            (
                parent.revision,
                parent.policy.clone(),
                parent.prefixes.clone(),
            )
        } else {
            (
                self.target_revision,
                self.candidate.clone(),
                self.destination_prefixes.clone(),
            )
        };
        let mut current = CurrentSource::from_acknowledged(
            &parent.anchor,
            revision,
            policy,
            prefixes,
            &self.transfer,
            kernel,
            inverse,
        )?;
        current.bind_epoch(parent.epoch.clone())?;
        current.receipt_tables.extend(parent.receipt_tables.iter().cloned());
        Ok(current)
    }
    pub(in crate::nm) fn parameters(&self) -> Result<Value> {
        let batch = self.transfer.batch(&self.transfer.original, false)?;
        let (wire, _) = raw::writer::encode(&batch)?;
        Ok(
            json!({"schemaVersion":1,"reviewKind":"nft.imported.update.plan.v1","operationId":self.transfer.operation_id,
            "initializationReceiptSha256":self.initialization_receipt_sha256,"sourceReceiptSha256":self.source_receipt_sha256,
            "baseRevision":self.base_revision,"targetRevision":self.target_revision,"sourceGeneration":self.transfer.original["kernelGeneration"],
            "sourceBindingSha256":self.transfer.source_binding()?,"transferSha256":digest(&serde_json::to_value(&self.transfer)?)?,
            "draftSha256":self.draft_sha256,"forwardBatchSha256":digest(&batch)?,"wirePreflightBytes":wire.len(),
            "selectedRuleCount":self.transfer.rules.iter().map(|g|g.original.len()).sum::<usize>(),
            "targetRuleCount":self.transfer.rules.iter().map(|g|g.replacement.len()).sum::<usize>(),"policyChanges":self.transfer.policies.len(),
            "preservesOriginalLayout":true,"dispatched":false,"applyReady":false,"writeEnabled":false,
            "requiredAuthority":"SAME_FIREWALL_TRANSACTION_AND_CURRENT_CORE_NM_LEASE"}),
        )
    }
}

#[cfg(test)]
pub(in crate::nm) mod tests;

mod observation;
pub(in crate::nm) use observation::ObservationPlan;
mod boot;

#[cfg(all(test, target_os = "linux"))]
mod kernel_tests;
