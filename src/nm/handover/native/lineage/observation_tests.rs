//! Synthetic complete-netlink evidence contracts;no live owner grant or kernel effects.
use super::*;

fn current() -> (CurrentSource, Value, epoch::Epoch, uuid::Uuid) {
    let (transfer, mut native, policy, prefixes) = initial();
    let name = transfer.names().0;
    for entry in native["nftables"].as_array_mut().unwrap() {
        if entry["table"]["family"] == "inet" && entry["table"]["name"] == name {
            entry["table"]["handle"] = json!(500_001);
        }
    }
    let mut current = CurrentSource::from_acknowledged(
        &"b".repeat(64),
        1,
        policy,
        prefixes,
        &transfer,
        &native,
        false,
    )
    .unwrap();
    let physical_epoch = epoch::Epoch::storage_fixture();
    current.bind_epoch(Some(physical_epoch.clone())).unwrap();
    (current, native, physical_epoch, transfer.operation_id)
}

fn foreign_change(native: &Value) -> Value {
    let mut changed = native.clone();
    let rule = json!({"family":"inet","table":"nm-foreign","chain":"traffic","handle":8,
        "expr":[{"counter":{"packets":19,"bytes":200}},{"accept":null}]});
    let payload = emitted_payload(&rule);
    changed["ruleFingerprints"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::to_value(raw::fixture_fingerprint(&payload)).unwrap());
    changed["nftables"].as_array_mut().unwrap().extend([
        json!({"table":{"family":"inet","name":"nm-foreign","handle":700_001}}),
        json!({"chain":{"family":"inet","table":"nm-foreign","name":"traffic","handle":1}}),
        json!({"rule":rule}),
    ]);
    changed["kernelGeneration"] = json!(native["kernelGeneration"].as_u64().unwrap() + 7);
    changed
}

#[test]
fn foreign_observation_advances_only_physical_source_and_preserves_strict_update_fence() {
    let (current, native, physical_epoch, _) = current();
    let witness = current.witness().unwrap();
    let changed = foreign_change(&native);
    assert!(current.require_native(&changed).is_err());
    let plan = current
        .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &changed)
        .unwrap();
    assert_eq!(plan.parameters().unwrap()["kernelEffect"], false);
    let next = plan.settled_source(&current).unwrap();
    assert_eq!(next.revision, current.revision);
    assert_eq!(next.policy, current.policy);
    assert_eq!(next.prefixes, current.prefixes);
    assert!(next.selected == current.selected);
    assert!(next.epoch == current.epoch);
    assert_eq!(next.receipt_tables, current.receipt_tables);
    assert_ne!(next.receipt, current.receipt);
    assert_eq!(current.witness().unwrap(), witness);
    next.require_native(&changed).unwrap();
    assert!(next.require_native(&native).is_err());
    plan.require_native(&changed).unwrap();
    assert!(plan.require_native(&native).is_err());
    assert!(
        !serde_json::to_string(&plan)
            .unwrap()
            .contains("transferIdentity")
    );
}

#[test]
fn foreign_base_chain_rules_are_never_claimed_or_deleted_by_the_next_strict_delta() {
    let (current, native, physical_epoch, _) = current();
    let mut changed = native.clone();
    let row = json!({"family":"ip","table":"filter","chain":"INPUT","handle":900_001,
        "expr":[{"counter":{"packets":0,"bytes":0}},{"accept":null}]});
    let payload = emitted_payload(&row);
    changed["ruleFingerprints"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::to_value(raw::fixture_fingerprint(&payload)).unwrap());
    let entries = changed["nftables"].as_array_mut().unwrap();
    let at = entries
        .iter()
        .position(|v| {
            v["rule"]["family"] == "ip"
                && v["rule"]["table"] == "filter"
                && v["rule"]["chain"] == "INPUT"
        })
        .unwrap();
    entries.insert(at, json!({"rule":row}));
    changed["kernelGeneration"] = json!(native["kernelGeneration"].as_u64().unwrap() + 1);
    let next = current
        .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &changed)
        .unwrap()
        .settled_source(&current)
        .unwrap();
    assert!(!next.selected.values().flatten().any(|id| *id == 900_001));
    let mut policy = next.policy.clone();
    policy["ipv4"]["inputPolicy"] = json!("accept");
    let update = next
        .plan(uuid::Uuid::new_v4(), policy, next.prefixes.clone())
        .unwrap();
    let batch = update.batch(&changed, false).unwrap();
    assert!(
        batch["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["delete"]["rule"]["handle"] != 900_001)
    );
    assert_eq!(batch["expectedGeneration"], changed["kernelGeneration"]);
}

#[test]
fn epoch_mismatch_legacy_provenance_noop_and_reused_native_identity_cannot_observe() {
    let (current, native, physical_epoch, original_id) = current();
    let changed = foreign_change(&native);
    let mut legacy = current.clone();
    legacy.epoch = None;
    assert!(
        legacy
            .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &changed)
            .is_err()
    );
    assert!(
        current
            .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &native)
            .is_err()
    );
    assert!(
        current
            .observe_source(uuid::Uuid::nil(), &physical_epoch, &changed)
            .is_err()
    );
    assert!(
        current
            .observe_source(original_id, &physical_epoch, &changed)
            .is_err()
    );
    let mut wrong = serde_json::to_value(&physical_epoch).unwrap();
    wrong["bootId"] = json!(uuid::Uuid::new_v4());
    let wrong: epoch::Epoch = serde_json::from_value(wrong).unwrap();
    assert!(
        current
            .observe_source(uuid::Uuid::new_v4(), &wrong, &changed)
            .is_err()
    );
    let plan = current
        .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &changed)
        .unwrap();
    assert!(plan.require_epoch(&wrong).is_err());
}

#[test]
fn protected_declarations_handles_and_receipts_cannot_be_recreated_or_modified() {
    let (current, native, physical_epoch, _) = current();
    for kind in [
        "table",
        "chain",
        "receipt",
        "missing-receipt",
        "receipt-child",
    ] {
        let mut changed = foreign_change(&native);
        let receipt = current.receipt_tables.first().unwrap();
        if kind == "missing-receipt" {
            changed["nftables"]
                .as_array_mut()
                .unwrap()
                .retain(|v| v["table"]["name"] != *receipt);
        } else if kind == "receipt-child" {
            changed["nftables"].as_array_mut().unwrap().push(
                json!({"chain":{"family":"inet","table":receipt,"name":"injected","handle":3}}),
            );
        } else {
            let entry = changed["nftables"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|v| match kind {
                    "table" => v["table"]["family"] == "ip" && v["table"]["name"] == "filter",
                    "chain" => {
                        v["chain"]["family"] == "ip"
                            && v["chain"]["table"] == "filter"
                            && v["chain"]["name"] == "INPUT"
                    }
                    _ => v["table"]["name"] == *receipt,
                })
                .unwrap();
            let body = if kind == "chain" {
                &mut entry["chain"]
            } else {
                &mut entry["table"]
            };
            body["handle"] = json!(800_001);
        }
        assert!(
            current
                .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &changed)
                .is_err(),
            "{kind}"
        );
    }
}

#[test]
fn owned_rule_order_raw_payload_and_loss_are_not_foreign_drift() {
    let (current, native, physical_epoch, _) = current();
    let (key, ids) = current.selected.iter().find(|(_, v)| v.len() > 1).unwrap();
    for kind in ["order", "missing", "opaque-raw", "metadata"] {
        let mut changed = foreign_change(&native);
        let matches = |v: &Value| {
            v["rule"]["family"] == key.family
                && v["rule"]["table"] == key.table
                && v["rule"]["chain"] == key.name
        };
        if kind == "order" {
            let rows = changed["nftables"].as_array_mut().unwrap();
            let first = rows
                .iter()
                .position(|v| matches(v) && v["rule"]["handle"] == ids[0])
                .unwrap();
            let second = rows
                .iter()
                .position(|v| matches(v) && v["rule"]["handle"] == ids[1])
                .unwrap();
            rows.swap(first, second);
        } else if kind == "missing" {
            changed["nftables"]
                .as_array_mut()
                .unwrap()
                .retain(|v| !(matches(v) && v["rule"]["handle"] == ids[0]));
            changed["ruleFingerprints"]
                .as_array_mut()
                .unwrap()
                .retain(|v| {
                    !(v["family"] == key.family && v["table"] == key.table && v["handle"] == ids[0])
                });
        } else if kind == "metadata" {
            let row = changed["nftables"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|v| matches(v) && v["rule"]["handle"] == ids[0])
                .unwrap();
            row["rule"]["comment"] = json!("same handle,changed metadata");
        } else {
            let fp = changed["ruleFingerprints"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|v| {
                    v["family"] == key.family
                        && v["table"] == key.table
                        && v["chain"] == key.name
                        && v["handle"] == ids[0]
                })
                .unwrap();
            let mut bytes = raw::decode(fp["payloadHex"].as_str().unwrap()).unwrap();
            bytes.extend(attribute(31, &[1, 2, 3, 4]));
            let payload = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            *fp = serde_json::to_value(raw::fixture_fingerprint(&payload)).unwrap();
        }
        assert!(
            current
                .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &changed)
                .is_err(),
            "{kind}"
        );
    }
}

#[test]
fn traffic_counters_remain_normalized_and_missing_raw_or_generation_never_passes() {
    let (current, native, physical_epoch, _) = current();
    let mut changed = foreign_change(&native);
    for entry in changed["nftables"].as_array_mut().unwrap() {
        if let Some(terms) = entry
            .get_mut("rule")
            .and_then(|v| v.get_mut("expr"))
            .and_then(Value::as_array_mut)
        {
            for term in terms {
                if term.get("counter").is_some() {
                    term["counter"]["packets"] = json!(1000);
                    term["counter"]["bytes"] = json!(32000);
                }
            }
        }
    }
    current
        .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &changed)
        .unwrap();
    for field in ["kernelGeneration", "payloadHex"] {
        let mut gap = changed.clone();
        if field == "kernelGeneration" {
            gap.as_object_mut().unwrap().remove(field);
        } else {
            gap["ruleFingerprints"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
        }
        assert!(
            current
                .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &gap)
                .is_err()
        );
    }
}

#[test]
fn receipt_registry_is_derived_from_ack_history_and_never_claims_a_foreign_lookalike() {
    let (current, native, physical_epoch, _) = current();
    let mut changed = foreign_change(&native);
    let foreign = format!("yofc_fwt_{}", uuid::Uuid::new_v4().simple());
    changed["nftables"].as_array_mut().unwrap().push(json!({"table":{"family":"inet","name":foreign,"handle":700_002,"comment":"yofc native forward lookalike"}}));
    let next = current
        .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &changed)
        .unwrap()
        .settled_source(&current)
        .unwrap();
    assert!(!next.receipt_tables.contains(&foreign));
    for v in changed["nftables"].as_array_mut().unwrap() {
        if v["table"]["name"] == foreign {
            v["table"]["comment"] = json!("still foreign");
        }
    }
    changed["kernelGeneration"] = json!(changed["kernelGeneration"].as_u64().unwrap() + 1);
    next.observe_source(uuid::Uuid::new_v4(), &physical_epoch, &changed)
        .unwrap();
    let mut policy = current.policy.clone();
    policy["ipv4"]["inputPolicy"] = json!("accept");
    let update = current
        .plan(uuid::Uuid::new_v4(), policy, current.prefixes.clone())
        .unwrap();
    for inverse in [false, true] {
        let mut outcome = outcome(&update.transfer, inverse);
        let name = if inverse {
            update.transfer.names().1
        } else {
            update.transfer.names().0
        };
        for v in outcome["nftables"].as_array_mut().unwrap() {
            if v["table"]["name"] == name {
                v["table"]["handle"] = json!(500_002);
            }
        }
        let settled = update.settled_source(&current, &outcome, inverse).unwrap();
        assert_eq!(settled.receipt_tables.len(), 2);
        let mut observed = foreign_change(&outcome);
        for v in observed["nftables"].as_array_mut().unwrap() {
            if current
                .receipt_tables
                .contains(v["table"]["name"].as_str().unwrap_or(""))
            {
                v["table"]["comment"] = json!("changed old receipt");
            }
        }
        assert!(
            settled
                .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &observed)
                .is_err()
        );
    }
}

#[test]
fn persisted_observation_cannot_change_parent_revision_anchor_or_add_fields() {
    let (current, native, physical_epoch, _) = current();
    let changed = foreign_change(&native);
    let plan = current
        .observe_source(uuid::Uuid::new_v4(), &physical_epoch, &changed)
        .unwrap();
    assert!(
        current
            .decode_observation(&serde_json::to_vec(&plan).unwrap())
            .unwrap()
            == plan
    );
    for key in [
        "revision",
        "sourceReceiptSha256",
        "initializationReceiptSha256",
        "unexpected",
    ] {
        let mut altered = serde_json::to_value(&plan).unwrap();
        altered[key] = json!("untrusted");
        assert!(
            current
                .decode_observation(&serde_json::to_vec(&altered).unwrap())
                .is_err(),
            "{key}"
        );
    }
}
