//! Deterministic netlink-payload contracts, not an operating-kernel acceptance.
use super::*;

#[path = "observation_tests.rs"]
mod source_observation;

fn initial() -> (Transfer, Value, Value, Prefixes) {
    let corpus: Value =
        serde_json::from_str(include_str!("../../../fixtures/rich-raw-corpus-v35.json")).unwrap();
    let exchange = &corpus["exchange"];
    let roles =
        roles::Observation::new(uuid::Uuid::new_v4(), 71, exchange["roles"].clone()).unwrap();
    let mut model = exchange["origin"].clone();
    for i in 0..2 {
        model["families"][i]["runtimeNatRuleTypes"] = json!(["IP_FORWARDING", "PORT_FORWARDING"]);
        model["modelRules"]["nat"][i * 2 + 1]["ruleType"] = json!("PORT_FORWARDING");
    }
    model["families"][0]["runtimePortForwardDestinationPrefixes"] = json!([24]);
    model["families"][1]["runtimePortForwardDestinationPrefixes"] = json!([64]);
    let origin = roles::Origin::new(
        roles.agent_instance,
        roles.bridge_epoch,
        &roles,
        model.clone(),
    )
    .unwrap();
    let transfer = factory::Reviewed::new(&"a".repeat(64), &origin, &roles, &corpus["source"])
        .unwrap()
        .bind(uuid::Uuid::new_v4())
        .unwrap();
    let kernel = outcome_tests::forward(&transfer);
    let mut policy = model["modelRules"].clone();
    policy["schemaVersion"] = json!(4);
    for family in model["families"].as_array().unwrap() {
        let key = family["family"].as_str().unwrap();
        let native = if key == "ipv4" { "ip" } else { "ip6" };
        policy[key] = json!({"allowIcmp":family["allowIcmp"]});
        for (name, field) in [
            ("INPUT", "inputPolicy"),
            ("FORWARD", "forwardPolicy"),
            ("OUTPUT", "outputPolicy"),
        ] {
            policy[key][field] = kernel["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|v| v.get("chain"))
                .find(|c| c["family"] == native && c["table"] == "filter" && c["name"] == name)
                .unwrap()["policy"]
                .clone();
        }
        for row in family["automaticNat"].as_array().unwrap() {
            policy["nat"].as_array_mut().unwrap().push(json!({"family":key,"inputInterface":row["sourceInterface"],"outputInterface":row["destinationInterface"],"masquerade":row["masquerade"],"automatic":true}));
        }
    }
    (
        transfer,
        kernel,
        policy,
        BTreeMap::from([("ipv4".into(), vec![24]), ("ipv6".into(), vec![64])]),
    )
}

fn replace_handle(payload: &str, id: u64) -> String {
    let bytes = raw::decode(payload).unwrap();
    let mut result = bytes[..4].to_vec();
    let handle = id.to_be_bytes();
    for (kind, data) in attrs(&bytes[4..]) {
        result.extend(attribute(
            kind,
            if kind & 0x3fff == 3 { &handle } else { data },
        ));
    }
    result.iter().map(|b| format!("{b:02x}")).collect()
}

fn attribute(kind: u16, body: &[u8]) -> Vec<u8> {
    let length = body.len() + 4;
    let mut value = Vec::with_capacity((length + 3) & !3);
    value.extend((length as u16).to_ne_bytes());
    value.extend(kind.to_ne_bytes());
    value.extend(body);
    value.resize((length + 3) & !3, 0);
    value
}

fn attrs(mut bytes: &[u8]) -> Vec<(u16, &[u8])> {
    let mut rows = Vec::new();
    while !bytes.is_empty() {
        assert!(bytes.len() >= 4);
        let size = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;
        assert!(size >= 4 && size <= bytes.len());
        let padded = (size + 3) & !3;
        assert!(padded <= bytes.len());
        rows.push((
            u16::from_ne_bytes(bytes[2..4].try_into().unwrap()),
            &bytes[4..size],
        ));
        bytes = &bytes[padded..];
    }
    rows
}

fn emitted_payload(row: &Value) -> String {
    let mut emitted = row.clone();
    emitted.as_object_mut().unwrap().remove("handle");
    let (wire, _) =
        raw::writer::encode(&json!({"expectedGeneration":1,"nftables":[{"add":{"rule":emitted}}]}))
            .unwrap();
    let first = u32::from_ne_bytes(wire[..4].try_into().unwrap()) as usize;
    let end = first + u32::from_ne_bytes(wire[first..first + 4].try_into().unwrap()) as usize;
    let body = &wire[first + 16..end];
    let mut result = body[..4].to_vec();
    // Creation compat context is validated by the kernel but is not a dump
    // attribute. Everything else, including user data and guards, is retained.
    for (kind, data) in attrs(&body[4..]) {
        if ![3, 5, 6, 8].contains(&(kind & 0x3fff)) {
            result.extend(attribute(kind, data));
        }
    }
    result.extend(attribute(3, &row["handle"].as_u64().unwrap().to_be_bytes()));
    result.iter().map(|b| format!("{b:02x}")).collect()
}

pub(in crate::nm) fn outcome(transfer: &Transfer, inverse: bool) -> Value {
    let original = Snapshot::read(&transfer.original).unwrap();
    let mut objects = original.objects.clone();
    let identity = transfer.identity().unwrap();
    if !inverse {
        for policy in &transfer.policies {
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
    objects.push(transfer.receipt(inverse).unwrap());
    let mut fingerprints = Vec::new();
    let mut next = 100_000;
    for (key, rows) in &original.rules {
        let change = transfer.rules.iter().position(|r| &r.chain == key);
        let desired = match change {
            Some(index) if !inverse => transfer
                .expected_rules(&original, index, &identity)
                .unwrap(),
            Some(index) => rows
                .iter()
                .map(|row| {
                    (
                        row.clone(),
                        transfer.rules[index]
                            .original
                            .contains(&row["handle"].as_u64().unwrap()),
                    )
                })
                .collect(),
            None => rows.iter().map(|row| (row.clone(), false)).collect(),
        };
        for (mut row, owned) in desired {
            let old_id = row["handle"].as_u64();
            let payload = if owned {
                next += 1;
                row["handle"] = json!(next);
                if inverse {
                    replace_handle(&original.payloads[&(key.clone(), old_id.unwrap())], next)
                } else {
                    emitted_payload(&row)
                }
            } else {
                original.payloads[&(key.clone(), old_id.unwrap())].clone()
            };
            fingerprints.push(serde_json::to_value(raw::fixture_fingerprint(&payload)).unwrap());
            objects.push(json!({"rule":row}));
        }
    }
    let first = next_generation(original.generation.unwrap());
    json!({"nftables":objects,"ruleFingerprints":fingerprints,"kernelGeneration":if inverse{next_generation(first)}else{first}})
}

#[test]
fn original_update_plan_is_provenance_handle_generation_and_full_layout_bound() {
    let (initial, kernel, before, prefixes) = initial();
    let current = CurrentSource::from_acknowledged(
        &"b".repeat(64),
        1,
        before.clone(),
        prefixes.clone(),
        &initial,
        &kernel,
        false,
    )
    .unwrap();
    let mut next = before.clone();
    next["ipv4"]["inputPolicy"] = json!("accept");
    next["input"] = json!([]);
    next["portForward"][0]["outPort"] = json!(2451);
    let mut desired = prefixes.clone();
    desired.insert("ipv4".into(), vec![32]);
    let id = uuid::Uuid::new_v4();
    let plan = current.plan(id, next, desired).unwrap();
    let parameters = plan.parameters().unwrap();
    assert_eq!(parameters["baseRevision"], 1);
    assert_eq!(parameters["targetRevision"], 2);
    assert_eq!(parameters["selectedRuleCount"], 144);
    assert_eq!(parameters["policyChanges"], 1);
    assert_eq!(parameters["applyReady"], false);
    assert_eq!(parameters["dispatched"], false);
    assert!(parameters["targetRuleCount"].as_u64().unwrap() < 144);
    let batch = plan.transfer.batch(&kernel, false).unwrap();
    assert_eq!(batch["expectedGeneration"], kernel["kernelGeneration"]);
    assert!(
        batch["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v.get("flush").is_none() && v.get("rename").is_none())
    );
    assert!(
        plan.transfer
            .rules
            .iter()
            .all(|r| r.chain.family == "ip" || r.chain.family == "ip6")
    );
    let mut stale = kernel.clone();
    stale["kernelGeneration"] = json!(999);
    assert!(plan.transfer.batch(&stale, false).is_err());
    assert!(
        current
            .plan(initial.operation_id, before.clone(), prefixes.clone())
            .is_err(),
        "original operation receipt must not be reused"
    );
    assert!(current.plan(uuid::Uuid::nil(), before, prefixes).is_err());
}

#[test]
fn actual_wire_outcomes_advance_physical_source_after_confirm_and_rollback_without_resetting_the_anchor()
 {
    let (initial, kernel, before, prefixes) = initial();
    let anchor = "b".repeat(64);
    let current = CurrentSource::from_acknowledged(
        &anchor,
        1,
        before.clone(),
        prefixes.clone(),
        &initial,
        &kernel,
        false,
    )
    .unwrap();
    let mut candidate = before.clone();
    candidate["input"] = json!([]);
    candidate["ipv6"]["allowIcmp"] = json!(false);
    let plan = current
        .plan(uuid::Uuid::new_v4(), candidate.clone(), prefixes.clone())
        .unwrap();
    let forward = outcome(&plan.transfer, false);
    assert!(plan.transfer.acknowledge(&forward, false).is_ok());
    let committed = CurrentSource::from_acknowledged(
        &anchor,
        2,
        candidate.clone(),
        prefixes.clone(),
        &plan.transfer,
        &forward,
        false,
    )
    .unwrap();
    assert_eq!(committed.anchor, current.anchor);
    assert_ne!(committed.receipt, current.receipt);
    let next = committed
        .plan(uuid::Uuid::new_v4(), before.clone(), prefixes.clone())
        .unwrap();
    assert_eq!(next.base_revision, 2);
    assert_eq!(
        next.transfer.original["kernelGeneration"],
        forward["kernelGeneration"]
    );
    let inverse = outcome(&plan.transfer, true);
    assert!(plan.transfer.batch(&forward, true).is_ok());
    assert!(plan.transfer.acknowledge(&inverse, true).is_ok());
    let rolled_back = CurrentSource::from_acknowledged(
        &anchor,
        1,
        before.clone(),
        prefixes.clone(),
        &plan.transfer,
        &inverse,
        true,
    )
    .unwrap();
    assert_eq!(rolled_back.revision, current.revision);
    assert_eq!(rolled_back.policy, current.policy);
    assert_ne!(rolled_back.receipt, current.receipt);
    assert_ne!(rolled_back.snapshot.generation, current.snapshot.generation);
    assert!(rolled_back.selected != current.selected);
    let after_rollback = rolled_back
        .plan(uuid::Uuid::new_v4(), before, prefixes)
        .unwrap();
    assert_eq!(after_rollback.base_revision, 1);
    assert_ne!(
        after_rollback.source_receipt_sha256,
        plan.source_receipt_sha256
    );
    assert!(
        plan.transfer.batch(&inverse, false).is_err(),
        "same logical revision never authorizes replay of the old batch"
    );
}

#[test]
fn current_source_rejects_named_lookalikes_raw_gaps_changed_policy_and_wrong_original_outcome() {
    let (initial, kernel, before, prefixes) = initial();
    let anchor = "b".repeat(64);
    let check = |value: &Value| {
        CurrentSource::from_acknowledged(
            &anchor,
            1,
            before.clone(),
            prefixes.clone(),
            &initial,
            value,
            false,
        )
        .is_err()
    };
    assert!(check(&initial.original));
    let mut wrong = kernel.clone();
    wrong["kernelGeneration"] = initial.original["kernelGeneration"].clone();
    assert!(check(&wrong));
    let mut missing = kernel.clone();
    missing["ruleFingerprints"][0]
        .as_object_mut()
        .unwrap()
        .remove("payloadHex");
    assert!(check(&missing));
    let mut foreign = kernel.clone();
    foreign["nftables"]
        .as_array_mut()
        .unwrap()
        .push(json!({"table":{"family":"inet","name":"foreign-drift"}}));
    assert!(check(&foreign));
    let mut lookalike = kernel.clone();
    for row in lookalike["nftables"].as_array_mut().unwrap() {
        if let Some(rule) = row.get_mut("rule") {
            rule.as_object_mut().unwrap().remove("comment");
        }
    }
    assert!(check(&lookalike));
    let mut changed = before;
    changed["portForward"][0]["outPort"] = json!(9999);
    assert!(
        CurrentSource::from_acknowledged(&anchor, 1, changed, prefixes, &initial, &kernel, false)
            .is_err()
    );
}

#[test]
fn prefix_intent_automatic_ownership_and_revision_are_bound_without_modifying_the_initial_source() {
    let (initial, kernel, before, prefixes) = initial();
    let original = serde_json::to_value(&initial).unwrap();
    let source = kernel.clone();
    let anchor = "b".repeat(64);
    let current = CurrentSource::from_acknowledged(
        &anchor,
        1,
        before.clone(),
        prefixes.clone(),
        &initial,
        &kernel,
        false,
    )
    .unwrap();
    let id = uuid::Uuid::new_v4();
    let unchanged = current.plan(id, before.clone(), prefixes.clone()).unwrap();
    let mut altered = prefixes.clone();
    altered.insert("ipv4".into(), vec![32]);
    let changed = current.plan(id, before.clone(), altered).unwrap();
    assert_ne!(
        unchanged.parameters().unwrap()["transferSha256"],
        changed.parameters().unwrap()["transferSha256"]
    );
    let mut lost = prefixes.clone();
    lost.remove("ipv6");
    assert!(current.plan(id, before.clone(), lost).is_err());
    let mut automatic = before.clone();
    automatic["nat"]
        .as_array_mut()
        .unwrap()
        .retain(|row| row["automatic"] != true);
    assert!(current.plan(id, automatic, prefixes.clone()).is_err());
    let overflow = CurrentSource::from_acknowledged(
        &anchor,
        u64::MAX,
        before.clone(),
        prefixes.clone(),
        &initial,
        &kernel,
        false,
    )
    .unwrap();
    assert!(overflow.plan(id, before, prefixes).is_err());
    assert_eq!(kernel, source);
    assert_eq!(serde_json::to_value(initial).unwrap(), original);
}
