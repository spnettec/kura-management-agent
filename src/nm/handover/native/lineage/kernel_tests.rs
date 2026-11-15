//! A fresh owned namespace only. Logical initialization/registration is synthetic;
//! the Java model, native reader, raw writer, kernel ACK and inverse are actual.
use super::*;
use std::time::{Duration, Instant};

#[test]
#[ignore = "V42 fresh original-layout native update/inverse namespace;NET_ADMIN;never replay retained fixture"]
fn original_layout_update_inverse_kernel_v42() {
    let root = PathBuf::from(std::env::var("YOFC_ORIGINAL_UPDATE_V42_ROOT").unwrap());
    assert!(root.join(".owned-original-update-v42").is_file());
    durable::publish_new(
        &root.join("invoked"),
        b"single original-layout V42 kernel contract",
        FileMetadata::private(),
    )
    .unwrap();
    let save = |name: &str, value: &Value| {
        durable::publish_new(
            &root.join(name),
            &serde_json::to_vec(value).unwrap(),
            FileMetadata::private(),
        )
        .unwrap()
    };
    let read = || {
        raw::observe(
            || {
                let result = crate::process::run(
                    Path::new("/usr/sbin/nft"),
                    &["-j", "-p", "list", "ruleset"],
                    None,
                    Duration::from_secs(10),
                )?;
                ensure!(
                    result.status.success(),
                    "fixture native JSON observation failed"
                );
                Ok(serde_json::from_slice(&result.stdout)?)
            },
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap()
    };
    let dispatch = |name: &str, batch: &Value| {
        save(&format!("{name}-batch.json"), batch);
        save(
            &format!("{name}-intent.json"),
            &json!({"dispatch":"once","batchSha256":digest(batch).unwrap(),"expectedGeneration":batch["expectedGeneration"]}),
        );
        let result = raw::writer::dispatch(batch, Instant::now() + Duration::from_secs(10));
        save(
            &format!("{name}-dispatch.json"),
            &json!({"acknowledged":result.is_ok(),"error":result.as_ref().err().map(ToString::to_string)}),
        );
        result.unwrap();
    };
    let primary: Value =
        serde_json::from_slice(&fs::read(root.join("java-primary-case.json")).unwrap()).unwrap();
    let roles =
        roles::Observation::new(uuid::Uuid::new_v4(), 42, primary["roles"].clone()).unwrap();
    let origin = roles::Origin::new(
        roles.agent_instance,
        roles.bridge_epoch,
        &roles,
        primary["origin"].clone(),
    )
    .unwrap();
    let original = read();
    save("original.json", &original);
    let initial = factory::Reviewed::new(&"e".repeat(64), &origin, &roles, &original)
        .unwrap()
        .bind(uuid::Uuid::new_v4())
        .unwrap();
    save(
        "initial-transfer.json",
        &serde_json::to_value(&initial).unwrap(),
    );
    dispatch("initial", &initial.batch(&original, false).unwrap());
    let initialized = read();
    initial.acknowledge(&initialized, false).unwrap();
    save("initialized.json", &initialized);
    let mut before = origin.model_rules().clone();
    before["schemaVersion"] = json!(4);
    let mut prefixes = Prefixes::new();
    for family in origin.families() {
        let key = &family.family;
        let native = if key == "ipv4" { "ip" } else { "ip6" };
        before[key] = json!({"allowIcmp":family.allow_icmp});
        for (name, field) in [
            ("INPUT", "inputPolicy"),
            ("FORWARD", "forwardPolicy"),
            ("OUTPUT", "outputPolicy"),
        ] {
            before[key][field] = initialized["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|v| v.get("chain"))
                .find(|v| v["family"] == native && v["table"] == "filter" && v["name"] == name)
                .unwrap()["policy"]
                .clone();
        }
        for row in &family.automatic_nat {
            before["nat"].as_array_mut().unwrap().push(json!({"family":key,"inputInterface":row.source_interface,"outputInterface":row.destination_interface,"masquerade":row.masquerade,"automatic":true}));
        }
        prefixes.insert(
            key.clone(),
            family
                .runtime_port_forward_destination_prefixes
                .clone()
                .unwrap(),
        );
    }
    // This is a synthetic logical anchor, never a Store publication or lease.
    let anchor = digest(
        &json!({"fixture":"V42-synthetic-initialization","transfer":initial.identity().unwrap()}),
    )
    .unwrap();
    let current = CurrentSource::from_acknowledged(
        &anchor,
        1,
        before.clone(),
        prefixes.clone(),
        &initial,
        &initialized,
        false,
    )
    .unwrap();
    let mut next = before.clone();
    next["input"] = json!([]);
    next["ipv6"]["allowIcmp"] = json!(false);
    next["ipv4"]["inputPolicy"] = json!(if before["ipv4"]["inputPolicy"] == "accept" {
        "drop"
    } else {
        "accept"
    });
    next["portForward"][0]["outPort"] = json!(2451);
    let mut desired = prefixes.clone();
    desired.insert("ipv4".into(), vec![32]);
    let plan = current
        .plan(uuid::Uuid::new_v4(), next.clone(), desired.clone())
        .unwrap();
    save("update-plan.json", &serde_json::to_value(&plan).unwrap());
    save("update-review.json", &plan.parameters().unwrap());
    assert!(
        plan.transfer.batch(&original, false).is_err(),
        "the pre-initialization source cannot authorize an ordinary update"
    );
    dispatch("update", &plan.transfer.batch(&initialized, false).unwrap());
    let applied = read();
    plan.transfer.acknowledge(&applied, false).unwrap();
    save("applied.json", &applied);
    let committed = CurrentSource::from_acknowledged(
        &anchor,
        2,
        next,
        desired,
        &plan.transfer,
        &applied,
        false,
    )
    .unwrap();
    let following = committed
        .plan(uuid::Uuid::new_v4(), before.clone(), prefixes.clone())
        .unwrap();
    save("following-review.json", &following.parameters().unwrap());
    assert!(
        plan.transfer.batch(&applied, false).is_err(),
        "an applied operation is not a new forward source"
    );
    dispatch("inverse", &plan.transfer.batch(&applied, true).unwrap());
    let reverted = read();
    plan.transfer.acknowledge(&reverted, true).unwrap();
    save("reverted.json", &reverted);
    let rolled_back = CurrentSource::from_acknowledged(
        &anchor,
        1,
        before.clone(),
        prefixes.clone(),
        &plan.transfer,
        &reverted,
        true,
    )
    .unwrap();
    assert_ne!(current.receipt, rolled_back.receipt);
    assert_ne!(current.snapshot.generation, rolled_back.snapshot.generation);
    assert!(
        plan.transfer.batch(&reverted, false).is_err(),
        "same logical revision cannot replay the original update"
    );
    let after_rollback = rolled_back
        .plan(uuid::Uuid::new_v4(), before, prefixes)
        .unwrap();
    save(
        "after-rollback-review.json",
        &after_rollback.parameters().unwrap(),
    );
    let before_snapshot = Snapshot::read(&initialized).unwrap();
    let after_snapshot = Snapshot::read(&reverted).unwrap();
    let unselected = before_snapshot
        .fingerprints
        .iter()
        .filter(|((chain, id), _)| {
            !current
                .selected
                .get(chain)
                .is_some_and(|ids| ids.contains(id))
        })
        .collect::<Vec<_>>();
    assert!(unselected.len() >= 2);
    for (key, hash) in &unselected {
        assert_eq!(after_snapshot.fingerprints.get(*key), Some(*hash));
        assert_eq!(
            after_snapshot.payloads.get(*key),
            before_snapshot.payloads.get(*key)
        );
    }
    save(
        "result.json",
        &json!({"status":"passed","scope":"actual original-layout native plan forward/inverse;synthetic logical anchor and registration;not owner/ordinary transaction acceptance",
        "initialOperationId":initial.operation_id,"updateOperationId":plan.transfer.operation_id,"selectedRuleCount":plan.transfer.rules.iter().map(|r|r.original.len()).sum::<usize>(),
        "targetRuleCount":plan.transfer.rules.iter().map(|r|r.replacement.len()).sum::<usize>(),"unselectedRawRulesPreserved":unselected.len(),
        "generations":{"before":original["kernelGeneration"],"initialized":initialized["kernelGeneration"],"applied":applied["kernelGeneration"],"inverse":reverted["kernelGeneration"]},
        "sameLogicalRevisionAfterInverse":true,"differentPhysicalSourceAfterInverse":true,"oldForwardRejectedAfterInverse":true,"ordinaryTransactionCoordinatorImplemented":false,
        "normalAgentStarted":false,"normalGatewayModified":false,"actualJvmOrOwnerLease":false,"unknownRedispatch":false}),
    );
}
