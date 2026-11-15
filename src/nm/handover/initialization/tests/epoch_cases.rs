//! Synthetic Store/filesystem contracts. No real owner lease or native dispatch.
use super::*;
use native::epoch::Epoch;

fn changed_epoch() -> Epoch {
    let mut value = serde_json::to_value(Epoch::storage_fixture()).unwrap();
    value["namespaceInode"] = json!(20);
    serde_json::from_value(value).unwrap()
}
fn journal(f: &Fixture) -> Value {
    serde_json::from_slice(&fs::read(f.store.journal_path()).unwrap()).unwrap()
}
#[test]
fn physical_epoch_is_checked_before_intent_and_again_before_the_first_native_send() {
    for change_at in [2, 3] {
        let f = Fixture::before_native();
        let before = fs::read(f.store.journal_path()).unwrap();
        let dispatches = AtomicUsize::new(0);
        let mut samples = 0;
        let result = f.store.native_change_epoch_fixture(
            f.id,
            &f.token,
            "actor",
            false,
            (
                |_, _, _, _| {
                    Ok(f.baseline
                        .native_transfer
                        .as_ref()
                        .unwrap()
                        .original
                        .clone())
                },
                |_| {
                    dispatches.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                || {
                    samples += 1;
                    Ok(if samples < change_at {
                        Epoch::storage_fixture()
                    } else {
                        changed_epoch()
                    })
                },
            ),
        );
        assert!(result.is_err());
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        if change_at == 2 {
            assert_eq!(fs::read(f.store.journal_path()).unwrap(), before);
        } else {
            let retained = fs::read(f.store.journal_path()).unwrap();
            assert_eq!(journal(&f)["native"]["state"], "INTENT");
            assert_eq!(
                journal(&f)["native"]["epoch"],
                serde_json::to_value(Epoch::storage_fixture()).unwrap()
            );
            assert!(
                f.store
                    .native_change_fixture(
                        f.id,
                        &f.token,
                        "actor",
                        false,
                        |_, _, _, _| panic!("never re-inspect issued work"),
                        |_| panic!("never resend")
                    )
                    .is_err()
            );
            assert_eq!(fs::read(f.store.journal_path()).unwrap(), retained);
        }
    }
}
#[test]
fn epoch_change_after_a_send_keeps_the_original_intent_unknown_despite_matching_forward_bytes() {
    let f = Fixture::before_native();
    let dispatches = AtomicUsize::new(0);
    let mut samples = 0;
    let result = f.store.native_change_epoch_fixture(
        f.id,
        &f.token,
        "actor",
        false,
        (
            |_, _, _, after| {
                Ok(if after {
                    f.current.clone()
                } else {
                    f.baseline
                        .native_transfer
                        .as_ref()
                        .unwrap()
                        .original
                        .clone()
                })
            },
            |_| {
                dispatches.fetch_add(1, Ordering::SeqCst);
                assert_eq!(journal(&f)["native"]["state"], "INTENT");
                assert_eq!(
                    journal(&f)["native"]["epoch"],
                    serde_json::to_value(Epoch::storage_fixture()).unwrap()
                );
                Ok(())
            },
            || {
                samples += 1;
                Ok(if samples <= 3 {
                    Epoch::storage_fixture()
                } else {
                    changed_epoch()
                })
            },
        ),
    );
    assert!(result.is_err());
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(journal(&f)["native"]["state"], "INTENT");
    let retained = fs::read(f.store.journal_path()).unwrap();
    assert!(
        f.store
            .native_original_epoch_fixture(
                f.id,
                "actor",
                (|| Ok(f.current.clone()), || Ok(changed_epoch()))
            )
            .is_err()
    );
    assert_eq!(fs::read(f.store.journal_path()).unwrap(), retained);
}
#[test]
fn initialization_inherits_the_first_native_intent_epoch_without_replacing_the_original_baseline() {
    let f = Fixture::new();
    let before = journal(&f);
    assert_eq!(before["native"]["schemaVersion"], 3);
    assert_eq!(
        before["native"]["epoch"],
        serde_json::to_value(Epoch::storage_fixture()).unwrap()
    );
    f.initialize().unwrap();
    let document: Value = serde_json::from_slice(&fs::read(f.root.join(POLICY)).unwrap()).unwrap();
    assert_eq!(document["schemaVersion"], 2);
    assert_eq!(document["nativeEpoch"], before["native"]["epoch"]);
    assert_eq!(journal(&f)["native"], before["native"]);
    let snapshot = producer::Snapshot::take(&f.root).unwrap();
    snapshot
        .require_native_epoch(&Epoch::storage_fixture())
        .unwrap();
    assert!(snapshot.require_native_epoch(&changed_epoch()).is_err());
    f.check_original();
}
#[test]
fn a_different_epoch_cannot_start_an_inverse_or_adjudicate_a_retained_original_even_with_identical_kernel_bytes()
 {
    let f = Fixture::new();
    let before = fs::read(f.store.journal_path()).unwrap();
    let inspect = AtomicUsize::new(0);
    let dispatch = AtomicUsize::new(0);
    assert!(
        f.store
            .native_change_epoch_fixture(
                f.id,
                &f.token,
                "actor",
                true,
                (
                    |_, _, _, _| {
                        inspect.fetch_add(1, Ordering::SeqCst);
                        Ok(f.current.clone())
                    },
                    |_| {
                        dispatch.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                    || Ok(changed_epoch()),
                )
            )
            .is_err()
    );
    assert!(
        f.store
            .native_original_epoch_fixture(
                f.id,
                "actor",
                (
                    || {
                        inspect.fetch_add(1, Ordering::SeqCst);
                        Ok(f.current.clone())
                    },
                    || Ok(changed_epoch()),
                )
            )
            .is_err()
    );
    assert_eq!(inspect.load(Ordering::SeqCst), 0);
    assert_eq!(dispatch.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(f.store.journal_path()).unwrap(), before);
    f.store
        .native_original_fixture(f.id, "actor", || Ok(f.current.clone()))
        .unwrap();
    assert_eq!(fs::read(f.store.journal_path()).unwrap(), before);
}
#[test]
fn original_query_never_stamps_an_old_intent_with_a_new_physical_epoch() {
    let f = Fixture::new();
    // Explicit interrupted-storage fixture, not a claim that a live send ran.
    let mut record = journal(&f);
    record["native"]["state"] = json!("INTENT");
    record["native"]
        .as_object_mut()
        .unwrap()
        .remove("kernelDigest");
    durable::json(&f.store.journal_path(), &record).unwrap();
    let before = fs::read(f.store.journal_path()).unwrap();
    let calls = AtomicUsize::new(0);
    assert!(
        f.store
            .native_original_epoch_fixture(
                f.id,
                "actor",
                (
                    || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(f.current.clone())
                    },
                    || Ok(changed_epoch()),
                )
            )
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(f.store.journal_path()).unwrap(), before);
    f.store
        .native_original_fixture(f.id, "actor", || Ok(f.current.clone()))
        .unwrap();
    let after = journal(&f);
    assert_eq!(after["native"]["state"], "APPLIED");
    assert_eq!(after["native"]["epoch"], record["native"]["epoch"]);
}
#[test]
fn legacy_evidence_remains_queryable_but_cannot_be_backfilled_into_a_new_initialization_or_inverse_grant()
 {
    let f = Fixture::new();
    let mut record = journal(&f);
    record["native"]["schemaVersion"] = json!(2);
    record["native"].as_object_mut().unwrap().remove("epoch");
    durable::json(&f.store.journal_path(), &record).unwrap();
    let before = fs::read(f.store.journal_path()).unwrap();
    f.store
        .native_original_fixture(f.id, "actor", || Ok(f.current.clone()))
        .unwrap();
    assert!(
        f.store
            .initialize_policy_fixture(
                f.id,
                &f.token,
                "actor",
                |_, _, _| panic!("no fresh inspection may invent missing original epoch"),
                |_, _| panic!("no publication")
            )
            .is_err()
    );
    assert!(
        f.store
            .native_change_fixture(
                f.id,
                &f.token,
                "actor",
                true,
                |_, _, _, _| panic!("no inverse inspection"),
                |_| panic!("no inverse dispatch")
            )
            .is_err()
    );
    assert_eq!(fs::read(f.store.journal_path()).unwrap(), before);
    assert!(!f.root.join(POLICY).exists());
}
#[test]
fn legacy_unresolved_intents_without_an_epoch_never_adopt_matching_current_kernel_bytes() {
    for version in [1, 2] {
        for phase in ["INTENT", "INVERSE_INTENT"] {
            let f = Fixture::new();
            let mut record = journal(&f);
            record["native"]["schemaVersion"] = json!(version);
            record["native"]["state"] = json!(phase);
            let native = record["native"].as_object_mut().unwrap();
            native.remove("epoch");
            native.remove("kernelDigest");
            if version == 1 {
                native.remove("batchSha256");
            }
            durable::json(&f.store.journal_path(), &record).unwrap();
            let before = fs::read(f.store.journal_path()).unwrap();
            let error = f
                .store
                .native_original_fixture(f.id, "actor", || {
                    panic!("a legacy intent cannot be adjudicated from any current namespace")
                })
                .unwrap_err();
            assert!(error.to_string().starts_with("OUTCOME_UNKNOWN"));
            assert_eq!(fs::read(f.store.journal_path()).unwrap(), before);
        }
    }
}
#[test]
fn epoch_drift_during_initialization_inspection_refuses_the_first_publication() {
    let f = Fixture::new();
    let before = fs::read(f.store.journal_path()).unwrap();
    let mut samples = 0;
    let publications = AtomicUsize::new(0);
    assert!(
        f.store
            .initialize_policy_at(
                f.id,
                &f.token,
                "actor",
                (
                    |b, id, p| f.inspect(b, id, p),
                    |_, _| {
                        publications.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                    || {
                        samples += 1;
                        Ok(if samples == 1 {
                            Epoch::storage_fixture()
                        } else {
                            changed_epoch()
                        })
                    },
                )
            )
            .is_err()
    );
    assert_eq!(publications.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(f.store.journal_path()).unwrap(), before);
    assert!(!f.root.join(POLICY).exists());
}
