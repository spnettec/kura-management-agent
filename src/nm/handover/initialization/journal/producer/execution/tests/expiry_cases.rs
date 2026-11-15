//! Fresh temporary original records and injected transport only. No registered
//! owner,real service,netlink write or retained one-shot scene is exercised.
use super::*;
use crate::system_change::Guard;
use expiry::Tick;

fn due(root: &Path) {
    let mut record = active(root).unwrap();
    record.deadline_ms = 1;
    // Model elapsed wall time on this newly created temporary transaction.
    durable::json(&root.join("firewall/transaction.json"), &record).unwrap();
}
fn poll(root: &Path) -> Result<Tick> {
    let _guard = Guard::observe(root)?;
    expiry::poll(root)
}
fn saved(root: &Path) -> Vec<u8> {
    fs::read(root.join("firewall/transaction.json")).unwrap()
}

#[tokio::test]
async fn imported_expiry_cancels_only_due_unissued_original_without_owner_key_or_private_backend() {
    let (f, snapshot, proof, input) = fixtures::fixture();
    let receipt = fixtures::prepare(&f, &snapshot, &proof, &input, "expiry-before-send").unwrap();
    let original = fs::read(f.store.journal_path()).unwrap();
    let policy = fs::read(f.root.join(POLICY)).unwrap();
    let before = saved(&f.root);
    assert!(matches!(poll(&f.root).unwrap(), Tick::Pending));
    assert_eq!(saved(&f.root), before);
    due(&f.root);
    let before = saved(&f.root);
    crate::firewall::Firewall::open(f.root.clone(), None)
        .unwrap()
        .enable_writes(true)
        .expire()
        .await
        .unwrap();
    assert_eq!(
        saved(&f.root),
        before,
        "private expiry must not parse,reapply or cancel imported work"
    );
    let Tick::Cancel(work) = poll(&f.root).unwrap() else {
        panic!("due original cancellation")
    };
    let value = {
        let _guard = Guard::observe(&f.root).unwrap();
        expiry::cancel(&f.root, &work).unwrap()
    };
    assert_eq!(value["id"], receipt["id"]);
    assert_eq!(value["state"], "ROLLED_BACK");
    assert_eq!(value["expiry"]["phase"], "BEFORE_DISPATCH");
    let record = active(&f.root).unwrap();
    assert_eq!(record.schema_version, 4);
    assert!(!record.forward_intent && !record.inverse_intent);
    assert!(record.forward_dispatch.is_none() && record.inverse_dispatch.is_none());
    assert!(matches!(poll(&f.root).unwrap(), Tick::Idle));
    let current = Snapshot::take(&f.root).unwrap();
    assert_eq!(current.revision(), snapshot.revision());
    assert_eq!(current.source(), snapshot.source());
    assert!(!f.root.join("firewall/confirmed.json").exists());
    assert_eq!(fs::read(f.store.journal_path()).unwrap(), original);
    assert_eq!(fs::read(f.root.join(POLICY)).unwrap(), policy);
    assert!(expiry::cancel(&f.root, &work).is_err());
}

#[test]
fn imported_expiry_rolls_back_the_original_acknowledged_forward_once_and_preserves_logical_revision()
 {
    let (f, snapshot, proof, input) = fixtures::fixture();
    let request = "expiry-original-inverse";
    let receipt = fixtures::prepare(&f, &snapshot, &proof, &input, request).unwrap();
    let (forward, inverse) = outcomes(&f.root);
    let calls = Cell::new(0);
    let ticket = pending(&f, &input, &receipt, request);
    let proof = fixtures::proof(&f, &ticket, Instant::now() + Duration::from_secs(300));
    run(
        &f.root,
        &ticket,
        &proof,
        77,
        action(&input, &receipt, request),
        false,
        |_| {
            calls.set(calls.get() + 1);
            Ok(())
        },
        || Ok(forward.clone()),
    )
    .unwrap();
    due(&f.root);
    let Tick::Rollback(work) = poll(&f.root).unwrap() else {
        panic!("known forward expiry")
    };
    work.snapshot().require_native(&forward).unwrap();
    let proof = fixtures::proof(
        &f,
        work.snapshot(),
        Instant::now() + Duration::from_secs(300),
    );
    let value = {
        let _guard = Guard::observe(&f.root).unwrap();
        expire_fixture(
            &f.root,
            work.snapshot(),
            &proof,
            &work,
            |batch| {
                let original = active(&f.root).unwrap();
                assert_eq!(original.id.to_string(), receipt["id"]);
                assert_eq!(original.schema_version, 4);
                assert!(original.state == State::RollingBack);
                assert!(original.inverse_intent);
                assert!(original.expiry.is_some());
                original
                    .inverse_dispatch
                    .as_ref()
                    .unwrap()
                    .require_batch(batch)?;
                calls.set(calls.get() + 1);
                Ok(())
            },
            || Ok(inverse.clone()),
        )
        .unwrap()
    };
    assert_eq!(value["state"], "ROLLED_BACK");
    assert_eq!(value["expiry"]["phase"], "AFTER_FORWARD");
    assert_eq!(calls.get(), 2);
    assert!(matches!(poll(&f.root).unwrap(), Tick::Idle));
    let current = Snapshot::take(&f.root).unwrap();
    assert_eq!(current.revision(), snapshot.revision());
    assert_ne!(current.source(), snapshot.source());
    current.require_native(&inverse).unwrap();
    assert!(
        expire_fixture(
            &f.root,
            work.snapshot(),
            &proof,
            &work,
            |_| panic!("expiry must never resend"),
            || panic!("expiry must never reobserve")
        )
        .is_err()
    );
    assert_eq!(calls.get(), 2);
}

#[test]
fn imported_expiry_ambiguous_inverse_keeps_original_intent_and_never_schedules_or_observes_again() {
    let (f, snapshot, proof, input) = fixtures::fixture();
    let request = "expiry-unknown-inverse";
    let receipt = fixtures::prepare(&f, &snapshot, &proof, &input, request).unwrap();
    let (forward, _) = outcomes(&f.root);
    let ticket = pending(&f, &input, &receipt, request);
    let proof = fixtures::proof(&f, &ticket, Instant::now() + Duration::from_secs(300));
    run(
        &f.root,
        &ticket,
        &proof,
        77,
        action(&input, &receipt, request),
        false,
        |_| Ok(()),
        || Ok(forward),
    )
    .unwrap();
    due(&f.root);
    let Tick::Rollback(work) = poll(&f.root).unwrap() else {
        panic!("expiry work")
    };
    let proof = fixtures::proof(
        &f,
        work.snapshot(),
        Instant::now() + Duration::from_secs(300),
    );
    let calls = Cell::new(0);
    let result = {
        let _guard = Guard::observe(&f.root).unwrap();
        expire_fixture(
            &f.root,
            work.snapshot(),
            &proof,
            &work,
            |_| {
                calls.set(calls.get() + 1);
                anyhow::bail!("OUTCOME_UNKNOWN: injected original inverse reply loss")
            },
            || panic!("ambiguous send must not capture/reclassify a native outcome"),
        )
    };
    assert!(result.is_err_and(|error| error.to_string().starts_with("OUTCOME_UNKNOWN")));
    let before = saved(&f.root);
    let record = active(&f.root).unwrap();
    assert!(
        record.state == State::RollingBack && record.inverse_intent && record.inverse.is_none()
    );
    assert!(record.expiry.is_some());
    assert!(matches!(poll(&f.root), Ok(Tick::Pending) | Err(_)));
    assert_eq!(saved(&f.root), before);
    assert!(Snapshot::take(&f.root).is_err());
    assert!(
        expire_fixture(
            &f.root,
            work.snapshot(),
            &proof,
            &work,
            |_| panic!("original inverse redispatch"),
            || panic!("original inverse reobserve")
        )
        .is_err()
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn imported_expiry_does_not_convert_an_unknown_forward_or_confirmed_decision_into_inverse_work() {
    for confirmed in [false, true] {
        let (f, snapshot, proof, input) = fixtures::fixture();
        let request = "expiry-unavailable-forward";
        let receipt = fixtures::prepare(&f, &snapshot, &proof, &input, request).unwrap();
        let (forward, _) = outcomes(&f.root);
        let ticket = pending(&f, &input, &receipt, request);
        let proof = fixtures::proof(&f, &ticket, Instant::now() + Duration::from_secs(300));
        let result = run(
            &f.root,
            &ticket,
            &proof,
            77,
            action(&input, &receipt, request),
            false,
            |_| {
                if !confirmed {
                    anyhow::bail!("OUTCOME_UNKNOWN: injected forward reply loss");
                }
                Ok(())
            },
            || Ok(forward),
        );
        if confirmed {
            result.unwrap();
        } else {
            assert!(result.is_err());
        }
        let mut record = active(&f.root).unwrap();
        record.deadline_ms = 1;
        if confirmed {
            record.state = State::Confirming;
            record.confirmed_decision = true;
        }
        durable::json(&f.root.join("firewall/transaction.json"), &record).unwrap();
        let before = saved(&f.root);
        assert!(matches!(
            poll(&f.root),
            Ok(Tick::Pending) | Ok(Tick::Idle) | Err(_)
        ));
        let after = active(&f.root).unwrap();
        assert!(!after.inverse_intent);
        assert!(after.expiry.is_none());
        if !confirmed {
            assert_eq!(saved(&f.root), before);
        }
    }
}

#[test]
fn imported_expiry_original_ticket_rejects_changed_identity_deadline_or_identical_replacement_inode()
 {
    for defect in ["id", "request", "deadline", "inode"] {
        let (f, snapshot, proof, input) = fixtures::fixture();
        fixtures::prepare(&f, &snapshot, &proof, &input, "expiry-ticket-fence").unwrap();
        due(&f.root);
        let Tick::Cancel(work) = poll(&f.root).unwrap() else {
            panic!("due cancellation")
        };
        let mut record = active(&f.root).unwrap();
        match defect {
            "id" => record.id = uuid::Uuid::new_v4(),
            "request" => record.request_id = "different-original".into(),
            "deadline" => record.deadline_ms = now_ms() + 60_000,
            "inode" => {}
            _ => unreachable!(),
        }
        durable::json(&f.root.join("firewall/transaction.json"), &record).unwrap();
        let before = saved(&f.root);
        let result = {
            let _guard = Guard::observe(&f.root).unwrap();
            expiry::cancel(&f.root, &work)
        };
        assert!(result.is_err(), "{defect}");
        assert_eq!(saved(&f.root), before);
    }
}
