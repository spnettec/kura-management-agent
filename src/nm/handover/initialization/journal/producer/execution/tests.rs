//! Explicit storage/transport contracts only. No live COMMITTED owner, native
//! socket or registered JVM is constructed or claimed by these fixtures.
use super::*;
use crate::nm::handover::initialization::tests::producer_cases as fixtures;
use std::cell::Cell;
use std::time::Duration;
mod expiry_cases;

fn remote_run(root:&Path,snapshot:&Snapshot,proof:&Verified,work:RemoteAction<'_>,
    send:impl FnOnce(&Value)->Result<()>,observe:impl FnOnce()->Result<Value>)->Result<Value> {
    let command=work.principal.require_action_dto(&work.action,if work.inverse {43}else{41})?;
    let record=owned(root,work.principal.uid(),&work.action)?;
    run_original(root,snapshot,proof,OriginalAction {record,inverse:work.inverse,expiry:None,command:Some(command)},send,observe)
}

#[tokio::test]
async fn remote_service_principal_retains_schema5_through_once_only_forward_and_inverse_history() {
    for inverse in [false,true] {
        let(f,snapshot,proof,input)=fixtures::fixture();
        let principal=super::super::principal::storage_principal(&input,false).await;
        let uid=principal.uid();let request=principal.request_id();
        let anchor=fs::read(f.root.join(POLICY)).unwrap();
        let _guard=crate::system_change::Guard::observe(&f.root).unwrap();
        let receipt=super::super::prepare_remote(&f.root,&snapshot,serde_json::from_value(input.clone()).unwrap(),&principal,&proof).unwrap();
        let(fwd,back)=outcomes(&f.root);let calls=Cell::new(0);
        let ticket=Snapshot::pending(&f.root,uid,&action(&input,&receipt,request)).unwrap();
        let proof=fixtures::proof(&f,&ticket,Instant::now()+Duration::from_secs(300));
        let forward_principal=principal.storage_action(41);
        remote_run(&f.root,&ticket,&proof,RemoteAction {principal:&forward_principal,action:action(&input,&receipt,request),inverse:false},|_|{calls.set(calls.get()+1);Ok(())},||Ok(fwd.clone())).unwrap();
        assert_eq!(active(&f.root).unwrap().schema_version,5);
        assert!(remote_run(&f.root,&ticket,&proof,RemoteAction {principal:&forward_principal,action:action(&input,&receipt,request),inverse:false},|_|panic!("remote forward redispatch"),||panic!("remote recapture")).is_err());
        let ticket=Snapshot::pending(&f.root,uid,&action(&input,&receipt,request)).unwrap();
        let proof=fixtures::proof(&f,&ticket,Instant::now()+Duration::from_secs(300));
        if inverse {
            remote_run(&f.root,&ticket,&proof,RemoteAction {principal:&principal.storage_action(43),action:action(&input,&receipt,request),inverse:true},|_|{calls.set(calls.get()+1);Ok(())},||Ok(back.clone())).unwrap();
        } else {confirm_remote(&f.root,&ticket,&proof,&principal.storage_action(42),action(&input,&receipt,request)).unwrap();}
        assert_eq!(calls.get(),if inverse {2}else{1});
        let audit: yofc_management_protocol::imported::DecisionEvidence=serde_json::from_value(super::super::original_evidence(&f.root,uid,&outcome(&f.root,uid,original(&input,request),||panic!("settled metadata only")).unwrap()).unwrap()).unwrap();
        assert_eq!(audit.resolution(41,if inverse {"ROLLED_BACK"}else{"COMMITTED"},forward_principal.command(41).unwrap().command_sha256(),false),Some(yofc_management_protocol::imported::OriginalResolution::Succeeded));
        assert_eq!(audit.resolution(41,if inverse {"ROLLED_BACK"}else{"COMMITTED"},principal.storage_action(41).command(41).unwrap().command_sha256(),false),Some(yofc_management_protocol::imported::OriginalResolution::Failed));
        let record=active(&f.root).unwrap();assert_eq!(record.schema_version,5);assert!(record.origin.is_some());
        let queried=outcome(&f.root,uid,original(&input,request),||panic!("settled remote query cannot read native backend")).unwrap();
        assert_eq!(queried["historical"],true);assert_eq!(queried["state"],if inverse {"ROLLED_BACK"}else{"COMMITTED"});
        assert_eq!(Snapshot::take(&f.root).unwrap().revision(),snapshot.revision()+u64::from(!inverse));
        assert_eq!(fs::read(f.root.join(POLICY)).unwrap(),anchor);
    }
}

#[tokio::test]
async fn remote_service_pre_dispatch_expiry_preserves_schema5_and_its_origin_without_native_effect() {
    let(f,snapshot,proof,input)=fixtures::fixture();
    let principal=super::super::principal::storage_principal(&input,false).await;
    let _guard=crate::system_change::Guard::observe(&f.root).unwrap();
    super::super::prepare_remote(&f.root,&snapshot,serde_json::from_value(input.clone()).unwrap(),&principal,&proof).unwrap();
    let mut record=active(&f.root).unwrap();record.deadline_ms=now_ms()-1;
    durable::json(&f.root.join("firewall/transaction.json"),&record).unwrap();
    let expiry::Tick::Cancel(work)=expiry::poll(&f.root).unwrap() else {panic!("original pre-dispatch expiry required")};
    expiry::cancel(&f.root,&work).unwrap();
    let record=active(&f.root).unwrap();assert_eq!(record.schema_version,5);assert!(record.origin.is_some());
    assert!(!record.forward_intent&&!record.inverse_intent&&record.expiry.is_some());
    assert!(record.state==State::RolledBack);assert_eq!(Snapshot::take(&f.root).unwrap().revision(),snapshot.revision());
}
fn pending(
    f: &crate::nm::handover::initialization::tests::Fixture,
    input: &Value,
    receipt: &Value,
    request: &str,
) -> Snapshot {
    Snapshot::pending(
        &f.root,
        77,
        &serde_json::from_value(fixtures::action(input, receipt, request)).unwrap(),
    )
    .unwrap()
}
fn outcomes(root: &Path) -> (Value, Value) {
    let record = active(root).unwrap();
    let bytes = record
        .plan
        .read(root, &record.path(root, "plan.json"))
        .unwrap();
    let plan: Value = serde_json::from_slice(&bytes).unwrap();
    let transfer: native::Transfer = serde_json::from_value(plan["transfer"].clone()).unwrap();
    (
        native::lineage::tests::outcome(&transfer, false),
        native::lineage::tests::outcome(&transfer, true),
    )
}
fn action(input: &Value, receipt: &Value, request: &str) -> Cancel {
    serde_json::from_value(fixtures::action(input, receipt, request)).unwrap()
}
fn original(input: &Value, request: &str) -> Outcome {
    serde_json::from_value(fixtures::outcome(input, request)).unwrap()
}
#[test]
fn once_only_intent_precedes_transport_and_confirm_advances_current_without_sending_again() {
    let (f, snapshot, proof, input) = fixtures::fixture();
    let request = "single-native";
    let anchor = fs::read(f.root.join(POLICY)).unwrap();
    let owner = fs::read(f.store.journal_path()).unwrap();
    let receipt = fixtures::prepare(&f, &snapshot, &proof, &input, request).unwrap();
    let ticket = pending(&f, &input, &receipt, request);
    let proof = fixtures::proof(&f, &ticket, Instant::now() + Duration::from_secs(300));
    let (forward, inverse) = outcomes(&f.root);
    let (_, plan) = checked(&f.root, &active(&f.root).unwrap()).unwrap();
    let (forward_bound, inverse_bound) = plan.evidence_bounds().unwrap();
    assert!(serde_json::to_vec(&forward).unwrap().len() <= forward_bound);
    assert!(serde_json::to_vec(&inverse).unwrap().len() <= inverse_bound);
    let calls = Cell::new(0);
    let applied = run(
        &f.root,
        &ticket,
        &proof,
        77,
        action(&input, &receipt, request),
        false,
        |batch| {
            let record = active(&f.root).unwrap();
            assert!(record.state == State::Applying);
            assert!(record.forward_dispatch.is_some());
            record
                .forward_dispatch
                .as_ref()
                .unwrap()
                .require_batch(batch)?;
            calls.set(calls.get() + 1);
            Ok(())
        },
        || Ok(forward.clone()),
    )
    .unwrap();
    assert_eq!(applied["state"], "WAIT_CONFIRM");
    assert_eq!(calls.get(), 1);
    assert!(
        run(
            &f.root,
            &ticket,
            &proof,
            77,
            action(&input, &receipt, request),
            false,
            |_| panic!("redispatch"),
            || panic!("reobserve")
        )
        .is_err()
    );
    assert!(
        pending(&f, &input, &receipt, request)
            .require_native(&forward)
            .is_ok()
    );
    let ticket = pending(&f, &input, &receipt, request);
    let proof = fixtures::proof(&f, &ticket, Instant::now() + Duration::from_secs(300));
    let settled = confirm(
        &f.root,
        &ticket,
        &proof,
        77,
        action(&input, &receipt, request),
    )
    .unwrap();
    assert_eq!(settled["state"], "COMMITTED");
    assert_eq!(calls.get(), 1);
    let current = Snapshot::take(&f.root).unwrap();
    assert_eq!(current.revision(), 2);
    current.require_native(&forward).unwrap();
    assert_eq!(fs::read(f.root.join(POLICY)).unwrap(), anchor);
    assert_eq!(fs::read(f.store.journal_path()).unwrap(), owner);
    let historical = outcome(&f.root, 77, original(&input, request), || {
        panic!("settled query cannot read backend")
    })
    .unwrap();
    assert_eq!(historical["historical"], true);
    assert_eq!(historical["state"], "COMMITTED");
}
#[test]
fn inverse_is_once_only_and_keeps_logical_revision_with_a_new_physical_source() {
    let (f, snapshot, proof, input) = fixtures::fixture();
    let request = "inverse-native";
    let original_source = snapshot.source().to_owned();
    let receipt = fixtures::prepare(&f, &snapshot, &proof, &input, request).unwrap();
    let (forward, inverse) = outcomes(&f.root);
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
    let ticket = pending(&f, &input, &receipt, request);
    let proof = fixtures::proof(&f, &ticket, Instant::now() + Duration::from_secs(300));
    let value = run(
        &f.root,
        &ticket,
        &proof,
        77,
        action(&input, &receipt, request),
        true,
        |_| Ok(()),
        || Ok(inverse.clone()),
    )
    .unwrap();
    assert_eq!(value["state"], "ROLLED_BACK");
    let current = Snapshot::take(&f.root).unwrap();
    assert_eq!(current.revision(), 1);
    assert_ne!(current.source(), original_source);
    current.require_native(&inverse).unwrap();
    assert!(
        run(
            &f.root,
            &ticket,
            &proof,
            77,
            action(&input, &receipt, request),
            true,
            |_| panic!("inverse retry"),
            || panic!("read")
        )
        .is_err()
    );
}
#[test]
fn ambiguous_send_only_observes_the_original_receipt_and_never_infers_no_effect_from_old_source() {
    let (f, snapshot, proof, input) = fixtures::fixture();
    let request = "ambiguous-native";
    let receipt = fixtures::prepare(&f, &snapshot, &proof, &input, request).unwrap();
    let (forward, _) = outcomes(&f.root);
    let ticket = pending(&f, &input, &receipt, request);
    let proof = fixtures::proof(&f, &ticket, Instant::now() + Duration::from_secs(300));
    assert!(
        run(
            &f.root,
            &ticket,
            &proof,
            77,
            action(&input, &receipt, request),
            false,
            |_| anyhow::bail!("timeout"),
            || panic!("send failed")
        )
        .is_err()
    );
    assert!(
        pending(&f, &input, &receipt, request)
            .admit_action(&f.root, "firewall.kura.imported.apply")
            .is_err()
    );
    let before = fs::read(f.root.join("firewall/transaction.json")).unwrap();
    assert!(
        outcome(&f.root, 77, original(&input, request), || Ok(f
            .current
            .clone()))
        .is_err()
    );
    assert_eq!(
        fs::read(f.root.join("firewall/transaction.json")).unwrap(),
        before
    );
    let observed = outcome(&f.root, 77, original(&input, request), || Ok(forward)).unwrap();
    assert_eq!(observed["state"], "WAIT_CONFIRM");
    assert!(fixtures::prepare(&f, &snapshot, &proof, &input, "new-id-bypass").is_err());
}
fn negative(batch: &Value) -> wire::Rejected {
    let (bytes, _) = writer::encode(batch).unwrap();
    let seq = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
    let mut reply = Vec::new();
    let original_size = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
    reply.extend((20u32 + original_size as u32).to_ne_bytes());
    reply.extend(2u16.to_ne_bytes());
    reply.extend(0u16.to_ne_bytes());
    reply.extend(seq.to_ne_bytes());
    reply.extend(0u32.to_ne_bytes());
    reply.extend((-85i32).to_ne_bytes());
    reply.extend(&bytes[..original_size]);
    writer::rejection(batch, &reply).unwrap()
}
#[test]
fn complete_forward_nack_is_an_immutable_no_effect_outcome_and_inverse_nack_stays_unresolved() {
    for inverse in [false, true] {
        let (f, snapshot, proof, input) = fixtures::fixture();
        let request = "rejected-native";
        let receipt = fixtures::prepare(&f, &snapshot, &proof, &input, request).unwrap();
        if inverse {
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
        }
        let ticket = pending(&f, &input, &receipt, request);
        let proof = fixtures::proof(&f, &ticket, Instant::now() + Duration::from_secs(300));
        let result = run(
            &f.root,
            &ticket,
            &proof,
            77,
            action(&input, &receipt, request),
            inverse,
            |batch| Err(negative(batch).into()),
            || panic!("negative ACK must not observe forward"),
        )
        .unwrap();
        assert_eq!(
            result["state"],
            if inverse {
                "RECOVERY_REQUIRED"
            } else {
                "REJECTED"
            }
        );
        let result = outcome(&f.root, 77, original(&input, request), || {
            panic!("negative ACK cannot observe or retry")
        })
        .unwrap();
        assert_eq!(
            result["state"],
            if inverse {
                "RECOVERY_REQUIRED"
            } else {
                "REJECTED"
            }
        );
        assert_eq!(Snapshot::take(&f.root).is_ok(), !inverse);
        assert!(!f.root.join("firewall/confirmed.json").exists());
    }
}
#[test]
fn missing_capture_or_attempted_settlement_is_unknown_and_never_republished() {
    for defect in ["capture", "history", "pointer"] {
        let (f, snapshot, proof, input) = fixtures::fixture();
        let request = "lost-native";
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
        let mut record = active(&f.root).unwrap();
        let missing = match defect {
            "capture" => {
                record.state = State::Applying;
                record.forward = None;
                record.path(&f.root, "forward.json")
            }
            "history" => {
                record.state = State::Confirming;
                record.confirmed_decision = true;
                record.settlement_intent = true;
                history(&f.root, 77, request)
            }
            "pointer" => {
                let ticket = pending(&f, &input, &receipt, request);
                let proof = fixtures::proof(&f, &ticket, Instant::now() + Duration::from_secs(300));
                confirm(
                    &f.root,
                    &ticket,
                    &proof,
                    77,
                    action(&input, &receipt, request),
                )
                .unwrap();
                record = active(&f.root).unwrap();
                f.root.join("firewall/confirmed.json")
            }
            _ => unreachable!(),
        };
        if missing.exists() {
            fs::remove_file(&missing).unwrap();
        }
        save(&f.root, &record).unwrap();
        let before = fs::read(f.root.join("firewall/transaction.json")).unwrap();
        let _ = outcome(&f.root, 77, original(&input, request), || {
            panic!("missing evidence must never reobserve")
        });
        assert!(!missing.exists());
        assert_eq!(
            fs::read(f.root.join("firewall/transaction.json")).unwrap(),
            before
        );
    }
}
