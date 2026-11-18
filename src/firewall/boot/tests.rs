use super::*;
use crate::firewall::Journal;
use std::sync::atomic::Ordering;

struct Fixture {
    root: PathBuf,
    firewall: Firewall,
    intent: Intent,
    candidate: VersionedCandidate,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("fw-confirmed-boot-{}", Uuid::new_v4()));
        let firewall = Firewall::open(root.clone(), None).unwrap();
        let candidate: VersionedCandidate = serde_json::from_value(json!({
            "schemaVersion":4,
            "ipv4":{"inputPolicy":"drop","forwardPolicy":"drop","outputPolicy":"accept","allowIcmp":true},
            "ipv6":{"inputPolicy":"drop","forwardPolicy":"drop","outputPolicy":"accept","allowIcmp":true},
            "input":[], "portForward":[], "nat":[]
        })).unwrap();
        let text = candidate.render().unwrap();
        let old = Confirmed {
            revision: 0,
            text: None,
            candidate: None,
        };
        let confirmed = Confirmed {
            revision: 1,
            text: Some(text.clone()),
            candidate: Some(candidate.clone()),
        };
        firewall.persist("confirmed.json", &confirmed).unwrap();
        let journal = Journal {
            id: Uuid::new_v4().to_string(),
            state: State::Committed,
            old,
            candidate_text: text,
            candidate: candidate.clone(),
            deadline_ms: 1,
            token: "fixture-original-token".into(),
            request_id: "fixture-confirmed-policy".into(),
            confirmed_decision: true,
            kura_binding: None,
            remote_binding: None,
            remote_actions: vec![],
        };
        firewall.persist("transaction.json", &journal).unwrap();
        let attr = fs::symlink_metadata(&root).unwrap();
        let network = fs::metadata("/proc/self/ns/net").unwrap_or_else(|_| attr.clone());
        let intent = Intent {
            schema_version: 1,
            boot_id: Uuid::new_v4(),
            scope: Scope {
                root_device: attr.dev(),
                root_inode: attr.ino(),
                net_device: network.dev(),
                net_inode: network.ino(),
                owner_lease_sha256: "1".repeat(64),
                confirmed_sha256: approved_policy(&firewall).unwrap().1,
                revision: 1,
            },
        };
        Self {
            root,
            firewall,
            intent,
            candidate,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn approved_policy_requires_its_original_settled_typed_decision() {
    let fixture = Fixture::new();
    let child = &fixture.firewall;
    let (confirmed, _, _) = approved_policy(child).unwrap();
    let mut journal = child.journal().unwrap().unwrap();
    journal.state = State::WaitConfirm;
    child.persist("transaction.json", &journal).unwrap();
    assert!(approved_policy(child).is_err());
    journal.state = State::Committed;
    journal.confirmed_decision = false;
    child.persist("transaction.json", &journal).unwrap();
    assert!(approved_policy(child).is_err());
    journal.state = State::RolledBack;
    journal.old = confirmed;
    child.persist("transaction.json", &journal).unwrap();
    assert!(approved_policy(child).is_ok());
    child
        .persist("imported-confirmed.json", &json!({}))
        .unwrap();
    assert!(approved_policy(child).is_err());
    assert_eq!(child.test_backend_invocations(), 0);
}

#[test]
fn unresolved_intent_blocks_other_writes_and_new_boot_dispatch() {
    let fixture = Fixture::new();
    let path = ledger(&fixture.root);
    durable::directory(&path).unwrap();
    let intent_file = path.join(PENDING);
    let original = publish(&intent_file, &fixture.intent).unwrap();
    assert!(Guard::acquire(&fixture.root, Subsystem::Firewall).is_err());
    assert!(Guard::acquire(&fixture.root, Subsystem::Network).is_err());
    let mut next = fixture.intent.clone();
    next.boot_id = Uuid::new_v4();
    assert!(
        restore_under_guard(&fixture.firewall, &next, &fixture.candidate)
            .unwrap_err()
            .to_string()
            .starts_with("OUTCOME_UNKNOWN:")
    );
    assert_eq!(fixture.firewall.test_backend_invocations(), 0);
    assert_eq!(bytes(&intent_file, RECORD_LIMIT).unwrap(), original);
    let mut receipt = Receipt {
        intent: fixture.intent.clone(),
        intent_sha256: durable::hash(&original),
    };
    receipt.intent.scope.root_inode += 1;
    let receipt_file = receipt_path(&path, fixture.intent.boot_id);
    publish(&receipt_file, &receipt).unwrap();
    assert!(Guard::acquire(&fixture.root, Subsystem::Firewall).is_err());
    durable::remove(&receipt_file).unwrap();
    receipt.intent = fixture.intent.clone();
    publish(&receipt_file, &receipt).unwrap();
    assert!(Guard::acquire(&fixture.root, Subsystem::Firewall).is_ok());
}

#[test]
fn exclusive_compilation_never_destroys_an_existing_table() {
    let fixture = Fixture::new();
    let text = exclusive_script(&fixture.candidate).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| *line == "create table inet yofc_kura")
            .count(),
        1
    );
    assert!(!text.contains("destroy table"));
    assert!(text.contains("table inet yofc_kura {"));
}

#[test]
fn a_fresh_root_cannot_supply_an_owner_by_confirmed_policy_alone() {
    let fixture = Fixture::new();
    assert!(crate::nm::handover::confirmed_private_firewall_boot_owner(&fixture.root).is_err());
    assert_eq!(fixture.firewall.test_backend_invocations(), 0);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a fresh unshared network namespace with CAP_NET_ADMIN"]
fn actual_boot_creates_once_and_observes_the_same_receipt() {
    let fixture = Fixture::new();
    let engine = &fixture.firewall;
    engine.0.real.store(true, Ordering::Relaxed);
    let _guard = Guard::acquire(&fixture.root, Subsystem::FirewallBoot).unwrap();
    let result = restore_under_guard(engine, &fixture.intent, &fixture.candidate).unwrap();
    assert_eq!(result["state"], "RESTORED");
    let path = ledger(&fixture.root);
    let receipt = receipt_path(&path, fixture.intent.boot_id);
    let before = bytes(&receipt, RECORD_LIMIT).unwrap();
    assert!(!path.join(PENDING).exists());
    let calls = engine.test_backend_invocations();
    let again = restore_under_guard(engine, &fixture.intent, &fixture.candidate).unwrap();
    assert_eq!(again["state"], "ALREADY_RESTORED");
    assert_eq!(engine.test_backend_invocations(), calls + 1);
    assert_eq!(bytes(&receipt, RECORD_LIMIT).unwrap(), before);
    let mut wrong = fixture.intent.clone();
    wrong.scope.net_inode += 1;
    assert!(restore_under_guard(engine, &wrong, &fixture.candidate).is_err());
    assert_eq!(engine.test_backend_invocations(), calls + 2);
    assert_eq!(bytes(&receipt, RECORD_LIMIT).unwrap(), before);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a fresh unshared network namespace with CAP_NET_ADMIN"]
fn actual_boot_refuses_a_foreign_table_without_writing() {
    let fixture = Fixture::new();
    let engine = &fixture.firewall;
    engine.0.real.store(true, Ordering::Relaxed);
    engine
        .run_nft(
            &["-f", "-"],
            Some("create table inet yofc_boot_test_site\n"),
        )
        .unwrap();
    let _guard = Guard::acquire(&fixture.root, Subsystem::FirewallBoot).unwrap();
    let before = engine
        .run_nft(&["-j", "-p", "list", "ruleset"], None)
        .unwrap();
    let failure = restore_under_guard(engine, &fixture.intent, &fixture.candidate).unwrap_err();
    assert!(failure.to_string().contains("another firewall writer"));
    assert_eq!(
        engine
            .run_nft(&["-j", "-p", "list", "ruleset"], None)
            .unwrap(),
        before
    );
    assert!(!ledger(&fixture.root).exists());
}
