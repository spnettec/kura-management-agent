//! Synthetic procfs and startup-child files only. There is no actual committed
//! owner lease, registered JVM or OS service here, and no kernel write is made.
use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::symlink;

fn witness(
    f: &Fixture,
    challenge: &CompletionChallenge,
    observer: uuid::Uuid,
    epoch: u64,
) -> CompletionWitness {
    let source = roles::Observation::new(
        f.original.baseline.roles.agent_instance,
        epoch,
        serde_json::to_value(&f.original.baseline.roles.roles).unwrap(),
    )
    .unwrap();
    let mut report = challenge.spec.parameters();
    report["schemaVersion"] = json!(1);
    report["observerInstanceId"] = json!(observer);
    report["profileId"] = json!(challenge.profile_id);
    report["processId"] = json!(challenge.unit.pid);
    report["frameworkStartLevel"] = json!(6);
    report["ordinaryLoad"] = json!(true);
    let association =
        roles::StartupAssociation::new(source.agent_instance, source.bridge_epoch, report).unwrap();
    let owner=roles::Owner::new(source.agent_instance,source.bridge_epoch,
        json!({"schemaVersion":2,"pid":roles::PID,"operationId":f.original.operation,"planSha256":f.original.plan,
            "mirrorSha256":f.original.template,"roles":source.roles,
            "firewall":{"schemaVersion":1,"pids":[roles::FIREWALL_V4_PID,roles::FIREWALL_V6_PID],
            "revision":"1","sourceDigest":"e".repeat(64)}})).unwrap();
    CompletionWitness {
        roles: source,
        association,
        owner,
    }
}
fn ready() -> (Fixture, uuid::Uuid, CompletionWitness) {
    let mut f = Fixture::new();
    let published = f.published();
    enable_start_at(&f.root, "success");
    let token = published["confirmationToken"].as_str().unwrap();
    let StartStep::Dispatch(command) = start_begin(
        &f.store,
        &f.original,
        "local-uid:fixture",
        token,
        &f.installed.systemctl,
    )
    .unwrap() else {
        panic!("fresh synthetic startup")
    };
    (*command).execute().unwrap();
    let CompletionStep::Challenge(challenge) = completion_begin(
        &f.store,
        &f.original,
        "local-uid:fixture",
        token,
        &f.installed.systemctl,
    )
    .unwrap() else {
        panic!("fresh synthetic terminal proof")
    };
    let observer = uuid::Uuid::new_v4();
    let current = witness(&f, &challenge, observer, 2);
    let stored = witness(&f, &challenge, observer, 2);
    completion_finish(
        &f.store,
        &f.original,
        "local-uid:fixture",
        token,
        &challenge,
        stored,
        &f.installed.systemctl,
    )
    .unwrap();
    // This models the caller's input shape only; no actual root owner lease is
    // installed. Production Store.current_runtime_challenge checks that lease.
    f.original.state = State::Committed;
    assert!(!f.store.join("confirmed.json").exists());
    (f, observer, current)
}
fn put(path: &Path, value: &[u8]) {
    durable::directory(path.parent().unwrap()).unwrap();
    durable::write(path, value, FileMetadata::private()).unwrap();
}
fn stat(pid: u32, ticks: u64) -> String {
    let mut fields = vec!["0".to_string(); 50];
    fields[0] = "S".into();
    fields[1] = "1".into();
    fields[19] = ticks.to_string();
    format!("{pid} (fixture (java) with ) name) {}\n", fields.join(" "))
}
fn proc_fixture(f: &Fixture, pid: u32, ticks: u64) -> PathBuf {
    let root = f
        .root
        .join(format!("synthetic-proc-{}", uuid::Uuid::new_v4()));
    durable::directory(&root).unwrap();
    put(
        &root.join("sys/kernel/random/boot_id"),
        format!("{}\n", uuid::Uuid::new_v4()).as_bytes(),
    );
    put(
        &root.join("self/cgroup"),
        b"0::/fixture-independent-agent.service\n",
    );
    let process = root.join(pid.to_string());
    put(&process.join("stat"), stat(pid, ticks).as_bytes());
    put(
        &process.join("status"),
        b"Name:\tjava\nUid:\t77 77 77 77\nGid:\t77 77 77 77\n",
    );
    put(
        &process.join("cgroup"),
        b"0::/system.slice/yofc-kura-fixture.service\n",
    );
    put(
        &process.join("cmdline"),
        b"/usr/bin/java\0@synthetic-fixture-args\0",
    );
    let image = root.join("not-an-executed-image");
    put(&image, b"synthetic-process-evidence-only-never-execute");
    symlink(&image, process.join("exe")).unwrap();
    root
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, String> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            files.extend(snapshot(&path));
        } else if path.is_file() {
            files.insert(path.clone(), durable::hash(&fs::read(path).unwrap()));
        }
    }
    files
}
#[test]
fn current_os_context_is_read_only_and_process_boot_or_credential_changes_invalidate_a_sampled_challenge()
 {
    let (f, _, witness) = ready();
    let proc = proc_fixture(&f, 5432, 1000);
    let original = snapshot(&f.store);
    let challenge =
        runtime::fixture_challenge(&f.store, &f.original, &f.installed.systemctl, &proc).unwrap();
    let receipt = runtime::fixture_finish(
        &f.store,
        &f.original,
        &challenge,
        &witness,
        &f.installed.systemctl,
        &proc,
    )
    .unwrap();
    assert_eq!(
        receipt,
        challenge.parameters()["originalStartupReceiptSha256"]
    );
    assert_eq!(challenge.parameters()["process"]["startTicks"], 1000);
    assert_eq!(challenge.parameters()["ownerGrant"], false);
    for defect in ["ticks", "boot", "uid"] {
        let path = match defect {
            "ticks" => proc.join("5432/stat"),
            "boot" => proc.join("sys/kernel/random/boot_id"),
            _ => proc.join("5432/status"),
        };
        let old = fs::read(&path).unwrap();
        let changed = match defect {
            "ticks" => stat(5432, 1001).into_bytes(),
            "boot" => format!("{}\n", uuid::Uuid::new_v4()).into_bytes(),
            _ => b"Name:\tjava\nUid:\t88 88 88 88\nGid:\t77 77 77 77\n".to_vec(),
        };
        put(&path, &changed);
        assert!(
            runtime::fixture_finish(
                &f.store,
                &f.original,
                &challenge,
                &witness,
                &f.installed.systemctl,
                &proc
            )
            .is_err()
        );
        put(&path, &old);
    }
    assert_eq!(snapshot(&f.store), original);
}
#[test]
fn new_unit_invocation_uses_a_new_live_witness_without_relaxing_historical_activation_or_rewriting_receipts()
 {
    let (f, old_observer, _) = ready();
    let original = snapshot(&f.store);
    put(&f.root.join("unit-state"),b"LoadState=loaded\nActiveState=active\nMainPID=6432\nInvocationID=cccccccccccccccccccccccccccccccc\nControlGroup=/system.slice/yofc-kura-fixture.service\nUnitFileState=disabled\n");
    let proc = proc_fixture(&f, 6432, 2000);
    assert!(
        activation_challenge(&f.store, &f.original, &f.installed.systemctl).is_err(),
        "original strict activation must remain unchanged"
    );
    let challenge =
        runtime::fixture_challenge(&f.store, &f.original, &f.installed.systemctl, &proc).unwrap();
    assert_eq!(challenge.parameters()["originalUnit"]["pid"], 5432);
    assert_eq!(challenge.parameters()["currentUnit"]["pid"], 6432);
    let replay = witness(&f, challenge.completion(), old_observer, 3);
    assert!(
        runtime::fixture_finish(
            &f.store,
            &f.original,
            &challenge,
            &replay,
            &f.installed.systemctl,
            &proc
        )
        .is_err()
    );
    let current = witness(&f, challenge.completion(), uuid::Uuid::new_v4(), 3);
    runtime::fixture_finish(
        &f.store,
        &f.original,
        &challenge,
        &current,
        &f.installed.systemctl,
        &proc,
    )
    .unwrap();
    assert_eq!(snapshot(&f.store), original);
    assert!(
        fs::read_to_string(&f.installed.calls)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("show "))
            .all(|line| line.starts_with("start ") || line.starts_with("stop "))
    );
}
#[test]
fn proc_identity_malformed_or_self_cgroup_cannot_substitute_for_a_current_process() {
    let (f, _, _) = ready();
    for defect in [
        "pid", "zombie", "ticks", "uid", "group", "self", "boot", "cmdline", "exe",
    ] {
        let proc = proc_fixture(&f, 5432, 1000);
        match defect {
            "pid" => put(&proc.join("5432/stat"), stat(9000, 1000).as_bytes()),
            "zombie" => put(
                &proc.join("5432/stat"),
                stat(5432, 1000).replace(") S ", ") Z ").as_bytes(),
            ),
            "ticks" => put(&proc.join("5432/stat"), stat(5432, 0).as_bytes()),
            "uid" => put(&proc.join("5432/status"), b"Uid: 77 77\nGid: 77 77 77 77\n"),
            "group" => put(
                &proc.join("5432/cgroup"),
                b"0::/system.slice/foreign.service\n",
            ),
            "self" => put(
                &proc.join("self/cgroup"),
                b"0::/system.slice/yofc-kura-fixture.service\n",
            ),
            "boot" => put(
                &proc.join("sys/kernel/random/boot_id"),
                b"00000000-0000-0000-0000-000000000000\n",
            ),
            "cmdline" => put(&proc.join("5432/cmdline"), b"missing-final-null"),
            "exe" => {
                fs::remove_file(proc.join("5432/exe")).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            runtime::fixture_challenge(&f.store, &f.original, &f.installed.systemctl, &proc)
                .is_err(),
            "{defect}"
        );
    }
}
#[test]
fn current_context_requires_original_terminal_selected_files_and_pinned_service_definition() {
    for defect in ["receipt", "profile", "definition", "uncommitted"] {
        let (mut f, _, _) = ready();
        let proc = proc_fixture(&f, 5432, 1000);
        match defect {
            "receipt" => {
                fs::remove_file(
                    f.store
                        .join(format!("{}.startup-completion.json", f.original.operation)),
                )
                .unwrap();
            }
            "profile" => {
                let selected = f
                    .store
                    .join(format!("{}.startup-profile.json", f.original.operation));
                let before = fs::metadata(&selected).unwrap().ino();
                let replacement = f.store.join("replacement-selected-profile.json");
                put(&replacement, &fs::read(&selected).unwrap());
                fs::rename(&replacement, &selected).unwrap();
                assert_ne!(fs::metadata(&selected).unwrap().ino(), before);
            }
            "definition" => put(
                &f.root.join("unit-stop-policy"),
                b"ExecStop=\nSlice=system.slice\nKillMode=process\nTimeoutStopUSec=3s\n",
            ),
            "uncommitted" => f.original.state = State::Fenced,
            _ => unreachable!(),
        }
        assert!(
            runtime::fixture_challenge(&f.store, &f.original, &f.installed.systemctl, &proc)
                .is_err(),
            "{defect}"
        );
    }
}

fn stopped_unit(f: &Fixture) {
    put(&f.root.join("unit-state"),b"LoadState=loaded\nActiveState=inactive\nMainPID=0\nInvocationID=\nControlGroup=\nUnitFileState=disabled\n");
}

#[test]
fn stopped_current_context_is_a_read_only_distinct_observation_without_a_jvm_witness_or_owner_grant()
 {
    let (f, _, _) = ready();
    crate::nm::handover::native::epoch::Epoch::with_storage_fixture(|| {
        assert!(!stopped::hint(&f.store, &f.original, &f.installed.systemctl).unwrap());
        assert!(
            stopped::challenge(&f.store, &f.original, &f.installed.systemctl).is_err(),
            "a running service never becomes a stopped grant after a failed live read"
        );
        stopped_unit(&f);
        let before = snapshot(&f.store);
        let actions = fs::read_to_string(&f.installed.calls)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("show "))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert!(stopped::hint(&f.store, &f.original, &f.installed.systemctl).unwrap());
        let proof = stopped::challenge(&f.store, &f.original, &f.installed.systemctl).unwrap();
        let value = proof.parameters();
        assert_eq!(value["originalUnit"]["pid"], 5432);
        assert_eq!(value["currentUnit"]["pid"], 0);
        assert_eq!(value["currentJvmWitness"], false);
        assert_eq!(value["ownerGrant"], false);
        assert_eq!(
            stopped::finish(&f.store, &f.original, &proof, &f.installed.systemctl).unwrap(),
            value["originalStartupReceiptSha256"]
        );
        proof
            .epoch()
            .require(&crate::nm::handover::native::epoch::Epoch::capture().unwrap())
            .unwrap();
        assert_eq!(snapshot(&f.store), before);
        assert_eq!(
            fs::read_to_string(&f.installed.calls)
                .unwrap()
                .lines()
                .filter(|line| !line.starts_with("show "))
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            actions
        );
    });
}

#[test]
fn stopped_current_context_rechecks_original_anchor_selected_identity_policy_and_actual_service_state()
 {
    for defect in [
        "receipt",
        "profile",
        "definition",
        "running",
        "transition",
        "invocation",
        "uncommitted",
    ] {
        let (mut f, _, _) = ready();
        stopped_unit(&f);
        crate::nm::handover::native::epoch::Epoch::with_storage_fixture(|| {
            let proof = stopped::challenge(&f.store, &f.original, &f.installed.systemctl).unwrap();
            match defect {
                "receipt" => fs::remove_file(f.store.join(format!("{}.startup-completion.json",f.original.operation))).unwrap(),
                "profile" => {
                    let selected=f.store.join(format!("{}.startup-profile.json",f.original.operation));
                    let replacement=f.store.join("new-selected-profile.json");
                    put(&replacement,&fs::read(&selected).unwrap());fs::rename(replacement,selected).unwrap();
                }
                "definition" => put(&f.root.join("unit-stop-policy"),b"ExecStop=\nSlice=system.slice\nKillMode=process\nTimeoutStopUSec=3s\n"),
                "running" => put(&f.root.join("unit-state"),b"LoadState=loaded\nActiveState=active\nMainPID=6432\nInvocationID=cccccccccccccccccccccccccccccccc\nControlGroup=/system.slice/yofc-kura-fixture.service\nUnitFileState=disabled\n"),
                "transition" => put(&f.root.join("unit-state"),b"LoadState=loaded\nActiveState=activating\nMainPID=0\nInvocationID=\nControlGroup=\nUnitFileState=disabled\n"),
                "invocation" => put(&f.root.join("unit-state"),b"LoadState=loaded\nActiveState=inactive\nMainPID=0\nInvocationID=dddddddddddddddddddddddddddddddd\nControlGroup=\nUnitFileState=disabled\n"),
                "uncommitted" => f.original.state=State::Fenced,
                _ => unreachable!(),
            }
            let changed = snapshot(&f.store);
            assert!(
                stopped::finish(&f.store, &f.original, &proof, &f.installed.systemctl).is_err(),
                "{defect}"
            );
            assert_eq!(
                snapshot(&f.store),
                changed,
                "a stopped query never repairs changed original evidence"
            );
        });
    }
}
