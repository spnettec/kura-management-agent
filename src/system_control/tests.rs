use super::*;
use prost::Message;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    dir: PathBuf,
    control: Control,
    local: crate::local::Local,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
impl Fixture {
    fn business_profile(&self) {
        let args = self.dir.join("ordinary.args");
        durable::write(&args,b"-Xmx256m\n-Dkura.management.ordinary.profile.id=profile-11111111-1111-1111-1111-111111111111\n-Dkura.management.ordinary.verification.enabled=true\n",FileMetadata::private()).unwrap();
        let file = self.dir.join("target.service");
        let basic = format!(
            "FragmentPath={}\nDropInPaths=\nExecStart={{ path=/test/java ; argv[]=/test/java @{} -jar /test/launcher.jar ; ignore_errors=no ; pid=0 }}\nEnvironment=\nEnvironmentFiles=\nUnsetEnvironment=JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS\nNeedDaemonReload=no\n",
            file.display(),
            args.display()
        );
        let definition = basic
            .lines()
            .map(|s| s.split_once('=').unwrap())
            .map(|(k, v)| {
                (
                    k.to_owned(),
                    v.split(" ; ignore_errors=").next().unwrap().to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>()
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect::<String>();
        durable::write(
            &self.dir.join("basic-definition"),
            basic.as_bytes(),
            FileMetadata::private(),
        )
        .unwrap();
        durable::write(&self.dir.join("definition"),format!("{basic}ExecStop=\nSlice=system.slice\nKillMode=control-group\nTimeoutStopUSec=20s\n").as_bytes(),FileMetadata::private()).unwrap();
        let script=fs::read_to_string(&self.control.native.systemctl).unwrap().replace("then cat \"$FIXTURE_ROOT/definition\"; exit 0; fi", "then case \"$4\" in *TimeoutStopUSec*) cat \"$FIXTURE_ROOT/definition\";; *) cat \"$FIXTURE_ROOT/basic-definition\";; esac; exit 0; fi");
        fs::write(&self.control.native.systemctl, script).unwrap();
        let profile = self.dir.join("ordinary.json");
        durable::json(&profile,&json!({"schema":1,"profileId":"profile-11111111-1111-1111-1111-111111111111","unit":"yofc-kura-system-fixture.service","unitFile":file,"jvmArgsPath":args,"unitDefinitionSha256":durable::hash(definition.as_bytes()),"timeoutSeconds":2,"validForSeconds":300,"componentPids":["pid"],"checkIds":["business.check"],"profileFiles":[{"path":file,"sha256":durable::hash(&fs::read(&file).unwrap())},{"path":args,"sha256":durable::hash(&fs::read(&args).unwrap())}]})).unwrap();
        let snapshots = self.dir.join("snapshots");
        durable::directory(&snapshots).unwrap();
        durable::write(
            &snapshots.join("snapshot_1.xml"),
            b"<test-only-snapshot/>",
            FileMetadata::private(),
        )
        .unwrap();
        let mut c: Config =
            serde_json::from_slice(&fs::read(&self.control.native.config).unwrap()).unwrap();
        c.ordinary_profile = Some(profile);
        c.snapshot_directory = Some(snapshots);
        durable::json(&self.control.native.config, &c).unwrap();
        let sealed = self.dir.join("business-grant.json");
        grant::seal(
            &self.control.native.config,
            &sealed,
            &self.control.native.systemctl,
        )
        .unwrap();
        durable::write(
            &self.control.native.config,
            &fs::read(sealed).unwrap(),
            FileMetadata::private(),
        )
        .unwrap();
        self.control.native.inputs().unwrap();
    }
    async fn new() -> Self {
        // Application snapshot fixtures need the same protected ancestors as
        // deployment sources; /tmp is intentionally not accepted by the grant.
        let test_root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/yofc-management-agent-system-tests");
        fs::create_dir_all(&test_root).unwrap();
        fs::set_permissions(&test_root, fs::Permissions::from_mode(0o700)).unwrap();
        let dir = test_root
            .canonicalize()
            .unwrap()
            .join(format!("system-control-{}", uuid::Uuid::new_v4()));
        durable::directory(&dir).unwrap();
        let root = dir.join("state");
        durable::directory(&root).unwrap();
        let state = root.join("system-control");
        for p in [
            &state,
            &state.join("commands"),
            &state.join("receipts"),
            &state.join("history"),
        ] {
            durable::directory(p).unwrap();
        }
        let unit = "yofc-kura-system-fixture.service";
        let file = dir.join("target.service");
        durable::write(
            &file,
            b"fixed reviewed test-only service",
            FileMetadata::private(),
        )
        .unwrap();
        let declaration = format!(
            "FragmentPath={}\nDropInPaths=\nExecStart={{ path=/test/java ; argv[]=/test/java -jar /test/launcher.jar ; ignore_errors=no ; pid=0 }}\nExecStop=\nEnvironment=\nEnvironmentFiles=\nUnsetEnvironment=JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS\nNeedDaemonReload=no\nSlice=system.slice\nKillMode=control-group\nTimeoutStopUSec=20s\n",
            file.display()
        );
        durable::write(
            &dir.join("definition"),
            declaration.as_bytes(),
            FileMetadata::private(),
        )
        .unwrap();
        let mut fields = declaration
            .lines()
            .map(|s| s.split_once('=').unwrap())
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect::<BTreeMap<_, _>>();
        let v = fields.get_mut("ExecStart").unwrap();
        *v = v.split(" ; ignore_errors=").next().unwrap().to_owned();
        let definition = durable::hash(
            fields
                .iter()
                .map(|(k, v)| format!("{k}={v}\n"))
                .collect::<String>()
                .as_bytes(),
        );
        let config = Config {
            schema: 1,
            unit: unit.into(),
            unit_file: file.clone(),
            unit_definition_sha256: definition,
            files: vec![grant::File {
                path: file,
                sha256: durable::hash(b"fixed reviewed test-only service"),
            }],
            ordinary_profile: None,
            snapshot_directory: None,
            allow_restart: true,
            allow_reboot: true,
            confirmation_seconds: 300,
            observation_seconds: 10,
            restart_timeout_seconds: 20,
        };
        let config_path = dir.join("grant.json");
        durable::json(&config_path, &config).unwrap();
        let script = dir.join("systemctl");
        fs::write(&script,format!(r#"#!/bin/sh
FIXTURE_ROOT='{}'
printf '%s\n' "$*" >> "$FIXTURE_ROOT/calls"
case "$1" in
show)
 if [ "$3" = --all ]; then cat "$FIXTURE_ROOT/definition"; exit 0; fi
 echo LoadState=loaded; echo ActiveState=active
 if [ -f "$FIXTURE_ROOT/restarted" ]; then echo MainPID=234; echo InvocationID={}; else echo MainPID=123; echo InvocationID={}; fi
 echo ControlGroup=/system.slice/{}
 echo UnitFileState=enabled;;
restart) touch "$FIXTURE_ROOT/restarted";;
*) exit 4;;
esac
"#,dir.display(),"b".repeat(32),"a".repeat(32),unit)).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let scheduler = dir.join("systemd-run");
        fs::write(
            &scheduler,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}/scheduled'\n",
                dir.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&scheduler, fs::Permissions::from_mode(0o700)).unwrap();
        let boot = dir.join("boot-id");
        durable::write(
            &boot,
            uuid::Uuid::new_v4().to_string().as_bytes(),
            FileMetadata::private(),
        )
        .unwrap();
        let db = crate::transport::database(root.join("results.sqlite").to_str().unwrap())
            .await
            .unwrap();
        let n = Native {
            root,
            config: config_path,
            systemctl: script,
            systemd_run: scheduler,
            boot_id: boot,
        };
        n.inputs().unwrap();
        Self {
            dir,
            control: Control {
                native: Arc::new(n),
                db,
            },
            local: crate::local::Local::new(unsafe { libc::geteuid() }, unsafe { libc::geteuid() }),
        }
    }
    fn command(&self, operation: i32, plan: Option<&Value>) -> ReadCommand {
        ReadCommand {
            command_id: uuid::Uuid::new_v4().to_string(),
            operation,
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            expires_at_unix_ms: i64::MAX,
            system_control_action: plan.map(|v| SystemControlAction {
                transaction_id: v["id"].as_str().unwrap().into(),
                confirmation_token: v["confirmToken"].as_str().unwrap().into(),
            }),
            ..Default::default()
        }
    }
    async fn run(&self, command: &ReadCommand) -> Result<TaskResult> {
        let hash = durable::hash(&command.encode_to_vec());
        ensure!(
            crate::journal::claim(&self.control.db, command, &hash)
                .await?
                .is_none(),
            "test requires a fresh original command"
        );
        let value = self
            .control
            .request(
                command.operation,
                command.system_control_action.clone(),
                Some(command),
                self.local.clone(),
            )
            .await?;
        let result = self.control.command_result(command, value).await?;
        crate::journal::finish(&self.control.db, &hash, result).await
    }
    fn calls(&self) -> Vec<u8> {
        fs::read(self.dir.join("calls")).unwrap_or_default()
    }
    fn starts(&self) -> usize {
        String::from_utf8(self.calls())
            .unwrap()
            .lines()
            .filter(|s| s.starts_with("restart "))
            .count()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_application_observation_waits_for_readiness_and_never_repeats_a_failed_check() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for scenario in ["ready", "failed", "duplicate", "wrong-pid", "boot-drift"] {
        let f = Fixture::new().await;
        f.business_profile();
        let prepared = f.run(&f.command(24, None)).await.unwrap();
        let p: Value = serde_json::from_slice(&prepared.result_json).unwrap();
        let execute = f.command(25, Some(&p));
        let mut rx = f.local.install_test_bridge(&["kura.ordinary.verify"]).await;
        let local = f.local.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let boot = f.control.native.boot_id.clone();
        let bridge = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let n = observed.fetch_add(1, Ordering::SeqCst);
                let q = frame.params.unwrap();
                let ready = scenario != "ready" || n > 0;
                if scenario == "boot-drift" {
                    durable::write(
                        &boot,
                        uuid::Uuid::new_v4().to_string().as_bytes(),
                        FileMetadata::private(),
                    )
                    .unwrap();
                }
                let report = json!({"schema":2,"handoffId":q["handoffId"],"profileId":q["profileId"],"nonce":q["nonce"],"approvedSnapshotSha256":q["snapshotSha256"],"observerInstanceId":uuid::Uuid::new_v4().to_string(),"processId":if scenario=="wrong-pid"{345}else{234},"frameworkStartLevel":5,"ordinaryLoad":true,"ready":ready,"components":[{"pid":"pid","registered":true}],"providers":[{"id":"business.check","available":ready,"unique":ready&&scenario!="duplicate"}],"checks":[{"id":"business.check","passed":ready&&scenario!="failed"&&scenario!="duplicate"}]});
                local.complete_pending(&frame.request_id, Some(report), None);
            }
        });
        let result = f.run(&execute).await;
        if scenario == "boot-drift" {
            assert!(result.is_err());
            assert_eq!(
                f.control.native.journal().unwrap().unwrap().state,
                State::RecoveryRequired
            );
            assert!(f.control.prove(&execute).await.unwrap().is_none());
        } else {
            let result = result.unwrap();
            assert_eq!(
                result.state,
                if scenario == "ready" {
                    TaskState::Succeeded
                } else {
                    TaskState::Failed
                } as i32,
                "{scenario}"
            );
            let value: Value = serde_json::from_slice(&result.result_json).unwrap();
            assert_eq!(value["applicationVerified"], scenario == "ready");
            assert_eq!(value["scope"], "administrator-selected-checks");
            assert_eq!(value["kuraRecoveryVerified"], false);
            let calls = f.calls();
            assert!(f.control.prove(&execute).await.unwrap().is_some());
            assert_eq!(f.calls(), calls);
        }
        assert_eq!(
            count.load(Ordering::SeqCst),
            if scenario == "ready" { 2 } else { 1 }
        );
        assert_eq!(f.starts(), 1);
        bridge.abort();
        f.control.db.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_default_off_and_original_reboot_receipt_reconcile_once_without_replay() {
    let f = Fixture::new().await;
    let mut local = f.local.clone();
    local.system_control = Some(f.control.clone());
    let denied = crate::transport::execute(&f.control.db, &local, f.command(26, None))
        .await
        .unwrap();
    assert_eq!(denied.error, ErrorCode::Unsupported as i32);
    assert!(!f.control.native.path().exists());
    local.system_control_remote = true;
    let prepared = crate::transport::execute(&f.control.db, &local, f.command(26, None))
        .await
        .unwrap();
    let p: Value = serde_json::from_slice(&prepared.result_json).unwrap();
    let command = f.command(27, Some(&p));
    let pending = crate::transport::execute(&f.control.db, &local, command.clone())
        .await
        .unwrap();
    assert_eq!(pending.state, TaskState::Unknown as i32);
    let schedule = fs::read(f.dir.join("scheduled")).unwrap();
    assert_eq!(
        crate::transport::execute(&f.control.db, &local, command.clone())
            .await
            .unwrap(),
        pending
    );
    assert_eq!(
        crate::transport::query_receipt(&f.control.db, &local, &command.command_id)
            .await
            .unwrap(),
        pending
    );
    // Reopen the actual private SQLite database and construct a fresh agent
    // control object. Pending reboot admission survives process replacement.
    f.control.db.close().await;
    let db = crate::transport::database(
        f.control
            .native
            .root
            .join("results.sqlite")
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap();
    let resumed = Control {
        native: f.control.native.clone(),
        db: db.clone(),
    };
    let mut local =
        crate::local::Local::new(unsafe { libc::geteuid() }, unsafe { libc::geteuid() });
    local.system_control = Some(resumed.clone());
    local.system_control_remote = true;
    assert_eq!(
        crate::transport::execute(&db, &local, command.clone())
            .await
            .unwrap(),
        pending
    );
    durable::write(
        &f.control.native.boot_id,
        uuid::Uuid::new_v4().to_string().as_bytes(),
        FileMetadata::private(),
    )
    .unwrap();
    fs::write(f.dir.join("restarted"), b"new boot test-only process").unwrap();
    resumed.observe_pending(local.clone()).await.unwrap();
    let calls = f.calls();
    let j = fs::read(f.control.native.path()).unwrap();
    let (a, b) = tokio::join!(
        crate::transport::query_receipt(&db, &local, &command.command_id),
        crate::transport::query_receipt(&db, &local, &command.command_id)
    );
    let a = a.unwrap();
    assert_eq!(a, b.unwrap());
    assert_eq!(a.state, TaskState::Succeeded as i32);
    assert_eq!(fs::read(f.dir.join("scheduled")).unwrap(), schedule);
    assert_eq!(f.calls(), calls);
    assert_eq!(fs::read(f.control.native.path()).unwrap(), j);
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM execution_resolutions WHERE command_id=?")
            .bind(&command.command_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(count, 1);
    db.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_restart_binds_original_command_and_proof_never_observes_or_restarts_again() {
    let f = Fixture::new().await;
    let prepare = f.command(24, None);
    let p = f.run(&prepare).await.unwrap();
    let p: Value = serde_json::from_slice(&p.result_json).unwrap();
    assert_eq!(p["state"], "PREPARED");
    assert_eq!(f.starts(), 0);
    let execute = f.command(25, Some(&p));
    let done = f.run(&execute).await.unwrap();
    assert_eq!(done.state, TaskState::Succeeded as i32);
    let value: Value = serde_json::from_slice(&done.result_json).unwrap();
    assert_eq!(value["processRestartVerified"], true);
    assert_eq!(value["hostRebootVerified"], false);
    assert_eq!(value["applicationVerificationConfigured"], false);
    assert_eq!(value["applicationVerified"], false);
    assert_eq!(value["scope"], "system-process-only");
    assert_eq!(value["kuraRecoveryVerified"], false);
    assert_eq!(f.starts(), 1);
    let native = fs::read(f.control.native.path()).unwrap();
    let status = f
        .control
        .request(23, None, None, f.local.clone())
        .await
        .unwrap();
    assert_eq!(status["transaction"], value);
    assert!(status["transaction"].get("confirmToken").is_none());
    assert_eq!(fs::read(f.control.native.path()).unwrap(), native);
    let calls = f.calls();
    for _ in 0..2 {
        let proof = f.control.prove(&execute).await.unwrap().unwrap();
        assert_eq!(proof.state, TaskState::Succeeded as i32);
        let mut result: Value = serde_json::from_slice(&proof.result_json).unwrap();
        assert_eq!(
            result["reconciliation"]["source"],
            "system.control.journal.v1"
        );
        result.as_object_mut().unwrap().remove("reconciliation");
        assert_eq!(result, value);
    }
    assert_eq!(f.calls(), calls);
    assert_eq!(fs::read(f.control.native.path()).unwrap(), native);
    for field in 0..5 {
        let mut wrong = execute.clone();
        match field {
            0 => wrong.expires_at_unix_ms -= 1,
            1 => wrong.idempotency_key.push('x'),
            2 => wrong.command_id = uuid::Uuid::new_v4().to_string(),
            3 => {
                wrong
                    .system_control_action
                    .as_mut()
                    .unwrap()
                    .confirmation_token = uuid::Uuid::new_v4().to_string()
            }
            _ => wrong.operation = 27,
        };
        assert!(f.control.prove(&wrong).await.unwrap().is_none());
    }
    // A later legitimate plan archives this result before replacing the mutable journal.
    let next = f.command(26, None);
    f.run(&next).await.unwrap();
    let after = f.calls();
    assert!(f.control.prove(&execute).await.unwrap().is_some());
    assert!(f.control.prove(&prepare).await.unwrap().is_some());
    assert_eq!(f.calls(), after);
    f.control.db.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reboot_acknowledgement_waits_for_a_new_boot_and_never_schedules_twice() {
    let f = Fixture::new().await;
    let prepared = f.run(&f.command(26, None)).await.unwrap();
    let p: Value = serde_json::from_slice(&prepared.result_json).unwrap();
    let command = f.command(27, Some(&p));
    let result = f.run(&command).await.unwrap();
    assert_eq!(result.state, TaskState::Unknown as i32);
    assert_eq!(
        serde_json::from_slice::<Value>(&result.result_json).unwrap()["requestAccepted"],
        true
    );
    assert!(f.control.prove(&command).await.unwrap().is_none());
    f.control.observe_pending(f.local.clone()).await.unwrap();
    assert!(f.control.prove(&command).await.unwrap().is_none());
    let schedule = fs::read(f.dir.join("scheduled")).unwrap();
    assert_eq!(
        String::from_utf8(schedule.clone()).unwrap().lines().count(),
        1
    );
    durable::write(
        &f.control.native.boot_id,
        uuid::Uuid::new_v4().to_string().as_bytes(),
        FileMetadata::private(),
    )
    .unwrap();
    fs::write(f.dir.join("restarted"), b"new boot test-only process").unwrap();
    f.control.observe_pending(f.local.clone()).await.unwrap();
    let calls = f.calls();
    let final_result = f.control.prove(&command).await.unwrap().unwrap();
    let v: Value = serde_json::from_slice(&final_result.result_json).unwrap();
    assert_eq!(v["hostRebootVerified"], true);
    assert_eq!(v["processRestartVerified"], true);
    assert_eq!(v["applicationVerified"], false);
    f.control.observe_pending(f.local.clone()).await.unwrap();
    assert_eq!(f.calls(), calls);
    assert_eq!(fs::read(f.dir.join("scheduled")).unwrap(), schedule);
    assert_eq!(f.starts(), 0);
    f.control.db.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_is_only_for_unissued_plans_and_does_not_clear_unrelated_recovery_required() {
    let f = Fixture::new().await;
    let prepare = f.command(24, None);
    let result = f.run(&prepare).await.unwrap();
    let p: Value = serde_json::from_slice(&result.result_json).unwrap();
    durable::directory(&f.control.native.root.join("firewall")).unwrap();
    durable::json(
        &f.control.native.root.join("firewall/transaction.json"),
        &json!({"state":"RECOVERY_REQUIRED"}),
    )
    .unwrap();
    let calls = f.calls();
    let cancelled = f.run(&f.command(28, Some(&p))).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&cancelled.result_json).unwrap()["state"],
        "CANCELLED"
    );
    assert_eq!(f.calls(), calls);
    assert!(
        Guard::acquire(
            &f.control.native.root,
            crate::system_change::Subsystem::Configuration
        )
        .is_ok()
    ); // firewall is deliberately independent of online CM
    assert!(
        Guard::acquire(
            &f.control.native.root,
            crate::system_change::Subsystem::Network
        )
        .is_err()
    );
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(f.control.native.root.join("firewall/transaction.json")).unwrap()
        )
        .unwrap()["state"],
        "RECOVERY_REQUIRED"
    );
    assert!(f.control.prove(&prepare).await.unwrap().is_some());
    f.control.db.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_issue_and_orphan_evidence_fail_closed_without_replay() {
    let f = Fixture::new().await;
    let result = f.run(&f.command(24, None)).await.unwrap();
    let p: Value = serde_json::from_slice(&result.result_json).unwrap();
    let mut j = f.control.native.journal().unwrap().unwrap();
    j.issued = true;
    j.state = State::Issuing;
    j.issued_at = Some(now());
    f.control.native.persist(&j).unwrap();
    let before = f.calls();
    f.control.observe_pending(f.local.clone()).await.unwrap();
    assert_eq!(
        f.control.native.journal().unwrap().unwrap().state,
        State::RecoveryRequired
    );
    assert_eq!(f.calls(), before);
    assert_eq!(f.starts(), 0);
    assert!(
        Guard::acquire(
            &f.control.native.root,
            crate::system_change::Subsystem::Configuration
        )
        .is_err()
    );
    assert!(
        f.control
            .request(
                28,
                Some(SystemControlAction {
                    transaction_id: p["id"].as_str().unwrap().into(),
                    confirmation_token: p["confirmToken"].as_str().unwrap().into()
                }),
                None,
                f.local.clone()
            )
            .await
            .is_err()
    );
    fs::rename(
        f.control.native.path(),
        f.control.native.state().join("transaction.retained.json"),
    )
    .unwrap();
    assert!(f.control.native.journal().is_err());
    assert!(
        Guard::acquire(
            &f.control.native.root,
            crate::system_change::Subsystem::Identity
        )
        .is_err()
    );
    assert_eq!(f.calls(), before);
    f.control.db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_receipt_command_and_permissions_deny_proof_and_all_managed_writers() {
    for changed in ["receipt", "command", "mode"] {
        let f = Fixture::new().await;
        let p = f.run(&f.command(24, None)).await.unwrap();
        let p: Value = serde_json::from_slice(&p.result_json).unwrap();
        let execute = f.command(25, Some(&p));
        f.run(&execute).await.unwrap();
        let j = f.control.native.journal().unwrap().unwrap();
        let path = if changed == "command" {
            f.control
                .native
                .state()
                .join("commands")
                .join(format!("{}.json", execute.command_id))
        } else {
            f.control.native.file(&j.id, ".completed.json")
        };
        let before = f.calls();
        if changed == "mode" {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        } else {
            let mut bytes = fs::read(&path).unwrap();
            bytes.push(b' ');
            durable::write(&path, &bytes, FileMetadata::private()).unwrap();
        }
        assert!(f.control.native.journal().is_err());
        assert!(f.control.prove(&execute).await.unwrap().is_none());
        for subsystem in [
            crate::system_change::Subsystem::Configuration,
            crate::system_change::Subsystem::Network,
            crate::system_change::Subsystem::Identity,
        ] {
            assert!(Guard::acquire(&f.control.native.root, subsystem).is_err());
        }
        assert_eq!(f.calls(), before);
        let status = f
            .control
            .request(23, None, None, f.local.clone())
            .await
            .unwrap();
        assert_eq!(status["configurationState"], "RECOVERY_REQUIRED");
        assert_eq!(status["allowRestart"], false);
        assert_eq!(status["allowReboot"], false);
        assert_eq!(f.starts(), 1);
        f.control.db.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_mapping_wrong_token_expiry_and_short_reboot_ttl_never_issue_an_action() {
    for changed in ["file", "definition", "token", "expiry", "ttl"] {
        let f = Fixture::new().await;
        let op = if changed == "ttl" { 26 } else { 24 };
        let p = f.run(&f.command(op, None)).await.unwrap();
        let p: Value = serde_json::from_slice(&p.result_json).unwrap();
        let mut execute = f.command(if changed == "ttl" { 27 } else { 25 }, Some(&p));
        match changed {
            "file" => fs::write(f.dir.join("target.service"), b"changed fixed target").unwrap(),
            "definition" => {
                let p = f.dir.join("definition");
                fs::write(
                    &p,
                    fs::read_to_string(&p)
                        .unwrap()
                        .replace("KillMode=control-group", "KillMode=process"),
                )
                .unwrap();
            }
            "token" => {
                execute
                    .system_control_action
                    .as_mut()
                    .unwrap()
                    .confirmation_token = uuid::Uuid::new_v4().to_string()
            }
            "expiry" => {
                let mut j = f.control.native.journal().unwrap().unwrap();
                j.expires_at = now() - 1;
                f.control.native.persist(&j).unwrap();
            }
            _ => execute.expires_at_unix_ms = now() as i64 + 5000,
        }
        assert!(f.run(&execute).await.is_err(), "{changed}");
        assert_eq!(f.starts(), 0);
        assert!(!f.dir.join("scheduled").exists());
        assert!(!f.control.native.journal().unwrap().unwrap().issued);
        f.control.db.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn installation_seal_is_create_only_and_never_starts_enables_or_schedules() {
    let f = Fixture::new().await;
    let output = f.dir.join("sealed.json");
    let value = grant::seal(
        &f.control.native.config,
        &output,
        &f.control.native.systemctl,
    )
    .unwrap();
    assert_eq!(value["unitStarted"], false);
    assert_eq!(value["unitEnabled"], false);
    assert_eq!(value["remoteEnabled"], false);
    assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
    let bytes = fs::read(&output).unwrap();
    assert!(
        grant::seal(
            &f.control.native.config,
            &output,
            &f.control.native.systemctl
        )
        .is_err()
    );
    assert_eq!(fs::read(&output).unwrap(), bytes);
    assert_eq!(f.starts(), 0);
    assert!(!f.dir.join("scheduled").exists());
    assert!(!f.control.native.path().exists());
    f.control.db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn installed_systemd_can_omit_empty_exec_stop_but_cannot_change_the_pinned_start() {
    let f = Fixture::new().await;
    let definition = f.dir.join("definition");
    let original = fs::read_to_string(&definition).unwrap();
    let omitted = original
        .lines()
        .filter(|s| !s.starts_with("ExecStop=") && !s.starts_with("EnvironmentFiles="))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&definition, &omitted).unwrap();
    f.control.native.inputs().unwrap();
    let without_start = omitted
        .lines()
        .filter(|s| !s.starts_with("ExecStart="))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&definition, without_start).unwrap();
    assert!(f.control.native.inputs().is_err());
    fs::write(
        &definition,
        omitted.replace("/test/java", "/test/changed-java"),
    )
    .unwrap();
    assert!(f.control.native.inputs().is_err());
    assert_eq!(f.starts(), 0);
    assert!(!f.dir.join("scheduled").exists());
    f.control.db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn background_observers_never_replace_a_concurrently_completed_restart_with_old_issuing_state()
 {
    use std::sync::atomic::{AtomicBool, Ordering};
    let f = Fixture::new().await;
    let script = fs::read_to_string(&f.control.native.systemctl)
        .unwrap()
        .replace("restart) touch", "restart) sleep 0.2; touch");
    fs::write(&f.control.native.systemctl, script).unwrap();
    let p = f.run(&f.command(24, None)).await.unwrap();
    let p: Value = serde_json::from_slice(&p.result_json).unwrap();
    let execute = f.command(25, Some(&p));
    let finished = Arc::new(AtomicBool::new(false));
    let mut jobs = Vec::new();
    for _ in 0..4 {
        let stop = finished.clone();
        let control = f.control.clone();
        let local = f.local.clone();
        jobs.push(tokio::spawn(async move {
            while !stop.load(Ordering::SeqCst) {
                control.observe_pending(local.clone()).await.unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            control.observe_pending(local).await.unwrap();
        }));
    }
    assert_eq!(
        f.run(&execute).await.unwrap().state,
        TaskState::Succeeded as i32
    );
    finished.store(true, Ordering::SeqCst);
    for job in jobs {
        job.await.unwrap();
    }
    assert_eq!(
        f.control.native.journal().unwrap().unwrap().state,
        State::Completed
    );
    assert!(f.control.prove(&execute).await.unwrap().is_some());
    assert_eq!(f.starts(), 1);
    f.control.db.close().await;
}
