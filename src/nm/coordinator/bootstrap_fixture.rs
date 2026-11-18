// Included only by the Linux test module. This seeds synthetic original state
// inside a fresh owned namespace; the actual agent binary has no fixture switch.

// The installed early unit runs separately in the next boot of this container.
// Only NM and the JVM witnesses are synthetic. The policy and paired lease are
// published by the normal transactions at their canonical paths.
#[test]
#[ignore = "requires an empty, disposable systemd container with its own nftables namespace"]
fn linux_paired_firewall_boot_fixture() {
    use crate::durable;
    use std::{fs, io::ErrorKind, os::unix::fs::MetadataExt, process::Command};

    let root = PathBuf::from("/var/lib/kura-management-agent");
    let marker = PathBuf::from("/etc/kura/network-owner-agent");
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(fs::read_to_string("/proc/1/comm").unwrap().trim(), "systemd");
    assert_eq!(fs::read("/var/tmp/yofc-owned-paired-firewall-boot").unwrap(), b"fresh owned paired firewall boot\n");
    for path in [&root, marker.parent().unwrap()] {
        assert_eq!(fs::symlink_metadata(path).unwrap_err().kind(), ErrorKind::NotFound);
    }
    let read_ruleset = || {
        let result = Command::new("/usr/sbin/nft").args(["-j", "-p", "list", "ruleset"]).output().unwrap();
        assert!(result.status.success());
        serde_json::from_slice::<Value>(&result.stdout).unwrap()
    };
    assert!(read_ruleset()["nftables"].as_array().unwrap().iter().all(|row| row.get("metainfo").is_some()));

    let f = Fixture::at_root(root.clone(), &["eth0"], &[("eth0", 4, 3)]);
    let firewall = crate::firewall::Firewall::open(root.clone(), None).unwrap().enable_writes(true);
    firewall.use_kernel_nft_for_test();
    let candidate = json!({"schemaVersion":3,
        "ipv4":{"inputPolicy":"accept","forwardPolicy":"accept","allowIcmp":true},
        "ipv6":{"inputPolicy":"accept","forwardPolicy":"accept","allowIcmp":true},
        "input":[],"portForward":[],"nat":[]});
    let result = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let prepared = firewall.prepare(candidate, 60, uuid::Uuid::new_v4().to_string()).await.unwrap();
        firewall.apply().await.unwrap();
        firewall.confirm(prepared["token"].as_str().unwrap()).await.unwrap()
    });
    assert_eq!(result["state"], "COMMITTED");
    assert_eq!(result["revision"], 1);
    f.engine.fake.lock().unwrap().kernel_policy = Some(read_ruleset());

    durable::directory(marker.parent().unwrap()).unwrap();
    let source = export_fixture_at(f, 0, marker, handover::Store::new(&root));
    let (f, _, request) = complete_fixture(start_fixture(stop_fixture(fence_fixture(source))));
    for _ in 0..4 { f.observe(); }
    let confirmation = json!({"operationId":request["operationId"],"confirmationToken":request["confirmationToken"]});
    let result = f.engine.ownership_request("network.nm.ownership.activate", confirmation, "local-uid:fixture").unwrap();
    assert_eq!(result["state"], "COMMITTED");

    let id = request["operationId"].as_str().unwrap();
    let lease = fs::read(root.join(format!("nm-ownership/{id}.lease.json"))).unwrap();
    let lease_sha256 = durable::hash(&lease);
    assert_eq!(handover::confirmed_private_firewall_boot_owner(&root).unwrap(), lease_sha256);
    assert_eq!(f.call_count("Update2"), 0);
    assert_eq!(f.call_count("CheckpointCreate"), 0);
    assert_eq!(f.engine.fake.lock().unwrap().writes, 0);
    let network = fs::metadata("/proc/self/ns/net").unwrap();
    println!("{}", json!({"operationId":id,"leaseSha256":lease_sha256,
        "sourceNetDevice":network.dev(),"sourceNetInode":network.ino()}));
    std::mem::forget(f);
}

#[test]
#[ignore = "fresh owned isolated Linux namespace; synthetic backend, real agent bootstrap tested separately"]
fn linux_bootstrap_prefix_fixture() {
    use crate::durable::{self,FileMetadata};
    use std::fs;
    assert_eq!(unsafe{libc::geteuid()},0);
    assert!(Path::new("/proof/owned-bootstrap-scope-v15").is_file());
    let prefix=std::env::var("YOFC_BOOTSTRAP_PREFIX").unwrap();
    assert!(["prepared","stop-unentered","stopped","publication-unentered","arguments-retained",
        "files-published","start-unentered","started","completion-unpointed","lease-intent"].contains(&prefix.as_str()));
    let output=PathBuf::from(std::env::var("YOFC_BOOTSTRAP_OUTPUT").unwrap());
    assert!(output.starts_with("/proof/results") && !output.exists());
    let marker=PathBuf::from("/etc/kura/network-owner-agent");assert!(!marker.exists());
    durable::directory(marker.parent().unwrap()).unwrap();
    let (mut f,source)=export_fixture(0);
    Arc::get_mut(&mut f.engine).unwrap().handover=handover::Store::relocated(&f.root,marker.clone());
    *source.owner_marker.lock().unwrap()=marker;
    let actor="local-uid:0";let digest=f.source_digest();for _ in 0..4{f.observe();}
    let id=uuid::Uuid::new_v4();
    let parent=f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":digest}),actor).unwrap();
    let confirmation=json!({"operationId":id,"confirmationToken":parent["confirmationToken"]});for _ in 0..2{f.observe();}
    f.engine.ownership_request("network.nm.ownership.fence",confirmation.clone(),actor).unwrap();
    let mut installed=handover::startup::tests::install(&f.root);
    handover::startup::tests::place_arguments_in_home(&mut installed);handover::startup::tests::enable_stop(&installed,"success");
    {let engine=Arc::get_mut(&mut f.engine).unwrap();engine.startup_profile=installed.profile.clone();engine.startup_systemctl=installed.systemctl.clone();}
    for _ in 0..4{f.observe();}
    let prepared=f.engine.ownership_request("network.nm.ownership.startup.prepare",confirmation.clone(),actor).unwrap();
    let mut request=confirmation.clone();request["startupConfirmationToken"]=prepared["confirmationToken"].clone();
    if prefix!="prepared" {
        for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.verify",request.clone(),actor).unwrap();
        if prefix=="stop-unentered" {
            let challenge={let _guard=Guard::acquire(&f.root,Subsystem::NmOwnership).unwrap();
                let handover::startup::AssociationStep::Challenge(challenge)=f.engine.handover.startup_stop_begin(id,
                    request["confirmationToken"].as_str().unwrap(),actor,request["startupConfirmationToken"].as_str().unwrap(),&installed.systemctl).unwrap()else{panic!("new stop")};challenge};
            let deadline=Instant::now()+Duration::from_secs(5);let roles=roles::Source::raw(source.as_ref(),deadline).unwrap();
            let association=roles::Source::association(source.as_ref(),&challenge.spec,deadline).unwrap();
            let _guard=Guard::acquire(&f.root,Subsystem::NmOwnership).unwrap();
            let expected=f.engine.handover.requirements(id,request["confirmationToken"].as_str().unwrap(),actor).unwrap();
            drop(f.engine.handover.startup_stop_arm(&expected,actor,request["startupConfirmationToken"].as_str().unwrap(),(association,roles),&installed.systemctl,deadline).unwrap());
        }else{
            for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.stop",request.clone(),actor).unwrap();
            if ["publication-unentered","arguments-retained"].contains(&prefix.as_str()) {
                {let _guard=Guard::acquire(&f.root,Subsystem::NmOwnership).unwrap();
                    let handover::startup::PublicationStep::Dispatch(command)=f.engine.handover.startup_publication_begin(id,
                        request["confirmationToken"].as_str().unwrap(),actor,request["startupConfirmationToken"].as_str().unwrap(),&installed.systemctl).unwrap()else{panic!("new publication")};drop(command);}
                if prefix=="arguments-retained" {
                    let intent:Value=serde_json::from_slice(&fs::read(f.root.join(format!("nm-ownership/{id}.startup-files-intent.json"))).unwrap()).unwrap();
                    // A lost acknowledgement of the first physical rename:
                    // keep its exact preimage, no invented step receipt.
                    durable::move_new(&PathBuf::from(intent["argumentsPath"].as_str().unwrap()),&PathBuf::from(intent["backupPath"].as_str().unwrap())).unwrap();
                }
            }else if prefix!="stopped" {
                for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.publish",request.clone(),actor).unwrap();
                if prefix=="start-unentered" {
                    let _guard=Guard::acquire(&f.root,Subsystem::NmOwnership).unwrap();
                    let handover::startup::StartStep::Dispatch(command)=f.engine.handover.startup_start_begin(id,
                        request["confirmationToken"].as_str().unwrap(),actor,request["startupConfirmationToken"].as_str().unwrap(),&installed.systemctl).unwrap()else{panic!("new start")};drop(command);
                }else if prefix!="files-published" {
                    handover::startup::tests::enable_start_at(&f.root,"success");for _ in 0..4{f.observe();}
                    f.engine.ownership_request("network.nm.ownership.startup.start",request.clone(),actor).unwrap();source.value.lock().unwrap().bridge_epoch=2;
                    if prefix!="started" {
                        for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.complete",request.clone(),actor).unwrap();
                        if prefix=="completion-unpointed" {
                            let path=f.root.join(format!("nm-ownership/{id}.startup-journal.json"));let mut journal:Value=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                            journal.as_object_mut().unwrap().remove("completionReceiptSha256");durable::json(&path,&journal).unwrap();
                        }else{
                            for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.activate",confirmation,actor).unwrap();
                            let path=f.root.join("nm-ownership/transaction.json");let mut journal:Value=serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                            journal["state"]=json!("LEASE_INTENT");journal["receiptSha256"]=Value::Null;durable::json(&path,&journal).unwrap();
                        }
                    }
                }
            }
        }
    }
    let status=f.engine.handover.original(id,actor).unwrap().unwrap();
    let metadata=json!({"prefix":prefix,"root":f.root,"request":request,"originalStatus":status,"ordinaryProfile":installed.profile,
        "argumentsPath":installed.args,"markerPath":"/etc/kura/network-owner-agent","syntheticNmAndKura":true,"actualAgentProcessTested":false});
    durable::publish_new(&output,&serde_json::to_vec(&metadata).unwrap(),FileMetadata::private()).unwrap();
    println!("owned synthetic prefix retained at {}",output.display());
    std::mem::forget(f);
}

// New recovery prefixes only. Never invoke/replay the closed v15 matrix.
#[test]
#[ignore = "fresh owned recovery namespace; actual non-test agent runs separately"]
fn linux_file_recovery_bootstrap_fixture() {
    use crate::durable::{self,FileMetadata};
    assert_eq!(unsafe{libc::geteuid()},0);
    assert!(Path::new("/proof/owned-recovery-bootstrap-scope-v18").is_file());
    let prefix=std::env::var("YOFC_RECOVERY_BOOTSTRAP_PREFIX").unwrap();
    assert!(["reviewed","recovery-unentered","quarantined","restored","cancelled","orphan-incomplete"].contains(&prefix.as_str()));
    let output=PathBuf::from(std::env::var("YOFC_RECOVERY_BOOTSTRAP_OUTPUT").unwrap());
    assert!(output.starts_with("/proof/results") && !output.exists());
    let marker=PathBuf::from("/etc/kura/network-owner-agent");assert!(!marker.exists());durable::directory(marker.parent().unwrap()).unwrap();
    let (mut f,source)=export_fixture(0);
    Arc::get_mut(&mut f.engine).unwrap().handover=handover::Store::relocated(&f.root,marker.clone());*source.owner_marker.lock().unwrap()=marker;
    let actor="local-uid:0";let digest=f.source_digest();for _ in 0..4{f.observe();}
    let id=uuid::Uuid::new_v4();
    let parent=f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":digest}),actor).unwrap();
    let confirmation=json!({"operationId":id,"confirmationToken":parent["confirmationToken"]});for _ in 0..2{f.observe();}
    f.engine.ownership_request("network.nm.ownership.fence",confirmation.clone(),actor).unwrap();
    let mut installed=handover::startup::tests::install(&f.root);handover::startup::tests::place_arguments_in_home(&mut installed);
    handover::startup::tests::enable_stop(&installed,"success");
    {let engine=Arc::get_mut(&mut f.engine).unwrap();engine.startup_profile=installed.profile.clone();engine.startup_systemctl=installed.systemctl.clone();}
    for _ in 0..4{f.observe();}
    let prepared=f.engine.ownership_request("network.nm.ownership.startup.prepare",confirmation.clone(),actor).unwrap();
    let mut request=confirmation;request["startupConfirmationToken"]=prepared["confirmationToken"].clone();
    for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.verify",request.clone(),actor).unwrap();
    for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.stop",request.clone(),actor).unwrap();
    Arc::get_mut(&mut f.engine).unwrap().role_source=None;
    for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.publish",request.clone(),actor).unwrap();
    handover::startup::tests::enable_job_at(&f.root);request["recoveryId"]=json!(uuid::Uuid::new_v4());for _ in 0..4{f.observe();}
    let reviewed=f.engine.ownership_request("network.nm.ownership.startup.recovery.prepare",request.clone(),actor).unwrap();
    let original_request=request.clone();request["recoveryConfirmationToken"]=reviewed["confirmationToken"].clone();
    if ["recovery-unentered","quarantined"].contains(&prefix.as_str()) {
        let command={let _guard=Guard::acquire(&f.root,Subsystem::NmOwnership).unwrap();
            let approval=handover::startup::RecoveryApproval{id:uuid::Uuid::parse_str(request["recoveryId"].as_str().unwrap()).unwrap(),token:reviewed["confirmationToken"].as_str().unwrap().into()};
            let handover::startup::RecoveryStep::Dispatch(command)=f.engine.handover.startup_recovery_begin(id,request["confirmationToken"].as_str().unwrap(),actor,
                request["startupConfirmationToken"].as_str().unwrap(),&approval,&installed.systemctl).unwrap()else{panic!("fresh compensation")};command};
        if prefix=="quarantined"{handover::startup::tests::recovery_bootstrap_quarantine(command);}else{drop(command);}
    }else if prefix=="restored" {
        for _ in 0..4{f.observe();}f.engine.ownership_request("network.nm.ownership.startup.recovery.execute",request.clone(),actor).unwrap();
    }else if prefix=="cancelled" {
        f.engine.ownership_request("network.nm.ownership.startup.recovery.cancel",request.clone(),actor).unwrap();
    }else if prefix=="orphan-incomplete" {
        let ledger=f.root.join(format!("nm-ownership/{id}.startup-recovery-{}.journal.json",request["recoveryId"].as_str().unwrap()));
        durable::move_new(&ledger,&f.root.join("retained-orphan-recovery-journal.json")).unwrap();
    }
    let original=f.engine.handover.original(id,actor);
    let recovery=f.engine.handover.startup_recovery_original(id,request["confirmationToken"].as_str().unwrap(),actor,
        request["startupConfirmationToken"].as_str().unwrap(),uuid::Uuid::parse_str(request["recoveryId"].as_str().unwrap()).unwrap());
    let expected=match prefix.as_str(){"reviewed"=>"PREPARED","restored"=>"ARGUMENTS_RESTORED","cancelled"=>"CANCELLED",
        "orphan-incomplete"=>"OUTCOME_UNKNOWN",_=>"RECOVERY_OUTCOME_UNKNOWN"};
    let (original_status,recovery_status)=if prefix=="orphan-incomplete" {
        assert!(original.err().unwrap().to_string().starts_with("OUTCOME_UNKNOWN"));assert!(recovery.err().unwrap().to_string().starts_with("OUTCOME_UNKNOWN"));(Value::Null,Value::Null)
    }else{let original=original.unwrap().unwrap();let recovery=recovery.unwrap();assert_eq!(recovery["state"],expected);(original,recovery)};
    assert_eq!(f.engine.fake.lock().unwrap().writes,0);assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);
    let metadata=json!({"prefix":prefix,"root":f.root,"request":request,"recoveryOriginalRequest":original_request,
        "originalStatus":original_status,"recoveryStatus":recovery_status,"expectedRecoveryState":expected,"parentState":"FENCED",
        "ordinaryProfile":installed.profile,"argumentsPath":installed.args,"markerPath":"/etc/kura/network-owner-agent",
        "syntheticNmAndKura":true,"actualAgentProcessTested":false,"closedV15MatrixReplayed":false});
    durable::publish_new(&output,&serde_json::to_vec(&metadata).unwrap(),FileMetadata::private()).unwrap();
    println!("fresh owned recovery prefix retained at {}",output.display());std::mem::forget(f);
}
