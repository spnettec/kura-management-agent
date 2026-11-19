use super::*;
use std::sync::atomic::{AtomicBool,AtomicUsize,Ordering};

// The older single-profile fixture repeats one UUID for every device. This
// multi-interface source must instead witness distinct stored/applied profiles.
struct MultiProfileWire(Arc<FakeWire>);
impl Wire for MultiProfileWire {
    fn server_guid(&self,deadline:Instant)->Result<Option<String>> {self.0.server_guid(deadline)}
    fn call(&self,call:&BusCall,deadline:Instant)->Result<Value> {
        let mut result=self.0.call(call,deadline)?;
        if ["GetSettings","GetAppliedConnection"].contains(&call.method.as_str()) {
            let id=call.path.rsplit('/').next().unwrap().parse::<u32>().unwrap()-u32::from(call.method=="GetAppliedConnection");
            result["data"][0]["connection"]["uuid"]=value("s",json!(format!("00000000-0000-4000-8000-{id:012}")));
        }
        Ok(result)
    }
}

struct OriginalSource {roles:roles::Observation,model:Value,root:PathBuf,exports:AtomicUsize,lost:bool,drift:AtomicBool,break_model:bool,change_model:AtomicBool,changed_instance:uuid::Uuid}
impl roles::Source for OriginalSource {
    fn read(&self,deadline:Instant)->Result<roles::Observation> {self.raw(deadline)}
    fn raw(&self,_:Instant)->Result<roles::Observation> {let mut value=self.roles.clone();if self.drift.load(Ordering::SeqCst){value.roles.revision="original-source-drift".into();}Ok(value)}
    fn firewall_source(&self,roles:&roles::Observation,_:Instant)->Result<roles::FirewallSource> {roles::Origin::new(roles.agent_instance,roles.bridge_epoch,roles,self.model.clone())?.stored(roles)}
    fn firewall_origin(&self,roles:&roles::Observation,_:Instant)->Result<Option<roles::Origin>> {
        ensure!(!self.break_model,"CONFLICT: advertised writer model unavailable");let mut model=self.model.clone();
        if self.change_model.load(Ordering::SeqCst)&&self.exports.load(Ordering::SeqCst)>0 {model["families"][0]["instanceId"]=json!(self.changed_instance);}
        Ok(Some(roles::Origin::new(roles.agent_instance,roles.bridge_epoch,roles,model)?))
    }
    fn export(&self,id:uuid::Uuid,roles:&roles::Observation,firewall:&roles::FirewallSource,nonce:&str,_:Instant)->Result<Value> {
        firewall.require(roles)?;assert_eq!(self.exports.fetch_add(1,Ordering::SeqCst),0,"never repeat original export");
        let _guard=Guard::acquire(&self.root,Subsystem::NmOwnership)?;
        handover::template::Transfer::new(&self.root).deposit(json!({"operationId":id,"revision":roles.roles.revision,"depositToken":nonce,
            "templateSha256":crate::durable::hash(b"AAAA-BBBB"),"chunkIndex":0,"chunkCount":1,"ciphertextChunk":"AAAA-BBBB"}),roles.agent_instance,roles.bridge_epoch)?;
        if self.lost {anyhow::bail!("OUTCOME_UNKNOWN: test-only lost final reply after original deposit");}Ok(json!({"stored":true}))
    }
}
fn fixture(lost:bool,break_model:bool,multi_wan:bool)->(Fixture,Arc<OriginalSource>) {
    let mut f=Fixture::new(&["eth0","lan0","wan0"],&[("eth0",4,3),("lan0",5,4),("wan0",6,5)]);
    let corpus:Value=serde_json::from_str(include_str!("../../fixtures/rich-raw-corpus-v35.json")).unwrap();let exchange=&corpus["exchange"];
    let roles=roles::Observation::new(uuid::Uuid::new_v4(),71,exchange["roles"].clone()).unwrap();
    // This coherent source has one enabled and one disabled LAN NAT, with wan0
    // upstream. The retained two-WAN model is tested separately as incomplete.
    let mut coherent=serde_json::to_value(&roles.roles).unwrap();
    if !multi_wan {coherent["interfaces"].as_array_mut().unwrap().iter_mut().find(|v|v["id"]=="eth0").unwrap()["ipv4Status"]=json!("netIPv4StatusEnabledLAN");}
    let roles=roles::Observation::new(roles.agent_instance,roles.bridge_epoch,coherent).unwrap();
    let source=Arc::new(OriginalSource{roles,model:exchange["origin"].clone(),root:f.root.clone(),exports:AtomicUsize::new(0),lost,drift:AtomicBool::new(false),break_model,change_model:AtomicBool::new(false),changed_instance:uuid::Uuid::new_v4()});
    let parent=f.root.join("installed-owner");crate::durable::directory(&parent).unwrap();
    let engine=Arc::get_mut(&mut f.engine).unwrap();engine.source.wire=Arc::new(MultiProfileWire(f.wire.clone()));engine.handover=handover::Store::relocated(&f.root,parent.join("network-owner-agent"));engine.set_role_source(source.clone());
    {let mut fake=engine.fake.lock().unwrap();fake.native_kernel=Some(corpus["source"].clone());fake.legacy_kernel=None;fake.kernel_policy=None;}
    for _ in 0..12 {f.observe();}(f,source)
}
#[test]
fn original_native_prepare_and_lost_export_reply_use_one_source_and_operation_without_private_initialization() {
    for lost in [false,true] {
        let (f,source)=fixture(lost,false,false);let preview=||f.engine.ownership_request("network.nm.ownership.status",json!({"includePreparationSource":true}),"local-uid:fixture").unwrap();
        let first=preview();let second=preview();let digest=first["preparationSource"]["sourceDigest"].as_str().unwrap();assert_eq!(first,second);
        assert_eq!(first["preparationSource"]["nativeSource"]["selectedRuleCount"],144);assert_eq!(source.exports.load(Ordering::SeqCst),0);
        assert!(!f.root.join("firewall/confirmed.json").exists());
        let id=uuid::Uuid::new_v4();let input=json!({"operationId":id,"sourceDigest":digest});let prepared=f.engine.ownership_request("network.nm.ownership.prepare",input.clone(),"local-uid:fixture").unwrap();assert_eq!(prepared["state"],"PREPARED");
        assert!(f.engine.ownership_request("network.nm.ownership.prepare",input,"local-uid:fixture").is_err());
        let original=f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").unwrap();assert_eq!(original["confirmationToken"],prepared["confirmationToken"]);
        let (_,baseline)=handover::template::Transfer::new(&f.root).ready(id,"local-uid:fixture").unwrap();let native=baseline.native_transfer.as_ref().unwrap();assert_eq!(native.operation_id,id);assert_eq!(native.source_binding().unwrap(),digest);
        assert!(native.source_model_sha256.is_some());assert!(!baseline.automatic_nat.is_null());
        assert_eq!(source.exports.load(Ordering::SeqCst),1);assert_eq!(f.call_count("CheckpointCreate"),0);assert_eq!(f.call_count("Update2"),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
        assert!(!f.root.join("firewall/confirmed.json").exists());assert!(!f.root.join("installed-owner/network-owner-agent").exists());
        let fenced=f.engine.ownership_request("network.nm.ownership.fence",json!({"operationId":id,"confirmationToken":prepared["confirmationToken"]}),"local-uid:fixture").unwrap();assert_eq!(fenced["state"],"FENCED");
        if lost {source.change_model.store(true,Ordering::SeqCst);}
        let error=handover::native::epoch::Epoch::with_storage_fixture(||f.engine.ownership_request("network.nm.ownership.native.apply",json!({"operationId":id,"confirmationToken":prepared["confirmationToken"]}),"local-uid:fixture")).unwrap_err();
        if lost {assert!(error.to_string().contains("writer model changed before native effect"));}
        else {assert!(error.to_string().starts_with("UNSUPPORTED"),"no real registered Java drain was provided by this fixture");}
        assert_eq!(source.exports.load(Ordering::SeqCst),1);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
}
#[test]
fn original_native_model_read_failure_and_raw_drift_never_fall_back_or_export() {
    for defect in ["model","raw"] {
        let (f,source)=fixture(false,defect=="model",false);
        if defect=="raw" {f.engine.fake.lock().unwrap().native_kernel.as_mut().unwrap()["ruleFingerprints"][0].as_object_mut().unwrap().remove("payloadHex");}
        assert!(f.engine.ownership_request("network.nm.ownership.status",json!({"includePreparationSource":true}),"local-uid:fixture").is_err());
        assert_eq!(source.exports.load(Ordering::SeqCst),0);assert!(f.engine.handover.active().unwrap().is_none());assert!(!f.root.join("nm-template/transaction.json").exists());assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    }
}
#[test]
fn original_native_incomplete_two_wan_model_is_refused_before_any_export_or_fence() {
    let (f,source)=fixture(false,false,true);
    let error=f.engine.ownership_request("network.nm.ownership.status",json!({"includePreparationSource":true}),"local-uid:fixture").unwrap_err();
    assert!(error.to_string().contains("complete CM automatic NAT matrix"));assert_eq!(source.exports.load(Ordering::SeqCst),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);assert!(!f.root.join("installed-owner/network-owner-agent").exists());
}
#[test]
fn original_native_writer_instance_drift_after_export_preserves_the_original_without_reexport() {
    let (f,source)=fixture(false,false,false);
    let preview=f.engine.ownership_request("network.nm.ownership.status",json!({"includePreparationSource":true}),"local-uid:fixture").unwrap();source.change_model.store(true,Ordering::SeqCst);
    let id=uuid::Uuid::new_v4();let input=json!({"operationId":id,"sourceDigest":preview["preparationSource"]["sourceDigest"]});
    let error=f.engine.ownership_request("network.nm.ownership.prepare",input.clone(),"local-uid:fixture").unwrap_err();assert!(error.to_string().contains("original source changed after template export"));
    assert!(f.engine.ownership_request("network.nm.ownership.original",json!({"operationId":id}),"local-uid:fixture").is_err());assert!(f.engine.ownership_request("network.nm.ownership.prepare",input,"local-uid:fixture").is_err());
    assert_eq!(source.exports.load(Ordering::SeqCst),1);assert!(!f.root.join("installed-owner/network-owner-agent").exists());assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    let (_,original)=handover::template::Transfer::new(&f.root).ready(id,"local-uid:fixture").unwrap();assert_eq!(original.native_transfer.unwrap().operation_id,id);
}
#[test]
fn private_confirmed_source_keeps_its_contract_even_when_the_bridge_advertises_legacy_models() {
    struct ExistingPrivate {inner:Arc<ExportSource>,model_reads:AtomicUsize}
    impl roles::Source for ExistingPrivate {
        fn read(&self,deadline:Instant)->Result<roles::Observation> {self.inner.raw(deadline)}
        fn raw(&self,deadline:Instant)->Result<roles::Observation> {self.inner.raw(deadline)}
        fn firewall_source(&self,roles:&roles::Observation,deadline:Instant)->Result<roles::FirewallSource> {self.inner.firewall_source(roles,deadline)}
        fn firewall_origin(&self,_:&roles::Observation,_:Instant)->Result<Option<roles::Origin>> {self.model_reads.fetch_add(1,Ordering::SeqCst);anyhow::bail!("private policy must not be replaced by legacy capability discovery")}
        fn export(&self,id:uuid::Uuid,roles:&roles::Observation,firewall:&roles::FirewallSource,nonce:&str,deadline:Instant)->Result<Value> {self.inner.export(id,roles,firewall,nonce,deadline)}
    }
    let (mut f,inner)=export_fixture(0);let source=Arc::new(ExistingPrivate{inner:inner.clone(),model_reads:AtomicUsize::new(0)});Arc::get_mut(&mut f.engine).unwrap().set_role_source(source.clone());for _ in 0..6 {f.observe();}
    let preview=f.engine.ownership_request("network.nm.ownership.status",json!({"includePreparationSource":true}),"local-uid:fixture").unwrap();assert!(preview["preparationSource"].get("nativeSource").is_none());
    let prepared=f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":uuid::Uuid::new_v4(),"sourceDigest":preview["preparationSource"]["sourceDigest"]}),"local-uid:fixture").unwrap();assert_eq!(prepared["state"],"PREPARED");
    assert_eq!(inner.exports.load(Ordering::SeqCst),1);assert_eq!(source.model_reads.load(Ordering::SeqCst),0);assert_eq!(f.engine.fake.lock().unwrap().writes,0);
}
#[test]
fn imported_backend_consumes_the_original_committed_transition_without_changing_baseline_zero() {
    // Actual Store/temporary-file transitions with a synthetic wire result. No
    // registered JVM drain or actual kernel/owner acceptance is claimed here.
    let (f,source)=fixture(false,false,false);for _ in 0..8{f.observe();}
    let preview=f.engine.ownership_request("network.nm.ownership.status",json!({"includePreparationSource":true}),"local-uid:fixture").unwrap();let id=uuid::Uuid::new_v4();
    let prepared=f.engine.ownership_request("network.nm.ownership.prepare",json!({"operationId":id,"sourceDigest":preview["preparationSource"]["sourceDigest"]}),"local-uid:fixture").unwrap();let token=prepared["confirmationToken"].as_str().unwrap();
    f.engine.ownership_request("network.nm.ownership.fence",json!({"operationId":id,"confirmationToken":token}),"local-uid:fixture").unwrap();
    let (_,baseline)=handover::template::Transfer::new(&f.root).ready(id,"local-uid:fixture").unwrap();let before=serde_json::to_vec(&baseline).unwrap();let native=baseline.native_transfer.as_ref().unwrap();let current=handover::native::outcome_tests::forward(native);
    f.engine.handover.native_change_fixture(id,token,"local-uid:fixture",false,|_,_,_,after|Ok(if after{current.clone()}else{native.original.clone()}),|_|Ok(())).unwrap();f.engine.fake.lock().unwrap().native_kernel=Some(current.clone());
    assert!(f.engine.ownership_request("network.nm.ownership.initialization.apply",json!({"operationId":id,"confirmationToken":token}),"local-uid:fixture").is_err(),"a real registered drain is still required by the production controller");
    assert!(!f.root.join("firewall/imported-confirmed.json").exists());
    f.engine.handover.initialize_policy_fixture(id,token,"local-uid:fixture",|_,_,_|Ok((current.clone(),source.model.clone())),|path,bytes|crate::durable::publish_new(path,bytes,crate::durable::FileMetadata::private())).unwrap();
    let binding=f.engine.firewall_binding().unwrap();assert_eq!(binding.revision,1);assert_ne!(digest(&serde_json::to_value(binding).unwrap()).unwrap(),baseline.firewall_digest);
    f.engine.verify_delegated_backend(&baseline,Instant::now()+Duration::from_secs(30)).unwrap();
    let (_,original)=handover::template::Transfer::new(&f.root).ready(id,"local-uid:fixture").unwrap();assert_eq!(serde_json::to_vec(&original).unwrap(),before);
    assert!(f.engine.handover.requirements(id,token,"local-uid:fixture").is_ok());assert!(f.engine.handover.active().unwrap().is_none());assert_eq!(f.engine.fake.lock().unwrap().writes,0);
    assert_eq!(source.exports.load(Ordering::SeqCst),1);assert!(!f.root.join("firewall/confirmed.json").exists());
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires a fresh disposable systemd container with empty canonical Root and markers"]
fn linux_signed_imported_early_boot_fixture() {
    use crate::durable;
    use std::{fs, io::ErrorKind};
    const ACTOR: &str = "local-uid:fixture";
    let root = PathBuf::from("/var/lib/kura-management-agent");
    let marker = PathBuf::from("/etc/kura/network-owner-agent");
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(fs::read_to_string("/proc/1/comm").unwrap().trim(), "systemd");
    assert_eq!(fs::read("/var/tmp/yofc-owned-imported-firewall-boot").unwrap(), b"fresh owned imported firewall early boot\n");
    for path in [&root, marker.parent().unwrap()] {
        assert_eq!(fs::symlink_metadata(path).unwrap_err().kind(), ErrorKind::NotFound);
    }

    let corpus: Value = serde_json::from_str(include_str!("../../fixtures/rich-raw-corpus-v35.json")).unwrap();
    let mut role_input = corpus["exchange"]["roles"].clone();
    role_input["interfaces"].as_array_mut().unwrap().iter_mut().find(|row| row["id"] == "eth0")
        .unwrap()["ipv4Status"] = json!("netIPv4StatusEnabledLAN");
    let roles = roles::Observation::new(uuid::Uuid::new_v4(), 71, role_input).unwrap();
    let mut model = corpus["exchange"]["origin"].clone();
    for (index, prefix) in [(0, 24), (1, 64)] {
        model["families"][index]["runtimeNatRuleTypes"] = json!(["IP_FORWARDING", "PORT_FORWARDING"]);
        model["families"][index]["runtimePortForwardDestinationPrefixes"] = json!([prefix]);
        model["modelRules"]["nat"][index * 2 + 1]["ruleType"] = json!("PORT_FORWARDING");
    }
    let mut kernel = corpus["source"].clone();
    handover::native::lineage::tests::exclude_foreign_fixture_rules(&mut kernel);
    kernel["nftables"].as_array_mut().unwrap().iter_mut().find(|entry| {
        entry["chain"]["family"] == "ip" && entry["chain"]["table"] == "filter" && entry["chain"]["name"] == "OUTPUT"
    }).unwrap()["chain"]["policy"] = json!("drop");

    durable::directory(marker.parent().unwrap()).unwrap();
    let f = Fixture::at_root(root.clone(), &["eth0", "lan0", "wan0"], &[("eth0",4,3),("lan0",5,4),("wan0",6,5)]);
    let store = handover::Store::new(&root);
    let (mut f, startup_source) = export_fixture_at(f, 0, marker, store);
    *startup_source.value.lock().unwrap() = roles.clone();
    let source = Arc::new(OriginalSource { roles, model, root:root.clone(), exports:AtomicUsize::new(0),
        lost:false, drift:AtomicBool::new(false), break_model:false,
        change_model:AtomicBool::new(false), changed_instance:uuid::Uuid::new_v4() });
    let engine = Arc::get_mut(&mut f.engine).unwrap();
    engine.source.wire = Arc::new(MultiProfileWire(f.wire.clone()));
    engine.set_role_source(source.clone());
    engine.fake.lock().unwrap().native_kernel = Some(kernel);
    for _ in 0..12 { f.observe(); }

    let preview = f.engine.ownership_request("network.nm.ownership.status", json!({"includePreparationSource":true}), ACTOR).unwrap();
    let id = uuid::Uuid::new_v4();
    let prepared = f.engine.ownership_request("network.nm.ownership.prepare",
        json!({"operationId":id,"sourceDigest":preview["preparationSource"]["sourceDigest"]}), ACTOR).unwrap();
    let confirmation = json!({"operationId":id,"confirmationToken":prepared["confirmationToken"]});
    let token = prepared["confirmationToken"].as_str().unwrap();
    f.engine.ownership_request("network.nm.ownership.fence", confirmation.clone(), ACTOR).unwrap();
    let (_, baseline) = handover::template::Transfer::new(&root).ready(id, ACTOR).unwrap();
    let native = baseline.native_transfer.as_ref().unwrap();
    let current = handover::native::outcome_tests::forward(native);
    f.engine.handover.native_change_fixture(id, token, ACTOR, false,
        |_,_,_,after| Ok(if after {current.clone()} else {native.original.clone()}), |_| Ok(())).unwrap();
    f.engine.fake.lock().unwrap().native_kernel = Some(current.clone());
    f.engine.handover.initialize_policy_fixture(id, token, ACTOR,
        |_,_,_| Ok((current.clone(), source.model.clone())),
        |path,bytes| durable::publish_new(path,bytes,durable::FileMetadata::private())).unwrap();

    Arc::get_mut(&mut f.engine).unwrap().set_role_source(startup_source.clone());
    let (f, _, _) = complete_fixture(start_fixture(stop_fixture((f, startup_source, confirmation.clone()))));
    for _ in 0..4 { f.observe(); }
    assert_eq!(f.engine.ownership_request("network.nm.ownership.activate", confirmation, ACTOR).unwrap()["state"], "COMMITTED");
    let review = handover::initialization::review_imported_boot(&root).unwrap();
    assert_eq!(review["tables"], 6);
    assert_eq!(review["rules"], 144);
    assert_eq!(review["ownerLeaseSha256"], durable::hash(&fs::read(root.join(format!("nm-ownership/{id}.lease.json"))).unwrap()));
    assert_eq!(f.call_count("Update2"), 0);
    assert_eq!(source.exports.load(Ordering::SeqCst), 1);
    assert_eq!(f.engine.fake.lock().unwrap().writes, 0);
    println!("{}", json!({"operationId":id,"review":review,"syntheticJVMNMAndInitialKernel":true}));
    std::mem::forget(f);
}
