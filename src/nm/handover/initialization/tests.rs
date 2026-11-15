//! Original Store and actual temporary filesystem contracts. The kernel and
//! registered Java transports are explicit fakes; these are not live acceptance.
use super::*;
use std::sync::atomic::{AtomicUsize,Ordering};
mod journal_cases;
mod epoch_cases;
mod observation_cases;
pub(in crate::nm::handover::initialization) mod producer_cases;
pub(in crate::nm::handover::initialization) struct Fixture {pub(in crate::nm::handover::initialization) root:PathBuf,pub(in crate::nm::handover::initialization) store:Store,id:uuid::Uuid,token:String,baseline:Baseline,pub(in crate::nm::handover::initialization) current:Value,model:Value,original:Vec<u8>}
impl Fixture {
    fn new()->Self {
          Self::with_changed_base_policies(false)
      }
      fn with_changed_base_policies(changed:bool)->Self {
          Self::with_original_model(changed,true)
      }
      fn with_original_model(changed:bool,with_types:bool)->Self {
          Self::with_model_metadata(changed,with_types,with_types)
      }
      fn with_model_metadata(changed:bool,with_types:bool,with_prefixes:bool)->Self {
          Self::with_native_stage(changed,with_types,with_prefixes,true)
      }
      fn before_native()->Self {
          Self::with_native_stage(false,true,true,false)
      }
      fn with_native_stage(changed:bool,with_types:bool,with_prefixes:bool,native_ready:bool)->Self {
        let root=std::env::temp_dir().join(format!("import-initialization-{}",uuid::Uuid::new_v4()));durable::directory(&root).unwrap();let installed=root.join("installed");durable::directory(&installed).unwrap();
        let store=Store::relocated(&root,installed.join("network-owner-agent"));
        let corpus:Value=serde_json::from_str(include_str!("../../fixtures/rich-raw-corpus-v35.json")).unwrap();let mut roles_value=corpus["exchange"]["roles"].clone();roles_value["interfaces"][0]["ipv4Status"]=json!("netIPv4StatusEnabledLAN");
          let roles=roles::Observation::new(uuid::Uuid::new_v4(),71,roles_value).unwrap();let mut model=corpus["exchange"]["origin"].clone();
          // Fresh unit model only: the retained Java rich fixture's second
          // manual NAT is PORT_FORWARDING; stored-property syntax loses it.
          if with_types {for index in 0..2 {model["families"][index]["runtimeNatRuleTypes"]=json!(["IP_FORWARDING","PORT_FORWARDING"]);model["modelRules"]["nat"][index*2+1]["ruleType"]=json!("PORT_FORWARDING");}}
          if with_prefixes {model["families"][0]["runtimePortForwardDestinationPrefixes"]=json!([24]);model["families"][1]["runtimePortForwardDestinationPrefixes"]=json!([64]);}
          let origin=roles::Origin::new(roles.agent_instance,roles.bridge_epoch,&roles,model.clone()).unwrap();let firewall=origin.stored(&roles).unwrap();let fence=store.observe_firewall_fence().unwrap();
          let mut source=corpus["source"].clone();
          if changed {for entry in source["nftables"].as_array_mut().unwrap() {if let Some(chain)=entry.get_mut("chain")&&chain["table"]=="filter" {match (chain["family"].as_str(),chain["name"].as_str()) {(Some("ip"),Some("INPUT"))=>chain["policy"]=json!("accept"),(Some("ip"),Some("OUTPUT"))=>chain["policy"]=json!("drop"),(Some("ip6"),Some("FORWARD"))=>chain["policy"]=json!("accept"),_=>{}}}}}
          let pair=Baseline::bind_pair_source(&"a".repeat(64),Some(&firewall),Some(&fence)).unwrap();let id=uuid::Uuid::new_v4();let native=native::factory::Reviewed::new(&pair,&origin,&roles,&source).unwrap().bind(id).unwrap();let current=native::outcome_tests::forward(&native);
        let baseline=Baseline{source_digest:native.source_binding().unwrap(),roles,profiles:["eth0","lan0","wan0"].iter().map(|name|ProfileBinding{interface:(*name).into(),profile_uuid:None,origin_cas:Some("c".repeat(64))}).collect(),firewall_digest:digest(&json!({"revision":0,"confirmedSha256":"","journalSettled":true})).unwrap(),automatic_nat:json!({"wan":"wan0","lan":["lan0"]}),firewall_source:Some(firewall),firewall_fence:Some(fence),native_transfer:Some(native)};
        let template=template::Transfer::new(&root);let nonce=template.start(id,"actor".into(),baseline.clone()).unwrap();template.deposit(json!({"operationId":id,"revision":baseline.roles.roles.revision,"depositToken":nonce,"templateSha256":durable::hash(b"AAAA-BBBB"),"chunkIndex":0,"chunkCount":1,"ciphertextChunk":"AAAA-BBBB"}),baseline.roles.agent_instance,baseline.roles.bridge_epoch).unwrap();
        let (binding,_)=template.ready(id,"actor").unwrap();let prepared=store.plan_with_template(id,"actor".into(),baseline.clone(),binding).unwrap();let token=prepared["confirmationToken"].as_str().unwrap().to_string();store.fence(&token,"actor",||Ok(baseline.clone())).unwrap();
          let writes=AtomicUsize::new(0);if native_ready {store.native_change_fixture(id,&token,"actor",false,|_,_,_,after|Ok(if after{current.clone()}else{baseline.native_transfer.as_ref().unwrap().original.clone()}),|_|{writes.fetch_add(1,Ordering::SeqCst);Ok(())}).unwrap();}assert_eq!(writes.load(Ordering::SeqCst),usize::from(native_ready));
        assert!(store.requirements(id,&token,"actor").is_err(),"native acknowledgement alone cannot authorize startup");
        let original=fs::read(store.artifact(id,"intent")).unwrap();Self{root,store,id,token,baseline,current,model,original}
    }
    fn inspect(&self,_:&Baseline,_:uuid::Uuid,_:&str)->Result<(Value,Value)> {Ok((self.current.clone(),self.model.clone()))}
    fn initialize(&self)->Result<Value> {self.store.initialize_policy_fixture(self.id,&self.token,"actor",|b,id,p|self.inspect(b,id,p),|path,bytes|durable::publish_new(path,bytes,FileMetadata::private()))}
    fn query(&self)->Result<Value> {self.store.initialization_original_fixture(self.id,"actor",|b,id,p|self.inspect(b,id,p))}
    fn check_original(&self) {assert_eq!(fs::read(self.store.artifact(self.id,"intent")).unwrap(),self.original);let (_,plan)=self.store.load().unwrap().unwrap();assert!(plan.baseline==self.baseline);assert!(!self.root.join("firewall/confirmed.json").exists());}
}
#[test]
fn imported_initialization_commits_in_the_original_journal_and_keeps_digest_zero_immutable() {
    let f=Fixture::new();let status=f.initialize().unwrap();assert_eq!(status["initialization"]["state"],"COMMITTED");assert_eq!(status["initialization"]["originalSourceDigest"],f.baseline.source_digest);assert_eq!(status["initialization"]["originalFirewallDigest"],f.baseline.firewall_digest);
    let source=confirmed_source(&f.root,Some(&f.current)).unwrap().unwrap();assert_eq!(source["sourceKind"],"nft.imported.confirmed.v1");assert_eq!(source["originalSourceDigest"],f.baseline.source_digest);assert_ne!(source["sourceDigest"],f.baseline.source_digest);
    assert_eq!(crate::firewall::core_confirmed_witness(&f.root).unwrap().revision,1);assert_eq!(crate::firewall::initialized_kernel_source(&f.root,&f.current).unwrap(),source);
    assert!(f.store.requirements(f.id,&f.token,"actor").is_ok());assert!(f.store.active().unwrap().is_none());f.check_original();
    let before=fs::read(f.store.journal_path()).unwrap();assert!(f.store.initialize_policy_fixture(f.id,&f.token,"actor",|_,_,_|panic!("no repeated inspection"),|_,_|panic!("never republish")).is_err());
    f.store.initialization_original_fixture(f.id,"actor",|_,_,_|panic!("historical committed query must not repeat live observations")).unwrap();assert_eq!(before,fs::read(f.store.journal_path()).unwrap());
    assert!(f.store.native_change_fixture(f.id,&f.token,"actor",true,|_,_,_,_|panic!("initialization must be retired first"),|_|panic!("no inverse dispatch")).is_err());
}

#[test]
fn original_preview_binds_explicit_native_update_identity_without_creating_or_dispatching_a_transaction() {
    let f=Fixture::new();f.initialize().unwrap();let view=core_view(&f.root).unwrap().unwrap();
    let journal=fs::read(f.store.journal_path()).unwrap();let anchor=fs::read(f.root.join(POLICY)).unwrap();
    let id=uuid::Uuid::new_v4();let mut candidate=view["candidate"].clone();candidate["input"][0]["ports"]["first"]=json!(5481);
    let mut input=json!({"operationId":id,"expectedRevision":1,"sourceDigest":view["sourceDigest"],"candidate":candidate,
        "destinationPrefixes":{"ipv4":[24],"ipv6":[64]}});
    let result=preview_update(&f.root,input.clone()).unwrap();let plan=&result["nativePlan"];
    assert_eq!(plan["operationId"],json!(id));assert_eq!(plan["baseRevision"],1);assert_eq!(plan["targetRevision"],2);
    assert_eq!(plan["sourceGeneration"],f.current["kernelGeneration"]);assert_eq!(plan["selectedRuleCount"],144);
    assert_eq!(plan["applyReady"],false);assert_eq!(plan["writeEnabled"],false);assert_eq!(plan["dispatched"],false);
    assert_eq!(plan["initializationReceiptSha256"],view["preservedSource"]["initializationReceiptSha256"]);
    assert_eq!(result["kernelObservation"],"initializationAcknowledgement");
    assert_eq!(preview_update(&f.root,input.clone()).unwrap(),result,"pure review is deterministic; no new operation is generated");
    input["operationId"]=json!(f.id);assert!(preview_update(&f.root,input.clone()).is_err());
    input["operationId"]=json!(uuid::Uuid::nil());assert!(preview_update(&f.root,input).is_err());
    assert_eq!(fs::read(f.store.journal_path()).unwrap(),journal);assert_eq!(fs::read(f.root.join(POLICY)).unwrap(),anchor);f.check_original();
    assert!(!f.root.join("firewall/transaction.json").exists());
    println!("ORIGINAL_NATIVE_PLAN_PREVIEW_FIXTURE={result}");
}
#[test]
fn imported_initialization_lost_reply_is_resolved_only_from_the_original_existing_file() {
    let f=Fixture::new();let publications=AtomicUsize::new(0);
    assert!(f.store.initialize_policy_fixture(f.id,&f.token,"actor",|b,id,p|f.inspect(b,id,p),|path,bytes|{publications.fetch_add(1,Ordering::SeqCst);durable::publish_new(path,bytes,FileMetadata::private())?;anyhow::bail!("lost reply after publication")}).unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
    assert_eq!(f.store.status().unwrap()["initialization"]["state"],"INTENT");assert!(confirmed_source(&f.root,None).is_err());assert!(f.store.requirements(f.id,&f.token,"actor").is_err());
    let file=fs::read(f.root.join(POLICY)).unwrap();assert_eq!(f.query().unwrap()["initialization"]["state"],"COMMITTED");assert_eq!(file,fs::read(f.root.join(POLICY)).unwrap());assert_eq!(publications.load(Ordering::SeqCst),1);f.check_original();
}
#[test]
fn imported_initialization_missing_or_replaced_publication_never_republishes_or_grants_startup() {
    for mode in ["before-write","deleted","replaced"] {
        let f=Fixture::new();
        if mode=="before-write" {assert!(f.store.initialize_policy_fixture(f.id,&f.token,"actor",|b,id,p|f.inspect(b,id,p),|_,_|anyhow::bail!("unavailable before publication")).is_err());}
        else {f.initialize().unwrap();let file=f.root.join(POLICY);let bytes=fs::read(&file).unwrap();let retained=file.with_extension("retained");fs::rename(&file,&retained).unwrap();if mode=="replaced"{durable::publish_new(&file,&bytes,FileMetadata::private()).unwrap();}}
        let before=fs::read(f.store.journal_path()).unwrap();assert!(f.query().is_err());assert!(f.store.requirements(f.id,&f.token,"actor").is_err());assert!(f.store.initialize_policy_fixture(f.id,&f.token,"actor",|_,_,_|panic!("no repeat"),|_,_|panic!("no repeat")).is_err());assert_eq!(before,fs::read(f.store.journal_path()).unwrap());f.check_original();
    }
}
#[test]
fn imported_initialization_wrong_actor_model_or_generation_fails_before_any_new_intent() {
    let f=Fixture::new();let before=fs::read(f.store.journal_path()).unwrap();
    assert!(f.store.initialize_policy_fixture(f.id,&f.token,"other",|_,_,_|panic!("unauthorized"),|_,_|panic!("no publication")).is_err());
    for mode in ["model","generation"] {
        let mut kernel=f.current.clone();let mut model=f.model.clone();if mode=="model"{model["families"][0]["instanceId"]=json!(uuid::Uuid::new_v4());}else{kernel["kernelGeneration"]=json!(999);}
        assert!(f.store.initialize_policy_fixture(f.id,&f.token,"actor",|_,_,_|Ok((kernel.clone(),model.clone())),|_,_|panic!("no publication")).is_err());assert_eq!(before,fs::read(f.store.journal_path()).unwrap());
    }
    assert!(!f.root.join(POLICY).exists());f.check_original();
}

  #[tokio::test]
  async fn imported_core_view_reads_the_original_projection_and_never_runs_the_private_backend() {
      let f=Fixture::new();f.initialize().unwrap();
      let engine=crate::firewall::Firewall::open(f.root.clone(),Some("/nonexistent/no-nft-for-imported-view".into())).unwrap().enable_writes(true);
      let before=fs::read(f.store.journal_path()).unwrap();let policy=fs::read(f.root.join(POLICY)).unwrap();
      let view=engine.kura_request("firewall.kura.view".into(),json!({}),"view-original".into(),77,true).await.unwrap();
      let source=confirmed_source(&f.root,None).unwrap().unwrap();
      assert_eq!(view["sourceDigest"],source["sourceDigest"]);assert_eq!(view["revision"],1);
      assert_eq!(view["sourceKind"],"nft.imported.confirmed.v1");assert_eq!(view["initialized"],true);assert_eq!(view["projectable"],true);
      assert_eq!(view["writeEnabled"],false);assert_eq!(view["writeRestriction"],"IMPORTED_LAYOUT_UPDATE_UNAVAILABLE");
      assert_eq!(view["policyScope"],"structuredKuraConfiguration");assert_eq!(view["transaction"],Value::Null);
      let c=&view["candidate"];assert_eq!(c["schemaVersion"],4);assert_eq!(c["input"],f.model["modelRules"]["input"]);assert_eq!(c["portForward"],f.model["modelRules"]["portForward"]);
      assert_eq!(c["ipv4"],json!({"inputPolicy":"drop","forwardPolicy":"drop","outputPolicy":"accept","allowIcmp":true}));assert_eq!(c["ipv6"],c["ipv4"]);
      let nat=c["nat"].as_array().unwrap();assert_eq!(nat.len(),8);assert_eq!(&nat[..4],f.model["modelRules"]["nat"].as_array().unwrap().as_slice());
      for (index,family) in ["ipv4","ipv6"].iter().enumerate() {
          for (offset,masquerade) in [true,false].iter().enumerate() {
              assert_eq!(nat[4+index*2+offset],json!({"family":family,"inputInterface":if offset==0{"lan0"}else{"eth0"},"outputInterface":"wan0","masquerade":masquerade,"automatic":true}));
          }
      }
      assert_eq!(view["preservedSource"]["operationId"],json!(f.id));assert_eq!(view["preservedSource"]["initializationReceiptSha256"],source["initializationReceiptSha256"]);
      assert_eq!(view["preservedSource"]["families"]["ipv4"]["additionalRules"],f.model["families"][0]["additionalRules"]);
      assert!(view["preservedSource"]["families"]["ipv4"]["layout"]["tables"][0]["rules"].as_array().unwrap().iter().any(|r|r["specification"]=="-j RETURN"));
      assert_eq!(before,fs::read(f.store.journal_path()).unwrap());assert_eq!(policy,fs::read(f.root.join(POLICY)).unwrap());assert!(!f.root.join("firewall/transaction.json").exists());f.check_original();
      for method in ["firewall.kura.prepare","firewall.kura.confirm","firewall.kura.rollback"] {
          let error=engine.kura_request(method.into(),json!({}),"no-private-write".into(),77,true).await.unwrap_err();
          assert!(error.to_string().starts_with("UNSUPPORTED: imported"),"{method}: {error}");
      }
      assert_eq!(before,fs::read(f.store.journal_path()).unwrap());assert_eq!(policy,fs::read(f.root.join(POLICY)).unwrap());
      println!("IMPORTED_CORE_VIEW_FIXTURE={view}");
  }

  #[tokio::test]
  async fn imported_core_policies_are_the_acknowledged_kernel_values_even_when_model_defaults_differ() {
      let f=Fixture::with_changed_base_policies(true);f.initialize().unwrap();
      let engine=crate::firewall::Firewall::open(f.root.clone(),Some("/nonexistent/no-kernel-read".into())).unwrap();
      let view=engine.kura_request("firewall.kura.view".into(),json!({}),"policy-source".into(),77,false).await.unwrap();
      assert_eq!(view["candidate"]["ipv4"],json!({"inputPolicy":"accept","forwardPolicy":"drop","outputPolicy":"drop","allowIcmp":true}));
      assert_eq!(view["candidate"]["ipv6"],json!({"inputPolicy":"drop","forwardPolicy":"accept","outputPolicy":"accept","allowIcmp":true}));
      assert_eq!(view["preservedSource"]["policySourceKind"],"initialization.native.snapshot");
      assert_eq!(view["preservedSource"]["families"]["ipv4"]["layout"]["tables"][0]["chains"][0]["policy"],"DROP");
      f.check_original();
  }

  #[tokio::test]
  async fn imported_core_keeps_old_runtime_type_gap_visible_without_rebinding_the_original_evidence() {
      let f=Fixture::with_original_model(false,false);f.initialize().unwrap();let original=fs::read(f.store.journal_path()).unwrap();
      let engine=crate::firewall::Firewall::open(f.root.clone(),Some("/nonexistent/no-kernel-read".into())).unwrap();
      let view=engine.kura_request("firewall.kura.view".into(),json!({}),"old-model".into(),77,false).await.unwrap();
      assert_eq!(view["initialized"],true);assert_eq!(view["projectable"],false);assert_eq!(view["candidate"],Value::Null);
      assert_eq!(view["readRestriction"],"RUNTIME_NAT_TYPE_UNAVAILABLE");assert_eq!(view["preservedSource"]["operationId"],json!(f.id));
      assert_eq!(original,fs::read(f.store.journal_path()).unwrap());f.check_original();
  }

  #[tokio::test]
  async fn original_layout_preview_uses_original_receipt_and_explicit_intent_without_writing_a_transaction() {
      let f=Fixture::new();f.initialize().unwrap();let engine=crate::firewall::Firewall::open(f.root.clone(),Some("/nonexistent/never-run-nft".into())).unwrap();
      let core=engine.kura_request("firewall.kura.view".into(),json!({}),"before-preview".into(),77,false).await.unwrap();
      let before=fs::read(f.store.journal_path()).unwrap();let policy=fs::read(f.root.join(POLICY)).unwrap();let mut candidate=core["candidate"].clone();candidate["input"].as_array_mut().unwrap().remove(0);
      let input=json!({"expectedRevision":1,"sourceDigest":core["sourceDigest"],"candidate":candidate,"destinationPrefixes":{"ipv4":[24],"ipv6":[64]}});
      let result=engine.kura_request("firewall.kura.preview".into(),input.clone(),"preview-once".into(),77,false).await.unwrap();
      assert_eq!(result["reviewKind"],"nft.imported.layout.preview.v1");assert_eq!(result["operationId"],json!(f.id));assert_eq!(result["candidate"],candidate);assert_eq!(result["applyReady"],false);assert_eq!(result["writeEnabled"],false);assert_eq!(result["kernelObservation"],"initializationAcknowledgement");
      assert_eq!(result["draft"]["families"]["ipv4"]["destinationPrefixes"],json!([24]));assert!(result["compiledRuleCount"].as_u64().unwrap()>100);
      let mut stale=input.clone();stale["sourceDigest"]=json!("b".repeat(64));assert!(engine.kura_request("firewall.kura.preview".into(),stale,"stale-preview".into(),77,false).await.is_err());
      let mut supplied=input;supplied["model"]=f.model.clone();assert!(engine.kura_request("firewall.kura.preview".into(),supplied,"untrusted-model".into(),77,false).await.is_err());
      assert_eq!(before,fs::read(f.store.journal_path()).unwrap());assert_eq!(policy,fs::read(f.root.join(POLICY)).unwrap());assert!(!f.root.join("firewall/transaction.json").exists());f.check_original();
  }

  #[tokio::test]
  async fn old_forwarding_models_without_runtime_prefixes_remain_unprojectable_and_immutable() {
      let f=Fixture::with_model_metadata(false,true,false);f.initialize().unwrap();let engine=crate::firewall::Firewall::open(f.root.clone(),None).unwrap();
      let before=fs::read(f.store.journal_path()).unwrap();let view=engine.kura_request("firewall.kura.view".into(),json!({}),"old-prefix".into(),77,false).await.unwrap();
      assert_eq!(view["projectable"],false);assert_eq!(view["readRestriction"],"RUNTIME_FORWARD_PREFIX_UNAVAILABLE");assert_eq!(view["candidate"],Value::Null);assert_eq!(before,fs::read(f.store.journal_path()).unwrap());f.check_original();
  }

  #[tokio::test]
  async fn imported_core_view_refuses_uncommitted_replaced_and_overlapping_authority_without_repair() {
      for mode in ["intent","replaced","overlap","unsafe"] {
          let f=Fixture::new();let file=f.root.join(POLICY);
          if mode=="intent" {
              assert!(f.store.initialize_policy_fixture(f.id,&f.token,"actor",|b,id,p|f.inspect(b,id,p),|path,bytes|{durable::publish_new(path,bytes,FileMetadata::private())?;anyhow::bail!("lost publication reply")}).is_err());
          }else {
              f.initialize().unwrap();
              match mode {
                  "replaced"=>{let bytes=fs::read(&file).unwrap();fs::rename(&file,file.with_extension("retained")).unwrap();durable::publish_new(&file,&bytes,FileMetadata::private()).unwrap();},
                  "overlap"=>durable::json(&f.root.join("firewall/confirmed.json"),&json!({"revision":0,"text":null})).unwrap(),
                  "unsafe"=>{use std::os::unix::fs::PermissionsExt;fs::set_permissions(&file,fs::Permissions::from_mode(0o644)).unwrap();},
                  _=>unreachable!(),
              }
          }
          let engine=crate::firewall::Firewall::open(f.root.clone(),Some("/nonexistent/no-nft-for-imported-view".into())).unwrap();
          let before=fs::read(f.store.journal_path()).unwrap();let policy=fs::read(&file).unwrap();
          assert!(engine.kura_request("firewall.kura.view".into(),json!({}),"read-only".into(),77,false).await.is_err(),"{mode}");
          assert_eq!(before,fs::read(f.store.journal_path()).unwrap());assert_eq!(policy,fs::read(&file).unwrap());assert!(!f.root.join("firewall/transaction.json").exists());
      }
  }
