//! Registered Kura UID contract. An owner secret belongs to one authenticated
//! UI session. Neither a new connection nor an outcome query replays a write.
use super::*;

#[tokio::test]
async fn legacy_history_query_does_not_parse_a_current_imported_journal_or_call_a_backend() {
    let root=std::env::temp_dir().join(format!("legacy-history-query-{}",uuid::Uuid::new_v4()));
    let engine=Firewall::open(root.clone(),None).unwrap();let request="closed-private-history";
    let candidate_value=json!({"schemaVersion":4,"ipv4":{"inputPolicy":"drop","forwardPolicy":"drop","outputPolicy":"accept","allowIcmp":true},
        "ipv6":{"inputPolicy":"drop","forwardPolicy":"drop","outputPolicy":"accept","allowIcmp":true},"input":[],"portForward":[],"nat":[]});
    let change_value=json!({"ownerKey":"a".repeat(64),"expectedRevision":0,"sourceDigest":"c".repeat(64),"confirmSeconds":120,"candidate":candidate_value});
    let change:Change=serde_json::from_value(change_value.clone()).unwrap();
    let candidate:VersionedCandidate=serde_json::from_value(candidate_value).unwrap();
    let retained=Journal{id:"fw-old-history".into(),state:State::Committed,old:Confirmed{revision:0,text:None,candidate:None},candidate_text:candidate.render().unwrap(),candidate,
        deadline_ms:1,token:"retained-token".into(),request_id:request.into(),confirmed_decision:true,
        kura_binding:Some(change.binding(77).unwrap()),remote_binding:None,remote_actions:vec![]};
    let path=engine.history_path(77,request);durable::directory(path.parent().unwrap()).unwrap();durable::json(&path,&retained).unwrap();
    durable::json(&root.join("firewall/transaction.json"),&json!({"backend":"nft.imported.v1","state":"APPLYING"})).unwrap();
    durable::json(&root.join("firewall/imported-confirmed.json"),&json!({"unavailableCurrentEvidence":true})).unwrap();
    let archive=durable::read(&path,LIMIT).unwrap().0;
    let active=durable::read(&root.join("firewall/transaction.json"),LIMIT).unwrap().0;
    let current=durable::read(&root.join("firewall/imported-confirmed.json"),LIMIT).unwrap().0;
    let input=json!({"originalRequestId":request,"change":change_value});
    let outcome=engine.kura_request("firewall.kura.outcome".into(),input.clone(),"query-only".into(),77,false).await.unwrap();
    assert_eq!(outcome["id"],retained.id);assert_eq!(outcome["state"],"COMMITTED");assert_eq!(outcome["revision"],1);
    assert_eq!(outcome["requestId"],request);assert_eq!(outcome["historical"],true);
    assert!(outcome["currentRevision"].is_null());assert_eq!(outcome["currentRevisionAvailable"],false);
    let mut wrong_owner=input.clone();wrong_owner["change"]["ownerKey"]=json!("b".repeat(64));
    assert!(engine.kura_request("firewall.kura.outcome".into(),wrong_owner,"wrong-owner".into(),77,false).await.unwrap_err().to_string().starts_with("FORBIDDEN:"));
    let mut wrong_input=input;wrong_input["change"]["sourceDigest"]=json!("d".repeat(64));
    assert!(engine.kura_request("firewall.kura.outcome".into(),wrong_input,"wrong-input".into(),77,false).await.unwrap_err().to_string().starts_with("CONFLICT:"));
    assert_eq!(durable::read(&path,LIMIT).unwrap().0,archive);
    assert_eq!(durable::read(&root.join("firewall/transaction.json"),LIMIT).unwrap().0,active);
    assert_eq!(durable::read(&root.join("firewall/imported-confirmed.json"),LIMIT).unwrap().0,current);
    assert_eq!(engine.test_backend_invocations(),0);std::fs::remove_dir_all(root).unwrap();
}
use sha2::{Digest, Sha256};

/// Validate a rule-only original CM projection through the actual v3 compiler.
/// Fixed validation policies are never returned,persisted or applied as policy.
pub(crate) fn validate_legacy_source_rules(rules:&Value)->Result<()> {
    compile_legacy_source_rules(rules)?;Ok(())
}
/// Validate a Core configuration projection. The compiled private-layout text
/// is discarded and never used as imported policy or update authority.
pub(crate) fn validate_core_projection(candidate:&Value)->Result<()> {
    model::compile_original_policy(candidate.clone())?;Ok(())
}
/// Compile a review draft only. No confirmed file,admission or kernel operation.
pub(crate) fn legacy_import_policy_digest(candidate:Value)->Result<String> {
    Ok(durable::hash(model::compile_original_policy(candidate)?.text.as_bytes()))
}
fn compile_legacy_source_rules(rules:&Value)->Result<Value> {
    let object=rules.as_object().context("CONFLICT: original firewall rules")?;
    ensure!(object.len()==3 && ["input","portForward","nat"].iter().all(|key|object.get(*key).is_some_and(Value::is_array)),
        "CONFLICT: original firewall rule fields");
    ensure!(rules["nat"].as_array().unwrap().iter().all(|row|row["automatic"]==false),
        "CONFLICT: stored CM cannot attest automatic NAT");
    let policy=json!({"inputPolicy":"drop","forwardPolicy":"drop","allowIcmp":false});
    let candidate:model::KuraCandidate=serde_json::from_value(json!({"schemaVersion":3,
        "ipv4":policy,"ipv6":policy,"input":rules["input"],"portForward":rules["portForward"],"nat":rules["nat"]}))?;
    model::expected_table(&candidate.compile()?.text)
}

/// Original stored clauses must agree with the actual initialized policy before
/// a new admission/activation. This never claims policies or automatic/foreign rules.
pub(crate) fn require_original_static_rules(root:&std::path::Path,rules:&Value)->Result<()> {
    if let Some(source)=crate::nm::handover::initialization::confirmed_source(root,None)? {
        ensure!(compile_legacy_source_rules(&source["originalStaticRules"])?==compile_legacy_source_rules(rules)?,"CONFLICT: original CM static rules differ from initialized imported source");return Ok(());
    }
    let confirmed=confirmed_core_source(root)?;
    let candidate=confirmed.kura_policy()?.context("UNSUPPORTED: projectable firewall source")?;
    let value=serde_json::to_value(&candidate)?;
    let nat=value["nat"].as_array().context("CONFLICT: confirmed NAT rules")?.iter()
        .filter(|row|row["automatic"]!=true).cloned().collect::<Vec<_>>();
    let actual=json!({"input":value["input"],"portForward":value["portForward"],"nat":nat});
    ensure!(compile_legacy_source_rules(&actual)?==compile_legacy_source_rules(rules)?,
        "CONFLICT: original CM static rules differ from the initialized confirmed firewall policy");Ok(())
}

/// Pure confirmed-file observation for the existing guarded NM/Core admission.
/// It neither acquires a second OS guard nor executes/adopts a kernel ruleset.
pub(crate) struct CoreConfirmedWitness {
    pub(crate) revision: u64,
    pub(crate) source_digest: String,
}

pub(crate) fn core_confirmed_witness(root: &std::path::Path) -> Result<CoreConfirmedWitness> {
    if let Some(source)=crate::nm::handover::initialization::confirmed_source(root,None)? {
        return Ok(CoreConfirmedWitness{revision:source["revision"].as_str().and_then(|v|v.parse().ok()).context("CONFLICT: imported firewall revision")?,
            source_digest:source["sourceDigest"].as_str().context("CONFLICT: imported firewall source digest")?.into()});
    }
    let confirmed=confirmed_core_source(root)?;
    Ok(CoreConfirmedWitness {
        revision: confirmed.revision,
        source_digest: digest(&serde_json::to_vec(&confirmed)?),
    })
}
fn confirmed_core_source(root:&std::path::Path)->Result<Confirmed> {
    let (bytes, metadata) = durable::read(&root.join("firewall/confirmed.json"), LIMIT)
        .context("UNSUPPORTED: initialized confirmed firewall source is unavailable")?;
    ensure!(metadata.uid == unsafe { libc::geteuid() } && metadata.mode == 0o600,
        "FORBIDDEN: unsafe confirmed firewall source");
    let confirmed: Confirmed = serde_json::from_slice(&bytes)?;
    ensure!(confirmed.revision > 0 && confirmed.kura_policy()?.is_some(),
        "UNSUPPORTED: initialized projectable confirmed firewall policy required");
    Ok(confirmed)
}

/// Verify the complete currently observed ruleset against existing private
/// confirmed authority. This neither creates policy nor owns/deletes foreign
/// objects. The caller supplies the bounded runner's actual read,not RPC input.
pub(crate) fn initialized_kernel_source(root:&std::path::Path,ruleset:&Value)->Result<Value> {
    if let Some(source)=crate::nm::handover::initialization::confirmed_source(root,Some(ruleset))? {return Ok(source);}
    let object=ruleset.as_object().context("CONFLICT: kernel ruleset envelope")?;
    ensure!(object.len()==1,"CONFLICT: unexpected kernel ruleset fields");
    let entries=object.get("nftables").and_then(Value::as_array).context("CONFLICT: kernel ruleset entries")?;
    ensure!(entries.len()<=4096 && serde_json::to_vec(ruleset)?.len() as u64<=LIMIT,
        "RESOURCE_EXHAUSTED: kernel ruleset source bounds");
    let file=root.join("firewall/confirmed.json");
    let (before,metadata)=durable::read(&file,LIMIT)?;
    ensure!(metadata.uid==unsafe {libc::geteuid()} && metadata.mode==0o600,"FORBIDDEN: unsafe confirmed firewall source");
    let raw:Value=serde_json::from_slice(&before)?;
    ensure!(raw.as_object().is_some_and(|value|value.len()==3 && ["revision","text","candidate"].iter().all(|key|value.contains_key(*key))),
        "CONFLICT: unrecognized confirmed firewall source fields");
    let confirmed=confirmed_core_source(root)?;
    let mut own=Vec::new();
    for entry in entries {
        let object=entry.as_object().context("CONFLICT: kernel rule object")?;
        ensure!(object.len()==1,"CONFLICT: ambiguous kernel rule object");
        let (kind,value)=object.iter().next().unwrap();
        if kind=="metainfo" {
            ensure!(value.is_object(),"CONFLICT: kernel metadata");continue;
        }
        ensure!(matches!(kind.as_str(),"table"|"chain"|"rule"),"FORBIDDEN: unsupported or foreign kernel object");
        let name=if kind=="table" {&value["name"]}else{&value["table"]};
        ensure!(value["family"]=="inet","FORBIDDEN: foreign kernel firewall family");
        if name==TABLE {own.push(entry.clone());}
        else {ensure!(name=="yofc_nm","FORBIDDEN: foreign kernel firewall table");}
    }
    let actual=model::semantic_table(&own)?;
    let expected=model::expected_table(confirmed.text.as_deref().context("CONFLICT: confirmed policy text")?)?;
    ensure!(actual==expected,"CONFLICT: full confirmed firewall policy differs from the current kernel");
    let nat=crate::nm::ownership::kernel_authority(root,ruleset)?;
    let (after,after_metadata)=durable::read(&file,LIMIT)?;
    ensure!(after==before && after_metadata.uid==metadata.uid && after_metadata.mode==metadata.mode,
        "CONFLICT: confirmed firewall source changed during kernel observation");
    ensure!(serde_json::to_value(&confirmed)?==raw,"CONFLICT: kernel observation and confirmed source differ");
    Ok(json!({"schemaVersion":1,"sourceKind":"nft.current.confirmed.v1",
        "revision":confirmed.revision.to_string(),"confirmedSha256":durable::hash(&before),
        "sourceDigest":digest(&serde_json::to_vec(&confirmed)?),"policy":confirmed.candidate,
        "semanticDigest":digest(&serde_json::to_vec(&actual)?),"automaticNatAuthority":nat}))
}

#[cfg(test)]
pub(crate) fn confirmed_kernel_fixture(root:&std::path::Path)->Result<Value> {
    let confirmed=confirmed_core_source(root)?;
    Ok(fake_table(confirmed.text.as_deref().context("fixture confirmed text")?))
}

#[cfg(test)]
pub(crate) fn seed_confirmed_core_fixture(root: &std::path::Path) -> Result<()> {
    // Fresh mutable unit fixtures only;never overwrite a retained operation or
    // claim that a stored policy initializes/adopts a kernel ruleset.
    let file=root.join("firewall/confirmed.json");
    ensure!(!file.exists(),"test confirmed source already exists");
    let candidate:model::KuraCandidate=serde_json::from_value(json!({"schemaVersion":3,
        "ipv4":{"inputPolicy":"accept","forwardPolicy":"accept","allowIcmp":true},
        "ipv6":{"inputPolicy":"accept","forwardPolicy":"accept","allowIcmp":true},
        "input":[],"portForward":[],"nat":[]}))?;
    let confirmed=Confirmed{revision:1,text:Some(candidate.compile()?.text),candidate:Some(VersionedCandidate::V3(candidate))};
    durable::directory(file.parent().unwrap())?;durable::json(&file,&confirmed)
}

#[cfg(test)]
mod core_owner_tests {
    use super::*;

    fn kernel_source_fixture()->(std::path::PathBuf,Value) {
        let root=std::env::temp_dir().join(format!("confirmed-kernel-source-{}",uuid::Uuid::new_v4()));
        durable::directory(&root).unwrap();seed_confirmed_core_fixture(&root).unwrap();
        let kernel=confirmed_kernel_fixture(&root).unwrap();(root,kernel)
    }

    #[test]
    fn current_kernel_policy_checks_full_policy_icmp_and_order_without_writing_source() {
        let (root,kernel)=kernel_source_fixture();let file=root.join("firewall/confirmed.json");let before=std::fs::read(&file).unwrap();
        let observed=initialized_kernel_source(&root,&kernel).unwrap();
        assert_eq!(observed["sourceKind"],"nft.current.confirmed.v1");
        assert_eq!(observed["policy"]["ipv4"]["allowIcmp"],true);
        assert_eq!(observed["confirmedSha256"],durable::hash(&before));
        let mut handles=kernel.clone();
        for entry in handles["nftables"].as_array_mut().unwrap() {
            entry.as_object_mut().unwrap().values_mut().next().unwrap()["handle"]=json!(123);
        }
        handles["nftables"].as_array_mut().unwrap().push(json!({"metainfo":{"version":"owned fixture"}}));
        assert_eq!(initialized_kernel_source(&root,&handles).unwrap(),observed);
        let mut wrong=kernel.clone();
        let chain=wrong["nftables"].as_array_mut().unwrap().iter_mut().find(|entry|!entry["chain"]["policy"].is_null()).unwrap();
        chain["chain"]["policy"]=json!("drop");assert!(initialized_kernel_source(&root,&wrong).is_err());
        let mut no_icmp=kernel.clone();let entries=no_icmp["nftables"].as_array_mut().unwrap();
        let index=entries.iter().position(|entry|entry["rule"]["expr"].to_string().contains("icmp")).unwrap();entries.remove(index);
        assert!(initialized_kernel_source(&root,&no_icmp).is_err());
        let mut reordered=kernel.clone();let entries=reordered["nftables"].as_array_mut().unwrap();
        let first=entries.iter().position(|entry|entry["rule"]["chain"].is_string()).unwrap();
        let second=(first+1..entries.len()).find(|index|entries[*index]["rule"]["chain"]==entries[first]["rule"]["chain"]).unwrap();
        entries.swap(first,second);assert!(initialized_kernel_source(&root,&reordered).is_err());
        assert_eq!(std::fs::read(file).unwrap(),before);
    }

    #[test]
    fn current_kernel_source_never_adopts_foreign_objects_names_or_unproven_nat() {
        let (root,kernel)=kernel_source_fixture();let file=root.join("firewall/confirmed.json");let before=std::fs::read(&file).unwrap();
        for extra in [json!({"table":{"family":"ip","name":"filter"}}),
            json!({"table":{"family":"inet","name":"docker"}}),
            json!({"set":{"family":"inet","table":"yofc_kura","name":"extra"}}),
            json!({"table":{"family":"inet","name":"yofc_kura"}}),
            json!({"table":{"family":"inet","name":"yofc_nm"}}),
            json!({"metainfo":null}),json!({"table":{},"rule":{}})] {
            let mut wrong=kernel.clone();wrong["nftables"].as_array_mut().unwrap().push(extra);
            assert!(initialized_kernel_source(&root,&wrong).is_err());
        }
        let mut extra=kernel.clone();extra["unrecognized"]=json!(true);assert!(initialized_kernel_source(&root,&extra).is_err());
        assert!(initialized_kernel_source(&root,&json!({"nftables":[]})).is_err());
        assert_eq!(std::fs::read(file).unwrap(),before);assert!(!root.join("nm/nat-confirmed.json").exists());
    }

    #[test]
    fn current_kernel_source_refuses_uninitialized_or_unrecognized_confirmed_file_without_repair() {
        let (root,kernel)=kernel_source_fixture();let file=root.join("firewall/confirmed.json");
        let before=std::fs::read(&file).unwrap();let mut value:Value=serde_json::from_slice(&before).unwrap();
        for changed in [json!({"revision":0,"text":null}),{value["foreign"]=json!(true);value}] {
            durable::json(&file,&changed).unwrap();let bytes=std::fs::read(&file).unwrap();
            assert!(initialized_kernel_source(&root,&kernel).is_err());assert_eq!(std::fs::read(&file).unwrap(),bytes);
        }
    }

    #[cfg(target_os="linux")]
    #[tokio::test]
    #[ignore = "new owned network-none nft namespace;explicit v24 fixture only"]
    async fn current_kernel_actual_nft_in_owned_namespace() {
        use std::os::unix::fs::OpenOptionsExt;
        let root=std::path::PathBuf::from(std::env::var("YOFC_FW_KERNEL_V24_ROOT").expect("explicit owned fixture root"));
        assert!(root.is_absolute());
        let authority:Value=serde_json::from_slice(&durable::read(&root.join("fixture-authority.json"),LIMIT).unwrap().0).unwrap();
        assert_eq!(authority["scope"],"kernel-policy-provenance-v24");
        assert_eq!(authority["networkNamespace"],std::fs::read_link("/proc/self/ns/net").unwrap().to_str().unwrap());
        assert_eq!(authority["hostname"],std::fs::read_to_string("/etc/hostname").unwrap().trim());
        let _once=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(root.join("fixture-started")).unwrap();
        assert!(!root.join("firewall/confirmed.json").exists());
        let firewall=Firewall::open(root.clone(),Some("/usr/sbin/nft".into())).unwrap().enable_writes(true);
        firewall.0.real.store(true,std::sync::atomic::Ordering::Relaxed);
        let before:Value=serde_json::from_str(&firewall.run_nft(&["-j","-p","list","ruleset"],None).unwrap()).unwrap();
        assert!(before["nftables"].as_array().unwrap().iter().all(|entry|entry.get("metainfo").is_some()),"owned namespace must start empty");
        let candidate=json!({"schemaVersion":3,"ipv4":{"inputPolicy":"drop","forwardPolicy":"drop","allowIcmp":true},
            "ipv6":{"inputPolicy":"accept","forwardPolicy":"drop","allowIcmp":false},
            "input":[{"family":"ipv4","protocol":"tcp","ports":{"first":22,"last":22}}],"portForward":[],"nat":[]});
        let prepared=firewall.prepare(candidate,60,"current-kernel-v24-owned".into()).await.unwrap();
        firewall.apply().await.unwrap();firewall.confirm(prepared["token"].as_str().unwrap()).await.unwrap();
        let kernel:Value=serde_json::from_str(&firewall.run_nft(&["-j","-p","list","ruleset"],None).unwrap()).unwrap();
        durable::json(&root.join("kernel-confirmed.json"),&kernel).unwrap();
        let observed=initialized_kernel_source(&root,&kernel).unwrap();
        durable::json(&root.join("policy-observation.json"),&observed).unwrap();
        let source=std::fs::read(root.join("firewall/confirmed.json")).unwrap();
        firewall.run_nft(&["-f","-"],Some("add table inet v24_foreign\n")).unwrap();
        let foreign:Value=serde_json::from_str(&firewall.run_nft(&["-j","-p","list","ruleset"],None).unwrap()).unwrap();
        durable::json(&root.join("kernel-with-foreign.json"),&foreign).unwrap();
        assert!(initialized_kernel_source(&root,&foreign).is_err());
        let after:Value=serde_json::from_str(&firewall.run_nft(&["-j","-p","list","ruleset"],None).unwrap()).unwrap();
        assert_eq!(after,foreign);assert_eq!(std::fs::read(root.join("firewall/confirmed.json")).unwrap(),source);
        durable::json(&root.join("fixture-result.json"),&json!({"passed":true,"actualNft":true,
            "sourceKind":observed["sourceKind"],"foreignPreserved":true,"normalAgentStarted":false,
            "legacyOrFullSystemAdoption":false})).unwrap();
    }

    #[test]
    fn original_static_rules_must_match_initialized_policy_without_claiming_family_policies() {
        let root=std::env::temp_dir().join(format!("stored-policy-match-{}",uuid::Uuid::new_v4()));durable::directory(&root).unwrap();
        let rules=json!({"input":[{"family":"ipv4","protocol":"tcp","ports":{"first":22,"last":22},"source":"192.0.2.7/24"}],"portForward":[],"nat":[]});
        assert!(require_original_static_rules(&root,&rules).is_err());seed_confirmed_core_fixture(&root).unwrap();
        let file=root.join("firewall/confirmed.json");let before=std::fs::read(&file).unwrap();assert!(require_original_static_rules(&root,&rules).is_err());assert_eq!(std::fs::read(&file).unwrap(),before);
        let candidate:model::KuraCandidate=serde_json::from_value(json!({"schemaVersion":3,
            "ipv4":{"inputPolicy":"accept","forwardPolicy":"drop","allowIcmp":true},
            "ipv6":{"inputPolicy":"drop","forwardPolicy":"accept","allowIcmp":false},
            "input":[{"family":"ipv4","protocol":"tcp","ports":{"first":22,"last":22},"source":"192.0.2.0/24"}],"portForward":[],"nat":[]})).unwrap();
        let confirmed=Confirmed{revision:2,text:Some(candidate.compile().unwrap().text),candidate:Some(VersionedCandidate::V3(candidate))};durable::json(&file,&confirmed).unwrap();
        let before=std::fs::read(&file).unwrap();require_original_static_rules(&root,&rules).unwrap();assert_eq!(std::fs::read(&file).unwrap(),before);
        let mut changed=rules;changed["input"][0]["ports"]["first"]=json!(23);changed["input"][0]["ports"]["last"]=json!(23);
        assert!(require_original_static_rules(&root,&changed).is_err());assert_eq!(std::fs::read(&file).unwrap(),before);std::fs::remove_dir_all(root).unwrap();
    }

    #[ignore = "explicit owned Core/Java/Rust exchange fixture;not a kernel or normal-agent acceptance"]
    #[tokio::test]
    async fn core_owner_exchange_fixture() {
        let root=std::path::PathBuf::from(std::env::var("YOFC_CORE_OWNER_EXCHANGE_ROOT").expect("explicit owned fixture root"));
        assert!(root.is_absolute());assert_eq!(root.canonicalize().unwrap(),root);
        assert_eq!(std::fs::read(root.join(".owned-core-owner-exchange")).unwrap(),b"YOFC_CORE_OWNER_V22\n");
        let phase=std::env::var("YOFC_CORE_OWNER_EXCHANGE_PHASE").expect("explicit export/verify phase");
        match phase.as_str() {
            "export"=>{
                let engine=Firewall::open(root.clone(),None).unwrap().enable_writes(false);seed_confirmed_core_fixture(&root).unwrap();
                let value=engine.kura_request("firewall.kura.view".into(),json!({}),uuid::Uuid::new_v4().to_string(),unsafe{libc::geteuid()},false).await.unwrap();
                assert_eq!(value["projectable"],true);assert_eq!(value["writeEnabled"],false);
                durable::publish_new(&root.join("firewall-view.json"),&serde_json::to_vec(&value).unwrap(),durable::FileMetadata::private()).unwrap();
                println!("EXPORTED actualReadOnlyFirewallView=true kernelAdoptionClaimed=false");
            }
            "verify"=>{
                let bytes=durable::read(&root.join("owner-wire.json"),LIMIT).unwrap().0;
                let value:Value=serde_json::from_slice(&bytes).unwrap();
                let owner=crate::nm::roles::Owner::new(uuid::Uuid::new_v4(),1,value.clone()).unwrap();
                let current=core_confirmed_witness(&root).unwrap();owner.require_firewall(current.revision,&current.source_digest).unwrap();
                let mut historical=value;historical["schemaVersion"]=json!(1);historical.as_object_mut().unwrap().remove("firewall");
                assert!(crate::nm::roles::Owner::new(uuid::Uuid::new_v4(),1,historical).is_err());
                durable::publish_new(&root.join("rust-verification.json"),&serde_json::to_vec(&json!({"schemaVersion":1,
                    "actualJavaCoreThreeHandlerProjectionParsed":true,"actualFullPolicyDigestMatched":true,
                    "networkOnlyDowngradeRejected":true,"kernelAdoptionClaimed":false})).unwrap(),durable::FileMetadata::private()).unwrap();
                println!("VERIFIED actualJavaCoreThreeHandlerProjection=true fullPolicyDigestMatched=true normalAgentStarted=false");
            }
            _=>panic!("unknown owned fixture phase"),
        }
    }

    #[test]
    fn core_witness_commits_the_whole_confirmed_policy_without_rewriting_or_running_a_backend() {
        let root=std::env::temp_dir().join(format!("kura-core-firewall-{}",uuid::Uuid::new_v4()));
        durable::directory(&root).unwrap();
        assert!(core_confirmed_witness(&root).is_err());assert!(!root.join("firewall/confirmed.json").exists());
        seed_confirmed_core_fixture(&root).unwrap();
        let file=root.join("firewall/confirmed.json");let before=std::fs::read(&file).unwrap();
        let confirmed:Confirmed=serde_json::from_slice(&before).unwrap();
        let observed=core_confirmed_witness(&root).unwrap();
        assert_eq!(observed.revision,1);assert_eq!(observed.source_digest,digest(&serde_json::to_vec(&confirmed).unwrap()));
        assert_eq!(std::fs::read(&file).unwrap(),before);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_digest_cannot_replace_initialization_projectability_or_exact_compiled_text() {
        for defect in ["revision","text","candidate","permissions"] {
            let root=std::env::temp_dir().join(format!("kura-core-firewall-refusal-{}",uuid::Uuid::new_v4()));
            durable::directory(&root).unwrap();seed_confirmed_core_fixture(&root).unwrap();
            let file=root.join("firewall/confirmed.json");
            let mut confirmed:Confirmed=serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
            match defect {
                "revision"=>confirmed.revision=0,
                "text"=>confirmed.text=Some("unrelated rules".into()),
                "candidate"=>confirmed.candidate=None,
                _=>{},
            }
            durable::json(&file,&confirmed).unwrap();
            if defect=="permissions" {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&file,std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            let before=std::fs::read(&file).unwrap();assert!(core_confirmed_witness(&root).is_err());
            assert_eq!(std::fs::read(&file).unwrap(),before);std::fs::remove_dir_all(root).unwrap();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Binding {
    uid: u32,
    owner_digest: String,
    input_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Change {
    owner_key: String,
    expected_revision: u64,
    source_digest: String,
    confirm_seconds: u64,
    candidate: model::KuraPolicy,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Outcome {
    original_request_id: String,
    change: Change,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Action {
    owner_key: String,
    id: String,
    token: String,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn request_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)),
        "INVALID_ARGUMENT: request ID"
    );
    Ok(())
}
fn owner(key: &str) -> Result<String> {
    ensure!(
        key.len() == 64 && key.bytes().all(|c| c.is_ascii_hexdigit()),
        "INVALID_ARGUMENT: owner key"
    );
    Ok(digest(key.as_bytes()))
}
impl Change {
    fn binding(&self, uid: u32) -> Result<Binding> {
        ensure!(
            (30..=300).contains(&self.confirm_seconds),
            "INVALID_ARGUMENT: confirmation window"
        );
        ensure!(
            self.source_digest.len() == 64
                && self.source_digest.bytes().all(|c| c.is_ascii_hexdigit()),
            "INVALID_ARGUMENT: source digest"
        );
        self.candidate.compile()?;
        Ok(Binding {
            uid,
            owner_digest: owner(&self.owner_key)?,
            input_digest: digest(&serde_json::to_vec(self)?),
        })
    }
}
impl Firewall {
    fn require_private_kura_backend(&self)->Result<()> {
        ensure!(crate::nm::handover::initialization::confirmed_source(&self.0.root,None)?.is_none(),
            "UNSUPPORTED: imported layout requires its own update coordinator");Ok(())
    }
    fn history_path(&self, uid: u32, request: &str) -> PathBuf {
        self.0.state.join("kura-history").join(format!(
            "{}.json",
            digest(format!("{uid}:{request}").as_bytes())
        ))
    }
    pub(super) fn archive_kura(&self, journal: &Journal) -> Result<()> {
        if let Some(binding) = &journal.kura_binding {
            ensure!(
                journal.state.settled(),
                "CONFLICT: active firewall transaction"
            );
            let path = self.history_path(binding.uid, &journal.request_id);
            if path.exists() {
                let retained: Journal = serde_json::from_slice(&durable::read(&path, LIMIT)?.0)?;
                ensure!(
                    serde_json::to_vec(&retained)? == serde_json::to_vec(journal)?,
                    "CONFLICT: retained firewall outcome differs"
                );
            } else {
                durable::directory(path.parent().unwrap())?;
                durable::json(&path, journal)?;
            }
        }
        Ok(())
    }
    fn original(&self, uid: u32, request: &str) -> Result<Option<Journal>> {
        let path = self.history_path(uid, request);
        if !path.exists() {
            if let Some(j)=self.journal()?&&j.request_id==request&&j.kura_binding.as_ref().is_some_and(|b|b.uid==uid) {return Ok(Some(j));}
            return Ok(None);
        }
        let bytes=durable::read(&path,LIMIT)?.0;let value:Value=serde_json::from_slice(&bytes)?;
        ensure!(value.get("backend").is_none(),"UNSUPPORTED: original outcome belongs to a typed firewall backend");
        let j: Journal = serde_json::from_slice(&bytes)?;
        ensure!(
            j.request_id == request && j.kura_binding.as_ref().is_some_and(|b| b.uid == uid),
            "CONFLICT: retained firewall outcome identity"
        );
        Ok(Some(j))
    }
    fn receipt_projection(j: &Journal, owned: bool) -> Value {
        let mut value = json!({"id":j.id,"state":j.state,"deadlineUnixMs":j.deadline_ms,
            "revision":if j.state == State::Committed { j.old.revision + 1 } else { j.old.revision },
            "requestId":j.request_id});
        if owned {
            value["confirmationToken"] = json!(j.token);
        }
        value
    }
    fn projection(&self, j: &Journal, owned: bool) -> Result<Value> {
        let mut value = Self::receipt_projection(j, owned);
        value["currentRevision"] = json!(self.confirmed()?.revision);
        Ok(value)
    }
    pub(super) async fn observe<T: Send + 'static>(
        &self,
        action: impl FnOnce(&Self) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = Guard::observe_shared(&this.0.root, std::time::Duration::from_secs(1))?;
            action(&this)
        })
        .await?
    }
    pub(crate) async fn kura_request(
        &self,
        method: String,
        params: Value,
        request: String,
        uid: u32,
        write_grant: bool,
    ) -> Result<Value> {
        match method.as_str() {
            "firewall.kura.preview" => {
                request_id(&request)?;
                self.observe(move |this|crate::nm::handover::initialization::preview_update(&this.0.root,params)).await
            }
            "firewall.kura.view" => {
                ensure!(
                    params == json!({}) || params.is_null(),
                    "INVALID_ARGUMENT: view fields"
                );
                self.observe(move |this| {
                    if let Some(view)=crate::nm::handover::initialization::core_view(&this.0.root)? {return Ok(view);}
                    let confirmed = this.confirmed()?;
                    let candidate = confirmed.kura_policy()?;
                    let transaction = this.journal()?.as_ref().map(|j| this.projection(j, false)).transpose()?;
                    Ok(json!({"schemaVersion":1,"revision":confirmed.revision,
                        "sourceDigest":digest(&serde_json::to_vec(&confirmed)?),"initialized":confirmed.text.is_some(),
                        "projectable":candidate.is_some(),"candidate":candidate,
                        "writeEnabled":this.0.write_enabled && write_grant,"transaction":transaction}))
                }).await
            }
            "firewall.kura.prepare" => {
                ensure!(
                    write_grant && self.0.write_enabled,
                    "FORBIDDEN: Kura firewall write grant disabled"
                );
                request_id(&request)?;
                self.observe(|this|this.require_private_kura_backend()).await?;
                let change: Change = serde_json::from_value(params)
                    .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: firewall change"))?;
                let binding = change.binding(uid)?;
                let candidate = VersionedCandidate::from(change.candidate.clone());
                let text = candidate.render()?;
                self.write(move |this| {
                    this.require_private_kura_backend()?;
                    // Even an identical duplicate is never an apply retry.
                    ensure!(
                        this.original(uid, &request)?.is_none(),
                        "OUTCOME_UNKNOWN: query the original request"
                    );
                    let old = this.confirmed()?;
                    ensure!(
                        old.revision == change.expected_revision
                            && digest(&serde_json::to_vec(&old)?) == change.source_digest,
                        "CONFLICT: stale confirmed firewall view"
                    );
                    let mut j = this.prepare_inner(
                        candidate,
                        text,
                        change.confirm_seconds,
                        request,
                        Some(binding),
                    )?;
                    this.apply_inner(&mut j)?;
                    this.projection(&j, true)
                })
                .await
            }
            "firewall.kura.outcome" => {
                let input: Outcome = serde_json::from_value(params)
                    .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: outcome fields"))?;
                request_id(&input.original_request_id)?;
                let binding = input.change.binding(uid)?;
                self.observe(move |this| {
                    let j = this
                        .original(uid, &input.original_request_id)?
                        .context("OUTCOME_UNKNOWN: no durable original outcome")?;
                    let retained = j
                        .kura_binding
                        .as_ref()
                        .context("OUTCOME_UNKNOWN: no owner binding")?;
                    ensure!(
                        retained.uid == binding.uid
                            && retained.owner_digest == binding.owner_digest,
                        "FORBIDDEN: transaction owner"
                    );
                    ensure!(
                        retained.input_digest == binding.input_digest,
                        "CONFLICT: original input differs"
                    );
                    if this.history_path(uid, &input.original_request_id).exists() {
                        // An immutable historical outcome does not depend on
                        // the current backend or the availability of its proof.
                        let mut value = Self::receipt_projection(&j, true);
                        value["historical"] = json!(true);
                        value["currentRevision"] = Value::Null;
                        value["currentRevisionAvailable"] = json!(false);
                        return Ok(value);
                    }
                    this.projection(&j, true)
                })
                .await
            }
            "firewall.kura.confirm" | "firewall.kura.rollback" => {
                let confirm = method == "firewall.kura.confirm";
                // Revoking a grant does not remove explicit compensation.
                ensure!(
                    !confirm || (write_grant && self.0.write_enabled),
                    "FORBIDDEN: Kura firewall write grant disabled"
                );
                self.observe(|this|this.require_private_kura_backend()).await?;
                let input: Action = serde_json::from_value(params)
                    .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT: action fields"))?;
                let owner_digest = owner(&input.owner_key)?;
                self.write(move |this| {
                    this.require_private_kura_backend()?;
                    let mut j = this.journal()?.context("CONFLICT: no transaction")?;
                    let b = j
                        .kura_binding
                        .as_ref()
                        .context("FORBIDDEN: not a Kura transaction")?;
                    ensure!(
                        b.uid == uid
                            && b.owner_digest == owner_digest
                            && j.id == input.id
                            && j.token == input.token,
                        "FORBIDDEN: transaction owner or token"
                    );
                    if confirm {
                        ensure!(
                            j.state == State::WaitConfirm && now() < j.deadline_ms,
                            "CONFLICT: transaction state or deadline"
                        );
                        this.verify(Some(&j.candidate_text))?;
                        j.confirmed_decision = true;
                        j.state = State::Confirming;
                        this.persist("transaction.json", &j)?;
                        this.commit(&mut j)?;
                    } else {
                        ensure!(!j.state.settled(), "CONFLICT: transaction state");
                        this.rollback_inner(&mut j)?;
                    }
                    this.projection(&j, false)
                })
                .await
            }
            _ => anyhow::bail!("UNSUPPORTED: Kura firewall method"),
        }
    }
}
