//! Original-bound native deltas. Opaque additional/foreign objects stay in place;
//! no table/chain flush,foreign rewrite or command-text interpretation is used.
//! The existing ownership Store journals intent before dispatching these batches.
use super::*;
use std::collections::{BTreeMap,BTreeSet};

#[cfg_attr(not(target_os="linux"),allow(dead_code))]
pub(in crate::nm) mod raw;
pub(in crate::nm) mod classify;
pub(in crate::nm) mod factory;
pub(in crate::nm) mod lineage;
pub(in crate::nm) mod epoch;
const MAX_BYTES:usize=512*1024;
// nf_tables_commit increments the u32 base sequence once and skips zero.
pub(super) fn next_generation(generation:u32)->u32 {generation.wrapping_add(1).max(1)}
pub(in crate::nm) fn canonical_source(value:&Value)->Result<Value> {
    let snapshot=Snapshot::read(value)?;
    ensure!(snapshot.generation.is_some()&&snapshot.payloads.len()==snapshot.fingerprints.len()&&!snapshot.fingerprints.is_empty(),"CONFLICT: complete native parameters and generation required");
    Ok(factory::canonical_source(&snapshot))
}

#[cfg(test)]
pub(in crate::nm) mod outcome_tests;

#[derive(Clone,Deserialize,Serialize,PartialEq,Eq,PartialOrd,Ord)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(in crate::nm) struct Chain {pub(in crate::nm) family:String,pub(in crate::nm) table:String,pub(in crate::nm) name:String}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(in crate::nm) struct Rules {
    pub(in crate::nm) chain:Chain,
    /// Explicit original handles in their original order,not ownership by name.
    pub(in crate::nm) original:Vec<u64>,
    pub(in crate::nm) before:Option<u64>,
    pub(in crate::nm) replacement:Vec<Vec<Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize,Ordering};
    fn source()->Value {
        let mut source=json!({"nftables":[{"metainfo":{"json_schema_version":1}},
            {"table":{"family":"ip","name":"filter","handle":1}},
            {"chain":{"family":"ip","table":"filter","name":"INPUT","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
            {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":10,"expr":[{"counter":{"packets":1,"bytes":2}},{"accept":null}]}},
            {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":11,"expr":[{"xt":{"type":"match","name":"comment"}},{"counter":{"packets":3,"bytes":4}},{"return":null}]}},
            {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":12,"expr":[{"drop":null}]}},
            {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":13,"expr":[{"return":null}],"comment":"foreign tail"}},
            {"table":{"family":"ip6","name":"filter","handle":2}},
            {"chain":{"family":"ip6","table":"filter","name":"INPUT","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
            {"rule":{"family":"ip6","table":"filter","chain":"INPUT","handle":10,"expr":[{"drop":null}],"comment":"foreign IPv6"}},
            {"table":{"family":"inet","name":"foreign","handle":3}},
            {"counter":{"family":"inet","table":"foreign","name":"traffic","handle":1,"packets":5,"bytes":6}},
            {"set":{"family":"inet","table":"foreign","name":"addresses","handle":2,"type":"ipv4_addr","elem":["10.0.0.1"]}}
        ]});
        source["ruleFingerprints"]=json!(source["nftables"].as_array().unwrap().iter().filter_map(|v|v.get("rule")).map(|r|json!({"family":r["family"],"table":r["table"],"chain":r["chain"],"handle":r["handle"],"sha256":durable::hash(format!("synthetic-test-only-{}-{}",r["family"],r["handle"]).as_bytes())})).collect::<Vec<_>>());source
    }
    fn transfer(original:Value)->Transfer {
        Transfer{operation_id:uuid::Uuid::new_v4(),source_digest:"a".repeat(64),source_model_sha256:None,original,
            rules:vec![Rules{chain:Chain{family:"ip".into(),table:"filter".into(),name:"INPUT".into()},original:vec![10,12],before:None,
                replacement:vec![vec![json!({"accept":null})],vec![json!({"drop":null})],vec![json!({"return":null})]]}],policies:vec![]}
    }
    #[test]
    fn native_delta_is_handle_bound_and_never_flushes_or_reemits_opaque_foreign_clauses() {
        let source=source();let transfer=transfer(source.clone());let batch=transfer.batch(&source,false).unwrap();let commands=batch["nftables"].as_array().unwrap();
        assert_eq!(commands.len(),4);assert!(commands[0].get("create").is_some());
        assert!(commands.iter().all(|v|v.get("flush").is_none()));
        let replacements=commands.iter().filter_map(|v|v.get("replace")).map(|v|v["rule"]["handle"].as_u64().unwrap()).collect::<Vec<_>>();assert_eq!(replacements,[10,12]);
        assert_eq!(commands[1]["insert"]["rule"]["handle"],13);
        assert!(!serde_json::to_string(&batch).unwrap().contains("\"xt\""));assert_eq!(source,transfer.original);
    }
    #[test]
    fn every_foreign_body_policy_order_and_handle_is_in_the_original_native_source() {
        let original=source();let transfer=transfer(original.clone());
        for defect in ["opaque","handle","policy","order","set","raw","missing-raw"] {
            let mut current=original.clone();match defect {
                "raw"=>current["ruleFingerprints"][1]["sha256"]=json!("f".repeat(64)),
                "missing-raw"=>{current.as_object_mut().unwrap().remove("ruleFingerprints");},
                "opaque"=>current["nftables"][4]["rule"]["expr"][0]["xt"]["name"]=json!("another"),
                "handle"=>current["nftables"][4]["rule"]["handle"]=json!(111),
                "policy"=>current["nftables"][8]["chain"]["policy"]=json!("accept"),
                "order"=>current["nftables"].as_array_mut().unwrap().swap(4,5),
                "set"=>current["nftables"][12]["set"]["elem"]=json!(["10.0.0.2"]),_=>unreachable!(),
            }
            assert!(transfer.batch(&current,false).unwrap_err().to_string().starts_with("CONFLICT"),"{defect}");
        }
        let mut traffic=original.clone();traffic["nftables"][3]["rule"]["expr"][0]["counter"]["packets"]=json!(999);
        traffic["nftables"][11]["counter"]["bytes"]=json!(999);
        assert_eq!(transfer.batch(&traffic,false).unwrap(),transfer.batch(&original,false).unwrap());
        assert!(transfer.acknowledge(&original,false).unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));
        assert!(transfer.batch(&original,true).is_err());
    }
    #[test]
    fn native_selection_cannot_use_a_chain_name_duplicate_handle_or_an_unserializable_inverse_as_authority() {
        for defect in ["missing","duplicate","reordered","opaque","anchor","empty"] {
            let mut transfer=transfer(source());match defect {
                "missing"=>transfer.rules[0].original=vec![99],"duplicate"=>transfer.rules[0].original=vec![10,10],
                "reordered"=>transfer.rules[0].original=vec![12,10],"opaque"=>transfer.rules[0].original=vec![11],
                "anchor"=>transfer.rules[0].before=Some(13),"empty"=>{transfer.rules[0].original.clear();transfer.rules[0].replacement.clear();},_=>unreachable!(),
            }
            assert!(transfer.validate().is_err(),"{defect}");
        }
    }
    struct Fixture {store:Store,source:Baseline,id:uuid::Uuid,token:String}
    impl Fixture {
        fn new()->Self {
            Self::at(std::env::temp_dir().join(format!("native-store-{}",uuid::Uuid::new_v4())),transfer(source()))
        }
        fn at(root:PathBuf,mut native:Transfer)->Self {
            let parent=root.join("installed");durable::directory(&root).unwrap();durable::directory(&parent).unwrap();
            let store=Store::relocated(&root,parent.join("network-owner-agent"));let origin=store.observe_firewall_fence().unwrap();
            let roles=roles::Observation::new(uuid::Uuid::new_v4(),1,json!({"schemaVersion":1,"pid":roles::PID,"revision":"native-source","interfaces":[{"id":"eth0","type":"ETHERNET","ipv4Status":"netIPv4StatusEnabledWAN","natEnabled":null}]})).unwrap();
            let firewall=roles::fixture_firewall_source(&roles);
            native.source_digest=Baseline::bind_pair_source(&"a".repeat(64),Some(&firewall),Some(&origin)).unwrap();let id=native.operation_id;
            let source=Baseline{source_digest:native.source_binding().unwrap(),roles,profiles:vec![ProfileBinding{interface:"eth0".into(),profile_uuid:Some(uuid::Uuid::new_v4().to_string()),origin_cas:Some("c".repeat(64))}],firewall_digest:"b".repeat(64),automatic_nat:Value::Null,firewall_source:Some(firewall),firewall_fence:Some(origin),native_transfer:Some(native)};
            let transfer=template::Transfer::new(&root);let nonce=transfer.start(id,"native-actor".into(),source.clone()).unwrap();
            transfer.deposit(json!({"operationId":id,"revision":source.roles.roles.revision,"depositToken":nonce,"templateSha256":durable::hash(b"AAAA-BBBB"),"chunkIndex":0,"chunkCount":1,"ciphertextChunk":"AAAA-BBBB"}),source.roles.agent_instance,source.roles.bridge_epoch).unwrap();let (binding,_)=transfer.ready(id,"native-actor").unwrap();
            let prepared=store.plan_with_template(id,"native-actor".into(),source.clone(),binding).unwrap();let token=prepared["confirmationToken"].as_str().unwrap().to_string();store.fence(&token,"native-actor",||Ok(source.clone())).unwrap();
            Self{store,source,id,token}
        }
    }
    #[test]
    fn native_store_journals_before_dispatch_and_a_lost_reply_never_authorizes_a_second_batch() {
        let f=Fixture::new();let calls=AtomicUsize::new(0);let kernel=f.source.native_transfer.as_ref().unwrap().original.clone();
        let result=f.store.native_change_fixture(f.id,&f.token,"native-actor",false,|_,_,_,_|Ok(kernel.clone()),|_|{
            calls.fetch_add(1,Ordering::SeqCst);let (j,_)=f.store.load().unwrap().unwrap();assert!(serde_json::to_string(&j).unwrap().contains("INTENT"));anyhow::bail!("lost reply")});
        assert!(result.unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));let original=fs::read(f.store.journal_path()).unwrap();
        assert!(f.store.native_change_fixture(f.id,&f.token,"native-actor",false,|_,_,_,_|Ok(kernel.clone()),|_|{calls.fetch_add(1,Ordering::SeqCst);Ok(())}).is_err());
        assert!(f.store.native_original_fixture(f.id,"native-actor",||Ok(kernel.clone())).is_err());
        assert_eq!(fs::read(f.store.journal_path()).unwrap(),original);assert_eq!(calls.load(Ordering::SeqCst),1);
        assert!(f.store.requirements(f.id,&f.token,"native-actor").is_err());assert!(f.store.active().unwrap().is_none());
    }
    #[test]
    fn native_store_source_drain_actor_and_token_fail_before_any_once_only_intent() {
        let f=Fixture::new();let original=fs::read(f.store.journal_path()).unwrap();let calls=AtomicUsize::new(0);
        for (actor,token) in [("another",f.token.as_str()),("native-actor","wrong")] {
            assert!(f.store.native_change_fixture(f.id,token,actor,false,|_,_,_,_|anyhow::bail!("must not inspect"),|_|{calls.fetch_add(1,Ordering::SeqCst);Ok(())}).is_err());
        }
        assert!(f.store.native_change_fixture(f.id,&f.token,"native-actor",false,|_,_,_,_|anyhow::bail!("Java drain unavailable"),|_|{calls.fetch_add(1,Ordering::SeqCst);Ok(())}).is_err());
        assert_eq!(fs::read(f.store.journal_path()).unwrap(),original);assert_eq!(calls.load(Ordering::SeqCst),0);
    }
    #[test]
    fn native_effect_cannot_cross_an_original_startup_child_or_orphan_execution_binding() {
        for suffix in ["journal.json","execution.json","cancelled.json","malformed"] {
            let f=Fixture::new();let original=fs::read(f.store.journal_path()).unwrap();
            let child=f.store.root.join(format!("{}.startup-{suffix}",f.id));fs::write(&child,b"retained original child evidence").unwrap();
            let error=f.store.native_change_fixture(f.id,&f.token,"native-actor",false,|_,_,_,_|panic!("child must block kernel observation"),|_|panic!("child must block dispatch")).unwrap_err();
            assert!(error.to_string().starts_with("CONFLICT"));assert_eq!(fs::read(f.store.journal_path()).unwrap(),original);
            assert_eq!(fs::read(child).unwrap(),b"retained original child evidence");assert!(f.store.active().unwrap().is_none());
        }
    }
    #[test]
    fn complete_kernel_rejection_is_durable_original_evidence_and_never_authorizes_another_dispatch() {
        let mut original=source();original["kernelGeneration"]=json!(17);let f=Fixture::at(std::env::temp_dir().join(format!("native-rejection-{}",uuid::Uuid::new_v4())),transfer(original.clone()));let calls=AtomicUsize::new(0);
        let result=f.store.native_change_fixture(f.id,&f.token,"native-actor",false,|_,_,_,_|Ok(original.clone()),|batch| {
            calls.fetch_add(1,Ordering::SeqCst);assert_eq!(batch["expectedGeneration"],17);
            Err(raw::wire::Rejected{errno:85,sequence:0x594f4600,reply_sha256:"a".repeat(64),reply:Vec::new()}.into())
        }).unwrap();assert_eq!(result["nativeTransfer"]["state"],"REJECTED");
        let saved=fs::read(f.store.journal_path()).unwrap();assert!(f.store.requirements(f.id,&f.token,"native-actor").is_err());
        assert_eq!(f.store.native_original_fixture(f.id,"native-actor",||anyhow::bail!("known rejection never needs a new kernel call")).unwrap()["nativeTransfer"]["state"],"REJECTED");
        assert!(f.store.native_change_fixture(f.id,&f.token,"native-actor",false,|_,_,_,_|Ok(original.clone()),|_|{calls.fetch_add(1,Ordering::SeqCst);Ok(())}).is_err());
        assert_eq!(calls.load(Ordering::SeqCst),1);assert_eq!(fs::read(f.store.journal_path()).unwrap(),saved);
    }
    #[test]
    #[ignore="fresh V31 Linux generation-CAS and opaque inverse with lost replies;synthetic CM/drain;never replay a retained phase"]
    fn native_generation_kernel_fixture() {
        use crate::system_change::{Guard,Subsystem};
        let root=PathBuf::from(std::env::var("YOFC_NATIVE_GENERATION_V31_ROOT").unwrap());let phase=std::env::var("YOFC_NATIVE_GENERATION_V31_PHASE").unwrap();
        assert!(root.join(".owned-native-v31").is_file());durable::publish_new(&root.join(format!("invoked-{phase}")),phase.as_bytes(),FileMetadata::private()).unwrap();
        let nft=|args:&[&str]|->Value {let output=crate::process::run(Path::new("/usr/sbin/nft"),args,None,std::time::Duration::from_secs(10)).unwrap();assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));if output.stdout.is_empty(){Value::Null}else{serde_json::from_slice(&output.stdout).unwrap()}};
        let read_kernel=||raw::observe(||Ok(nft(&["-j","-p","list","ruleset"])),std::time::Instant::now()+std::time::Duration::from_secs(10)).unwrap();
        let cas=phase.ends_with("-cas");let world=root.join(if cas{"cas-world"}else{"world"});let driver_path=root.join(if cas{"cas-driver.json"}else{"driver.json"});
        if phase=="prepare"||phase=="prepare-cas" {
            assert!(!world.exists());let original=read_kernel();let source=Snapshot::read(&original).unwrap();let key=|family:&str,table:&str,name:&str|Chain{family:family.into(),table:table.into(),name:name.into()};
            let filter=key("ip","filter","INPUT");let selected=source.rules[&filter].iter().filter(|v|v["expr"].as_array().unwrap().iter().any(|v|v["match"]["left"]["payload"]["field"]=="dport"&&[18180,18181].iter().any(|n|v["match"]["right"]==*n))).map(|v|handle(v).unwrap()).collect::<Vec<_>>();assert_eq!(selected.len(),2);
            let nat=key("ip","nat","POSTROUTING");let nat_selected=source.rules[&nat].iter().filter(|v|v["expr"].as_array().unwrap().iter().any(|v|v["xt"]["name"]=="MASQUERADE")).map(|v|handle(v).unwrap()).collect::<Vec<_>>();assert_eq!(nat_selected.len(),1);
            let mangle=key("ip","mangle","PREROUTING");let marks=source.rules[&mangle].iter().filter(|v|v["expr"].as_array().unwrap().iter().any(|v|v["xt"]["name"]=="MARK")).map(|v|handle(v).unwrap()).collect::<Vec<_>>();assert_eq!(marks.len(),2);
            let port=|protocol:&str,number:u16,allow:bool|vec![json!({"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":"dport"}},"right":number}}),if allow{json!({"accept":null})}else{json!({"drop":null})}];
            let native=Transfer{operation_id:uuid::Uuid::new_v4(),source_digest:"a".repeat(64),source_model_sha256:None,original,rules:vec![
                Rules{chain:filter,original:selected,before:None,replacement:vec![port("tcp",18143,true),port("udp",18144,false),port("tcp",18145,true)]},
                Rules{chain:nat,original:nat_selected,before:None,replacement:vec![vec![json!({"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"nativewan0"}}),json!({"masquerade":null})]]},
                Rules{chain:mangle,original:marks,before:None,replacement:vec![vec![json!({"mangle":{"key":{"meta":{"key":"mark"}},"value":2}})]]}],policies:vec![Policy{chain:key("ip6","filter","OUTPUT"),value:"accept".into()}]};
            let f=Fixture::at(world,native);durable::publish_new(&driver_path,&serde_json::to_vec(&json!({"operationId":f.id,"token":f.token})).unwrap(),FileMetadata::private()).unwrap();println!("fresh V31 original plan fenced");return;
        }
        let driver:Value=serde_json::from_slice(&durable::read(&driver_path,16384).unwrap().0).unwrap();let id=uuid::Uuid::parse_str(driver["operationId"].as_str().unwrap()).unwrap();let store=Store::relocated(&world,world.join("installed/network-owner-agent"));
        if ["forward-lost","inverse-lost","reject-cas"].contains(&phase.as_str()) {
            let inverse=phase=="inverse-lost";let _guard=Guard::acquire(&world,Subsystem::NmOwnership).unwrap();
            let result=store.native_change(id,driver["token"].as_str().unwrap(),"native-actor",inverse,|_,_,_,_|Ok(read_kernel()),|batch|{
                durable::publish_new(&root.join(format!("batch-{phase}.json")),&serde_json::to_vec(batch).unwrap(),FileMetadata::private()).unwrap();
                if phase=="reject-cas" {nft(&["add","table","inet","intervening_v31"]);}
                raw::writer::dispatch(batch,std::time::Instant::now()+std::time::Duration::from_secs(10))?;
                anyhow::bail!("fixture lost reply AFTER successful kernel batch-END ACK")
            });
            if cas {assert_eq!(result.unwrap()["nativeTransfer"]["state"],"REJECTED");}
            else {assert!(result.unwrap_err().to_string().starts_with("OUTCOME_UNKNOWN"));assert_eq!(store.status().unwrap()["nativeTransfer"]["state"],if inverse{"INVERSE_INTENT"}else{"INTENT"});}
        }else{
            assert!(["query","query-inverse","query-cas"].contains(&phase.as_str()));let _guard=Guard::observe(&world).unwrap();let status=store.native_original(id,"native-actor",||{assert!(!cas,"known NACK must never reread/redispatch");Ok(read_kernel())}).unwrap();assert_eq!(status["nativeTransfer"]["state"],if cas{"REJECTED"}else if phase=="query-inverse"{"REVERTED"}else{"APPLIED"});
        }
        assert!(store.active().unwrap().is_none());println!("V31 original phase completed with no owner lease or redispatch");
    }
    #[test]
    #[ignore="fresh owned Linux native delta/Store fixture;synthetic CM/drain,not full ownership acceptance;never replay a retained phase"]
    fn native_kernel_store_fixture() {
        use crate::system_change::{Guard,Subsystem};
        let root=PathBuf::from(std::env::var("YOFC_NATIVE_TRANSFER_V30_ROOT").unwrap());
        let phase=std::env::var("YOFC_NATIVE_TRANSFER_V30_PHASE").unwrap();
        assert!(root.join(".owned-native-v30").is_file());let path=root.join(format!("invoked-{phase}"));
        durable::publish_new(&path,phase.as_bytes(),FileMetadata::private()).unwrap();
        let nft=|args:&[&str],input:Option<&Value>|->Value {
            let input=input.map(|v|serde_json::to_vec(v).unwrap());
            let output=crate::process::run(Path::new("/usr/sbin/nft"),args,input.as_deref(),std::time::Duration::from_secs(10)).unwrap();
            assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
            if output.stdout.is_empty(){Value::Null}else{serde_json::from_slice(&output.stdout).unwrap()}
        };
        let read_kernel=||raw::observe(||Ok(nft(&["-j","-p","list","ruleset"],None)),std::time::Instant::now()+std::time::Duration::from_secs(10)).unwrap();
        let world=root.join("world");
        if phase=="prepare" {
            assert!(!world.exists());let original=read_kernel();let snapshot=Snapshot::read(&original).unwrap();
            let key=|table:&str,name:&str|Chain{family:"ip".into(),table:table.into(),name:name.into()};
            let filter=key("filter","INPUT");let rows=&snapshot.rules[&filter];
            let mut selected=Vec::new();for row in rows {
                let expr=row["expr"].as_array().unwrap();
                let owned=expr.iter().any(|v|(v["match"]["left"]["payload"]["protocol"]=="tcp"&&v["match"]["left"]["payload"]["field"]=="dport"&&v["match"]["right"]==18080)
                    ||(v["match"]["left"]["payload"]["protocol"]=="udp"&&v["match"]["left"]["payload"]["field"]=="dport"&&v["match"]["right"]==18081));
                if owned {assert!(native_inverse_safe(row));selected.push(handle(row).unwrap());}
            }
            assert_eq!(selected.len(),2);assert!(rows.iter().any(|v|!native_inverse_safe(v)),"real opaque xt clause required");
            let port=|protocol:&str,number:u16,allow:bool|vec![json!({"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":"dport"}},"right":number}}),if allow{json!({"accept":null})}else{json!({"drop":null})}];
            let nat=key("nat","POSTROUTING");let nat_selected=snapshot.rules[&nat].iter().filter(|v|v["expr"].as_array().unwrap().iter().any(|v|v.get("masquerade").is_some())).map(|v|handle(v).unwrap()).collect::<Vec<_>>();assert_eq!(nat_selected.len(),1);
            let mangle=key("mangle","PREROUTING");let mangle_selected=snapshot.rules[&mangle].iter().filter(|v|v["expr"].as_array().unwrap().iter().any(|v|v.get("mangle").is_some())).map(|v|handle(v).unwrap()).collect::<Vec<_>>();assert_eq!(mangle_selected.len(),2);
            let transfer=Transfer{operation_id:uuid::Uuid::new_v4(),source_digest:"a".repeat(64),source_model_sha256:None,original,rules:vec![
                Rules{chain:filter.clone(),original:selected,before:None,replacement:vec![port("tcp",18443,true),port("udp",18444,false),port("tcp",18445,true)]},
                Rules{chain:nat,original:nat_selected,before:None,replacement:vec![]},
                Rules{chain:mangle,original:mangle_selected,before:None,replacement:vec![vec![json!({"mangle":{"key":{"meta":{"key":"mark"}},"value":2}})]]}],
                policies:vec![Policy{chain:filter,value:"accept".into()}]};
            let fixture=Fixture::at(world,transfer);durable::publish_new(&root.join("driver.json"),&serde_json::to_vec(&json!({"operationId":fixture.id,"token":fixture.token})).unwrap(),FileMetadata::private()).unwrap();
            println!("native fixture prepared");return;
        }
        let driver:Value=serde_json::from_slice(&durable::read(&root.join("driver.json"),16384).unwrap().0).unwrap();let id=uuid::Uuid::parse_str(driver["operationId"].as_str().unwrap()).unwrap();
        let store=Store::relocated(&world,world.join("installed/network-owner-agent"));
        let status=if phase=="forward"||phase=="inverse" {
            let _guard=Guard::acquire(&world,Subsystem::NmOwnership).unwrap();
            store.native_change(id,driver["token"].as_str().unwrap(),"native-actor",phase=="inverse",|_,_,_,_|Ok(read_kernel()),|batch| {
                durable::publish_new(&root.join(format!("batch-{phase}.json")),&serde_json::to_vec(batch).unwrap(),FileMetadata::private()).unwrap();nft(&["-j","-f","-"],Some(batch));Ok(())
            }).unwrap()
        }else{
            assert!(phase=="query"||phase=="query-inverse");let _guard=Guard::observe(&world).unwrap();store.native_original(id,"native-actor",||Ok(read_kernel())).unwrap()
        };
        assert_eq!(status["nativeTransfer"]["state"],if phase=="inverse"||phase=="query-inverse"{"REVERTED"}else{"APPLIED"});
        assert!(store.active().unwrap().is_none());
        println!("native original phase acknowledged without an owner lease");
    }
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(in crate::nm) struct Policy {pub(in crate::nm) chain:Chain,pub(in crate::nm) value:String}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(in crate::nm) struct Transfer {
    pub(in crate::nm) operation_id:uuid::Uuid,
    pub(in crate::nm) source_digest:String,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(in crate::nm) source_model_sha256:Option<String>,
    pub(in crate::nm) original:Value,
    pub(in crate::nm) rules:Vec<Rules>,
    pub(in crate::nm) policies:Vec<Policy>,
}

#[derive(Clone)]
struct Snapshot {objects:Vec<Value>,rules:BTreeMap<Chain,Vec<Value>>,fingerprints:BTreeMap<(Chain,u64),String>,payloads:BTreeMap<(Chain,u64),String>,generation:Option<u32>}
fn checked_tree(value:&Value,depth:usize)->Result<()> {
    ensure!(depth<=32,"RESOURCE_EXHAUSTED: native source nesting");
    match value {
        Value::Array(values)=>{ensure!(values.len()<=8192,"RESOURCE_EXHAUSTED: native array");for v in values {checked_tree(v,depth+1)?;}},
        Value::Object(values)=>{ensure!(values.len()<=128,"RESOURCE_EXHAUSTED: native object");for (k,v) in values {ensure!(k.len()<=128,"RESOURCE_EXHAUSTED: native key");checked_tree(v,depth+1)?;}},
        Value::String(text)=>ensure!(text.len()<=16384,"RESOURCE_EXHAUSTED: native string"),_=>{},
    }
    Ok(())
}
fn counters(value:&mut Value)->Result<()> {
    if let Some(terms)=value.get_mut("expr").and_then(Value::as_array_mut) {
        for term in terms {
            if let Some(count)=term.get_mut("counter").and_then(Value::as_object_mut)
                && count.len()==2 && count.contains_key("packets") && count.contains_key("bytes") {
                for k in ["packets","bytes"] {ensure!(count[k].as_u64().is_some(),"CONFLICT: native traffic counter");count.insert(k.into(),json!(0));}
            }
        }
    }
    Ok(())
}
fn chain(value:&Value)->Result<Chain> {
    let text=|key:&str|value[key].as_str().map(str::to_owned).context("CONFLICT: native object identity");
    Ok(Chain{family:text("family")?,table:text("table")?,name:text("chain")?})
}
fn handle(value:&Value)->Result<u64> {value["handle"].as_u64().filter(|v|*v>0).context("CONFLICT: native rule handle")}
fn without_handle(value:&Value)->Value {let mut v=value.clone();v.as_object_mut().unwrap().remove("handle");v}
fn matches_entry(actual:&Value,expected:&Value,flexible:bool)->bool {
    if !actual.is_object() || !expected.is_object() {return false;}
    if flexible {let mut actual=without_handle(actual);let mut expected=without_handle(expected);crate::firewall::normalize_native_rule(&mut actual);crate::firewall::normalize_native_rule(&mut expected);actual==expected}else{actual==expected}
}
impl Snapshot {
    fn read(value:&Value)->Result<Self> {
        ensure!(serde_json::to_vec(value)?.len()<=MAX_BYTES,"RESOURCE_EXHAUSTED: native ruleset source");checked_tree(value,0)?;
        let object=value.as_object().context("CONFLICT: native source envelope")?;
        ensure!((object.len()==2 || (object.len()==3 && object.contains_key("kernelGeneration"))) && object.contains_key("ruleFingerprints"),"CONFLICT: complete raw rule fingerprints required");
        let entries=value["nftables"].as_array().context("CONFLICT: native source entries")?;
        let fingerprints:Vec<raw::Fingerprint>=serde_json::from_value(value["ruleFingerprints"].clone()).context("CONFLICT: raw rule fingerprints")?;
        let generation=value.get("kernelGeneration").map(|v|v.as_u64().filter(|v|*v>0&&*v<=u32::MAX as u64).map(|v|v as u32).context("CONFLICT: native kernel generation")).transpose()?;
        let mut result=Self{objects:Vec::new(),rules:BTreeMap::new(),fingerprints:BTreeMap::new(),payloads:BTreeMap::new(),generation};let mut ids=BTreeSet::new();
        for f in fingerprints {raw::validate_payload(&f)?;let key=(Chain{family:f.family,table:f.table,name:f.chain},f.handle);if let Some(payload)=f.payload_hex {result.payloads.insert(key.clone(),payload);}
            ensure!(hex(&f.sha256,64) && result.fingerprints.insert(key,f.sha256).is_none(),"CONFLICT: invalid/duplicate raw rule fingerprint");}
        for item in entries {
            let object=item.as_object().context("CONFLICT: native source item")?;ensure!(object.len()==1,"CONFLICT: ambiguous native source item");
            let (kind,value)=object.iter().next().unwrap();ensure!(value.is_object(),"CONFLICT: native source object body");
            if kind=="metainfo" {continue;}
            ensure!(!["add","delete","flush","replace","insert","create","rename","reset","list"].contains(&kind.as_str()),"CONFLICT: source contains commands");
            if kind=="rule" {
                let key=chain(value)?;let id=handle(value)?;ensure!(ids.insert((key.family.clone(),key.table.clone(),id)),"CONFLICT: duplicate native rule identity");
                ensure!(value["expr"].as_array().is_some_and(|v|!v.is_empty()),"CONFLICT: native rule expression");
                ensure!(result.fingerprints.contains_key(&(key.clone(),id)),"CONFLICT: native rule lacks raw parameter witness");
                let mut value=value.clone();counters(&mut value)?;result.rules.entry(key).or_default().push(value);
            } else {
                let mut value=value.clone();
                if kind=="counter" {let o=value.as_object_mut().unwrap();for key in ["packets","bytes"] {if let Some(v)=o.get_mut(key) {ensure!(v.as_u64().is_some(),"CONFLICT: named native counter");*v=json!(0);}}}
                result.objects.push(json!({kind:value}));
            }
        }
        ensure!(result.fingerprints.len()==ids.len(),"CONFLICT: raw witness contains unobserved rules");
        let mut tables=BTreeSet::new();let mut chains=BTreeSet::new();
        for object in &result.objects {
            if let Some(table)=object.get("table") {ensure!(table["family"].is_string()&&table["name"].is_string()&&tables.insert((table["family"].clone().to_string(),table["name"].clone().to_string())),"CONFLICT: duplicate or incomplete native table");}
            if let Some(value)=object.get("chain") {let key=Chain{family:value["family"].as_str().context("CONFLICT: native chain family")?.into(),table:value["table"].as_str().context("CONFLICT: native chain table")?.into(),name:value["name"].as_str().context("CONFLICT: native chain name")?.into()};ensure!(chains.insert(key),"CONFLICT: duplicate native chain");}
        }
        for key in chains.iter().chain(result.rules.keys()) {ensure!(tables.contains(&(json!(key.family).to_string(),json!(key.table).to_string()))&&chains.contains(key),"CONFLICT: native source contains an orphan object");}
        result.objects.sort_by_key(Value::to_string);Ok(result)
    }
    fn find_chain(&self,key:&Chain)->Result<&Value> {
        let values=self.objects.iter().filter_map(|v|v.get("chain")).filter(|v|v["family"]==key.family && v["table"]==key.table && v["name"]==key.name).collect::<Vec<_>>();
        ensure!(values.len()==1,"CONFLICT: original native chain is not unique");Ok(values[0])
    }
    fn table_absent(&self,name:&str)->bool {self.objects.iter().filter_map(|v|v.get("table")).all(|v|v["family"]!="inet" || v["name"]!=name)}
    fn digest(&self)->Result<String> {let mut value=json!({"objects":self.objects,"rawRules":self.fingerprints.iter().map(|((chain,handle),hash)|json!({"chain":chain,"handle":handle,"sha256":hash})).collect::<Vec<_>>(),"rules":self.rules.iter().map(|(k,v)|json!({"chain":k,"rules":v})).collect::<Vec<_>>()});if let Some(generation)=self.generation{value["kernelGeneration"]=json!(generation);}digest(&value)}
}
fn mutable_chain(key:&Chain)->bool {
    ["ip","ip6"].contains(&key.family.as_str()) && ["filter","nat","mangle"].contains(&key.table.as_str())
        && !key.name.is_empty() && key.name.len()<=64 && key.name.bytes().all(|c|c.is_ascii_alphanumeric()||b"_.:-".contains(&c))
}
fn native_inverse_safe(value:&Value)->bool {
    match value {Value::Object(v)=>!v.contains_key("xt")&&v.values().all(native_inverse_safe),Value::Array(v)=>v.iter().all(native_inverse_safe),_=>true}
}
impl Transfer {
    fn names(&self)->(String,String) {(format!("yofc_fwt_{}",self.operation_id.simple()),format!("yofc_fwi_{}",self.operation_id.simple()))}
    fn identity(&self)->Result<String> {digest(&json!({"domain":"nm.legacy.native.transfer.v1","transfer":self}))}
    pub(in crate::nm) fn source_binding(&self)->Result<String> {
        factory::source_binding(&self.source_digest,self.source_model_sha256.as_deref(),&self.original,&self.rules,&self.policies)
    }
    pub(in crate::nm) fn validate(&self)->Result<()> {
        ensure!(!self.operation_id.is_nil() && hex(&self.source_digest,64),"CONFLICT: original native transfer identity");
        ensure!(self.source_model_sha256.as_ref().is_none_or(|v|hex(v,64)),"CONFLICT: original writer model binding");
        ensure!(self.rules.len()+self.policies.len()<=64 && !(self.rules.is_empty()&&self.policies.is_empty()),"INVALID_ARGUMENT: native transfer scope");
        let source=Snapshot::read(&self.original)?;let (forward,inverse)=self.names();ensure!(source.table_absent(&forward)&&source.table_absent(&inverse),"CONFLICT: native transfer receipt already exists");
        let mut chains=BTreeSet::new();let mut count=0;
        for change in &self.rules {
            ensure!(!(change.original.is_empty()&&change.replacement.is_empty()),"INVALID_ARGUMENT: empty native rule change");
            ensure!(mutable_chain(&change.chain)&&chains.insert(change.chain.clone()),"FORBIDDEN: ambiguous native mutation scope");source.find_chain(&change.chain)?;
            let rows=source.rules.get(&change.chain).cloned().unwrap_or_default();let selected=rows.iter().filter(|v|change.original.contains(&v["handle"].as_u64().unwrap())).collect::<Vec<_>>();
            ensure!(change.original.len()==selected.len() && selected.iter().map(|v|v["handle"].as_u64().unwrap()).collect::<Vec<_>>()==change.original,
                "CONFLICT: original native selection is missing,duplicated or reordered");
            ensure!(change.before.is_none() || (change.original.is_empty()&&rows.iter().any(|v|v["handle"].as_u64()==change.before)),"CONFLICT: original native insertion anchor");
            for row in selected {if !native_inverse_safe(row) {let payload=source.payloads.get(&(change.chain.clone(),handle(row)?)).context("UNSUPPORTED: selected extension has no complete raw inverse")?;raw::inverse_supported(payload)?;ensure!(source.generation.is_some(),"UNSUPPORTED: selected opaque inverse requires generation fencing");}}
            count+=change.original.len()+change.replacement.len();
            for expr in &change.replacement {ensure!(!expr.is_empty()&&native_inverse_safe(&json!(expr)),"UNSUPPORTED: native replacement expression");checked_tree(&json!(expr),0)?;}
        }
        ensure!(count<=4096 && serde_json::to_vec(self)?.len()<=MAX_BYTES,"RESOURCE_EXHAUSTED: original native transfer bounds");
        let mut policies=BTreeSet::new();for policy in &self.policies {
            ensure!(mutable_chain(&policy.chain)&&policy.chain.table=="filter"&&policies.insert(policy.chain.clone())&&["accept","drop"].contains(&policy.value.as_str()),"FORBIDDEN: native policy mutation scope");
            let old=source.find_chain(&policy.chain)?;ensure!(old["type"]=="filter"&&["input","forward","output"].contains(&old["hook"].as_str().unwrap_or(""))&&["accept","drop"].contains(&old["policy"].as_str().unwrap_or("")),"CONFLICT: original native base policy");
        }
        Ok(())
    }
    fn receipt_for(&self,inverse:bool,identity:&str)->Value {
        let names=self.names();json!({"table":{"family":"inet","name":if inverse{names.1}else{names.0},"comment":format!("yofc native {} {}",if inverse{"inverse"}else{"forward"},identity)}})
    }
    fn tag_for(identity:&str,group:usize,index:usize)->String {format!("yofc-t-{identity}-{group}-{index}")}
    fn replacement_for(&self,group:usize,index:usize,identity:&str)->Value {
        let change=&self.rules[group];json!({"family":change.chain.family,"table":change.chain.table,"chain":change.chain.name,"expr":change.replacement[index],"comment":Self::tag_for(identity,group,index)})
    }
    #[cfg(test)]
    fn receipt(&self,inverse:bool)->Result<Value> {Ok(self.receipt_for(inverse,&self.identity()?))}
    #[cfg(test)]
    fn replacement(&self,group:usize,index:usize)->Result<Value> {Ok(self.replacement_for(group,index,&self.identity()?))}
    fn expected_rules(&self,source:&Snapshot,group:usize,identity:&str)->Result<Vec<(Value,bool)>> {
        let change=&self.rules[group];let rows=source.rules.get(&change.chain).cloned().unwrap_or_default();
        let last=change.original.last().and_then(|id|rows.iter().position(|v|v["handle"].as_u64()==Some(*id)));
        let extra_at=last.map(|i|i+1).or_else(||change.before.and_then(|id|rows.iter().position(|v|v["handle"].as_u64()==Some(id)))).unwrap_or(rows.len());
        let mut out=Vec::new();
        for i in 0..=rows.len() {
            if i==extra_at {for j in change.original.len()..change.replacement.len() {out.push((self.replacement_for(group,j,identity),true));}}
            if let Some(row)=rows.get(i) {
                if let Some(j)=change.original.iter().position(|id|row["handle"].as_u64()==Some(*id)) {if j<change.replacement.len() {out.push((self.replacement_for(group,j,identity),true));}}
                else {out.push((row.clone(),false));}
            }
        }
        Ok(out)
    }
    fn matches(&self,current:&Snapshot,inverse:bool)->Result<bool> {
        let source=Snapshot::read(&self.original)?;let mut objects=source.objects.clone();
        if let Some(before)=source.generation {
            let forward=next_generation(before);let expected=if inverse{next_generation(forward)}else{forward};
            if current.generation!=Some(expected) {return Ok(false);}
        }
        let complete_raw=!source.fingerprints.is_empty()&&source.payloads.len()==source.fingerprints.len();
        if complete_raw && (current.payloads.len()!=current.fingerprints.len() || (source.generation.is_some()&&current.generation.is_none())) {return Ok(false);}
        if !inverse {for policy in &self.policies {for object in &mut objects {if object.get("chain").is_some_and(|v|v["family"]==policy.chain.family&&v["table"]==policy.chain.table&&v["name"]==policy.chain.name) {object["chain"]["policy"]=json!(policy.value);}}}}
        let identity=self.identity()?;let receipt=self.receipt_for(inverse,&identity);let mut observed=current.objects.clone();
        for object in &mut observed {if object["table"]["family"]=="inet"&&object["table"]["name"]==receipt["table"]["name"] {object["table"].as_object_mut().unwrap().remove("handle");}}
        objects.push(receipt);objects.sort_by_key(Value::to_string);observed.sort_by_key(Value::to_string);if observed!=objects{return Ok(false);}
        let keys:BTreeSet<_>=source.rules.keys().chain(current.rules.keys()).chain(self.rules.iter().map(|v|&v.chain)).collect();
        for key in keys {
            let group=self.rules.iter().position(|v|&v.chain==key);
            let expected=if let Some(group)=group {
                if inverse {source.rules.get(key).cloned().unwrap_or_default().into_iter().map(|v|{let owned=self.rules[group].original.contains(&v["handle"].as_u64().unwrap());(v,owned)}).collect()}
                else{self.expected_rules(&source,group,&identity)?}
            } else {source.rules.get(key).cloned().unwrap_or_default().into_iter().map(|v|(v,false)).collect::<Vec<_>>()};
            let actual=current.rules.get(key).cloned().unwrap_or_default();if expected.len()!=actual.len(){return Ok(false);}
            for (actual,(expected,flexible)) in actual.iter().zip(&expected) {
                if *flexible && !inverse && complete_raw {
                    let mut actual_metadata=without_handle(actual);actual_metadata.as_object_mut().unwrap().remove("expr");
                    let mut expected_metadata=without_handle(expected);expected_metadata.as_object_mut().unwrap().remove("expr");
                    if actual_metadata!=expected_metadata {return Ok(false);}
                    let Some(payload)=current.payloads.get(&(key.clone(),handle(actual)?)) else {return Ok(false);};
                    if !raw::matcher::replacement_matches(payload,expected)? {return Ok(false);}
                } else if !matches_entry(actual,expected,*flexible){return Ok(false);}
                if !flexible && current.fingerprints.get(&(key.clone(),handle(actual)?))!=source.fingerprints.get(&(key.clone(),handle(expected)?)){return Ok(false);}
                if *flexible && inverse && let Some(original)=source.payloads.get(&(key.clone(),handle(expected)?)) {let Some(observed)=current.payloads.get(&(key.clone(),handle(actual)?)) else {return Ok(false);};if !raw::same_semantics(original,observed)? {return Ok(false);}}
            }
        }
        Ok(true)
    }
    pub(in crate::nm) fn acknowledge(&self,current:&Value,inverse:bool)->Result<String> {
        self.validate()?;let current=Snapshot::read(current)?;
        ensure!(self.matches(&current,inverse)?,"OUTCOME_UNKNOWN: original native transfer has no complete kernel acknowledgement");current.digest()
    }
    /// The caller must first save its once-only intent in the existing Store.
    pub(in crate::nm) fn batch(&self,current:&Value,inverse:bool)->Result<Value> {
        self.validate()?;let actual=Snapshot::read(current)?;let source=Snapshot::read(&self.original)?;
        if inverse {ensure!(self.matches(&actual,false)?,"CONFLICT: native inverse requires the complete original forward outcome");}
        else{ensure!(actual.digest()?==source.digest()?,"CONFLICT: original native kernel source changed");}
        let identity=self.identity()?;let mut commands=vec![json!({"create":self.receipt_for(inverse,&identity)})];
        for (group,change) in self.rules.iter().enumerate() {
            let old=source.rules.get(&change.chain).cloned().unwrap_or_default();let prefix=change.original.len().min(change.replacement.len());
            let base=json!({"family":change.chain.family,"table":change.chain.table,"chain":change.chain.name});
            if inverse {
                let rows=actual.rules.get(&change.chain).cloned().unwrap_or_default();let mut current=Vec::new();
                for i in 0..change.replacement.len() {let tag=Self::tag_for(&identity,group,i);let found=rows.iter().filter(|v|v["comment"]==tag).collect::<Vec<_>>();ensure!(found.len()==1,"CONFLICT: original native rule receipt");current.push(handle(found[0])?);}
                for id in &current[prefix..] {let mut value=base.clone();value["handle"]=json!(id);commands.push(json!({"delete":{"rule":value}}));}
                for id in &change.original[prefix..] {
                    let position=old.iter().position(|v|v["handle"].as_u64()==Some(*id)).unwrap();let mut value=without_handle(&old[position]);
                    if let Some(payload)=source.payloads.get(&(change.chain.clone(),*id)){value["originalRawRule"]=json!(payload);}
                    let anchor=old[position+1..].iter().find(|v|!change.original.contains(&v["handle"].as_u64().unwrap()));
                    if let Some(anchor)=anchor {value["handle"]=json!(handle(anchor)?);commands.push(json!({"insert":{"rule":value}}));}else{commands.push(json!({"add":{"rule":value}}));}
                }
                for (i,id) in current.iter().take(prefix).enumerate() {let original=old.iter().find(|v|v["handle"].as_u64()==Some(change.original[i])).unwrap();let mut value=without_handle(original);if let Some(payload)=source.payloads.get(&(change.chain.clone(),handle(original)?)){value["originalRawRule"]=json!(payload);}value["handle"]=json!(id);commands.push(json!({"replace":{"rule":value}}));}
            } else {
                let last=change.original.last().and_then(|id|old.iter().position(|v|v["handle"].as_u64()==Some(*id)));
                let anchor=last.and_then(|i|old.get(i+1)).map(handle).transpose()?.or(change.before);
                for i in change.original.len()..change.replacement.len() {let mut value=self.replacement_for(group,i,&identity);if let Some(anchor)=anchor {value["handle"]=json!(anchor);commands.push(json!({"insert":{"rule":value}}));}else{commands.push(json!({"add":{"rule":value}}));}}
                for (i,id) in change.original.iter().take(prefix).enumerate() {let mut value=self.replacement_for(group,i,&identity);value["handle"]=json!(id);commands.push(json!({"replace":{"rule":value}}));}
                for id in &change.original[prefix..] {let mut value=base.clone();value["handle"]=json!(id);commands.push(json!({"delete":{"rule":value}}));}
            }
        }
        for policy in &self.policies {let mut value=without_handle(source.find_chain(&policy.chain)?);if !inverse {value["policy"]=json!(policy.value);}commands.push(json!({"add":{"chain":value}}));}
        if inverse {commands.push(json!({"delete":{"table":{"family":"inet","name":self.names().0}}}));}
        let mut result=json!({"nftables":commands});if let Some(generation)=actual.generation {result["expectedGeneration"]=json!(generation);raw::writer::encode(&result)?;}
        ensure!(serde_json::to_vec(&result)?.len()<=MAX_BYTES,"RESOURCE_EXHAUSTED: native transfer batch");Ok(result)
    }
}
