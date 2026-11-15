//! Offline regression using the retained actual rich kernel corpus, not a replay.
use super::*;

fn encode_hex(bytes:&[u8])->String {bytes.iter().map(|v|format!("{v:02x}")).collect()}
fn nla(kind:u16,value:&[u8])->Vec<u8> {
    let mut out=Vec::new();out.extend(((value.len()+4) as u16).to_ne_bytes());out.extend(kind.to_ne_bytes());out.extend(value);out.resize((out.len()+3)&!3,0);out
}
fn attributes(mut bytes:&[u8])->Vec<(u16,Vec<u8>)> {
    let mut out=Vec::new();while !bytes.is_empty() {let len=u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;out.push((u16::from_ne_bytes(bytes[2..4].try_into().unwrap()),bytes[4..len].to_vec()));bytes=&bytes[(len+3)&!3..];}out
}
fn changed_counter(payload:&str,remove:bool)->String {
    let bytes=raw::decode(payload).unwrap();let mut out=bytes[..4].to_vec();
    for (kind,mut data) in attributes(&bytes[4..]) {
        if kind&0x3fff==4 {
            let mut entries=attributes(&data);let index=entries.iter().position(|(_,v)|attributes(v).iter().any(|(t,name)|t&0x3fff==1&&name==b"counter\0")).unwrap();
            let counter=entries.remove(index);if !remove {entries.insert(0,counter);}data=entries.iter().flat_map(|(k,v)|nla(*k,v)).collect();
        }
        out.extend(nla(kind,&data));
    }
    encode_hex(&out)
}
#[test]
fn native_nat_kernel_derived_flags_are_exact_implicit_address_and_port_semantics() {
    let corpus:Value=serde_json::from_str(include_str!("../../fixtures/native-nat-readback-v36.json")).unwrap();
    assert_eq!(corpus["cases"].as_array().unwrap().len(),2);
    for case in corpus["cases"].as_array().unwrap() {
        assert!(raw::matcher::replacement_matches(case["payloadHex"].as_str().unwrap(),&case["wanted"]).unwrap());
        let bytes=raw::decode(case["payloadHex"].as_str().unwrap()).unwrap();let mut modified=bytes[..4].to_vec();
        for (kind,mut data) in attributes(&bytes[4..]) {
            if kind&0x3fff==4 {
                data=attributes(&data).iter().flat_map(|(kind,entry)| {
                    let mut fields=attributes(entry);
                    if fields.iter().any(|(k,v)|k&0x3fff==1&&v==b"nat\0") {
                        let field=fields.iter_mut().find(|(k,_)|k&0x3fff==2).unwrap();
                        field.1=attributes(&field.1).iter().flat_map(|(k,v)|if k&0x3fff==7{nla(*k,&7u32.to_be_bytes())}else{nla(*k,v)}).collect();
                    }
                    nla(*kind,&fields.iter().flat_map(|(k,v)|nla(*k,v)).collect::<Vec<_>>())
                }).collect();
            }
            modified.extend(nla(kind,&data));
        }
        assert!(!raw::matcher::replacement_matches(&encode_hex(&modified),&case["wanted"]).unwrap(),"randomization flags are not implied by an exact address and port");
    }
}
fn userdata(payload:&str,comment:&str)->String {
    let bytes=raw::decode(payload).unwrap();let mut out=bytes[..4].to_vec();let mut at=4;
    while at<bytes.len() {
        let len=u16::from_ne_bytes(bytes[at..at+2].try_into().unwrap()) as usize;
        let kind=u16::from_ne_bytes(bytes[at+2..at+4].try_into().unwrap());
        if kind&0x3fff!=7 {out.extend_from_slice(&bytes[at..at+((len+3)&!3)]);}
        at+=(len+3)&!3;
    }
    let mut value=vec![0,(comment.len()+1) as u8];value.extend(comment.as_bytes());value.push(0);
    out.extend(nla(7,&value));encode_hex(&out)
}
fn transfer_for(source:Value,exchange:&Value)->Transfer {
    let observed=roles::Observation::new(uuid::Uuid::new_v4(),71,exchange["roles"].clone()).unwrap();
    let origin=roles::Origin::new(observed.agent_instance,observed.bridge_epoch,&observed,exchange["origin"].clone()).unwrap();
    let report=classify::review_raw(&origin,&observed,&source).unwrap();
    let rules=report["selected"].as_array().unwrap().iter().map(|group|Rules {
        chain:serde_json::from_value(group["chain"].clone()).unwrap(),
        original:group["rules"].as_array().unwrap().iter().map(|r|r["handle"].as_u64().unwrap()).collect(),before:None,
        replacement:serde_json::from_value::<Vec<Vec<Value>>>(group["replacementExpressions"].clone()).unwrap().into_iter().map(|mut expr| {expr.insert(expr.len()-1,json!({"counter":{"packets":0,"bytes":0}}));expr}).collect(),
    }).collect();
    Transfer{operation_id:uuid::Uuid::new_v4(),source_digest:"a".repeat(64),source_model_sha256:None,original:source,rules,policies:vec![]}
}
fn fixture()->(Transfer,Value) {
    let corpus:Value=serde_json::from_str(include_str!("../../fixtures/rich-raw-corpus-v35.json")).unwrap();
    let transfer=transfer_for(corpus["source"].clone(),&corpus["exchange"]);
    let current=forward(&transfer);(transfer,current)
}
pub(in crate::nm) fn forward(transfer:&Transfer)->Value {
    let mut current=transfer.original.clone();
    let identity=transfer.identity().unwrap();
    for (group,change) in transfer.rules.iter().enumerate() {
        for (index,id) in change.original.iter().enumerate() {
            let tag=Transfer::tag_for(&identity,group,index);
            for entry in current["nftables"].as_array_mut().unwrap() {
                if let Some(row)=entry.get_mut("rule").filter(|r|chain(r).unwrap()==change.chain&&handle(r).unwrap()==*id) {row["comment"]=json!(tag);}
            }
            for f in current["ruleFingerprints"].as_array_mut().unwrap() {
                if f["family"]==change.chain.family&&f["table"]==change.chain.table&&f["chain"]==change.chain.name&&f["handle"]==*id {
                    let payload=userdata(f["payloadHex"].as_str().unwrap(),&tag);
                    *f=serde_json::to_value(raw::fixture_fingerprint(&payload)).unwrap();
                }
            }
        }
    }
    current["nftables"].as_array_mut().unwrap().push(transfer.receipt(false).unwrap());
    let generation=transfer.original["kernelGeneration"].as_u64().unwrap() as u32;
    current["kernelGeneration"]=json!(generation.wrapping_add(1).max(1));current
}

#[test]
fn native_generation_ack_requires_the_exact_committed_forward_and_inverse_steps() {
    let (transfer,current)=fixture();let original=transfer.original["kernelGeneration"].as_u64().unwrap();
    assert!(transfer.acknowledge(&current,false).is_ok());
    for generation in [Some(original),Some(original+2),None] {
        let mut drift=current.clone();if let Some(generation)=generation{drift["kernelGeneration"]=json!(generation);}else{drift.as_object_mut().unwrap().remove("kernelGeneration");}
        assert!(transfer.acknowledge(&drift,false).is_err(),"unchanged receipt and rules cannot confirm unexpected forward generation {generation:?}");
    }
    let mut inverse=transfer.original.clone();inverse["nftables"].as_array_mut().unwrap().push(transfer.receipt(true).unwrap());inverse["kernelGeneration"]=json!(original+2);
    assert!(transfer.acknowledge(&inverse,true).is_ok());
    for generation in [original+1,original+3] {let mut drift=inverse.clone();drift["kernelGeneration"]=json!(generation);assert!(transfer.acknowledge(&drift,true).is_err(),"unexpected inverse generation {generation}");}
}

#[test]
fn native_generation_ack_skips_zero_on_u32_wrap_like_the_kernel_commit() {
    let (mut transfer,_)=fixture();transfer.original["kernelGeneration"]=json!(u32::MAX);
    let current=forward(&transfer);assert_eq!(current["kernelGeneration"],1);assert!(transfer.acknowledge(&current,false).is_ok());
    let mut inverse=transfer.original.clone();inverse["nftables"].as_array_mut().unwrap().push(transfer.receipt(true).unwrap());inverse["kernelGeneration"]=json!(2);
    assert!(transfer.acknowledge(&inverse,true).is_ok());
    inverse["kernelGeneration"]=json!(1);assert!(transfer.acknowledge(&inverse,true).is_err());
}

#[test]
#[ignore="V36 v1 CLOSED after ACK/UNKNOWN;never replay;retained offline review only;no owner/export/drain"]
fn native_header_inverse_kernel_fixture() {
    use std::{fs,io::Write,time::{Duration,Instant}};
    let root=PathBuf::from(std::env::var("YOFC_NATIVE_OUTCOME_V36_ROOT").expect("new explicit V36 fixture required"));
    assert_eq!(root,Path::new("/proof"));
    assert_eq!(fs::read_to_string(root.join(".owned-native-outcome-v36")).unwrap(),"fresh V36 forward-inverse ABI;no owner/export/drain\n");
    let save=|name:&str,value:&Value| {let mut f=fs::OpenOptions::new().write(true).create_new(true).open(root.join(name)).unwrap();f.write_all(&serde_json::to_vec_pretty(value).unwrap()).unwrap();f.sync_all().unwrap();};
    save("native-outcome-invoked.json",&json!({"scope":"new V36 bounded forward/inverse ABI","noReplay":true}));
    let read=||raw::observe(|| {let output=std::process::Command::new("/usr/sbin/nft").args(["-j","-p","list","ruleset"]).output().unwrap();assert!(output.status.success());Ok(serde_json::from_slice(&output.stdout).unwrap())},Instant::now()+Duration::from_secs(10)).unwrap();
    let original=read();save("native-outcome-original.json",&original);
    let exchange:Value=serde_json::from_slice(&fs::read(root.join("java-origin-bridge.json")).unwrap()).unwrap();
    let transfer=transfer_for(original.clone(),&exchange);transfer.validate().unwrap();
    let selected=transfer.rules.iter().map(|g|g.original.len()).sum::<usize>();assert_eq!(selected,144);
    let headers=transfer.rules.iter().flat_map(|g|&g.replacement).flatten().filter(|e|e.get("transportHeader").is_some()).count();assert!(headers>0);
    save("native-outcome-transfer.json",&serde_json::to_value(&transfer).unwrap());
    let forward=transfer.batch(&original,false).unwrap();save("native-outcome-forward-batch.json",&forward);
    raw::writer::dispatch(&forward,Instant::now()+Duration::from_secs(10)).unwrap();save("native-outcome-forward-dispatch.json",&json!({"acknowledged":true}));
    let current=read();save("native-outcome-forward.json",&current);let forward_digest=transfer.acknowledge(&current,false).unwrap();
    save("native-outcome-forward-confirmed.json",&json!({"kernelDigest":forward_digest}));
    let inverse=transfer.batch(&current,true).unwrap();save("native-outcome-inverse-batch.json",&inverse);
    raw::writer::dispatch(&inverse,Instant::now()+Duration::from_secs(10)).unwrap();save("native-outcome-inverse-dispatch.json",&json!({"acknowledged":true}));
    let restored=read();save("native-outcome-inverse.json",&restored);let inverse_digest=transfer.acknowledge(&restored,true).unwrap();
    save("native-outcome-result.json",&json!({"status":"passed","selectedRuleCount":selected,"typedHeaderRules":headers,"forwardConfirmed":true,"inverseConfirmed":true,"inverseDigest":inverse_digest,"unselectedRawExactlyPreserved":true,"sameOriginalTransfer":true,"originalModelRegistrationSynthetic":true,"actualJvmOrDrainAccepted":false,"coreOwnerAccepted":false,"normalGatewayModified":false,"unknownRedispatch":false,"oldScenesReplayed":false}));
}

#[test]
#[ignore="explicit retained V36v1 evidence read-only;no kernel observation or dispatch"]
fn retained_forward_read_only_fixture() {
    use std::{fs,io::Write};
    let root=PathBuf::from(std::env::var("YOFC_NATIVE_RETAINED_V36_ROOT").unwrap());let scope=root.join("kernel-outcome-v36-v1");
    assert_eq!(fs::read_to_string(scope.join(".owned-native-outcome-v36")).unwrap(),"fresh V36 forward-inverse ABI;no owner/export/drain\n");
    let read=|name:&str|serde_json::from_slice::<Value>(&fs::read(scope.join(name)).unwrap()).unwrap();
    assert_eq!(read("result.json")["status"],"failed");assert_eq!(read("native-outcome-forward-dispatch.json")["acknowledged"],true);
    assert!(!scope.join("native-outcome-inverse-dispatch.json").exists());
    let transfer:Transfer=serde_json::from_value(read("native-outcome-transfer.json")).unwrap();assert_eq!(transfer.original,read("native-outcome-original.json"));
    let observed=read("native-outcome-forward.json");let digest=transfer.acknowledge(&observed,false).unwrap();
    let result=json!({"status":"recorded-forward-readback-confirmed-offline","operationId":transfer.operation_id,"kernelDigest":digest,"scope":"original saved ACK and complete same-generation raw snapshot only","liveKernelInspected":false,"originalScopeStillFailedAndRetained":true,"inverseDispatched":false,"dispatchCount":0,"journalChanged":false,"unknownRedispatch":false});
    let mut f=fs::OpenOptions::new().write(true).create_new(true).open(root.join("v1-retained-forward-read-only-review.json")).unwrap();f.write_all(&serde_json::to_vec_pretty(&result).unwrap()).unwrap();f.sync_all().unwrap();
}

#[test]
#[ignore="new owned V36 original-parameter creation-context ABI only;not retry/recovery of V36v1"]
fn native_original_context_kernel_fixture() {
    use std::{fs,io::Write,time::{Duration,Instant}};
    let root=PathBuf::from(std::env::var("YOFC_NATIVE_CONTEXT_V36_ROOT").unwrap());assert_eq!(root,Path::new("/proof"));
    assert_eq!(fs::read_to_string(root.join(".owned-native-context-v36")).unwrap(),"fresh V36 original context ABI;no prior operation retry\n");
    let save=|name:&str,value:&Value|{let mut f=fs::OpenOptions::new().write(true).create_new(true).open(root.join(name)).unwrap();f.write_all(&serde_json::to_vec_pretty(value).unwrap()).unwrap();f.sync_all().unwrap();};
    save("context-invoked.json",&json!({"purpose":"new original raw creation-context ABI","noPriorOperationRetry":true}));
    let read=||raw::observe(|| {let output=std::process::Command::new("/usr/sbin/nft").args(["-j","-p","list","ruleset"]).output().unwrap();assert!(output.status.success());Ok(serde_json::from_slice(&output.stdout).unwrap())},Instant::now()+Duration::from_secs(10)).unwrap();
    let original=read();save("context-original.json",&original);let source=Snapshot::read(&original).unwrap();
    let exchange:Value=serde_json::from_slice(&fs::read(root.join("java-origin-bridge.json")).unwrap()).unwrap();let transfer=transfer_for(original.clone(),&exchange);
    let mut selected=BTreeSet::new();let mut modules=BTreeSet::new();let mut commands=Vec::new();
    for change in &transfer.rules {for id in &change.original {
        let key=(change.chain.clone(),*id);assert!(selected.insert(key.clone()));let row=source.rules[&change.chain].iter().find(|r|handle(r).unwrap()==*id).unwrap();
        for expr in row["expr"].as_array().unwrap() {if let Some(name)=expr["xt"]["name"].as_str(){modules.insert(name.to_string());}}
        let mut body=row.clone();body["originalRawRule"]=json!(source.payloads[&key]);commands.push(json!({"replace":{"rule":body}}));
    }}
    assert_eq!(selected.len(),144);for name in ["tcp","udp","icmp","icmp6","conntrack","MASQUERADE","DNAT"] {assert!(modules.contains(name),"missing actual module {name}");}
    let batch=json!({"expectedGeneration":source.generation.unwrap(),"nftables":commands});save("context-batch.json",&batch);
    raw::writer::dispatch(&batch,Instant::now()+Duration::from_secs(10)).unwrap();save("context-dispatch.json",&json!({"acknowledged":true}));
    let after=read();save("context-after.json",&after);let current=Snapshot::read(&after).unwrap();assert!(source.objects==current.objects&&source.rules==current.rules);
    for (key,hash) in &source.fingerprints {
        if selected.contains(key) {assert!(raw::same_semantics(&source.payloads[key],&current.payloads[key]).unwrap());}
        else {assert_eq!(hash,&current.fingerprints[key]);assert_eq!(source.payloads[key],current.payloads[key]);}
    }
    save("context-result.json",&json!({"status":"passed","selectedRuleCount":144,"opaqueForeignExactlyPreserved":2,"knownModules":modules,"originalExpressionsAndUserdataExact":true,"creationContextAcceptedByKernel":true,"noTransferReceiptOrOwner":true,"fullTransferForwardInverseCycleAccepted":false,"oldOperationRedispatched":false,"normalGatewayModified":false}));
}

#[test]
fn raw_outcome_accepts_actual_lowering_with_default_transport_header_and_exact_receipts() {
    let (transfer,current)=fixture();
    assert!(transfer.rules.iter().flat_map(|g|&g.replacement).flatten().any(|e|e.get("transportHeader").is_some()));
    let snapshot=Snapshot::read(&current).unwrap();
    for (group,change) in transfer.rules.iter().enumerate() {for (index,id) in change.original.iter().enumerate() {
        let wanted=transfer.replacement(group,index).unwrap();let payload=&snapshot.payloads[&(change.chain.clone(),*id)];
        assert!(raw::matcher::replacement_matches(payload,&wanted).unwrap(),"raw mismatch {} {} {} {index}: wanted={wanted}",change.chain.family,change.chain.table,change.chain.name);
    }}
    assert!(transfer.acknowledge(&current,false).is_ok(),"complete original-bound raw parameters must confirm the lowered model");
}

#[test]
fn raw_outcome_rejects_foreign_drift_missing_parameters_receipt_forgery_and_header_erasure() {
    let (transfer,current)=fixture();
    assert!(transfer.acknowledge(&current,false).is_ok());
    for defect in ["foreign-raw","missing-selected","missing-foreign","comment","raw-comment","metadata","order","header-erasure","counter-position","counter-removal","unknown-raw"] {
        let mut changed=current.clone();
        let group=transfer.rules.iter().position(|g|g.replacement.iter().flatten().any(|e|e.get("transportHeader").is_some())).unwrap();
        let change=&transfer.rules[group];let index=change.replacement.iter().position(|expr|expr.iter().any(|e|e.get("transportHeader").is_some())).unwrap();
        let id=change.original[index];let fp=changed["ruleFingerprints"].as_array().unwrap().iter().position(|f|f["family"]==change.chain.family&&f["table"]==change.chain.table&&f["handle"]==id).unwrap();
        let row=changed["nftables"].as_array().unwrap().iter().position(|v|v.get("rule").is_some_and(|r|chain(r).unwrap()==change.chain&&handle(r).unwrap()==id)).unwrap();
        match defect {
            "missing-selected"=>{changed["ruleFingerprints"][fp].as_object_mut().unwrap().remove("payloadHex");},
            "missing-foreign"|"foreign-raw"=>{
                let foreign=changed["nftables"].as_array().unwrap().iter().filter_map(|v|v.get("rule")).find(|r|r["comment"].as_str().is_some_and(|v|v.starts_with("foreign-native-v35"))).unwrap().clone();
                let f=changed["ruleFingerprints"].as_array_mut().unwrap().iter_mut().find(|f|f["family"]==foreign["family"]&&f["table"]==foreign["table"]&&f["handle"]==foreign["handle"]).unwrap();
                if defect=="missing-foreign" {f.as_object_mut().unwrap().remove("payloadHex");}else{f.as_object_mut().unwrap().remove("payloadHex");f["sha256"]=json!("f".repeat(64));}
            },
            "comment"=>changed["nftables"][row]["rule"]["comment"]=json!("forged"),
            "raw-comment"=>{let payload=userdata(changed["ruleFingerprints"][fp]["payloadHex"].as_str().unwrap(),"forged");changed["ruleFingerprints"][fp]=serde_json::to_value(raw::fixture_fingerprint(&payload)).unwrap();},
            "metadata"=>changed["nftables"][row]["rule"]["unexpected"]=json!(true),
            "counter-position"|"counter-removal"|"unknown-raw"=>{
                let original=changed["ruleFingerprints"][fp]["payloadHex"].as_str().unwrap();
                let payload=if defect=="unknown-raw" {let mut bytes=raw::decode(original).unwrap();bytes.extend(nla(44,&[1]));encode_hex(&bytes)}else{changed_counter(original,defect=="counter-removal")};
                changed["ruleFingerprints"][fp]=serde_json::to_value(raw::fixture_fingerprint(&payload)).unwrap();
            },
            "order"=>{let other=changed["nftables"].as_array().unwrap().iter().enumerate().find(|(i,v)|*i!=row&&v.get("rule").is_some_and(|r|chain(r).unwrap()==change.chain)).unwrap().0;changed["nftables"].as_array_mut().unwrap().swap(row,other);},
            "header-erasure"=>{
                let mut wanted=transfer.replacement(group,index).unwrap();wanted["expr"]=json!(change.replacement[index].iter().filter(|e|e.get("transportHeader").is_none()).cloned().collect::<Vec<_>>());
                assert!(!raw::matcher::replacement_matches(changed["ruleFingerprints"][fp]["payloadHex"].as_str().unwrap(),&wanted).unwrap());continue;
            },_=>unreachable!(),
        }
        assert!(transfer.acknowledge(&changed,false).is_err(),"{defect}");
    }
}
