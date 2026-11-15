use super::*;

fn corpus()->Value {serde_json::from_str(include_str!("../../../../fixtures/legacy-raw-corpus-v35.json")).unwrap()}
fn match_term(left:Value,op:&str,right:Value)->Value {json!({"match":{"left":left,"op":op,"right":right}})}
fn payload(family:&str,expr:Value)->String {
    let batch=json!({"expectedGeneration":1,"nftables":[{"add":{"rule":{"family":family,"table":"test","chain":"input","expr":expr}}}]});
    let (bytes,_)=writer::encode(&batch).unwrap();let start=u32n(&bytes) as usize;let msg=&bytes[start..];let end=u32n(msg) as usize;
    msg[16..end].iter().map(|v|format!("{v:02x}")).collect()
}

#[test]
fn real_legacy_parameters_match_all_116_authenticated_model_clauses() {
    let data=corpus();let compiled=crate::nm::handover::native::classify::compiled_fixture();let mut count=0;
    for group in data["classification"]["selected"].as_array().unwrap() {
        let chain:Chain=serde_json::from_value(group["chain"].clone()).unwrap();
        let rows=&compiled.iter().find(|v|v.0==chain).unwrap().1;
        assert_eq!(rows.len(),group["rules"].as_array().unwrap().len());
        for (expr,binding) in rows.iter().zip(group["rules"].as_array().unwrap()) {
            let witness=data["source"]["ruleFingerprints"].as_array().unwrap().iter().find(|v|v["family"]==chain.family&&v["table"]==chain.table&&v["chain"]==chain.name&&v["handle"]==binding["handle"]).unwrap();
            assert_eq!(observed(witness["payloadHex"].as_str().unwrap()),Some(expected(&chain.family,&json!(expr)).unwrap()),"{} {} {} {}",chain.family,chain.table,chain.name,binding["handle"]);count+=1;
        }
    }
    assert_eq!(count,116);
}

#[test]
fn native_prefix_address_ports_and_state_have_the_same_bounded_signature() {
    let expr=json!([
        match_term(json!({"meta":{"key":"iifname"}}),"!=",json!("eth*")),
        match_term(json!({"payload":{"protocol":"ip6","field":"saddr"}}),"==",json!({"prefix":{"addr":"2001:db8::","len":64}})),
        match_term(json!({"payload":{"protocol":"tcp","field":"sport"}}),"==",json!({"range":[1000,2000]})),
        match_term(json!({"ct":{"key":"state"}}),"in",json!({"set":["related","established"]})),
        {"accept":null}
    ]);
    assert_eq!(observed(&payload("ip6",expr.clone())),Some(expected("ip6",&expr).unwrap()));
}

#[test]
fn predicate_order_and_duplicate_pure_guards_do_not_change_the_signature() {
    let a=match_term(json!({"meta":{"key":"iifname"}}),"==",json!("lo"));
    let b=match_term(json!({"payload":{"protocol":"udp","field":"dport"}}),"==",json!(8888));
    let first=json!([a,b,{"accept":null}]);let second=json!([b,a,b,{"counter":{"packets":19,"bytes":100}},{"accept":null}]);
    assert_eq!(expected("ip",&first).unwrap(),observed(&payload("ip",second)).unwrap());
}

#[test]
fn jump_return_drop_and_single_nat_targets_are_distinct() {
    for (family,expr) in [("ip",json!([{"jump":{"target":"input-kura"}}])),("ip6",json!([{"return":null}])),("ip",json!([{"drop":null}])),("ip6",json!([{"dnat":{"family":"ip6","addr":"2001:db8::8","port":8443}}])),("ip",json!([{"masquerade":null}]))] {
        assert_eq!(observed(&payload(family,expr.clone())),Some(expected(family,&expr).unwrap()));
    }
    assert_ne!(expected("ip",&json!([{"accept":null}])).unwrap(),expected("ip",&json!([{"drop":null}])).unwrap());
}

#[test]
fn unknown_or_extra_effects_never_hide_behind_a_matching_verdict() {
    let foreign=json!([{"mangle":{"key":{"meta":{"key":"mark"}},"value":19}},{"accept":null}]);
    assert!(observed(&payload("ip",foreign)).is_none());
    assert!(observed(&payload("ip",json!([{"accept":null},{"drop":null}]))).is_none());
    assert!(observed("00").is_none());
}

fn pack(values:&[(u16,Vec<u8>)])->Vec<u8> {values.iter().flat_map(|(tag,data)|wire::attribute(*tag,data)).collect()}
fn owned(bytes:&[u8])->Vec<(u16,Vec<u8>)> {attrs(bytes).unwrap().into_iter().map(|(tag,data)|(tag,data.to_vec())).collect()}
fn rewrite_module(payload:&str,name:&str,change:impl Fn(&mut Vec<(u16,Vec<u8>)>))->String {
    let bytes=decode(payload).unwrap();let mut outer=owned(&bytes[4..]);let expressions=outer.iter_mut().find(|v|v.0&0x3fff==4).unwrap();let mut terms=owned(&expressions.1);let mut changed=0;
    for (_,bytes) in &mut terms {let mut expression=owned(bytes);let kind=text(&expression.iter().find(|v|v.0&0x3fff==1).unwrap().1).unwrap();
        if !["match","target"].contains(&kind.as_str()){continue;}
        let raw=expression.iter_mut().find(|v|v.0&0x3fff==2).unwrap();let mut fields=owned(&raw.1);
        if text(&fields.iter().find(|v|v.0&0x3fff==1).unwrap().1).unwrap()==name {change(&mut fields);raw.1=pack(&fields);changed+=1;}
        *bytes=pack(&expression);
    }
    assert_eq!(changed,1);expressions.1=pack(&terms);[bytes[..4].to_vec(),pack(&outer)].concat().iter().map(|v|format!("{v:02x}")).collect()
}
fn witness(name:&str)->Value {
    corpus()["source"]["ruleFingerprints"].as_array().unwrap().iter().find(|v| {
        let bytes=decode(v["payloadHex"].as_str().unwrap()).unwrap();let outer=fields(&bytes[4..],&[1,2,3,4,5,7,8]).unwrap();
        attrs(get(&outer,4).unwrap()).unwrap().iter().any(|(_,bytes)|{let expr=fields(bytes,&[1,2]).unwrap();let kind=text(get(&expr,1).unwrap()).unwrap();["match","target"].contains(&kind.as_str())&&text(get(&fields(get(&expr,2).unwrap(),&[1,2,3]).unwrap(),1).unwrap()).unwrap()==name})
    }).unwrap().clone()
}

#[test]
fn opaque_xt_parameters_and_revisions_never_normalize_away() {
    let row=witness("conntrack");let original=row["payloadHex"].as_str().unwrap();let signature=observed(original).unwrap();
    for offset in [0,148,152,167] {let changed=rewrite_module(original,"conntrack",|f|f.iter_mut().find(|v|v.0&0x3fff==3).unwrap().1[offset]=2);assert!(observed(&changed).is_none(),"reserved offset {offset}");}
    let changed=rewrite_module(original,"conntrack",|f|f.iter_mut().find(|v|v.0&0x3fff==2).unwrap().1=2u32.to_be_bytes().to_vec());assert!(observed(&changed).is_none());
    let changed=rewrite_module(original,"conntrack",|f|f.iter_mut().find(|v|v.0&0x3fff==3).unwrap().1[150]|=8);assert_ne!(observed(&changed).unwrap(),signature);
    let row=witness("icmp6");let original=row["payloadHex"].as_str().unwrap();let changed=rewrite_module(original,"icmp6",|f|f.iter_mut().find(|v|v.0&0x3fff==3).unwrap().1[3]=8);assert!(observed(&changed).is_none());
    let row=witness("MASQUERADE");let original=row["payloadHex"].as_str().unwrap();assert!(observed(original).is_some());
    let changed=rewrite_module(original,"MASQUERADE",|f|f.iter_mut().find(|v|v.0&0x3fff==3).unwrap().1[4]=4);assert!(observed(&changed).is_none());
}

#[test]
fn lossy_xt_json_cannot_hide_changed_connection_state_from_the_complete_raw_review() {
    let row=witness("conntrack");let original=row["payloadHex"].as_str().unwrap();let changed=rewrite_module(original,"conntrack",|f|f.iter_mut().find(|v|v.0&0x3fff==3).unwrap().1[150]|=8);
    let mut source=corpus()["source"].clone();let rows=source["ruleFingerprints"].as_array_mut().unwrap();let index=rows.iter().position(|v|v==&row).unwrap();rows[index]=json!(fixture_fingerprint(&changed));
    let (roles,origin,_,_)=crate::nm::handover::native::classify::fixture();assert!(crate::nm::handover::native::classify::review_raw(&origin,&roles,&source).is_err());
}

#[test]
fn a_duplicate_matching_body_is_ambiguous_even_when_both_handles_are_valid() {
    let mut source=corpus()["source"].clone();let witness=source["ruleFingerprints"].as_array().unwrap().iter().find(|v|v["family"]=="ip"&&v["table"]=="filter"&&v["chain"]=="input-kura"&&v["handle"]==14).unwrap().clone();
    let bytes=decode(witness["payloadHex"].as_str().unwrap()).unwrap();let mut values=owned(&bytes[4..]);values.iter_mut().find(|v|v.0&0x3fff==3).unwrap().1=2222u64.to_be_bytes().to_vec();
    let payload=[bytes[..4].to_vec(),pack(&values)].concat().iter().map(|v|format!("{v:02x}")).collect::<String>();source["ruleFingerprints"].as_array_mut().unwrap().push(json!(fixture_fingerprint(&payload)));
    let entries=source["nftables"].as_array_mut().unwrap();let index=entries.iter().position(|v|v["rule"]["family"]=="ip"&&v["rule"]["table"]=="filter"&&v["rule"]["handle"]==14).unwrap();let mut copy=entries[index].clone();copy["rule"]["handle"]=json!(2222);entries.insert(index+1,copy);
    let (roles,origin,_,_)=crate::nm::handover::native::classify::fixture();let error=crate::nm::handover::native::classify::review_raw(&origin,&roles,&source).unwrap_err();assert!(format!("{error:#}").contains("ambiguous"));
}

#[test]
fn actual_rich_kernel_source_keeps_byte_prefixes_and_default_transport_header_checks() {
    let corpus:Value=serde_json::from_str(include_str!("../../../../fixtures/rich-raw-corpus-v35.json")).unwrap();let exchange=&corpus["exchange"];
    let observed=crate::nm::roles::Observation::new(uuid::Uuid::new_v4(),71,exchange["roles"].clone()).unwrap();
    let origin=crate::nm::roles::Origin::new(observed.agent_instance,observed.bridge_epoch,&observed,exchange["origin"].clone()).unwrap();
    let result=crate::nm::handover::native::classify::review_raw(&origin,&observed,&corpus["source"]);
    if result.is_err() {
        let raw=Snapshot::read(&corpus["source"]).unwrap();
        for (chain,expressions) in crate::nm::handover::native::classify::compiled_origin(&origin) {
            let rows=raw.rules.get(&chain).unwrap();let actual=rows.iter().map(|row|observed_signature(&raw,&chain,row)).collect::<Vec<_>>();
            for (index,expr) in expressions.iter().enumerate() {let expected=expected(&chain.family,&json!(expr)).unwrap();if !actual.iter().any(|a|a.as_ref()==Some(&expected)){eprintln!("UNMATCHED {} {} {} index={index} expected={expected:?} actual={actual:?}",chain.family,chain.table,chain.name);}}
        }
    }
    let result=result.unwrap();
    assert_eq!(result["unselectedRuleCount"],2);assert_eq!(result["opaqueRuleCountInModelChains"],2);assert!(result["selectedRuleCount"].as_u64().unwrap()>116);assert_eq!(result["preparationReady"],false);
}

fn observed_signature(raw:&Snapshot,chain:&Chain,row:&Value)->Option<Signature> {observed(&raw.payloads[&(chain.clone(),handle(row).unwrap())])}

#[test]
fn a_default_transport_module_is_not_equivalent_to_protocol_only() {
    let protocol=match_term(json!({"meta":{"key":"l4proto"}}),"==",json!(6));
    let guarded=json!([protocol,{"transportHeader":{"protocol":"tcp"}},{"accept":null}]);let unguarded=json!([protocol,{"accept":null}]);
    assert_ne!(expected("ip",&guarded).unwrap(),expected("ip",&unguarded).unwrap());
}
    #[test]
    fn original_icmp_header_guard_and_ipv6_type_255_are_not_normalized_away() {
        for (family,protocol,number,kind) in [("ip","icmp",1,8),("ip6","icmpv6",58,128)] {
            let guarded=json!([{"icmpHeader":{"protocol":protocol,"type":kind,"codeFirst":0,"codeLast":255,"inverted":false}},{"accept":null}]);
            let unguarded=json!([{"match":{"left":{"meta":{"key":"l4proto"}},"op":"==","right":number}},{"match":{"left":{"payload":{"protocol":protocol,"field":"type"}},"op":"==","right":kind}},{"accept":null}]);
            assert_ne!(expected(family,&guarded).unwrap(),expected(family,&unguarded).unwrap());
        }
        let signature=expected("ip6",&json!([{"icmpHeader":{"protocol":"icmpv6","type":255,"codeFirst":0,"codeLast":255,"inverted":false}},{"accept":null}])).unwrap();
        assert!(signature.predicates.contains(&Predicate::Compare(Key::Payload(2,0,1),vec![255],0,vec![255])));
    }

#[test]
fn an_unused_extra_packet_read_cannot_disappear_from_a_model_match() {
    let original=payload("ip",json!([match_term(json!({"meta":{"key":"l4proto"}}),"==",json!(6)),{"accept":null}]));
    let bytes=decode(&original).unwrap();let mut outer=owned(&bytes[4..]);let expr=outer.iter_mut().find(|v|v.0&0x3fff==4).unwrap();let mut terms=owned(&expr.1);
    let n=|tag:u16,value:u32|wire::attribute(tag,&value.to_be_bytes());
    let load=[wire::attribute(1,b"payload\0"),wire::attribute(0x8002,&[n(1,1),n(2,2),n(3,200),n(4,1)].concat())].concat();terms.insert(0,(1,load));expr.1=pack(&terms);
    let changed=[bytes[..4].to_vec(),pack(&outer)].concat().iter().map(|v|format!("{v:02x}")).collect::<String>();assert!(observed(&changed).is_none());
}
