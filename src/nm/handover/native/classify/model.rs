//! Adapter tests against the agent's observed model, wire encoder and original-layout fixtures.
use super::*;
use kura_firewall_policy::compile_clause as clause;

#[cfg(test)]
mod tests {
    use super::*;
    fn table()->Table {Table{name:"filter".into(),chains:vec![Declaration{name:"input-kura".into(),policy:None}],rules:vec![]}}
    fn compile(family:&str,text:&str)->Vec<Value> {clause(family,&table(),text).unwrap()}
    fn matching(left:Value,op:&str,right:Value)->Value {json!({"match":{"left":left,"op":op,"right":right}})}

    #[test]
    fn renderer_jump_return_and_verdicts_keep_control_flow() {
        assert_eq!(compile("ip","-j input-kura"),vec![json!({"jump":{"target":"input-kura"}})]);
        for (old,new) in [("RETURN","return"),("ACCEPT","accept"),("DROP","drop")] {assert_eq!(compile("ip",&format!("-j {old}")),vec![json!({new:null})]);}
    }
    #[test]
    fn interfaces_keep_prefix_negation_and_impossible_excluded_universal() {
        let row=compile("ip","-i eth+ ! -o wan0 -j ACCEPT");
        assert_eq!(row[0],matching(json!({"meta":{"key":"iifname"}}),"==",json!("eth*")));
        assert_eq!(row[1],matching(json!({"meta":{"key":"oifname"}}),"!=",json!("wan0")));
        assert_eq!(compile("ip","-i + -j ACCEPT"),vec![json!({"accept":null})]);
        assert_eq!(compile("ip6","! -i + -j ACCEPT")[0],matching(json!({"meta":{"key":"nfproto"}}),"!=",json!("ipv6")));
    }
    #[test]
    fn predicates_keep_both_address_families_mac_and_transport_ranges() {
        let row=compile("ip6","-s 2001:db8::1/64 -d 2001:db8:1::8 -i lan0 -p tcp --sport 1000:2000 --dport 8443 -m mac --mac-source 02:AA:BB:CC:DD:01 -j ACCEPT");
        assert!(row.contains(&matching(json!({"payload":{"protocol":"ip6","field":"saddr"}}),"==",json!({"prefix":{"addr":"2001:db8::","len":64}}))));
        assert!(row.contains(&matching(json!({"payload":{"protocol":"tcp","field":"sport"}}),"==",json!({"range":[1000,2000]}))));
        assert!(row.contains(&matching(json!({"payload":{"protocol":"ether","field":"saddr"}}),"==",json!("02:aa:bb:cc:dd:01"))));
    }
    #[test]
    fn ct_icmp_types_codes_and_family_are_explicit() {
        let row=compile("ip6","-p ipv6-icmp -m ipv6-icmp --icmpv6-type 3/1 -m state --state RELATED,ESTABLISHED -j DROP");
          assert!(row.contains(&json!({"icmpHeader":{"protocol":"icmpv6","type":3,"codeFirst":1,"codeLast":1,"inverted":false}})));
        assert!(row.contains(&matching(json!({"ct":{"key":"state"}}),"in",json!({"set":["established","related"]}))));
    }
    #[test]
    fn dnat_targets_and_masquerade_keep_original_family_port_and_conditions() {
        let nat=Table{name:"nat".into(),..table()};
        let row=clause("ip6",&nat,"-p tcp --dport 443 -j DNAT --to-destination [2001:db8::8]:8443").unwrap();
        assert_eq!(row.last().unwrap(),&json!({"dnat":{"family":"ip6","addr":"2001:db8::8","port":8443}}));
        assert_eq!(clause("ip",&nat,"-o wan0 -j MASQUERADE").unwrap().last().unwrap(),&json!({"masquerade":null}));
    }
    #[test]
    fn every_original_java_fixture_clause_can_compile_without_flattening() {
        let (_,origin,_,_)=super::super::fixture();let mut count=0;
        for (index,family) in origin.families().iter().enumerate() {
            let view:View=serde_json::from_value(crate::firewall::legacy_model_snapshot(&family.managed_ruleset).unwrap()).unwrap();
            for table in view.tables {for row in &table.rules {assert!(!clause(if index==0{"ip"}else{"ip6"},&table,&row.specification).unwrap().is_empty());count+=1;}}
        }
        assert_eq!(count,116);
    }
    #[test]
    fn every_compiled_original_clause_has_a_bounded_wire_adapter() {
        let (_,origin,_,_)=super::super::fixture();let mut count=0;
        for (index,family) in origin.families().iter().enumerate() {
            let family_name=if index==0{"ip"}else{"ip6"};
            let view:View=serde_json::from_value(crate::firewall::legacy_model_snapshot(&family.managed_ruleset).unwrap()).unwrap();
            for table in view.tables {for row in &table.rules {
                let expr=clause(family_name,&table,&row.specification).unwrap();
                let batch=json!({"expectedGeneration":17,"nftables":[{"add":{"rule":{"family":family_name,"table":table.name,"chain":row.chain,"expr":expr}}}]});
                raw::writer::encode(&batch).unwrap();count+=1;
            }}
        }
        assert_eq!(count,116);
    }
    #[test]
    fn unknown_ambiguous_or_cross_family_fields_cannot_disappear() {
          for text in ["-p tcp --tcp-flags SYN SYN -j ACCEPT","-i eth* -j ACCEPT","-p udp --dport 443 -j DNAT","-s 2001:db8::/64 -j ACCEPT","--icmpv6-type 1 -p icmp -j ACCEPT","-j unknown-chain","-j ACCEPT --to-source 192.0.2.1","--dport 443 -j ACCEPT","-p tcp -m udp --dport 443 -j ACCEPT","-m state --state DNAT -j ACCEPT","-p icmp -m icmp -j ACCEPT"] {
            assert!(clause("ip",&table(),text).is_err(),"{text}");
        }
        let nat=Table{name:"nat".into(),..table()};
        for text in ["-j DNAT --to-destination 192.0.2.1:80","-p icmp -j SNAT --to-source 192.0.2.1:80","-j DNAT --to-destination 192.0.2.1-192.0.2.2","-j DNAT --to-destination 2001:db8::1"] {assert!(clause("ip",&nat,text).is_err(),"{text}");}
    }

    #[test]
    fn universal_networks_keep_family_validation_before_normalization() {
        for (family,wrong,valid) in [("ip","::/0","0.0.0.0/0"),("ip6","0.0.0.0/0","::/0")] {
            for key in ["-s","--source","-d","--destination"] {
                assert!(clause(family,&table(),&format!("{key} {wrong} -j ACCEPT")).is_err(),"{family} {key} {wrong}");
                assert!(clause(family,&table(),&format!("{key} ! {wrong} -j ACCEPT")).is_err());
                assert_eq!(clause(family,&table(),&format!("{key} {valid} -j ACCEPT")).unwrap(),vec![json!({"accept":null})]);
                assert_eq!(clause(family,&table(),&format!("{key} ! {valid} -j ACCEPT")).unwrap().len(),2);
            }
        }
    }

    #[test]
    fn review_binds_compiled_rows_to_original_chains_and_handles_without_creating_a_plan() {
        let (observed,origin,legacy,native)=super::super::fixture();
        let review=super::super::review(&origin,&observed,&legacy,&native).unwrap();
        assert_eq!(review["schemaVersion"],2);assert_eq!(review["compiledManagedRuleCount"],116);
        let groups=review["selected"].as_array().unwrap();let mut count=0;
        for group in groups {let rules=group["rules"].as_array().unwrap();let expr=group["replacementExpressions"].as_array().unwrap();assert_eq!(rules.len(),expr.len());count+=rules.len();}
        assert_eq!(count,116);assert_eq!(review["preparationReady"],false);assert_eq!(review["nativePlanProduced"],false);
        assert!(groups.iter().any(|v|v["chain"]["name"]=="forward-kura-ipf"));
        assert!(groups.iter().any(|v|v["chain"]["table"]=="mangle"));
    }

    /// New compiler/control-flow proof only. Never an ownership, export, drain,
    /// inverse, lost-reply or old V33 predicate/policy-update scene.
    #[test]
    #[ignore="V34 fresh model/jump namespace only;explicit marker and NET_ADMIN"]
    fn native_model_jump_kernel_fixture() {
        use std::{fs,io::Write,path::Path,time::Duration};
        let root=std::path::PathBuf::from(std::env::var("YOFC_NATIVE_MODEL_V34_ROOT").expect("explicit new V34 fixture required"));
        assert_eq!(root,Path::new("/proof"));
        assert_eq!(fs::read_to_string(root.join(".owned-native-model-v34")).unwrap(),"fresh V34 compiler/jump namespace;no owner/export/drain\n");
        let save=|name:&str,value:&Value| {let mut f=fs::OpenOptions::new().write(true).create_new(true).open(root.join(name)).unwrap();f.write_all(&serde_json::to_vec_pretty(value).unwrap()).unwrap();f.sync_all().unwrap();};
        let nft=|| {let output=std::process::Command::new("/usr/sbin/nft").args(["-a","-j","list","ruleset"]).output().unwrap();assert!(output.status.success());serde_json::from_slice::<Value>(&output.stdout).unwrap()};
        save("model-driver-invoked.json",&json!({"scope":"new compiler jump/return only","noReplay":true}));
        let original=raw::observe(||Ok(nft()),Instant::now()+Duration::from_secs(5)).unwrap();
        let mut commands=Vec::new();
        for family in ["ip","ip6","inet"] {
            let name=format!("model_v34_{family}");
            commands.push(json!({"create":{"table":{"family":family,"name":name}}}));
            commands.push(json!({"add":{"chain":{"family":family,"table":name,"name":"base","type":"filter","hook":"input","prio":17,"policy":"accept"}}}));
            for chain in ["entry","child"] {commands.push(json!({"add":{"chain":{"family":family,"table":name,"name":chain}}}));}
            let descriptor=Table{name:"filter".into(),chains:["entry","child"].into_iter().map(|name|Declaration{name:name.into(),policy:None}).collect(),rules:vec![]};
            for (chain,label,text) in [("base","base-jump","-j entry"),("base","base-resumed","-j ACCEPT"),("entry","entry-jump","-j child"),("entry","entry-resumed","-j RETURN"),("child","child-return","-j RETURN"),("child","child-unreachable","-j ACCEPT")] {
                let mut expr=clause(if family=="ip6"{"ip6"}else{"ip"},&descriptor,text).unwrap();expr.insert(0,json!({"counter":{"packets":0,"bytes":0}}));
                commands.push(json!({"add":{"rule":{"family":family,"table":name,"chain":chain,"expr":expr,"comment":label}}}));
            }
        }
        let batch=json!({"expectedGeneration":original["kernelGeneration"],"nftables":commands});save("model-batch.json",&batch);
        raw::writer::dispatch(&batch,Instant::now()+Duration::from_secs(5)).unwrap();save("model-batch-ack.json",&json!({"acknowledged":true}));
        let counters=|state:&Value| {let mut map=BTreeMap::new();for item in state["nftables"].as_array().unwrap() {if let Some(rule)=item.get("rule").filter(|v|v["table"].as_str().is_some_and(|s|s.starts_with("model_v34_"))) {let c=rule["expr"].as_array().unwrap().iter().find_map(|v|v.get("counter")).unwrap();map.insert((rule["family"].as_str().unwrap().to_string(),rule["comment"].as_str().unwrap().to_string()),c["packets"].as_u64().unwrap());}}map};
        let before=nft();save("model-before-packets.json",&before);let zero=counters(&before);assert_eq!(zero.len(),18);assert!(zero.values().all(|v|*v==0));
        for host in ["127.0.0.1","::1"] {let receiver=std::net::UdpSocket::bind((host,0)).unwrap();receiver.set_read_timeout(Some(Duration::from_secs(2))).unwrap();let sender=std::net::UdpSocket::bind((host,0)).unwrap();sender.send_to(b"model-v34",receiver.local_addr().unwrap()).unwrap();let mut bytes=[0u8;32];let (count,_)=receiver.recv_from(&mut bytes).unwrap();assert_eq!(&bytes[..count],b"model-v34");}
        let after=nft();save("model-after-packets.json",&after);let observed=counters(&after);assert_eq!(observed.len(),18);
        for ((family,label),count) in &observed {let expected=if label=="child-unreachable"{0}else if family=="inet"{2}else{1};assert_eq!(*count,expected,"{family} {label}");}
        save("model-control-flow-result.json",&json!({"status":"passed","families":["ip","ip6","inet"],"privateUdpPackets":2,"zeroCountersBeforePackets":18,"observedCounterCases":18,"jumpReturnsThroughBothFrames":true,"childAfterReturnUnreachable":true,"nativePlanProduced":false,"preparationReady":false,"oldScenesReplayed":false}));
    }
}
