//! UAPI contracts independently checked against nftables 1.0.9 in V33's fresh
//! namespace. These tests only encode and inspect bytes; they never dispatch.
use super::*;

type Fields = Vec<(u16, Vec<u8>)>;
type Terms = Vec<(String, Fields)>;

fn owned_fields(bytes: &[u8]) -> Fields {
    attrs(bytes).unwrap().into_iter().map(|(k, v)| (k, v.to_vec())).collect()
}

fn field(fields: &Fields, key: u16) -> &[u8] {
    let matches = fields.iter().filter(|(k, _)| k & 0x3fff == key).collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "attribute {key}");
    &matches[0].1
}

fn be32(fields: &Fields, key: u16) -> u32 {
    u32::from_be_bytes(field(fields, key).try_into().unwrap())
}

fn command_fields(batch: &Value) -> (u16, Fields) {
    let (bytes, _) = encode(batch).unwrap();
    let begin = u32n(&bytes) as usize;
    let message = &bytes[begin..];
    let end = u32n(message) as usize;
    (u16n(&message[6..]), owned_fields(&message[20..end]))
}

fn rule(family: &str, left: Value, op: &str, right: Value) -> Value {
    json!({"expectedGeneration":17,"nftables":[{"add":{"rule":{
        "family":family,"table":"v33","chain":"input",
        "expr":[{"match":{"op":op,"left":left,"right":right}},{"accept":null}]
    }}}]})
}

fn decoded_terms(batch: &Value) -> Terms {
    let (_, fields) = command_fields(batch);
    owned_fields(field(&fields, 4)).iter().map(|(_, item)| {
        let fields = owned_fields(item);
        (text(field(&fields, 1)).unwrap(), owned_fields(field(&fields, 2)))
    }).collect()
}

fn cmp_data(term: &Fields) -> Vec<u8> {
    field(&owned_fields(field(term, 3)), 1).to_vec()
}

fn last_cmp(terms: &Terms) -> &Fields {
    &terms.iter().rev().find(|(name, _)| name == "cmp").unwrap().1
}

#[test]
fn original_jump_uses_the_verdict_register_code_and_chain_attribute() {
    let batch=json!({"expectedGeneration":17,"nftables":[{"add":{"rule":{"family":"ip","table":"filter","chain":"INPUT","expr":[{"jump":{"target":"input-kura"}}]}}}]});
    let terms=decoded_terms(&batch);assert_eq!(terms.len(),1);assert_eq!(terms[0].0,"immediate");
    assert_eq!(be32(&terms[0].1,1),0); // NFT_REG_VERDICT
    let data=owned_fields(field(&terms[0].1,2));let verdict=owned_fields(field(&data,2));
    assert_eq!(be32(&verdict,1) as i32,-3); // NFT_JUMP, not GOTO or RETURN
    assert_eq!(field(&verdict,2),b"input-kura\0");
    for value in [json!({"target":""}),json!({"target":"x y"}),json!({"target":"input-kura","goto":true}),json!({"chain":"input-kura"})] {
        let mut changed=batch.clone();changed["nftables"][0]["add"]["rule"]["expr"]=json!([{"jump":value}]);assert!(encode(&changed).is_err());
    }
}

#[test]
fn bounded_transport_header_has_exact_default_module_and_creation_protocol() {
    for (protocol,number) in [("tcp",6),("udp",17)] {
        let batch=json!({"expectedGeneration":17,"nftables":[{"add":{"rule":{"family":"ip","table":"filter","chain":"FORWARD","expr":[{"transportHeader":{"protocol":protocol}},{"accept":null}]}}}]});
        let (_,fields)=command_fields(&batch);let compat=owned_fields(field(&fields,5));assert_eq!(be32(&compat,1),number);assert_eq!(be32(&compat,2),0);
        let terms=decoded_terms(&batch);let module=&terms.iter().find(|v|v.0=="match").unwrap().1;assert_eq!(field(module,1),format!("{protocol}\0").as_bytes());assert_eq!(be32(module,2),0);assert_eq!(field(module,3),&[0,0,255,255,0,0,255,255,0,0,0,0,0,0,0,0]);
        for invalid in [json!({"protocol":"sctp"}),json!({"protocol":protocol,"raw":"untrusted"})] {let mut changed=batch.clone();changed["nftables"][0]["add"]["rule"]["expr"][0]["transportHeader"]=invalid;assert!(encode(&changed).is_err());}
    }
}
    #[test]
    fn typed_icmp_module_preserves_family_type_codes_and_creation_context() {
        for (family,protocol,module,number,kind) in [("ip","icmp","icmp",1,8),("ip6","icmpv6","icmp6",58,128)] {
            let batch=json!({"expectedGeneration":17,"nftables":[{"add":{"rule":{"family":family,"table":"filter","chain":"INPUT","expr":[{"icmpHeader":{"protocol":protocol,"type":kind,"codeFirst":0,"codeLast":255,"inverted":false}},{"accept":null}]}}}]});
            let (_,fields)=command_fields(&batch);let compat=owned_fields(field(&fields,5));assert_eq!(be32(&compat,1),number);assert_eq!(be32(&compat,2),0);
            let terms=decoded_terms(&batch);let data=&terms.iter().find(|v|v.0=="match").unwrap().1;assert_eq!(field(data,1),format!("{module}\0").as_bytes());assert_eq!(field(data,3),&[kind as u8,0,255,0,0,0,0,0]);
            for defect in ["family","type","range","field"] {
                let mut changed=batch.clone();let rule=&mut changed["nftables"][0]["add"]["rule"];
                match defect {"family"=>rule["family"]=json!(if family=="ip"{"ip6"}else{"ip"}),"type"=>rule["expr"][0]["icmpHeader"]["type"]=json!(256),"range"=>rule["expr"][0]["icmpHeader"]["codeFirst"]=json!(256),_=>rule["expr"][0]["icmpHeader"]["raw"]=json!("untrusted")};assert!(encode(&changed).is_err());
            }
        }
    }

#[test]
fn inverse_keeps_original_expression_bytes_and_restores_creation_only_module_context() {
    let corpus:Value=serde_json::from_str(include_str!("../../../../fixtures/rich-raw-corpus-v35.json")).unwrap();let source=&corpus["source"];let mut checked=std::collections::BTreeSet::new();
    for row in source["nftables"].as_array().unwrap().iter().filter_map(|v|v.get("rule")) {
        for name in ["tcp","udp","icmp","icmp6"] {
            if !row["expr"].as_array().unwrap().iter().any(|v|v["xt"]["name"]==name){continue;}
            let f=source["ruleFingerprints"].as_array().unwrap().iter().find(|v|v["family"]==row["family"]&&v["table"]==row["table"]&&v["chain"]==row["chain"]&&v["handle"]==row["handle"]).unwrap();
            let raw=decode(f["payloadHex"].as_str().unwrap()).unwrap();let original=owned_fields(&raw[4..]);let batch=json!({"expectedGeneration":17,"nftables":[{"add":{"rule":{"family":row["family"],"table":row["table"],"chain":row["chain"],"originalRawRule":f["payloadHex"]}}}]});
            let (_,current)=command_fields(&batch);assert_eq!(field(&current,4),field(&original,4));let context=owned_fields(field(&current,5));assert_eq!(be32(&context,1),match name{"tcp"=>6,"udp"=>17,"icmp"=>1,_=>58});assert_eq!(be32(&context,2),0);checked.insert(name);
        }
    }
    assert_eq!(checked.len(),4);
}

#[test]
fn mac_matches_require_ethernet_and_compare_six_octets_not_text() {
    for family in ["ip", "ip6", "inet"] {
        for (name, offset) in [("saddr", 6), ("daddr", 0)] {
            let batch = rule(family, json!({"payload":{"protocol":"ether","field":name}}), "==", json!("aA:Bb:cC:Dd:eE:Ff"));
            let terms = decoded_terms(&batch);
            assert_eq!(terms[0].0, "meta");
            assert_eq!(be32(&terms[0].1, 2), 8); // NFT_META_IIFTYPE
            assert_eq!(cmp_data(&terms[1].1), 1u16.to_ne_bytes()); // ARPHRD_ETHER, host byte order
            let payload = &terms.iter().find(|(name, _)| name == "payload").unwrap().1;
            assert_eq!((be32(payload, 2), be32(payload, 3), be32(payload, 4)), (0, offset, 6));
            assert_eq!(cmp_data(last_cmp(&terms)), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        }
    }
}

#[test]
fn interface_prefixes_compare_stem_bytes_and_exact_names_keep_the_terminator() {
    for (key, number) in [("iifname", 6), ("oifname", 7)] {
        for (op, cmp) in [("==", 0), ("!=", 1)] {
            for (name, expected) in [("lo*", b"lo".as_slice()), ("lo", b"lo\0".as_slice())] {
                let terms = decoded_terms(&rule("inet", json!({"meta":{"key":key}}), op, json!(name)));
                assert_eq!(be32(&terms[0].1, 2), number);
                assert_eq!(be32(last_cmp(&terms), 2), cmp);
                assert_eq!(cmp_data(last_cmp(&terms)), expected);
            }
        }
    }
}

#[test]
fn unbounded_or_ambiguous_names_and_malformed_macs_are_refused_before_dispatch() {
    for name in ["*", "*lo", "lo**", "lo*x", "lo\\*", "1234567890123456", "lo/name", "lo name"] {
        assert!(encode(&rule("ip", json!({"meta":{"key":"iifname"}}), "==", json!(name))).is_err(), "{name}");
    }
    for mac in ["", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:fg", "a:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff:00"] {
        assert!(encode(&rule("ip", json!({"payload":{"protocol":"ether","field":"saddr"}}), "==", json!(mac))).is_err(), "{mac}");
    }
}

#[test]
fn conntrack_state_uses_a_data_register_and_the_state_key_with_no_ignored_fields() {
    let right = json!({"set":["established","related"]});
    let terms = decoded_terms(&rule("inet", json!({"ct":{"key":"state"}}), "in", right.clone()));
    assert_eq!(terms[0].0, "ct");
    assert_eq!(be32(&terms[0].1, 1), 1); // NFTA_CT_DREG = NFT_REG_1, not verdict
    assert_eq!(be32(&terms[0].1, 2), 0); // NFTA_CT_KEY = NFT_CT_STATE, not direction
    let bitwise = &terms.iter().find(|(name, _)| name == "bitwise").unwrap().1;
    assert_eq!(field(&owned_fields(field(bitwise, 4)), 1), 6u32.to_ne_bytes());
    assert_eq!(be32(last_cmp(&terms), 2), 1);
    let bad = json!({"set":["established"],"ignored":true});
    assert!(encode(&rule("inet", json!({"ct":{"key":"state"}}), "in", bad)).is_err());
}

#[test]
fn base_chains_bind_type_hook_signed_priority_and_policy_without_silent_omission() {
    for (hook, number, kind, priority) in [("input", 1, "filter", 5), ("prerouting", 0, "nat", -100), ("postrouting", 4, "nat", 100)] {
        let chain = json!({"family":"inet","table":"v33","name":"input","type":kind,"hook":hook,"prio":priority,"policy":"drop"});
        let batch = json!({"expectedGeneration":17,"nftables":[{"add":{"chain":chain}}]});
        let (flags, fields) = command_fields(&batch);
        assert_ne!(flags & 0x400, 0); // create the missing chain, matching nft add
        assert_eq!(text(field(&fields, 7)).unwrap(), kind);
        let hook_fields = owned_fields(field(&fields, 4));
        assert_eq!(be32(&hook_fields, 1), number);
        assert_eq!(i32::from_be_bytes(field(&hook_fields, 2).try_into().unwrap()), priority);
        assert_eq!(be32(&fields, 5), 0);
        for missing in ["type", "hook", "prio"] {
            let mut bad = batch.clone();
            bad["nftables"][0]["add"]["chain"].as_object_mut().unwrap().remove(missing);
            assert!(encode(&bad).is_err(), "{missing}");
        }
    }
}

#[test]
fn version_nibbles_and_inet_addresses_keep_protocol_context_and_network_bytes() {
    for (protocol, version, family, address, offset, length) in [
        ("ip", 4u8, 2u8, "192.0.2.7", 12, 4),
        ("ip6", 6, 10, "2001:db8::7", 8, 16),
    ] {
        let left = json!({"payload":{"protocol":protocol,"field":"version"}});
        let terms = decoded_terms(&rule("inet", left, "==", json!(version)));
        assert_eq!(be32(&terms[0].1, 2), 15); // NFT_META_NFPROTO
        assert_eq!(cmp_data(&terms[1].1), [family]);
        let payload = &terms.iter().find(|(name, _)| name == "payload").unwrap().1;
        assert_eq!((be32(payload, 2), be32(payload, 3), be32(payload, 4)), (1, 0, 1));
        let bitwise = &terms.iter().find(|(name, _)| name == "bitwise").unwrap().1;
        assert_eq!(field(&owned_fields(field(bitwise, 4)), 1), [0xf0]);
        assert_eq!(cmp_data(last_cmp(&terms)), [version << 4]);
        let terms = decoded_terms(&rule("inet", json!({"payload":{"protocol":protocol,"field":"saddr"}}), "==", json!(address)));
        assert_eq!(be32(&terms[0].1, 2), 15);
        assert_eq!(cmp_data(&terms[1].1), [family]);
        let payload = &terms.iter().find(|(name, _)| name == "payload").unwrap().1;
        assert_eq!((be32(payload, 2), be32(payload, 3), be32(payload, 4)), (1, offset, length));
        let expected = match address.parse::<std::net::IpAddr>().unwrap() {
            std::net::IpAddr::V4(v) => v.octets().to_vec(),
            std::net::IpAddr::V6(v) => v.octets().to_vec(),
        };
        assert_eq!(cmp_data(last_cmp(&terms)), expected);
    }
}

fn nft_ruleset() -> Value {
    let output = std::process::Command::new("/usr/sbin/nft").args(["-a", "-j", "list", "ruleset"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn save_proof(root: &std::path::Path, name: &str, value: &Value) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().create_new(true).write(true).open(root.join(name)).unwrap();
    file.write_all(&serde_json::to_vec_pretty(value).unwrap()).unwrap();
    file.sync_all().unwrap();
}

fn kernel_rule(family: &str, table: &str, name: &str, matches: Vec<Value>) -> Value {
    let mut expressions = matches;
    expressions.push(json!({"counter":{"packets":0,"bytes":0}}));
    json!({"add":{"rule":{"family":family,"table":table,"chain":"input","comment":name,"expr":expressions}}})
}

fn predicate(left: Value, op: &str, right: Value) -> Value {
    json!({"match":{"left":left,"op":op,"right":right}})
}

/// A new wire-only namespace contract. Not an original transfer, ownership,
/// inverse, generation-rejection or lost-reply scene; no management API runs.
#[test]
#[ignore = "V33 fresh namespace only;requires its own marker and NET_ADMIN"]
fn native_wire_kernel_fixture() {
    let root = std::path::PathBuf::from(std::env::var("YOFC_NATIVE_WIRE_V33_ROOT").expect("new explicit V33 fixture required"));
    assert_eq!(root, std::path::Path::new("/proof"));
    assert_eq!(std::fs::read_to_string(root.join(".owned-native-wire-v33")).unwrap(), "fresh V33 wire namespace;no owner/export/drain\n");
    save_proof(&root, "wire-invoked.json", &json!({"scope":"fresh-wire-only","noRetry":true}));
    let before = nft_ruleset();
    assert!(before["nftables"].as_array().unwrap().iter().all(|row| {
        row.get("metainfo").is_some() || row.get("table").is_some_and(|v|v["name"]=="retained_v33")
            || row.get("chain").is_some_and(|v|v["table"]=="retained_v33")
            || row.get("rule").is_some_and(|v|v["table"]=="retained_v33")
    }));
    save_proof(&root, "wire-before.json", &before);
    let receiver = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    receiver.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
    let sender = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let mut commands = Vec::new();
    let mut expected = std::collections::BTreeMap::<(String, String), u64>::new();
    for family in ["ip", "ip6", "inet"] {
        let table = format!("wire_v33_{family}");
        commands.push(json!({"create":{"table":{"family":family,"name":table,"comment":"fresh V33 wire contract"}}}));
        for (name, kind, hook, priority) in [("input","filter","input",5),("prerouting","nat","prerouting",-100),("postrouting","nat","postrouting",100)] {
            commands.push(json!({"add":{"chain":{"family":family,"table":table,"name":name,"type":kind,"hook":hook,"prio":priority,"policy":"accept"}}}));
        }
        commands.push(json!({"add":{"chain":{"family":family,"table":table,"name":"plain"}}}));
        let packet = u64::from(family != "ip6");
        let mut cases = vec![
            ("prefix-positive", predicate(json!({"meta":{"key":"iifname"}}),"==",json!("lo*")),packet),
            ("prefix-negative", predicate(json!({"meta":{"key":"iifname"}}),"!=",json!("lo*")),0),
            ("other-prefix-negative", predicate(json!({"meta":{"key":"iifname"}}),"!=",json!("absent*")),packet),
            ("exact-lo", predicate(json!({"meta":{"key":"iifname"}}),"==",json!("lo")),packet),
            ("ct-new", predicate(json!({"ct":{"key":"state"}}),"in",json!({"set":["new"]})),packet),
            ("ct-established", predicate(json!({"ct":{"key":"state"}}),"in",json!({"set":["established","related"]})),0),
            ("ct-not-established", predicate(json!({"ct":{"key":"state"}}),"not in",json!({"set":["established","related"]})),packet),
            ("mac-excludes-loopback", predicate(json!({"payload":{"protocol":"ether","field":"saddr"}}),"==",json!("00:00:00:00:00:00")),0),
            ("mac-destination", predicate(json!({"payload":{"protocol":"ether","field":"daddr"}}),"!=",json!("00:11:22:33:44:55")),0),
        ];
        for (protocol, version, address) in [("ip",4,"127.0.0.1"),("ip6",6,"::1")] {
            if family != "inet" && family != protocol { continue; }
            let count = if protocol == "ip" { packet } else { 0 };
            cases.push((if protocol=="ip"{"version4"}else{"version6"}, predicate(json!({"payload":{"protocol":protocol,"field":"version"}}),"==",json!(version)),count));
            cases.push((if protocol=="ip"{"address4"}else{"address6"}, predicate(json!({"payload":{"protocol":protocol,"field":"saddr"}}),"==",json!(address)),count));
        }
        for (name, condition, count) in cases {
            commands.push(kernel_rule(family,&table,name,vec![condition]));
            expected.insert((table.clone(),name.into()),count);
        }
        if family != "ip6" {
            commands.push(kernel_rule(family,&table,"compound",vec![
                predicate(json!({"payload":{"protocol":"ip","field":"version"}}),"==",json!(4)),
                predicate(json!({"payload":{"protocol":"ip","field":"saddr"}}),"==",json!({"prefix":{"addr":"127.0.0.1","len":8}})),
                predicate(json!({"meta":{"key":"iifname"}}),"==",json!("lo*")),
                predicate(json!({"ct":{"key":"state"}}),"in",json!({"set":["new"]})),
                predicate(json!({"payload":{"protocol":"udp","field":"sport"}}),"==",json!(sender.local_addr().unwrap().port())),
                predicate(json!({"payload":{"protocol":"udp","field":"dport"}}),"==",json!(receiver.local_addr().unwrap().port())),
            ]));
            expected.insert((table.clone(),"compound".into()),1);
        }
    }
    let batch = json!({"expectedGeneration":wire::generation(Instant::now()+std::time::Duration::from_secs(5)).unwrap(),"nftables":commands});
    save_proof(&root,"wire-batch.json",&batch);
    dispatch(&batch,Instant::now()+std::time::Duration::from_secs(5)).unwrap();
    save_proof(&root,"wire-batch-ack.json",&json!({"acknowledged":true}));
    let pre_packet=nft_ruleset();save_proof(&root,"wire-before-packet.json",&pre_packet);
    let mut zero_counters=0;
    for row in pre_packet["nftables"].as_array().unwrap() {
        if let Some(rule)=row.get("rule").filter(|v|v["table"].as_str().is_some_and(|v|v.starts_with("wire_v33_"))) {
            let counter=rule["expr"].as_array().unwrap().iter().find_map(|v|v.get("counter")).unwrap();
            assert_eq!(counter["packets"],0);assert_eq!(counter["bytes"],0);zero_counters+=1;
        }
    }
    assert_eq!(zero_counters,expected.len(),"traffic assertions start from actual zero counters");
    sender.send_to(b"wire-v33",receiver.local_addr().unwrap()).unwrap();
    let mut buffer = [0;32];
    let (size,_) = receiver.recv_from(&mut buffer).unwrap();assert_eq!(&buffer[..size],b"wire-v33");
    let after = nft_ruleset();save_proof(&root,"wire-after-packet.json",&after);
    let mut observed = std::collections::BTreeMap::new();
    let mut chains = 0;
    for row in after["nftables"].as_array().unwrap() {
        if let Some(chain)=row.get("chain").filter(|v|v["table"].as_str().is_some_and(|v|v.starts_with("wire_v33_"))) {
            let name=chain["name"].as_str().unwrap();
            if name=="plain" {assert!(chain.get("hook").is_none()&&chain.get("policy").is_none());}
            else {
                let (kind,priority)=if name=="input"{("filter",5)}else if name=="prerouting"{("nat",-100)}else{assert_eq!(name,"postrouting");("nat",100)};
                assert_eq!(chain["type"],kind);assert_eq!(chain["hook"],name);assert_eq!(chain["prio"],priority);assert_eq!(chain["policy"],"accept");
            }
            chains+=1;
        }
        if let Some(rule)=row.get("rule").filter(|v|v["table"].as_str().is_some_and(|v|v.starts_with("wire_v33_"))) {
            let key=(rule["table"].as_str().unwrap().into(),rule["comment"].as_str().unwrap().into());
            let counter=rule["expr"].as_array().unwrap().iter().find_map(|v|v.get("counter")).unwrap();
            observed.insert(key,counter["packets"].as_u64().unwrap());
        }
    }
    assert_eq!(chains,12);assert_eq!(observed,expected,"actual loopback packet predicate counters");
    let expected_rows=expected.iter().map(|((table,comment),packets)|json!({"table":table,"comment":comment,"packets":packets})).collect::<Vec<_>>();
    save_proof(&root,"wire-traffic-result.json",&json!({"status":"passed","cases":expected_rows,"privateLoopbackUdpPacketsSent":1,"physicalEthernetPositiveClaimed":false}));
    let late = json!({"expectedGeneration":wire::generation(Instant::now()+std::time::Duration::from_secs(5)).unwrap(),"nftables":[{"add":{"chain":{"family":"inet","table":"wire_v33_inet","name":"late_drop","type":"filter","hook":"input","prio":12,"policy":"drop"}}}]});
    save_proof(&root,"wire-drop-batch.json",&late);dispatch(&late,Instant::now()+std::time::Duration::from_secs(5)).unwrap();
    let final_state=nft_ruleset();save_proof(&root,"wire-final.json",&final_state);
    assert!(final_state["nftables"].as_array().unwrap().iter().any(|v|v["chain"]["table"]=="wire_v33_inet"&&v["chain"]["name"]=="late_drop"&&v["chain"]["policy"]=="drop"&&v["chain"]["hook"]=="input"&&v["chain"]["prio"]==12));
}

/// Separately verifies the existing Transfer::batch full-chain policy-update
/// shape. It never invokes the already closed V33 packet contract.
#[test]
#[ignore = "V33 fresh chain-update namespace only;explicit marker and NET_ADMIN"]
fn native_chain_update_kernel_fixture() {
    let root=std::path::PathBuf::from(std::env::var("YOFC_NATIVE_CHAIN_UPDATE_V33_ROOT").expect("explicit fresh chain update fixture"));
    assert_eq!(root,std::path::Path::new("/proof"));
    assert_eq!(std::fs::read_to_string(root.join(".owned-native-chain-update-v33")).unwrap(),"fresh V33 chain update namespace;no owner/export/drain\n");
    save_proof(&root,"chain-update-invoked.json",&json!({"scope":"fresh-chain-update-only","noRetry":true}));
    let before=nft_ruleset();
    assert!(before["nftables"].as_array().unwrap().iter().all(|row|row.get("metainfo").is_some()
        ||row.get("table").is_some_and(|v|v["name"]=="retained_v33")
        ||row.get("chain").is_some_and(|v|v["table"]=="retained_v33")
        ||row.get("rule").is_some_and(|v|v["table"]=="retained_v33")));
    let families=["ip","ip6","inet"];
    let mut create=Vec::new();
    for family in families {
        let table=format!("chain_v33_{family}");
        create.push(json!({"create":{"table":{"family":family,"name":table}}}));
        create.push(json!({"add":{"chain":{"family":family,"table":table,"name":"input","type":"filter","hook":"input","prio":17,"policy":"accept"}}}));
    }
    let batch=json!({"expectedGeneration":wire::generation(Instant::now()+std::time::Duration::from_secs(5)).unwrap(),"nftables":create});
    save_proof(&root,"chain-create-batch.json",&batch);dispatch(&batch,Instant::now()+std::time::Duration::from_secs(5)).unwrap();
    let initial=nft_ruleset();save_proof(&root,"chain-created.json",&initial);
    let originals=initial["nftables"].as_array().unwrap().iter().filter_map(|v|v.get("chain"))
        .filter(|v|v["table"].as_str().is_some_and(|s|s.starts_with("chain_v33_"))).cloned().collect::<Vec<_>>();
    assert_eq!(originals.len(),3);
    for policy in ["drop","accept"] {
        let mut commands=Vec::new();
        for original in &originals {
            let mut body=original.clone();body.as_object_mut().unwrap().remove("handle");body["policy"]=json!(policy);
            commands.push(json!({"add":{"chain":body}}));
        }
        let batch=json!({"expectedGeneration":wire::generation(Instant::now()+std::time::Duration::from_secs(5)).unwrap(),"nftables":commands});
        save_proof(&root,&format!("chain-update-{policy}-batch.json"),&batch);
        dispatch(&batch,Instant::now()+std::time::Duration::from_secs(5)).unwrap();
        let current=nft_ruleset();save_proof(&root,&format!("chain-updated-{policy}.json"),&current);
        for original in &originals {
            let matches=current["nftables"].as_array().unwrap().iter().filter_map(|v|v.get("chain"))
                .filter(|v|v["family"]==original["family"]&&v["table"]==original["table"]&&v["name"]==original["name"]).collect::<Vec<_>>();
            assert_eq!(matches.len(),1);let mut expected=original.clone();expected["policy"]=json!(policy);
            assert_eq!(*matches[0],expected,"policy-only update retains every other original chain field including handle");
        }
    }
    save_proof(&root,"chain-update-result.json",&json!({"status":"passed","families":families,"updates":["drop","accept"],"originalHandlesAndAllOtherChainFieldsRetained":true,"packetFixtureReplayed":false}));
}
