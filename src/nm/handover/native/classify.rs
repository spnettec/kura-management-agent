//! Read-only classification of authenticated model intent against a complete
//! compatibility view and the same-generation raw/native observation. It does
//! not manufacture a transfer,owner lease or initialized private firewall.
use super::*;
#[cfg(test)]
mod model;

use kura_firewall_policy::{Layout as View, compile_clause};
#[cfg(test)]
use kura_firewall_policy::{Declaration, Row, Table, canonical_clause as canonical};

/// Pure original-chain compiler and wire preflight. No kernel observation,
/// source adoption or dispatch. Policy values are checked separately against
/// their acknowledged native base chains, not renderer defaults.
pub(in crate::nm) fn compiled_layout(family:&str,layout:&Value)->Result<Value> {
    let view: View = serde_json::from_value(layout.clone())?;
    let compiled = kura_firewall_policy::compile_layout(family, &view)?;
    let mut declarations = Vec::new();
    let mut groups = Vec::new();
    let mut commands = Vec::new();
    for table in compiled {
        declarations.push(json!({"name":table.name,"chains":table.chains.iter().map(|c|
            json!({"name":c.name,"base":c.policy.is_some()})).collect::<Vec<_>>()}));
        for chain in table.chains {
            for expr in &chain.rules {
                commands.push(json!({"add":{"rule":{"family":family,"table":table.name,"chain":chain.name,"expr":expr}}}));
            }
            if !chain.rules.is_empty() {
                groups.push(json!({"chain":{"family":family,"table":table.name,"name":chain.name},"expressions":chain.rules}));
            }
        }
    }
    let (bytes,_)=raw::writer::encode(&json!({"expectedGeneration":1,"nftables":commands}))?;
    Ok(json!({"schemaVersion":1,"declarations":declarations,"groups":groups,"ruleCount":commands.len(),"wirePreflightBytes":bytes.len(),"dispatched":false}))
}

#[cfg(test)]
fn selected(expected:&[&Row],actual:&[&Row])->Result<Vec<usize>> {
    let expected=expected.iter().map(|v|canonical(&v.specification)).collect::<Result<Vec<_>>>()?;
    let actual=actual.iter().map(|v|canonical(&v.specification).ok()).collect::<Vec<_>>();
    unique_selection(&expected,&actual)
}
fn unique_selection<T:PartialEq>(expected:&[T],actual:&[Option<T>])->Result<Vec<usize>> {
    let m=expected.len();let n=actual.len();
    ensure!((m+1).checked_mul(n+1).is_some_and(|v|v<=1_048_576),"RESOURCE_EXHAUSTED: model matching scope");
    let mut ways=vec![0u8;(m+1)*(n+1)];for cell in &mut ways[..=n] {*cell=1;}
    for i in 1..=m {for j in 1..=n {
        ways[i*(n+1)+j]=(ways[i*(n+1)+j-1]+if actual[j-1].as_ref()==Some(&expected[i-1]){ways[(i-1)*(n+1)+j-1]}else{0}).min(2);
    }}
    ensure!(ways[m*(n+1)+n]==1,"CONFLICT: managed model rules missing,reordered or ambiguous");
    let (mut i,mut j)=(m,n);let mut result=Vec::with_capacity(m);
    while i>0 {
        ensure!(j>0,"CONFLICT: model match reconstruction");
        if actual[j-1].as_ref()==Some(&expected[i-1])&&ways[(i-1)*(n+1)+j-1]>0 {
            result.push(j-1);i-=1;
        }
        j-=1;
    }
    result.reverse();Ok(result)
}

pub(in crate::nm) fn kernel_digest(value:&Value)->Result<String> {
    let source=Snapshot::read(value)?;ensure!(source.generation.is_some(),"UNSUPPORTED: original raw kernel generation required");source.digest()
}

#[cfg(test)]
pub(in crate::nm) fn review(origin:&roles::Origin,observed:&roles::Observation,legacy:&Value,native:&Value)->Result<Value> {
    origin.require(observed)?;
    ensure!(legacy["schemaVersion"]==1&&legacy["sourceKind"]=="iptables.current.unowned.v1"
        &&legacy["snapshotSha256"]==digest(&legacy["snapshot"])?,"CONFLICT: complete legacy source binding");
    let raw=Snapshot::read(native)?;let generation=raw.generation.context("UNSUPPORTED: same-generation raw kernel source required")?;
    let mut groups=Vec::new();let mut chosen=BTreeSet::new();let mut candidate=origin.model_rules().clone();candidate["schemaVersion"]=json!(4);
    for (index,model) in origin.families().iter().enumerate() {
        let family=if index==0{"ip"}else{"ip6"};let label=if index==0{"ipv4"}else{"ipv6"};
        let managed:View=serde_json::from_value(crate::firewall::legacy_model_snapshot(&model.managed_ruleset)?)?;
        let actual:View=serde_json::from_value(legacy["snapshot"][label].clone())?;
        let mut policies=BTreeMap::new();
        for table in &managed.tables {
            let current=actual.tables.iter().find(|v|v.name==table.name).context("CONFLICT: original model table missing")?;
            // The compatibility view must enumerate every native rule in every
            // corresponding chain. A partial xtables view cannot map ordinals.
            let native_chains=raw.objects.iter().filter_map(|v|v.get("chain"))
                .filter(|v|v["family"]==family&&v["table"]==table.name).collect::<Vec<_>>();
            ensure!(native_chains.len()==current.chains.len(),"UNSUPPORTED: partial legacy chain view");
            for declaration in &current.chains {
                let chain=Chain{family:family.into(),table:table.name.clone(),name:declaration.name.clone()};
                let body=raw.find_chain(&chain)?;let rows=current.rules.iter().filter(|v|v.chain==declaration.name).collect::<Vec<_>>();
                ensure!(rows.len()==raw.rules.get(&chain).map_or(0,Vec::len),"UNSUPPORTED: partial legacy rule view");
                ensure!(match &declaration.policy {Some(policy)=>body["policy"]==policy.to_ascii_lowercase(),None=>body.get("policy").is_none()&&body.get("hook").is_none()},
                    "CONFLICT: legacy/native chain policy disagreement");
            }
            for declaration in &table.chains {
                let current_declaration=current.chains.iter().find(|v|v.name==declaration.name).context("CONFLICT: managed chain missing")?;
                let chain=Chain{family:family.into(),table:table.name.clone(),name:declaration.name.clone()};
                let body=raw.find_chain(&chain)?;
                if table.name=="filter"&&["INPUT","FORWARD","OUTPUT"].contains(&declaration.name.as_str()) {
                    let policy=current_declaration.policy.as_ref().context("CONFLICT: original base policy absent")?.to_ascii_lowercase();
                    let hook=declaration.name.to_ascii_lowercase();
                    ensure!(body["type"]=="filter"&&body["hook"]==hook&&body["prio"]==0,"CONFLICT: original base hook binding");
                    policies.insert(format!("{}Policy",hook),json!(policy));
                }else{ensure!(declaration.policy.is_some()==current_declaration.policy.is_some(),"CONFLICT: original model chain kind");}
                let expected=table.rules.iter().filter(|v|v.chain==declaration.name).collect::<Vec<_>>();
                let rows=current.rules.iter().filter(|v|v.chain==declaration.name).collect::<Vec<_>>();
                if expected.is_empty(){continue;}
                let indices=selected(&expected,&rows)?;let native_rows=raw.rules.get(&chain).context("CONFLICT: missing original native rows")?;
                  let replacements=expected.iter().map(|row|compile_clause(family,table,&row.specification)).collect::<Result<Vec<_>>>()?;
                  for expr in &replacements {raw::writer::encode(&json!({"expectedGeneration":generation,"nftables":[{"add":{"rule":{"family":family,"table":table.name,"chain":declaration.name,"expr":expr}}}]}))?;}
                let mut matches=Vec::new();
                for ordinal in indices {
                    let row=&native_rows[ordinal];let handle=handle(row)?;let key=(chain.clone(),handle);
                    ensure!(chosen.insert(key.clone()),"CONFLICT: duplicate model selection");
                    matches.push(json!({"handle":handle,"ordinal":ordinal,"rawSha256":raw.fingerprints[&key]}));
                }
                  ensure!(matches.len()==replacements.len(),"CONFLICT: original model compilation cardinality");
                  groups.push(json!({"chain":chain,"rules":matches,"replacementExpressions":replacements}));
            }
        }
        ensure!(policies.len()==3,"CONFLICT: complete original family policies");policies.insert("allowIcmp".into(),json!(model.allow_icmp));
        candidate[label]=serde_json::to_value(policies)?;
        for automatic in &model.automatic_nat {
            candidate["nat"].as_array_mut().context("CONFLICT: original model NAT list")?.push(json!({
                "family":label,"inputInterface":automatic.source_interface,"outputInterface":automatic.destination_interface,
                "protocol":null,"masquerade":automatic.masquerade,"automatic":true}));
        }
    }
    let policy_digest=crate::firewall::legacy_import_policy_digest(candidate.clone())?;
      let binding=digest(&json!({"domain":"legacy.writer.native.classification.v2","origin":origin,"legacy":legacy["snapshot"],"native":kernel_digest(native)?,"selected":groups,"candidate":candidate}))?;
      Ok(json!({"schemaVersion":2,"reviewKind":"legacy.writer.native.classification.v2","classificationDigest":binding,
        "kernelGeneration":generation,"nativeKernelDigest":raw.digest()?,"writerModelSha256":digest(&origin.parameters()?)?,
          "selected":groups,"selectedRuleCount":chosen.len(),"compiledManagedRuleCount":chosen.len(),"unselectedRuleCount":raw.fingerprints.len()-chosen.len(),
        "candidate":candidate,"candidateRulesetSha256":policy_digest,"nativePlanProduced":false,"preparationReady":false,
          "scope":"complete xtables compatibility view plus same-generation raw/native source;bounded model compilation preserves original chains;foreign objects remain in place"}))
}

/// Complete raw/native review. Unsupported foreign rows are retained in the
/// source binding and never converted into a partial compatibility snapshot.
pub(in crate::nm) fn review_raw(origin:&roles::Origin,observed:&roles::Observation,native:&Value)->Result<Value> {
    origin.require(observed)?;let raw=Snapshot::read(native)?;
    let generation=raw.generation.context("UNSUPPORTED: same-generation raw kernel source required")?;
    ensure!(raw.payloads.len()==raw.fingerprints.len(),"UNSUPPORTED: complete original raw parameters required");
    let mut groups=Vec::new();let mut chosen=BTreeSet::new();let mut opaque=BTreeSet::new();
    let mut candidate=origin.model_rules().clone();candidate["schemaVersion"]=json!(4);
    for (index,model) in origin.families().iter().enumerate() {
        let family=if index==0{"ip"}else{"ip6"};let label=if index==0{"ipv4"}else{"ipv6"};
        let managed:View=serde_json::from_value(crate::firewall::legacy_model_snapshot(&model.managed_ruleset)?)?;
        let mut policies=BTreeMap::new();
        for table in &managed.tables {for declaration in &table.chains {
            let chain=Chain{family:family.into(),table:table.name.clone(),name:declaration.name.clone()};let body=raw.find_chain(&chain)?;
            if declaration.policy.is_some() {
                ensure!(["accept","drop"].iter().any(|p|body["policy"]==*p)&&body["hook"].is_string()&&body["type"].is_string()&&body["prio"].as_i64().is_some(),"CONFLICT: original native base chain binding");
            }else{ensure!(body.get("policy").is_none()&&body.get("hook").is_none(),"CONFLICT: original native regular chain binding");}
            if table.name=="filter"&&["INPUT","FORWARD","OUTPUT"].contains(&declaration.name.as_str()) {
                let hook=declaration.name.to_ascii_lowercase();ensure!(body["type"]=="filter"&&body["hook"]==hook&&body["prio"]==0,"CONFLICT: original filter hook binding");
                policies.insert(format!("{hook}Policy"),body["policy"].clone());
            }
            let expected=table.rules.iter().filter(|v|v.chain==declaration.name).collect::<Vec<_>>();if expected.is_empty(){continue;}
            let replacements=expected.iter().map(|row|compile_clause(family,table,&row.specification)).collect::<Result<Vec<_>>>()?;
            let signatures=replacements.iter().map(|expr|raw::matcher::expected(family,&json!(expr))).collect::<Result<Vec<_>>>()?;
            let rows=raw.rules.get(&chain).context("CONFLICT: missing native model rows")?;
            let actual=rows.iter().map(|row| {let id=handle(row)?;let key=(chain.clone(),id);let value=raw::matcher::observed(raw.payloads.get(&key).context("CONFLICT: original raw parameters missing")?);if value.is_none(){opaque.insert(key);}Ok(value)}).collect::<Result<Vec<_>>>()?;
            let indices=unique_selection(&signatures,&actual).with_context(||format!("CONFLICT: native model source in {family} {} {}",table.name,declaration.name))?;let mut bindings=Vec::new();
            for ordinal in indices {let id=handle(&rows[ordinal])?;let key=(chain.clone(),id);ensure!(chosen.insert(key.clone()),"CONFLICT: duplicate native model selection");bindings.push(json!({"handle":id,"ordinal":ordinal,"rawSha256":raw.fingerprints[&key]}));}
            groups.push(json!({"chain":chain,"rules":bindings,"replacementExpressions":replacements}));
        }}
        ensure!(policies.len()==3,"CONFLICT: complete native family policies");policies.insert("allowIcmp".into(),json!(model.allow_icmp));candidate[label]=json!(policies);
        for automatic in &model.automatic_nat {candidate["nat"].as_array_mut().context("CONFLICT: original NAT list")?.push(json!({"family":label,"inputInterface":automatic.source_interface,"outputInterface":automatic.destination_interface,"protocol":null,"masquerade":automatic.masquerade,"automatic":true}));}
    }
    ensure!(!chosen.is_empty(),"CONFLICT: empty original native model selection");
    let policy_digest=crate::firewall::legacy_import_policy_digest(candidate.clone())?;
    let binding=digest(&json!({"domain":"legacy.writer.raw.classification.v1","origin":origin,"native":kernel_digest(native)?,"selected":groups,"candidate":candidate}))?;
    Ok(json!({"schemaVersion":1,"reviewKind":"legacy.writer.raw.classification.v1","classificationDigest":binding,"kernelGeneration":generation,"nativeKernelDigest":raw.digest()?,"writerModelSha256":digest(&origin.parameters()?)?,"selected":groups,"selectedRuleCount":chosen.len(),"unselectedRuleCount":raw.fingerprints.len()-chosen.len(),"opaqueRuleCountInModelChains":opaque.len(),"compiledManagedRuleCount":chosen.len(),"candidate":candidate,"candidateRulesetSha256":policy_digest,"nativePlanProduced":false,"preparationReady":false,"scope":"complete same-generation raw/native source;bounded pure model matching;all unselected foreign objects retained;no compatibility projection"}))
}

#[cfg(test)]
pub(in crate::nm) fn raw_fixture()->Value {serde_json::from_str::<Value>(include_str!("../../fixtures/legacy-raw-corpus-v35.json")).unwrap()["source"].clone()}
#[cfg(test)]
pub(super) fn compiled_fixture()->Vec<(Chain,Vec<Vec<Value>>)> {compiled_origin(&fixture().1)}
#[cfg(test)]
pub(super) fn compiled_origin(origin:&roles::Origin)->Vec<(Chain,Vec<Vec<Value>>)> {
    let mut result=Vec::new();
    for (index,family) in origin.families().iter().enumerate() {
        let name=if index==0{"ip"}else{"ip6"};
        let view:View=serde_json::from_value(crate::firewall::legacy_model_snapshot(&family.managed_ruleset).unwrap()).unwrap();
        for table in view.tables {for chain in &table.chains {
            let rows=table.rules.iter().filter(|r|r.chain==chain.name).map(|r|compile_clause(name,&table,&r.specification).unwrap()).collect::<Vec<_>>();
            if !rows.is_empty() {result.push((Chain{family:name.into(),table:table.name.clone(),name:chain.name.clone()},rows));}
        }}
    }
    result
}
#[cfg(test)]
pub(in crate::nm) fn fixture()->(roles::Observation,roles::Origin,Value,Value) {
    let exchange:Value=serde_json::from_str(include_str!("../../fixtures/legacy-origin-v32.json")).unwrap();
    let observed=roles::Observation::new(uuid::Uuid::new_v4(),31,exchange["roles"].clone()).unwrap();
    let origin=roles::Origin::new(observed.agent_instance,observed.bridge_epoch,&observed,exchange["origin"].clone()).unwrap();
    let mut views=serde_json::Map::new();let mut entries=Vec::new();let mut fingerprints=Vec::new();
    let mut next=1u64;
    for (index,model) in origin.families().iter().enumerate() {
        let family=if index==0{"ip"}else{"ip6"};let label=if index==0{"ipv4"}else{"ipv6"};
        let view=crate::firewall::legacy_model_snapshot(&model.expected_ruleset).unwrap();
        let typed:View=serde_json::from_value(view.clone()).unwrap();views.insert(label.into(),view);
        for table in typed.tables {
            entries.push(json!({"table":{"family":family,"name":table.name,"handle":next}}));next+=1;
            for chain in table.chains {
                let mut body=json!({"family":family,"table":table.name,"name":chain.name,"handle":next});next+=1;
                if let Some(policy)=chain.policy {body["policy"]=json!(policy.to_ascii_lowercase());body["type"]=json!(if table.name=="nat"{"nat"}else{"filter"});body["hook"]=json!(chain.name.to_ascii_lowercase());body["prio"]=json!(0);}
                entries.push(json!({"chain":body}));
            }
            for row in table.rules {
                // Synthetic wire shape for source-binding unit tests only;the
                // Linux compatibility contract checks the actual kernel views.
                entries.push(json!({"rule":{"family":family,"table":table.name,"chain":row.chain,"handle":next,"expr":[{"accept":null}]}}));
                fingerprints.push(json!({"family":family,"table":table.name,"chain":row.chain,"handle":next,"sha256":durable::hash(row.specification.as_bytes())}));next+=1;
            }
        }
    }
    let snapshot=Value::Object(views);let legacy=json!({"schemaVersion":1,"sourceKind":"iptables.current.unowned.v1","snapshotSha256":digest(&snapshot).unwrap(),"snapshot":snapshot});
    let native=json!({"nftables":entries,"ruleFingerprints":fingerprints,"kernelGeneration":57});
    (observed,origin,legacy,native)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn raw_corpus()->Value {serde_json::from_str(include_str!("../../fixtures/legacy-raw-corpus-v35.json")).unwrap()}
    #[test]
    fn complete_raw_review_selects_original_handles_without_a_compatibility_projection() {
        let (observed,origin,_,_)=fixture();let corpus=raw_corpus();let native=&corpus["source"];
        let result=review_raw(&origin,&observed,native).unwrap();
        assert_eq!(result["selectedRuleCount"],116);assert_eq!(result["unselectedRuleCount"],4);
        assert_eq!(result["preparationReady"],false);assert_eq!(result["nativePlanProduced"],false);
        for old in corpus["classification"]["selected"].as_array().unwrap() {
            let current=result["selected"].as_array().unwrap().iter().find(|v|v["chain"]==old["chain"]).unwrap();assert_eq!(current["rules"],old["rules"]);
        }
        assert_eq!(result["nativeKernelDigest"],Snapshot::read(native).unwrap().digest().unwrap());
        assert_eq!(result["candidate"]["ipv4"]["outputPolicy"],"drop");
    }
    #[test]
    fn complete_raw_review_refuses_a_missing_foreign_parameter_witness_or_model_reordering() {
        let (observed,origin,_,_)=fixture();let native=raw_corpus()["source"].clone();let mut missing=native.clone();
        missing["ruleFingerprints"][0].as_object_mut().unwrap().remove("payloadHex");assert!(review_raw(&origin,&observed,&missing).is_err());
        let mut reordered=native;let entries=reordered["nftables"].as_array_mut().unwrap();let index=entries.iter().position(|v|v["rule"]["family"]=="ip"&&v["rule"]["table"]=="filter"&&v["rule"]["chain"]=="input-kura"&&v["rule"]["handle"]==14).unwrap();
        entries.swap(index,index+1);assert!(review_raw(&origin,&observed,&reordered).is_err());
    }
    #[test]
    #[ignore="V35 fresh raw-only namespace with new rich Java renderer fixture;explicit marker;never replay"]
    fn raw_native_only_kernel_fixture() {
        use std::{fs,io::Write,path::Path,time::Duration};
        let root=std::path::PathBuf::from(std::env::var("YOFC_NATIVE_RAW_V35_ROOT").expect("new explicit raw-native fixture required"));assert_eq!(root,Path::new("/proof"));
        assert_eq!(fs::read_to_string(root.join(".owned-native-raw-v35")).unwrap(),"fresh V35 raw-only review;no owner/export/drain\n");
        let save=|name:&str,value:&Value|{let mut f=fs::OpenOptions::new().write(true).create_new(true).open(root.join(name)).unwrap();f.write_all(&serde_json::to_vec_pretty(value).unwrap()).unwrap();f.sync_all().unwrap();};
        save("raw-review-invoked.json",&json!({"scope":"fresh rich model/raw-native only","noReplay":true}));
        let exchange:Value=serde_json::from_slice(&fs::read(root.join("java-origin-bridge.json")).unwrap()).unwrap();
        let observed=roles::Observation::new(uuid::Uuid::new_v4(),71,exchange["roles"].clone()).unwrap();let origin=roles::Origin::new(observed.agent_instance,observed.bridge_epoch,&observed,exchange["origin"].clone()).unwrap();
        let nft=||{let output=std::process::Command::new("/usr/sbin/nft").args(["-j","-p","list","ruleset"]).output().unwrap();assert!(output.status.success());Ok(serde_json::from_slice::<Value>(&output.stdout).unwrap())};
        let native=raw::observe(nft,std::time::Instant::now()+Duration::from_secs(10)).unwrap();save("raw-native-source.json",&native);
        let report=review_raw(&origin,&observed,&native).unwrap();save("raw-classification.json",&report);
        let expected=origin.families().iter().map(|f| {let view:View=serde_json::from_value(crate::firewall::legacy_model_snapshot(&f.managed_ruleset).unwrap()).unwrap();view.tables.iter().map(|t|t.rules.len()).sum::<usize>()}).sum::<usize>();
        assert_eq!(report["selectedRuleCount"],expected);assert_eq!(report["unselectedRuleCount"],2);assert_eq!(report["opaqueRuleCountInModelChains"],2);assert_eq!(report["nativePlanProduced"],false);assert_eq!(report["preparationReady"],false);
        let after=raw::observe(nft,std::time::Instant::now()+Duration::from_secs(10)).unwrap();save("raw-native-after.json",&after);assert_eq!(kernel_digest(&native).unwrap(),kernel_digest(&after).unwrap());
        save("raw-review-result.json",&json!({"status":"passed","selectedRuleCount":expected,"unselectedRuleCount":2,"opaqueNativeForeignCount":2,"readOnlyKernelDigestUnchanged":true,"compatibilityViewUsed":false,"syntheticRegistration":true,"actualJvmOrDrainAccepted":false,"preparationReady":false,"nativePlanProduced":false}));
    }
    #[test]
    #[ignore="fresh V32 Linux namespace with the actual Java producer model;read-only classification only;never replay a retained invocation"]
    fn legacy_origin_kernel_fixture() {
        let root=PathBuf::from(std::env::var("YOFC_LEGACY_SOURCE_V32_ROOT").unwrap());assert!(root.join(".owned-origin-v32").is_file());
        durable::publish_new(&root.join("invoked-classifier"),b"original V32 classifier invocation",FileMetadata::private()).unwrap();
        let exchange:Value=serde_json::from_slice(&durable::read(&root.join("java-origin-bridge.json"),128*1024).unwrap().0).unwrap();
        let observed=roles::Observation::new(uuid::Uuid::new_v4(),32,exchange["roles"].clone()).unwrap();
        let origin=roles::Origin::new(observed.agent_instance,observed.bridge_epoch,&observed,exchange["origin"].clone()).unwrap();
        let deadline=std::time::Instant::now()+std::time::Duration::from_secs(40);
        let read=||raw::observe(||{
            let out=crate::process::run(Path::new("/usr/sbin/nft"),&["-j","-p","list","ruleset"],None,std::time::Duration::from_secs(10))?;
            ensure!(out.status.success(),"nft source failed");Ok(serde_json::from_slice(&out.stdout)?)
        },deadline);
        let before=read().unwrap();let legacy=crate::firewall::observe_legacy_kernel(deadline).unwrap();let after=read().unwrap();
        assert_eq!(kernel_digest(&before).unwrap(),kernel_digest(&after).unwrap());
        let report=review(&origin,&observed,&legacy,&after).unwrap();
        assert_eq!(report["candidate"]["ipv4"]["outputPolicy"],"drop");assert_eq!(report["candidate"]["nat"][0]["masquerade"],false);
        assert_eq!(report["unselectedRuleCount"],4);assert_eq!(report["preparationReady"],false);assert_eq!(report["nativePlanProduced"],false);
        for (name,value) in [("classification.json",report),("native-source.json",after),("legacy-source.json",legacy)] {
            durable::publish_new(&root.join(name),&serde_json::to_vec(&value).unwrap(),FileMetadata::private()).unwrap();
        }
    }
    #[test]
    fn actual_java_model_maps_exact_handles_but_never_creates_a_plan_or_owner() {
        let (observed,origin,legacy,native)=fixture();let report=review(&origin,&observed,&legacy,&native).unwrap();
        assert_eq!(report["candidate"]["ipv4"]["allowIcmp"],false);assert_eq!(report["candidate"]["ipv6"]["allowIcmp"],true);
        assert_eq!(report["candidate"]["ipv4"]["outputPolicy"],"accept");assert_eq!(report["candidate"]["nat"][0]["masquerade"],false);
        assert_eq!(report["candidate"]["nat"][0]["automatic"],true);assert_eq!(report["candidate"]["input"].as_array().unwrap().len(),2);
        assert_eq!(report["unselectedRuleCount"],3);assert!(report["selectedRuleCount"].as_u64().unwrap()>100);
        assert_eq!(report["preparationReady"],false);assert_eq!(report["nativePlanProduced"],false);
        assert_ne!(origin.model_rules(),origin.stored(&observed).unwrap().rules());
        let mut drift=native.clone();drift["kernelGeneration"]=json!(58);assert_ne!(kernel_digest(&native).unwrap(),kernel_digest(&drift).unwrap());
    }
    #[test]
    fn only_known_equivalent_predicates_normalize_and_unknown_parameters_never_disappear() {
        assert_eq!(canonical("-p tcp -s 0.0.0.0/0 -i eth0 --dport 5400 -j ACCEPT").unwrap(),canonical("-i eth0 -p 6 -m tcp --destination-port 5400:5400 -j ACCEPT").unwrap());
        assert_eq!(canonical("-m state --state RELATED,ESTABLISHED -j ACCEPT").unwrap(),canonical("-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT").unwrap());
        assert_eq!(canonical("-s 2001:0db8::1/64 -j ACCEPT").unwrap(),canonical("-s 2001:db8::/64 -j ACCEPT").unwrap());
        assert_ne!(canonical("! -i eth0 -j ACCEPT").unwrap(),canonical("-i eth0 -j ACCEPT").unwrap());
        assert_ne!(canonical("-p icmp --icmp-type 8 -j DROP").unwrap(),canonical("-p icmp --icmp-type 0 -j DROP").unwrap());
        for text in ["-p tcp --dport 5400 -m comment --comment claimed -j ACCEPT","-m tcp -j ACCEPT","-i eth0 -i eth0 -j ACCEPT","-m limit --limit 1/sec -j ACCEPT"] {assert!(canonical(text).is_err(),"{text}");}
    }
    #[test]
    fn missing_reordered_or_ambiguous_rows_cannot_claim_familiar_chains() {
        let row=|s:&str|Row{chain:"input-kura".into(),specification:s.into()};
        let first=row("-p tcp --dport 5400 -j ACCEPT");let last=row("-j RETURN");let opaque=row("-m comment --comment foreign -j RETURN");
        assert_eq!(selected(&[&first,&last],&[&opaque,&first,&last]).unwrap(),vec![1,2]);
        for actual in [vec![&last,&first],vec![&first,&first,&last],vec![&first,&last,&last],vec![&opaque,&last]] {assert!(selected(&[&first,&last],&actual).is_err());}
    }
    #[test]
    fn partial_views_and_policy_disagreement_are_rejected_while_actual_policy_is_preserved() {
        let (observed,origin,mut legacy,mut native)=fixture();
        let index=native["nftables"].as_array().unwrap().iter().position(|v|v["chain"]["family"]=="ip"&&v["chain"]["table"]=="filter"&&v["chain"]["name"]=="OUTPUT").unwrap();
        native["nftables"][index]["chain"]["policy"]=json!("drop");assert!(review(&origin,&observed,&legacy,&native).is_err());
        legacy["snapshot"]["ipv4"]["tables"][0]["chains"][2]["policy"]=json!("DROP");legacy["snapshotSha256"]=json!(digest(&legacy["snapshot"]).unwrap());
        assert_eq!(review(&origin,&observed,&legacy,&native).unwrap()["candidate"]["ipv4"]["outputPolicy"],"drop");
        legacy["snapshot"]["ipv4"]["tables"][0]["rules"].as_array_mut().unwrap().remove(0);legacy["snapshotSha256"]=json!(digest(&legacy["snapshot"]).unwrap());assert!(review(&origin,&observed,&legacy,&native).is_err());
    }
}
