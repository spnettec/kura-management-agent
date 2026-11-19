//! Structured Core configuration and retained original layout are separate
//! fields. A v4 configuration is never compiled/applied as a replacement for the
//! original ip/ip6 topology, additional rules or foreign kernel objects.
use super::*;

fn family_policy(layout:&Value,allow_icmp:bool)->Result<Value> {
    let tables=layout["tables"].as_array().context("CONFLICT: imported family tables")?;
    let filters=tables.iter().filter(|t|t["name"]=="filter").collect::<Vec<_>>();
    ensure!(filters.len()==1,"CONFLICT: imported filter table");
    let chains=filters[0]["chains"].as_array().context("CONFLICT: imported filter chains")?;
    let mut result=json!({"allowIcmp":allow_icmp});
    for (chain,field) in [("INPUT","inputPolicy"),("FORWARD","forwardPolicy"),("OUTPUT","outputPolicy")] {
        let matches=chains.iter().filter(|c|c["name"]==chain).collect::<Vec<_>>();
        ensure!(matches.len()==1,"CONFLICT: imported base chain");
        let policy=match matches[0]["policy"].as_str() {
            Some("ACCEPT")=>"accept",Some("DROP")=>"drop",_=>anyhow::bail!("UNSUPPORTED: imported base policy"),
        };
        result[field]=json!(policy);
    }
    Ok(result)
}

fn acknowledged_policy(kernel:&Value,family:&str,allow_icmp:bool)->Result<Value> {
    let entries=kernel["nftables"].as_array().context("CONFLICT: initialized native policy source")?;
    let mut chains=Vec::new();
    for name in ["INPUT","FORWARD","OUTPUT"] {
        let found=entries.iter().filter_map(|v|v.get("chain")).filter(|v|v["family"]==family&&v["table"]=="filter"&&v["name"]==name).collect::<Vec<_>>();
        ensure!(found.len()==1,"CONFLICT: initialized native policy chain");let chain=found[0];
        ensure!(chain["type"]=="filter"&&chain["hook"]==name.to_ascii_lowercase()&&chain["prio"]==0,"CONFLICT: initialized native policy hook");
        let policy=chain["policy"].as_str().filter(|v|["accept","drop"].contains(v)).context("CONFLICT: initialized native policy value")?;
        chains.push(json!({"name":name,"policy":policy.to_ascii_uppercase()}));
    }
    family_policy(&json!({"tables":[{"name":"filter","chains":chains}]}),allow_icmp)
}

// Match the existing Java FirewallValues boundary before returning provider
// data, including retained additional clauses, rather than emitting a response
// which the registered API cannot decode.
fn bounded(value:&Value,depth:usize,budget:&mut usize)->Result<()> {
    ensure!(depth<=24&&*budget>0,"RESOURCE_EXHAUSTED: imported Core view structure");*budget-=1;
    match value {
        Value::Array(values)=>for value in values {bounded(value,depth+1,budget)?;},
        Value::Object(values)=>for value in values.values() {bounded(value,depth+1,budget)?;},
        _=>{},
    }
    Ok(())
}

pub(super) fn view(document:&Document,origin:&roles::Origin,source:&Value)->Result<Value> {
    let rules=origin.model_rules();
    let mut candidate=json!({"schemaVersion":4,"input":rules["input"],"portForward":rules["portForward"],"nat":rules["nat"]});
    let mut families=serde_json::Map::new();
    for family in origin.families() {
        let layout=if source.get("currentLayouts").is_some() {source["currentLayouts"][&family.family]["layout"].clone()}else{crate::firewall::legacy_model_snapshot(&family.expected_ruleset)?};
        candidate[&family.family]=acknowledged_policy(&document.kernel,if family.family=="ipv4"{"ip"}else{"ip6"},family.allow_icmp)?;
        for row in &family.automatic_nat {
            candidate["nat"].as_array_mut().context("CONFLICT: imported structured NAT")?.push(json!({"family":family.family,
                "inputInterface":row.source_interface,"outputInterface":row.destination_interface,"masquerade":row.masquerade,"automatic":true}));
        }
        families.insert(family.family.clone(),json!({"layout":layout,"additionalRules":family.additional_rules,
            "runtimePortForwardDestinationPrefixes":if source.get("currentDestinationPrefixes").is_some(){source["currentDestinationPrefixes"][&family.family].clone()}else{json!(family.runtime_port_forward_destination_prefixes)}}));
    }
    // Grammar validation only. The private inet compiler output is discarded;
    // it is never policy authority, persisted text or an executable update.
    if let Some(current)=source.get("currentPolicy") {candidate=current.clone();}
    crate::firewall::validate_core_projection(&candidate)?;
    let restriction=if !origin.runtime_nat_types_complete(){Some("RUNTIME_NAT_TYPE_UNAVAILABLE")}else if !origin.runtime_forward_prefixes_complete(){Some("RUNTIME_FORWARD_PREFIX_UNAVAILABLE")}else{None};let complete=restriction.is_none();
    let has_current=source.get("currentPolicy").is_some();
    let result=json!({"schemaVersion":1,"revision":source["revision"].as_str().context("CONFLICT: imported current revision")?.parse::<u64>()?,"sourceDigest":source["sourceDigest"],
        "sourceKind":"nft.imported.confirmed.v1","initialized":true,"projectable":complete,"candidate":if complete{candidate}else{Value::Null},
        "readRestriction":restriction,
        "writeEnabled":false,"writeRestriction":"IMPORTED_LAYOUT_UPDATE_UNAVAILABLE","transaction":source["transaction"],"journalSettled":source["journalSettled"],
        "policyScope":"structuredKuraConfiguration","preservedSource":{"operationId":document.operation_id,
            "planSha256":document.plan_sha256,"initializationReceiptSha256":source["initializationReceiptSha256"],
            "originalSourceDigest":document.original_source_digest,"originalFirewallDigest":document.original_firewall_digest,
            "kernelLayoutSha256":source["semanticDigest"],"kernelObservation":source["kernelObservation"].as_str().unwrap_or(if has_current{"confirmedTransactionAcknowledgement"}else{"initializationAcknowledgement"}),
            "layoutSourceKind":if has_current{"nft.imported.current.original-layout.v1"}else{"legacy.writer.model.v1"},
            "policySourceKind":if source["kernelObservation"]=="confirmedBootRestoreAcknowledgement"{"confirmed.boot.native.snapshot"}else if has_current{"confirmed.transaction.native.snapshot"}else{"initialization.native.snapshot"},"families":families}});
    bounded(&result,0,&mut 16384)?;
    ensure!(serde_json::to_vec(&result)?.len()<=LIMIT as usize,"RESOURCE_EXHAUSTED: imported Core view bytes");
    Ok(result)
}

pub(super) fn preview(document:&Document,origin:&roles::Origin,core:&Value,input:&LayoutPreview,current:Option<&native::lineage::CurrentSource>)->Result<Value> {
    ensure!(core["revision"]==input.expected_revision&&core["sourceDigest"]==input.source_digest,"CONFLICT: stale original layout source");
    ensure!(core["projectable"]==true,"UNSUPPORTED: complete runtime projection metadata required");
    let before=&core["candidate"];let mut prefixes=BTreeMap::new();
    for family in origin.families(){prefixes.insert(family.family.clone(),serde_json::from_value(core["preservedSource"]["families"][&family.family]["runtimePortForwardDestinationPrefixes"].clone())?);}
    let original=crate::firewall::original_layout_draft(before,before,&prefixes,&prefixes)?;
    let draft=crate::firewall::original_layout_draft(before,&input.candidate,&prefixes,&input.destination_prefixes)?;let mut compiled=serde_json::Map::new();let mut count=0u64;
    for family in origin.families() {
        let native=if family.family=="ipv4"{"ip"}else{"ip6"};
        let actual=compiled_original_layout(native,&if current.is_some(){core["preservedSource"]["families"][&family.family]["layout"].clone()}else{crate::firewall::legacy_model_snapshot(&family.managed_ruleset)?})?;
        let projected=compiled_original_layout(native,&original["families"][&family.family]["layout"])?;
        ensure!(actual["declarations"]==projected["declarations"]&&actual["groups"]==projected["groups"],"CONFLICT: structured runtime projection does not preserve the original managed layout");
        let next=compiled_original_layout(native,&draft["families"][&family.family]["layout"])?;count+=next["ruleCount"].as_u64().unwrap();compiled.insert(family.family.clone(),next);
    }
    let mut result=json!({"schemaVersion":1,"reviewKind":"nft.imported.layout.preview.v1","revision":core["revision"],"sourceDigest":core["sourceDigest"],
        "operationId":document.operation_id,"initializationReceiptSha256":core["preservedSource"]["initializationReceiptSha256"],
        "candidate":input.candidate,"draft":draft,"compiledLayoutSha256":digest(&json!(compiled))?,"compiledRuleCount":count,
        "kernelObservation":core["preservedSource"]["kernelObservation"],"applyReady":false,"writeEnabled":false,"writeRestriction":"IMPORTED_TRANSACTION_COORDINATOR_UNAVAILABLE"});
    if let Some(operation)=input.operation_id {
        ensure!(operation!=document.operation_id,"CONFLICT: original initialization operation cannot be reused for an update");
        let anchor=core["preservedSource"]["initializationReceiptSha256"].as_str().context("CONFLICT: original initialization receipt")?;
        let current=if let Some(current)=current {current.clone()}else{native::lineage::CurrentSource::from_acknowledged(anchor,document.revision,before.clone(),prefixes,&document.native_transfer,&document.kernel,false)?};
        result["nativePlan"]=current.plan(operation,input.candidate.clone(),input.destination_prefixes.clone())?.parameters()?;
    }
    bounded(&result,0,&mut 16384)?;ensure!(serde_json::to_vec(&result)?.len()<=LIMIT as usize,"RESOURCE_EXHAUSTED: original layout preview");Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_family_policies_are_read_from_original_chains_and_never_defaulted() {
        let source=crate::firewall::legacy_model_snapshot("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n").unwrap();
        assert_eq!(family_policy(&source,false).unwrap(),json!({"inputPolicy":"accept","forwardPolicy":"drop","outputPolicy":"drop","allowIcmp":false}));
        for changed in [json!({"tables":[]}),json!({"tables":[source["tables"][0].clone(),source["tables"][0].clone()]}),
            json!({"tables":[{"name":"filter","chains":[{"name":"INPUT","policy":"ACCEPT"},{"name":"FORWARD","policy":"DROP"}]}]})] {
            assert!(family_policy(&changed,true).is_err());
        }
        let mut missing=source;missing["tables"][0]["chains"][2]["policy"]=Value::Null;assert!(family_policy(&missing,true).is_err());
    }
    #[test]
    fn imported_view_enforces_the_existing_java_depth_and_value_budget() {
        assert!(bounded(&json!([1,2]),0,&mut 3).is_ok());assert!(bounded(&json!([1,2]),0,&mut 2).is_err());
        let mut deep=Value::Null;for _ in 0..25 {deep=json!([deep]);}assert!(bounded(&deep,0,&mut 16384).is_err());
    }
}
