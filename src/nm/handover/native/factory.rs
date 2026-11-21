//! Build original-bound transfers from an authenticated writer model and complete
//! same-generation source. A JSON review supplied by a caller is never authority.
use super::*;

pub(super) fn source_binding(source:&str,model:Option<&str>,original:&Value,rules:&[Rules],policies:&[Policy])->Result<String> {
    let mut binding=json!({"schemaVersion":3,"domain":"nm.ownership.native-source.v1","sourceDigest":source,
        "kernelDigest":Snapshot::read(original)?.digest()?,"rules":rules,"policies":policies});
    if let Some(model)=model {binding["writerModelSha256"]=json!(model);}digest(&binding)
}
pub(super) fn canonical_source(snapshot:&Snapshot)->Value {
    let mut entries=snapshot.objects.clone();
    for rows in snapshot.rules.values() {entries.extend(rows.iter().map(|row|json!({"rule":row})));}
    let fingerprints=snapshot.fingerprints.iter().map(|((chain,handle),sha)|json!({"family":chain.family,"table":chain.table,"chain":chain.name,"handle":handle,"sha256":sha,"payloadHex":snapshot.payloads[&(chain.clone(),*handle)]})).collect::<Vec<_>>();
    json!({"nftables":entries,"ruleFingerprints":fingerprints,"kernelGeneration":snapshot.generation})
}

pub(in crate::nm) struct Reviewed {
    source:String,model:String,original:Value,rules:Vec<Rules>,binding:String,classification:Value,
}
impl Reviewed {
    pub(in crate::nm) fn new(source:&str,origin:&roles::Origin,roles:&roles::Observation,native:&Value)->Result<Self> {
        ensure!(hex(source,64),"CONFLICT: original backend pair source");
        let classification=classify::review_raw(origin,roles,native)?;
        let snapshot=Snapshot::read(native)?;let mut rules=Vec::new();let mut count=0;
        for group in classification["selected"].as_array().context("CONFLICT: complete original selection")? {
            let chain:Chain=serde_json::from_value(group["chain"].clone())?;
            let rows=snapshot.rules.get(&chain).context("CONFLICT: original selected chain missing")?;
            let selected=group["rules"].as_array().context("CONFLICT: original selection parameters")?;
            let mut replacement:Vec<Vec<Value>>=serde_json::from_value(group["replacementExpressions"].clone())?;
            ensure!(!selected.is_empty()&&selected.len()==replacement.len(),"CONFLICT: original model/selection count");
            let mut original=Vec::new();
            for (index,binding) in selected.iter().enumerate() {
                let id=binding["handle"].as_u64().context("CONFLICT: selected original handle")?;
                let ordinal=binding["ordinal"].as_u64().context("CONFLICT: selected original position")? as usize;
                let row=rows.get(ordinal).context("CONFLICT: selected original position disappeared")?;
                let key=(chain.clone(),id);
                ensure!(handle(row)?==id && binding["rawSha256"]==snapshot.fingerprints[&key],"CONFLICT: original raw selection changed");
                let counters=row["expr"].as_array().context("CONFLICT: selected original expressions")?.iter().filter(|e|e.get("counter").is_some()).count();
                for _ in 0..counters {let at=replacement[index].len().checked_sub(1).context("CONFLICT: empty original replacement")?;replacement[index].insert(at,json!({"counter":{"packets":0,"bytes":0}}));}
                ensure!(raw::matcher::model_matches(&snapshot.payloads[&key],&chain.family,&json!(replacement[index]))?,"UNSUPPORTED: original counter conditions cannot be preserved");
                original.push(id);count+=1;
            }
            rules.push(Rules{chain,original,before:None,replacement});
        }
        ensure!(count>0&&count*2<=4096&&rules.len()<=64,"RESOURCE_EXHAUSTED: complete original native transfer bounds");
        let model=classification["writerModelSha256"].as_str().context("CONFLICT: original writer model digest")?.to_string();
        let original=canonical_source(&snapshot);
        ensure!(Snapshot::read(&original)?.digest()?==snapshot.digest()?,"CONFLICT: canonical original source lost evidence");
        let binding=source_binding(source,Some(&model),&original,&rules,&[])?;
        Ok(Self{source:source.into(),model,original,rules,binding,classification})
    }
    pub(in crate::nm) fn binding(&self)->&str {&self.binding}
    pub(in crate::nm) fn parameters(&self)->Value {
        json!({"schemaVersion":1,"sourceKind":"legacy.native.source.v1","sourceDigest":self.binding,
            "classificationDigest":self.classification["classificationDigest"],"writerModelSha256":self.classification["writerModelSha256"],
            "selectedRuleCount":self.classification["selectedRuleCount"],"originalChains":self.rules.len(),
            "preservesOriginalLayout":true,"requiresInitializationTransition":true,"ownerActivationReady":false})
    }
    pub(in crate::nm) fn bind(self,operation_id:uuid::Uuid)->Result<Transfer> {
        let transfer=Transfer{operation_id,source_digest:self.source,source_model_sha256:Some(self.model),original:self.original,rules:self.rules,policies:vec![]};
        transfer.validate()?;ensure!(transfer.source_binding()?==self.binding,"CONFLICT: original native source binding changed");Ok(transfer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rich()->(roles::Observation,roles::Origin,Value) {
        let corpus:Value=serde_json::from_str(include_str!("../../fixtures/rich-raw-corpus-v35.json")).unwrap();
        let exchange=&corpus["exchange"];let roles=roles::Observation::new(uuid::Uuid::new_v4(),71,exchange["roles"].clone()).unwrap();
        let origin=roles::Origin::new(roles.agent_instance,roles.bridge_epoch,&roles,exchange["origin"].clone()).unwrap();(roles,origin,corpus["source"].clone())
    }
    // These digests come from the installed a1f1ebe source, using the same
    // recorded two-family kernel dump and fixed review and operation IDs.
    #[test]
    fn retained_original_matches_the_installed_classification_and_batch() -> Result<()> {
        let corpus: Value = serde_json::from_str(include_str!("../../fixtures/rich-raw-corpus-v35.json"))?;
        let exchange = &corpus["exchange"];
        let kernel = &corpus["source"];
        let instance = uuid::Uuid::from_u128(0x421);
        let roles = roles::Observation::new(instance, 71, exchange["roles"].clone())?;
        let origin = roles::Origin::new(instance, 71, &roles, exchange["origin"].clone())?;
        let reviewed = Reviewed::new(&"a".repeat(64), &origin, &roles, kernel)?;
        assert_eq!(digest(&reviewed.classification)?, "c006c0282ce965d67d07b0e6cb7ff1b6920d64759b8ad7cad206d2ffcb1726bb");
        let transfer = reviewed.bind(uuid::Uuid::from_u128(0x852))?;
        assert_eq!(digest(&serde_json::to_value(&transfer)?)?, "b81c8704099bc659585bad01849cf2706c0ab90fb8206f85da56fadb4206c466");
        let (bytes, _) = raw::writer::encode(&transfer.batch(kernel, false)?)?;
        assert_eq!(durable::hash(&bytes), "e61ce08d67df018c8b3c70bf8d47cc7b7cc3a4317522d82c592fc0a0d4835d13");
        Ok(())
    }
    #[test]
    fn original_factory_binds_complete_model_and_counter_conditions_to_the_given_operation() {
        let (roles,origin,native)=rich();let source="a".repeat(64);let first=Reviewed::new(&source,&origin,&roles,&native).unwrap();let binding=first.binding().to_string();
        assert_eq!(first.parameters()["selectedRuleCount"],144);assert_eq!(first.parameters()["ownerActivationReady"],false);
        let a=uuid::Uuid::new_v4();let b=uuid::Uuid::new_v4();let first=first.bind(a).unwrap();let second=Reviewed::new(&source,&origin,&roles,&native).unwrap().bind(b).unwrap();
        assert_eq!(first.source_binding().unwrap(),binding);assert_eq!(second.source_binding().unwrap(),binding);
        assert_eq!(first.operation_id,a);assert_eq!(second.operation_id,b);assert_eq!(Snapshot::read(&first.original).unwrap().digest().unwrap(),Snapshot::read(&native).unwrap().digest().unwrap());
        let batch=first.batch(&native,false).unwrap();let commands=batch["nftables"].as_array().unwrap();
        assert_eq!(commands.iter().filter(|v|v.get("replace").is_some()).count(),144);assert_eq!(commands.len(),145);
        assert!(commands.iter().all(|v|v.get("flush").is_none()&&v.get("delete").is_none()));
        assert!(first.rules.iter().flat_map(|g|&g.replacement).all(|e|e.iter().any(|v|v.get("counter").is_some())));
        assert_ne!(first.replacement(0,0).unwrap()["comment"],second.replacement(0,0).unwrap()["comment"]);
        let mut changed=origin.parameters().unwrap();changed["families"][0]["instanceId"]=json!(uuid::Uuid::new_v4());
        let changed=roles::Origin::new(roles.agent_instance,roles.bridge_epoch,&roles,changed).unwrap();
        assert_ne!(Reviewed::new(&source,&changed,&roles,&native).unwrap().binding(),binding,"writer identity must stay bound even if all traffic predicates are unchanged");
        assert!(first.policies.is_empty(),"the actual original policies remain in the source,not a flattened preview");
        let mut traffic=native.clone();for row in traffic["nftables"].as_array_mut().unwrap() {if let Some(rule)=row.get_mut("rule") {for e in rule["expr"].as_array_mut().unwrap() {if let Some(c)=e.get_mut("counter"){c["packets"]=json!(999);c["bytes"]=json!(9999);}}}}
        let moving=Reviewed::new(&source,&origin,&roles,&traffic).unwrap().bind(a).unwrap();assert_eq!(serde_json::to_value(&moving).unwrap(),serde_json::to_value(&first).unwrap(),"traffic alone must not invalidate the original baseline after export");
    }
    #[test]
    fn original_factory_refuses_missing_foreign_parameters_wrong_registration_and_existing_operation_receipt() {
        let (roles,origin,native)=rich();let mut missing=native.clone();missing["ruleFingerprints"][0].as_object_mut().unwrap().remove("payloadHex");
        assert!(Reviewed::new(&"a".repeat(64),&origin,&roles,&missing).is_err());
        let mut wrong=roles.clone();wrong.agent_instance=uuid::Uuid::new_v4();assert!(Reviewed::new(&"a".repeat(64),&origin,&wrong,&native).is_err());
        assert!(Reviewed::new("caller text",&origin,&roles,&native).is_err());
        assert!(Reviewed::new(&"a".repeat(64),&origin,&roles,&native).unwrap().bind(uuid::Uuid::nil()).is_err());
        let id=uuid::Uuid::new_v4();let mut collision=native.clone();collision["nftables"].as_array_mut().unwrap().push(json!({"table":{"family":"inet","name":format!("yofc_fwt_{}",id.simple()),"handle":999}}));
        assert!(Reviewed::new(&"a".repeat(64),&origin,&roles,&collision).unwrap().bind(id).is_err());
    }
    #[test]
    fn retained_v36_transfer_receipt_and_batch_identity_survive_the_optional_writer_binding() {
        let corpus:Value=serde_json::from_str(include_str!("../../fixtures/native-transfer-v36-identity.json")).unwrap();
        let original:Transfer=serde_json::from_value(corpus["transfer"].clone()).unwrap();assert!(original.source_model_sha256.is_none());
        assert_eq!(serde_json::to_value(&original).unwrap(),corpus["transfer"]);
        assert_eq!(original.receipt(false).unwrap(),corpus["receipt"]);
        assert_eq!(digest(&original.batch(&original.original,false).unwrap()).unwrap(),corpus["batchCanonicalSha256"].as_str().unwrap(),"existing original plans must never gain a new identity or need redispatch");
    }
}
