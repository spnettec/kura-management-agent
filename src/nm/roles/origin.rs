//! Exact registered legacy writer inputs. This is model intent,not kernel or
//! ownership authority;the source classifier still binds complete raw kernel data.
use super::*;

#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(crate) struct Origin {agent_instance:uuid::Uuid,bridge_epoch:u64,source:Model}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct Model {schema_version:u8,source_kind:String,network_revision:String,kernel_observed:bool,stored_firewall:Value,
    families:[Family;2],model_rules:Value}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(in crate::nm) struct Family {
    pub(in crate::nm) family:String,pub(in crate::nm) instance_id:uuid::Uuid,pub(in crate::nm) allow_icmp:bool,
    pub(in crate::nm) expected_ruleset:String,pub(in crate::nm) managed_ruleset:String,
    pub(in crate::nm) model_properties:BTreeMap<String,String>,pub(in crate::nm) automatic_nat:Vec<Automatic>,
    pub(in crate::nm) additional_rules:BTreeMap<String,Vec<String>>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(in crate::nm) runtime_nat_rule_types:Option<Vec<String>>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(in crate::nm) runtime_port_forward_destination_prefixes:Option<Vec<u8>>,
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(in crate::nm) struct Automatic {pub(in crate::nm) source_interface:String,pub(in crate::nm) destination_interface:String,pub(in crate::nm) masquerade:bool}
impl Origin {
    pub(crate) fn new(instance:uuid::Uuid,epoch:u64,roles:&Observation,value:Value)->Result<Self> {
        ensure!(serde_json::to_vec(&value)?.len()<=1024*1024-4096,"RESOURCE_EXHAUSTED: original writer model");
        let result=Self{agent_instance:instance,bridge_epoch:epoch,source:serde_json::from_value(value)?};result.require(roles)?;Ok(result)
    }
    pub(in crate::nm) fn require(&self,roles:&Observation)->Result<()> {
        roles.validate()?;
        ensure!(self.agent_instance==roles.agent_instance&&self.bridge_epoch==roles.bridge_epoch&&self.bridge_epoch>0
            &&self.source.schema_version==1&&self.source.source_kind=="legacy.writer.model.v1"&&!self.source.kernel_observed
            &&self.source.network_revision==roles.source_revision(),"CONFLICT: original model registration/network source");
        self.stored(roles)?;crate::firewall::validate_legacy_source_rules(&self.source.model_rules)?;
        let names=roles.roles.interfaces.iter().map(|v|v.id.as_str()).collect::<BTreeSet<_>>();let mut instances=BTreeSet::new();
        for (index,family) in self.source.families.iter().enumerate() {
            ensure!(family.family==if index==0{"ipv4"}else{"ipv6"}&&!family.instance_id.is_nil()&&instances.insert(family.instance_id),"CONFLICT: original model family/instance");
            let prefix=if index==0{"firewall."}else{"firewall.ipv6."};let keys=["open.ports","port.forwarding","nat"].map(|v|format!("{prefix}{v}"));
            ensure!(family.model_properties.len()==3&&keys.iter().all(|k|family.model_properties.get(k).is_some_and(|v|v.len()<=65536&&v.bytes().all(|b|b.is_ascii_graphic()))),"CONFLICT: complete original runtime model properties");
            for text in [&family.expected_ruleset,&family.managed_ruleset] {
                ensure!(text.len()<=256*1024,"RESOURCE_EXHAUSTED: rendered model");let source=crate::firewall::legacy_model_snapshot(text)?;
                ensure!(source["tables"].as_array().is_some_and(|v|v.len()==3&&v.iter().zip(["filter","nat","mangle"]).all(|(row,name)|row["name"]==name)),"CONFLICT: complete rendered model tables");
            }
            ensure!(family.additional_rules.len()==3&&["filter","nat","mangle"].iter().all(|k|family.additional_rules.contains_key(*k)),"CONFLICT: additional source scopes");
            for rows in family.additional_rules.values() {ensure!(rows.len()<=4096&&rows.iter().all(|v|!v.is_empty()&&v.len()<=16384&&!v.chars().any(char::is_control)),"RESOURCE_EXHAUSTED: additional model rows");}
            ensure!(family.automatic_nat.len()<=4096&&family.automatic_nat.iter().all(|v|names.contains(v.source_interface.as_str())&&names.contains(v.destination_interface.as_str())&&v.source_interface!=v.destination_interface),"CONFLICT: original automatic NAT interface mapping");
            if let Some(types)=&family.runtime_nat_rule_types {
                let rows=self.source.model_rules["nat"].as_array().context("CONFLICT: original runtime NAT rules")?.iter().filter(|row|row["family"]==family.family).collect::<Vec<_>>();
                ensure!(types.len()==rows.len()&&types.iter().zip(rows).all(|(kind,row)|["GENERIC","IP_FORWARDING","PORT_FORWARDING"].contains(&kind.as_str())&&row["ruleType"]==*kind),"CONFLICT: original runtime NAT type evidence differs from model rules");
            }
            if let Some(prefixes)=&family.runtime_port_forward_destination_prefixes {
                let count=self.source.model_rules["portForward"].as_array().context("CONFLICT: original runtime forwarding rules")?.iter().filter(|row|row["family"]==family.family).count();
                ensure!(prefixes.len()==count&&prefixes.iter().all(|v|*v<=if family.family=="ipv4"{32}else{128}),"CONFLICT: original runtime destination prefix evidence");
            }
        }
        Ok(())
    }
    pub(in crate::nm) fn stored(&self,roles:&Observation)->Result<FirewallSource> {FirewallSource::new(self.agent_instance,self.bridge_epoch,roles,self.source.stored_firewall.clone())}
    pub(in crate::nm) fn parameters(&self)->Result<Value> {Ok(serde_json::to_value(&self.source)?)}
    pub(in crate::nm) fn families(&self)->&[Family;2] {&self.source.families}
    pub(in crate::nm) fn model_rules(&self)->&Value {&self.source.model_rules}
    pub(in crate::nm) fn runtime_nat_types_complete(&self)->bool {
        self.source.families.iter().all(|family|family.runtime_nat_rule_types.is_some()||self.source.model_rules["nat"].as_array().is_some_and(|rows|rows.iter().all(|row|row["family"]!=family.family)))
    }
    pub(in crate::nm) fn runtime_forward_prefixes_complete(&self)->bool {
        self.source.families.iter().all(|family|family.runtime_port_forward_destination_prefixes.is_some()||self.source.model_rules["portForward"].as_array().is_some_and(|rows|rows.iter().all(|row|row["family"]!=family.family)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete_claimed_or_rebound_original_models_never_become_a_source() {
        let exchange:Value=serde_json::from_str(include_str!("../fixtures/legacy-origin-v32.json")).unwrap();
        let roles=Observation::new(uuid::Uuid::new_v4(),9,exchange["roles"].clone()).unwrap();
        for defect in ["instance","epoch","version","kernel","family","nil","duplicate","property","automatic","render"] {
            let mut value=exchange["origin"].clone();let mut instance=roles.agent_instance;let mut epoch=roles.bridge_epoch;
            match defect {
                "instance"=>instance=uuid::Uuid::new_v4(),"epoch"=>epoch+=1,"version"=>value["schemaVersion"]=json!(2),"kernel"=>value["kernelObserved"]=json!(true),
                "family"=>value["families"][1]["family"]=json!("ipv4"),"nil"=>value["families"][0]["instanceId"]=json!(uuid::Uuid::nil()),
                "duplicate"=>value["families"][1]["instanceId"]=value["families"][0]["instanceId"].clone(),
                "property"=>{value["families"][0]["modelProperties"].as_object_mut().unwrap().remove("firewall.nat");},
                "automatic"=>value["families"][0]["automaticNat"][0]["sourceInterface"]=json!("unknown0"),
                "render"=>value["families"][0]["managedRuleset"]=json!("*filter\nCOMMIT\n"),_=>unreachable!(),
            }
            assert!(Origin::new(instance,epoch,&roles,value).is_err(),"{defect}");
        }
    }
        #[test]
        fn runtime_nat_type_evidence_is_optional_for_history_but_never_inferred_or_rebound() {
            let exchange:Value=serde_json::from_str(include_str!("../fixtures/rich-raw-corpus-v35.json")).unwrap();let exchange=&exchange["exchange"];
            let roles=Observation::new(uuid::Uuid::new_v4(),12,exchange["roles"].clone()).unwrap();let old=exchange["origin"].clone();
            let history=Origin::new(roles.agent_instance,roles.bridge_epoch,&roles,old.clone()).unwrap();assert_eq!(history.parameters().unwrap(),old);assert!(!history.runtime_nat_types_complete());
            let mut value=old.clone();for family in value["families"].as_array_mut().unwrap() {family["runtimeNatRuleTypes"]=json!(["IP_FORWARDING","IP_FORWARDING"]);}
            assert!(Origin::new(roles.agent_instance,roles.bridge_epoch,&roles,value.clone()).unwrap().runtime_nat_types_complete());
            for wrong in [json!([]),json!(["IP_FORWARDING","UNKNOWN"]),json!(["IP_FORWARDING","PORT_FORWARDING"])] {
                let mut changed=value.clone();changed["families"][0]["runtimeNatRuleTypes"]=wrong;assert!(Origin::new(roles.agent_instance,roles.bridge_epoch,&roles,changed).is_err());
            }
            assert_eq!(history.parameters().unwrap(),old);
        }
}
