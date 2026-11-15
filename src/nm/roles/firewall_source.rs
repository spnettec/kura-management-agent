//! Original stored-CM rule observations. No backend policy or kernel ownership.
use super::*;

#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(crate) struct FirewallSource {
    agent_instance:uuid::Uuid,
    bridge_epoch:u64,
    source:StoredSource,
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct StoredSource {
    schema_version:u8,
    source_kind:String,
    network_revision:String,
    families:[FamilySource;2],
    rules:Value,
    backend_policy_observed:bool,
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct FamilySource {
    pid:String,
    revision:String,
    present:bool,
    properties:BTreeMap<String,String>,
    defaulted_properties:Vec<String>,
}
impl FirewallSource {
    pub(crate) fn new(instance:uuid::Uuid,epoch:u64,roles:&Observation,value:Value)->Result<Self> {
        ensure!(serde_json::to_vec(&value)?.len()<=512*1024,"RESOURCE_EXHAUSTED: original firewall source");
        let result=Self{agent_instance:instance,bridge_epoch:epoch,source:serde_json::from_value(value)?};
        result.require(roles)?;Ok(result)
    }
    pub(in crate::nm) fn require(&self,roles:&Observation)->Result<()> {
        roles.validate()?;
        ensure!(self.agent_instance==roles.agent_instance && self.bridge_epoch==roles.bridge_epoch
            && !self.agent_instance.is_nil() && self.bridge_epoch>0
            && self.source.schema_version==1 && self.source.source_kind=="stored.cm.rules.v1"
            && self.source.network_revision==roles.roles.revision && !self.source.backend_policy_observed,
            "CONFLICT: original firewall source registration/network identity");
        for (family,pid,prefix) in [(&self.source.families[0],FIREWALL_V4_PID,"firewall."),
                                    (&self.source.families[1],FIREWALL_V6_PID,"firewall.ipv6.")] {
            let fields:Vec<String>=["open.ports","port.forwarding","nat"].iter().map(|suffix|format!("{prefix}{suffix}")).collect();
            ensure!(family.pid==pid && family.revision.strip_prefix("stored:").is_some_and(|token|token.len()==64
                && token.bytes().all(|ch|ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch)))
                && (family.present || family.properties.is_empty())
                && family.properties.iter().all(|(key,value)|fields.contains(key) && value.len()<=65536 && value.bytes().all(|ch|ch.is_ascii_graphic()))
                && family.defaulted_properties==fields.into_iter().filter(|field|!family.properties.contains_key(field)).collect::<Vec<_>>(),
                "CONFLICT: original stored firewall family source");
        }
        crate::firewall::validate_legacy_source_rules(&self.source.rules)
    }
    pub(in crate::nm) fn parameters(&self)->Result<Value> {Ok(serde_json::to_value(&self.source)?)}
    pub(in crate::nm) fn rules(&self)->&Value {&self.source.rules}
}

#[cfg(test)]
pub(crate) fn fixture(roles:&Observation)->FirewallSource {
    let families=[(FIREWALL_V4_PID,"firewall."),(FIREWALL_V6_PID,"firewall.ipv6.")].into_iter().map(|(pid,prefix)| {
        json!({"pid":pid,"revision":format!("stored:{}","a".repeat(64)),"present":true,
            "properties":{format!("{prefix}open.ports"):"",format!("{prefix}port.forwarding"):"",format!("{prefix}nat"):""},"defaultedProperties":[]})
    }).collect::<Vec<_>>();
    FirewallSource::new(roles.agent_instance,roles.bridge_epoch,roles,json!({"schemaVersion":1,"sourceKind":"stored.cm.rules.v1",
        "networkRevision":roles.roles.revision,"families":families,"rules":{"input":[],"portForward":[],"nat":[]},"backendPolicyObserved":false})).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_java_core_stored_source_has_the_same_fixed_pids_absence_and_rule_grammar() {
        let value:Value=serde_json::from_str(include_str!("../fixtures/v23-stored-fw-source.json")).unwrap();
        let observed=Observation::new(uuid::Uuid::new_v4(),1,json!({"schemaVersion":1,"pid":PID,
            "revision":value["networkRevision"],"interfaces":[]})).unwrap();
        let source=FirewallSource::new(observed.agent_instance,1,&observed,value).unwrap();let view=source.parameters().unwrap();
        assert_eq!(view["networkRevision"],"core-source-interop");assert_eq!(view["families"][0]["pid"],FIREWALL_V4_PID);
        assert_eq!(view["families"][1]["pid"],FIREWALL_V6_PID);assert_eq!(view["families"][1]["present"],false);
        for key in ["input","portForward","nat"] {assert_eq!(view["rules"][key].as_array().unwrap().len(),1);}
        assert_eq!(view["backendPolicyObserved"],false);
    }
    fn roles()->Observation {Observation::new(uuid::Uuid::new_v4(),1,json!({"schemaVersion":1,"pid":PID,
        "revision":"original-cm","interfaces":[]})).unwrap()}
    #[test]
    fn complete_fixed_stored_source_is_readonly_data_not_backend_policy() {
        let roles=roles();let source=fixture(&roles);source.require(&roles).unwrap();let value=source.parameters().unwrap();
        assert_eq!(value["backendPolicyObserved"],false);assert!(value["rules"].get("ipv4").is_none());
        let restored:FirewallSource=serde_json::from_slice(&serde_json::to_vec(&source).unwrap()).unwrap();assert!(source==restored);
    }
    #[test]
    fn wrong_pid_registration_domain_presence_defaults_and_extra_fields_refuse() {
        let roles=roles();let original=fixture(&roles).parameters().unwrap();
        for defect in ["pid","revision","present","defaults","backend","extra","network","rules","secret"] {
            let mut value=original.clone();match defect {
                "pid"=>value["families"][1]["pid"]=json!("org.eclipse.kura.net.admin.FirewallConfigurationServiceIPv6"),
                "revision"=>value["families"][0]["revision"]=json!("generic-edit-revision"),
                "present"=>value["families"][0]["present"]=json!(false),
                "defaults"=>value["families"][0]["defaultedProperties"]=json!(["firewall.open.ports"]),
                "backend"=>value["backendPolicyObserved"]=json!(true),
                "extra"=>value["grant"]=json!(true),
                "network"=>value["networkRevision"]=json!("another"),
                "rules"=>value["rules"]["ipv4"]=json!({"inputPolicy":"accept"}),
                "secret"=>value["families"][0]["properties"]["password"]=json!("unreviewed"),
                _=>unreachable!(),
            }
            assert!(FirewallSource::new(roles.agent_instance,roles.bridge_epoch,&roles,value).is_err(),"{defect}");
        }
        assert!(FirewallSource::new(uuid::Uuid::new_v4(),roles.bridge_epoch,&roles,original.clone()).is_err());
        assert!(FirewallSource::new(roles.agent_instance,roles.bridge_epoch+1,&roles,original).is_err());
    }
    #[test]
    fn actual_v3_grammar_rejects_injection_automatic_nat_and_partial_target_data() {
        let roles=roles();let mut value=fixture(&roles).parameters().unwrap();
        value["rules"]["input"]=json!([{"family":"ipv4","protocol":"tcp","ports":{"first":22,"last":22},"inputInterface":"eth0\";flush ruleset"}]);
        assert!(FirewallSource::new(roles.agent_instance,1,&roles,value).is_err());
        let mut value=fixture(&roles).parameters().unwrap();value["rules"]["nat"]=json!([{"automatic":true}]);
        assert!(FirewallSource::new(roles.agent_instance,1,&roles,value).is_err());
        let mut value=fixture(&roles).parameters().unwrap();value["rules"].as_object_mut().unwrap().remove("input");
        assert!(FirewallSource::new(roles.agent_instance,1,&roles,value).is_err());
    }
}
