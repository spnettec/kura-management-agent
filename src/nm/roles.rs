//! Kura CM role projections. This data names configuration intent; it is not a
//! writer lease, kernel-state proof, or authority to adopt an existing ruleset.
use super::*;
use std::collections::{BTreeMap,BTreeSet};
mod firewall_source;
mod origin;
pub(crate) use origin::Origin;
pub(crate) use firewall_source::FirewallSource;
#[cfg(test)]
pub(crate) use firewall_source::fixture as fixture_firewall_source;

pub(super) const PID: &str="org.eclipse.kura.net.admin.NetworkConfigurationService";
pub(crate) const FIREWALL_V4_PID:&str="org.eclipse.kura.net.admin.FirewallConfigurationService";
pub(crate) const FIREWALL_V6_PID:&str="org.eclipse.kura.net.admin.ipv6.FirewallConfigurationServiceIPv6";
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(super) struct ConfigurationRoles {
    schema_version:u8,
    pid:String,
    pub(super) revision:String,
    interfaces:Vec<InterfaceRole>,
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct InterfaceRole {
    id:String,
    #[serde(rename="type")]
    kind:String,
    ipv4_status:Option<String>,
    nat_enabled:Option<bool>,
}
#[derive(Clone,Debug,PartialEq,Eq,PartialOrd,Ord,Deserialize,Serialize)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(super) struct NatPair {pub(super) lan:String,pub(super) wan:String}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(crate) struct Observation {
    pub(super) agent_instance:uuid::Uuid,
    pub(super) bridge_epoch:u64,
    pub(super) roles:ConfigurationRoles,
}
/// Fixed-PID Core ownership observation, bound to the authenticated current
/// bridge. Its plan/mirror identities must still match the original handover.
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(crate) struct Owner {
    agent_instance:uuid::Uuid,
    bridge_epoch:u64,
    operation_id:uuid::Uuid,
    plan_sha256:String,
    mirror_sha256:String,
    roles:ConfigurationRoles,
    // Historical receipt bytes omit this field. Absence remains queryable but
    // cannot attest a fresh complete Core/firewall ownership observation.
    #[serde(default,skip_serializing_if="Option::is_none")]
    firewall:Option<FirewallOwner>,
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct FirewallOwner {revision:u64,source_digest:String}
impl Owner {
    pub(in crate::nm) fn require_complete(&self)->Result<()> {
        ensure!(self.firewall.as_ref().is_some_and(|value|value.revision>0
            && value.source_digest.len()==64 && value.source_digest.bytes().all(|ch|ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))),
            "UNSUPPORTED: complete three-handler Core firewall proof required");Ok(())
    }
    pub(crate) fn require_firewall(&self,revision:u64,source:&str)->Result<()> {
        self.require_complete()?;
        ensure!(self.firewall.as_ref().is_some_and(|value|value.revision==revision && value.source_digest==source),
            "CONFLICT: Core firewall proof differs from the original current confirmed policy");Ok(())
    }
    pub(in crate::nm) fn firewall_binding(&self)->Result<(u64,&str)> {
        self.require_complete()?;
        let firewall=self.firewall.as_ref().unwrap();
        Ok((firewall.revision,&firewall.source_digest))
    }
    pub(in crate::nm) fn require_registration(&self,roles:&Observation)->Result<()> {
        roles.validate()?;ensure!(self.agent_instance==roles.agent_instance && self.bridge_epoch==roles.bridge_epoch,
            "CONFLICT: Core owner and startup JVM use different registrations");Ok(())
    }
    pub(in crate::nm) fn require_original(&self,operation:uuid::Uuid,plan:&str,template:&str,roles:&ConfigurationRoles)->Result<()> {
        if self.firewall.is_some(){self.require_complete()?;}
        ensure!(!self.agent_instance.is_nil() && self.bridge_epoch>0 && self.operation_id==operation && self.plan_sha256==plan
            && self.mirror_sha256==template && &self.roles==roles,"CONFLICT: actual Core owner differs from original delegation");self.roles.validate()
    }
    pub(in crate::nm) fn require_same_firewall(&self, other:&Self)->Result<()> {
        self.require_complete()?;other.require_complete()?;
        ensure!(self.firewall==other.firewall,"CONFLICT: current owner firewall differs from the prepared source");Ok(())
    }
    pub(in crate::nm) fn registration(&self)->(uuid::Uuid,u64) {(self.agent_instance,self.bridge_epoch)}
    pub(in crate::nm) fn role_configuration(&self)->&ConfigurationRoles {&self.roles}
    pub(in crate::nm) fn mirror_hash(&self)->&str {&self.mirror_sha256}
    pub(crate) fn new(agent_instance:uuid::Uuid,bridge_epoch:u64,value:Value)->Result<Self> {
        let object=value.as_object().context("CONFLICT: external owner projection")?;
        ensure!(object.len()==7 && ["schemaVersion","pid","operationId","planSha256","mirrorSha256","roles","firewall"].iter().all(|k|object.contains_key(*k))
            && value["schemaVersion"]==2 && value["pid"]==PID && !agent_instance.is_nil() && bridge_epoch>0,
            "CONFLICT: external owner identity");
        let id=value["operationId"].as_str().context("CONFLICT: external owner operation")?;
        let operation_id=uuid::Uuid::parse_str(id)?;
        ensure!(!operation_id.is_nil() && operation_id.to_string()==id,"CONFLICT: external owner operation");
        let hash=|name:&str|->Result<String> {
            let value=value[name].as_str().context("CONFLICT: external owner digest")?;
            ensure!(value.len()==64 && value.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),"CONFLICT: external owner digest");Ok(value.into())
        };
        let firewall=&value["firewall"];
        ensure!(firewall.as_object().is_some_and(|object|object.len()==4
            && ["schemaVersion","pids","revision","sourceDigest"].iter().all(|key|object.contains_key(*key)))
            && firewall["schemaVersion"]==1 && firewall["pids"]==json!([FIREWALL_V4_PID,FIREWALL_V6_PID]),
            "CONFLICT: actual firewall handler cohort");
        let revision=firewall["revision"].as_str().context("CONFLICT: firewall owner revision")?;
        let parsed=revision.parse::<u64>()?;ensure!(parsed>0 && parsed.to_string()==revision,"CONFLICT: firewall owner revision");
        let source=firewall["sourceDigest"].as_str().context("CONFLICT: firewall owner digest")?;
        let result=Self{agent_instance,bridge_epoch,operation_id,plan_sha256:hash("planSha256")?,
            mirror_sha256:hash("mirrorSha256")?,roles:ConfigurationRoles::parse(value["roles"].clone())?,
            firewall:Some(FirewallOwner{revision:parsed,source_digest:source.into()})};
        result.require_complete()?;Ok(result)
    }
}
fn ascii(value:&str,max:usize)->bool {
    !value.is_empty() && value.len()<=max && value.bytes().all(|b|b.is_ascii_graphic())
}
fn interface(value:&str)->bool {
    !value.is_empty() && value.len()<=15 && value.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b))
}
impl ConfigurationRoles {
    pub(super) fn parse(value:Value)->Result<Self> {
        // Nullable fields are still required. Missing and explicitly unknown
        // cannot silently acquire an enabled/default role during a new schema.
        let fields=value.as_object().context("CONFLICT: CM role projection")?;
        ensure!(fields.len()==4 && ["schemaVersion","pid","revision","interfaces"].iter().all(|k|fields.contains_key(*k)),"CONFLICT: CM role envelope");
        for row in value["interfaces"].as_array().context("CONFLICT: CM role rows")? {
            let fields=row.as_object().context("CONFLICT: CM role row")?;
            ensure!(fields.len()==4 && ["id","type","ipv4Status","natEnabled"].iter().all(|k|fields.contains_key(*k)),"CONFLICT: CM role fields");
        }
        let roles:Self=serde_json::from_value(value)?;roles.validate()?;Ok(roles)
    }
    fn validate(&self)->Result<()> {
        ensure!(self.schema_version==1 && self.pid==PID && ascii(&self.revision,512) && self.interfaces.len()<=128,"CONFLICT: CM role identity");
        let mut ids=BTreeSet::new();
        for row in &self.interfaces {
            ensure!(ascii(&row.id,128) && ids.insert(&row.id),"CONFLICT: CM role interface identity");
            ensure!(["UNKNOWN","ETHERNET","WIFI","UNUSED1","UNUSED2","BT","OLPC_MESH","WIMAX","MODEM","INFINIBAND","BOND","VLAN","ADSL","LOOPBACK"].contains(&row.kind.as_str()),"CONFLICT: CM role device type");
            ensure!(row.ipv4_status.as_deref().is_none_or(|s|["netIPv4StatusDisabled","netIPv4StatusUnmanaged","netIPv4StatusL2Only","netIPv4StatusEnabledLAN","netIPv4StatusEnabledWAN","netIPv4StatusUnknown"].contains(&s)),"CONFLICT: CM IPv4 role");
        }
        Ok(())
    }
    /// Validate the whole managed CM scope before an original delegation is
    /// admitted, including disabled/L2-only interfaces. Identity comes only
    /// from observed NM devices in the adopted allowlist. A logical modem ID
    /// that does not name that actual device requires an explicit mapping;
    /// never infer its backend from routes, an alias, or another device type.
    pub(super) fn adopted_nat(&self,devices:&[Device])->Result<Option<nat::NatSet>> {
        self.validate()?;
        let mut resolved=BTreeMap::new();
        let owned=devices.iter().map(|device|device.interface.clone()).collect();
        for row in &self.interfaces {
            if !matches!(row.ipv4_status.as_deref(),Some("netIPv4StatusDisabled"|"netIPv4StatusL2Only"|"netIPv4StatusEnabledLAN"|"netIPv4StatusEnabledWAN")) {continue;}
            let device=devices.iter().find(|device|device.interface==row.id)
                .context("UNSUPPORTED: managed CM role endpoint has no adopted backend mapping")?;
            // Values match NetworkManager's DeviceType and the retained
            // Java NMDeviceType.fromUInt32 conversion, not enum ordinals.
            let expected=match row.kind.as_str() {
                "ETHERNET"=>1,"WIFI"=>2,"BT"=>5,"OLPC_MESH"=>6,"WIMAX"=>7,
                "MODEM"=>8,"INFINIBAND"=>9,"BOND"=>10,"VLAN"=>11,"ADSL"=>12,"LOOPBACK"=>32,
                _=>anyhow::bail!("UNSUPPORTED: managed CM role device type requires explicit adoption"),
            };
            ensure!(device.managed && device.device_type==expected,
                "CONFLICT: managed CM role differs from the actual adopted backend device");
            resolved.insert(row.id.clone(),device.interface.clone());
        }
        nat::NatSet::from_pairs(self.automatic_nat(&resolved,&owned)?)
    }
    /// Resolved names must come from the adopted backend binding, never a
    /// caller's role flag or an inferred default route. All required endpoints
    /// must be in the same owned allowlist; extra WANs may not disappear.
    pub(super) fn automatic_nat(&self,resolved:&BTreeMap<String,String>,owned:&BTreeSet<String>)->Result<BTreeSet<NatPair>> {
        self.validate()?;
        let wan:Vec<_>=self.interfaces.iter().filter(|r|r.ipv4_status.as_deref()==Some("netIPv4StatusEnabledWAN")).collect();
        let lan:Vec<_>=self.interfaces.iter().filter(|r|r.ipv4_status.as_deref()==Some("netIPv4StatusEnabledLAN") && r.nat_enabled==Some(true)
            && ["ETHERNET","WIFI","MODEM","VLAN"].contains(&r.kind.as_str())).collect();
        if wan.is_empty() || lan.is_empty() {return Ok(BTreeSet::new());}
        let mut names=BTreeSet::new();let mut upstream=Vec::new();let mut downstream=Vec::new();
        for (rows,output) in [(&wan,&mut upstream),(&lan,&mut downstream)] {for row in rows {
            let name=resolved.get(&row.id).context("UNSUPPORTED: authoritative role endpoint is unresolved")?;
            ensure!(interface(name) && owned.contains(name) && names.insert(name),"FORBIDDEN: CM role endpoint is not uniquely adopted");output.push(name);
        }}
        let mut pairs=BTreeSet::new();
        for input in downstream {for output in &upstream {
            if !input.eq_ignore_ascii_case(output) {pairs.insert(NatPair{lan:input.clone(),wan:(*output).clone()});}
        }}
        ensure!(pairs.len()<=256,"UNSUPPORTED: authoritative NAT bounds");Ok(pairs)
    }
}
impl Observation {
    pub(crate) fn source_revision(&self)->&str {&self.roles.revision}
    pub(crate) fn matches_registration(&self,instance:uuid::Uuid,epoch:u64)->bool {
        self.agent_instance==instance && self.bridge_epoch==epoch
    }
    pub(super) fn validate(&self)->Result<()> {
        ensure!(!self.agent_instance.is_nil() && self.bridge_epoch>0,"CONFLICT: retained CM role session");
        self.roles.validate()
    }
    pub(crate) fn new(agent_instance:uuid::Uuid,bridge_epoch:u64,value:Value)->Result<Self> {
        ensure!(!agent_instance.is_nil() && bridge_epoch>0,"FORBIDDEN: authenticated CM role session required");
        Ok(Self{agent_instance,bridge_epoch,roles:ConfigurationRoles::parse(value)?})
    }
}

#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(crate) struct StartupSpec {pub(super) operation_id:uuid::Uuid,pub(super) plan_sha256:String,pub(super) nonce:String}
fn startup_hash(value:&str)->bool {value.len()==64 && value.bytes().all(|ch|ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))}
impl StartupSpec {
    pub(super) fn new(operation_id:uuid::Uuid,plan_sha256:String,nonce:String)->Result<Self> {
        let spec=Self{operation_id,plan_sha256,nonce};spec.validate()?;Ok(spec)
    }
    pub(super) fn validate(&self)->Result<()> {
        ensure!(!self.operation_id.is_nil() && startup_hash(&self.plan_sha256) && startup_hash(&self.nonce),"CONFLICT: original startup association challenge");Ok(())
    }
    pub(crate) fn parameters(&self)->Value {json!({"operationId":self.operation_id,"planSha256":self.plan_sha256,"nonce":self.nonce})}
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
struct StartupReport {
    schema_version:u8,operation_id:uuid::Uuid,plan_sha256:String,nonce:String,observer_instance_id:uuid::Uuid,
    profile_id:String,process_id:u32,framework_start_level:u32,ordinary_load:bool,
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(crate) struct StartupAssociation {agent_instance:uuid::Uuid,bridge_epoch:u64,report:StartupReport}
impl StartupAssociation {
    pub(in crate::nm) fn require_new_observer(&self,old:&Self)->Result<()> {
        self.validate()?;old.validate()?;ensure!(self.report.observer_instance_id!=old.report.observer_instance_id,
            "CONFLICT: original old JVM observer cannot attest the new startup");Ok(())
    }
    pub(crate) fn new(agent_instance:uuid::Uuid,bridge_epoch:u64,value:Value)->Result<Self> {
        ensure!(value.as_object().is_some_and(|object|object.len()==9),"CONFLICT: startup association envelope");
        let operation=value["operationId"].as_str().context("CONFLICT: startup association operation")?;
        let observer=value["observerInstanceId"].as_str().context("CONFLICT: startup association observer")?;
        for text in [operation,observer] {
            ensure!(uuid::Uuid::parse_str(text).is_ok_and(|id|!id.is_nil() && id.to_string()==text),"CONFLICT: startup association UUID");
        }
        let observed=Self{agent_instance,bridge_epoch,report:serde_json::from_value(value)?};observed.validate()?;Ok(observed)
    }
    fn validate(&self)->Result<()> {
        let report=&self.report;
        ensure!(!self.agent_instance.is_nil() && self.bridge_epoch>0 && report.schema_version==1 && !report.operation_id.is_nil()
            && !report.observer_instance_id.is_nil() && startup_hash(&report.plan_sha256) && startup_hash(&report.nonce)
            && report.profile_id.strip_prefix("profile-").is_some_and(|text|uuid::Uuid::parse_str(text).is_ok_and(|id|!id.is_nil() && id.to_string()==text))
            && report.process_id>0 && report.process_id<=i32::MAX as u32 && report.framework_start_level<=i32::MAX as u32,
            "CONFLICT: startup association source identity");Ok(())
    }
    pub(super) fn require(&self,spec:&StartupSpec,profile:&str,pid:u32,roles:&Observation)->Result<()> {
        self.validate()?;spec.validate()?;roles.validate()?;
        ensure!(self.report.operation_id==spec.operation_id && self.report.plan_sha256==spec.plan_sha256 && self.report.nonce==spec.nonce
            && self.report.profile_id==profile && self.report.process_id==pid && self.report.ordinary_load && self.report.framework_start_level>=5
            && self.agent_instance==roles.agent_instance && self.bridge_epoch==roles.bridge_epoch,
            "CONFLICT: actual Kura JVM/profile/unit or registered startup source differs");Ok(())
    }
    fn registration(&self)->(uuid::Uuid,u64){(self.agent_instance,self.bridge_epoch)}
}

pub(crate) trait Source:Send+Sync {
    fn read(&self,deadline:Instant)->Result<Observation>;
    fn raw(&self,deadline:Instant)->Result<Observation> {self.read(deadline)}
    fn firewall_source(&self,_roles:&Observation,_deadline:Instant)->Result<FirewallSource> {
        anyhow::bail!("UNSUPPORTED: original stored firewall source unavailable")
    }
    fn firewall_origin(&self,_roles:&Observation,_deadline:Instant)->Result<Option<Origin>> {Ok(None)}
    fn legacy_drain(&self,_roles:&Observation,_operation:uuid::Uuid,_plan:&str,_deadline:Instant)->Result<()> {
        anyhow::bail!("UNSUPPORTED: authenticated original Java paired writer drain observer unavailable")
    }
    #[cfg(target_os = "linux")]
    fn require_continuity_registration(&self,_roles:&Observation,_anchor:&super::handover::continuity::RegistrationAnchor,_deadline:Instant)->Result<()> {
        anyhow::bail!("UNSUPPORTED: original live continuity registration unavailable")
    }
    fn owner(&self,_deadline:Instant)->Result<Owner> {anyhow::bail!("UNSUPPORTED: Core ownership observer unavailable")}
    fn owner_still_registered(&self,_owner:&Owner,_deadline:Instant)->Result<()> {
        anyhow::bail!("UNSUPPORTED: actual owner registration check unavailable")
    }
    fn association(&self,_spec:&StartupSpec,_deadline:Instant)->Result<StartupAssociation> {
        anyhow::bail!("UNSUPPORTED: actual startup JVM association observer unavailable")
    }
    fn association_still_registered(&self,_observed:&StartupAssociation,_deadline:Instant)->Result<()> {
        anyhow::bail!("UNSUPPORTED: startup association registration check unavailable")
    }
    fn export(&self,_operation:uuid::Uuid,_source:&Observation,_firewall:&FirewallSource,_nonce:&str,_deadline:Instant)->Result<Value> {
        anyhow::bail!("UNSUPPORTED: complete original template export unavailable")
    }
}
pub(crate) struct BridgeSource {local:crate::local::Local,runtime:tokio::runtime::Handle}
impl BridgeSource {
    pub(crate) fn new(mut local:crate::local::Local)->Self {
        // Shared registration/pending state is retained without a cycle through
        // the NM engine that will own this source.
        local.nm=None;Self{local,runtime:tokio::runtime::Handle::current()}
    }
    fn wait<T>(&self,deadline:Instant,future:impl std::future::Future<Output=Result<T,&'static str>>)->Result<T> {
        let remaining=deadline.checked_duration_since(Instant::now()).filter(|v|!v.is_zero())
            .context("TIMEOUT: CM role read deadline")?;
        self.runtime.block_on(async {
            tokio::time::timeout(remaining,future).await
                .map_err(|_|anyhow::anyhow!("TIMEOUT: CM role read deadline"))?
                .map_err(|code|anyhow::anyhow!("{code}: CM role source unavailable"))
        })
    }
}
impl Source for BridgeSource {
    fn read(&self,deadline:Instant)->Result<Observation> {self.wait(deadline,self.local.network_role_fence())}
    fn firewall_origin(&self,roles:&Observation,deadline:Instant)->Result<Option<Origin>> {
        self.wait(deadline,self.local.network_firewall_origin(roles))
    }
    fn legacy_drain(&self,roles:&Observation,operation:uuid::Uuid,plan:&str,deadline:Instant)->Result<()> {
        ensure!(!operation.is_nil() && plan.len()==64 && plan.bytes().all(|v|v.is_ascii_digit()||(b'a'..=b'f').contains(&v)),"INVALID_ARGUMENT: original paired drain identity");
        // Store binds both exact operation/plan markers on both sides. The
        // existing registered Java callback drains both participating writers.
        ensure!(self.read(deadline)?==*roles,"CONFLICT: original paired writer source/registration changed");Ok(())
    }
    fn raw(&self,deadline:Instant)->Result<Observation> {self.wait(deadline,self.local.network_roles())}
    #[cfg(target_os = "linux")]
    fn require_continuity_registration(&self,roles:&Observation,anchor:&super::handover::continuity::RegistrationAnchor,deadline:Instant)->Result<()> {
        self.wait(deadline,self.local.require_continuity_registration(roles,anchor))
    }
    fn firewall_source(&self,roles:&Observation,deadline:Instant)->Result<FirewallSource> {
        self.wait(deadline,self.local.network_firewall_source(roles))
    }
    fn owner(&self,deadline:Instant)->Result<Owner> {self.wait(deadline,self.local.network_owner())}
    fn owner_still_registered(&self,owner:&Owner,deadline:Instant)->Result<()> {
        let (instance,epoch)=owner.registration();self.wait(deadline,self.local.network_owner_registration(instance,epoch))
    }
    fn association(&self,spec:&StartupSpec,deadline:Instant)->Result<StartupAssociation> {
        self.wait(deadline,self.local.network_startup_association(spec.parameters()))
    }
    fn association_still_registered(&self,observed:&StartupAssociation,deadline:Instant)->Result<()> {
        let (instance,epoch)=observed.registration();self.wait(deadline,self.local.network_owner_registration(instance,epoch))
    }
    fn export(&self,operation:uuid::Uuid,source:&Observation,firewall:&FirewallSource,nonce:&str,deadline:Instant)->Result<Value> {
        firewall.require(source)?;
        self.wait(deadline,self.local.network_template_export(operation.to_string(),source.roles.revision.clone(),nonce.into(),source.agent_instance,source.bridge_epoch,firewall.parameters()?))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(id:&str,status:&str,nat:Option<bool>)->Value {json!({"id":id,"type":"ETHERNET","ipv4Status":status,"natEnabled":nat})}
    fn view(rows:Vec<Value>)->Value {json!({"schemaVersion":1,"pid":PID,"revision":"opaque-cm-revision","interfaces":rows})}
    fn complete_owner()->Value {
        json!({"schemaVersion":2,"pid":PID,"operationId":"12345678-1234-4123-8123-123456789abc",
            "planSha256":"a".repeat(64),"mirrorSha256":"b".repeat(64),
            "roles":view(vec![row("eth0","netIPv4StatusEnabledWAN",None)]),
            "firewall":{"schemaVersion":1,"pids":[FIREWALL_V4_PID,FIREWALL_V6_PID],"revision":"1","sourceDigest":"c".repeat(64)}})
    }
    #[test]
    fn owner_requires_both_actual_firewall_pids_and_an_exact_positive_u64_revision() {
        let instance=uuid::Uuid::new_v4();
        for defect in ["pid","missing","zero","leading","overflow","digest"] {
            let mut value=complete_owner();
            match defect {
                "pid"=>value["firewall"]["pids"][1]=json!(FIREWALL_V4_PID),
                "missing"=>{value["firewall"].as_object_mut().unwrap().remove("pids");},
                "zero"=>value["firewall"]["revision"]=json!("0"),
                "leading"=>value["firewall"]["revision"]=json!("01"),
                "overflow"=>value["firewall"]["revision"]=json!("18446744073709551616"),
                "digest"=>value["firewall"]["sourceDigest"]=json!("C".repeat(64)),
                _=>unreachable!(),
            }
            assert!(Owner::new(instance,1,value).is_err(),"{defect}");
        }
        let mut value=complete_owner();value["firewall"]["revision"]=json!(u64::MAX.to_string());
        Owner::new(instance,1,value).unwrap().require_firewall(u64::MAX,&"c".repeat(64)).unwrap();
    }
    #[test]
    fn network_only_and_changed_current_firewall_are_not_new_owner_authority() {
        let instance=uuid::Uuid::new_v4();let owner=Owner::new(instance,1,complete_owner()).unwrap();
        owner.require_firewall(1,&"c".repeat(64)).unwrap();
        assert!(owner.require_firewall(2,&"c".repeat(64)).is_err());
        assert!(owner.require_firewall(1,&"d".repeat(64)).is_err());
        let mut old=complete_owner();old["schemaVersion"]=json!(1);old.as_object_mut().unwrap().remove("firewall");
        assert!(Owner::new(instance,1,old).is_err());
    }
    #[test]
    fn historical_persisted_owner_bytes_roundtrip_without_acquiring_complete_authority() {
        #[derive(Serialize)]
        #[serde(rename_all="camelCase")]
        struct Historical<'a> {
            agent_instance:uuid::Uuid,bridge_epoch:u64,operation_id:uuid::Uuid,
            plan_sha256:&'a str,mirror_sha256:&'a str,roles:&'a ConfigurationRoles,
        }
        let instance=uuid::Uuid::new_v4();let current=Owner::new(instance,1,complete_owner()).unwrap();
        let old=Historical{agent_instance:instance,bridge_epoch:1,operation_id:current.operation_id,
            plan_sha256:&current.plan_sha256,mirror_sha256:&current.mirror_sha256,roles:&current.roles};
        let bytes=serde_json::to_vec(&old).unwrap();let restored:Owner=serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(),bytes);
        restored.require_original(current.operation_id,&current.plan_sha256,&current.mirror_sha256,&current.roles).unwrap();
        assert!(restored.require_complete().is_err());
    }
    #[test]
    fn cm_roles_preserve_multi_wan_cross_product_and_never_infer_roles_from_nat_flags() {
        let value=view(vec![row("eth0","netIPv4StatusEnabledWAN",None),row("eth2","netIPv4StatusEnabledWAN",Some(false)),row("eth1","netIPv4StatusEnabledLAN",Some(true)),row("eth3","netIPv4StatusUnmanaged",Some(true))]);
        let roles=ConfigurationRoles::parse(value).unwrap();
        let names=BTreeMap::from_iter(["eth0","eth1","eth2","eth3"].map(|n|(n.to_owned(),n.to_owned())));
        let owned=names.values().cloned().collect();let pairs=roles.automatic_nat(&names,&owned).unwrap();
        assert_eq!(pairs.len(),2);assert!(pairs.contains(&NatPair{lan:"eth1".into(),wan:"eth0".into()}));assert!(pairs.contains(&NatPair{lan:"eth1".into(),wan:"eth2".into()}));
        assert!(roles.automatic_nat(&names,&BTreeSet::from(["eth0".into(),"eth1".into()])).is_err());
    }
    #[test]
    fn absent_false_disabled_and_unsupported_lan_do_not_acquire_automatic_nat() {
        for nat in [None,Some(false)] {
            let roles=ConfigurationRoles::parse(view(vec![row("eth0","netIPv4StatusEnabledWAN",None),row("eth1","netIPv4StatusEnabledLAN",nat)])).unwrap();
            assert!(roles.automatic_nat(&BTreeMap::from([("eth0".into(),"eth0".into())]),&BTreeSet::from(["eth0".into()])).unwrap().is_empty());
        }
        let mut unsupported=row("eth1","netIPv4StatusEnabledLAN",Some(true));unsupported["type"]=json!("BOND");
        let roles=ConfigurationRoles::parse(view(vec![row("eth0","netIPv4StatusEnabledWAN",None),unsupported])).unwrap();
        assert!(roles.automatic_nat(&BTreeMap::from([("eth0".into(),"eth0".into())]),&BTreeSet::from(["eth0".into()])).unwrap().is_empty());
    }
    #[test]
    fn malformed_cross_pid_role_claims_and_unresolved_or_aliased_endpoints_fail_closed() {
        let source=view(vec![row("eth0","netIPv4StatusEnabledWAN",None),row("eth1","netIPv4StatusEnabledLAN",Some(true))]);
        for key in ["pid","revision","schemaVersion"] {let mut bad=source.clone();bad[key]=if key=="revision" {json!("")} else {json!("forged")};assert!(ConfigurationRoles::parse(bad).is_err());}
        let mut bad=source.clone();bad["interfaces"][0]["natEnabled"]=json!("true");assert!(ConfigurationRoles::parse(bad).is_err());
        let mut bad=source.clone();bad["interfaces"][0].as_object_mut().unwrap().remove("natEnabled");assert!(ConfigurationRoles::parse(bad).is_err());
        let roles=ConfigurationRoles::parse(source).unwrap();assert!(roles.automatic_nat(&BTreeMap::new(),&BTreeSet::new()).is_err());
        assert!(roles.automatic_nat(&BTreeMap::from([("eth0".into(),"eth0".into()),("eth1".into(),"eth0".into())]),&BTreeSet::from(["eth0".into()])).is_err());
    }
    #[test]
    fn source_revision_and_authenticated_registration_are_both_bound() {
        let source=view(vec![]);let first=Observation::new(uuid::Uuid::new_v4(),1,source.clone()).unwrap();
        assert!(Observation::new(uuid::Uuid::nil(),1,source.clone()).is_err());assert!(Observation::new(first.agent_instance,0,source.clone()).is_err());
        let mut changed=source;changed["revision"]=json!("next-cm-revision");let second=ConfigurationRoles::parse(changed).unwrap();
        assert_ne!(digest(&serde_json::to_value(&first.roles).unwrap()).unwrap(),digest(&serde_json::to_value(&second).unwrap()).unwrap());
    }
    fn observed_device(name:&str,kind:u32)->Device {
        Device{interface:name.into(),device_path:format!("{ROOT}/Devices/{kind}"),device_type:kind,
            active_connection_path:"/".into(),managed:true,state:30,active_profile:None}
    }
    #[test]
    fn adopted_endpoints_bind_multi_wan_wifi_vlan_and_real_modem_device_names() {
        let mut modem=row("wwan0","netIPv4StatusEnabledWAN",None);modem["type"]=json!("MODEM");
        let mut wifi=row("wlan0","netIPv4StatusEnabledLAN",Some(true));wifi["type"]=json!("WIFI");
        let mut vlan=row("eth0.2","netIPv4StatusEnabledLAN",Some(true));vlan["type"]=json!("VLAN");
        let roles=ConfigurationRoles::parse(view(vec![row("eth0","netIPv4StatusEnabledWAN",None),modem,wifi,vlan,
            row("foreign0","netIPv4StatusUnmanaged",Some(true)),row("unknown0","netIPv4StatusUnknown",Some(true))])).unwrap();
        let devices=vec![observed_device("eth0",1),observed_device("wwan0",8),observed_device("wlan0",2),observed_device("eth0.2",11)];
        let pairs=roles.adopted_nat(&devices).unwrap().unwrap().pairs().unwrap();
        assert_eq!(pairs.len(),4);
        assert!(pairs.contains(&NatPair{lan:"wlan0".into(),wan:"wwan0".into()}));
        assert!(pairs.contains(&NatPair{lan:"eth0.2".into(),wan:"eth0".into()}));
        assert!(roles.adopted_nat(&devices[..3]).is_err());
        let mut aliases=serde_json::to_value(&roles).unwrap();aliases["interfaces"][1]["id"]=json!("logical-modem-id");
        assert!(ConfigurationRoles::parse(aliases).unwrap().adopted_nat(&devices).is_err(),"logical modem names require a real explicit mapping, not route inference");
    }
    #[test]
    fn original_delegation_requires_the_complete_observed_nat_and_never_installs_missing_pairs() {
        let roles=Observation::new(uuid::Uuid::new_v4(),1,view(vec![row("eth0","netIPv4StatusEnabledWAN",None),
            row("eth1","netIPv4StatusEnabledLAN",Some(true)),row("eth2","netIPv4StatusEnabledWAN",None)])).unwrap();
        let devices=vec![observed_device("eth0",1),observed_device("eth1",1),observed_device("eth2",1)];
        let allowed=devices.iter().map(|device|device.interface.clone()).collect::<Vec<_>>();
        let mut baseline=handover::Baseline{source_digest:"a".repeat(64),roles,
            profiles:devices.iter().map(handover::ProfileBinding::observe).collect::<Result<_>>().unwrap(),
            firewall_digest:"b".repeat(64),automatic_nat:Value::Null,native_transfer:None,firewall_fence:None,firewall_source:None};
        assert!(baseline.validate_origin_current(&allowed,&devices).unwrap_err().to_string().contains("automatic NAT"));
        baseline.automatic_nat=json!({"wan":"eth0","lan":["eth1"]});
        assert!(baseline.validate_origin_current(&allowed,&devices).is_err(),"the second authoritative WAN may not disappear at adoption");
        baseline.automatic_nat=serde_json::to_value(baseline.roles.roles.adopted_nat(&devices).unwrap()).unwrap();
        baseline.validate_origin_current(&allowed,&devices).unwrap();
        baseline.automatic_nat=json!({"wan":"eth1","lan":["eth0"]});
        assert!(baseline.validate_origin_current(&allowed,&devices).is_err(),"an existing reversed policy is not automatically adopted");
    }
    #[test]
    fn startup_association_binds_real_observed_pid_profile_context_and_registration_without_caller_readiness() {
        let instance=uuid::Uuid::new_v4();let spec=StartupSpec::new(uuid::Uuid::new_v4(),"a".repeat(64),"b".repeat(64)).unwrap();
        let profile=format!("profile-{}",uuid::Uuid::new_v4());let roles=Observation::new(instance,1,view(vec![])).unwrap();
        let original=json!({"schemaVersion":1,"operationId":spec.operation_id,"planSha256":spec.plan_sha256,"nonce":spec.nonce,
            "observerInstanceId":uuid::Uuid::new_v4(),"profileId":profile,"processId":4321,"frameworkStartLevel":6,"ordinaryLoad":true});
        StartupAssociation::new(instance,1,original.clone()).unwrap().require(&spec,&profile,4321,&roles).unwrap();
        for (key,value) in [("processId",json!(4322)),("profileId",json!(format!("profile-{}",uuid::Uuid::new_v4()))),
            ("nonce",json!("c".repeat(64))),("planSha256",json!("d".repeat(64))),("frameworkStartLevel",json!(4)),("ordinaryLoad",json!(false))] {
            let mut bad=original.clone();bad[key]=value;
            assert!(StartupAssociation::new(instance,1,bad).unwrap().require(&spec,&profile,4321,&roles).is_err());
        }
        for (peer,epoch) in [(uuid::Uuid::new_v4(),1),(instance,2)] {
            assert!(StartupAssociation::new(peer,epoch,original.clone()).unwrap().require(&spec,&profile,4321,&roles).is_err());
        }
        let mut extra=original.clone();extra["ready"]=json!(true);assert!(StartupAssociation::new(instance,1,extra).is_err());
        let mut bad=original;bad["processId"]=json!("4321");assert!(StartupAssociation::new(instance,1,bad).is_err());
    }
}
