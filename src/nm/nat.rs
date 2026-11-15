//! Single-WAN compatibility and explicit multi-WAN automatic NAT policy.
use super::*;
use super::roles::NatPair;
use std::collections::BTreeSet;
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(untagged,deny_unknown_fields)]
pub(super) enum NatSet {
    Legacy {wan:String,lan:Vec<String>},
    Matrix {#[serde(rename="schemaVersion")] schema_version:u8,pairs:Vec<NatPair>},
}
fn valid_name(s:&str)->bool {!s.is_empty() && s.len()<=15 && s.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b))}
impl NatSet {
    pub(super) fn pairs(&self)->Result<BTreeSet<NatPair>> {
        let pairs=match self {
            Self::Legacy{wan,lan}=>{
                ensure!(!lan.is_empty() && lan.len()<=16,"INVALID_ARGUMENT: NAT downstream bounds");
                lan.iter().map(|l|NatPair{wan:wan.clone(),lan:l.clone()}).collect::<Vec<_>>()
            },
            Self::Matrix{schema_version,pairs}=>{
                ensure!(*schema_version==2 && !pairs.is_empty() && pairs.len()<=256,"INVALID_ARGUMENT: NAT matrix bounds");pairs.clone()
            },
        };
        let mut unique=BTreeSet::new();
        for pair in pairs {
            ensure!(valid_name(&pair.wan) && valid_name(&pair.lan) && pair.wan!=pair.lan && unique.insert(pair),"INVALID_ARGUMENT: NAT endpoint or duplicate pair");
        }
        Ok(unique)
    }
    pub(super) fn from_pairs(pairs:BTreeSet<NatPair>)->Result<Option<Self>> {
        if pairs.is_empty(){return Ok(None);}
        let outputs:BTreeSet<_>=pairs.iter().map(|p|p.wan.clone()).collect();
        let value=if outputs.len()==1 {Self::Legacy{wan:outputs.into_iter().next().unwrap().to_owned(),lan:pairs.into_iter().map(|p|p.lan).collect()}}
            else {Self::Matrix{schema_version:2,pairs:pairs.into_iter().collect()}};
        value.pairs()?;Ok(Some(value))
    }
    pub(super) fn render(&self)->Result<String> {
        let mut text=String::from("destroy table inet yofc_nm\ntable inet yofc_nm {\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n");
        for pair in self.pairs()? {text.push_str(&format!("    iifname \"{}\" oifname \"{}\" masquerade comment \"yofc nm auto\"\n",pair.lan,pair.wan));}
        text.push_str("  }\n}\n");Ok(text)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_wire_shape_is_retained_while_matrix_has_explicit_identity() {
        let old=json!({"wan":"eth0","lan":["eth1"]});let parsed:NatSet=serde_json::from_value(old.clone()).unwrap();assert_eq!(serde_json::to_value(&parsed).unwrap(),old);
        let pairs=BTreeSet::from([NatPair{lan:"eth1".into(),wan:"eth0".into()},NatPair{lan:"eth1".into(),wan:"eth2".into()}]);
        let matrix=NatSet::from_pairs(pairs.clone()).unwrap().unwrap();assert_eq!(matrix.pairs().unwrap(),pairs);
        let wire=serde_json::to_value(&matrix).unwrap();assert_eq!(wire["schemaVersion"],2);assert_eq!(wire["pairs"].as_array().unwrap().len(),2);
        let text=matrix.render().unwrap();assert_eq!(text.matches("masquerade").count(),2);
        assert!(text.contains("oifname \"eth0\""));assert!(text.contains("oifname \"eth2\""));
    }
    #[test]
    fn duplicate_unknown_version_mixed_shapes_and_bad_endpoints_cannot_render() {
        for bad in [json!({"schemaVersion":1,"pairs":[{"lan":"eth1","wan":"eth0"}]}),json!({"schemaVersion":2,"pairs":[]}),json!({"wan":"eth0","lan":["eth1","eth1"]}),json!({"wan":"eth0\nflush ruleset","lan":["eth1"]}),json!({"wan":"eth0","lan":["eth0"]})] {
            assert!(serde_json::from_value::<NatSet>(bad).ok().is_none_or(|v|v.render().is_err()));
        }
        assert!(serde_json::from_value::<NatSet>(json!({"wan":"eth0","lan":["eth1"],"schemaVersion":2,"pairs":[]})).is_err());
    }
}
