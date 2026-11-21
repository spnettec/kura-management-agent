//! Read-only NFT_MSG_GETRULE dumps. Preserve opaque expression data; normalize
//! only documented traffic counters and placement already bound by JSON order.
use super::*;
use kura_firewall_policy::netlink::{attributes as attrs, attribute_text as text};
use std::time::Instant;
pub(in crate::nm) mod wire;
pub(in crate::nm) mod writer;
pub(super) mod matcher;

#[derive(Clone,Deserialize,Serialize,PartialEq,Eq,PartialOrd,Ord)]
#[serde(deny_unknown_fields,rename_all="camelCase")]
pub(super) struct Fingerprint {pub family:String,pub table:String,pub chain:String,pub handle:u64,pub sha256:String,#[serde(default,skip_serializing_if="Option::is_none")]pub payload_hex:Option<String>}
#[cfg(test)]
const NEW_RULE:u16=10*256+6;
const SEQUENCE:u32=0x594f4630;

#[cfg(test)]
fn u16n(b:&[u8])->u16 {u16::from_ne_bytes(b[..2].try_into().unwrap())}
fn u32n(b:&[u8])->u32 {u32::from_ne_bytes(b[..4].try_into().unwrap())}
fn one<'a>(v:&[(u16,&'a [u8])],key:u16)->Result<&'a [u8]> {
    let values=v.iter().filter(|(t,_)|t&0x3fff==key).collect::<Vec<_>>();
    ensure!(values.len()==1,"CONFLICT: missing/duplicate Netfilter identity");Ok(values[0].1)
}
fn encoded(t:u16,payload:&[u8],out:&mut Vec<u8>) {
    out.extend_from_slice(&t.to_be_bytes());out.extend_from_slice(&(payload.len() as u32).to_be_bytes());out.extend_from_slice(payload);
}
fn expressions(b:&[u8])->Result<Vec<u8>> {
    let mut result=Vec::new();
    for (kind,data) in attrs(b)? {
        ensure!(kind&0x3fff==1,"CONFLICT: unknown Netfilter expression list item");
        let fields=attrs(data)?;let name=text(one(&fields,1)?)?;let mut entry=Vec::new();
        for (t,data) in fields {
            if t&0x3fff==2 && name=="counter" {
                let mut counter=Vec::new();let mut known=BTreeSet::new();
                for (k,value) in attrs(data)? {
                    match k&0x3fff {
                        1|2=>{ensure!(value.len()==8 && known.insert(k&0x3fff),"CONFLICT: invalid Netfilter traffic counter");encoded(k,&[0;8],&mut counter);},
                        3=>ensure!(value.is_empty(),"CONFLICT: Netfilter counter padding"),
                        _=>encoded(k,value,&mut counter),
                    }
                }
                ensure!(known.len()==2,"CONFLICT: incomplete Netfilter traffic counter");encoded(t,&counter,&mut entry);
            }else{encoded(t,data,&mut entry);}
        }
        encoded(kind,&entry,&mut result);
    }
    Ok(result)
}
fn normalized_expressions(b:&[u8])->Result<Vec<u8>> {
    let mut out=Vec::new();
    for (kind,data) in attrs(b)? {
        let fields=attrs(data)?;let counter=text(one(&fields,1)?)?=="counter";let mut expression=Vec::new();
        for (t,data) in fields {
            if counter && t&0x3fff==2 {
                let mut counts=Vec::new();for (k,value) in attrs(data)? {
                    if [1,2].contains(&(k&0x3fff)) {ensure!(value.len()==8,"CONFLICT: raw counter shape");counts.extend(wire::attribute(k,&[0;8]));}
                    else if k&0x3fff!=3 {counts.extend(wire::attribute(k,value));}
                }
                expression.extend(wire::attribute(t,&counts));
            }else{expression.extend(wire::attribute(t,data));}
        }
        out.extend(wire::attribute(kind,&expression));
    }
    Ok(out)
}
pub(super) fn decode(text:&str)->Result<Vec<u8>> {
    ensure!(text.len()<=16384 && text.len().is_multiple_of(2) && text.bytes().all(|v|v.is_ascii_digit()||(b'a'..=b'f').contains(&v)),"CONFLICT: bounded raw rule hex");
    (0..text.len()).step_by(2).map(|i|u8::from_str_radix(&text[i..i+2],16).map_err(Into::into)).collect()
}
pub(super) fn validate_payload(f:&Fingerprint)->Result<()> {
    let Some(payload)=&f.payload_hex else {return Ok(());};let actual=rule(&decode(payload)?)?;
    ensure!(actual==*f,"CONFLICT: raw parameter payload does not match its canonical identity/hash");Ok(())
}
#[cfg(test)]
pub(super) fn fixture_fingerprint(payload:&str)->Fingerprint {rule(&decode(payload).unwrap()).unwrap()}
pub(super) fn inverse_supported(payload:&str)->Result<()> {
    let b=decode(payload)?;rule(&b)?;
    ensure!(attrs(&b[4..])?.iter().all(|(t,_)|(1..=8).contains(&(t&0x3fff))),"UNSUPPORTED: selected raw rule contains non-restorable outer attributes");Ok(())
}
pub(super) fn same_semantics(a:&str,b:&str)->Result<bool> {
    fn semantic(s:&str)->Result<Vec<u8>> {
        let b=decode(s)?;let r=rule(&b)?;let b=decode(r.payload_hex.as_ref().unwrap())?;let mut result=vec![b[0],0];
        for (t,data) in attrs(&b[4..])? {if ![3,6,8].contains(&(t&0x3fff)){encoded(t,data,&mut result);}}Ok(result)
    }
    Ok(semantic(a)?==semantic(b)?)
}
fn rule(body:&[u8])->Result<Fingerprint> {
    ensure!(body.len()>=4 && body[1]==0,"CONFLICT: Netfilter rule header");
    let family=match body[0] {1=>"inet",2=>"ip",3=>"arp",5=>"netdev",7=>"bridge",10=>"ip6",_=>anyhow::bail!("UNSUPPORTED: Netfilter rule family")};
    let fields=attrs(&body[4..])?;let table=text(one(&fields,1)?)?;let chain=text(one(&fields,2)?)?;
    let handle=one(&fields,3)?;ensure!(handle.len()==8,"CONFLICT: Netfilter handle");let handle=u64::from_be_bytes(handle.try_into().unwrap());
    ensure!(handle>0,"CONFLICT: zero Netfilter handle");let mut canonical=vec![body[0],0];let mut seen=BTreeSet::new();
    for (t,data) in fields {
        ensure!(seen.insert(t&0x3fff),"CONFLICT: duplicate Netfilter rule attribute");
        match t&0x3fff {
            4=>encoded(t,&expressions(data)?,&mut canonical),
            // Position is bound by ordered JSON rule identities, not by the
            // previous handle which legitimately changes during a delta.
            6=>ensure!(data.len()==8,"CONFLICT: Netfilter position"),
            8=>ensure!(data.is_empty(),"CONFLICT: Netfilter rule padding"),
            _=>encoded(t,data,&mut canonical),
        }
    }
    let mut payload=vec![body[0],0,0,0];
    for (t,data) in attrs(&body[4..])? {if t&0x3fff==4 {payload.extend(wire::attribute(t,&normalized_expressions(data)?));}else if ![6,8].contains(&(t&0x3fff)){payload.extend(wire::attribute(t,data));}}
    Ok(Fingerprint{family:family.into(),table,chain,handle,sha256:durable::hash(&canonical),payload_hex:Some(payload.iter().map(|v|format!("{v:02x}")).collect())})
}
fn messages(packet: &[u8], result: &mut Vec<Fingerprint>) -> Result<bool> {
    kura_firewall_policy::transport::visit_rule_packet(packet, SEQUENCE, |payload| {
        ensure!(result.len()<8192,"RESOURCE_EXHAUSTED: Netfilter rules");
        result.push(rule(payload)?);
        Ok(())
    })
}

pub(in crate::nm) fn observe(read:impl FnOnce()->Result<Value>,deadline:Instant)->Result<Value> {
    let generation=wire::generation(deadline)?;let before=wire::dump(deadline)?;let mut json=read()?;
    ensure!(json.as_object().is_some_and(|v|v.len()==1&&v.contains_key("nftables")),"CONFLICT: native JSON envelope");
    let after=wire::dump(deadline)?;ensure!(generation==wire::generation(deadline)? && before==after,"CONFLICT: Netfilter rules changed during JSON observation");
    json["ruleFingerprints"]=serde_json::to_value(after)?;json["kernelGeneration"]=json!(generation);Snapshot::read(&json)?;Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn nla(t:u16,b:&[u8])->Vec<u8> {let mut v=Vec::new();v.extend_from_slice(&((b.len()+4) as u16).to_ne_bytes());v.extend_from_slice(&t.to_ne_bytes());v.extend_from_slice(b);v.resize((v.len()+3)&!3,0);v}
    pub(super) fn body(parameter:u8,packets:u64)->Vec<u8> {
        let mut counter=nla(1,&7u64.to_be_bytes());counter.extend(nla(2,&packets.to_be_bytes()));
        let mut count=nla(1,b"counter\0");count.extend(nla(0x8002,&counter));
        let mut opaque=nla(1,b"target\0");opaque.extend(nla(0x8002,&nla(3,&[parameter,9,8,7])));
        let mut expr=nla(0x8001,&opaque);expr.extend(nla(0x8001,&count));
        let mut b=vec![2,0,0,0];b.extend(nla(1,b"mangle\0"));b.extend(nla(2,b"PREROUTING\0"));b.extend(nla(3,&10u64.to_be_bytes()));b.extend(nla(0x8004,&expr));b
    }
    #[test]
    fn opaque_parameters_are_bound_even_when_json_names_match_and_only_traffic_counters_are_ignored() {
        assert_eq!(rule(&body(1,3)).unwrap().sha256,rule(&body(1,999)).unwrap().sha256);
        assert_ne!(rule(&body(1,3)).unwrap().sha256,rule(&body(9,3)).unwrap().sha256);
        let mut invalid=body(1,3);invalid.pop();assert!(rule(&invalid).is_err());
        let mut duplicate=body(1,3);duplicate.extend(nla(3,&10u64.to_be_bytes()));assert!(rule(&duplicate).is_err());
    }
    #[test]
    fn raw_inverse_payload_preserves_all_parameters_and_binds_its_hash_without_counter_noise() {
        let a=rule(&body(1,3)).unwrap();let b=rule(&body(1,999)).unwrap();assert_eq!(a.payload_hex,b.payload_hex);validate_payload(&a).unwrap();
        assert!(!same_semantics(a.payload_hex.as_ref().unwrap(),rule(&body(9,3)).unwrap().payload_hex.as_ref().unwrap()).unwrap());
        let mut forged=a.clone();forged.sha256="f".repeat(64);assert!(validate_payload(&forged).is_err());
        let mut moved=decode(a.payload_hex.as_ref().unwrap()).unwrap();let fields=attrs(&moved[4..]).unwrap();let mut normalized=vec![2,0,0,0];let replacement=77u64.to_be_bytes();for (t,data) in fields {normalized.extend(nla(t,if t&0x3fff==3{&replacement}else{data}));}moved=normalized;
        let moved=rule(&moved).unwrap();assert_ne!(a.sha256,moved.sha256);assert!(same_semantics(a.payload_hex.as_ref().unwrap(),moved.payload_hex.as_ref().unwrap()).unwrap());
        let mut future=body(1,3);future.extend(nla(44,&[9,8]));let future=rule(&future).unwrap();assert!(inverse_supported(future.payload_hex.as_ref().unwrap()).is_err());
    }
    #[test]
    fn malformed_or_interrupted_dump_cannot_become_a_complete_witness() {
        let mut msg=Vec::new();let body=body(1,3);msg.extend_from_slice(&((body.len()+16) as u32).to_ne_bytes());msg.extend_from_slice(&NEW_RULE.to_ne_bytes());msg.extend_from_slice(&2u16.to_ne_bytes());msg.extend_from_slice(&SEQUENCE.to_ne_bytes());msg.extend_from_slice(&0u32.to_ne_bytes());msg.extend(body);let mut rows=Vec::new();assert!(!messages(&msg,&mut rows).unwrap());assert_eq!(rows.len(),1);
        let mut wrong=msg.clone();wrong[8]^=1;assert!(messages(&wrong,&mut Vec::new()).is_err());
        let mut interrupted=msg.clone();interrupted[6]|=0x10;assert!(messages(&interrupted,&mut Vec::new()).is_err());
        let mut short=msg;short.pop();assert!(messages(&short,&mut Vec::new()).is_err());
    }
}
