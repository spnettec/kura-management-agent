//! Bounded wire adapter for the existing reviewed native delta. No parser for
//! command text,no foreign table reconstruction,and no userspace send retries.
use super::*;
use wire::{attribute as a,message};
const FIRST:u32=0x594f4600;
use kura_firewall_policy::netlink::{
    bounded_string as string, check_fields as keys, compatibility_attribute as creation_context,
    integer_attribute as n, rule_attributes, string_attribute_value as z, unsigned_integer as u32v,
};

fn original_context(bytes:&[u8])->Result<Option<u32>> {
    let outer=attrs(&bytes[4..])?;let mut proto=None;
    for (_,item) in attrs(one(&outer,4)?)? {
        let fields=attrs(item)?;if text(one(&fields,1)?)?!="match"{continue;}
        let module=attrs(one(&fields,2)?)?;let name=text(one(&module,1)?)?;
        if let Some(next)=match name.as_str(){"tcp"=>Some(6),"udp"=>Some(17),"icmp"=>Some(1),"icmp6"=>Some(58),_=>None} {
            ensure!(proto.is_none_or(|old|old==next),"UNSUPPORTED: conflicting original module contexts");proto=Some(next);
        }
    }
    Ok(proto)
}
fn family(v:&Value)->Result<u8> {match string(v)? {"ip"=>Ok(2),"ip6"=>Ok(10),"inet"=>Ok(1),_=>anyhow::bail!("UNSUPPORTED: native mutable family")}}
fn comment(v:&Value)->Result<Vec<u8>> {let b=z(v)?;ensure!(b.len()<=254,"INVALID_ARGUMENT: native comment");let mut u=vec![0,b.len() as u8];u.extend(b);Ok(u)}
fn chain(v:&Value)->Result<Vec<u8>> {
    keys(v,&["family","table","name","type","hook","prio","policy"])?;
    let mut out=[a(1,&z(&v["table"])?),a(3,&z(&v["name"])?)].concat();
    let fields=["type","hook","prio","policy"];
    if fields.iter().any(|key|v.get(*key).is_some()) {
        ensure!(fields.iter().all(|key|v.get(*key).is_some()),"INVALID_ARGUMENT: incomplete native base chain");
        let kind=string(&v["type"])?;
        let hook=string(&v["hook"])?;
        ensure!(["filter","nat"].contains(&kind)||kind=="route"&&hook=="output"
            &&["ip","ip6"].contains(&string(&v["family"])?),"UNSUPPORTED: native chain type or route hook");
        let number=match hook {"prerouting"=>0,"input"=>1,"forward"=>2,"output"=>3,"postrouting"=>4,_=>anyhow::bail!("UNSUPPORTED: native base hook")};
        ensure!(kind!="nat"||hook!="forward","UNSUPPORTED: native NAT forward hook");
        let priority=i32::try_from(v["prio"].as_i64().context("INVALID_ARGUMENT: native signed priority")?)
            .context("INVALID_ARGUMENT: native priority range")?;
        let policy=match string(&v["policy"])? {"accept"=>1,"drop"=>0,_=>anyhow::bail!("INVALID_ARGUMENT: native policy")};
        out.extend(a(0x8004,&[n(1,number),n(2,priority as u32)].concat()));
        out.extend(n(5,policy));out.extend(a(7,&z(&v["type"])?));
    }
    Ok(out)
}
fn command(value:&Value,seq:u32,ack_flags:u16)->Result<Vec<u8>> {
    ensure!(value.as_object().is_some_and(|v|v.len()==1),"INVALID_ARGUMENT: native command");let (action,object)=value.as_object().unwrap().iter().next().unwrap();ensure!(object.as_object().is_some_and(|v|v.len()==1),"INVALID_ARGUMENT: native command object");let (kind,v)=object.as_object().unwrap().iter().next().unwrap();let family=family(&v["family"])?;
    let (number,flags,payload)=match (action.as_str(),kind.as_str()) {
        ("create"|"delete","table")=>{keys(v,&["family","name","comment"])?;let mut b=a(1,&z(&v["name"])?);if let Some(c)=v.get("comment"){ensure!(action=="create","INVALID_ARGUMENT: table delete comment");b.extend(a(6,&comment(c)?));}(if action=="create"{0}else{2},if action=="create"{0x600}else{0},b)},
        ("add","chain")=>(3,0x400,chain(v)?),
        ("add"|"insert"|"replace"|"delete","rule")=>{
            keys(v,&["family","table","chain","handle","expr","comment","originalRawRule"])?;
            let mut b=[a(1,&z(&v["table"])?),a(2,&z(&v["chain"])?)] .concat();
            let flags=match action.as_str(){"add"=>0xc00,"insert"=>0x400,"replace"=>0x100,_=>0};
            if let Some(handle)=v.get("handle"){let h=handle.as_u64().filter(|v|*v>0).context("INVALID_ARGUMENT: native command handle")?;b.extend(a(if action=="insert"{6}else{3},&h.to_be_bytes()));}
            else {ensure!(!["replace","delete"].contains(&action.as_str()),"INVALID_ARGUMENT: native handle required");}
            if action!="delete" {
                if let Some(raw)=v.get("originalRawRule") {
                    let raw=raw.as_str().context("CONFLICT: inverse raw bytes")?;inverse_supported(raw)?;let bytes=decode(raw)?;let r=rule(&bytes)?;ensure!(r.family==v["family"]&&r.table==v["table"]&&r.chain==v["chain"],"CONFLICT: inverse raw identity");
                    for (t,data) in attrs(&bytes[4..])? {if [4,5,7].contains(&(t&0x3fff)){b.extend(a(t,data));}}
                      // GETRULE omits validation-only rule compatibility data.
                      // Restore it for known protocol-specific original modules;
                      // original expression/userdata bytes remain untouched.
                      if !attrs(&bytes[4..])?.iter().any(|(tag,_)|tag&0x3fff==5)
                          && let Some(proto)=original_context(&bytes)? {b.extend(creation_context(proto));}
                  }else{
                      b.extend(rule_attributes(&v["expr"],family)?);
                      if let Some(c)=v.get("comment"){b.extend(a(7,&comment(c)?));}
                  }
            }else{ensure!(v.get("expr").is_none()&&v.get("originalRawRule").is_none()&&v.get("comment").is_none(),"INVALID_ARGUMENT: native deletion fields");}
            (if action=="delete"{8}else{6},flags,b)
        },
        _=>anyhow::bail!("UNSUPPORTED: native command outside original delta adapter"),
    };
    // Netfilter reports command errors even without NLM_F_ACK. Request one
    // success ACK at BATCH_END so large atomic batches cannot fill the receive
    // queue with a separate positive ACK for each command.
    Ok(message(10*256+number,1|ack_flags|flags,seq,family,0,&payload))
}
pub(in crate::nm) fn encode(batch:&Value)->Result<(Vec<u8>,u32)> {
    encode_with_ack_flags(batch,0)
}
fn encode_with_ack_flags(batch:&Value,ack_flags:u16)->Result<(Vec<u8>,u32)> {
    keys(batch,&["nftables","expectedGeneration"])?;let generation=u32v(&batch["expectedGeneration"])?;ensure!(generation>0,"FORBIDDEN: native kernel generation required");let commands=batch["nftables"].as_array().filter(|v|!v.is_empty()&&v.len()<=8192).context("INVALID_ARGUMENT: native batch commands")?;
    let mut bytes=message(16,1,FIRST,0,10,&a(1,&generation.to_be_bytes()));
    for (i,cmd) in commands.iter().enumerate(){bytes.extend(command(cmd,FIRST+1+i as u32,ack_flags)?);ensure!(bytes.len()<=512*1024,"RESOURCE_EXHAUSTED: native encoded batch");}
    let end=FIRST+1+commands.len() as u32;bytes.extend(message(17,5,end,0,10,&[]));Ok((bytes,end))
}
/// The original encoding has no version field. Recognize its exact previous
/// wire digest when reading retained authority. All new sends use `encode`.
pub(in crate::nm) fn matches_recorded_wire(batch:&Value,recorded:&str)->Result<bool> {
    Ok(durable::hash(&encode(batch)?.0)==recorded
        || durable::hash(&encode_with_ack_flags(batch,4)?.0)==recorded)
}
pub(in crate::nm) fn dispatch(batch:&Value,deadline:Instant)->Result<()> {let (bytes,end)=encode(batch)?;wire::dispatch(&bytes,FIRST,end,deadline)}

/// Re-adjudicate a persisted original negative ACK against this exact batch.
pub(in crate::nm) fn rejection(batch:&Value,reply:&[u8])->Result<wire::Rejected> {
    let (bytes,end)=encode(batch)?;
    negative_for_wire(&bytes,end,reply)
}

/// Recovery selects exactly the encoding whose digest was stored before dispatch.
pub(in crate::nm) fn recorded_rejection(batch:&Value,wire_digest:&str,reply:&[u8])->Result<wire::Rejected> {
    let (bytes,end)=encode(batch)?;
    if durable::hash(&bytes)==wire_digest {
        return negative_for_wire(&bytes,end,reply);
    }
    let (legacy,end)=encode_with_ack_flags(batch,4)?;
    ensure!(durable::hash(&legacy)==wire_digest,"CONFLICT: original negative ACK wire digest");
    negative_for_wire(&legacy,end,reply)
}

fn negative_for_wire(bytes:&[u8],end:u32,reply:&[u8])->Result<wire::Rejected> {
    let mut original=kura_firewall_policy::receipt::BatchReceipts::new(bytes,FIRST,end)?;
    let error=wire::acknowledgement(reply,&mut original)
        .err().context("CONFLICT: original negative ACK required")?;
    error.downcast::<wire::Rejected>().map_err(|_|anyhow::anyhow!("CONFLICT: invalid original negative ACK"))
}

#[cfg(test)]
mod match_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "requires a fresh disposable Linux namespace with NET_ADMIN and explicit fixture marker"]
    fn native_command_error_aborts_atomic_batch_with_end_only_ack() {
        use std::time::Duration;
        let proof = Path::new("/proof/end-only-ack");
        assert_eq!(fs::read(proof.join("owned")).unwrap(), b"fresh disposable end-only ack\n");
        let read = || observe(|| {
            let result = crate::process::run(Path::new("/usr/sbin/nft"),
                &["-j", "-p", "list", "ruleset"], None, Duration::from_secs(10))?;
            ensure!(result.status.success(), "fixture native ruleset observation failed");
            Ok(serde_json::from_slice(&result.stdout)?)
        }, Instant::now() + Duration::from_secs(10)).unwrap();
        let before = read();
        assert!(Snapshot::read(&before).unwrap().objects.is_empty());
        let create = json!({"create":{"table":{"family":"inet","name":"yofc_fixture_end_ack"}}});
        let batch = json!({"expectedGeneration":before["kernelGeneration"],"nftables":[create,create]});
        durable::publish_new(&proof.join("intent"), digest(&batch).unwrap().as_bytes(), FileMetadata::private()).unwrap();
        let error = dispatch(&batch, Instant::now() + Duration::from_secs(10)).unwrap_err();
        let rejected = error.downcast_ref::<wire::Rejected>().unwrap();
        assert_eq!(rejected.errno, libc::EEXIST);
        assert_eq!(rejected.sequence, FIRST + 2);
        assert_eq!(rejection(&batch, &rejected.reply).unwrap().reply_sha256, rejected.reply_sha256);
        assert_eq!(read(), before);
        let report = json!({"errno":rejected.errno,"rejectedSequence":rejected.sequence,
            "replySha256":rejected.reply_sha256,"kernelUnchanged":true});
        durable::publish_new(&proof.join("result.json"), &serde_json::to_vec(&report).unwrap(), FileMetadata::private()).unwrap();
        println!("{report}");
    }
    #[test]
    fn generation_is_mandatory_and_unknown_commands_or_expressions_never_encode() {
        let valid=json!({"expectedGeneration":17,"nftables":[{"create":{"table":{"family":"inet","name":"receipt","comment":"bound"}}}]});
        let (bytes,end)=encode(&valid).unwrap();assert_eq!(u16n(&bytes[4..]),16);assert_eq!(u32::from_be_bytes(one(&attrs(&bytes[20..28]).unwrap(),1).unwrap().try_into().unwrap()),17);assert_eq!(end,FIRST+2);
        let command = ((u32n(&bytes) as usize) + 3) & !3;
        let batch_end = command + (((u32n(&bytes[command..]) as usize) + 3) & !3);
        assert_eq!(u16n(&bytes[command+6..]) & 4,0);
        assert_eq!(u16n(&bytes[batch_end+6..]) & 4,4);
        let mut previous = bytes.clone();
        previous[command+6..command+8].copy_from_slice(&(u16n(&bytes[command+6..]) | 4).to_ne_bytes());
        assert!(matches_recorded_wire(&valid,&durable::hash(&previous)).unwrap());
        previous[command+8] ^= 1;
        assert!(!matches_recorded_wire(&valid,&durable::hash(&previous)).unwrap());
        for defect in ["zero","missing","flush","unknown","mixed","rule"] {
            let mut v=valid.clone();match defect {
                "zero"=>v["expectedGeneration"]=json!(0),"missing"=>{v.as_object_mut().unwrap().remove("expectedGeneration");},
                "flush"=>v["nftables"]=json!([{"flush":{"ruleset":null}}]),"unknown"=>v["ignored"]=json!(true),
                "mixed"=>v["nftables"][0]["delete"]=json!({"table":{"family":"inet","name":"foreign"}}),
                "rule"=>v["nftables"]=json!([{"add":{"rule":{"family":"ip","table":"filter","chain":"INPUT","expr":[{"unrecognized":true}]}}}]),_=>unreachable!(),
            }assert!(encode(&v).is_err(),"{defect}");
        }
    }
    #[test]
    fn inverse_raw_rule_must_match_the_original_family_table_and_chain() {
        let mut raw=super::super::tests::body(9,2);raw.extend(a(7,&[0;128]));let witness=rule(&raw).unwrap();let payload=witness.payload_hex.unwrap();assert!(payload.len()>255);
        let mut batch=json!({"expectedGeneration":3,"nftables":[{"replace":{"rule":{"family":"ip","table":"mangle","chain":"PREROUTING","handle":77,"expr":[{"xt":{"name":"opaque"}}],"originalRawRule":payload}}}]});
        assert!(encode(&batch).is_ok());batch["nftables"][0]["replace"]["rule"]["chain"]=json!("INPUT");assert!(encode(&batch).is_err());
    }
}
