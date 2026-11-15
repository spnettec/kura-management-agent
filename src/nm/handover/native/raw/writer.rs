//! Bounded wire adapter for the existing reviewed native delta. No parser for
//! command text,no foreign table reconstruction,and no userspace send retries.
use super::*;
use wire::{attribute as a,message};
const FIRST:u32=0x594f4600;
fn keys(v:&Value,allowed:&[&str])->Result<()> {ensure!(v.as_object().is_some_and(|v|v.keys().all(|k|allowed.contains(&k.as_str()))),"UNSUPPORTED: native wire fields");Ok(())}
fn string(v:&Value)->Result<&str> {v.as_str().filter(|s|!s.is_empty()&&s.len()<=255&&!s.as_bytes().contains(&0)).context("INVALID_ARGUMENT: native wire string")}
fn z(v:&Value)->Result<Vec<u8>> {let mut b=string(v)?.as_bytes().to_vec();b.push(0);Ok(b)}
fn u32v(v:&Value)->Result<u32> {v.as_u64().filter(|v|*v<=u32::MAX as u64).map(|v|v as u32).context("INVALID_ARGUMENT: native integer")}
fn n(t:u16,v:u32)->Vec<u8> {a(t,&v.to_be_bytes())}
fn data(t:u16,b:&[u8])->Vec<u8> {a(0x8000|t,&a(1,b))}
fn expression(name:&str,body:&[u8])->Vec<u8> {let mut b=a(1,&[name.as_bytes(),&[0]].concat());b.extend(a(0x8002,body));a(0x8001,&b)}
fn immediate(register:u32,b:&[u8])->Vec<u8> {expression("immediate",&[n(1,register),data(2,b)].concat())}
fn cmp(op:u32,b:&[u8])->Vec<u8> {expression("cmp",&[n(1,1),n(2,op),data(3,b)].concat())}
fn meta(key:u32)->Vec<u8> {expression("meta",&[n(1,1),n(2,key)].concat())}
fn bitwise(mask:&[u8])->Vec<u8> {expression("bitwise",&[n(1,1),n(2,1),n(3,mask.len() as u32),data(4,mask),data(5,&vec![0;mask.len()])].concat())}
fn protocol(name:&str)->Result<u8> {match name {"tcp"=>Ok(6),"udp"=>Ok(17),"icmp"=>Ok(1),"icmpv6"|"ipv6-icmp"=>Ok(58),_=>anyhow::bail!("UNSUPPORTED: native transport protocol")}}
fn ip(v:&Value,family:u8)->Result<Vec<u8>> {
    let address:std::net::IpAddr=string(v)?.parse()?;
    match address {std::net::IpAddr::V4(v) if family==2=>Ok(v.octets().to_vec()),std::net::IpAddr::V6(v) if family==10=>Ok(v.octets().to_vec()),_=>anyhow::bail!("INVALID_ARGUMENT: native IP family")}
}
enum Kind {Byte,Version,Port,Mac,Address(u8),Name,NativeU32,State}
fn mac(v:&Value)->Result<Vec<u8>> {
    let value=string(v)?;
    ensure!(value.len()==17&&value.split(':').count()==6
        &&value.split(':').all(|part|part.len()==2&&part.bytes().all(|c|c.is_ascii_hexdigit())),
        "INVALID_ARGUMENT: native Ethernet address");
    value.split(':').map(|part|u8::from_str_radix(part,16).map_err(Into::into)).collect()
}
fn interface_name(v:&Value)->Result<Vec<u8>> {
    let value=string(v)?;let prefix=value.strip_suffix('*');let stem=prefix.unwrap_or(value);
    ensure!(!stem.is_empty()&&value.len()<=15
        &&stem.bytes().all(|c|c.is_ascii_alphanumeric()||b"_.:-".contains(&c)),
        "UNSUPPORTED: native bounded interface name/prefix");
    let mut bytes=stem.as_bytes().to_vec();
    // nft compares a prefix without a terminator; an exact name includes NUL.
    if prefix.is_none(){bytes.push(0);}
    Ok(bytes)
}
fn left(v:&Value,family:u8,out:&mut Vec<u8>)->Result<Kind> {
    ensure!(v.as_object().is_some_and(|v|v.len()==1),"UNSUPPORTED: native match lhs");
    if let Some(v)=v.get("meta") {
        keys(v,&["key"])?;let key=string(&v["key"])?;
        let (number,kind)=match key {"iifname"=>(6,Kind::Name),"oifname"=>(7,Kind::Name),"l4proto"=>(16,Kind::Byte),"nfproto"=>(15,Kind::Byte),"mark"=>(3,Kind::NativeU32),_=>anyhow::bail!("UNSUPPORTED: native meta key")};out.extend(meta(number));return Ok(kind);
    }
    if let Some(v)=v.get("ct") {keys(v,&["key"])?;ensure!(v["key"]=="state","UNSUPPORTED: native conntrack key");out.extend(expression("ct",&[n(1,1),n(2,0)].concat()));return Ok(Kind::State);}
    let v=v.get("payload").context("UNSUPPORTED: native payload match")?;keys(v,&["protocol","field"])?;
    let protocol_name=string(&v["protocol"])?;let field=string(&v["field"])?;
    if let Some(required)=match protocol_name {"ip"|"icmp"=>Some(2),"ip6"|"icmpv6"=>Some(10),_=>None} {
        ensure!(family==1||family==required,"INVALID_ARGUMENT: native payload protocol family");
        if family==1 {out.extend(meta(15));out.extend(cmp(0,&[required]));}
    }
    let (base,offset,length,kind)=match (protocol_name,field) {
        ("ip"|"ip6","version")=>(1,0,1,Kind::Version),
        ("ip","saddr")=>(1,12,4,Kind::Address(2)),("ip","daddr")=>(1,16,4,Kind::Address(2)),
        ("ip6","saddr")=>(1,8,16,Kind::Address(10)),("ip6","daddr")=>(1,24,16,Kind::Address(10)),
        ("ether","saddr"|"daddr")=>{
            out.extend(meta(8));out.extend(cmp(0,&1u16.to_ne_bytes()));
            (0,if field=="saddr"{6}else{0},6,Kind::Mac)
        },
        ("tcp"|"udp","sport"|"dport")=>{out.extend(meta(16));out.extend(cmp(0,&[protocol(protocol_name)?]));(2,if field=="sport"{0}else{2},2,Kind::Port)},
        ("icmp"|"icmpv6","type"|"code")=>{out.extend(meta(16));out.extend(cmp(0,&[protocol(protocol_name)?]));(2,if field=="type"{0}else{1},1,Kind::Byte)},
        _=>anyhow::bail!("UNSUPPORTED: native payload field/family"),
    };out.extend(expression("payload",&[n(1,1),n(2,base),n(3,offset),n(4,length)].concat()));
    if matches!(&kind,Kind::Version){out.extend(bitwise(&[0xf0]));}
    Ok(kind)
}
fn scalar(v:&Value,kind:&Kind)->Result<Vec<u8>> {match kind {
    Kind::Byte=>{let value=if let Some(s)=v.as_str(){match s {"ipv4"=>2,"ipv6"=>10,_=>protocol(s)? as u32}}else{u32v(v)?};ensure!(value<=255,"INVALID_ARGUMENT: native byte");Ok(vec![value as u8])},
    Kind::Version=>{let value=u32v(v)?;ensure!(value<=15,"INVALID_ARGUMENT: native IP version nibble");Ok(vec![(value as u8)<<4])},
    Kind::Port=>{let value=u32v(v)?;ensure!(value<=65535,"INVALID_ARGUMENT: native port");Ok((value as u16).to_be_bytes().to_vec())},
    Kind::Mac=>mac(v),Kind::Address(f)=>ip(v,*f),Kind::Name=>interface_name(v),
    Kind::NativeU32=>Ok(u32v(v)?.to_ne_bytes().to_vec()),Kind::State=>anyhow::bail!("UNSUPPORTED: scalar conntrack state"),
}}
fn match_expression(v:&Value,family:u8,out:&mut Vec<u8>)->Result<()> {
    keys(v,&["op","left","right"])?;let kind=left(&v["left"],family,out)?;let op=string(&v["op"])?;let right=&v["right"];
    if matches!(&kind,Kind::Name) {
        ensure!(["==","!="].contains(&op),"UNSUPPORTED: native interface comparison");
        out.extend(cmp(if op=="=="{0}else{1},&interface_name(right)?));return Ok(());
    }
    if matches!(kind,Kind::State) {
        ensure!(["in","==","!=","not in"].contains(&op),"UNSUPPORTED: conntrack operator");keys(right,&["set"])?;let values=right.get("set").and_then(Value::as_array).filter(|v|!v.is_empty()&&v.len()<=4).context("UNSUPPORTED: bounded explicit conntrack state set")?;let mut mask=0u32;
        for v in values {mask|=match string(v)? {"established"=>2,"related"=>4,"new"=>8,"invalid"=>1,_=>anyhow::bail!("UNSUPPORTED: native conntrack state")};}
        ensure!(mask>0,"INVALID_ARGUMENT: empty state set");out.extend(bitwise(&mask.to_ne_bytes()));out.extend(cmp(if ["!=","not in"].contains(&op){0}else{1},&0u32.to_ne_bytes()));return Ok(());
    }
    if let Some(prefix)=right.get("prefix") {
        keys(right,&["prefix"])?;keys(prefix,&["addr","len"])?;ensure!(["==","!=","in","not in"].contains(&op),"UNSUPPORTED: prefix operator");let Kind::Address(f)=kind else{anyhow::bail!("UNSUPPORTED: prefix on non-address");};let mut addr=ip(&prefix["addr"],f)?;let len=u32v(&prefix["len"])? as usize;ensure!(len<=addr.len()*8,"INVALID_ARGUMENT: prefix length");let mut mask=vec![0;addr.len()];for (i,m) in mask.iter_mut().enumerate(){*m=if len>=i*8+8{255}else if len>i*8{255<<(8-(len-i*8))}else{0};addr[i]&=*m;}out.extend(bitwise(&mask));out.extend(cmp(if ["!=","not in"].contains(&op){1}else{0},&addr));return Ok(());
    }
    if let Some(range)=right.get("range") {keys(right,&["range"])?;let range=range.as_array().filter(|v|v.len()==2).context("INVALID_ARGUMENT: native range")?;let op=match op {"=="|"in"=>0,"!="|"not in"=>1,_=>anyhow::bail!("UNSUPPORTED: native range operator")};out.extend(expression("range",&[n(1,1),n(2,op),data(3,&scalar(&range[0],&kind)?),data(4,&scalar(&range[1],&kind)?)].concat()));return Ok(());}
    let op=match op {"=="=>0,"!="=>1,"<"=>2,"<="=>3,">"=>4,">="=>5,_=>anyhow::bail!("UNSUPPORTED: native comparison operator")};out.extend(cmp(op,&scalar(right,&kind)?));Ok(())
}
fn header_protocol(v:&Value)->Result<u32> {
    keys(v,&["protocol"])?;match string(&v["protocol"])? {"tcp"=>Ok(6),"udp"=>Ok(17),_=>anyhow::bail!("UNSUPPORTED: bounded transport header protocol")}
}
fn icmp_protocol(v:&Value)->Result<u32> {
    keys(v,&["protocol","type","codeFirst","codeLast","inverted"])?;
    match string(&v["protocol"])? {"icmp"=>Ok(1),"icmpv6"=>Ok(58),_=>anyhow::bail!("UNSUPPORTED: bounded ICMP module protocol")}
}
fn creation_context(proto:u32)->Vec<u8> {a(0x8005,&[n(1,proto),n(2,0)].concat())}
fn expression_context(v:&Value)->Result<Option<u32>> {
    let mut proto=None;
    for term in v.as_array().context("INVALID_ARGUMENT: expression context")? {
        let next=if let Some(value)=term.get("transportHeader"){Some(header_protocol(value)?)}else if let Some(value)=term.get("icmpHeader"){Some(icmp_protocol(value)?)}else{None};
        if let Some(next)=next {ensure!(proto.is_none_or(|old|old==next),"UNSUPPORTED: conflicting transport header protocols");proto=Some(next);}
    }
    Ok(proto)
}
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
fn expressions(v:&Value,family:u8)->Result<Vec<u8>> {
    let mut out=Vec::new();let terms=v.as_array().filter(|v|!v.is_empty()&&v.len()<=256).context("INVALID_ARGUMENT: native expression list")?;
    for term in terms {
        ensure!(term.as_object().is_some_and(|v|v.len()==1),"INVALID_ARGUMENT: native expression object");let (name,value)=term.as_object().unwrap().iter().next().unwrap();
        match name.as_str() {
            "accept"|"drop"|"return"=>{ensure!(value.is_null(),"UNSUPPORTED: native verdict arguments");let code=match name.as_str(){"accept"=>1i32,"drop"=>0,_=>-5};out.extend(expression("immediate",&[n(1,0),a(0x8002,&a(0x8002,&a(1,&code.to_be_bytes())))].concat()));},
              "jump"=>{keys(value,&["target"])?;let target=string(&value["target"])?;ensure!(!target.is_empty()&&target.len()<=255&&target.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.:-".contains(&b)),"UNSUPPORTED: native jump target");let verdict=[a(1,&(-3i32).to_be_bytes()),a(2,&z(&value["target"])?)].concat();out.extend(expression("immediate",&[n(1,0),a(0x8002,&a(0x8002,&verdict))].concat()));},
            "counter"=>{keys(value,&["packets","bytes"])?;for key in ["packets","bytes"] {ensure!(value[key].as_u64().is_some(),"INVALID_ARGUMENT: native counter");}out.extend(expression("counter",&[a(1,&value["bytes"].as_u64().unwrap().to_be_bytes()),a(2,&value["packets"].as_u64().unwrap().to_be_bytes())].concat()));},
            "match"=>match_expression(value,family,&mut out)?,
                  "transportHeader"=>{let proto=header_protocol(value)?;out.extend(meta(16));out.extend(cmp(0,&[proto as u8]));let name=if proto==6{"tcp"}else{"udp"};let info=[0,0,255,255,0,0,255,255,0,0,0,0,0,0,0,0];out.extend(expression("match",&[a(1,&z(&json!(name))?),n(2,0),a(3,&info)].concat()));},
                  "icmpHeader"=>{let proto=icmp_protocol(value)?;ensure!(family==if proto==1{2}else{10},"UNSUPPORTED: bounded ICMP header family");let kind=u32v(&value["type"])?;let first=u32v(&value["codeFirst"])?;let last=u32v(&value["codeLast"])?;let inverted=value["inverted"].as_bool().context("INVALID_ARGUMENT: ICMP inversion")?;ensure!(kind<=255&&first<=last&&last<=255&&(!inverted||(first==0&&last==255))&&!(proto==1&&kind==255&&inverted),"UNSUPPORTED: bounded ICMP type/code scope");out.extend(meta(16));out.extend(cmp(0,&[proto as u8]));let name=if proto==1{"icmp"}else{"icmp6"};let info=[kind as u8,first as u8,last as u8,u8::from(inverted),0,0,0,0];out.extend(expression("match",&[a(1,&z(&json!(name))?),n(2,0),a(3,&info)].concat()));},
            "masquerade"=>{ensure!(value.is_null()||value.as_object().is_some_and(|v|v.is_empty()),"UNSUPPORTED: native masquerade options");out.extend(expression("masq",&[]));},
            "mangle"=>{keys(value,&["key","value"])?;ensure!(value["key"]==json!({"meta":{"key":"mark"}}),"UNSUPPORTED: native mangle key");out.extend(immediate(1,&u32v(&value["value"])?.to_ne_bytes()));out.extend(expression("meta",&[n(2,3),n(3,1)].concat()));},
            "snat"|"dnat"=>{keys(value,&["addr","port","family"])?;let actual_family=match value.get("family").and_then(Value::as_str) {Some("ip")=>2,Some("ip6")=>10,None if [2,10].contains(&family)=>family,_=>anyhow::bail!("UNSUPPORTED: native NAT family")};let mut fields=[n(1,if name=="snat"{0}else{1}),n(2,actual_family as u32)].concat();out.extend(immediate(1,&ip(&value["addr"],actual_family)?));fields.extend(n(3,1));if let Some(port)=value.get("port"){out.extend(immediate(2,&scalar(port,&Kind::Port)?));fields.extend(n(5,2));}out.extend(expression("nat",&fields));},
            _=>anyhow::bail!("UNSUPPORTED: native expression has no bounded wire adapter"),
        }
    }
    ensure!(out.len()<=60000,"RESOURCE_EXHAUSTED: native encoded expressions");Ok(out)
}
fn family(v:&Value)->Result<u8> {match string(v)? {"ip"=>Ok(2),"ip6"=>Ok(10),"inet"=>Ok(1),_=>anyhow::bail!("UNSUPPORTED: native mutable family")}}
fn comment(v:&Value)->Result<Vec<u8>> {let b=z(v)?;ensure!(b.len()<=254,"INVALID_ARGUMENT: native comment");let mut u=vec![0,b.len() as u8];u.extend(b);Ok(u)}
fn chain(v:&Value)->Result<Vec<u8>> {
    keys(v,&["family","table","name","type","hook","prio","policy"])?;
    let mut out=[a(1,&z(&v["table"])?),a(3,&z(&v["name"])?)].concat();
    let fields=["type","hook","prio","policy"];
    if fields.iter().any(|key|v.get(*key).is_some()) {
        ensure!(fields.iter().all(|key|v.get(*key).is_some()),"INVALID_ARGUMENT: incomplete native base chain");
        let kind=string(&v["type"])?;ensure!(["filter","nat"].contains(&kind),"UNSUPPORTED: native chain type");
        let hook=string(&v["hook"])?;
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
fn command(value:&Value,seq:u32)->Result<Vec<u8>> {
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
                      b.extend(a(0x8004,&expressions(&v["expr"],family)?));
                      if let Some(proto)=expression_context(&v["expr"])?{b.extend(creation_context(proto));}
                      if let Some(c)=v.get("comment"){b.extend(a(7,&comment(c)?));}
                  }
            }else{ensure!(v.get("expr").is_none()&&v.get("originalRawRule").is_none()&&v.get("comment").is_none(),"INVALID_ARGUMENT: native deletion fields");}
            (if action=="delete"{8}else{6},flags,b)
        },
        _=>anyhow::bail!("UNSUPPORTED: native command outside original delta adapter"),
    };Ok(message(10*256+number,5|flags,seq,family,0,&payload))
}
pub(in crate::nm) fn encode(batch:&Value)->Result<(Vec<u8>,u32)> {
    keys(batch,&["nftables","expectedGeneration"])?;let generation=u32v(&batch["expectedGeneration"])?;ensure!(generation>0,"FORBIDDEN: native kernel generation required");let commands=batch["nftables"].as_array().filter(|v|!v.is_empty()&&v.len()<=8192).context("INVALID_ARGUMENT: native batch commands")?;
    let mut bytes=message(16,1,FIRST,0,10,&a(1,&generation.to_be_bytes()));
    for (i,cmd) in commands.iter().enumerate(){bytes.extend(command(cmd,FIRST+1+i as u32)?);ensure!(bytes.len()<=512*1024,"RESOURCE_EXHAUSTED: native encoded batch");}
    let end=FIRST+1+commands.len() as u32;bytes.extend(message(17,5,end,0,10,&[]));Ok((bytes,end))
}
pub(in crate::nm) fn dispatch(batch:&Value,deadline:Instant)->Result<()> {let (bytes,end)=encode(batch)?;wire::dispatch(&bytes,FIRST,end,deadline)}

/// Re-adjudicate a persisted original negative ACK against this exact batch.
pub(in crate::nm) fn rejection(batch:&Value,reply:&[u8])->Result<wire::Rejected> {
    let (_,end)=encode(batch)?;
    let error=wire::acknowledgement(reply,FIRST,end,&mut BTreeSet::new())
        .err().context("CONFLICT: original negative ACK required")?;
    error.downcast::<wire::Rejected>().map_err(|_|anyhow::anyhow!("CONFLICT: invalid original negative ACK"))
}

#[cfg(test)]
mod match_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generation_is_mandatory_and_unknown_commands_or_expressions_never_encode() {
        let valid=json!({"expectedGeneration":17,"nftables":[{"create":{"table":{"family":"inet","name":"receipt","comment":"bound"}}}]});
        let (bytes,end)=encode(&valid).unwrap();assert_eq!(u16n(&bytes[4..]),16);assert_eq!(u32::from_be_bytes(one(&attrs(&bytes[20..28]).unwrap(),1).unwrap().try_into().unwrap()),17);assert_eq!(end,FIRST+2);
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
