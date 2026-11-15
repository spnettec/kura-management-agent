//! Read-only semantic witnesses for known pure model predicates. Unknown native
//! expressions remain opaque and cannot become a managed selection.
use super::*;
mod compat;

#[derive(Clone,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub(in crate::nm::handover::native) struct Signature {family:u8,predicates:BTreeSet<Predicate>,action:Action}
#[derive(Clone,Debug,PartialEq,Eq,PartialOrd,Ord)]
enum Key {Meta(u32),Payload(u32,u32,usize),State}
#[derive(Clone,Debug,PartialEq,Eq,PartialOrd,Ord)]
enum Predicate {Compare(Key,Vec<u8>,u32,Vec<u8>),Range(Key,bool,Vec<u8>,Vec<u8>),State(u32,bool),TransportHeader(u8),Impossible}
#[derive(Clone,Debug,PartialEq,Eq,PartialOrd,Ord)]
enum Action {Accept,Drop,Return,Jump(String),Masquerade,Nat(u32,u8,Vec<u8>,Option<Vec<u8>>)}
#[derive(Clone)]
enum Register {Field(Key,Vec<u8>),Data(Vec<u8>)}
type Fields<'a>=BTreeMap<u16,&'a [u8]>;

fn fields<'a>(bytes:&'a [u8],allowed:&[u16])->Result<Fields<'a>> {
    let mut result=BTreeMap::new();
    for (tag,data) in attrs(bytes)? {let tag=tag&0x3fff;ensure!(allowed.contains(&tag)&&result.insert(tag,data).is_none(),"UNSUPPORTED: unknown/duplicate raw predicate attribute");}
    Ok(result)
}
fn get<'a>(fields:&Fields<'a>,key:u16)->Result<&'a [u8]> {fields.get(&key).copied().context("UNSUPPORTED: missing raw predicate field")}
fn number(fields:&Fields<'_>,key:u16)->Result<u32> {let value=get(fields,key)?;ensure!(value.len()==4,"UNSUPPORTED: raw u32 width");Ok(u32::from_be_bytes(value.try_into().unwrap()))}
fn data(bytes:&[u8])->Result<Vec<u8>> {let v=fields(bytes,&[1])?;let value=get(&v,1)?;ensure!(!value.is_empty()&&value.len()<=16,"UNSUPPORTED: raw literal width");Ok(value.to_vec())}
fn reg(id:u32)->Result<u32> {match id {1..=4=>Ok((id-1)*16),8..=23=>Ok((id-8)*4),_=>anyhow::bail!("UNSUPPORTED: non-data raw register")}}
fn set(registers:&mut BTreeMap<u32,Register>,id:u32,value:Register)->Result<()> {
    let start=reg(id)?;let width=match &value {Register::Field(_,v)|Register::Data(v)=>v.len() as u32};
    ensure!(start+width<=64,"UNSUPPORTED: raw register span");
    registers.retain(|old,stored| {let len=match stored {Register::Field(_,v)|Register::Data(v)=>v.len() as u32};*old>=start+width||start>=*old+len});registers.insert(start,value);Ok(())
}
fn field(registers:&BTreeMap<u32,Register>,id:u32)->Result<(Key,Vec<u8>)> {
    match registers.get(&reg(id)?) {Some(Register::Field(key,mask))=>Ok((key.clone(),mask.clone())),_=>anyhow::bail!("UNSUPPORTED: raw predicate reads an unwitnessed register")}
}
fn literal(registers:&BTreeMap<u32,Register>,id:u32,width:usize)->Result<Vec<u8>> {
    match registers.get(&reg(id)?) {Some(Register::Data(value)) if value.len()==width=>Ok(value.clone()),_=>anyhow::bail!("UNSUPPORTED: raw NAT reads an unwitnessed literal")}
}
fn compare(predicates:&mut BTreeSet<Predicate>,family:u8,mut key:Key,mut mask:Vec<u8>,op:u32,mut value:Vec<u8>)->Result<()> {
    ensure!(op<=5,"UNSUPPORTED: raw comparison operator");
    if key==Key::State {
        ensure!(mask.len()==4&&value==[0,0,0,0]&&[0,1].contains(&op),"UNSUPPORTED: raw state comparison");
        let bits=u32::from_ne_bytes(mask.try_into().unwrap());ensure!(bits>0&&bits&!15==0,"UNSUPPORTED: raw state bits");
        predicates.insert(Predicate::State(bits,op==0));return Ok(());
    }
    if matches!(key,Key::Meta(6|7)) {
        ensure!([0,1].contains(&op)&&value.len()<=16&&mask.iter().all(|v|*v==255),"UNSUPPORTED: masked/ranged interface");
        if let Some(end)=value.iter().position(|v|*v==0) {ensure!(value[end..].iter().all(|v|*v==0),"UNSUPPORTED: noncanonical interface padding");value.truncate(end+1);}
        ensure!(!value.is_empty(),"UNSUPPORTED: empty native interface prefix");mask=vec![255;value.len()];
    } else {ensure!(value.len()==mask.len(),"UNSUPPORTED: raw comparison width");}
    // The address lies within the mandatory IP network header. A short byte-
    // aligned prefix load and a full-width masked load have identical meaning.
    if let Key::Payload(1,offset,len)=key {
        let width=if family==2&&[12,16].contains(&offset){Some(4)}else if family==10&&[8,24].contains(&offset){Some(16)}else{None};
        if let Some(width)=width.filter(|width|len<*width) {ensure!([0,1].contains(&op),"UNSUPPORTED: ordered short address comparison");mask.resize(width,0);value.resize(width,0);key=Key::Payload(1,offset,width);}
    }
    if key==Key::Meta(15)&&[2,10].contains(&family)&&mask==[255]&&[0,1].contains(&op) {
        if (value==[family])!=(op==0) {predicates.insert(Predicate::Impossible);}return Ok(());
    }
    predicates.insert(Predicate::Compare(key,mask,op,value));Ok(())
}
fn range(predicates:&mut BTreeSet<Predicate>,key:Key,mask:Vec<u8>,negated:bool,min:Vec<u8>,max:Vec<u8>)->Result<()> {
    ensure!(mask.iter().all(|v|*v==255)&&min.len()==mask.len()&&max.len()==mask.len()&&min<=max,"UNSUPPORTED: raw masked/ranged value");
    if min==max {predicates.insert(Predicate::Compare(key,mask,u32::from(negated),min));}else{predicates.insert(Predicate::Range(key,negated,min,max));}Ok(())
}
fn normalize_ranges(predicates:&mut BTreeSet<Predicate>) {
    let values=predicates.iter().cloned().collect::<Vec<_>>();
    for low in &values {if let Predicate::Compare(key,mask,5,min)=low {
        if !matches!(key,Key::Payload(2,0|2,2))||!mask.iter().all(|v|*v==255){continue;}
        let upper=values.iter().find(|v|matches!(v,Predicate::Compare(k,m,3,max) if k==key&&m==mask&&min<=max));
        if let Some(high @ Predicate::Compare(_,_,_,max))=upper {predicates.remove(low);predicates.remove(high);range(predicates,key.clone(),mask.clone(),false,min.clone(),max.clone()).unwrap();}
    }}
}

fn signature(family:u8,bytes:&[u8])->Result<Signature> {
    ensure!([1,2,10].contains(&family),"UNSUPPORTED: raw family");
    let expressions=attrs(bytes)?;ensure!(!expressions.is_empty()&&expressions.len()<=256,"UNSUPPORTED: raw expression count");
    let mut registers=BTreeMap::new();let mut predicates=BTreeSet::new();let mut pending=BTreeSet::new();let mut action=None;
    for (tag,bytes) in expressions {
        ensure!(tag&0x3fff==1,"UNSUPPORTED: raw expression item");let expression=fields(bytes,&[1,2])?;let name=text(get(&expression,1)?)?;
        ensure!(action.is_none(),"UNSUPPORTED: raw expression after terminal action");let bytes=get(&expression,2)?;
        match name.as_str() {
            "counter"=>{let f=fields(bytes,&[1,2])?;ensure!(get(&f,1)?.len()==8&&get(&f,2)?.len()==8,"UNSUPPORTED: raw counter width");},
            "meta"=>{let f=fields(bytes,&[1,2])?;let key=number(&f,2)?;let width=match key {6|7=>16,8=>2,15|16=>1,3=>4,_=>anyhow::bail!("UNSUPPORTED: native meta predicate")};pending.insert(Key::Meta(key));set(&mut registers,number(&f,1)?,Register::Field(Key::Meta(key),vec![255;width]))?;},
            "payload"=>{let f=fields(bytes,&[1,2,3,4])?;let base=number(&f,2)?;let offset=number(&f,3)?;let len=number(&f,4)? as usize;
                ensure!(base<=2&&offset<=256&&(1..=16).contains(&len),"UNSUPPORTED: payload scope");
                let key=if family==2&&base==1&&offset==9&&len==1 {Key::Meta(16)}else{Key::Payload(base,offset,len)};
                pending.insert(key.clone());set(&mut registers,number(&f,1)?,Register::Field(key,vec![255;len]))?;},
            "ct"=>{let f=fields(bytes,&[1,2])?;ensure!(number(&f,2)?==0,"UNSUPPORTED: non-state conntrack");pending.insert(Key::State);set(&mut registers,number(&f,1)?,Register::Field(Key::State,vec![255;4]))?;},
            "bitwise"=>{let f=fields(bytes,&[1,2,3,4,5,6])?;ensure!(!f.contains_key(&6)||number(&f,6)?==0,"UNSUPPORTED: bitwise operation");let (key,old)=field(&registers,number(&f,1)?)?;let mask=data(get(&f,4)?)?;let xor=data(get(&f,5)?)?;
                ensure!(number(&f,3)? as usize==mask.len()&&mask.len()==old.len()&&xor.len()==mask.len()&&xor.iter().all(|v|*v==0),"UNSUPPORTED: non-mask bitwise predicate");let mask=old.iter().zip(mask).map(|(a,b)|a&b).collect();set(&mut registers,number(&f,2)?,Register::Field(key,mask))?;},
            "cmp"=>{let f=fields(bytes,&[1,2,3])?;let (key,mask)=field(&registers,number(&f,1)?)?;pending.remove(&key);compare(&mut predicates,family,key,mask,number(&f,2)?,data(get(&f,3)?)?)?;},
            "range"=>{let f=fields(bytes,&[1,2,3,4])?;let op=number(&f,2)?;ensure!(op<=1,"UNSUPPORTED: raw range operator");let (key,mask)=field(&registers,number(&f,1)?)?;pending.remove(&key);range(&mut predicates,key,mask,op==1,data(get(&f,3)?)?,data(get(&f,4)?)?)?;},
            "immediate"=>{let f=fields(bytes,&[1,2])?;let dest=number(&f,1)?;
                if dest==0 {let outer=fields(get(&f,2)?,&[2])?;let verdict=fields(get(&outer,2)?,&[1,2])?;let code=number(&verdict,1)? as i32;
                    action=Some(match code {1=>{ensure!(verdict.len()==1,"UNSUPPORTED: verdict fields");Action::Accept},0=>{ensure!(verdict.len()==1,"UNSUPPORTED: verdict fields");Action::Drop},-5=>{ensure!(verdict.len()==1,"UNSUPPORTED: verdict fields");Action::Return},-3=>Action::Jump(text(get(&verdict,2)?)?),_=>anyhow::bail!("UNSUPPORTED: non-model verdict")});
                }else{set(&mut registers,dest,Register::Data(data(get(&f,2)?)?))?;}
            },
            "masq"=>{let f=fields(bytes,&[1])?;ensure!(f.is_empty()||number(&f,1)?==0,"UNSUPPORTED: masquerade flags");action=Some(Action::Masquerade);},
            "nat"=>{let f=fields(bytes,&[1,2,3,4,5,6,7])?;let mode=number(&f,1)?;let scope=number(&f,2)?;let implied_flags=1|if f.contains_key(&5){2}else{0};
                // nft_nat_init ORs MAP_IPS/PROTO_SPECIFIED into the dump. These
                // are already implied by the exact address/port registers.
                ensure!(mode<=1&&[2,10].contains(&scope)&&(family==1||u32::from(family)==scope)&&(!f.contains_key(&7)||number(&f,7)?&!implied_flags==0),"UNSUPPORTED: NAT mode/family/flags");let scope=scope as u8;let width=if scope==2{4}else{16};let addr=literal(&registers,number(&f,3)?,width)?;
                if f.contains_key(&4){ensure!(addr==literal(&registers,number(&f,4)?,width)?,"UNSUPPORTED: address range");}
                let port=if f.contains_key(&5){Some(literal(&registers,number(&f,5)?,2)?)}else{None};
                if f.contains_key(&6){ensure!(port==Some(literal(&registers,number(&f,6)?,2)?),"UNSUPPORTED: port range");}
                action=Some(Action::Nat(mode,scope,addr,port));
            },
            "match"=>compat::matching(bytes,family,&mut predicates)?,
            "target"=>{action=Some(compat::target(bytes,family)?);},
            _=>anyhow::bail!("UNSUPPORTED: opaque native expression"),
        }
    }
    ensure!(pending.is_empty(),"UNSUPPORTED: unconsumed packet-read guard");normalize_ranges(&mut predicates);Ok(Signature{family,predicates,action:action.context("UNSUPPORTED: no terminal model action")?})
}

pub(in crate::nm::handover::native) fn expected(family:&str,expr:&Value)->Result<Signature> {
    let batch=json!({"expectedGeneration":1,"nftables":[{"add":{"rule":{"family":family,"table":"model","chain":"model","expr":expr}}}]});
    let (bytes,_)=writer::encode(&batch)?;let start=u32n(&bytes) as usize;let message=&bytes[start..];let end=u32n(message) as usize;
    let f=fields(&message[20..end],&[1,2,3,4,5,6,7,8,9,10])?;signature(message[16],get(&f,4)?)
}
pub(in crate::nm::handover::native) fn observed(payload:&str)->Option<Signature> {
    (|| {let bytes=decode(payload)?;ensure!(bytes.len()>=4&&bytes[1]==0,"UNSUPPORTED: raw rule header");let f=fields(&bytes[4..],&[1,2,3,4,5,7,8])?;
        ensure!(!f.contains_key(&8)||get(&f,8)?.is_empty(),"UNSUPPORTED: raw rule padding");
        if let Some(bytes)=f.get(&5) {let c=fields(bytes,&[1,2])?;ensure!(number(&c,1)?<=65535&&[0,2].contains(&number(&c,2)?),"UNSUPPORTED: rule compatibility metadata");}
        signature(bytes[0],get(&f,4)?)
    })().ok()
}

// Forward outcomes bind the exact rule receipt and complete known raw semantics.
// The custom model and nft's presentation need not have the same JSON spelling.
pub(in crate::nm::handover::native) fn replacement_matches(payload:&str,wanted:&Value)->Result<bool> {
    let Some(actual)=observed(payload) else {return Ok(false);};
    let batch=json!({"expectedGeneration":1,"nftables":[{"add":{"rule":wanted}}]});
    let (bytes,_)=writer::encode(&batch)?;let start=u32n(&bytes) as usize;let message=&bytes[start..];let end=u32n(message) as usize;
    let expected=fields(&message[20..end],&[1,2,3,4,5,6,7,8,9,10])?;
    let bytes=decode(payload)?;let observed=fields(&bytes[4..],&[1,2,3,4,5,7,8])?;
    if [1,2,7].iter().any(|key|observed.get(key)!=expected.get(key)) {return Ok(false);}
    let expected_signature=signature(message[16],get(&expected,4)?)?;
    if actual!=expected_signature {return Ok(false);}
    // Preserve counter placement relative to traffic predicates, not their values.
    Ok(counter_guards(bytes[0],get(&observed,4)?)?==counter_guards(message[16],get(&expected,4)?)?)
}

fn counter_guards(family:u8,expressions:&[u8])->Result<Vec<Signature>> {
    let family_name=match family {1=>"inet",2=>"ip",10=>"ip6",_=>anyhow::bail!("UNSUPPORTED: outcome counter family")};
    let batch=json!({"expectedGeneration":1,"nftables":[{"add":{"rule":{"family":family_name,"table":"probe","chain":"probe","expr":[{"accept":null}]}}}]});
    let (bytes,_)=writer::encode(&batch)?;let start=u32n(&bytes) as usize;let message=&bytes[start..];let end=u32n(message) as usize;
    let accept=fields(&message[20..end],&[1,2,3,4])?;
    let entries=attrs(expressions)?;
    let mut prefix=Vec::new();let mut result=Vec::new();
    for (kind,data) in &entries {
        let fields=fields(data,&[1,2])?;
        if text(get(&fields,1)?)?=="counter" {let mut probe=prefix.clone();probe.extend(get(&accept,4)?);result.push(signature(family,&probe)?);}
        prefix.extend(wire::attribute(*kind,data));
    }
    Ok(result)
}

pub(in crate::nm::handover::native) fn model_matches(payload:&str,family:&str,expr:&Value)->Result<bool> {
    let Some(actual)=observed(payload) else {return Ok(false);};
    let batch=json!({"expectedGeneration":1,"nftables":[{"add":{"rule":{"family":family,"table":"model","chain":"model","expr":expr}}}]});
    let (bytes,_)=writer::encode(&batch)?;let start=u32n(&bytes) as usize;let message=&bytes[start..];let end=u32n(message) as usize;
    let expected=fields(&message[20..end],&[1,2,3,4,5])?;
    if actual!=signature(message[16],get(&expected,4)?)? {return Ok(false);}
    let source=decode(payload)?;let observed=fields(&source[4..],&[1,2,3,4,5,7,8])?;
    Ok(counter_guards(source[0],get(&observed,4)?)?==counter_guards(message[16],get(&expected,4)?)?)
}

#[cfg(test)]
mod tests;
