//! Exact bounded UAPI adapters. All unused fields/padding must remain zero.
//! Unknown revisions, flags and non-model module parameters stay opaque.
use super::*;

fn module(bytes:&[u8])->Result<(String,u32,&[u8])> {
    let fields=fields(bytes,&[1,2,3])?;Ok((text(get(&fields,1)?)?,number(&fields,2)?,get(&fields,3)?))
}
pub(super) fn matching(bytes:&[u8],family:u8,predicates:&mut BTreeSet<Predicate>)->Result<()> {
    let (name,revision,info)=module(bytes)?;
    match (name.as_str(),revision) {
        ("tcp",0)|("udp",0)=>{
            ensure!(info.len()==16&&info[..8]==[0,0,255,255,0,0,255,255]&&info[8..].iter().all(|v|*v==0),"UNSUPPORTED: non-default transport module");
            predicates.insert(Predicate::TransportHeader(if name=="tcp"{6}else{17}));
        },
        ("conntrack",3)=>{
            ensure!(info.len()==168&&info.iter().enumerate().all(|(i,b)|(146..152).contains(&i)||*b==0),"UNSUPPORTED: extended conntrack parameters");
            let flags=u16::from_ne_bytes(info[146..148].try_into().unwrap());let inverse=u16::from_ne_bytes(info[148..150].try_into().unwrap());let mask=u16::from_ne_bytes(info[150..152].try_into().unwrap()) as u32;
            ensure!([1,0x2001].contains(&flags)&&inverse<=1&&mask>0&&mask&!15==0,"UNSUPPORTED: conntrack flags/state");predicates.insert(Predicate::State(mask,inverse==1));
        },
        ("icmp",0)|("icmp6",0)=>{
            ensure!(family==if name=="icmp"{2}else{10},"UNSUPPORTED: compat ICMP family");
            ensure!(info.len()==8&&info[4..].iter().all(|v|*v==0)&&info[1]<=info[2]&&info[3]<=1,"UNSUPPORTED: compat ICMP data");
              // Even an all-types match performs the original module's full
              // header/fragment checks; never collapse it to protocol-only.
              predicates.insert(Predicate::TransportHeader(if name=="icmp"{1}else{58}));
            let (kind,first,last,inverse)=(info[0],info[1],info[2],info[3]!=0);
            ensure!(!inverse||(first==0&&last==255),"UNSUPPORTED: compound inverted ICMP");
              if kind!=255||name=="icmp6" {compare(predicates,family,Key::Payload(2,0,1),vec![255],u32::from(inverse),vec![kind])?;}else{ensure!(!inverse,"UNSUPPORTED: inverted all ICMP");}
            if first!=0||last!=255 {range(predicates,Key::Payload(2,1,1),vec![255],false,vec![first],vec![last])?;}
        },
        ("mac",0)=>{
            ensure!(info.len()==16&&info[6..8]==[0,0]&&info[12..].iter().all(|v|*v==0),"UNSUPPORTED: compat MAC layout");let inverse=u32::from_ne_bytes(info[8..12].try_into().unwrap());ensure!(inverse<=1,"UNSUPPORTED: MAC inversion");
            compare(predicates,family,Key::Meta(8),vec![255;2],0,1u16.to_ne_bytes().to_vec())?;
            compare(predicates,family,Key::Payload(0,6,6),vec![255;6],inverse,info[..6].to_vec())?;
        },
        _=>anyhow::bail!("UNSUPPORTED: opaque xt match"),
    }
    Ok(())
}

pub(super) fn target(bytes:&[u8],family:u8)->Result<Action> {
    let (name,revision,info)=module(bytes)?;ensure!([2,10].contains(&family),"UNSUPPORTED: compat NAT family");
    ensure!((name=="MASQUERADE"&&revision==0)||(["DNAT","SNAT"].contains(&name.as_str())&&revision<=2),"UNSUPPORTED: NAT target name/revision");
    let (flags,min,max,first,last)=if revision==0&&family==2 {
        ensure!(info.len()==24&&u32::from_ne_bytes(info[..4].try_into().unwrap())==1&&info[20..].iter().all(|v|*v==0),"UNSUPPORTED: IPv4 NAT compatibility layout");
        (u32::from_ne_bytes(info[4..8].try_into().unwrap()),&info[8..12],&info[12..16],&info[16..18],&info[18..20])
    }else if revision==1||revision==2||(revision==0&&family==10&&name=="MASQUERADE") {
        ensure!(info.len()==if revision==2{48}else{40}&&info[40..].iter().all(|v|*v==0),"UNSUPPORTED: NAT range layout");
        let width=if family==2{4}else{16};ensure!(info[4+width..20].iter().all(|v|*v==0)&&info[20+width..36].iter().all(|v|*v==0),"UNSUPPORTED: NAT address padding");
        (u32::from_ne_bytes(info[..4].try_into().unwrap()),&info[4..4+width],&info[20..20+width],&info[36..38],&info[38..40])
    }else{anyhow::bail!("UNSUPPORTED: NAT target revision");};
    if name=="MASQUERADE" {ensure!(flags==0&&min.iter().chain(max).chain(first).chain(last).all(|v|*v==0),"UNSUPPORTED: extended masquerade");return Ok(Action::Masquerade);}
    ensure!(["DNAT","SNAT"].contains(&name.as_str())&&[1,3].contains(&flags)&&min==max,"UNSUPPORTED: extended address translation");
    let port=if flags&2!=0 {ensure!(first==last,"UNSUPPORTED: compat NAT port range");Some(first.to_vec())}else{ensure!(first==[0,0]&&last==[0,0],"UNSUPPORTED: unflagged NAT port");None};
    Ok(Action::Nat(u32::from(name=="DNAT"),family,min.to_vec(),port))
}
