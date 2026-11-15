//! One bounded socket per exchange. The writer never retries a send,including a
//! generation NACK. Only a matching successful batch-END ACK proves commitment.
use super::*;
#[cfg(target_os="linux")]
use std::os::fd::{AsRawFd,FromRawFd,OwnedFd};

pub(super) fn attribute(t:u16,b:&[u8])->Vec<u8> {
    let mut v=Vec::new();v.extend_from_slice(&((b.len()+4) as u16).to_ne_bytes());v.extend_from_slice(&t.to_ne_bytes());v.extend_from_slice(b);v.resize((v.len()+3)&!3,0);v
}
pub(super) fn message(kind:u16,flags:u16,seq:u32,family:u8,resource:u16,data:&[u8])->Vec<u8> {
    let mut v=Vec::new();v.extend_from_slice(&((data.len()+20) as u32).to_ne_bytes());v.extend_from_slice(&kind.to_ne_bytes());v.extend_from_slice(&flags.to_ne_bytes());v.extend_from_slice(&seq.to_ne_bytes());v.extend_from_slice(&0u32.to_ne_bytes());v.extend_from_slice(&[family,0]);v.extend_from_slice(&resource.to_be_bytes());v.extend_from_slice(data);v.resize((v.len()+3)&!3,0);v
}
#[cfg(target_os="linux")]
struct Socket(OwnedFd);
#[cfg(target_os="linux")]
impl Socket {
    fn new()->Result<Self> {
        let fd=unsafe{libc::socket(libc::AF_NETLINK,libc::SOCK_RAW|libc::SOCK_CLOEXEC|libc::SOCK_NONBLOCK,libc::NETLINK_NETFILTER)};
        ensure!(fd>=0,"UNSUPPORTED: Netfilter socket: {}",std::io::Error::last_os_error());let socket=Self(unsafe{OwnedFd::from_raw_fd(fd)});
        let mut address:libc::sockaddr_nl=unsafe{std::mem::zeroed()};address.nl_family=libc::AF_NETLINK as u16;
        ensure!(unsafe{libc::bind(socket.0.as_raw_fd(),(&address as *const libc::sockaddr_nl).cast(),std::mem::size_of_val(&address) as _)}==0,"UNSUPPORTED: bind Netfilter socket");Ok(socket)
    }
    fn send_once(&self,bytes:&[u8])->Result<()> {
        ensure!(bytes.len()<=512*1024,"RESOURCE_EXHAUSTED: Netfilter batch");
        let mut address:libc::sockaddr_nl=unsafe{std::mem::zeroed()};address.nl_family=libc::AF_NETLINK as u16;
        ensure!(unsafe{libc::sendto(self.0.as_raw_fd(),bytes.as_ptr().cast(),bytes.len(),0,(&address as *const libc::sockaddr_nl).cast(),std::mem::size_of_val(&address) as _)}==bytes.len() as isize,"OUTCOME_UNKNOWN: Netfilter send;never resend");Ok(())
    }
    fn receive(&self,deadline:Instant)->Result<Vec<u8>> {
        loop {
            let remaining=deadline.checked_duration_since(Instant::now()).context("DEADLINE_EXCEEDED: Netfilter reply")?;
            let mut poll=libc::pollfd{fd:self.0.as_raw_fd(),events:libc::POLLIN,revents:0};
            let status=unsafe{libc::poll(&mut poll,1,remaining.as_millis().min(i32::MAX as u128) as i32)};
            if status<0&&std::io::Error::last_os_error().kind()==std::io::ErrorKind::Interrupted {continue;}
            ensure!(status>0&&poll.revents==libc::POLLIN,"OUTCOME_UNKNOWN: incomplete Netfilter reply");
            let mut bytes=vec![0u8;256*1024];let mut sender:libc::sockaddr_nl=unsafe{std::mem::zeroed()};let mut length=std::mem::size_of_val(&sender) as libc::socklen_t;
            let n=unsafe{libc::recvfrom(self.0.as_raw_fd(),bytes.as_mut_ptr().cast(),bytes.len(),libc::MSG_TRUNC,(&mut sender as *mut libc::sockaddr_nl).cast(),&mut length)};
            ensure!(n>0&&n as usize<=bytes.len()&&length as usize==std::mem::size_of_val(&sender)&&sender.nl_pid==0&&sender.nl_groups==0,"CONFLICT: truncated/non-kernel Netfilter reply");bytes.truncate(n as usize);return Ok(bytes);
        }
    }
}
#[cfg(target_os="linux")]
pub(super) fn dump(deadline:Instant)->Result<Vec<Fingerprint>> {
    let socket=Socket::new()?;socket.send_once(&message(GET_RULE,0x301,SEQUENCE,0,0,&[]))?;
    let mut result=Vec::new();let mut total=0;
    loop {let b=socket.receive(deadline)?;total+=b.len();ensure!(total<=MAX_DUMP,"RESOURCE_EXHAUSTED: Netfilter dump");if messages(&b,&mut result)?{break;}}
    result.sort();Ok(result)
}
#[cfg(not(target_os="linux"))]
pub(super) fn dump(_:Instant)->Result<Vec<Fingerprint>> {anyhow::bail!("UNSUPPORTED: Netfilter requires Linux")}
#[cfg(target_os="linux")]
pub(super) fn generation(deadline:Instant)->Result<u32> {
    let socket=Socket::new()?;socket.send_once(&message(10*256+16,1,SEQUENCE,0,0,&[]))?;
    let b=socket.receive(deadline)?;ensure!(b.len()>=20&&u32n(&b) as usize==b.len()&&u16n(&b[4..])==10*256+15&&u32n(&b[8..])==SEQUENCE,"CONFLICT: Netfilter generation reply");
    let fields=attrs(&b[20..])?;let id=one(&fields,1)?;ensure!(id.len()==4,"CONFLICT: Netfilter generation identity");let id=u32::from_be_bytes(id.try_into().unwrap());ensure!(id>0,"UNSUPPORTED: zero kernel generation cannot fence writes");Ok(id)
}
#[cfg(not(target_os="linux"))]
pub(super) fn generation(_:Instant)->Result<u32> {anyhow::bail!("UNSUPPORTED: Netfilter requires Linux")}

/// A complete kernel negative ACK means this atomic batch was rejected. The
/// existing Store must persist it as a terminal original outcome,never retry it.
#[derive(Debug)]
pub(in crate::nm) struct Rejected {pub errno:i32,pub sequence:u32,pub reply_sha256:String,pub reply:Vec<u8>}
impl std::fmt::Display for Rejected {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {write!(f,"CONFLICT: original Netfilter batch rejected errno {} seq {};never resend",self.errno,self.sequence)}}
impl std::error::Error for Rejected {}
pub(super) fn acknowledgement(mut b:&[u8],first:u32,end:u32,seen:&mut BTreeSet<u32>)->Result<bool> {
    let mut committed=false;
    while !b.is_empty() {
        ensure!(b.len()>=36,"CONFLICT: short Netfilter ACK");let n=u32n(b) as usize;ensure!(n>=36&&n<=b.len()&&((n+3)&!3)<=b.len()&&u16n(&b[4..])==2,"CONFLICT: invalid Netfilter ACK");
        let seq=u32n(&b[8..]);ensure!((first..=end).contains(&seq)&&seen.insert(seq),"CONFLICT: wrong/duplicate Netfilter ACK sequence");
        ensure!(u32n(&b[28..])==seq,"CONFLICT: ACK original message sequence");let error=i32::from_ne_bytes(b[16..20].try_into().unwrap());
        if error<0 {return Err(Rejected{errno:-error,sequence:seq,reply_sha256:durable::hash(&b[..n]),reply:b[..n].to_vec()}.into());}
        ensure!(error==0,"CONFLICT: positive Netfilter ACK error");if seq==end {committed=true;}
        b=&b[(n+3)&!3..];
    }
    Ok(committed)
}
#[cfg(target_os="linux")]
pub(super) fn dispatch(bytes:&[u8],first:u32,end:u32,deadline:Instant)->Result<()> {
    let socket=Socket::new()?;socket.send_once(bytes)?;let mut seen=BTreeSet::new();let mut total=0;
    loop {let b=socket.receive(deadline)?;total+=b.len();ensure!(total<=MAX_DUMP,"RESOURCE_EXHAUSTED: Netfilter ACK bytes");if acknowledgement(&b,first,end,&mut seen)? {return Ok(());}}
}
#[cfg(not(target_os="linux"))]
pub(super) fn dispatch(_: &[u8],_:u32,_:u32,_:Instant)->Result<()> {anyhow::bail!("UNSUPPORTED: Netfilter requires Linux")}

#[cfg(test)]
mod tests {
    use super::*;
    fn ack(seq:u32,error:i32)->Vec<u8> {
        let mut b=Vec::new();b.extend_from_slice(&36u32.to_ne_bytes());b.extend_from_slice(&2u16.to_ne_bytes());b.extend_from_slice(&0u16.to_ne_bytes());b.extend_from_slice(&seq.to_ne_bytes());b.extend_from_slice(&0u32.to_ne_bytes());b.extend_from_slice(&error.to_ne_bytes());b.extend_from_slice(&message(16,1,seq,0,10,&[])[..16]);b
    }
    #[test]
    fn only_successful_matching_batch_end_ack_can_commit_and_negative_ack_is_terminal_evidence() {
        let mut seen=BTreeSet::new();assert!(!acknowledgement(&ack(11,0),10,12,&mut seen).unwrap());assert!(acknowledgement(&ack(12,0),10,12,&mut seen).unwrap());
        assert!(acknowledgement(&ack(12,0),10,12,&mut seen).is_err());assert!(acknowledgement(&ack(99,0),10,12,&mut BTreeSet::new()).is_err());
        let negative=ack(10,-85);let error=acknowledgement(&negative,10,12,&mut BTreeSet::new()).unwrap_err();let rejected=error.downcast_ref::<Rejected>().unwrap();assert_eq!(rejected.errno,85);assert_eq!(rejected.reply_sha256,durable::hash(&negative));
        let mut mismatched=ack(12,0);mismatched[28]^=1;assert!(acknowledgement(&mismatched,10,12,&mut BTreeSet::new()).is_err());
        let mut short=ack(12,0);short.pop();assert!(acknowledgement(&short,10,12,&mut BTreeSet::new()).is_err());
    }
}
