use super::*;
pub(super) use kura_firewall_policy::{
    netlink::attribute,
    transport::{generation, message},
};

pub(super) fn dump(deadline: Instant) -> Result<Vec<Fingerprint>> {
    let mut result = Vec::new();
    kura_firewall_policy::transport::read_rules(SEQUENCE, deadline, |packet| {
        messages(packet, &mut result)
    })?;
    result.sort();
    Ok(result)
}

/// A complete kernel negative ACK means this atomic batch was rejected. The
/// existing Store must persist it as a terminal original outcome,never retry it.
#[derive(Debug)]
pub(in crate::nm) struct Rejected {
    pub errno: i32,
    pub sequence: u32,
    pub reply_sha256: String,
    pub reply: Vec<u8>,
}
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CONFLICT: original Netfilter batch rejected errno {} seq {};never resend",
            self.errno, self.sequence
        )
    }
}
impl std::error::Error for Rejected {}
use kura_firewall_policy::receipt::{BatchReceipts, Reply};

pub(super) fn acknowledgement(packet: &[u8], batch: &mut BatchReceipts<'_>) -> Result<bool> {
    match batch.observe(packet)? {
        Reply::Pending => Ok(false),
        Reply::Committed { .. } => Ok(true),
        Reply::Rejected {
            errno,
            sequence,
            message,
        } => Err(Rejected {
            errno,
            sequence,
            reply_sha256: durable::hash(message),
            reply: message.to_vec(),
        }
        .into()),
    }
}
pub(super) fn dispatch(bytes: &[u8], first: u32, end: u32, deadline: Instant) -> Result<()> {
    use kura_firewall_policy::transport::{self, Outcome};
    match transport::dispatch(bytes, first, end, deadline)? {
        Outcome::Committed { .. } => Ok(()),
        Outcome::Rejected {
            errno,
            sequence,
            reply,
        } => Err(Rejected {
            errno,
            sequence,
            reply_sha256: durable::hash(&reply),
            reply,
        }
        .into()),
    }
}
