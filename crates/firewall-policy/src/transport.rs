//! Linux Netfilter transport used by original-layout publishers. Callers bind
//! and persist the request before dispatch; this module never resends a batch.
use anyhow::Result;
use std::time::Instant;
#[cfg(target_os = "linux")]
use {
    anyhow::{Context, ensure},
    std::os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

#[cfg(target_os = "linux")]
const EXCHANGE_LIMIT: usize = 8 * 1024 * 1024;
pub fn message(kind: u16, flags: u16, seq: u32, family: u8, resource: u16, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&((data.len() + 20) as u32).to_ne_bytes());
    v.extend_from_slice(&kind.to_ne_bytes());
    v.extend_from_slice(&flags.to_ne_bytes());
    v.extend_from_slice(&seq.to_ne_bytes());
    v.extend_from_slice(&0u32.to_ne_bytes());
    v.extend_from_slice(&[family, 0]);
    v.extend_from_slice(&resource.to_be_bytes());
    v.extend_from_slice(data);
    v.resize((v.len() + 3) & !3, 0);
    v
}
#[cfg(target_os = "linux")]
struct Socket(OwnedFd);
#[cfg(target_os = "linux")]
impl Socket {
    fn new() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_NETFILTER,
            )
        };
        ensure!(
            fd >= 0,
            "UNSUPPORTED: Netfilter socket: {}",
            std::io::Error::last_os_error()
        );
        let socket = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        ensure!(
            unsafe {
                libc::bind(
                    socket.0.as_raw_fd(),
                    (&address as *const libc::sockaddr_nl).cast(),
                    std::mem::size_of_val(&address) as _,
                )
            } == 0,
            "UNSUPPORTED: bind Netfilter socket"
        );
        Ok(socket)
    }
    fn send_once(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= 512 * 1024,
            "RESOURCE_EXHAUSTED: Netfilter batch"
        );
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        ensure!(
            unsafe {
                libc::sendto(
                    self.0.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    0,
                    (&address as *const libc::sockaddr_nl).cast(),
                    std::mem::size_of_val(&address) as _,
                )
            } == bytes.len() as isize,
            "OUTCOME_UNKNOWN: Netfilter send;never resend"
        );
        Ok(())
    }
    fn receive(&self, deadline: Instant) -> Result<Vec<u8>> {
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .context("DEADLINE_EXCEEDED: Netfilter reply")?;
            let mut poll = libc::pollfd {
                fd: self.0.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let status = unsafe {
                libc::poll(
                    &mut poll,
                    1,
                    remaining.as_millis().min(i32::MAX as u128) as i32,
                )
            };
            if status < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            ensure!(
                status > 0 && poll.revents == libc::POLLIN,
                "OUTCOME_UNKNOWN: incomplete Netfilter reply"
            );
            let mut bytes = vec![0u8; 256 * 1024];
            let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of_val(&sender) as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    self.0.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_TRUNC,
                    (&mut sender as *mut libc::sockaddr_nl).cast(),
                    &mut length,
                )
            };
            ensure!(
                n > 0
                    && n as usize <= bytes.len()
                    && length as usize == std::mem::size_of_val(&sender)
                    && sender.nl_pid == 0
                    && sender.nl_groups == 0,
                "CONFLICT: truncated/non-kernel Netfilter reply"
            );
            bytes.truncate(n as usize);
            return Ok(bytes);
        }
    }
}

/// The read-only NFNL dump messages used by the publisher and boot receipt reader.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dump {
    Tables = 1,
    Chains = 4,
    Rules = 7,
    Sets = 10,
    Elements = 13,
    Objects = 19,
    Flowtables = 23,
}

#[cfg(target_os = "linux")]
fn dump_packets(
    request: Dump,
    sequence: u32,
    family: u8,
    filter: &[u8],
    deadline: Instant,
    mut consume: impl FnMut(&[u8]) -> Result<bool>,
) -> Result<()> {
    let socket = Socket::new()?;
    socket.send_once(&message(
        10 * 256 + request as u16,
        0x301,
        sequence,
        family,
        0,
        filter,
    ))?;
    let mut total = 0;
    loop {
        let packet = socket.receive(deadline)?;
        total += packet.len();
        ensure!(
            total <= EXCHANGE_LIMIT,
            "RESOURCE_EXHAUSTED: Netfilter dump"
        );
        if consume(&packet)? {
            return Ok(());
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn dump_packets(
    _: Dump,
    _: u32,
    _: u8,
    _: &[u8],
    _: Instant,
    _: impl FnMut(&[u8]) -> Result<bool>,
) -> Result<()> {
    anyhow::bail!("UNSUPPORTED: Netfilter requires Linux")
}

pub fn read_rules(
    sequence: u32,
    deadline: Instant,
    consume: impl FnMut(&[u8]) -> Result<bool>,
) -> Result<()> {
    dump_packets(Dump::Rules, sequence, 0, &[], deadline, consume)
}

pub fn read_objects(
    request: Dump,
    family: u8,
    filter: &[u8],
    deadline: Instant,
    mut row: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let sequence = 0x594f4600 + request as u32;
    dump_packets(request, sequence, family, filter, deadline, |packet| {
        visit_dump_packet(packet, sequence, request, &mut row)
    })
}

#[cfg(target_os = "linux")]
pub fn generation(deadline: Instant) -> Result<u32> {
    let sequence = 0x594f4630;
    let socket = Socket::new()?;
    socket.send_once(&message(10 * 256 + 16, 1, sequence, 0, 0, &[]))?;
    let b = socket.receive(deadline)?;
    ensure!(
        b.len() >= 20
            && u32::from_ne_bytes(b[..4].try_into()?) as usize == b.len()
            && u16::from_ne_bytes(b[4..6].try_into()?) == 10 * 256 + 15
            && u32::from_ne_bytes(b[8..12].try_into()?) == sequence,
        "CONFLICT: Netfilter generation reply"
    );
    let attrs = crate::netlink::attributes(&b[20..])?;
    let mut ids = attrs.iter().filter(|(tag, _)| tag & 0x3fff == 1);
    let id = ids
        .next()
        .context("CONFLICT: missing Netfilter generation")?
        .1;
    ensure!(
        ids.next().is_none() && id.len() == 4,
        "CONFLICT: Netfilter generation identity"
    );
    let generation = u32::from_be_bytes(id.try_into()?);
    ensure!(
        generation != 0,
        "UNSUPPORTED: zero kernel generation cannot fence writes"
    );
    Ok(generation)
}

#[cfg(not(target_os = "linux"))]
pub fn generation(_: Instant) -> Result<u32> {
    anyhow::bail!("UNSUPPORTED: Netfilter requires Linux")
}

/// Receipt from one kernel socket bound exclusively to this datagram.
#[derive(Debug)]
pub enum Outcome {
    Committed {
        reply: Vec<u8>,
    },
    Rejected {
        errno: i32,
        sequence: u32,
        reply: Vec<u8>,
    },
}

#[cfg(target_os = "linux")]
pub fn dispatch(wire: &[u8], first: u32, end: u32, deadline: Instant) -> Result<Outcome> {
    use crate::receipt::{BatchReceipts, Reply};
    let mut batch = BatchReceipts::new(wire, first, end)?;
    ensure!(
        Instant::now() < deadline,
        "DEADLINE_EXCEEDED: Netfilter admission"
    );
    let socket = Socket::new()?;
    socket.send_once(wire)?;
    let mut total = 0;
    loop {
        let packet = socket.receive(deadline)?;
        total += packet.len();
        ensure!(
            total <= EXCHANGE_LIMIT,
            "RESOURCE_EXHAUSTED: Netfilter ACK bytes"
        );
        match batch.observe(&packet)? {
            Reply::Pending => (),
            Reply::Committed { message } => {
                return Ok(Outcome::Committed {
                    reply: message.to_vec(),
                });
            }
            Reply::Rejected {
                errno,
                sequence,
                message,
            } => {
                return Ok(Outcome::Rejected {
                    errno,
                    sequence,
                    reply: message.to_vec(),
                });
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn dispatch(_: &[u8], _: u32, _: u32, _: Instant) -> Result<Outcome> {
    anyhow::bail!("UNSUPPORTED: Netfilter requires Linux")
}

/// Verify framing and dump completion before accepting the ordered rule payloads.
pub fn visit_rule_packet(
    packet: &[u8],
    sequence: u32,
    row: impl FnMut(&[u8]) -> Result<()>,
) -> Result<bool> {
    visit_dump_packet(packet, sequence, Dump::Rules, row)
}

fn visit_dump_packet(
    mut packet: &[u8],
    sequence: u32,
    request: Dump,
    mut row: impl FnMut(&[u8]) -> Result<()>,
) -> Result<bool> {
    let mut done = false;
    while !packet.is_empty() {
        ensure!(
            !done && packet.len() >= 16,
            "CONFLICT: truncated/trailing Netfilter message"
        );
        let n = u32::from_ne_bytes(packet[..4].try_into()?) as usize;
        let padded = n
            .checked_add(3)
            .ok_or_else(|| anyhow::anyhow!("invalid Netfilter length"))?
            & !3;
        ensure!(
            n >= 16 && padded <= packet.len(),
            "CONFLICT: Netfilter message length"
        );
        let flags = u16::from_ne_bytes(packet[6..8].try_into()?);
        ensure!(
            u32::from_ne_bytes(packet[8..12].try_into()?) == sequence && flags & 0x10 == 0,
            "CONFLICT: wrong/interrupted Netfilter dump"
        );
        let payload = &packet[16..n];
        match u16::from_ne_bytes(packet[4..6].try_into()?) {
            kind if kind == 10 * 256 + request as u16 - 1 => row(payload)?,
            3 => {
                ensure!(
                    payload.is_empty() || payload == [0; 4],
                    "CONFLICT: failed Netfilter dump completion"
                );
                done = true;
            }
            2 => anyhow::bail!("UNSUPPORTED: Netfilter rule dump rejected"),
            _ => anyhow::bail!("CONFLICT: unexpected Netfilter dump message"),
        }
        packet = &packet[padded..];
    }
    Ok(done)
}
