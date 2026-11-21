//! Check Netfilter acknowledgements against the original generation-fenced datagram.
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;

const HEADER: usize = 16;
const CAPPED: u16 = 0x100;
const ACK_TLVS: u16 = 0x200;

fn word(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes[..4].try_into().unwrap())
}

fn half(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes[..2].try_into().unwrap())
}

fn message(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    ensure!(
        bytes.len() >= HEADER,
        "CONFLICT: incomplete Netfilter header"
    );
    let size = word(bytes) as usize;
    let padded = size.checked_add(3).context("invalid Netfilter size")? & !3;
    ensure!(
        size >= HEADER && padded <= bytes.len(),
        "CONFLICT: incomplete Netfilter message"
    );
    Ok((&bytes[..size], &bytes[padded..]))
}

/// A socket exchange or a durable intent supplies these bytes. Sequence numbers
/// index the commands within that one batch and are reused by later operations.
pub struct BatchReceipts<'a> {
    first: u32,
    messages: Vec<&'a [u8]>,
    seen: BTreeSet<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reply<'a> {
    Pending,
    Committed {
        message: &'a [u8],
    },
    Rejected {
        errno: i32,
        sequence: u32,
        message: &'a [u8],
    },
}

impl<'a> BatchReceipts<'a> {
    pub fn new(mut wire: &'a [u8], first: u32, end: u32) -> Result<Self> {
        ensure!(
            wire.len() <= 512 * 1024
                && end
                    .checked_sub(first)
                    .is_some_and(|d| (2..=8193).contains(&d)),
            "CONFLICT: invalid Netfilter batch bounds"
        );
        let mut messages = Vec::new();
        for sequence in first..=end {
            let (request, rest) = message(wire)?;
            ensure!(
                request.len() >= 20 && word(&request[8..]) == sequence,
                "CONFLICT: original Netfilter sequence"
            );
            let kind = half(&request[4..]);
            let expected_kind = if sequence == first {
                kind == 16
                    && half(&request[6..]) == 1
                    && request.len() == 28
                    && request[16..20] == [0, 0, 0, 10]
                    && half(&request[20..]) == 8
                    && half(&request[22..]) == 1
                    && request[24..28] != [0; 4]
            } else if sequence == end {
                kind == 17
                    && half(&request[6..]) == 5
                    && request.len() == 20
                    && request[16..20] == [0, 0, 0, 10]
            } else {
                kind >> 8 == 10
            };
            ensure!(expected_kind, "CONFLICT: original Netfilter batch framing");
            messages.push(request);
            wire = rest;
        }
        ensure!(wire.is_empty(), "CONFLICT: leftover Netfilter batch bytes");
        Ok(Self {
            first,
            messages,
            seen: BTreeSet::new(),
        })
    }

    pub fn observe<'b>(&mut self, mut packet: &'b [u8]) -> Result<Reply<'b>> {
        let mut outcome = Reply::Pending;
        while !packet.is_empty() {
            let (ack, rest) = message(packet)?;
            ensure!(
                ack.len() >= 36 && half(&ack[4..]) == 2,
                "CONFLICT: invalid Netfilter ACK"
            );
            let seq = word(&ack[8..]);
            let index = seq
                .checked_sub(self.first)
                .context("CONFLICT: Netfilter sequence")? as usize;
            let original = self
                .messages
                .get(index)
                .context("CONFLICT: Netfilter sequence")?;
            ensure!(
                self.seen.insert(seq) && ack[20..36] == original[..HEADER],
                "CONFLICT: ACK does not match original command header"
            );
            let flags = half(&ack[6..]);
            ensure!(
                flags & !(CAPPED | ACK_TLVS) == 0,
                "CONFLICT: unsupported Netfilter ACK flags"
            );
            let error = i32::from_ne_bytes(ack[16..20].try_into().unwrap());
            ensure!(error <= 0, "CONFLICT: invalid Netfilter errno");
            let echoed = if error < 0 {
                // A header alone cannot distinguish equal-size commands in different batches.
                ensure!(
                    flags & CAPPED == 0 && ack.get(20..20 + original.len()) == Some(*original),
                    "CONFLICT: negative ACK does not echo the original command"
                );
                20 + original.len()
            } else {
                36
            };
            if flags & ACK_TLVS == 0 {
                ensure!(
                    ack.len() == echoed,
                    "CONFLICT: unexpected Netfilter ACK data"
                );
            } else {
                let offset = (echoed + 3) & !3;
                let tail = ack
                    .get(offset..)
                    .context("CONFLICT: truncated Netfilter ACK attributes")?;
                crate::netlink::attributes(tail)?;
            }
            if error < 0 {
                let errno = error
                    .checked_neg()
                    .context("CONFLICT: invalid Netfilter errno")?;
                ensure!(
                    outcome == Reply::Pending,
                    "CONFLICT: contradictory Netfilter ACK"
                );
                outcome = Reply::Rejected {
                    errno,
                    sequence: seq,
                    message: ack,
                };
            } else if index + 1 == self.messages.len() {
                ensure!(
                    outcome == Reply::Pending,
                    "CONFLICT: contradictory Netfilter ACK"
                );
                outcome = Reply::Committed { message: ack };
            }
            packet = rest;
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(size: usize, kind: u16, flags: u16, seq: u32) -> Vec<u8> {
        let mut b = (size as u32).to_ne_bytes().to_vec();
        b.extend(kind.to_ne_bytes());
        b.extend(flags.to_ne_bytes());
        b.extend(seq.to_ne_bytes());
        b.extend(0u32.to_ne_bytes());
        b
    }
    fn request(kind: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        let mut b = header(20 + body.len(), kind, if kind == 17 { 5 } else { 1 }, seq);
        b.extend([0, 0, 0, 10]);
        b.extend(body);
        b
    }
    fn reply(request: &[u8], errno: i32, flags: u16) -> Vec<u8> {
        let echo = if errno == 0 || flags & CAPPED != 0 {
            &request[..HEADER]
        } else {
            request
        };
        let mut b = header(20 + echo.len(), 2, flags, word(&request[8..]));
        b.extend(errno.to_ne_bytes());
        b.extend(echo);
        b
    }
    #[test]
    fn a_rejection_is_bound_to_the_original_command_and_encoding() {
        let generation = crate::netlink::attribute(1, &7u32.to_be_bytes());
        let begin = request(16, 50, &generation);
        let end = request(17, 52, &[]);
        let command = request(2566, 51, b"left");
        let wire = [begin.clone(), command.clone(), end.clone()].concat();
        let receipts = || BatchReceipts::new(&wire, 50, 52).unwrap();
        let positive = reply(&end, 0, CAPPED);
        let mut batch = receipts();
        assert_eq!(
            batch.observe(&reply(&command, 0, CAPPED)).unwrap(),
            Reply::Pending
        );
        assert_eq!(
            batch.observe(&positive).unwrap(),
            Reply::Committed { message: &positive }
        );
        assert!(batch.observe(&positive).is_err());
        let negative = reply(&command, -17, 0);
        assert_eq!(
            receipts().observe(&negative).unwrap(),
            Reply::Rejected {
                errno: 17,
                sequence: 51,
                message: &negative
            }
        );
        for bytes in [
            reply(&request(2566, 51, b"else"), -17, 0),
            reply(&command, -17, CAPPED),
            reply(&request(16, 52, &[]), 0, CAPPED),
        ] {
            assert!(receipts().observe(&bytes).is_err());
        }
        let mut legacy = command.clone();
        legacy[6..8].copy_from_slice(&5u16.to_ne_bytes());
        assert!(receipts().observe(&reply(&legacy, -17, 0)).is_err());
        let legacy_wire = [begin, legacy.clone(), end].concat();
        assert!(matches!(
            BatchReceipts::new(&legacy_wire, 50, 52)
                .unwrap()
                .observe(&reply(&legacy, -17, 0)),
            Ok(Reply::Rejected { .. })
        ));
        assert!(receipts().observe(&negative[..negative.len() - 1]).is_err());
        assert!(BatchReceipts::new(&wire, 50, 53).is_err());
    }
}
