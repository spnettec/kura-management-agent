//! Typed forms emitted by Networking's FloodingProtectionOptions in the mangle table.
use crate::{Table, compile_clause};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) enum Guard {
    TcpFlags { mask: u8, bits: u8, invert: bool },
    Fragment,
    MssOutsideBaseline,
    Ipv6Header(u8),
    RoutingTypeZero,
}

fn tcp_flags(value: &str) -> Option<u8> {
    match value {
        "ALL" => Some(0x3f),
        "NONE" => Some(0),
        _ => value.split(',').try_fold(0, |mask, flag| {
            let bit = match flag {
                "FIN" => 1,
                "SYN" => 2,
                "RST" => 4,
                "PSH" => 8,
                "ACK" => 16,
                "URG" => 32,
                _ => return None,
            };
            (mask & bit == 0).then_some(mask | bit)
        }),
    }
}

pub(crate) fn compile(family: &str, table: &Table, text: &str) -> Result<Option<Vec<Value>>> {
    if table.name != "mangle" {
        return Ok(None);
    }
    let words: Vec<_> = text.split_whitespace().collect();
    let Some(test) = words.strip_suffix(&["-j", "DROP"]) else {
        return Ok(None);
    };
    let (prefix, guard) = match test {
        ["-m", "conntrack", "--ctstate", "INVALID"] => {
            return Ok(Some(compile_clause(
                family,
                table,
                "-m state --state INVALID -j DROP",
            )?));
        }
        ["-p", "tcp", "--tcp-flags", mask, bits] => (
            "-p tcp",
            Guard::TcpFlags {
                mask: tcp_flags(mask).context("UNSUPPORTED: TCP flag mask")?,
                bits: tcp_flags(bits).context("UNSUPPORTED: TCP flag comparison")?,
                invert: false,
            },
        ),
        [
            "-p",
            "tcp",
            "!",
            "--syn",
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
        ] => (
            "-p tcp -m state --state NEW",
            Guard::TcpFlags {
                mask: 0x17,
                bits: 2,
                invert: true,
            },
        ),
        [
            "-p",
            "tcp",
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-m",
            "tcpmss",
            "!",
            "--mss",
            "536:65535",
        ] => ("-p tcp -m state --state NEW", Guard::MssOutsideBaseline),
        ["-f"] if family == "ip" => ("", Guard::Fragment),
        ["-m", "ipv6header", "--header", name, "--soft"] if family == "ip6" => {
            let bit = match *name {
                "hop" => 128,
                "dst" => 64,
                "route" => 32,
                "frag" => 16,
                "auth" => 8,
                "esp" => 4,
                "none" => 2,
                _ => anyhow::bail!("UNSUPPORTED: IPv6 extension header"),
            };
            ("", Guard::Ipv6Header(bit))
        }
        ["-m", "rt", "--rt-type", "0"] if family == "ip6" => ("", Guard::RoutingTypeZero),
        _ => return Ok(None),
    };
    let mut terms = compile_clause(family, table, &format!("{prefix} -j DROP"))?;
    terms.insert(terms.len() - 1, json!({"floodGuard":guard}));
    Ok(Some(terms))
}

impl Guard {
    pub(crate) fn xt_info(&self, family: u8) -> Result<Option<(&'static str, Vec<u8>)>> {
        Ok(Some(match self {
            Self::MssOutsideBaseline => {
                let mut bytes = vec![0; 8];
                bytes[..2].copy_from_slice(&536u16.to_ne_bytes());
                bytes[2..4].copy_from_slice(&u16::MAX.to_ne_bytes());
                bytes[4] = 1;
                ("tcpmss", bytes)
            }
            Self::Ipv6Header(bit) => {
                ensure!(
                    family == 10 && [2, 4, 8, 16, 32, 64, 128].contains(bit),
                    "UNSUPPORTED: IPv6 header match"
                );
                ("ipv6header", vec![*bit, 0, 255, 0, 0, 0, 0, 0])
            }
            Self::RoutingTypeZero => {
                ensure!(family == 10, "UNSUPPORTED: routing type family");
                let mut bytes = vec![0; 280];
                bytes[8..12].fill(255);
                bytes[16] = 1;
                ("rt", bytes)
            }
            _ => return Ok(None),
        }))
    }
    pub(crate) fn context(&self) -> Option<u32> {
        match self {
            Self::MssOutsideBaseline => Some(6),
            Self::Ipv6Header(_) | Self::RoutingTypeZero => Some(0),
            _ => None,
        }
    }
}
