//! Encoding shared by the original-layout compiler and the registered agent's
//! generation-checked Netfilter writer. No socket or transport is opened here.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use self::attribute as a;

pub fn attribute(t: u16, b: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&((b.len() + 4) as u16).to_ne_bytes());
    v.extend_from_slice(&t.to_ne_bytes());
    v.extend_from_slice(b);
    v.resize((v.len() + 3) & !3, 0);
    v
}
pub fn check_fields(v: &Value, allowed: &[&str]) -> Result<()> {
    ensure!(
        v.as_object()
            .is_some_and(|v| v.keys().all(|k| allowed.contains(&k.as_str()))),
        "UNSUPPORTED: native wire fields"
    );
    Ok(())
}
pub fn bounded_string(v: &Value) -> Result<&str> {
    v.as_str()
        .filter(|s| !s.is_empty() && s.len() <= 255 && !s.as_bytes().contains(&0))
        .context("INVALID_ARGUMENT: native wire string")
}
pub fn string_attribute_value(v: &Value) -> Result<Vec<u8>> {
    let mut b = bounded_string(v)?.as_bytes().to_vec();
    b.push(0);
    Ok(b)
}
pub fn unsigned_integer(v: &Value) -> Result<u32> {
    v.as_u64()
        .filter(|v| *v <= u32::MAX as u64)
        .map(|v| v as u32)
        .context("INVALID_ARGUMENT: native integer")
}
pub fn integer_attribute(t: u16, v: u32) -> Vec<u8> {
    a(t, &v.to_be_bytes())
}
fn data(t: u16, b: &[u8]) -> Vec<u8> {
    a(0x8000 | t, &a(1, b))
}
fn expression(name: &str, body: &[u8]) -> Vec<u8> {
    let mut b = a(1, &[name.as_bytes(), &[0]].concat());
    b.extend(a(0x8002, body));
    a(0x8001, &b)
}
fn immediate(register: u32, b: &[u8]) -> Vec<u8> {
    expression(
        "immediate",
        &[integer_attribute(1, register), data(2, b)].concat(),
    )
}
fn cmp(op: u32, b: &[u8]) -> Vec<u8> {
    expression(
        "cmp",
        &[
            integer_attribute(1, 1),
            integer_attribute(2, op),
            data(3, b),
        ]
        .concat(),
    )
}
fn meta(key: u32) -> Vec<u8> {
    expression(
        "meta",
        &[integer_attribute(1, 1), integer_attribute(2, key)].concat(),
    )
}
fn bitwise(mask: &[u8]) -> Vec<u8> {
    expression(
        "bitwise",
        &[
            integer_attribute(1, 1),
            integer_attribute(2, 1),
            integer_attribute(3, mask.len() as u32),
            data(4, mask),
            data(5, &vec![0; mask.len()]),
        ]
        .concat(),
    )
}
fn protocol(name: &str) -> Result<u8> {
    match name {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "icmpv6" | "ipv6-icmp" => Ok(58),
        _ => anyhow::bail!("UNSUPPORTED: native transport protocol"),
    }
}
fn ip(v: &Value, family: u8) -> Result<Vec<u8>> {
    let address: std::net::IpAddr = bounded_string(v)?.parse()?;
    match address {
        std::net::IpAddr::V4(v) if family == 2 => Ok(v.octets().to_vec()),
        std::net::IpAddr::V6(v) if family == 10 => Ok(v.octets().to_vec()),
        _ => anyhow::bail!("INVALID_ARGUMENT: native IP family"),
    }
}
enum Kind {
    Byte,
    Version,
    Port,
    Mac,
    Address(u8),
    Name,
    NativeU32,
    State,
}
fn mac(v: &Value) -> Result<Vec<u8>> {
    let value = bounded_string(v)?;
    ensure!(
        value.len() == 17
            && value.split(':').count() == 6
            && value
                .split(':')
                .all(|part| part.len() == 2 && part.bytes().all(|c| c.is_ascii_hexdigit())),
        "INVALID_ARGUMENT: native Ethernet address"
    );
    value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16).map_err(Into::into))
        .collect()
}
fn interface_name(v: &Value) -> Result<Vec<u8>> {
    let value = bounded_string(v)?;
    let prefix = value.strip_suffix('*');
    let stem = prefix.unwrap_or(value);
    ensure!(
        !stem.is_empty()
            && value.len() <= 15
            && stem
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)),
        "UNSUPPORTED: native bounded interface name/prefix"
    );
    let mut bytes = stem.as_bytes().to_vec();
    // nft compares a prefix without a terminator; an exact name includes NUL.
    if prefix.is_none() {
        bytes.push(0);
    }
    Ok(bytes)
}
fn left(v: &Value, family: u8, out: &mut Vec<u8>) -> Result<Kind> {
    ensure!(
        v.as_object().is_some_and(|v| v.len() == 1),
        "UNSUPPORTED: native match lhs"
    );
    if let Some(v) = v.get("meta") {
        check_fields(v, &["key"])?;
        let key = bounded_string(&v["key"])?;
        let (number, kind) = match key {
            "iifname" => (6, Kind::Name),
            "oifname" => (7, Kind::Name),
            "l4proto" => (16, Kind::Byte),
            "nfproto" => (15, Kind::Byte),
            "mark" => (3, Kind::NativeU32),
            _ => anyhow::bail!("UNSUPPORTED: native meta key"),
        };
        out.extend(meta(number));
        return Ok(kind);
    }
    if let Some(v) = v.get("ct") {
        check_fields(v, &["key"])?;
        ensure!(v["key"] == "state", "UNSUPPORTED: native conntrack key");
        return Ok(Kind::State);
    }
    let v = v
        .get("payload")
        .context("UNSUPPORTED: native payload match")?;
    check_fields(v, &["protocol", "field"])?;
    let protocol_name = bounded_string(&v["protocol"])?;
    let field = bounded_string(&v["field"])?;
    if let Some(required) = match protocol_name {
        "ip" | "icmp" => Some(2),
        "ip6" | "icmpv6" => Some(10),
        _ => None,
    } {
        ensure!(
            family == 1 || family == required,
            "INVALID_ARGUMENT: native payload protocol family"
        );
        if family == 1 {
            out.extend(meta(15));
            out.extend(cmp(0, &[required]));
        }
    }
    let (base, offset, length, kind) = match (protocol_name, field) {
        ("ip" | "ip6", "version") => (1, 0, 1, Kind::Version),
        ("ip", "saddr") => (1, 12, 4, Kind::Address(2)),
        ("ip", "daddr") => (1, 16, 4, Kind::Address(2)),
        ("ip6", "saddr") => (1, 8, 16, Kind::Address(10)),
        ("ip6", "daddr") => (1, 24, 16, Kind::Address(10)),
        ("ether", "saddr" | "daddr") => {
            out.extend(meta(8));
            out.extend(cmp(0, &1u16.to_ne_bytes()));
            (0, if field == "saddr" { 6 } else { 0 }, 6, Kind::Mac)
        }
        ("tcp" | "udp", "sport" | "dport") => {
            out.extend(meta(16));
            out.extend(cmp(0, &[protocol(protocol_name)?]));
            (2, if field == "sport" { 0 } else { 2 }, 2, Kind::Port)
        }
        ("icmp" | "icmpv6", "type" | "code") => {
            out.extend(meta(16));
            out.extend(cmp(0, &[protocol(protocol_name)?]));
            (2, if field == "type" { 0 } else { 1 }, 1, Kind::Byte)
        }
        _ => anyhow::bail!("UNSUPPORTED: native payload field/family"),
    };
    out.extend(expression(
        "payload",
        &[
            integer_attribute(1, 1),
            integer_attribute(2, base),
            integer_attribute(3, offset),
            integer_attribute(4, length),
        ]
        .concat(),
    ));
    if matches!(&kind, Kind::Version) {
        out.extend(bitwise(&[0xf0]));
    }
    Ok(kind)
}
fn scalar(v: &Value, kind: &Kind) -> Result<Vec<u8>> {
    match kind {
        Kind::Byte => {
            let value = if let Some(s) = v.as_str() {
                match s {
                    "ipv4" => 2,
                    "ipv6" => 10,
                    _ => protocol(s)? as u32,
                }
            } else {
                unsigned_integer(v)?
            };
            ensure!(value <= 255, "INVALID_ARGUMENT: native byte");
            Ok(vec![value as u8])
        }
        Kind::Version => {
            let value = unsigned_integer(v)?;
            ensure!(value <= 15, "INVALID_ARGUMENT: native IP version nibble");
            Ok(vec![(value as u8) << 4])
        }
        Kind::Port => {
            let value = unsigned_integer(v)?;
            ensure!(value <= 65535, "INVALID_ARGUMENT: native port");
            Ok((value as u16).to_be_bytes().to_vec())
        }
        Kind::Mac => mac(v),
        Kind::Address(f) => ip(v, *f),
        Kind::Name => interface_name(v),
        Kind::NativeU32 => Ok(unsigned_integer(v)?.to_ne_bytes().to_vec()),
        Kind::State => anyhow::bail!("UNSUPPORTED: scalar conntrack state"),
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum StateEncoding {
    Native,
    Xtables { alias: bool },
}

fn match_expression(v: &Value, family: u8, out: &mut Vec<u8>, state: StateEncoding) -> Result<()> {
    check_fields(v, &["op", "left", "right"])?;
    let kind = left(&v["left"], family, out)?;
    let op = bounded_string(&v["op"])?;
    let right = &v["right"];
    if matches!(&kind, Kind::Name) {
        ensure!(
            ["==", "!="].contains(&op),
            "UNSUPPORTED: native interface comparison"
        );
        out.extend(cmp(if op == "==" { 0 } else { 1 }, &interface_name(right)?));
        return Ok(());
    }
    if matches!(kind, Kind::State) {
        ensure!(
            ["in", "==", "!=", "not in"].contains(&op),
            "UNSUPPORTED: conntrack operator"
        );
        check_fields(right, &["set"])?;
        let values = right
            .get("set")
            .and_then(Value::as_array)
            .filter(|v| !v.is_empty() && v.len() <= 4)
            .context("UNSUPPORTED: bounded explicit conntrack state set")?;
        let mut mask = 0u32;
        for v in values {
            mask |= match bounded_string(v)? {
                "established" => 2,
                "related" => 4,
                "new" => 8,
                "invalid" => 1,
                _ => anyhow::bail!("UNSUPPORTED: native conntrack state"),
            };
        }
        ensure!(mask > 0, "INVALID_ARGUMENT: empty state set");
        if let StateEncoding::Xtables { alias } = state {
            // xt_conntrack_mtinfo3, the same revision and state alias used by
            // iptables-nft for "-m state". Keep all unused match fields zero.
            let mut info = [0u8; 168];
            let flags = if alias { 0x2001u16 } else { 1u16 };
            info[146..148].copy_from_slice(&flags.to_ne_bytes());
            info[148..150].copy_from_slice(&u16::from(matches!(op, "!=" | "not in")).to_ne_bytes());
            info[150..152].copy_from_slice(&(mask as u16).to_ne_bytes());
            out.extend(expression(
                "match",
                &[a(1, b"conntrack\0"), integer_attribute(2, 3), a(3, &info)].concat(),
            ));
            return Ok(());
        }
        out.extend(expression(
            "ct",
            &[integer_attribute(1, 1), integer_attribute(2, 0)].concat(),
        ));
        out.extend(bitwise(&mask.to_ne_bytes()));
        out.extend(cmp(
            if ["!=", "not in"].contains(&op) { 0 } else { 1 },
            &0u32.to_ne_bytes(),
        ));
        return Ok(());
    }
    if let Some(prefix) = right.get("prefix") {
        check_fields(right, &["prefix"])?;
        check_fields(prefix, &["addr", "len"])?;
        ensure!(
            ["==", "!=", "in", "not in"].contains(&op),
            "UNSUPPORTED: prefix operator"
        );
        let Kind::Address(f) = kind else {
            anyhow::bail!("UNSUPPORTED: prefix on non-address");
        };
        let mut addr = ip(&prefix["addr"], f)?;
        let len = unsigned_integer(&prefix["len"])? as usize;
        ensure!(len <= addr.len() * 8, "INVALID_ARGUMENT: prefix length");
        let mut mask = vec![0; addr.len()];
        for (i, m) in mask.iter_mut().enumerate() {
            *m = if len >= i * 8 + 8 {
                255
            } else if len > i * 8 {
                255 << (8 - (len - i * 8))
            } else {
                0
            };
            addr[i] &= *m;
        }
        out.extend(bitwise(&mask));
        out.extend(cmp(
            if ["!=", "not in"].contains(&op) { 1 } else { 0 },
            &addr,
        ));
        return Ok(());
    }
    if let Some(range) = right.get("range") {
        check_fields(right, &["range"])?;
        let range = range
            .as_array()
            .filter(|v| v.len() == 2)
            .context("INVALID_ARGUMENT: native range")?;
        let op = match op {
            "==" | "in" => 0,
            "!=" | "not in" => 1,
            _ => anyhow::bail!("UNSUPPORTED: native range operator"),
        };
        out.extend(expression(
            "range",
            &[
                integer_attribute(1, 1),
                integer_attribute(2, op),
                data(3, &scalar(&range[0], &kind)?),
                data(4, &scalar(&range[1], &kind)?),
            ]
            .concat(),
        ));
        return Ok(());
    }
    let op = match op {
        "==" => 0,
        "!=" => 1,
        "<" => 2,
        "<=" => 3,
        ">" => 4,
        ">=" => 5,
        _ => anyhow::bail!("UNSUPPORTED: native comparison operator"),
    };
    out.extend(cmp(op, &scalar(right, &kind)?));
    Ok(())
}
fn header_protocol(v: &Value) -> Result<u32> {
    check_fields(v, &["protocol"])?;
    match bounded_string(&v["protocol"])? {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        _ => anyhow::bail!("UNSUPPORTED: bounded transport header protocol"),
    }
}
fn icmp_protocol(v: &Value) -> Result<u32> {
    check_fields(
        v,
        &["protocol", "type", "codeFirst", "codeLast", "inverted"],
    )?;
    match bounded_string(&v["protocol"])? {
        "icmp" => Ok(1),
        "icmpv6" => Ok(58),
        _ => anyhow::bail!("UNSUPPORTED: bounded ICMP module protocol"),
    }
}
pub fn compatibility_attribute(proto: u32) -> Vec<u8> {
    a(
        0x8005,
        &[integer_attribute(1, proto), integer_attribute(2, 0)].concat(),
    )
}
fn expression_context(v: &Value) -> Result<Option<u32>> {
    let mut proto = None;
    for term in v
        .as_array()
        .context("INVALID_ARGUMENT: expression context")?
    {
        let next = if let Some(value) = term.get("transportHeader") {
            Some(header_protocol(value)?)
        } else if let Some(value) = term.get("floodGuard") {
            serde_json::from_value::<crate::flood::Guard>(value.clone())?.context()
        } else if let Some(value) = term.get("icmpHeader") {
            Some(icmp_protocol(value)?)
        } else {
            None
        };
        if let Some(next) = next {
            ensure!(
                proto.is_none_or(|old| old == next),
                "UNSUPPORTED: conflicting transport header protocols"
            );
            proto = Some(next);
        }
    }
    Ok(proto)
}
fn flood_expression(value: &Value, family: u8) -> Result<Vec<u8>> {
    use crate::flood::Guard;
    let guard: Guard = serde_json::from_value(value.clone())?;
    if let Some((name, bytes)) = guard.xt_info(family)? {
        return Ok(expression(
            "match",
            &[
                a(1, &[name.as_bytes(), &[0]].concat()),
                integer_attribute(2, 0),
                a(3, &bytes),
            ]
            .concat(),
        ));
    }
    let (base, offset, mask, bits, inverse) = match guard {
        Guard::TcpFlags { mask, bits, invert } => {
            ensure!(
                mask != 0 && mask & !0x3f == 0 && bits & !mask == 0,
                "UNSUPPORTED: TCP flags"
            );
            (2, 13, vec![mask], vec![bits], invert)
        }
        Guard::Fragment if family == 2 => (1, 6, vec![0x1f, 0xff], vec![0, 0], true),
        _ => anyhow::bail!("UNSUPPORTED: flood protection family"),
    };
    Ok([
        expression(
            "payload",
            &[
                integer_attribute(1, 1),
                integer_attribute(2, base),
                integer_attribute(3, offset),
                integer_attribute(4, mask.len() as u32),
            ]
            .concat(),
        ),
        bitwise(&mask),
        cmp(u32::from(inverse), &bits),
    ]
    .concat())
}

fn expressions(v: &Value, family: u8) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let terms = v
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .context("INVALID_ARGUMENT: native expression list")?;
    for term in terms {
        ensure!(
            term.as_object().is_some_and(|v| v.len() == 1),
            "INVALID_ARGUMENT: native expression object"
        );
        let (name, value) = term.as_object().unwrap().iter().next().unwrap();
        match name.as_str() {
            "floodGuard" => out.extend(flood_expression(value, family)?),
            "accept" | "drop" | "return" => {
                ensure!(value.is_null(), "UNSUPPORTED: native verdict arguments");
                let code = match name.as_str() {
                    "accept" => 1i32,
                    "drop" => 0,
                    _ => -5,
                };
                out.extend(expression(
                    "immediate",
                    &[
                        integer_attribute(1, 0),
                        a(0x8002, &a(0x8002, &a(1, &code.to_be_bytes()))),
                    ]
                    .concat(),
                ));
            }
            "jump" => {
                check_fields(value, &["target"])?;
                let target = bounded_string(&value["target"])?;
                ensure!(
                    !target.is_empty()
                        && target.len() <= 255
                        && target
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)),
                    "UNSUPPORTED: native jump target"
                );
                let verdict = [
                    a(1, &(-3i32).to_be_bytes()),
                    a(2, &string_attribute_value(&value["target"])?),
                ]
                .concat();
                out.extend(expression(
                    "immediate",
                    &[integer_attribute(1, 0), a(0x8002, &a(0x8002, &verdict))].concat(),
                ));
            }
            "counter" => {
                check_fields(value, &["packets", "bytes"])?;
                for key in ["packets", "bytes"] {
                    ensure!(
                        value[key].as_u64().is_some(),
                        "INVALID_ARGUMENT: native counter"
                    );
                }
                out.extend(expression(
                    "counter",
                    &[
                        a(1, &value["bytes"].as_u64().unwrap().to_be_bytes()),
                        a(2, &value["packets"].as_u64().unwrap().to_be_bytes()),
                    ]
                    .concat(),
                ));
            }
            "match" => match_expression(value, family, &mut out, StateEncoding::Native)?,
            "xtState" => {
                check_fields(value, &["alias", "match"])?;
                let alias = value["alias"]
                    .as_bool()
                    .context("Invalid xtables state alias")?;
                ensure!(
                    value["match"]["left"] == json!({"ct":{"key":"state"}}),
                    "Invalid xtables state match"
                );
                match_expression(
                    &value["match"],
                    family,
                    &mut out,
                    StateEncoding::Xtables { alias },
                )?;
            }
            "transportHeader" => {
                let proto = header_protocol(value)?;
                out.extend(meta(16));
                out.extend(cmp(0, &[proto as u8]));
                let name = if proto == 6 { "tcp" } else { "udp" };
                let info = [0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0];
                out.extend(expression(
                    "match",
                    &[
                        a(1, &string_attribute_value(&json!(name))?),
                        integer_attribute(2, 0),
                        a(3, &info),
                    ]
                    .concat(),
                ));
            }
            "icmpHeader" => {
                let proto = icmp_protocol(value)?;
                ensure!(
                    family == if proto == 1 { 2 } else { 10 },
                    "UNSUPPORTED: bounded ICMP header family"
                );
                let kind = unsigned_integer(&value["type"])?;
                let first = unsigned_integer(&value["codeFirst"])?;
                let last = unsigned_integer(&value["codeLast"])?;
                let inverted = value["inverted"]
                    .as_bool()
                    .context("INVALID_ARGUMENT: ICMP inversion")?;
                ensure!(
                    kind <= 255
                        && first <= last
                        && last <= 255
                        && (!inverted || (first == 0 && last == 255))
                        && !(proto == 1 && kind == 255 && inverted),
                    "UNSUPPORTED: bounded ICMP type/code scope"
                );
                out.extend(meta(16));
                out.extend(cmp(0, &[proto as u8]));
                let name = if proto == 1 { "icmp" } else { "icmp6" };
                let info = [
                    kind as u8,
                    first as u8,
                    last as u8,
                    u8::from(inverted),
                    0,
                    0,
                    0,
                    0,
                ];
                out.extend(expression(
                    "match",
                    &[
                        a(1, &string_attribute_value(&json!(name))?),
                        integer_attribute(2, 0),
                        a(3, &info),
                    ]
                    .concat(),
                ));
            }
            "masquerade" => {
                ensure!(
                    value.is_null() || value.as_object().is_some_and(|v| v.is_empty()),
                    "UNSUPPORTED: native masquerade options"
                );
                out.extend(expression("masq", &[]));
            }
            "mangle" => {
                check_fields(value, &["key", "value"])?;
                ensure!(
                    value["key"] == json!({"meta":{"key":"mark"}}),
                    "UNSUPPORTED: native mangle key"
                );
                out.extend(immediate(
                    1,
                    &unsigned_integer(&value["value"])?.to_ne_bytes(),
                ));
                out.extend(expression(
                    "meta",
                    &[integer_attribute(2, 3), integer_attribute(3, 1)].concat(),
                ));
            }
            "snat" | "dnat" => {
                check_fields(value, &["addr", "port", "family"])?;
                let actual_family = match value.get("family").and_then(Value::as_str) {
                    Some("ip") => 2,
                    Some("ip6") => 10,
                    None if [2, 10].contains(&family) => family,
                    _ => anyhow::bail!("UNSUPPORTED: native NAT family"),
                };
                let mut fields = [
                    integer_attribute(1, if name == "snat" { 0 } else { 1 }),
                    integer_attribute(2, actual_family as u32),
                ]
                .concat();
                out.extend(immediate(1, &ip(&value["addr"], actual_family)?));
                fields.extend(integer_attribute(3, 1));
                if let Some(port) = value.get("port") {
                    out.extend(immediate(2, &scalar(port, &Kind::Port)?));
                    fields.extend(integer_attribute(5, 2));
                }
                out.extend(expression("nat", &fields));
            }
            _ => anyhow::bail!("UNSUPPORTED: native expression has no bounded wire adapter"),
        }
    }
    ensure!(
        out.len() <= 60000,
        "RESOURCE_EXHAUSTED: native encoded expressions"
    );
    Ok(out)
}

/// Encode the expression list and any creation-time xtables protocol context.
/// The kernel does not include that context in a subsequent GETRULE reply.
pub fn rule_attributes(terms: &Value, family: u8) -> Result<Vec<u8>> {
    ensure!(
        !uses_xt_state(terms),
        "UNSUPPORTED: xtables state outside original publication"
    );
    model_rule_attributes(terms, family)
}

fn uses_xt_state(terms: &Value) -> bool {
    terms
        .as_array()
        .is_some_and(|list| list.iter().any(|term| term.get("xtState").is_some()))
}

pub(crate) fn model_rule_attributes(terms: &Value, family: u8) -> Result<Vec<u8>> {
    ensure!(
        matches!(family, 1 | 2 | 10),
        "UNSUPPORTED: native mutable family"
    );
    let mut result = attribute(0x8004, &expressions(terms, family)?);
    if let Some(protocol) = expression_context(terms)?.or(uses_xt_state(terms).then_some(0)) {
        result.extend(compatibility_attribute(protocol));
    }
    Ok(result)
}

pub fn attributes(mut b: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !b.is_empty() {
        ensure!(b.len() >= 4, "CONFLICT: truncated Netfilter attribute");
        let n = usize::from(u16::from_ne_bytes([b[0], b[1]]));
        ensure!(
            n >= 4 && n <= b.len(),
            "CONFLICT: invalid Netfilter attribute length"
        );
        let aligned = (n + 3) & !3;
        ensure!(
            aligned <= b.len(),
            "CONFLICT: truncated Netfilter attribute alignment"
        );
        result.push((u16::from_ne_bytes([b[2], b[3]]), &b[4..n]));
        b = &b[aligned..];
    }
    Ok(result)
}
pub fn attribute_text(b: &[u8]) -> Result<String> {
    ensure!(
        !b.is_empty() && b.len() <= 256 && b.last() == Some(&0) && !b[..b.len() - 1].contains(&0),
        "CONFLICT: Netfilter string"
    );
    Ok(std::str::from_utf8(&b[..b.len() - 1])?.into())
}

pub type Attributes<'a> = std::collections::BTreeMap<u16, &'a [u8]>;

pub fn checked_attributes<'a>(bytes: &'a [u8], allowed: &[u16]) -> Result<Attributes<'a>> {
    let mut result = std::collections::BTreeMap::new();
    for (tag, data) in attributes(bytes)? {
        let tag = tag & 0x3fff;
        ensure!(
            allowed.contains(&tag) && result.insert(tag, data).is_none(),
            "UNSUPPORTED: unknown/duplicate raw predicate attribute"
        );
    }
    Ok(result)
}
pub fn required_attribute<'a>(fields: &Attributes<'a>, key: u16) -> Result<&'a [u8]> {
    fields
        .get(&key)
        .copied()
        .context("UNSUPPORTED: missing raw predicate field")
}

#[cfg(test)]
mod state_tests {
    use super::*;
    use crate::witness::expected;

    #[test]
    fn original_state_matches_retain_native_meaning_and_the_xtables_alias() {
        for family in [2, 10] {
            for op in ["in", "not in"] {
                let state = json!({"left":{"ct":{"key":"state"}},"op":op,"right":{"set":["related","established"]}});
                let native = json!([{"match":state},{"accept":null}]);
                for alias in [true, false] {
                    let original =
                        json!([{"xtState":{"alias":alias,"match":state}},{"accept":null}]);
                    let flags = if alias { 0x2001u16 } else { 1u16 };
                    let body = model_rule_attributes(&original, family).unwrap();
                    let mut blob = [0u8; 168];
                    blob[146..148].copy_from_slice(&flags.to_ne_bytes());
                    blob[148..150].copy_from_slice(&u16::from(op == "not in").to_ne_bytes());
                    blob[150..152].copy_from_slice(&6u16.to_ne_bytes());
                    assert!(body.windows(blob.len()).any(|part| part == blob));
                    assert_eq!(
                        expected(family, &original).unwrap(),
                        expected(family, &native).unwrap()
                    );
                    assert!(rule_attributes(&original, family).is_err());
                }
            }
        }
    }
}
