//! Read-only matching of a previously authenticated model against raw Netfilter rules.
use crate::netlink::{
    Attributes as Fields, checked_attributes as fields, required_attribute as get,
};
use crate::netlink::{
    attribute, attribute_text as text, attributes as attrs, model_rule_attributes,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
mod compat;
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signature {
    family: u8,
    predicates: BTreeSet<Predicate>,
    action: Action,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Meta(u32),
    Payload(u32, u32, usize),
    State,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Predicate {
    Compare(Key, Vec<u8>, u32, Vec<u8>),
    Range(Key, bool, Vec<u8>, Vec<u8>),
    State(u32, bool),
    TransportHeader(u8),
    FloodGuard(crate::flood::Guard),
    Impossible,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Action {
    Accept,
    Drop,
    Return,
    Jump(String),
    Masquerade,
    Nat(u32, u8, Vec<u8>, Option<Vec<u8>>),
}
#[derive(Clone)]
enum Register {
    Field(Key, Vec<u8>),
    Data(Vec<u8>),
}
fn number(fields: &Fields<'_>, key: u16) -> Result<u32> {
    let value = get(fields, key)?;
    ensure!(value.len() == 4, "UNSUPPORTED: raw u32 width");
    Ok(u32::from_be_bytes(value.try_into().unwrap()))
}
fn data(bytes: &[u8]) -> Result<Vec<u8>> {
    let v = fields(bytes, &[1])?;
    let value = get(&v, 1)?;
    ensure!(
        !value.is_empty() && value.len() <= 16,
        "UNSUPPORTED: raw literal width"
    );
    Ok(value.to_vec())
}
fn reg(id: u32) -> Result<u32> {
    match id {
        1..=4 => Ok((id - 1) * 16),
        8..=23 => Ok((id - 8) * 4),
        _ => anyhow::bail!("UNSUPPORTED: non-data raw register"),
    }
}
fn set(registers: &mut BTreeMap<u32, Register>, id: u32, value: Register) -> Result<()> {
    let start = reg(id)?;
    let width = match &value {
        Register::Field(_, v) | Register::Data(v) => v.len() as u32,
    };
    ensure!(start + width <= 64, "UNSUPPORTED: raw register span");
    registers.retain(|old, stored| {
        let len = match stored {
            Register::Field(_, v) | Register::Data(v) => v.len() as u32,
        };
        *old >= start + width || start >= *old + len
    });
    registers.insert(start, value);
    Ok(())
}
fn field(registers: &BTreeMap<u32, Register>, id: u32) -> Result<(Key, Vec<u8>)> {
    match registers.get(&reg(id)?) {
        Some(Register::Field(key, mask)) => Ok((key.clone(), mask.clone())),
        _ => anyhow::bail!("UNSUPPORTED: raw predicate reads an unwitnessed register"),
    }
}
fn literal(registers: &BTreeMap<u32, Register>, id: u32, width: usize) -> Result<Vec<u8>> {
    match registers.get(&reg(id)?) {
        Some(Register::Data(value)) if value.len() == width => Ok(value.clone()),
        _ => anyhow::bail!("UNSUPPORTED: raw NAT reads an unwitnessed literal"),
    }
}
fn compare(
    predicates: &mut BTreeSet<Predicate>,
    family: u8,
    mut key: Key,
    mut mask: Vec<u8>,
    op: u32,
    mut value: Vec<u8>,
) -> Result<()> {
    ensure!(op <= 5, "UNSUPPORTED: raw comparison operator");
    if key == Key::State {
        ensure!(
            mask.len() == 4 && value == [0, 0, 0, 0] && [0, 1].contains(&op),
            "UNSUPPORTED: raw state comparison"
        );
        let bits = u32::from_ne_bytes(mask.try_into().unwrap());
        ensure!(bits > 0 && bits & !15 == 0, "UNSUPPORTED: raw state bits");
        predicates.insert(Predicate::State(bits, op == 0));
        return Ok(());
    }
    if matches!(key, Key::Meta(6 | 7)) {
        ensure!(
            [0, 1].contains(&op) && value.len() <= 16 && mask.iter().all(|v| *v == 255),
            "UNSUPPORTED: masked/ranged interface"
        );
        if let Some(end) = value.iter().position(|v| *v == 0) {
            ensure!(
                value[end..].iter().all(|v| *v == 0),
                "UNSUPPORTED: noncanonical interface padding"
            );
            value.truncate(end + 1);
        }
        ensure!(
            !value.is_empty(),
            "UNSUPPORTED: empty native interface prefix"
        );
        mask = vec![255; value.len()];
    } else {
        ensure!(
            value.len() == mask.len(),
            "UNSUPPORTED: raw comparison width"
        );
    }
    // The address lies within the mandatory IP network header. A short byte-
    // aligned prefix load and a full-width masked load have identical meaning.
    if let Key::Payload(1, offset, len) = key {
        let width = if family == 2 && [12, 16].contains(&offset) {
            Some(4)
        } else if family == 10 && [8, 24].contains(&offset) {
            Some(16)
        } else {
            None
        };
        if let Some(width) = width.filter(|width| len < *width) {
            ensure!(
                [0, 1].contains(&op),
                "UNSUPPORTED: ordered short address comparison"
            );
            mask.resize(width, 0);
            value.resize(width, 0);
            key = Key::Payload(1, offset, width);
        }
    }
    if key == Key::Meta(15) && [2, 10].contains(&family) && mask == [255] && [0, 1].contains(&op) {
        if (value == [family]) != (op == 0) {
            predicates.insert(Predicate::Impossible);
        }
        return Ok(());
    }
    predicates.insert(Predicate::Compare(key, mask, op, value));
    Ok(())
}
fn range(
    predicates: &mut BTreeSet<Predicate>,
    key: Key,
    mask: Vec<u8>,
    negated: bool,
    min: Vec<u8>,
    max: Vec<u8>,
) -> Result<()> {
    ensure!(
        mask.iter().all(|v| *v == 255)
            && min.len() == mask.len()
            && max.len() == mask.len()
            && min <= max,
        "UNSUPPORTED: raw masked/ranged value"
    );
    if min == max {
        predicates.insert(Predicate::Compare(key, mask, u32::from(negated), min));
    } else {
        predicates.insert(Predicate::Range(key, negated, min, max));
    }
    Ok(())
}
fn normalize_ranges(predicates: &mut BTreeSet<Predicate>) {
    let values = predicates.iter().cloned().collect::<Vec<_>>();
    for low in &values {
        if let Predicate::Compare(key, mask, 5, min) = low {
            if !matches!(key, Key::Payload(2, 0 | 2, 2)) || !mask.iter().all(|v| *v == 255) {
                continue;
            }
            let upper = values
                .iter()
                .find(|v| matches!(v,Predicate::Compare(k,m,3,max) if k==key&&m==mask&&min<=max));
            if let Some(high @ Predicate::Compare(_, _, _, max)) = upper {
                predicates.remove(low);
                predicates.remove(high);
                range(
                    predicates,
                    key.clone(),
                    mask.clone(),
                    false,
                    min.clone(),
                    max.clone(),
                )
                .unwrap();
            }
        }
    }
}

fn signature(family: u8, bytes: &[u8]) -> Result<Signature> {
    ensure!([1, 2, 10].contains(&family), "UNSUPPORTED: raw family");
    let expressions = attrs(bytes)?;
    ensure!(
        !expressions.is_empty() && expressions.len() <= 256,
        "UNSUPPORTED: raw expression count"
    );
    let mut registers = BTreeMap::new();
    let mut predicates = BTreeSet::new();
    let mut pending = BTreeSet::new();
    let mut action = None;
    for (tag, bytes) in expressions {
        ensure!(tag & 0x3fff == 1, "UNSUPPORTED: raw expression item");
        let expression = fields(bytes, &[1, 2])?;
        let name = text(get(&expression, 1)?)?;
        ensure!(
            action.is_none(),
            "UNSUPPORTED: raw expression after terminal action"
        );
        let bytes = get(&expression, 2)?;
        match name.as_str() {
            "counter" => {
                let f = fields(bytes, &[1, 2, 3])?;
                ensure!(
                    f.get(&3).is_none_or(|padding| padding.is_empty())
                        && get(&f, 1)?.len() == 8
                        && get(&f, 2)?.len() == 8,
                    "UNSUPPORTED: raw counter width"
                );
            }
            "meta" => {
                let f = fields(bytes, &[1, 2])?;
                let key = number(&f, 2)?;
                let width = match key {
                    6 | 7 => 16,
                    8 => 2,
                    15 | 16 => 1,
                    3 => 4,
                    _ => anyhow::bail!("UNSUPPORTED: native meta predicate"),
                };
                pending.insert(Key::Meta(key));
                set(
                    &mut registers,
                    number(&f, 1)?,
                    Register::Field(Key::Meta(key), vec![255; width]),
                )?;
            }
            "payload" => {
                let f = fields(bytes, &[1, 2, 3, 4])?;
                let base = number(&f, 2)?;
                let offset = number(&f, 3)?;
                let len = number(&f, 4)? as usize;
                ensure!(
                    base <= 2 && offset <= 256 && (1..=16).contains(&len),
                    "UNSUPPORTED: payload scope"
                );
                let key = if family == 2 && base == 1 && offset == 9 && len == 1 {
                    Key::Meta(16)
                } else {
                    Key::Payload(base, offset, len)
                };
                pending.insert(key.clone());
                set(
                    &mut registers,
                    number(&f, 1)?,
                    Register::Field(key, vec![255; len]),
                )?;
            }
            "ct" => {
                let f = fields(bytes, &[1, 2])?;
                ensure!(number(&f, 2)? == 0, "UNSUPPORTED: non-state conntrack");
                pending.insert(Key::State);
                set(
                    &mut registers,
                    number(&f, 1)?,
                    Register::Field(Key::State, vec![255; 4]),
                )?;
            }
            "bitwise" => {
                let f = fields(bytes, &[1, 2, 3, 4, 5, 6])?;
                ensure!(
                    !f.contains_key(&6) || number(&f, 6)? == 0,
                    "UNSUPPORTED: bitwise operation"
                );
                let (key, old) = field(&registers, number(&f, 1)?)?;
                let mask = data(get(&f, 4)?)?;
                let xor = data(get(&f, 5)?)?;
                ensure!(
                    number(&f, 3)? as usize == mask.len()
                        && mask.len() == old.len()
                        && xor.len() == mask.len()
                        && xor.iter().all(|v| *v == 0),
                    "UNSUPPORTED: non-mask bitwise predicate"
                );
                let mask = old.iter().zip(mask).map(|(a, b)| a & b).collect();
                set(&mut registers, number(&f, 2)?, Register::Field(key, mask))?;
            }
            "cmp" => {
                let f = fields(bytes, &[1, 2, 3])?;
                let (key, mask) = field(&registers, number(&f, 1)?)?;
                pending.remove(&key);
                compare(
                    &mut predicates,
                    family,
                    key,
                    mask,
                    number(&f, 2)?,
                    data(get(&f, 3)?)?,
                )?;
            }
            "range" => {
                let f = fields(bytes, &[1, 2, 3, 4])?;
                let op = number(&f, 2)?;
                ensure!(op <= 1, "UNSUPPORTED: raw range operator");
                let (key, mask) = field(&registers, number(&f, 1)?)?;
                pending.remove(&key);
                range(
                    &mut predicates,
                    key,
                    mask,
                    op == 1,
                    data(get(&f, 3)?)?,
                    data(get(&f, 4)?)?,
                )?;
            }
            "immediate" => {
                let f = fields(bytes, &[1, 2])?;
                let dest = number(&f, 1)?;
                if dest == 0 {
                    let outer = fields(get(&f, 2)?, &[2])?;
                    let verdict = fields(get(&outer, 2)?, &[1, 2])?;
                    let code = number(&verdict, 1)? as i32;
                    action = Some(match code {
                        1 => {
                            ensure!(verdict.len() == 1, "UNSUPPORTED: verdict fields");
                            Action::Accept
                        }
                        0 => {
                            ensure!(verdict.len() == 1, "UNSUPPORTED: verdict fields");
                            Action::Drop
                        }
                        -5 => {
                            ensure!(verdict.len() == 1, "UNSUPPORTED: verdict fields");
                            Action::Return
                        }
                        -3 => Action::Jump(text(get(&verdict, 2)?)?),
                        _ => anyhow::bail!("UNSUPPORTED: non-model verdict"),
                    });
                } else {
                    set(&mut registers, dest, Register::Data(data(get(&f, 2)?)?))?;
                }
            }
            "masq" => {
                let f = fields(bytes, &[1])?;
                ensure!(
                    f.is_empty() || number(&f, 1)? == 0,
                    "UNSUPPORTED: masquerade flags"
                );
                action = Some(Action::Masquerade);
            }
            "nat" => {
                let f = fields(bytes, &[1, 2, 3, 4, 5, 6, 7])?;
                let mode = number(&f, 1)?;
                let scope = number(&f, 2)?;
                let implied_flags = 1 | if f.contains_key(&5) { 2 } else { 0 };
                // nft_nat_init ORs MAP_IPS/PROTO_SPECIFIED into the dump. These
                // are already implied by the exact address/port registers.
                ensure!(
                    mode <= 1
                        && [2, 10].contains(&scope)
                        && (family == 1 || u32::from(family) == scope)
                        && (!f.contains_key(&7) || number(&f, 7)? & !implied_flags == 0),
                    "UNSUPPORTED: NAT mode/family/flags"
                );
                let scope = scope as u8;
                let width = if scope == 2 { 4 } else { 16 };
                let addr = literal(&registers, number(&f, 3)?, width)?;
                if f.contains_key(&4) {
                    ensure!(
                        addr == literal(&registers, number(&f, 4)?, width)?,
                        "UNSUPPORTED: address range"
                    );
                }
                let port = if f.contains_key(&5) {
                    Some(literal(&registers, number(&f, 5)?, 2)?)
                } else {
                    None
                };
                if f.contains_key(&6) {
                    ensure!(
                        port == Some(literal(&registers, number(&f, 6)?, 2)?),
                        "UNSUPPORTED: port range"
                    );
                }
                action = Some(Action::Nat(mode, scope, addr, port));
            }
            "match" => compat::matching(bytes, family, &mut predicates)?,
            "target" => {
                action = Some(compat::target(bytes, family)?);
            }
            _ => anyhow::bail!("UNSUPPORTED: opaque native expression"),
        }
    }
    ensure!(
        pending.is_empty(),
        "UNSUPPORTED: unconsumed packet-read guard"
    );
    normalize_ranges(&mut predicates);
    Ok(Signature {
        family,
        predicates,
        action: action.context("UNSUPPORTED: no terminal model action")?,
    })
}

pub fn expected(family: u8, terms: &Value) -> Result<Signature> {
    let encoded = model_rule_attributes(terms, family)?;
    let f = fields(&encoded, &[4, 5])?;
    signature(family, get(&f, 4)?)
}

pub fn observed(bytes: &[u8]) -> Option<Signature> {
    observed_inner(bytes).ok()
}

fn observed_inner(bytes: &[u8]) -> Result<Signature> {
    ensure!(
        bytes.len() >= 4 && bytes.len() <= 8192 && bytes[1] == 0,
        "UNSUPPORTED: raw rule header or length"
    );
    let f = fields(&bytes[4..], &[1, 2, 3, 4, 5, 6, 7, 8])?;
    ensure!(
        f.get(&6).is_none_or(|position| position.len() == 8)
            && f.get(&8).is_none_or(|padding| padding.is_empty()),
        "UNSUPPORTED: raw rule placement or padding"
    );
    if let Some(bytes) = f.get(&5) {
        let c = fields(bytes, &[1, 2])?;
        ensure!(
            number(&c, 1)? <= 65535 && [0, 2].contains(&number(&c, 2)?),
            "UNSUPPORTED: rule compatibility metadata"
        );
    }
    signature(bytes[0], get(&f, 4)?)
}
/// Compare the counter positions and predicates of a source rule with the encoded candidate.
/// The calling adapter checks the chain, handle and userdata for its operation.
pub fn matches_expression_list(source: &[u8], family: u8, encoded_terms: &[u8]) -> Result<bool> {
    let Some(actual) = observed(source) else {
        return Ok(false);
    };
    if actual != signature(family, encoded_terms)? {
        return Ok(false);
    }
    let f = fields(&source[4..], &[1, 2, 3, 4, 5, 6, 7, 8])?;
    Ok(counter_guards(source[0], get(&f, 4)?)? == counter_guards(family, encoded_terms)?)
}
fn counter_guards(family: u8, expressions: &[u8]) -> Result<Vec<Signature>> {
    let encoded = model_rule_attributes(&json!([{"accept":null}]), family)?;
    let accept = fields(&encoded, &[4])?;
    let entries = attrs(expressions)?;
    let mut prefix = Vec::new();
    let mut result = Vec::new();
    for (kind, data) in &entries {
        let fields = fields(data, &[1, 2])?;
        if text(get(&fields, 1)?)? == "counter" {
            let mut probe = prefix.clone();
            probe.extend(get(&accept, 4)?);
            result.push(signature(family, &probe)?);
        }
        prefix.extend(attribute(*kind, data));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_icmp_header_guard_and_ipv6_type_255_are_not_normalized_away() {
        for (family, protocol, number, kind) in [("ip", "icmp", 1, 8), ("ip6", "icmpv6", 58, 128)] {
            let guarded = json!([{"icmpHeader":{"protocol":protocol,"type":kind,"codeFirst":0,"codeLast":255,"inverted":false}},{"accept":null}]);
            let unguarded = json!([{"match":{"left":{"meta":{"key":"l4proto"}},"op":"==","right":number}},{"match":{"left":{"payload":{"protocol":protocol,"field":"type"}},"op":"==","right":kind}},{"accept":null}]);
            assert_ne!(
                expected(if family == "ip" { 2 } else { 10 }, &guarded).unwrap(),
                expected(if family == "ip" { 2 } else { 10 }, &unguarded).unwrap()
            );
        }
        let signature=expected(10,&json!([{"icmpHeader":{"protocol":"icmpv6","type":255,"codeFirst":0,"codeLast":255,"inverted":false}},{"accept":null}])).unwrap();
        assert!(signature.predicates.contains(&Predicate::Compare(
            Key::Payload(2, 0, 1),
            vec![255],
            0,
            vec![255]
        )));
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RuleMatch {
    pub ordinal: usize,
    pub handle: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChainMatch {
    pub rules: Vec<RuleMatch>,
    pub opaque: usize,
}

/// Locate the original model's rows in one complete kernel chain in dump order.
/// A match describes observed traffic semantics. A writer must additionally
/// authenticate the prior model, bind the source generation and verify its authority.
pub fn match_chain<P: AsRef<[u8]>>(
    family: u8,
    table: &str,
    chain: &str,
    model: &[Vec<Value>],
    dump: &[P],
) -> Result<ChainMatch> {
    ensure!(
        matches!(family, 2 | 10),
        "UNSUPPORTED: original model family"
    );
    check_scope(model.len(), dump.len())?;
    let signatures = model
        .iter()
        .map(|terms| expected(family, &json!(terms)))
        .collect::<Result<Vec<_>>>()?;
    let mut identities = Vec::with_capacity(dump.len());
    let mut seen = BTreeSet::new();
    let mut actual = Vec::with_capacity(dump.len());
    for row in dump {
        let row = row.as_ref();
        ensure!(
            row.len() >= 4 && row.len() <= 8192 && row[0] == family && row[1] == 0,
            "CONFLICT: original rule family, version or length"
        );
        let attributes = attrs(&row[4..])?;
        let required = |tag| -> Result<&[u8]> {
            let mut found = attributes.iter().filter(|(kind, _)| kind & 0x3fff == tag);
            let value = found.next().context("CONFLICT: missing rule identity")?.1;
            ensure!(found.next().is_none(), "CONFLICT: duplicate rule identity");
            Ok(value)
        };
        ensure!(
            text(required(1)?)? == table && text(required(2)?)? == chain,
            "CONFLICT: rule outside original chain"
        );
        let handle = u64::from_be_bytes(
            required(3)?
                .try_into()
                .context("CONFLICT: rule handle width")?,
        );
        ensure!(
            handle > 0 && seen.insert(handle),
            "CONFLICT: zero or duplicate rule handle"
        );
        let has_userdata = attributes.iter().any(|(tag, _)| tag & 0x3fff == 7);
        identities.push((handle, has_userdata));
        actual.push(observed(row));
    }
    let indices = unique_selection(&signatures, &actual)?;
    let mut rules = Vec::with_capacity(indices.len());
    for ordinal in indices {
        let (handle, has_userdata) = identities[ordinal];
        // The original Java clauses have no userdata. Include tagged rows when
        // detecting ambiguity, but never adopt a site's metadata as our own.
        ensure!(
            !has_userdata,
            "CONFLICT: selected original rule has unmodeled userdata"
        );
        rules.push(RuleMatch { ordinal, handle });
    }
    Ok(ChainMatch {
        rules,
        opaque: actual.iter().filter(|v| v.is_none()).count(),
    })
}

fn check_scope(model: usize, dump: usize) -> Result<()> {
    ensure!(
        model <= 4096 && dump <= 8192 && (model + 1) * (dump + 1) <= 1_048_576,
        "RESOURCE_EXHAUSTED: model matching scope"
    );
    Ok(())
}

/// Ordered matching is unique exactly when its earliest and latest embeddings coincide.
pub fn unique_selection<T: PartialEq>(expected: &[T], actual: &[Option<T>]) -> Result<Vec<usize>> {
    check_scope(expected.len(), actual.len())?;
    let mut forward = actual.iter().enumerate();
    let mut indices = Vec::with_capacity(expected.len());
    for wanted in expected {
        let (index, _) = forward
            .find(|(_, entry)| entry.as_ref() == Some(wanted))
            .context("CONFLICT: managed model rules missing,reordered or ambiguous")?;
        indices.push(index);
    }
    let mut reverse = actual.iter().enumerate().rev();
    for (wanted, first) in expected.iter().zip(&indices).rev() {
        let (last, _) = reverse
            .find(|(_, entry)| entry.as_ref() == Some(wanted))
            .context("CONFLICT: managed model rules missing,reordered or ambiguous")?;
        ensure!(
            *first == last,
            "CONFLICT: managed model rules missing,reordered or ambiguous"
        );
    }
    Ok(indices)
}
