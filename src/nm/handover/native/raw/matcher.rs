//! Bind shared rule semantics to the complete original agent command and its receipt.
use super::*;
use kura_firewall_policy::netlink::{checked_attributes as fields, required_attribute as get};
use kura_firewall_policy::witness;
#[cfg(test)]
use witness::Signature;
#[cfg(test)]
fn expected(family: &str, expr: &Value) -> Result<Signature> {
    let number = match family {
        "ip" => 2,
        "ip6" => 10,
        "inet" => 1,
        _ => anyhow::bail!("UNSUPPORTED: native family"),
    };
    witness::expected(number, expr)
}
#[cfg(test)]
fn observed(payload: &str) -> Option<Signature> {
    witness::observed(&decode(payload).ok()?)
}

pub(in crate::nm::handover::native) fn replacement_matches(
    payload: &str,
    wanted: &Value,
) -> Result<bool> {
    let source = match decode(payload) {
        Ok(bytes) if witness::observed(&bytes).is_some() => bytes,
        _ => return Ok(false),
    };
    let batch = json!({"expectedGeneration":1,"nftables":[{"add":{"rule":wanted}}]});
    let (bytes, _) = writer::encode(&batch)?;
    let start = u32n(&bytes) as usize;
    let message = &bytes[start..];
    let end = u32n(message) as usize;
    let expected = fields(&message[20..end], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
    let actual = fields(&source[4..], &[1, 2, 3, 4, 5, 7, 8])?;
    if [1, 2, 7]
        .iter()
        .any(|key| actual.get(key) != expected.get(key))
    {
        return Ok(false);
    }
    witness::matches_expression_list(&source, message[16], get(&expected, 4)?)
}
pub(in crate::nm::handover::native) fn model_matches(
    payload: &str,
    family: &str,
    expr: &Value,
) -> Result<bool> {
    let source = match decode(payload) {
        Ok(bytes) if witness::observed(&bytes).is_some() => bytes,
        _ => return Ok(false),
    };
    let batch = json!({"expectedGeneration":1,"nftables":[{"add":{"rule":{"family":family,"table":"model","chain":"model","expr":expr}}}]});
    let (bytes, _) = writer::encode(&batch)?;
    let start = u32n(&bytes) as usize;
    let message = &bytes[start..];
    let end = u32n(message) as usize;
    let expected = fields(&message[20..end], &[1, 2, 3, 4, 5])?;
    witness::matches_expression_list(&source, message[16], get(&expected, 4)?)
}
#[cfg(test)]
mod tests;
