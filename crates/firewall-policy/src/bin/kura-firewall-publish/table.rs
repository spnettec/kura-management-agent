//! Fingerprint a live IPv4 or IPv6 table that xtables cannot render. Keep raw
//! extension data, chain policies, rule order, and static set/map members.
use anyhow::{Context, Result, ensure};
use kura_firewall_policy::{
    netlink::{attribute, attribute_text, attributes},
    parse_rendered,
    publication::FamilyChange,
    transport::{self, Dump},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

type Fields<'a> = Vec<(u16, &'a [u8])>;

fn field<'a>(fields: &Fields<'a>, tag: u16) -> Result<&'a [u8]> {
    let mut values = fields.iter().filter(|(t, _)| t & 0x3fff == tag);
    let value = values
        .next()
        .with_context(|| format!("Missing nftables field {tag}"))?
        .1;
    ensure!(values.next().is_none(), "Duplicate nftables field");
    Ok(value)
}

fn expected_initial_base(table: &str, name: &str) -> Result<(&'static str, u32, i32)> {
    let hook = match name {
        "PREROUTING" => 0,
        "INPUT" => 1,
        "FORWARD" => 2,
        "OUTPUT" => 3,
        "POSTROUTING" => 4,
        _ => anyhow::bail!("UNPAIRED: initial firewall base chain"),
    };
    let (policy, priority) = match (table, name) {
        ("filter", "INPUT" | "FORWARD") => ("DROP", 0),
        ("filter", "OUTPUT") => ("ACCEPT", 0),
        ("nat", "PREROUTING" | "OUTPUT") => ("ACCEPT", -100),
        ("nat", "INPUT" | "POSTROUTING") => ("ACCEPT", 100),
        ("mangle", _) => ("ACCEPT", -150),
        _ => anyhow::bail!("UNPAIRED: initial firewall base chain table"),
    };
    Ok((policy, hook, priority))
}

pub(super) fn verify_initial_chains(
    change: &FamilyChange,
    generation: u32,
    deadline: Instant,
) -> Result<()> {
    let family = match change.family.as_str() {
        "ipv4" => 2,
        "ipv6" => 10,
        _ => anyhow::bail!("INVALID_ARGUMENT: initial firewall family"),
    };
    let layout = parse_rendered(&change.candidate)?;
    let mut remaining = BTreeMap::new();
    for table in &layout.tables {
        for chain in &table.chains {
            remaining.insert(
                (table.name.clone(), chain.name.clone()),
                chain.policy.as_deref(),
            );
        }
    }
    let mut seen = BTreeSet::new();
    transport::read_objects(Dump::Chains, family, &[], deadline, |row| {
        ensure!(row.len() >= 4, "Invalid nftables chain record");
        if row[0] != family {
            return Ok(());
        }
        let fields = attributes(&row[4..])?;
        let key = (
            attribute_text(field(&fields, 1)?)?,
            attribute_text(field(&fields, 3)?)?,
        );
        if let Some(policy) = remaining.remove(&key) {
            let (table, chain) = &key;
            let has_tag = |id| fields.iter().any(|(tag, _)| tag & 0x3fff == id);
            if let Some(policy) = policy {
                let (expected, hook, priority) = expected_initial_base(table, chain)?;
                let kernel_policy = u32::from(policy == "ACCEPT").to_be_bytes();
                let attributes = attributes(field(&fields, 4)?)?;
                ensure!(
                    policy == expected
                        && field(&fields, 5)? == kernel_policy
                        && field(&attributes, 1)? == hook.to_be_bytes()
                        && field(&attributes, 2)? == priority.to_be_bytes(),
                    "CONFLICT: initial firewall hook or policy differs ({table}/{chain})"
                );
            } else {
                ensure!(
                    !has_tag(4) && !has_tag(5),
                    "CONFLICT: initial managed firewall chain is a base chain ({table}/{chain})"
                );
            }
            seen.insert(key);
        } else {
            ensure!(
                !seen.contains(&key),
                "CONFLICT: duplicate initial firewall chain"
            );
        }
        Ok(())
    })?;
    ensure!(
        remaining.is_empty() && transport::generation(deadline)? == generation,
        "CONFLICT: initial firewall chains are missing or changed"
    );
    Ok(())
}

fn count_fields(data: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    for (tag, value) in attributes(data)? {
        if matches!(tag & 0x3fff, 1 | 2) {
            ensure!(value.len() == 8, "Invalid nftables counter");
            result.extend(attribute(tag, &[0; 8]));
        } else {
            result.extend(attribute(tag, value));
        }
    }
    Ok(result)
}

fn expressions(data: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    for (element, expression) in attributes(data)? {
        let fields = attributes(expression)?;
        if field(&fields, 1)? == b"counter\0" {
            let mut normalized = Vec::new();
            for (tag, value) in fields {
                normalized.extend(if tag & 0x3fff == 2 {
                    attribute(tag, &count_fields(value)?)
                } else {
                    attribute(tag, value)
                });
            }
            result.extend(attribute(element, &normalized));
        } else {
            result.extend(attribute(element, expression));
        }
    }
    Ok(result)
}

pub(super) fn digest(family: u8, selected: Option<&str>, deadline: Instant) -> Result<String> {
    let generation = transport::generation(deadline)?;
    let mut hash = Sha256::new();
    if selected.is_some() {
        hash.update(b"Kura boot nftables table v1\0");
    } else {
        hash.update(b"Kura boot nftables family v1\0");
    }
    hash.update([family]);
    let mut tables = BTreeSet::new();
    let mut sets = Vec::new();
    let mut bytes = 0usize;
    let mut rows = |kind, filter: &[u8], sets: &mut Vec<(String, String)>| {
        transport::read_objects(kind, family, filter, deadline, |row| {
            ensure!(row.len() >= 4, "Invalid nftables record");
            if row[0] != family {
                return Ok(());
            }
            let fields = attributes(&row[4..])?;
            let table = attribute_text(field(&fields, 1)?)?;
            if selected.is_some_and(|name| name != table) {
                return Ok(());
            }
            bytes += row.len();
            ensure!(bytes <= 16 * 1024 * 1024, "Table snapshot too large");
            if kind == Dump::Tables {
                ensure!(
                    tables.len() < 8192 && tables.insert(table.clone()),
                    "Invalid native table catalogue"
                );
            } else {
                ensure!(tables.contains(&table), "Missing native table definition");
            }
            if kind == Dump::Sets {
                let flags = match fields.iter().find(|(tag, _)| tag & 0x3fff == 3) {
                    Some(_) => u32::from_be_bytes(field(&fields, 3)?.try_into()?),
                    None => 0,
                };
                ensure!(
                    flags & 0x30 == 0,
                    "Cannot bind expiring or packet-updated set members"
                );
                ensure!(sets.len() < 4096, "Too many nftables sets");
                sets.push((table, attribute_text(field(&fields, 2)?)?));
            }
            let counter_object = kind == Dump::Objects && field(&fields, 3)? == 1u32.to_be_bytes();
            let mut record = Vec::new();
            for (tag, value) in fields {
                let id = tag & 0x3fff;
                let normalized = match (kind, id) {
                    (Dump::Rules, 4) => expressions(value)?,
                    (Dump::Chains, 8) => count_fields(value)?,
                    (Dump::Objects, 4) if counter_object => count_fields(value)?,
                    _ => value.to_vec(),
                };
                record.extend(attribute(tag, &normalized));
            }
            hash.update([kind as u8]);
            hash.update((record.len() as u64).to_be_bytes());
            hash.update(record);
            Ok(())
        })
    };
    for kind in [
        Dump::Tables,
        Dump::Chains,
        Dump::Rules,
        Dump::Sets,
        Dump::Objects,
        Dump::Flowtables,
    ] {
        rows(kind, &[], &mut sets)?;
    }
    for (table, set) in std::mem::take(&mut sets) {
        let mut filter = attribute(1, &[table.as_bytes(), &[0]].concat());
        filter.extend(attribute(2, &[set.as_bytes(), &[0]].concat()));
        rows(Dump::Elements, &filter, &mut sets)?;
    }
    ensure!(
        selected.is_none_or(|name| tables.contains(name))
            && transport::generation(deadline)? == generation,
        "Native firewall table changed during observation"
    );
    Ok(super::hex(&hash.finalize()))
}
