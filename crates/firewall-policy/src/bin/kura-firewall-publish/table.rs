//! Fingerprint a live IPv4 or IPv6 table that xtables cannot render. Keep raw
//! extension data, chain policies, rule order, and static set/map members.
use anyhow::{Context, Result, ensure};
use kura_firewall_policy::{
    netlink::{attribute, attribute_text, attributes},
    transport::{self, Dump},
};
use sha2::{Digest, Sha256};
use std::time::Instant;

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

pub(super) fn digest(family: u8, table: &str, deadline: Instant) -> Result<String> {
    let generation = transport::generation(deadline)?;
    let mut hash = Sha256::new();
    hash.update(b"Kura boot nftables table v1\0");
    hash.update([family]);
    let mut found = 0;
    let mut sets = Vec::new();
    let mut bytes = 0usize;
    let mut rows = |kind, filter: &[u8], sets: &mut Vec<String>| {
        transport::read_objects(kind, family, filter, deadline, |row| {
            ensure!(row.len() >= 4, "Invalid nftables record");
            if row[0] != family {
                return Ok(());
            }
            let fields = attributes(&row[4..])?;
            if attribute_text(field(&fields, 1)?)? != table {
                return Ok(());
            }
            bytes += row.len();
            ensure!(bytes <= 16 * 1024 * 1024, "Table snapshot too large");
            if kind == Dump::Tables {
                found += 1;
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
                sets.push(attribute_text(field(&fields, 2)?)?);
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
    for set in std::mem::take(&mut sets) {
        let mut filter = attribute(1, &[table.as_bytes(), &[0]].concat());
        filter.extend(attribute(2, &[set.as_bytes(), &[0]].concat()));
        rows(Dump::Elements, &filter, &mut sets)?;
    }
    ensure!(
        found == 1 && transport::generation(deadline)? == generation,
        "Native firewall table changed during observation"
    );
    Ok(super::hex(&hash.finalize()))
}
