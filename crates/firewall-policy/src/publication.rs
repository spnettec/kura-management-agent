//! Compile an authenticated pair of original-layout models into a bounded kernel delta.
use crate::{
    compile_layout,
    netlink::{attribute, rule_attributes},
    parse_rendered,
    transport::message,
    witness::{expected, match_chain, observed, unique_selection},
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const FIRST_SEQUENCE: u32 = 0x594f4600;
pub type RuleDump = BTreeMap<(u8, String, String), Vec<Vec<u8>>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyChange {
    pub family: String,
    pub previous: String,
    pub candidate: String,
}

pub struct Publication {
    pub generation: u32,
    pub commands: usize,
    pub wire: Vec<u8>,
    pub end: u32,
}

struct Batch {
    commands: usize,
    wire: Vec<u8>,
}

struct Chain<'a> {
    family: u8,
    table: &'a str,
    name: &'a str,
}

impl Batch {
    fn push(
        &mut self,
        chain: &Chain<'_>,
        kind: u16,
        flags: u16,
        reference: Option<(u16, u64)>,
        rule: Option<&Vec<Value>>,
    ) -> Result<()> {
        let mut payload = attribute(1, &[chain.table.as_bytes(), b"\0"].concat());
        payload.extend(attribute(2, &[chain.name.as_bytes(), b"\0"].concat()));
        if let Some((tag, handle)) = reference {
            payload.extend(attribute(tag, &handle.to_be_bytes()));
        }
        if let Some(terms) = rule {
            payload.extend(rule_attributes(&json!(terms), chain.family)?);
        }
        self.commands += 1;
        ensure!(
            self.commands <= 8192,
            "RESOURCE_EXHAUSTED: firewall commands"
        );
        self.wire.extend(message(
            2560 + kind,
            flags | 1,
            FIRST_SEQUENCE + self.commands as u32,
            chain.family,
            0,
            &payload,
        ));
        ensure!(
            self.wire.len() + 20 <= 512 * 1024,
            "RESOURCE_EXHAUSTED: firewall datagram"
        );
        Ok(())
    }
}

/// Keep equal rules in place, including their handles and counters. The LCS
/// is bounded before allocation. Equal alternatives keep the earliest old row.
fn retained(old: &[Vec<Value>], new: &[Vec<Value>]) -> Result<Vec<(usize, usize)>> {
    let width = new.len() + 1;
    ensure!(
        (old.len() + 1) * width <= 1_048_576,
        "RESOURCE_EXHAUSTED: firewall change scope"
    );
    let mut cells = vec![0u16; (old.len() + 1) * width];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            cells[i * width + j] = if old[i] == new[j] {
                1 + cells[(i + 1) * width + j + 1]
            } else {
                cells[(i + 1) * width + j].max(cells[i * width + j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut kept = Vec::new();
    while i < old.len() && j < new.len() {
        if old[i] == new[j] {
            kept.push((i, j));
            i += 1;
            j += 1;
        } else if cells[i * width + j + 1] >= cells[(i + 1) * width + j] {
            j += 1;
        } else {
            i += 1;
        }
    }
    kept.push((old.len(), new.len()));
    Ok(kept)
}

fn mutable_chain(table: &str, name: &str) -> bool {
    match table {
        "filter" => matches!(
            name,
            "input-kura" | "output-kura" | "forward-kura" | "forward-kura-pf" | "forward-kura-ipf"
        ),
        "nat" => matches!(
            name,
            "input-kura"
                | "output-kura"
                | "prerouting-kura"
                | "prerouting-kura-pf"
                | "postrouting-kura"
                | "postrouting-kura-pf"
                | "postrouting-kura-ipf"
        ),
        "mangle" => matches!(
            name,
            "input-kura" | "output-kura" | "forward-kura" | "prerouting-kura" | "postrouting-kura"
        ),
        _ => false,
    }
}

fn check_declarations(table: &crate::Table) -> Result<()> {
    let bases: &[&str] = match table.name.as_str() {
        "filter" => &["INPUT", "OUTPUT", "FORWARD"],
        "nat" => &["INPUT", "OUTPUT", "PREROUTING", "POSTROUTING"],
        "mangle" => &["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"],
        _ => anyhow::bail!("CONFLICT: original firewall table"),
    };
    let regular_count = match table.name.as_str() {
        "filter" => 5,
        "nat" => 7,
        _ => 5,
    };
    ensure!(
        table.chains.len() == bases.len() + regular_count
            && table.chains.iter().all(|c| {
                if bases.contains(&c.name.as_str()) {
                    matches!(c.policy.as_deref(), Some("DROP" | "ACCEPT"))
                } else {
                    c.policy.is_none() && mutable_chain(&table.name, &c.name)
                }
            }),
        "CONFLICT: incomplete or unexpected firewall declarations"
    );
    Ok(())
}

fn plan_chain(
    batch: &mut Batch,
    chain: &Chain<'_>,
    old: &[Vec<Value>],
    new: &[Vec<Value>],
    raw: &[Vec<u8>],
) -> Result<()> {
    let owned = match_chain(chain.family, chain.table, chain.name, old, raw)?.rules;
    if old == new {
        return Ok(());
    }
    ensure!(
        mutable_chain(chain.table, chain.name),
        "CONFLICT: original firewall chain is not writable"
    );
    let target = new
        .iter()
        .map(|terms| expected(chain.family, &json!(terms)))
        .collect::<Result<Vec<_>>>()?;
    // Simulate the exact insertion positions, so the resulting model is still
    // uniquely identifiable among the site's unmodified rules.
    let mut projected = raw.iter().map(|row| observed(row)).collect::<Vec<_>>();
    let mut shift: isize = 0;
    let (mut a, mut b) = (0, 0);
    for (end_old, end_new) in retained(old, new)? {
        let common = (end_old - a).min(end_new - b);
        for k in 0..common {
            let row = &owned[a + k];
            batch.push(chain, 6, 0x100, Some((3, row.handle)), Some(&new[b + k]))?;
            projected[row
                .ordinal
                .checked_add_signed(shift)
                .context("invalid firewall position")?] = Some(target[b + k].clone());
        }
        for row in &owned[a + common..end_old] {
            batch.push(chain, 8, 0, Some((3, row.handle)), None)?;
            projected.remove(
                row.ordinal
                    .checked_add_signed(shift)
                    .context("invalid firewall deletion")?,
            );
            shift -= 1;
        }
        let extra = b + common..end_new;
        if !extra.is_empty() {
            let next = owned.get(end_old);
            let previous = end_old.checked_sub(1).and_then(|i| owned.get(i));
            let original_at = next
                .map(|r| r.ordinal)
                .or_else(|| previous.map(|r| r.ordinal + 1))
                .unwrap_or(0);
            ensure!(
                next.is_some() || previous.is_some() || raw.is_empty(),
                "CONFLICT: no owned insertion position"
            );
            let at = original_at
                .checked_add_signed(shift)
                .context("invalid firewall insertion")?;
            if let Some(next) = next {
                // Repeated insert-before keeps model order.
                for i in extra.clone() {
                    batch.push(chain, 6, 0x400, Some((6, next.handle)), Some(&new[i]))?;
                }
            } else if let Some(previous) = previous {
                // Repeated append-after the same predecessor uses reverse order.
                for i in extra.clone().rev() {
                    batch.push(chain, 6, 0xc00, Some((6, previous.handle)), Some(&new[i]))?;
                }
            } else {
                for i in extra.clone() {
                    batch.push(chain, 6, 0xc00, None, Some(&new[i]))?;
                }
            }
            shift += extra.len() as isize;
            projected.splice(at..at, extra.map(|i| Some(target[i].clone())));
        }
        a = end_old + 1;
        b = end_new + 1;
    }
    unique_selection(&target, &projected)?;
    Ok(())
}

/// Caller supplies the authenticated model and a complete, same-generation dump in kernel order.
pub fn plan(generation: u32, changes: &[FamilyChange], dump: &RuleDump) -> Result<Publication> {
    ensure!(
        generation > 0 && (1..=2).contains(&changes.len()),
        "INVALID_ARGUMENT: firewall publication"
    );
    let mut batch = Batch {
        commands: 0,
        wire: message(
            16,
            1,
            FIRST_SEQUENCE,
            0,
            10,
            &attribute(1, &generation.to_be_bytes()),
        ),
    };
    let mut last = 0;
    for change in changes {
        let (family, code) = match change.family.as_str() {
            "ipv4" => ("ip", 2),
            "ipv6" => ("ip6", 10),
            _ => anyhow::bail!("INVALID_ARGUMENT: firewall family"),
        };
        ensure!(
            code > last,
            "INVALID_ARGUMENT: repeated or unordered firewall families"
        );
        last = code;
        let old = parse_rendered(&change.previous)?;
        let new = parse_rendered(&change.candidate)?;
        for table in &old.tables {
            check_declarations(table)?;
        }
        ensure!(
            old.tables
                .iter()
                .map(|t| (&t.name, &t.chains))
                .eq(new.tables.iter().map(|t| (&t.name, &t.chains))),
            "CONFLICT: changed firewall declarations or base policies"
        );
        for (before, after) in compile_layout(family, &old)?
            .into_iter()
            .zip(compile_layout(family, &new)?)
        {
            for (from, to) in before.chains.into_iter().zip(after.chains) {
                let rows = dump
                    .get(&(code, before.name.to_owned(), from.name.to_owned()))
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                plan_chain(
                    &mut batch,
                    &Chain {
                        family: code,
                        table: before.name,
                        name: from.name,
                    },
                    &from.rules,
                    &to.rules,
                    rows,
                )?;
            }
        }
    }
    let end = FIRST_SEQUENCE + batch.commands as u32 + 1;
    if batch.commands > 0 {
        batch.wire.extend(message(17, 5, end, 0, 10, &[]));
    } else {
        batch.wire.clear();
    }
    Ok(Publication {
        generation,
        commands: batch.commands,
        wire: batch.wire,
        end,
    })
}
