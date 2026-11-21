use super::DUMP_LIMIT as LIMIT;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Layout {
    pub tables: Vec<Table>,
}
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Table {
    pub name: String,
    pub chains: Vec<Declaration>,
    pub rules: Vec<Row>,
}
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Declaration {
    pub name: String,
    pub policy: Option<String>,
}
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Row {
    pub chain: String,
    pub specification: String,
}

fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn counters(value: &str) -> bool {
    value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .and_then(|v| v.split_once(':'))
        .is_some_and(|(packets, bytes)| {
            [packets, bytes].iter().all(|v| {
                !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) && v.parse::<u64>().is_ok()
            })
        })
}
fn quoted(value: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        match (quote, ch) {
            (Some(open), close) if open == close => quote = None,
            (None, '\'' | '"') => quote = Some(ch),
            _ => {}
        }
    }
    quote.is_none() && !escaped
}
/// Read the append-only output of iptables-save, retaining foreign chains for comparison.
pub fn parse_observed(text: &str) -> Result<Layout> {
    parse_with(text, false)
}

/// Resolve insertions in the order used by the original Kura renderer.
pub fn parse_rendered(text: &str) -> Result<Layout> {
    parse_with(text, true)
}
fn parse_with(text: &str, rendered_model: bool) -> Result<Layout> {
    ensure!(
        text.len() <= LIMIT,
        "RESOURCE_EXHAUSTED: legacy firewall dump size"
    );
    ensure!(
        !text
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t'),
        "UNSUPPORTED: legacy firewall dump control character"
    );
    let mut tables: Vec<Table> = Vec::new();
    let mut active: Option<Table> = None;
    let mut table_names = BTreeSet::new();
    let mut total_chains = 0;
    let mut total_rules = 0;
    for line in text.lines() {
        ensure!(
            line.len() <= 16384,
            "RESOURCE_EXHAUSTED: legacy firewall line size"
        );
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(table) = line.strip_prefix('*') {
            ensure!(
                active.is_none() && name(table) && table_names.insert(table.to_owned()),
                "UNSUPPORTED: legacy firewall table framing"
            );
            ensure!(
                table_names.len() <= 32,
                "RESOURCE_EXHAUSTED: legacy firewall table count"
            );
            active = Some(Table {
                name: table.into(),
                chains: Vec::new(),
                rules: Vec::new(),
            });
            continue;
        }
        if line == "COMMIT" {
            let mut table = active
                .take()
                .context("UNSUPPORTED: legacy firewall COMMIT outside table")?;
            if rendered_model {
                table.rules.sort_by_key(|rule| {
                    table
                        .chains
                        .iter()
                        .position(|chain| chain.name == rule.chain)
                        .unwrap()
                });
            }
            tables.push(table);
            continue;
        }
        let table = active
            .as_mut()
            .context("UNSUPPORTED: legacy firewall record outside table")?;
        if let Some(chain) = line.strip_prefix(':') {
            let fields = chain.split_whitespace().collect::<Vec<_>>();
            ensure!(
                fields.len() == 3
                    && name(fields[0])
                    && matches!(fields[1], "ACCEPT" | "DROP" | "-")
                    && counters(fields[2])
                    && !table.chains.iter().any(|c| c.name == fields[0])
                    && table.rules.is_empty(),
                "UNSUPPORTED: legacy firewall chain declaration"
            );
            total_chains += 1;
            ensure!(
                total_chains <= 1024,
                "RESOURCE_EXHAUSTED: legacy firewall chain count"
            );
            table.chains.push(Declaration {
                name: fields[0].into(),
                policy: if fields[1] == "-" {
                    None
                } else {
                    Some(fields[1].into())
                },
            });
        } else if let Some((body, insert)) = line
            .strip_prefix("-A ")
            .map(|body| (body, false))
            .or_else(|| {
                rendered_model
                    .then(|| line.strip_prefix("-I "))
                    .flatten()
                    .map(|body| (body, true))
            })
        {
            let (chain, mut specification) = body
                .split_once(' ')
                .context("UNSUPPORTED: legacy firewall append framing")?;
            let mut position = 1usize;
            if insert
                && let Some((first, rest)) = specification.split_once(' ')
                && first.bytes().all(|b| b.is_ascii_digit())
            {
                position = first.parse()?;
                specification = rest;
            }
            ensure!(
                name(chain)
                    && table.chains.iter().any(|c| c.name == chain)
                    && !specification.is_empty()
                    && !specification.starts_with(char::is_whitespace)
                    && quoted(specification),
                "UNSUPPORTED: legacy firewall rule framing"
            );
            total_rules += 1;
            ensure!(
                total_rules <= 8192,
                "RESOURCE_EXHAUSTED: legacy firewall rule count"
            );
            // Retain every rule verbatim and in kernel dump order, including
            // additional/foreign modules,targets,quoted comments and user chains.
            // These strings are data. They are never passed to a shell/restore.
            let rule = Row {
                chain: chain.into(),
                specification: specification.into(),
            };
            if insert {
                let indices = table
                    .rules
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| row.chain == chain)
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>();
                ensure!(
                    position > 0 && position <= indices.len() + 1,
                    "UNSUPPORTED: rendered model insertion position"
                );
                let index = indices
                    .get(position - 1)
                    .copied()
                    .unwrap_or(table.rules.len());
                table.rules.insert(index, rule);
            } else {
                table.rules.push(rule);
            }
        } else {
            anyhow::bail!("UNSUPPORTED: unrecognized legacy firewall record");
        }
    }
    ensure!(
        active.is_none(),
        "UNSUPPORTED: incomplete legacy firewall table"
    );
    Ok(Layout { tables })
}
