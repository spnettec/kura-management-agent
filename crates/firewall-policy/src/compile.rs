use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde_json::Value;

use crate::{Layout, compile_clause};

/// Original chain order, action order and base-chain policy from the renderer.
/// A declared policy is model data and does not grant permission to replace a site's policy.
pub struct CompiledChain<'a> {
    pub name: &'a str,
    pub policy: Option<&'a str>,
    pub rules: Vec<Vec<Value>>,
}

pub struct CompiledTable<'a> {
    pub name: &'a str,
    pub chains: Vec<CompiledChain<'a>>,
}

/// Compile the three original tables in declaration order. Every row must compile.
/// A caller can use the result for observation or build a separately authorized transaction.
pub fn compile_layout<'a>(family: &str, layout: &'a Layout) -> Result<Vec<CompiledTable<'a>>> {
    compile_with(family, layout, false)
}

pub(crate) fn compile_publication_layout<'a>(
    family: &str,
    layout: &'a Layout,
) -> Result<Vec<CompiledTable<'a>>> {
    compile_with(family, layout, true)
}

fn compile_with<'a>(
    family: &str,
    layout: &'a Layout,
    xtables: bool,
) -> Result<Vec<CompiledTable<'a>>> {
    ensure!(
        matches!(family, "ip" | "ip6"),
        "INVALID_ARGUMENT: original family"
    );
    ensure!(
        layout
            .tables
            .iter()
            .map(|table| table.name.as_str())
            .eq(["filter", "nat", "mangle"]),
        "CONFLICT: complete original model tables"
    );
    let total_rules = layout
        .tables
        .iter()
        .map(|table| table.rules.len())
        .sum::<usize>();
    ensure!(
        total_rules <= 4096,
        "RESOURCE_EXHAUSTED: original compiled model rules"
    );

    let mut tables = Vec::with_capacity(layout.tables.len());
    for table in &layout.tables {
        let mut chains = Vec::with_capacity(table.chains.len());
        let mut indexes = BTreeMap::new();
        for declaration in &table.chains {
            let name = declaration.name.as_str();
            ensure!(
                indexes.insert(name, chains.len()).is_none(),
                "CONFLICT: original model chain declarations"
            );
            chains.push(CompiledChain {
                name,
                policy: declaration.policy.as_deref(),
                rules: Vec::new(),
            });
        }
        for row in &table.rules {
            let Some(&index) = indexes.get(row.chain.as_str()) else {
                anyhow::bail!("CONFLICT: original model chain declarations");
            };
            let mut terms = compile_clause(family, table, &row.specification)?;
            if xtables {
                for term in &mut terms {
                    if term.pointer("/match/left/ct/key") == Some(&serde_json::json!("state")) {
                        let alias = row
                            .specification
                            .split_whitespace()
                            .any(|token| token == "--state");
                        *term = serde_json::json!({"xtState":{"alias":alias, "match":term["match"].take()}});
                    }
                }
            }
            chains[index].rules.push(terms);
        }
        tables.push(CompiledTable {
            name: &table.name,
            chains,
        });
    }
    Ok(tables)
}
