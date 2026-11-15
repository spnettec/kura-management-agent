//! Complete legacy kernel observations for explicit migration review. No restore,
//! rule translation, owner claim or durable admission is performed by this reader.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path, time::{Duration, Instant}};

const LIMIT: usize = 512 * 1024;
const PROGRAMS: [&str; 2] = ["/usr/sbin/iptables-save", "/usr/sbin/ip6tables-save"];

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all="camelCase")]
struct Snapshot { tables: Vec<Table> }
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all="camelCase")]
struct Table { name: String, chains: Vec<Chain>, rules: Vec<Rule> }
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all="camelCase")]
struct Chain { name: String, policy: Option<String> }
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all="camelCase")]
struct Rule { chain: String, specification: String }

fn name(value:&str)->bool {
    !value.is_empty() && value.len()<=64
        && value.bytes().all(|b|b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn counters(value:&str)->bool {
    value.strip_prefix('[').and_then(|v|v.strip_suffix(']')).and_then(|v|v.split_once(':'))
        .is_some_and(|(packets,bytes)|[packets,bytes].iter().all(|v|!v.is_empty()
            && v.bytes().all(|b|b.is_ascii_digit()) && v.parse::<u64>().is_ok()))
}
fn quoted(value:&str)->bool {
    let mut quote=None;let mut escaped=false;
    for ch in value.chars() {
        if escaped {escaped=false;continue;}
        if ch=='\\' {escaped=true;continue;}
        match (quote,ch) {
            (Some(open),close) if open==close => quote=None,
            (None,'\''|'"')=>quote=Some(ch),
            _=>{},
        }
    }
    quote.is_none() && !escaped
}
fn parse(text:&str)->Result<Snapshot> {parse_with(text,false)}
fn parse_with(text:&str,rendered_model:bool)->Result<Snapshot> {
    ensure!(text.len()<=LIMIT,"RESOURCE_EXHAUSTED: legacy firewall dump size");
    ensure!(!text.chars().any(|c|c.is_control() && c!='\n' && c!='\t'),
        "UNSUPPORTED: legacy firewall dump control character");
    let mut tables:Vec<Table>=Vec::new();let mut active:Option<Table>=None;
    let mut table_names=BTreeSet::new();let mut total_chains=0;let mut total_rules=0;
    for line in text.lines() {
        ensure!(line.len()<=16384,"RESOURCE_EXHAUSTED: legacy firewall line size");
        if line.is_empty() || line.starts_with('#') {continue;}
        if let Some(table)=line.strip_prefix('*') {
            ensure!(active.is_none() && name(table) && table_names.insert(table.to_owned()),
                "UNSUPPORTED: legacy firewall table framing");
            ensure!(table_names.len()<=32,"RESOURCE_EXHAUSTED: legacy firewall table count");
            active=Some(Table{name:table.into(),chains:Vec::new(),rules:Vec::new()});continue;
        }
        if line=="COMMIT" {
            let mut table=active.take().context("UNSUPPORTED: legacy firewall COMMIT outside table")?;
            if rendered_model {table.rules.sort_by_key(|rule|table.chains.iter().position(|chain|chain.name==rule.chain).unwrap());}
            tables.push(table);continue;
        }
        let table=active.as_mut().context("UNSUPPORTED: legacy firewall record outside table")?;
        if let Some(chain)=line.strip_prefix(':') {
            let fields=chain.split_whitespace().collect::<Vec<_>>();
            ensure!(fields.len()==3 && name(fields[0]) && matches!(fields[1],"ACCEPT"|"DROP"|"-")
                && counters(fields[2]) && !table.chains.iter().any(|c|c.name==fields[0]) && table.rules.is_empty(),
                "UNSUPPORTED: legacy firewall chain declaration");
            total_chains+=1;ensure!(total_chains<=1024,"RESOURCE_EXHAUSTED: legacy firewall chain count");
            table.chains.push(Chain{name:fields[0].into(),policy:if fields[1]=="-"{None}else{Some(fields[1].into())}});
        } else if let Some((body,insert))=line.strip_prefix("-A ").map(|body|(body,false))
            .or_else(||rendered_model.then(||line.strip_prefix("-I ")).flatten().map(|body|(body,true))) {
            let (chain,mut specification)=body.split_once(' ').context("UNSUPPORTED: legacy firewall append framing")?;
            let mut position=1usize;
            if insert && let Some((first,rest))=specification.split_once(' ') && first.bytes().all(|b|b.is_ascii_digit()) {
                position=first.parse()?;specification=rest;
            }
            ensure!(name(chain) && table.chains.iter().any(|c|c.name==chain) && !specification.is_empty()
                && !specification.starts_with(char::is_whitespace) && quoted(specification),
                "UNSUPPORTED: legacy firewall rule framing");
            total_rules+=1;ensure!(total_rules<=8192,"RESOURCE_EXHAUSTED: legacy firewall rule count");
            // Retain every rule verbatim and in kernel dump order, including
            // additional/foreign modules,targets,quoted comments and user chains.
            // These strings are data. They are never passed to a shell/restore.
            let rule=Rule{chain:chain.into(),specification:specification.into()};
            if insert {
                let indices=table.rules.iter().enumerate().filter(|(_,row)|row.chain==chain).map(|(i,_)|i).collect::<Vec<_>>();
                ensure!(position>0&&position<=indices.len()+1,"UNSUPPORTED: rendered model insertion position");
                let index=indices.get(position-1).copied().unwrap_or(table.rules.len());table.rules.insert(index,rule);
            }else{table.rules.push(rule);}
        } else {anyhow::bail!("UNSUPPORTED: unrecognized legacy firewall record");}
    }
    ensure!(active.is_none(),"UNSUPPORTED: incomplete legacy firewall table");
    Ok(Snapshot{tables})
}

pub(crate) fn legacy_model_snapshot(text:&str)->Result<Value> {Ok(serde_json::to_value(parse_with(text,true)?)?)}

pub(crate) fn observe_legacy_kernel(deadline:Instant)->Result<Value> {
    observe_with(deadline,|program,deadline| {
        let duration=deadline.checked_duration_since(Instant::now()).filter(|d|!d.is_zero())
            .context("TIMEOUT: legacy firewall source deadline")?.min(Duration::from_secs(10));
        // No table selector:read every currently available table without asking
        // iptables-save to autoload a missing table. No counters,file or modprobe
        // arguments,and no shell. The shared runner bounds output and duration.
        let output=crate::process::run(Path::new(program),&[],None,duration)?;
        ensure!(output.status.success(),"UNSUPPORTED: legacy firewall source command failed ({} diagnostic bytes)",output.stderr.len());
        Ok(String::from_utf8(output.stdout)?)
    })
}

fn observe_with(mut deadline:Instant,mut read:impl FnMut(&str,Instant)->Result<String>)->Result<Value> {
    // Keep one bounded deadline across both address families and both passes.
    deadline=deadline.min(Instant::now()+Duration::from_secs(40));
    let mut capture=||->Result<([Snapshot;2],[String;2])>{
        ensure!(Instant::now()<deadline,"TIMEOUT: legacy firewall source deadline");
        let v4=read(PROGRAMS[0],deadline)?;
        ensure!(Instant::now()<deadline,"TIMEOUT: legacy firewall source deadline");
        let v6=read(PROGRAMS[1],deadline)?;
        ensure!(Instant::now()<deadline,"TIMEOUT: legacy firewall source deadline");
        ensure!(v4.len()+v6.len()<=LIMIT,"RESOURCE_EXHAUSTED: paired legacy firewall source size");
        Ok(([parse(&v4)?,parse(&v6)?],[crate::durable::hash(v4.as_bytes()),crate::durable::hash(v6.as_bytes())]))
    };
    let (before,before_raw)=capture()?;let (after,after_raw)=capture()?;
    ensure!(before==after,"CONFLICT: legacy firewall source changed across observation");
    let snapshot=json!({"ipv4":after[0],"ipv6":after[1]});
    let result=json!({"schemaVersion":1,"sourceKind":"iptables.current.unowned.v1",
        "snapshotSha256":crate::durable::hash(&serde_json::to_vec(&snapshot)?),"snapshot":snapshot,
        "rawBeforeSha256":before_raw,"rawAfterSha256":after_raw,
        "excludedMetadata":["dumpComments","chainCounters"],"migrationReady":false});
    ensure!(serde_json::to_vec(&result)?.len()<=LIMIT,"RESOURCE_EXHAUSTED: legacy firewall source representation");
    Ok(result)
}

#[cfg(test)]
pub(crate) fn fixture_observe(values:[String;4],deadline:Instant)->Result<Value> {
    let mut values=values.into_iter();let mut index=0;
    observe_with(deadline,|program,_| {
        assert_eq!(program,PROGRAMS[index%2]);index+=1;
        values.next().context("fixture source absent")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rendered_insertions_have_actual_head_order_without_relaxing_kernel_dump_framing() {
        let text="*filter\n:FORWARD DROP [0:0]\n:forward-kura - [0:0]\n:forward-kura-pf - [0:0]\n:forward-kura-ipf - [0:0]\n-I FORWARD -j forward-kura\n-I forward-kura -j forward-kura-pf\n-I forward-kura -j forward-kura-ipf\n-A forward-kura -j RETURN\nCOMMIT\n";
        assert!(parse(text).is_err());let source=legacy_model_snapshot(text).unwrap();
        assert_eq!(source["tables"][0]["rules"][1]["specification"],"-j forward-kura-ipf");
        assert_eq!(source["tables"][0]["rules"][2]["specification"],"-j forward-kura-pf");
        assert!(legacy_model_snapshot(&text.replace("-I FORWARD -j","-I FORWARD 0 -j")).is_err());
    }
    fn v4()->String {
        "# Generated by iptables-save\n*filter\n:INPUT DROP [12:34]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:input-kura - [0:0]\n-A INPUT -j input-kura\n-A input-kura -p icmp -j ACCEPT\n-A input-kura -m comment --comment \"additional #; rule\" -j RETURN\nCOMMIT\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -o wan0 -j MASQUERADE\nCOMMIT\n*mangle\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -m limit --limit 10/sec -j MARK --set-xmark 0x1/0xff\nCOMMIT\n*raw\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -j CT --notrack\nCOMMIT\n*security\n:INPUT ACCEPT [0:0]\n-A INPUT -j SECMARK --selctx system_u:object_r:packet_t:s0\nCOMMIT\n".into()
    }
    fn v6()->String {"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -p ipv6-icmp -j DROP\nCOMMIT\n".into()}
    #[test]
    fn whole_kernel_source_keeps_policies_icmp_nat_additional_foreign_tables_and_exact_order() {
        let a=v4();let b=v6();let result=fixture_observe([a.clone(),b.clone(),a,b],Instant::now()+Duration::from_secs(1)).unwrap();
        let tables=result["snapshot"]["ipv4"]["tables"].as_array().unwrap();assert_eq!(tables.len(),5);
        assert_eq!(tables[0]["chains"][0]["policy"],"DROP");assert!(tables[0]["chains"][3]["policy"].is_null());
        assert_eq!(tables[0]["rules"][1]["specification"],"-p icmp -j ACCEPT");
        assert_eq!(tables[0]["rules"][2]["specification"],"-m comment --comment \"additional #; rule\" -j RETURN");
        assert_eq!(tables[1]["rules"][0]["specification"],"-o wan0 -j MASQUERADE");
        assert_eq!(tables[2]["name"],"mangle");assert_eq!(tables[3]["name"],"raw");assert_eq!(tables[4]["name"],"security");
        assert_eq!(result["snapshot"]["ipv6"]["tables"][0]["rules"][0]["specification"],"-p ipv6-icmp -j DROP");
        assert_eq!(result["migrationReady"],false);assert!(result.get("candidate").is_none());
    }
    #[test]
    fn traffic_counters_and_dump_comments_do_not_hide_semantic_drift() {
        let a=v4();let b=v6();let moved=a.replace("[12:34]","[99:999]").replace("# Generated by iptables-save","# Completed at another time");
        let result=fixture_observe([a.clone(),b.clone(),moved,b.clone()],Instant::now()+Duration::from_secs(1)).unwrap();
        assert_ne!(result["rawBeforeSha256"][0],result["rawAfterSha256"][0]);
        for changed in [a.replace(":INPUT DROP",":INPUT ACCEPT"),a.replace("icmp -j ACCEPT","icmp -j DROP"),
            a.replace("-o wan0","-o wan1"),a.replace("10/sec","20/sec"),a.replace("packet_t","another_t")] {
            assert!(fixture_observe([a.clone(),b.clone(),changed,b.clone()],Instant::now()+Duration::from_secs(1)).unwrap_err().to_string().starts_with("CONFLICT"));
        }
    }
    #[test]
    fn malformed_partial_unknown_duplicate_and_unbounded_source_never_become_empty_policy() {
        for text in ["*filter\n:INPUT DROP [0:0]\n", "COMMIT\n", "*filter\n:INPUT DROP [0:0]\n:INPUT DROP [0:0]\nCOMMIT\n",
            "*filter\n:INPUT QUEUE [0:0]\nCOMMIT\n", "*filter\n:INPUT DROP [0:0]\n-A foreign -j ACCEPT\nCOMMIT\n",
            "*filter\n:INPUT DROP [0:0]\n-I INPUT -j ACCEPT\nCOMMIT\n", "*filter\n:INPUT DROP [0:0]\n-A INPUT --comment \"open\nCOMMIT\n",
            "*filter\n:INPUT DROP [0:0]\nCOMMIT\n*filter\nCOMMIT\n", "\0", "*filter\n:INPUT DROP [18446744073709551616:0]\nCOMMIT\n"] {
            assert!(parse(text).is_err(),"{text:?}");
        }
        assert!(parse(&"x".repeat(LIMIT+1)).is_err());
        assert!(fixture_observe([String::new(),String::new(),String::new(),String::new()],Instant::now()).is_err());
        let empty=parse("").unwrap();assert!(empty.tables.is_empty());
    }
}
