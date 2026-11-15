//! Original ip/ip6 Kura layout compiler. The four fixed templates are outputs of
//! the actual Java renderer; dynamic clauses retain its chain/type/reverse flow.
//! This pure draft is not a source, owner grant, executable transaction or retry.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn text<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    row[key]
        .as_str()
        .context("INVALID_ARGUMENT: original layout field")
}
fn range(value: &Value) -> Result<String> {
    let first = value["first"]
        .as_u64()
        .context("INVALID_ARGUMENT: source ports")?;
    let last = value["last"]
        .as_u64()
        .context("INVALID_ARGUMENT: source ports")?;
    Ok(format!("{first}:{last}"))
}
fn protocol(row: &Value) -> Option<String> {
    match &row["protocol"] {
        Value::String(v) => Some(if v == "icmpv6" {
            "ipv6-icmp".into()
        } else {
            v.clone()
        }),
        Value::Number(v) => Some(v.to_string()),
        _ => None,
    }
}
fn network(row: &Value, key: &str, maximum: u8) -> Result<Option<String>> {
    let Some(value) = row[key].as_str() else {
        return Ok(None);
    };
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, maximum.to_string()), |(a, p)| (a, p.to_owned()));
    let address: std::net::IpAddr = address.parse()?;
    Ok(Some(format!("{address}/{prefix}")))
}
fn append(layout: &mut Value, table: &str, chain: &str, spec: String) -> Result<()> {
    let tables = layout["tables"]
        .as_array_mut()
        .context("CONFLICT: original layout tables")?;
    let table = tables
        .iter_mut()
        .find(|v| v["name"] == table)
        .context("CONFLICT: original layout table")?;
    let rows = table["rules"]
        .as_array_mut()
        .context("CONFLICT: original layout rules")?;
    let at = rows
        .iter()
        .position(|v| v["chain"] == chain && v["specification"] == "-j RETURN")
        .context("CONFLICT: original RETURN anchor")?;
    rows.insert(at, json!({"chain":chain,"specification":spec}));
    Ok(())
}
fn filter(
    layout: &mut Value,
    chain: &str,
    networks: (Option<&str>, Option<&str>),
    interfaces: (&str, &str),
    proto: Option<&str>,
    mac: Option<&str>,
    ports: Option<&Value>,
) -> Result<()> {
    let (source, destination) = networks;
    let (input, output) = interfaces;
    let mut forward = String::new();
    if let Some(v) = source {
        forward += &format!("-s {v} ");
    }
    if let Some(v) = destination {
        forward += &format!("-d {v} ");
    }
    forward += &format!("-i {input} -o {output}");
    if let Some(p) = proto {
        forward += &format!(" -p {p}");
        if !["all", "icmp", "ipv6-icmp"].contains(&p) && !p.bytes().all(|b| b.is_ascii_digit()) {
            forward += &format!(" -m {p}");
        }
    }
    if let Some(v) = mac {
        forward += &format!(" -m mac --mac-source {v}");
    }
    if let Some(v) = ports {
        forward += &format!(" --sport {}", range(v)?);
    }
    forward += " -j ACCEPT";
    append(layout, "filter", chain, forward)?;
    let mut reverse = String::new();
    if let Some(v) = destination {
        reverse += &format!("-s {v} ");
    }
    reverse += &format!("-i {output} -o {input}");
    if let Some(p) = proto {
        reverse += &format!(" -p {p}");
    }
    reverse += " -m state --state RELATED,ESTABLISHED -j ACCEPT";
    append(layout, "filter", chain, reverse)
}
fn postrouting(
    layout: &mut Value,
    chain: &str,
    source: Option<&str>,
    destination: Option<&str>,
    output: &str,
    proto: Option<&str>,
    masquerade: bool,
) -> Result<()> {
    if !masquerade {
        return Ok(());
    }
    let mut value = String::new();
    if let Some(v) = source {
        value += &format!("-s {v} ");
    }
    if let Some(v) = destination {
        value += &format!("-d {v} ");
    }
    value += &format!("-o {output}");
    if let Some(p) = proto {
        value += &format!(" -p {p}");
    }
    value += " -j MASQUERADE";
    append(layout, "nat", chain, value)
}

fn prefixes(
    policy: &Value,
    bound: &BTreeMap<String, Vec<u8>>,
    family: &str,
    maximum: u8,
) -> Result<Vec<u8>> {
    let count = policy["portForward"]
        .as_array()
        .context("INVALID_ARGUMENT: forwarding rows")?
        .iter()
        .filter(|r| r["family"] == family)
        .count();
    let values = bound
        .get(family)
        .context("INVALID_ARGUMENT: explicit destination prefix intent required")?;
    ensure!(
        values.len() == count && values.iter().all(|v| *v <= maximum),
        "INVALID_ARGUMENT: destination prefix count/family bounds"
    );
    Ok(values.clone())
}

pub(crate) fn layout_draft(
    before: &Value,
    desired: &Value,
    bound: &BTreeMap<String, Vec<u8>>,
    intent: &BTreeMap<String, Vec<u8>>,
) -> Result<Value> {
    ensure!(
        before["schemaVersion"] == 4 && desired["schemaVersion"] == 4,
        "UNSUPPORTED: original layout requires explicit v4 policies"
    );
    super::validate_core_projection(before)?;
    super::validate_core_projection(desired)?;
    ensure!(
        bound.len() == 2
            && intent.len() == 2
            && ["ipv4", "ipv6"]
                .iter()
                .all(|f| bound.contains_key(*f) && intent.contains_key(*f)),
        "INVALID_ARGUMENT: both explicit prefix families required"
    );
    let automatic = |value: &Value| -> Vec<Value> {
        value["nat"].as_array().unwrap().iter().filter(|row|row["automatic"]==true).map(|row|json!({"family":row["family"],"inputInterface":row["inputInterface"],"outputInterface":row["outputInterface"],"masquerade":row["masquerade"]})).collect()
    };
    ensure!(
        automatic(before) == automatic(desired),
        "FORBIDDEN: automatic NAT intent belongs to the bound network roles"
    );
    let mut families = serde_json::Map::new();
    for (family, maximum) in [("ipv4", 32), ("ipv6", 128)] {
        let template = match (
            family,
            desired[family]["allowIcmp"]
                .as_bool()
                .context("INVALID_ARGUMENT: ICMP policy")?,
        ) {
            ("ipv4", true) => include_str!("original/templates/ip-icmp-on.save"),
            ("ipv4", false) => include_str!("original/templates/ip-icmp-off.save"),
            (_, true) => include_str!("original/templates/ip6-icmp-on.save"),
            (_, false) => include_str!("original/templates/ip6-icmp-off.save"),
        };
        let mut layout = super::legacy_model_snapshot(template)?;
        prefixes(before, bound, family, maximum)?;
        let prefixes = prefixes(desired, intent, family, maximum)?;
        for (name, key) in [
            ("INPUT", "inputPolicy"),
            ("FORWARD", "forwardPolicy"),
            ("OUTPUT", "outputPolicy"),
        ] {
            let chain = layout["tables"][0]["chains"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|c| c["name"] == name)
                .unwrap();
            chain["policy"] = json!(text(&desired[family], key)?.to_ascii_uppercase());
        }
        for row in desired["input"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["family"] == family)
        {
            let mut value = format!("-p {}", text(row, "protocol")?);
            if let Some(v) = network(row, "source", maximum)? {
                value += &format!(" -s {v}");
            }
            if let Some(v) = row["inputInterface"].as_str() {
                value += &format!(" -i {v}");
            } else if let Some(v) = row["excludedInterface"].as_str() {
                value += &format!(" ! -i {v}");
            }
            if let Some(v) = row["sourceMac"].as_str() {
                value += &format!(" -m mac --mac-source {v}");
            }
            if !row["sourcePorts"].is_null() {
                value += &format!(" --sport {}", range(&row["sourcePorts"])?);
            }
            value += &format!(" --dport {} -j ACCEPT", range(&row["ports"])?);
            append(&mut layout, "filter", "input-kura", value)?;
        }
        for (index, row) in desired["portForward"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["family"] == family)
            .enumerate()
        {
            let input = text(row, "inputInterface")?;
            let output = text(row, "outputInterface")?;
            let proto = text(row, "protocol")?;
            let address: std::net::IpAddr = text(row, "address")?.parse()?;
            let target = format!("{address}/{}", prefixes[index]);
            let source = network(row, "source", maximum)?;
            let mac = row["sourceMac"].as_str();
            let ports = (!row["sourcePorts"].is_null()).then_some(&row["sourcePorts"]);
            filter(
                &mut layout,
                "forward-kura-pf",
                (source.as_deref(), Some(&target)),
                (input, output),
                Some(proto),
                mac,
                ports,
            )?;
            let mut pre = String::new();
            if let Some(v) = &source {
                pre += &format!("-s {v} ");
            }
            pre += &format!("-i {input} -p {proto}");
            if let Some(v) = mac {
                pre += &format!(" -m mac --mac-source {v}");
            }
            pre += &format!(" -m {proto}");
            if let Some(v) = ports {
                pre += &format!(" --sport {}", range(v)?);
            }
            let host = if address.is_ipv6() {
                format!("[{address}]")
            } else {
                address.to_string()
            };
            pre += &format!(
                " --dport {} -j DNAT --to-destination {host}:{}",
                row["inPort"], row["outPort"]
            );
            append(&mut layout, "nat", "prerouting-kura-pf", pre)?;
            postrouting(
                &mut layout,
                "postrouting-kura-pf",
                source.as_deref(),
                Some(&target),
                output,
                Some(proto),
                row["masquerade"] == true,
            )?;
        }
        // Java emits automatic NAT before manual NAT regardless of JSON order.
        for automatic in [true, false] {
            for row in desired["nat"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v["family"] == family && v["automatic"] == automatic)
            {
                let kind = row["ruleType"].as_str().unwrap_or("GENERIC");
                let suffix = if automatic {
                    ""
                } else {
                    match kind {
                        "IP_FORWARDING" => "-ipf",
                        "PORT_FORWARDING" => "-pf",
                        _ => "",
                    }
                };
                let source = network(row, "source", maximum)?;
                let destination = network(row, "destination", maximum)?;
                let proto = protocol(row);
                let input = text(row, "inputInterface")?;
                let output = text(row, "outputInterface")?;
                filter(
                    &mut layout,
                    &format!("forward-kura{suffix}"),
                    (source.as_deref(), destination.as_deref()),
                    (input, output),
                    proto.as_deref(),
                    None,
                    None,
                )?;
                postrouting(
                    &mut layout,
                    &format!("postrouting-kura{suffix}"),
                    source.as_deref(),
                    destination.as_deref(),
                    output,
                    proto.as_deref(),
                    row["masquerade"] == true,
                )?;
            }
        }
        families.insert(
            family.into(),
            json!({"layout":layout,"destinationPrefixes":prefixes}),
        );
    }
    let result = json!({"schemaVersion":1,"reviewKind":"legacy.original.layout.draft.v1","beforePolicySha256":crate::durable::hash(&serde_json::to_vec(&json!({"policy":before,"destinationPrefixes":bound}))?),"candidateSha256":crate::durable::hash(&serde_json::to_vec(&json!({"policy":desired,"destinationPrefixes":intent}))?),"families":families,"applyReady":false});
    ensure!(
        serde_json::to_vec(&result)?.len() <= 1 << 20,
        "RESOURCE_EXHAUSTED: original layout draft"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn oracle() -> Value {
        serde_json::from_str(include_str!(
            "original/fixtures/java-layout-oracle-v41.json"
        ))
        .unwrap()
    }
    fn candidate(case: &Value) -> (Value, BTreeMap<String, Vec<u8>>) {
        let origin = &case["origin"];
        let mut candidate = origin["modelRules"].clone();
        candidate["schemaVersion"] = json!(4);
        let mut prefixes = BTreeMap::new();
        for model in origin["families"].as_array().unwrap() {
            let family = model["family"].as_str().unwrap();
            let source =
                super::super::legacy_model_snapshot(model["managedRuleset"].as_str().unwrap())
                    .unwrap();
            let mut policy = json!({"allowIcmp":model["allowIcmp"]});
            for (name, key) in [
                ("INPUT", "inputPolicy"),
                ("FORWARD", "forwardPolicy"),
                ("OUTPUT", "outputPolicy"),
            ] {
                policy[key] = json!(
                    source["tables"][0]["chains"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|c| c["name"] == name)
                        .unwrap()["policy"]
                        .as_str()
                        .unwrap()
                        .to_ascii_lowercase()
                );
            }
            candidate[family] = policy;
            for row in model["automaticNat"].as_array().unwrap() {
                candidate["nat"].as_array_mut().unwrap().push(json!({"family":family,"inputInterface":row["sourceInterface"],"outputInterface":row["destinationInterface"],"masquerade":row["masquerade"],"automatic":true}));
            }
            prefixes.insert(
                family.into(),
                serde_json::from_value(model["runtimePortForwardDestinationPrefixes"].clone())
                    .unwrap(),
            );
        }
        (candidate, prefixes)
    }
    #[test]
    fn actual_java_original_layouts_match_dynamic_clauses_prefixes_types_and_bounded_wire() {
        let mut rules = 0;
        for case in oracle()["cases"].as_array().unwrap() {
            let (candidate, prefixes) = candidate(case);
            let draft = layout_draft(&candidate, &candidate, &prefixes, &prefixes).unwrap();
            assert_eq!(draft["applyReady"], false);
            for model in case["origin"]["families"].as_array().unwrap() {
                let family = model["family"].as_str().unwrap();
                let native = if family == "ipv4" { "ip" } else { "ip6" };
                let expected =
                    super::super::legacy_model_snapshot(model["managedRuleset"].as_str().unwrap())
                        .unwrap();
                let actual = &draft["families"][family]["layout"];
                let compile = crate::nm::handover::initialization::compiled_original_layout;
                let left = compile(native, &expected).unwrap();
                let right = compile(native, actual).unwrap();
                assert_eq!(
                    left["declarations"], right["declarations"],
                    "case{} {family}",
                    case["case"]
                );
                assert_eq!(
                    left["groups"], right["groups"],
                    "case{} {family}",
                    case["case"]
                );
                assert!(right["wirePreflightBytes"].as_u64().unwrap() > 0);
                assert_eq!(right["dispatched"], false);
                rules += right["ruleCount"].as_u64().unwrap();
                assert_eq!(
                    draft["families"][family]["destinationPrefixes"],
                    model["runtimePortForwardDestinationPrefixes"]
                );
            }
        }
        assert!(rules > 300);
        println!("ORIGINAL_LAYOUT_PRIMARY_RULES={rules}");
    }
    #[test]
    fn changed_prefix_intent_is_explicit_and_changes_the_bound_draft_without_claiming_source() {
        let data = oracle();
        let (before, prefixes) = candidate(&data["cases"][0]);
        let first = layout_draft(&before, &before, &prefixes, &prefixes).unwrap();
        let mut intent = prefixes.clone();
        intent.insert("ipv4".into(), vec![32]);
        intent.insert("ipv6".into(), vec![128]);
        let changed = layout_draft(&before, &before, &prefixes, &intent).unwrap();
        assert_ne!(first["candidateSha256"], changed["candidateSha256"]);
        assert_eq!(first["beforePolicySha256"], changed["beforePolicySha256"]);
        for bad in [
            BTreeMap::new(),
            BTreeMap::from([("ipv4".into(), vec![33]), ("ipv6".into(), vec![128])]),
            BTreeMap::from([("ipv4".into(), vec![]), ("ipv6".into(), vec![128])]),
        ] {
            assert!(layout_draft(&before, &before, &prefixes, &bad).is_err());
        }
        let mut desired = before.clone();
        let automatic = desired["nat"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["automatic"] == true)
            .unwrap();
        automatic["masquerade"] = json!(false);
        assert!(layout_draft(&before, &desired, &prefixes, &prefixes).is_err());
    }
}
