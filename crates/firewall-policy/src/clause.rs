use crate::Table;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Normalize legacy syntax when comparing an observed clause with an original rule.
pub fn canonical_clause(text: &str) -> Result<BTreeMap<String, (bool, String)>> {
    canonical_in_family(text, None)
}

fn canonical_in_family(
    text: &str,
    family: Option<&str>,
) -> Result<BTreeMap<String, (bool, String)>> {
    ensure!(
        text.len() <= 16384
            && !text
                .chars()
                .any(|c| c.is_control() || matches!(c, '\'' | '"' | '\\')),
        "UNSUPPORTED: non-model rule syntax"
    );
    let fields = text.split_whitespace().collect::<Vec<_>>();
    let mut out = BTreeMap::new();
    let mut modules = BTreeSet::new();
    let mut i = 0;
    while i < fields.len() {
        let mut negated = false;
        if fields[i] == "!" {
            negated = true;
            i += 1;
        }
        let key = *fields
            .get(i)
            .context("UNSUPPORTED: incomplete model option")?;
        i += 1;
        if fields.get(i) == Some(&"!") {
            ensure!(!negated, "UNSUPPORTED: duplicate model negation");
            negated = true;
            i += 1;
        }
        let mut value = fields
            .get(i)
            .context("UNSUPPORTED: missing model option value")?
            .to_string();
        i += 1;
        let key = match key {
            "-p" | "--protocol" => "protocol",
            "-s" | "--source" => "source",
            "-d" | "--destination" => "destination",
            "-i" | "--in-interface" => "input",
            "-o" | "--out-interface" => "output",
            "--dport" | "--destination-port" => "dport",
            "--sport" | "--source-port" => "sport",
            "--state" | "--ctstate" => "state",
            "--mac-source" => "mac",
            "--icmp-type" => "icmp",
            "--icmpv6-type" => "icmpv6",
            "-j" | "--jump" => "jump",
            "--to-destination" => "dnat",
            "--to-source" => "snat",
            "-m" | "--match" => {
                ensure!(
                    !negated && modules.insert(value),
                    "UNSUPPORTED: duplicate/negated model module"
                );
                continue;
            }
            _ => anyhow::bail!("UNSUPPORTED: non-model rule option"),
        };
        match key {
            "protocol" => {
                value = match value.as_str() {
                    "6" => "tcp",
                    "17" => "udp",
                    "1" => "icmp",
                    "58" | "ipv6-icmp" => "icmpv6",
                    "0" => "all",
                    _ => &value,
                }
                .into();
                if value == "all" && !negated {
                    continue;
                }
            }
            "source" | "destination" => {
                let (address, prefix) = if let Some((a, p)) = value.split_once('/') {
                    (a, p.parse::<u8>()?)
                } else {
                    (value.as_str(), if value.contains(':') { 128 } else { 32 })
                };
                let address: std::net::IpAddr = address.parse()?;
                // Validate even a universal source/destination before it can
                // disappear from the canonical conjunction below.
                ensure!(
                    family.is_none_or(|family| address.is_ipv4() == (family == "ip")),
                    "UNSUPPORTED: original model address family"
                );
                value = match address {
                    std::net::IpAddr::V4(a) => {
                        ensure!(prefix <= 32, "UNSUPPORTED: IPv4 model prefix");
                        let bits = u32::from(a)
                            & if prefix == 0 {
                                0
                            } else {
                                u32::MAX << (32 - prefix)
                            };
                        format!("{}/{prefix}", std::net::Ipv4Addr::from(bits))
                    }
                    std::net::IpAddr::V6(a) => {
                        ensure!(prefix <= 128, "UNSUPPORTED: IPv6 model prefix");
                        let bits = u128::from(a)
                            & if prefix == 0 {
                                0
                            } else {
                                u128::MAX << (128 - prefix)
                            };
                        format!("{}/{prefix}", std::net::Ipv6Addr::from(bits))
                    }
                };
                if prefix == 0 && !negated {
                    continue;
                }
            }
            "state" => {
                let mut states = value.split(',').collect::<Vec<_>>();
                ensure!(
                    states.iter().all(|v| [
                        "NEW",
                        "RELATED",
                        "ESTABLISHED",
                        "INVALID",
                        "UNTRACKED",
                        "SNAT",
                        "DNAT"
                    ]
                    .contains(v)),
                    "UNSUPPORTED: model connection state"
                );
                states.sort();
                ensure!(
                    !states.windows(2).any(|v| v[0] == v[1]),
                    "UNSUPPORTED: duplicate model connection state"
                );
                value = states.join(",");
            }
            "mac" => value = value.to_ascii_lowercase(),
            "dport" | "sport" => {
                let parts = value
                    .split(':')
                    .map(str::parse::<u16>)
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                ensure!(
                    (1..=2).contains(&parts.len())
                        && parts[0] > 0
                        && parts[0] <= *parts.last().unwrap(),
                    "UNSUPPORTED: model port range"
                );
                value = format!("{}:{}", parts[0], parts.last().unwrap());
            }
            _ => {}
        }
        ensure!(
            out.insert(key.into(), (negated, value)).is_none(),
            "UNSUPPORTED: duplicate model predicate"
        );
    }
    ensure!(
        out.get("jump").is_some_and(|(negated, _)| !*negated),
        "UNSUPPORTED: missing model action"
    );
    for module in modules {
        ensure!(
            match module.as_str() {
                "tcp" | "udp" => out.get("protocol").is_some_and(|v| !v.0 && v.1 == module),
                "icmp" => out.get("protocol").is_some_and(|v| !v.0 && v.1 == "icmp"),
                "ipv6-icmp" | "icmp6" =>
                    out.get("protocol").is_some_and(|v| !v.0 && v.1 == "icmpv6"),
                "state" | "conntrack" => out.contains_key("state"),
                "mac" => out.contains_key("mac"),
                _ => false,
            },
            "UNSUPPORTED: non-model match module"
        );
    }
    Ok(out)
}

fn matching(left: Value, negated: bool, right: Value) -> Value {
    json!({"match":{"left":left,"op":if negated{"!="}else{"=="},"right":right}})
}
fn address(family: &str, value: &str) -> Result<Value> {
    let (host, prefix) = value
        .split_once('/')
        .map_or((value, None), |(a, p)| (a, Some(p)));
    let addr: std::net::IpAddr = host
        .parse()
        .context("UNSUPPORTED: original model address")?;
    ensure!(
        addr.is_ipv4() == (family == "ip"),
        "UNSUPPORTED: original model address family"
    );
    Ok(if let Some(prefix) = prefix {
        let len = prefix.parse::<u8>()?;
        ensure!(
            len <= if family == "ip" { 32 } else { 128 },
            "UNSUPPORTED: original prefix length"
        );
        json!({"prefix":{"addr":addr.to_string(),"len":len}})
    } else {
        json!(addr.to_string())
    })
}
fn interface(value: &str) -> Result<Option<String>> {
    if value == "+" {
        return Ok(None);
    }
    let stem = value.strip_suffix('+').unwrap_or(value);
    ensure!(
        !stem.is_empty()
            && value.len() <= 15
            && stem
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)),
        "UNSUPPORTED: original model interface"
    );
    Ok(Some(if value.ends_with('+') {
        format!("{stem}*")
    } else {
        value.into()
    }))
}
fn nat_target(family: &str, value: &str) -> Result<Value> {
    let (host, port) = if let Ok(socket) = value.parse::<std::net::SocketAddr>() {
        (socket.ip().to_string(), Some(socket.port()))
    } else {
        (value.to_string(), None)
    };
    let addr = address(family, &host)?;
    ensure!(addr.is_string(), "UNSUPPORTED: original NAT target prefix");
    let mut result = json!({"family":family,"addr":addr});
    if let Some(port) = port {
        ensure!(port > 0, "UNSUPPORTED: original NAT target port");
        result["port"] = json!(port);
    }
    Ok(result)
}

pub fn compile_clause(family: &str, table: &Table, text: &str) -> Result<Vec<Value>> {
    ensure!(
        ["ip", "ip6"].contains(&family)
            && ["filter", "nat", "mangle"].contains(&table.name.as_str()),
        "UNSUPPORTED: original model scope"
    );
    let mut terms = canonical_in_family(text, Some(family))?;
    let mut out = Vec::new();
    let (_, action) = terms
        .remove("jump")
        .context("UNSUPPORTED: original model action")?;
    for (key, meta) in [("input", "iifname"), ("output", "oifname")] {
        if let Some((negated, value)) = terms.remove(key) {
            if let Some(name) = interface(&value)? {
                out.push(matching(json!({"meta":{"key":meta}}), negated, json!(name)));
            } else if negated {
                out.push(matching(
                    json!({"meta":{"key":"nfproto"}}),
                    true,
                    json!(if family == "ip" { "ipv4" } else { "ipv6" }),
                ));
            }
        }
    }
    let protocol = terms.remove("protocol");
    if let Some((negated, value)) = &protocol {
        let number = match value.as_str() {
            "tcp" => 6,
            "udp" => 17,
            "icmp" => {
                ensure!(family == "ip", "UNSUPPORTED: ICMP model family");
                1
            }
            "icmpv6" => {
                ensure!(family == "ip6", "UNSUPPORTED: ICMPv6 model family");
                58
            }
            _ => value
                .parse::<u8>()
                .context("UNSUPPORTED: original model protocol")?,
        };
        out.push(matching(
            json!({"meta":{"key":"l4proto"}}),
            *negated,
            json!(number),
        ));
        if !negated
            && ["tcp", "udp"].contains(&value.as_str())
            && !terms.contains_key("sport")
            && !terms.contains_key("dport")
        {
            let tokens = text.split_whitespace().collect::<Vec<_>>();
            if tokens
                .windows(2)
                .any(|p| ["-m", "--match"].contains(&p[0]) && p[1] == value)
            {
                out.push(json!({"transportHeader":{"protocol":value}}));
            }
        }
    }
    for (key, field) in [("source", "saddr"), ("destination", "daddr")] {
        if let Some((negated, value)) = terms.remove(key) {
            out.push(matching(
                json!({"payload":{"protocol":family,"field":field}}),
                negated,
                address(family, &value)?,
            ));
        }
    }
    if let Some((negated, value)) = terms.remove("mac") {
        ensure!(
            value.len() == 17
                && value.split(':').count() == 6
                && value
                    .split(':')
                    .all(|v| v.len() == 2 && v.bytes().all(|b| b.is_ascii_hexdigit())),
            "UNSUPPORTED: original MAC"
        );
        out.push(matching(
            json!({"payload":{"protocol":"ether","field":"saddr"}}),
            negated,
            json!(value),
        ));
    }
    for key in ["sport", "dport"] {
        if let Some((negated, value)) = terms.remove(key) {
            let p = protocol
                .as_ref()
                .filter(|(n, p)| !*n && ["tcp", "udp"].contains(&p.as_str()))
                .context(
                    "UNSUPPORTED: model ports require an explicit positive TCP/UDP protocol",
                )?;
            let (first, last) = value
                .split_once(':')
                .context("UNSUPPORTED: original normalized ports")?;
            let (first, last) = (first.parse::<u16>()?, last.parse::<u16>()?);
            out.push(matching(
                json!({"payload":{"protocol":p.1,"field":key}}),
                negated,
                if first == last {
                    json!(first)
                } else {
                    json!({"range":[first,last]})
                },
            ));
        }
    }
    for (key, name) in [("icmp", "icmp"), ("icmpv6", "icmpv6")] {
        if let Some((negated, value)) = terms.remove(key) {
            ensure!(
                protocol.as_ref().is_some_and(|(n, p)| !*n && p == name),
                "UNSUPPORTED: original ICMP protocol context"
            );
            let parts = value
                .split('/')
                .map(str::parse::<u8>)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ensure!(
                (1..=2).contains(&parts.len()) && (!negated || parts.len() == 1),
                "UNSUPPORTED: compound ICMP negation"
            );
            let first = parts.get(1).copied().unwrap_or(0);
            let last = parts.get(1).copied().unwrap_or(255);
            out.push(json!({"icmpHeader":{"protocol":name,"type":parts[0],"codeFirst":first,"codeLast":last,"inverted":negated}}));
        } else if protocol.as_ref().is_some_and(|(n, p)| !*n && p == name) {
            let tokens = text.split_whitespace().collect::<Vec<_>>();
            ensure!(
                !tokens.windows(2).any(|p| ["-m", "--match"].contains(&p[0])
                    && (p[1] == name
                        || (name == "icmpv6" && ["ipv6-icmp", "icmp6"].contains(&p[1])))),
                "UNSUPPORTED: original default ICMP module requires explicit type evidence"
            );
        }
    }
    if let Some((negated, value)) = terms.remove("state") {
        let states = value
            .split(',')
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>();
        ensure!(
            states
                .iter()
                .all(|s| ["new", "related", "established", "invalid"].contains(&s.as_str())),
            "UNSUPPORTED: original model state"
        );
        out.push(json!({"match":{"left":{"ct":{"key":"state"}},"op":if negated{"not in"}else{"in"},"right":{"set":states}}}));
    }
    let verdict = match action.as_str() {
        "ACCEPT" => json!({"accept":null}),
        "DROP" => json!({"drop":null}),
        "RETURN" => json!({"return":null}),
        "MASQUERADE" => {
            ensure!(
                table.name == "nat",
                "UNSUPPORTED: masquerade outside original NAT table"
            );
            json!({"masquerade":null})
        }
        "DNAT" | "SNAT" => {
            ensure!(
                table.name == "nat",
                "UNSUPPORTED: address translation outside original NAT table"
            );
            let key = if action == "DNAT" { "dnat" } else { "snat" };
            let (negated, value) = terms
                .remove(key)
                .context("UNSUPPORTED: missing original NAT target")?;
            ensure!(!negated, "UNSUPPORTED: negated original NAT target");
            let target = nat_target(family, &value)?;
            if target.get("port").is_some() {
                ensure!(
                    protocol
                        .as_ref()
                        .is_some_and(|(n, p)| !*n && ["tcp", "udp"].contains(&p.as_str())),
                    "UNSUPPORTED: original NAT port requires TCP/UDP"
                );
            }
            json!({key:target})
        }
        target => {
            ensure!(
                table
                    .chains
                    .iter()
                    .any(|c| c.name == target && c.policy.is_none()),
                "UNSUPPORTED: undeclared/non-regular original jump target"
            );
            json!({"jump":{"target":target}})
        }
    };
    ensure!(
        terms.is_empty(),
        "UNSUPPORTED: unconsumed original model fields"
    );
    out.push(verdict);
    Ok(out)
}
