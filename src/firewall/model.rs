//! Versioned, bounded firewall grammar. NAT never implicitly grants forwarding
//! and an IPv4 rule never opens its IPv6 counterpart.
use super::{TABLE, prefix};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::IpAddr;
mod kura;
pub(super) use kura::Candidate as KuraCandidate;

const MARKER: &str = "# yofc-firewall-v2 ";
const MAX_RULES: usize = 256;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Policy {
    Accept,
    Drop,
}
impl Policy {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Drop => "drop",
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Family {
    Ipv4,
    Ipv6,
}
impl Family {
    fn payload(self) -> &'static str {
        match self {
            Self::Ipv4 => "ip",
            Self::Ipv6 => "ip6",
        }
    }
    fn meta(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
    fn address(self, value: &str) -> Result<String> {
        let address: IpAddr = value.parse().context("INVALID_ARGUMENT: NAT address")?;
        ensure!(
            address.is_ipv6() == matches!(self, Self::Ipv6),
            "INVALID_ARGUMENT: address family"
        );
        ensure!(
            !address.is_unspecified() && !address.is_multicast(),
            "INVALID_ARGUMENT: unicast NAT address required"
        );
        Ok(address.to_string())
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    Tcp,
    Udp,
}
impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Candidate {
    schema_version: u8,
    pub(super) input_policy: Policy,
    forward_policy: Policy,
    input: Vec<Input>,
    forward: Vec<Forward>,
    destination_nat: Vec<DestinationNat>,
    source_nat: Vec<SourceNat>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Input {
    family: Family,
    protocol: Protocol,
    port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    input_interface: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Forward {
    family: Family,
    input_interface: String,
    output_interface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protocol: Option<Protocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DestinationNat {
    family: Family,
    input_interface: String,
    protocol: Protocol,
    port: u16,
    destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    translated_address: String,
    translated_port: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SourceNat {
    family: Family,
    output_interface: String,
    source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
    translation: Translation,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum Translation {
    Masquerade {},
    Snat { address: String },
}

pub(super) struct Compiled {
    pub text: String,
    expected: Value,
}
struct Builder {
    text: String,
    entries: Vec<Value>,
}
struct Rule {
    text: Vec<String>,
    expr: Vec<Value>,
}
impl Rule {
    fn family(family: Family) -> Self {
        Self {
            text: vec![format!("meta nfproto {}", family.meta())],
            expr: vec![matching(
                json!({"meta":{"key":"nfproto"}}),
                json!(family.meta()),
            )],
        }
    }
    fn interface(&mut self, key: &str, name: &str) -> Result<()> {
        ensure!(
            !name.is_empty()
                && name.len() <= 15
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)),
            "INVALID_ARGUMENT: interface name"
        );
        self.text.push(format!("{key} \"{name}\""));
        self.expr
            .push(matching(json!({"meta":{"key":key}}), json!(name)));
        Ok(())
    }
    fn address(&mut self, family: Family, field: &str, value: &str) -> Result<()> {
        let canonical = prefix(value, matches!(family, Family::Ipv6))?;
        let (address, length) = canonical
            .split_once('/')
            .context("INVALID_ARGUMENT: prefix")?;
        let length: u32 = length.parse()?;
        let right = if length
            == if matches!(family, Family::Ipv6) {
                128
            } else {
                32
            } {
            json!(address)
        } else {
            json!({"prefix":{"addr":address,"len":length}})
        };
        self.text
            .push(format!("{} {field} {canonical}", family.payload()));
        self.expr.push(matching(
            json!({"payload":{"protocol":family.payload(),"field":field}}),
            right,
        ));
        Ok(())
    }
    fn port(&mut self, protocol: Protocol, port: u16) -> Result<()> {
        ensure!(port > 0, "INVALID_ARGUMENT: port");
        self.text
            .push(format!("{} dport {port}", protocol.as_str()));
        self.expr.push(matching(
            json!({"payload":{"protocol":protocol.as_str(),"field":"dport"}}),
            json!(port),
        ));
        Ok(())
    }
}
fn matching(left: Value, right: Value) -> Value {
    json!({"match":{"op":"==","left":left,"right":right}})
}
impl Builder {
    fn chain(&mut self, name: &str, kind: &str, priority: i32, policy: &str) {
        self.text.push_str(&format!(
            "chain {name} {{ type {kind} hook {name} priority {priority}; policy {policy};\n"
        ));
        self.entries.push(json!({"chain":{"family":"inet","table":TABLE,"name":name,"type":kind,"hook":name,"prio":priority,"policy":policy}}));
    }
    fn rule(&mut self, chain: &str, rule: Rule, action: &str, value: Value, comment: &str) {
        self.text.push_str(&format!(
            "{} {action} comment \"{comment}\"\n",
            rule.text.join(" ")
        ));
        let mut expr = rule.expr;
        expr.push(value);
        self.entries.push(json!({"rule":{"family":"inet","table":TABLE,"chain":chain,"comment":comment,"expr":expr}}));
    }
    fn established(&mut self, chain: &str) {
        self.rule(chain, Rule {text:vec!["ct state established,related".into()],expr:vec![json!({"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}})]}, "accept", json!({"accept":null}), "yofc baseline");
    }
}
impl Candidate {
    pub(super) fn forwarding_families(&self) -> (bool, bool) {
        let mut families = (false, false);
        for family in self
            .forward
            .iter()
            .map(|r| r.family)
            .chain(self.destination_nat.iter().map(|r| r.family))
            .chain(self.source_nat.iter().map(|r| r.family))
        {
            match family {
                Family::Ipv4 => families.0 = true,
                Family::Ipv6 => families.1 = true,
            }
        }
        families
    }
    pub(super) fn compile(&self) -> Result<Compiled> {
        ensure!(
            self.schema_version == 2,
            "INVALID_ARGUMENT: firewall schema version"
        );
        ensure!(
            self.input.len()
                + self.forward.len()
                + self.destination_nat.len()
                + self.source_nat.len()
                <= MAX_RULES,
            "INVALID_ARGUMENT: too many firewall rules"
        );
        let mut b = Builder {
            text: format!(
                "{MARKER}{}\ndestroy table inet {TABLE}\ntable inet {TABLE} {{\n",
                serde_json::to_string(self)?
            ),
            entries: vec![json!({"table":{"family":"inet","name":TABLE}})],
        };
        b.chain("input", "filter", 0, self.input_policy.as_str());
        b.established("input");
        b.rule(
            "input",
            Rule {
                text: vec!["iifname \"lo\"".into()],
                expr: vec![matching(json!({"meta":{"key":"iifname"}}), json!("lo"))],
            },
            "accept",
            json!({"accept":null}),
            "yofc baseline",
        );
        // Essential IPv6 control traffic, including neighbour discovery, must
        // survive a drop policy. No TCP/UDP service is opened by this baseline.
        for (name, number) in [
            ("destination-unreachable", 1),
            ("packet-too-big", 2),
            ("time-exceeded", 3),
            ("parameter-problem", 4),
            ("nd-router-solicit", 133),
            ("nd-router-advert", 134),
            ("nd-neighbor-solicit", 135),
            ("nd-neighbor-advert", 136),
        ] {
            b.rule(
                "input",
                Rule {
                    text: vec![format!("meta l4proto ipv6-icmp icmpv6 type {name}")],
                    expr: vec![
                        matching(json!({"meta":{"key":"l4proto"}}), json!("ipv6-icmp")),
                        matching(
                            json!({"payload":{"protocol":"icmpv6","field":"type"}}),
                            json!(number),
                        ),
                    ],
                },
                "accept",
                json!({"accept":null}),
                "yofc baseline",
            );
        }
        for input in &self.input {
            let mut r = Rule::family(input.family);
            if let Some(interface) = &input.input_interface {
                r.interface("iifname", interface)?;
            }
            if let Some(source) = &input.source {
                r.address(input.family, "saddr", source)?;
            }
            r.port(input.protocol, input.port)?;
            b.rule("input", r, "accept", json!({"accept":null}), "yofc managed");
        }
        b.text.push_str("}\n");
        b.chain("forward", "filter", 0, self.forward_policy.as_str());
        b.established("forward");
        for forward in &self.forward {
            let mut r = Rule::family(forward.family);
            r.interface("iifname", &forward.input_interface)?;
            r.interface("oifname", &forward.output_interface)?;
            if let Some(source) = &forward.source {
                r.address(forward.family, "saddr", source)?;
            }
            if let Some(destination) = &forward.destination {
                r.address(forward.family, "daddr", destination)?;
            }
            match (forward.protocol, forward.port) {
                (Some(protocol), Some(port)) => r.port(protocol, port)?,
                (Some(protocol), None) => {
                    r.text.push(format!("meta l4proto {}", protocol.as_str()));
                    r.expr.push(matching(
                        json!({"meta":{"key":"l4proto"}}),
                        json!(protocol.as_str()),
                    ));
                }
                (None, Some(_)) => anyhow::bail!("INVALID_ARGUMENT: port requires protocol"),
                (None, None) => (),
            }
            b.rule(
                "forward",
                r,
                "accept",
                json!({"accept":null}),
                "yofc managed",
            );
        }
        b.text.push_str("}\n");
        b.chain("prerouting", "nat", -100, "accept");
        for nat in &self.destination_nat {
            let mut r = Rule::family(nat.family);
            r.interface("iifname", &nat.input_interface)?;
            if let Some(source) = &nat.source {
                r.address(nat.family, "saddr", source)?;
            }
            r.address(nat.family, "daddr", &nat.family.address(&nat.destination)?)?;
            r.port(nat.protocol, nat.port)?;
            let address = nat.family.address(&nat.translated_address)?;
            ensure!(nat.translated_port > 0, "INVALID_ARGUMENT: translated port");
            let target = if matches!(nat.family, Family::Ipv6) {
                format!("[{address}]")
            } else {
                address.clone()
            };
            b.rule("prerouting",r,&format!("dnat {} to {target}:{}",nat.family.payload(),nat.translated_port),json!({"dnat":{"family":nat.family.payload(),"addr":address,"port":nat.translated_port}}),"yofc managed");
        }
        b.text.push_str("}\n");
        b.chain("postrouting", "nat", 100, "accept");
        for nat in &self.source_nat {
            let mut r = Rule::family(nat.family);
            r.interface("oifname", &nat.output_interface)?;
            r.address(nat.family, "saddr", &nat.source)?;
            if let Some(destination) = &nat.destination {
                r.address(nat.family, "daddr", destination)?;
            }
            match &nat.translation {
                Translation::Masquerade {} => b.rule(
                    "postrouting",
                    r,
                    "masquerade",
                    json!({"masquerade":null}),
                    "yofc managed",
                ),
                Translation::Snat { address } => {
                    let address = nat.family.address(address)?;
                    b.rule(
                        "postrouting",
                        r,
                        &format!("snat {} to {address}", nat.family.payload()),
                        json!({"snat":{"family":nat.family.payload(),"addr":address}}),
                        "yofc managed",
                    );
                }
            }
        }
        b.text.push_str("}\n}\n");
        let expected = semantic_table(&b.entries)?;
        Ok(Compiled {
            text: b.text,
            expected,
        })
    }
}
pub(super) fn is_versioned(text: &str) -> bool {
    text.starts_with(MARKER) || text.starts_with(kura::MARKER)
}
pub(super) fn expected_table(text: &str) -> Result<Value> {
    if text.starts_with(kura::MARKER) {
        let compiled = kura::expected(text)?;
        ensure!(
            compiled.text == text,
            "CONFLICT: firewall v3 text differs from candidate"
        );
        return Ok(compiled.expected);
    }
    let raw = text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix(MARKER))
        .context("CONFLICT: firewall v2 marker")?;
    let candidate: Candidate =
        serde_json::from_str(raw).context("CONFLICT: firewall v2 grammar")?;
    let compiled = candidate.compile()?;
    ensure!(
        compiled.text == text,
        "CONFLICT: firewall v2 text differs from candidate"
    );
    Ok(compiled.expected)
}
pub(super) fn semantic_table(entries: &[Value]) -> Result<Value> {
    let mut chains = Vec::new();
    let mut rules = Vec::new();
    let mut tables = 0;
    for entry in entries {
        let object = entry.as_object().context("CONFLICT: firewall object")?;
        ensure!(object.len() == 1, "CONFLICT: unexpected firewall object");
        let (kind, value) = object.iter().next().unwrap();
        match kind.as_str() {
            "metainfo" => continue,
            "table" => {
                tables += 1;
                ensure!(
                    value["family"] == "inet" && value["name"] == TABLE,
                    "CONFLICT: wrong firewall table"
                );
                ensure!(
                    value.as_object().is_some_and(|v| v
                        .keys()
                        .all(|k| ["family", "name", "handle"].contains(&k.as_str()))),
                    "CONFLICT: unexpected table attributes"
                );
            }
            "chain" | "rule" => {
                ensure!(
                    value["family"] == "inet" && value["table"] == TABLE,
                    "CONFLICT: wrong firewall owner"
                );
                let mut normalized = value
                    .as_object()
                    .context("CONFLICT: firewall entry")?
                    .clone();
                normalized.remove("handle");
                normalized.remove("index");
                if kind == "chain" {
                    chains.push(Value::Object(normalized));
                } else {
                    rules.push(Value::Object(normalized));
                }
            }
            _ => anyhow::bail!("CONFLICT: unsupported object in owned firewall table"),
        }
    }
    ensure!(tables == 1, "CONFLICT: firewall table count");
    // nft emits symbolic ICMPv6 type names. Normalize only this known enum;
    // preserve every other expression/attribute so additions cannot hide drift.
    for rule in &mut rules {
        if let Some(expr) = rule["expr"].as_array_mut() {
            // nft elides protocol dependencies implied by an IP address or
            // ICMPv6 payload expression. Remove only an exact same-family
            // dependency on either side; unrelated or conflicting predicates
            // remain visible to the equality check.
            let implied_v4 = expr
                .iter()
                .any(|e| e["match"]["left"]["payload"]["protocol"] == "ip");
            let implied_v6 = expr
                .iter()
                .any(|e| e["match"]["left"]["payload"]["protocol"] == "ip6");
            let implied_icmp6 = expr
                .iter()
                .any(|e| e["match"]["left"]["payload"]["protocol"] == "icmpv6");
            let implied_tcp = expr
                .iter()
                .any(|e| e["match"]["left"]["payload"]["protocol"] == "tcp");
            let implied_udp = expr
                .iter()
                .any(|e| e["match"]["left"]["payload"]["protocol"] == "udp");
            expr.retain(|term| {
                let matched = &term["match"];
                !(matched["op"] == "=="
                    && ((matched["left"] == json!({"meta":{"key":"nfproto"}})
                        && ((matched["right"] == "ipv4" && implied_v4 && !implied_v6)
                            || (matched["right"] == "ipv6" && implied_v6 && !implied_v4)))
                        || (matched["left"] == json!({"meta":{"key":"l4proto"}})
                            && (((matched["right"] == "ipv6-icmp" || matched["right"] == 58)
                                && implied_icmp6
                                && !implied_tcp
                                && !implied_udp)
                                || ((matched["right"] == "tcp" || matched["right"] == 6)
                                    && implied_tcp
                                    && !implied_udp
                                    && !implied_icmp6)
                                || ((matched["right"] == "udp" || matched["right"] == 17)
                                    && implied_udp
                                    && !implied_tcp
                                    && !implied_icmp6)))))
            });
            for term in expr {
                // Numeric-protocol readback avoids host /etc/protocols aliases.
                // Only known exact enum names are normalized; arbitrary extra
                // expressions, numeric changes and unknown names remain drift.
                if term["match"]["left"] == json!({"meta":{"key":"l4proto"}}) {
                    let number = match term["match"]["right"].as_str() {
                        Some("icmp") => Some(1),
                        Some("tcp") => Some(6),
                        Some("udp") => Some(17),
                        Some("ipv6-icmp") => Some(58),
                        _ => None,
                    };
                    if let Some(number) = number {
                        term["match"]["right"] = json!(number);
                    }
                }
                if term["match"]["left"] == json!({"payload":{"protocol":"icmpv6","field":"type"}})
                    && let Some(name) = term["match"]["right"].as_str()
                {
                    let number = match name {
                        "destination-unreachable" => 1,
                        "packet-too-big" => 2,
                        "time-exceeded" => 3,
                        "parameter-problem" => 4,
                        "nd-router-solicit" => 133,
                        "nd-router-advert" => 134,
                        "nd-neighbor-solicit" => 135,
                        "nd-neighbor-advert" => 136,
                        _ => continue,
                    };
                    term["match"]["right"] = json!(number);
                }
            }
        }
    }
    Ok(json!({"chains":chains,"rules":rules}))
}
#[cfg(test)]
pub(super) fn fake_table(text: &str) -> Value {
    let expected = expected_table(text).unwrap();
    let mut entries = vec![json!({"table":{"family":"inet","name":TABLE}})];
    for chain in expected["chains"].as_array().unwrap() {
        entries.push(json!({"chain":chain}));
    }
    for rule in expected["rules"].as_array().unwrap() {
        entries.push(json!({"rule":rule}));
    }
    json!({"nftables":entries})
}

#[cfg(test)]
pub(super) fn fixture_kura_candidate() -> Value {
    serde_json::from_str(include_str!("fixtures/v3-kura-candidate.json")).unwrap()
}

#[cfg(test)]
pub(super) fn fixture_candidate() -> Value {
    json!({"schemaVersion":2,"inputPolicy":"drop","forwardPolicy":"drop",
        "input":[{"family":"ipv4","protocol":"tcp","port":18443,"source":"192.0.2.7/24","inputInterface":"wan0"}],
        "forward":[{"family":"ipv4","inputInterface":"wan0","outputInterface":"lan0","destination":"198.51.100.2","protocol":"tcp","port":18080}],
        "destinationNat":[{"family":"ipv4","inputInterface":"wan0","protocol":"tcp","port":18081,"destination":"192.0.2.1","translatedAddress":"198.51.100.2","translatedPort":18080}],
        "sourceNat":[{"family":"ipv4","outputInterface":"wan0","source":"198.51.100.0/24","translation":{"type":"masquerade"}},
                     {"family":"ipv6","outputInterface":"wan0","source":"2001:db8:2::/64","translation":{"type":"snat","address":"2001:db8:1::1"}}]})
}
#[cfg(test)]
mod tests {
    use super::*;
    fn compile(value: Value) -> Result<Compiled> {
        serde_json::from_value::<Candidate>(value)?.compile()
    }

    #[test]
    fn actual_kura_capture_elides_only_implied_transport_and_keeps_family_ambiguity_visible() {
        let raw: Value =
            serde_json::from_str(include_str!("fixtures/v3-initial-readback-mismatch.json"))
                .unwrap();
        let actual = semantic_table(raw["kernel"]["nftables"].as_array().unwrap()).unwrap();
        let mut entries = vec![json!({"table":{"family":"inet","name":TABLE}})];
        for chain in raw["expected"]["chains"].as_array().unwrap() {
            entries.push(json!({"chain":chain}));
        }
        for rule in raw["expected"]["rules"].as_array().unwrap() {
            entries.push(json!({"rule":rule}));
        }
        let expected = semantic_table(&entries).unwrap();
        assert_eq!(actual["rules"][16], expected["rules"][16]);
        assert_eq!(actual["rules"][17], expected["rules"][17]);
        // The first renderer lacked an independent IP-header predicate on its
        // ICMP rule. Do not hide that absent family condition as normalization.
        assert_ne!(actual["rules"][10], expected["rules"][10]);
        let mut changed = raw["kernel"]["nftables"].as_array().unwrap().clone();
        let rule = changed
            .iter_mut()
            .filter_map(|v| v.get_mut("rule"))
            .nth(16)
            .unwrap();
        rule["expr"]
            .as_array_mut()
            .unwrap()
            .insert(0, matching(json!({"meta":{"key":"l4proto"}}), json!(6)));
        assert_ne!(
            semantic_table(&changed).unwrap()["rules"][16],
            expected["rules"][16]
        );
    }
    #[test]
    fn actual_nft_1_0_9_capture_normalizes_only_implied_protocol_dependencies() {
        let candidate: Candidate =
            serde_json::from_str(include_str!("fixtures/v2-candidate.json")).unwrap();
        let kernel: Value =
            serde_json::from_str(include_str!("fixtures/v2-nft-1.0.9.json")).unwrap();
        let compiled = candidate.compile().unwrap();
        assert_eq!(
            semantic_table(kernel["nftables"].as_array().unwrap()).unwrap(),
            compiled.expected
        );
        let mut drift = kernel.clone();
        let rule = drift["nftables"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .filter_map(|e| e.get_mut("rule"))
            .find(|r| r["chain"] == "forward")
            .unwrap();
        rule["expr"].as_array_mut().unwrap().insert(
            0,
            matching(json!({"meta":{"key":"nfproto"}}), json!("ipv6")),
        );
        assert_ne!(
            semantic_table(drift["nftables"].as_array().unwrap()).unwrap(),
            compiled.expected
        );
    }
    #[test]
    fn bounded_grammar_rejects_unknown_fields_injection_and_ambiguous_families() {
        let original = fixture_candidate();
        // Each mutation is independent; no invalid candidate may reach nft.
        let cases = [
            ("/schemaVersion", json!(1)),
            ("/input/0/family", json!("inet")),
            ("/input/0/port", json!(0)),
            ("/input/0/source", json!("2001:db8::1")),
            ("/input/0/inputInterface", json!("wan0\"; flush ruleset;#")),
            ("/destinationNat/0/translatedAddress", json!("2001:db8::1")),
            ("/destinationNat/0/translatedPort", json!(0)),
            ("/sourceNat/1/translation/address", json!("::")),
        ];
        for (path, replacement) in cases {
            let mut candidate = original.clone();
            *candidate.pointer_mut(path).unwrap() = replacement;
            assert!(compile(candidate).is_err(), "{path}");
        }
        let mut extra = original.clone();
        extra["sourceNat"][0]["translation"]["command"] = json!("flush ruleset");
        assert!(compile(extra).is_err());
        let mut missing_protocol = original.clone();
        missing_protocol["forward"][0]
            .as_object_mut()
            .unwrap()
            .remove("protocol");
        assert!(compile(missing_protocol).is_err());
        let mut too_many = original.clone();
        too_many["input"] = json!(vec![original["input"][0].clone(); 257]);
        assert!(compile(too_many).is_err());
        let compiled = compile(original).unwrap();
        assert_eq!(compiled.text.matches("destroy table").count(), 1);
        assert!(!compiled.text.contains("flush ruleset"));
        assert!(
            compiled.text.contains(
                "meta nfproto ipv4 iifname \"wan0\" ip saddr 192.0.2.0/24 tcp dport 18443"
            )
        );
        assert!(compiled.text.contains("dnat ip to 198.51.100.2:18080"));
        assert!(compiled.text.contains("snat ip6 to 2001:db8:1::1"));
    }
    #[test]
    fn readback_detects_nat_chain_action_family_policy_and_foreign_object_drift() {
        let compiled = compile(fixture_candidate()).unwrap();
        let listed = fake_table(&compiled.text);
        assert_eq!(
            semantic_table(listed["nftables"].as_array().unwrap()).unwrap(),
            compiled.expected
        );
        for (path, replacement) in [
            ("/nftables/2/chain/prio", json!(5)),
            ("/nftables/2/chain/policy", json!("accept")),
            ("/nftables/4/chain/hook", json!("output")),
            ("/nftables/1/chain/family", json!("ip")),
        ] {
            let mut changed = listed.clone();
            *changed.pointer_mut(path).unwrap() = replacement;
            assert!(
                !semantic_table(changed["nftables"].as_array().unwrap())
                    .is_ok_and(|value| value == compiled.expected)
            );
        }
        let mut changed = listed.clone();
        let rules = changed["nftables"].as_array_mut().unwrap();
        let dnat = rules
            .iter_mut()
            .find_map(|entry| {
                entry
                    .get_mut("rule")?
                    .get_mut("expr")?
                    .as_array_mut()
                    .and_then(|expr| expr.iter_mut().find(|term| term.get("dnat").is_some()))
            })
            .unwrap();
        dnat["dnat"]["addr"] = json!("198.51.100.99");
        assert_ne!(
            semantic_table(changed["nftables"].as_array().unwrap()).unwrap(),
            compiled.expected
        );
        let mut changed = listed.clone();
        changed["nftables"]
            .as_array_mut()
            .unwrap()
            .push(json!({"set":{"family":"inet","table":TABLE,"name":"unknown"}}));
        assert!(semantic_table(changed["nftables"].as_array().unwrap()).is_err());
        assert!(expected_table(&(compiled.text.clone() + "# extra\n")).is_err());
        let candidate: Candidate = serde_json::from_value(fixture_candidate()).unwrap();
        assert_eq!(candidate.forwarding_families(), (true, true));
    }
}
