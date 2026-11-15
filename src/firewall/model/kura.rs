//! Version 3 preserves Kura's complete structured firewall rule surface.
//! It deliberately does not accept arbitrary iptables or nft source text.
use super::*;
mod exact;
pub(in crate::firewall) use exact::Candidate as ExactCandidate;
pub(super) const EXACT_MARKER: &str = exact::MARKER;

pub(super) fn exact_compile(value: Value) -> Result<Compiled> {
    exact::compile(value)
}

pub(super) const MARKER: &str = "# yofc-firewall-v3 ";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::firewall) struct Candidate {
    schema_version: u8,
    ipv4: FamilyPolicy,
    ipv6: FamilyPolicy,
    input: Vec<Input>,
    port_forward: Vec<PortForward>,
    nat: Vec<Nat>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FamilyPolicy {
    input_policy: Policy,
    forward_policy: Policy,
    allow_icmp: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ports {
    first: u16,
    last: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Input {
    family: Family,
    protocol: Protocol,
    ports: Ports,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    input_interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    excluded_interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_ports: Option<Ports>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PortForward {
    family: Family,
    protocol: Protocol,
    input_interface: String,
    output_interface: String,
    address: String,
    in_port: u16,
    out_port: u16,
    masquerade: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_ports: Option<Ports>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NatProtocol {
    All,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Gre,
    Esp,
    Ah,
    Sctp,
    #[serde(untagged)]
    Number(u8),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Nat {
    family: Family,
    input_interface: String,
    output_interface: String,
    protocol: Option<NatProtocol>,
    masquerade: bool,
    automatic: bool,
    rule_type: Option<RuleType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RuleType {
    Generic,
    IpForwarding,
    PortForwarding,
}

impl Rule {
    fn kura_family(family: Family) -> Self {
        let mut rule = Self::family(family);
        let version = if matches!(family, Family::Ipv4) { 4 } else { 6 };
        rule.text
            .push(format!("{} version {version}", family.payload()));
        rule.expr.push(matching(
            json!({"payload":{"protocol":family.payload(),"field":"version"}}),
            json!(version),
        ));
        rule
    }
    fn kura_interface(&mut self, key: &str, name: &str, excluded: bool) -> Result<()> {
        if name == "+" {
            return Ok(());
        }
        let (stem, wildcard) = match name.strip_suffix('+') {
            Some(stem) => (stem, true),
            None => (name, false),
        };
        ensure!(
            !stem.is_empty()
                && name.len() <= 15
                && stem
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)),
            "INVALID_ARGUMENT: Kura interface name"
        );
        let name = format!("{stem}{}", if wildcard { "*" } else { "" });
        let op = if excluded { "!=" } else { "==" };
        self.text.push(format!(
            "{key} {}\"{name}\"",
            if excluded { "!= " } else { "" }
        ));
        self.expr
            .push(json!({"match":{"op":op,"left":{"meta":{"key":key}},"right":name}}));
        Ok(())
    }

    fn ports(&mut self, protocol: Protocol, field: &str, ports: &Ports) -> Result<()> {
        ensure!(
            ports.first > 0 && ports.first <= ports.last,
            "INVALID_ARGUMENT: Kura port range"
        );
        let (text, right) = if ports.first == ports.last {
            (ports.first.to_string(), json!(ports.first))
        } else {
            (
                format!("{}-{}", ports.first, ports.last),
                json!({"range":[ports.first,ports.last]}),
            )
        };
        self.text
            .push(format!("{} {field} {text}", protocol.as_str()));
        self.expr.push(matching(
            json!({"payload":{"protocol":protocol.as_str(),"field":field}}),
            right,
        ));
        Ok(())
    }

    fn source_mac(&mut self, mac: &Option<String>) -> Result<()> {
        if let Some(mac) = mac {
            ensure!(
                mac.len() == 17
                    && mac.split(':').count() == 6
                    && mac
                        .split(':')
                        .all(|part| part.len() == 2 && part.bytes().all(|c| c.is_ascii_hexdigit())),
                "INVALID_ARGUMENT: Kura source MAC"
            );
            let mac = mac.to_ascii_lowercase();
            self.text.push(format!("ether saddr {mac}"));
            self.expr.push(matching(
                json!({"payload":{"protocol":"ether","field":"saddr"}}),
                json!(mac),
            ));
        }
        Ok(())
    }

    fn nat_protocol(&mut self, family: Family, protocol: NatProtocol) -> Result<()> {
        let name = match protocol {
            NatProtocol::All => return Ok(()),
            NatProtocol::Tcp => "tcp",
            NatProtocol::Udp => "udp",
            NatProtocol::Icmp => {
                ensure!(
                    matches!(family, Family::Ipv4),
                    "INVALID_ARGUMENT: ICMP family"
                );
                "icmp"
            }
            NatProtocol::Icmpv6 => {
                ensure!(
                    matches!(family, Family::Ipv6),
                    "INVALID_ARGUMENT: ICMPv6 family"
                );
                "ipv6-icmp"
            }
            NatProtocol::Gre => "47",
            NatProtocol::Esp => "50",
            NatProtocol::Ah => "51",
            NatProtocol::Sctp => "132",
            NatProtocol::Number(0) => return Ok(()),
            NatProtocol::Number(number) => {
                self.text.push(format!("meta l4proto {number}"));
                self.expr
                    .push(matching(json!({"meta":{"key":"l4proto"}}), json!(number)));
                return Ok(());
            }
        };
        self.text.push(format!("meta l4proto {name}"));
        let right = match name.parse::<u8>() {
            Ok(number) => json!(number),
            Err(_) => json!(name),
        };
        self.expr
            .push(matching(json!({"meta":{"key":"l4proto"}}), right));
        Ok(())
    }

    fn source(&mut self, family: Family, source: &Option<String>) -> Result<()> {
        if let Some(source) = source {
            self.address(family, "saddr", source)?;
        }
        Ok(())
    }

    fn source_ports(&mut self, protocol: Protocol, ports: &Option<Ports>) -> Result<()> {
        if let Some(ports) = ports {
            self.ports(protocol, "sport", ports)?;
        }
        Ok(())
    }
}

impl Candidate {
    pub(in crate::firewall) fn forwarding_families(&self) -> (bool, bool) {
        let mut result = (false, false);
        for family in self
            .port_forward
            .iter()
            .map(|r| r.family)
            .chain(self.nat.iter().map(|r| r.family))
        {
            match family {
                Family::Ipv4 => result.0 = true,
                Family::Ipv6 => result.1 = true,
            }
        }
        result
    }

    pub(in crate::firewall) fn compile(&self) -> Result<Compiled> {
        ensure!(
            self.schema_version == 3,
            "INVALID_ARGUMENT: Kura firewall schema version"
        );
        self.compile_with(format!("{MARKER}{}", serde_json::to_string(self)?), None)
    }

    fn compile_with(&self, header: String, legacy_output: Option<[Policy; 2]>) -> Result<Compiled> {
        ensure!(
            self.input.len() + self.port_forward.len() + self.nat.len() <= MAX_RULES,
            "INVALID_ARGUMENT: too many Kura firewall rules"
        );
        let mut b = Builder {
            text: format!("{header}\ndestroy table inet {TABLE}\ntable inet {TABLE} {{\n"),
            entries: vec![json!({"table":{"family":"inet","name":TABLE}})],
        };
        // A common inet base-chain policy cannot encode two independent family
        // policies. Explicit terminal family rules preserve that distinction.
        b.chain("input", "filter", 0, "accept");
        if legacy_output.is_none() {
            b.established("input");
        }
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
        if legacy_output.is_some() {
            b.established("input");
        }
        if legacy_output.is_some() {
            exact::write_input_icmp(self, &mut b)?;
        } else {
            // Retain essential IPv6 control traffic even when ICMP echo is closed.
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
                        text: vec![format!(
                            "ip6 version 6 meta l4proto ipv6-icmp icmpv6 type {name}"
                        )],
                        expr: vec![
                            matching(
                                json!({"payload":{"protocol":"ip6","field":"version"}}),
                                json!(6),
                            ),
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
            for (family, policy) in [(Family::Ipv4, &self.ipv4), (Family::Ipv6, &self.ipv6)] {
                if policy.allow_icmp {
                    let mut r = Rule::kura_family(family);
                    r.nat_protocol(
                        family,
                        if matches!(family, Family::Ipv4) {
                            NatProtocol::Icmp
                        } else {
                            NatProtocol::Icmpv6
                        },
                    )?;
                    b.rule("input", r, "accept", json!({"accept":null}), "yofc managed");
                }
            }
        }
        for input in &self.input {
            ensure!(
                input.input_interface.is_none() || input.excluded_interface.is_none(),
                "INVALID_ARGUMENT: conflicting Kura input interface conditions"
            );
            let mut r = Rule::kura_family(input.family);
            r.source(input.family, &input.source)?;
            if let Some(name) = &input.input_interface {
                r.kura_interface("iifname", name, false)?;
            }
            if let Some(name) = &input.excluded_interface {
                r.kura_interface("iifname", name, true)?;
            }
            r.source_mac(&input.source_mac)?;
            r.source_ports(input.protocol, &input.source_ports)?;
            r.ports(input.protocol, "dport", &input.ports)?;
            // Validate every field before omitting this intentionally inactive
            // legacy rule; it must still round-trip through the Kura API.
            if input.excluded_interface.as_deref() == Some("+") {
                continue;
            }
            b.rule("input", r, "accept", json!({"accept":null}), "yofc managed");
        }
        self.terminal_policies(&mut b, "input");
        b.text.push_str("}\n");
        b.chain("forward", "filter", 0, "accept");
        if legacy_output.is_none() {
            b.established("forward");
        }
        for pf in &self.port_forward {
            let address = pf.family.address(&pf.address)?;
            ensure!(
                pf.in_port > 0 && pf.out_port > 0,
                "INVALID_ARGUMENT: Kura forwarding port"
            );
            let mut r = Rule::kura_family(pf.family);
            r.source(pf.family, &pf.source)?;
            r.address(pf.family, "daddr", &address)?;
            r.kura_interface("iifname", &pf.input_interface, false)?;
            r.kura_interface("oifname", &pf.output_interface, false)?;
            r.nat_protocol(
                pf.family,
                match pf.protocol {
                    Protocol::Tcp => NatProtocol::Tcp,
                    Protocol::Udp => NatProtocol::Udp,
                },
            )?;
            r.source_mac(&pf.source_mac)?;
            r.source_ports(pf.protocol, &pf.source_ports)?;
            // Original Kura port-forward filtering admits the selected target
            // host/protocol, not only outPort. Preserve that reviewed meaning.
            b.rule(
                "forward",
                r,
                "accept",
                json!({"accept":null}),
                "yofc managed",
            );
        }
        for nat in &self.nat {
            ensure!(
                !nat.automatic
                    || (nat.protocol.is_none()
                        && nat.rule_type.is_none()
                        && nat.source.is_none()
                        && nat.destination.is_none()),
                "INVALID_ARGUMENT: automatic Kura NAT has extra conditions"
            );
            let mut r = Rule::kura_family(nat.family);
            r.source(nat.family, &nat.source)?;
            if let Some(dst) = &nat.destination {
                r.address(nat.family, "daddr", dst)?;
            }
            r.kura_interface("iifname", &nat.input_interface, false)?;
            r.kura_interface("oifname", &nat.output_interface, false)?;
            r.nat_protocol(nat.family, nat.protocol.unwrap_or(NatProtocol::All))?;
            b.rule(
                "forward",
                r,
                "accept",
                json!({"accept":null}),
                "yofc managed",
            );
        }
        if legacy_output.is_some() {
            exact::write_forward_icmp(self, &mut b)?;
        }
        self.terminal_policies(&mut b, "forward");
        b.text.push_str("}\n");
        if let Some(outputs) = legacy_output {
            exact::write_output(self, &mut b, outputs)?;
        }
        b.chain("prerouting", "nat", -100, "accept");
        for pf in &self.port_forward {
            let mut r = Rule::kura_family(pf.family);
            r.kura_interface("iifname", &pf.input_interface, false)?;
            r.source(pf.family, &pf.source)?;
            r.source_mac(&pf.source_mac)?;
            r.source_ports(pf.protocol, &pf.source_ports)?;
            r.port(pf.protocol, pf.in_port)?;
            let address = pf.family.address(&pf.address)?;
            let target = if matches!(pf.family, Family::Ipv6) {
                format!("[{address}]")
            } else {
                address.clone()
            };
            b.rule(
                "prerouting",
                r,
                &format!("dnat {} to {target}:{}", pf.family.payload(), pf.out_port),
                json!({"dnat":{"family":pf.family.payload(),"addr":address,"port":pf.out_port}}),
                "yofc managed",
            );
        }
        b.text.push_str("}\n");
        b.chain("postrouting", "nat", 100, "accept");
        for pf in &self.port_forward {
            if pf.masquerade {
                let mut r = Rule::kura_family(pf.family);
                r.source(pf.family, &pf.source)?;
                r.address(pf.family, "daddr", &pf.family.address(&pf.address)?)?;
                r.kura_interface("oifname", &pf.output_interface, false)?;
                r.nat_protocol(
                    pf.family,
                    match pf.protocol {
                        Protocol::Tcp => NatProtocol::Tcp,
                        Protocol::Udp => NatProtocol::Udp,
                    },
                )?;
                b.rule(
                    "postrouting",
                    r,
                    "masquerade",
                    json!({"masquerade":null}),
                    "yofc managed",
                );
            }
        }
        for nat in &self.nat {
            if nat.masquerade {
                let mut r = Rule::kura_family(nat.family);
                // Kura's unspecified protocol selects its interface-only NAT
                // constructor; source/destination still constrain forwarding.
                if nat.protocol.is_some() {
                    r.source(nat.family, &nat.source)?;
                    if let Some(dst) = &nat.destination {
                        r.address(nat.family, "daddr", dst)?;
                    }
                }
                // Original Kura's postrouting match omits the input interface.
                r.kura_interface("oifname", &nat.output_interface, false)?;
                r.nat_protocol(nat.family, nat.protocol.unwrap_or(NatProtocol::All))?;
                b.rule(
                    "postrouting",
                    r,
                    "masquerade",
                    json!({"masquerade":null}),
                    "yofc managed",
                );
            }
        }
        b.text.push_str("}\n}\n");
        Ok(Compiled {
            text: b.text,
            expected: semantic_table(&b.entries)?,
        })
    }

    fn terminal_policies(&self, b: &mut Builder, chain: &str) {
        for (family, policy) in [(Family::Ipv4, &self.ipv4), (Family::Ipv6, &self.ipv6)] {
            let policy = if chain == "input" {
                policy.input_policy
            } else {
                policy.forward_policy
            };
            let action = policy.as_str();
            b.rule(
                chain,
                Rule::kura_family(family),
                action,
                json!({action:null}),
                "yofc policy",
            );
        }
    }
}

pub(super) fn expected(text: &str) -> Result<Compiled> {
    let raw = text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix(MARKER))
        .context("CONFLICT: firewall v3 marker")?;
    let candidate: Candidate =
        serde_json::from_str(raw).context("CONFLICT: firewall v3 grammar")?;
    candidate.compile()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn candidate() -> Value {
        super::super::fixture_kura_candidate()
    }
    fn compile(value: Value) -> Result<Compiled> {
        serde_json::from_value::<Candidate>(value)?.compile()
    }
    #[test]
    fn complete_kura_fields_compile_without_weakening_either_address_family() {
        let compiled = compile(candidate()).unwrap();
        assert!(compiled.text.contains("iifname != \"wan*\""));
        assert!(
            compiled.text.contains(
                "ether saddr 02:ab:00:00:00:01 tcp sport 20000-20002 tcp dport 18080-18082"
            )
        );
        assert!(compiled.text.contains("dnat ip6 to [2001:db8:2::2]:18084"));
        assert!(
            compiled
                .text
                .contains("meta nfproto ipv4 ip version 4 drop comment \"yofc policy\"")
        );
        assert!(
            compiled
                .text
                .contains("meta nfproto ipv6 ip6 version 6 accept comment \"yofc policy\"")
        );
        assert_eq!(
            super::super::expected_table(&compiled.text).unwrap(),
            compiled.expected
        );
        assert!(
            super::super::expected_table(&compiled.text.replace("20000-20002", "20000-20003"))
                .is_err()
        );
    }
    #[test]
    fn malformed_or_ambiguous_fields_fail_before_nft_or_journal_mutation() {
        let cases = [
            ("/schemaVersion", json!(2)),
            ("/input/0/ports/first", json!(0)),
            ("/input/0/ports/last", json!(18079)),
            ("/input/0/sourcePorts/last", json!(19999)),
            ("/input/0/sourceMac", json!("02:00:00:00:00:zz")),
            ("/input/0/excludedInterface", json!("wan+bad")),
            ("/input/0/source", json!("2001:db8::/64")),
            ("/portForward/0/address", json!("192.0.2.2")),
            ("/portForward/0/outPort", json!(0)),
            ("/nat/0/protocol", json!("icmpv6")),
        ];
        for (path, value) in cases {
            let mut v = candidate();
            *v.pointer_mut(path).unwrap() = value;
            assert!(compile(v).is_err(), "{path}");
        }
        let mut v = candidate();
        v["input"][0]["inputInterface"] = json!("wan0");
        assert!(compile(v).is_err());
        let mut v = candidate();
        v["input"][0]["script"] = json!("flush ruleset");
        assert!(compile(v).is_err());
        let mut v = candidate();
        let row = v["nat"][0].clone();
        v["nat"] = json!(vec![row; 257]);
        assert!(compile(v).is_err());
    }
    #[test]
    fn explicit_no_masquerade_and_both_icmp_families_remain_distinct() {
        let mut v = candidate();
        v["portForward"][0]["masquerade"] = json!(false);
        v["nat"][0]["masquerade"] = json!(false);
        let compiled = compile(v).unwrap();
        assert!(!compiled.text.contains("masquerade comment"));
        let mut v = candidate();
        v["ipv4"]["allowIcmp"] = json!(false);
        v["ipv6"]["allowIcmp"] = json!(true);
        v["nat"][0]["protocol"] = json!("icmp");
        let compiled = compile(v).unwrap();
        assert!(
            compiled
                .text
                .contains("meta nfproto ipv6 ip6 version 6 meta l4proto ipv6-icmp accept")
        );
        assert!(
            !compiled
                .text
                .contains("meta nfproto ipv4 ip version 4 meta l4proto icmp accept")
        );
        assert!(compiled.text.contains("meta l4proto icmp masquerade"));
    }

    #[test]
    fn numeric_protocols_and_legacy_universal_interfaces_have_exact_bounded_meaning() {
        for number in [0, 1, 6, 17, 47, 58, 132, 255] {
            let mut value = candidate();
            value["nat"][0]["protocol"] = json!(number);
            value["nat"][0]["inputInterface"] = json!("+");
            let compiled = compile(value).unwrap();
            if number == 0 {
                assert!(!compiled.text.contains("meta l4proto 0"));
            } else {
                assert!(compiled.text.contains(&format!("meta l4proto {number}")));
            }
        }
        for bad in [json!(256), json!(-1), json!(6.5), json!("unknown-protocol")] {
            let mut value = candidate();
            value["nat"][0]["protocol"] = bad;
            assert!(compile(value).is_err());
        }
        let mut value = candidate();
        value["input"][0]["excludedInterface"] = json!("+");
        assert!(
            !compile(value.clone())
                .unwrap()
                .text
                .contains("tcp dport 18080-18082")
        );
        value["input"][0]["ports"]["first"] = json!(0);
        assert!(compile(value).is_err());
    }

    #[test]
    fn unspecified_nat_protocol_retains_kuras_interface_only_masquerade_constructor() {
        let mut value = candidate();
        value["nat"][0]["protocol"] = Value::Null;
        value["nat"][0]["source"] = json!("192.0.2.0/24");
        let compiled = compile(value.clone()).unwrap();
        let post = compiled.text.split("chain postrouting").nth(1).unwrap();
        assert!(!post.contains("192.0.2.0/24"));
        value["nat"][0]["protocol"] = json!("all");
        let explicit = compile(value).unwrap();
        assert!(
            explicit
                .text
                .split("chain postrouting")
                .nth(1)
                .unwrap()
                .contains("192.0.2.0/24")
        );
    }
}
