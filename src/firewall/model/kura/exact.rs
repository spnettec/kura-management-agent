//! Version4 retains the legacy Kura ICMP/control-traffic contract. Version3
//! durable policies keep their original compiler and byte representation.
//! This compiler does not claim or migrate arbitrary additional/kernel rules.
use super::*;

pub(super) const MARKER: &str = "# yofc-firewall-v4 ";

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
    output_policy: Policy,
    allow_icmp: bool,
}

impl Candidate {
    pub(in crate::firewall) fn compile(&self) -> Result<Compiled> {
        ensure!(
            self.schema_version == 4,
            "INVALID_ARGUMENT: exact Kura firewall version"
        );
        let original = super::Candidate {
            schema_version: 3,
            ipv4: super::FamilyPolicy {
                input_policy: self.ipv4.input_policy,
                forward_policy: self.ipv4.forward_policy,
                allow_icmp: self.ipv4.allow_icmp,
            },
            ipv6: super::FamilyPolicy {
                input_policy: self.ipv6.input_policy,
                forward_policy: self.ipv6.forward_policy,
                allow_icmp: self.ipv6.allow_icmp,
            },
            input: self.input.clone(),
            port_forward: self.port_forward.clone(),
            nat: self.nat.clone(),
        };
        original.compile_with(
            format!("{MARKER}{}", serde_json::to_string(self)?),
            Some([self.ipv4.output_policy, self.ipv6.output_policy]),
        )
    }

    pub(in crate::firewall) fn forwarding_families(&self) -> (bool, bool) {
        let mut result = (false, false);
        for family in self.port_forward.iter().map(|r| r.family).chain(self.nat.iter().map(|r| r.family)) {
            match family {
                Family::Ipv4 => result.0 = true,
                Family::Ipv6 => result.1 = true,
            }
        }
        result
    }
}

pub(super) fn compile(value: Value) -> Result<Compiled> {
    serde_json::from_value::<Candidate>(value)
        .context("CONFLICT: firewall v4 grammar")?
        .compile()
}

fn icmp(
    family: Family,
    kind: u8,
    code: Option<u8>,
    source: Option<&str>,
    states: &[&str],
) -> Result<Rule> {
    let mut rule = Rule::kura_family(family);
    let protocol = if matches!(family, Family::Ipv4) {
        "icmp"
    } else {
        "icmpv6"
    };
    rule.nat_protocol(
        family,
        if matches!(family, Family::Ipv4) {
            NatProtocol::Icmp
        } else {
            NatProtocol::Icmpv6
        },
    )?;
    rule.text.push(format!("{protocol} type {kind}"));
    rule.expr.push(matching(
        json!({"payload":{"protocol":protocol,"field":"type"}}),
        json!(kind),
    ));
    if let Some(code) = code {
        rule.text.push(format!("{protocol} code {code}"));
        rule.expr.push(matching(
            json!({"payload":{"protocol":protocol,"field":"code"}}),
            json!(code),
        ));
    }
    if let Some(source) = source {
        rule.address(family, "saddr", source)?;
    }
    if !states.is_empty() {
        rule.text
            .push(format!("ct state {{ {} }}", states.join(", ")));
        rule.expr.push(matching(
            json!({"ct":{"key":"state"}}),
            json!({"set":states}),
        ));
    }
    Ok(rule)
}

fn echo(
    candidate: &super::Candidate,
    b: &mut Builder,
    chain: &str,
    kind: u8,
    states: &[&str],
) -> Result<()> {
    let action = if candidate.ipv4.allow_icmp {
        "accept"
    } else {
        "drop"
    };
    b.rule(
        chain,
        icmp(Family::Ipv4, kind, None, None, states)?,
        action,
        json!({action:null}),
        "yofc legacy ICMP",
    );
    Ok(())
}

pub(super) fn write_input_icmp(candidate: &super::Candidate, b: &mut Builder) -> Result<()> {
    // Exactly IptablesConfigConstants.{ALLOW,DO_NOT_ALLOW}_ICMP: echo request,
    // not an unconditional allow/drop of every IPv4 ICMP type.
    echo(candidate, b, "input", 8, &["established", "related", "new"])?;
    if candidate.ipv6.allow_icmp {
        // IptablesConfigIPv6.ALLOW_ICMP_IPV6. Code and link-local restrictions
        // are retained;the disabled legacy list is empty,including ND/MLD.
        for (kind, code) in [
            (1, None),
            (2, None),
            (3, Some(0)),
            (3, Some(1)),
            (4, Some(0)),
            (4, Some(1)),
            (4, Some(2)),
            (128, None),
            (129, None),
            (144, None),
            (145, None),
            (146, None),
            (147, None),
            (130, None),
            (131, None),
            (132, None),
            (133, None),
            (134, None),
            (135, None),
            (136, None),
        ] {
            b.rule(
                "input",
                icmp(Family::Ipv6, kind, code, None, &[])?,
                "accept",
                json!({"accept":null}),
                "yofc legacy ICMP",
            );
        }
        for kind in [141, 142, 148, 149] {
            b.rule(
                "input",
                icmp(Family::Ipv6, kind, None, Some("fe80::/10"), &[])?,
                "accept",
                json!({"accept":null}),
                "yofc legacy ICMP",
            );
        }
        for kind in [151, 152, 153] {
            b.rule(
                "input",
                icmp(Family::Ipv6, kind, None, None, &[])?,
                "accept",
                json!({"accept":null}),
                "yofc legacy ICMP",
            );
        }
    }
    Ok(())
}

pub(super) fn write_forward_icmp(candidate: &super::Candidate, b: &mut Builder) -> Result<()> {
    if candidate.ipv6.allow_icmp {
        for (kind, code) in [
            (1, None),
            (2, None),
            (3, Some(0)),
            (3, Some(1)),
            (4, Some(0)),
            (4, Some(1)),
            (4, Some(2)),
            (144, None),
            (145, None),
            (146, None),
            (147, None),
        ] {
            b.rule(
                "forward",
                icmp(Family::Ipv6, kind, code, None, &[])?,
                "accept",
                json!({"accept":null}),
                "yofc legacy ICMP",
            );
        }
    }
    Ok(())
}

pub(super) fn write_output(
    candidate: &super::Candidate,
    b: &mut Builder,
    policies: [Policy; 2],
) -> Result<()> {
    b.chain("output", "filter", 0, "accept");
    echo(candidate, b, "output", 0, &["established", "related"])?;
    for (family, policy) in [(Family::Ipv4, policies[0]), (Family::Ipv6, policies[1])] {
        let action = policy.as_str();
        b.rule(
            "output",
            Rule::kura_family(family),
            action,
            json!({action:null}),
            "yofc policy",
        );
    }
    b.text.push_str("}\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn candidate(allowed: bool) -> Candidate {
        serde_json::from_value(json!({"schemaVersion":4,
            "ipv4":{"inputPolicy":"drop","forwardPolicy":"drop","outputPolicy":"accept","allowIcmp":allowed},
            "ipv6":{"inputPolicy":"drop","forwardPolicy":"drop","outputPolicy":"accept","allowIcmp":allowed},
            "input":[],"portForward":[],"nat":[]})).unwrap()
    }
    fn rules(compiled: &Compiled, chain: &str, protocol: &str) -> Vec<Value> {
        compiled.expected["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|rule| {
                rule["chain"] == chain
                    && rule["expr"].as_array().unwrap().iter().any(|term| {
                        term["match"]["left"]["payload"]["protocol"] == protocol
                            && term["match"]["left"]["payload"]["field"] == "type"
                    })
            })
            .cloned()
            .collect()
    }
    fn types(rules: &[Value]) -> Vec<(u64, Option<u64>)> {
        rules
            .iter()
            .map(|rule| {
                let mut kind = None;
                let mut code = None;
                for term in rule["expr"].as_array().unwrap() {
                    match term["match"]["left"]["payload"]["field"].as_str() {
                        Some("type") => kind = term["match"]["right"].as_u64(),
                        Some("code") => code = term["match"]["right"].as_u64(),
                        _ => {}
                    }
                }
                (kind.unwrap(), code)
            })
            .collect()
    }
    #[test]
    fn disabled_legacy_icmp_keeps_v4_request_and_reply_drops_and_does_not_invent_v6_control_exceptions()
     {
        let compiled = candidate(false).compile().unwrap();
        for (chain, kind) in [("input", 8), ("output", 0)] {
            let rows = rules(&compiled, chain, "icmp");
            assert_eq!(types(&rows), vec![(kind, None)]);
            let expr = rows[0]["expr"].as_array().unwrap();
            assert_eq!(expr.last().unwrap(), &json!({"drop":null}));
            assert!(
                expr.iter()
                    .any(|term| term["match"]["left"] == json!({"ct":{"key":"state"}}))
            );
        }
        for chain in ["input", "forward", "output"] {
            assert!(rules(&compiled, chain, "icmpv6").is_empty());
        }
        let forwarded = compiled.expected["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|rule| rule["chain"] == "forward")
            .collect::<Vec<_>>();
        assert!(
            forwarded
                .iter()
                .all(|rule| !rule.to_string().contains("state")),
            "legacy Kura has no implicit forward conntrack accept"
        );
    }
    #[test]
    fn enabled_legacy_v6_keeps_exact_type_code_direction_and_link_local_constraints() {
        let compiled = candidate(true).compile().unwrap();
        let input = rules(&compiled, "input", "icmpv6");
        let forward = rules(&compiled, "forward", "icmpv6");
        assert_eq!(
            types(&input),
            vec![
                (1, None),
                (2, None),
                (3, Some(0)),
                (3, Some(1)),
                (4, Some(0)),
                (4, Some(1)),
                (4, Some(2)),
                (128, None),
                (129, None),
                (144, None),
                (145, None),
                (146, None),
                (147, None),
                (130, None),
                (131, None),
                (132, None),
                (133, None),
                (134, None),
                (135, None),
                (136, None),
                (141, None),
                (142, None),
                (148, None),
                (149, None),
                (151, None),
                (152, None),
                (153, None)
            ]
        );
        assert_eq!(
            types(&forward),
            vec![
                (1, None),
                (2, None),
                (3, Some(0)),
                (3, Some(1)),
                (4, Some(0)),
                (4, Some(1)),
                (4, Some(2)),
                (144, None),
                (145, None),
                (146, None),
                (147, None)
            ]
        );
        for (index, rule) in input.iter().enumerate() {
            let scoped =
                rule["expr"].as_array().unwrap().iter().any(|term| {
                    term["match"]["right"] == json!({"prefix":{"addr":"fe80::","len":10}})
                });
            assert_eq!(scoped, (20..24).contains(&index));
        }
        assert!(rules(&compiled, "output", "icmpv6").is_empty());
        for chain in ["input", "output"] {
            assert_eq!(rules(&compiled, chain, "icmp").len(), 1);
        }
    }
    #[test]
    fn output_policies_are_independent_per_family_and_never_defaulted_from_input() {
        let mut value = serde_json::to_value(candidate(false)).unwrap();
        value["ipv4"]["outputPolicy"] = json!("drop");
        value["ipv6"]["inputPolicy"] = json!("accept");
        let compiled = serde_json::from_value::<Candidate>(value)
            .unwrap()
            .compile()
            .unwrap();
        let rows = compiled.expected["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|rule| rule["chain"] == "output")
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[1]["expr"].as_array().unwrap().last().unwrap(),
            &json!({"drop":null})
        );
        assert_eq!(
            rows[2]["expr"].as_array().unwrap().last().unwrap(),
            &json!({"accept":null})
        );
    }
    #[test]
    fn v4_requires_explicit_output_policy_and_rejects_cross_version_markers_and_extra_fields() {
        let base = serde_json::to_value(candidate(false)).unwrap();
        for defect in [
            "missing-output",
            "unknown-family-field",
            "unknown-rule",
            "wrong-version",
        ] {
            let mut value = base.clone();
            match defect {
                "missing-output" => {
                    value["ipv4"]
                        .as_object_mut()
                        .unwrap()
                        .remove("outputPolicy");
                }
                "unknown-family-field" => value["ipv6"]["allowEverything"] = json!(true),
                "unknown-rule" => value["extra"] = json!("flush ruleset"),
                "wrong-version" => value["schemaVersion"] = json!(3),
                _ => unreachable!(),
            }
            assert!(
                serde_json::from_value::<Candidate>(value)
                    .and_then(|c| c.compile().map(|_| ()).map_err(serde::de::Error::custom))
                    .is_err(),
                "{defect}"
            );
        }
        let compiled = candidate(false).compile().unwrap();
        assert_eq!(
            super::super::super::expected_table(&compiled.text).unwrap(),
            compiled.expected
        );
        assert!(
            super::super::super::expected_table(
                &compiled.text.replace(MARKER, super::super::MARKER)
            )
            .is_err()
        );
        assert!(super::super::super::expected_table(&(compiled.text + "flush ruleset\n")).is_err());
    }
    #[test]
    fn v4_uses_the_existing_complete_bounded_static_rule_compiler_and_retains_explicit_no_masquerade()
     {
        let mut value = serde_json::to_value(candidate(false)).unwrap();
        value["input"] = json!([{"family":"ipv4","protocol":"tcp","ports":{"first":22,"last":22},"inputInterface":"eth+"}]);
        value["nat"] = json!([{"family":"ipv6","inputInterface":"lan0","outputInterface":"wan0","protocol":null,"masquerade":false,"automatic":false,"ruleType":"IP_FORWARDING"}]);
        let compiled = serde_json::from_value::<Candidate>(value.clone())
            .unwrap()
            .compile()
            .unwrap();
        assert!(compiled.text.contains("tcp dport 22"));
        assert!(
            compiled.expected["rules"]
                .as_array()
                .unwrap()
                .iter()
                .all(|rule| rule["expr"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|term| term.get("masquerade").is_none()))
        );
        value["input"][0]["inputInterface"] = json!("eth0\"; flush ruleset");
        assert!(
            serde_json::from_value::<Candidate>(value)
                .unwrap()
                .compile()
                .is_err()
        );
    }

    #[test]
    fn actual_nft_1_0_9_readback_keeps_legacy_types_codes_sources_and_rejects_semantic_drift() {
        let fixtures: Value = serde_json::from_str(include_str!("actual-nft-v28.json")).unwrap();
        for fixture in fixtures.as_array().unwrap() {
            let compiled = compile(fixture["candidate"].clone()).unwrap();
            let raw = fixture["actualOwned"].as_array().unwrap();
            assert_eq!(semantic_table(raw).unwrap(), compiled.expected);
            for field in ["type", "code", "saddr"] {
                let mut wrong = raw.clone();
                let matched = wrong
                    .iter_mut()
                    .filter_map(|entry| {
                        entry
                            .get_mut("rule")
                            .and_then(|rule| rule.get_mut("expr"))
                            .and_then(Value::as_array_mut)
                    })
                    .flat_map(|expr| expr.iter_mut())
                    .find(|term| term["match"]["left"]["payload"]["field"] == field);
                if let Some(matched) = matched {
                    matched["match"]["right"] = if field == "saddr" {
                        json!({"prefix":{"addr":"fe80::","len":11}})
                    } else {
                        json!(255)
                    };
                    assert_ne!(
                        semantic_table(&wrong).unwrap(),
                        compiled.expected,
                        "{field} drift disappeared"
                    );
                }
            }
            let mut wrong = raw.clone();
            let rule = wrong
                .iter_mut()
                .find(|entry| entry["rule"]["comment"] == "yofc legacy ICMP")
                .unwrap();
            rule["rule"]["expr"]
                .as_array_mut()
                .unwrap()
                .push(json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":17}}));
            assert_ne!(
                semantic_table(&wrong).unwrap(),
                compiled.expected,
                "conflicting transport predicate disappeared"
            );
            let mut wrong = raw.clone();
            let rule = wrong
                .iter_mut()
                .find(|entry| entry["rule"]["comment"] == "yofc legacy ICMP")
                .unwrap();
            let term = rule["rule"]["expr"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|term| term["match"]["left"]["payload"]["field"] == "type")
                .unwrap();
            term["match"]["right"] = json!("unknown-type-not-a-reviewed-alias");
            assert_ne!(
                semantic_table(&wrong).unwrap(),
                compiled.expected,
                "unknown enum disappeared"
            );
        }
    }
}
