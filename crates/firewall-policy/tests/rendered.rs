use kura_firewall_policy::{
    compile_layout,
    netlink::{attribute, rule_attributes},
    parse_observed, parse_rendered,
    publication::{FamilyChange, RuleDump, plan_initial},
};
use serde_json::json;
use std::fmt::Write;

const MODEL: &str = "*filter\n:INPUT DROP [0:0]\n:input-kura - [0:0]\n\
-I INPUT -j input-kura\n-A input-kura -j RETURN\n\
-I input-kura -s fe80::/10 -p ipv6-icmp -m ipv6-icmp --icmpv6-type 148 -j ACCEPT\n\
-I input-kura -p ipv6-icmp -m ipv6-icmp --icmpv6-type 3/1 -j ACCEPT\n\
COMMIT\n*nat\nCOMMIT\n*mangle\nCOMMIT\n";

#[test]
fn renderer_insertions_keep_numeric_icmp_constraints_and_rule_order() {
    assert!(parse_observed(MODEL).is_err());
    let layout = parse_rendered(MODEL).unwrap();
    let tables = compile_layout("ip6", &layout).unwrap();
    let base = &tables[0].chains[0];
    assert_eq!(base.policy, Some("DROP"));
    assert_eq!(base.rules, [vec![json!({"jump":{"target":"input-kura"}})]]);
    let rules = &tables[0].chains[1].rules;
    assert_eq!(rules.len(), 3);
    assert!(rules[0].contains(&json!({"icmpHeader":{"protocol":"icmpv6","type":3,"codeFirst":1,"codeLast":1,"inverted":false}})));
    assert!(rules[1].contains(&json!({"icmpHeader":{"protocol":"icmpv6","type":148,"codeFirst":0,"codeLast":255,"inverted":false}})));
    assert!(
        rules[1]
            .iter()
            .any(|term| term["match"]["right"] == json!({"prefix":{"addr":"fe80::","len":10}}))
    );
    assert_eq!(rules[2], [json!({"return":null})]);
    for rule in &rules[..2] {
        let encoded = rule_attributes(&json!(rule), 10).unwrap();
        assert!(encoded.windows(6).any(|word| word == b"icmp6\0"));
        assert!(rule_attributes(&json!(rule), 2).is_err());
    }
}

#[test]
fn unsupported_final_row_refuses_the_complete_layout() {
    let text = MODEL.replace(
        "*mangle\nCOMMIT",
        "*mangle\n:input-kura - [0:0]\n-A input-kura --unsupported-match 1 -j RETURN\nCOMMIT",
    );
    let layout = parse_rendered(&text).unwrap();
    assert!(compile_layout("ip6", &layout).is_err());
}

fn initial_model() -> String {
    let mut model = String::new();
    for (table, chains, links) in [
        (
            "filter",
            "INPUT FORWARD OUTPUT",
            &[
                ("forward-kura", "forward-kura-pf"),
                ("forward-kura", "forward-kura-ipf"),
            ][..],
        ),
        (
            "nat",
            "INPUT OUTPUT PREROUTING POSTROUTING",
            &[
                ("prerouting-kura", "prerouting-kura-pf"),
                ("postrouting-kura", "postrouting-kura-pf"),
                ("postrouting-kura", "postrouting-kura-ipf"),
            ][..],
        ),
        (
            "mangle",
            "PREROUTING POSTROUTING INPUT OUTPUT FORWARD",
            &[][..],
        ),
    ] {
        writeln!(model, "*{table}").unwrap();
        for chain in chains.split_whitespace() {
            let policy = if table == "filter" && chain != "OUTPUT" {
                "DROP"
            } else {
                "ACCEPT"
            };
            writeln!(model, ":{chain} {policy} [0:0]").unwrap();
        }
        for chain in chains.to_ascii_lowercase().split_whitespace() {
            writeln!(model, ":{chain}-kura - [0:0]").unwrap();
        }
        for (_, target) in links {
            writeln!(model, ":{target} - [0:0]").unwrap();
        }
        for chain in chains.split_whitespace() {
            writeln!(model, "-I {chain} -j {}-kura", chain.to_ascii_lowercase()).unwrap();
        }
        for (chain, target) in links {
            writeln!(model, "-I {chain} -j {target}").unwrap();
        }
        writeln!(model, "COMMIT").unwrap();
    }
    model
}

fn row(family: u8, table: &str, chain: &str, handle: u64, terms: serde_json::Value) -> Vec<u8> {
    [
        vec![family, 0, 0, 0],
        attribute(1, format!("{table}\0").as_bytes()),
        attribute(2, format!("{chain}\0").as_bytes()),
        attribute(3, &handle.to_be_bytes()),
        rule_attributes(&terms, family).unwrap(),
    ]
    .concat()
}

#[test]
fn initial_plan_preserves_base_site_rules_and_refuses_unowned_managed_bodies() {
    let scaffold = initial_model();
    let layout = parse_rendered(&scaffold).unwrap();
    for (family, native, code) in [("ipv4", "ip", 2), ("ipv6", "ip6", 10)] {
        let mut dump = RuleDump::new();
        for table in compile_layout(native, &layout).unwrap() {
            for chain in table.chains {
                let rows = chain
                    .rules
                    .into_iter()
                    .zip(1..)
                    .map(|(terms, handle)| row(code, table.name, chain.name, handle, json!(terms)))
                    .collect::<Vec<_>>();
                dump.insert((code, table.name.into(), chain.name.into()), rows);
            }
        }
        let base = (code, "filter".into(), "INPUT".into());
        dump.get_mut(&base)
            .unwrap()
            .push(row(code, "filter", "INPUT", 99, json!([{"drop":null}])));
        let change = FamilyChange {
            family: family.into(),
            previous: String::new(),
            candidate: scaffold.replacen(
                "COMMIT",
                "-A input-kura -p udp --dport 49360 -j ACCEPT\nCOMMIT",
                1,
            ),
        };
        assert_eq!(plan_initial(11, &change, &dump).unwrap().commands, 1);

        let managed = (code, "mangle".into(), "output-kura".into());
        dump.get_mut(&managed).unwrap().push(row(
            code,
            "mangle",
            "output-kura",
            99,
            json!([{"return":null}]),
        ));
        let err = plan_initial(11, &change, &dump).err().unwrap().to_string();
        assert!(err.contains("initial managed chain is not empty ("));
        dump.get_mut(&managed).unwrap().clear();

        dump.get_mut(&base).unwrap().remove(0);
        assert!(plan_initial(11, &change, &dump).is_err());
    }
}
