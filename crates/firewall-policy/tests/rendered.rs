use kura_firewall_policy::{
    compile_layout, netlink::rule_attributes, parse_observed, parse_rendered,
};
use serde_json::json;

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
