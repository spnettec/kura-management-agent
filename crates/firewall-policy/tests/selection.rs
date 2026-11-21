use kura_firewall_policy::{
    netlink::{attribute, rule_attributes},
    witness::{RuleMatch, match_chain, unique_selection},
};
use serde_json::{Value, json};

fn raw_rule(chain: &str, handle: u64, terms: &[Value]) -> Vec<u8> {
    let chain = [chain.as_bytes(), &[0]].concat();
    [
        vec![2, 0, 0, 0],
        attribute(1, b"filter\0"),
        attribute(2, &chain),
        attribute(3, &handle.to_be_bytes()),
        rule_attributes(&json!(terms), 2).unwrap(),
    ]
    .concat()
}

#[test]
fn selection_binds_kernel_family_chain_position_and_handle() {
    let rules = vec![vec![json!({"accept":null})], vec![json!({"return":null})]];
    let first = raw_rule("INPUT", 61, &rules[0]);
    let second = raw_rule("INPUT", 2, &rules[1]);
    let foreign = raw_rule("INPUT", 987, &[json!({"drop":null})]);
    let select = |raw: &[Vec<u8>]| match_chain(2, "filter", "INPUT", &rules, raw);
    assert_eq!(
        select(&[first.clone(), foreign, second.clone()])
            .unwrap()
            .rules,
        vec![
            RuleMatch {
                ordinal: 0,
                handle: 61
            },
            RuleMatch {
                ordinal: 2,
                handle: 2
            }
        ]
    );
    assert!(select(&[first.clone(), raw_rule("other", 2, &rules[1])]).is_err());
    let mut wrong_family = second.clone();
    wrong_family[0] = 10;
    assert!(select(&[first.clone(), wrong_family]).is_err());
    assert!(select(&[first.clone(), raw_rule("INPUT", 61, &rules[1])]).is_err());
    assert!(select(&[first.clone(), raw_rule("INPUT", 0, &rules[1])]).is_err());
    assert!(
        select(&[
            first.clone(),
            raw_rule("INPUT", 31, &rules[0]),
            second.clone()
        ])
        .is_err()
    );
    assert!(select(&[second, first]).is_err());
}

#[test]
fn rule_with_site_metadata_cannot_be_adopted_as_an_original_rule() {
    let model = vec![vec![json!({"accept": null})]];
    let plain = raw_rule("INPUT", 14, &model[0]);
    let mut tagged = raw_rule("INPUT", 27, &model[0]);
    tagged.extend(attribute(7, b"site metadata"));
    let select = |raw: &[Vec<u8>]| match_chain(2, "filter", "INPUT", &model, raw);
    let error = select(std::slice::from_ref(&tagged)).unwrap_err();
    assert!(error.to_string().contains("userdata"));
    let error = select(&[plain, tagged]).unwrap_err();
    assert!(error.to_string().contains("ambiguous"));
}

#[test]
fn conflict_identifies_the_model_ordinal_without_logging_rule_contents() {
    let actual = [Some(10), Some(20), Some(30), Some(60)];
    let missing = unique_selection(&[10, 20, 30, 40, 50, 60], &actual).unwrap_err();
    assert_eq!(
        missing.to_string(),
        "CONFLICT: managed rule 4 missing or out of order"
    );
    let ambiguous = unique_selection(&[10, 20], &[Some(10), Some(20), Some(20)]).unwrap_err();
    assert_eq!(
        ambiguous.to_string(),
        "CONFLICT: managed rule 2 has ambiguous ownership"
    );
}

#[test]
fn ordered_matching_agrees_with_every_small_subsequence_including_opaque_rows() {
    // Enumerate possible embeddings independently, including equal managed rows.
    for length in 0..=5 {
        for mut pattern in 0..3_usize.pow(length) {
            let actual: Vec<_> = (0..length)
                .map(|_| {
                    let value = [None, Some(0), Some(1)][pattern % 3];
                    pattern /= 3;
                    value
                })
                .collect();
            for wanted in [
                vec![],
                vec![0],
                vec![1],
                vec![0, 1],
                vec![1, 0],
                vec![1, 1],
                vec![0, 0, 1],
            ] {
                let mut solutions = Vec::new();
                for subset in 0..(1_usize << length) {
                    let index: Vec<_> = (0..actual.len())
                        .filter(|i| subset & (1 << i) != 0)
                        .collect();
                    if index
                        .iter()
                        .map(|&i| actual[i])
                        .eq(wanted.iter().copied().map(Some))
                    {
                        solutions.push(index);
                    }
                }
                let found = unique_selection(&wanted, &actual);
                if solutions.len() == 1 {
                    assert_eq!(found.unwrap(), solutions[0]);
                } else {
                    assert!(found.is_err());
                }
            }
        }
    }
}
