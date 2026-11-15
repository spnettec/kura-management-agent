//! Recording Java adapter fixture; actual decoding/AEAD is tested in SnapshotTool.
use super::*;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

#[test]
fn core_validator_has_no_local_key_or_java_and_does_not_depend_on_running_core_at_startup() {
    let root = std::env::temp_dir().join(format!("core-validator-{}", uuid::Uuid::new_v4()));
    durable::directory(&root).unwrap();
    let path = root.join("validator.json");
    let config =
        json!({"schema":2,"mode":"plain","passwordPolicy":"authenticated","key":{"kind":"core"}});
    durable::json(&path, &config).unwrap();
    assert!(Validator::new(path.clone()).is_ok());
    for patch in [
        json!({"schema":1}),
        json!({"java":"/usr/bin/java"}),
        json!({"jar":"/tool.jar"}),
        json!({"key":{"kind":"file","path":"/key"}}),
        json!({"key":{"kind":"default"}}),
    ] {
        let mut invalid = config.clone();
        for (key, value) in patch.as_object().unwrap() {
            invalid[key] = value.clone();
        }
        durable::json(&path, &invalid).unwrap();
        assert!(Validator::new(path.clone()).is_err());
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn logical_v1_requires_explicit_policy_and_cannot_forge_password_authentication() {
    let root = std::env::temp_dir().join(format!("logical-validator-{}", uuid::Uuid::new_v4()));
    durable::directory(&root).unwrap();
    fs::create_dir(root.join("lib")).unwrap();
    fs::write(root.join("validator.jar"), b"fixed fixture tool").unwrap();
    fs::write(root.join("lib/fixed.jar"), b"fixed fixture dependency").unwrap();
    let java = root.join("java");
    fs::write(
        &java,
        format!(
            "#!/usr/bin/python3\nimport pathlib\nprint(pathlib.Path({}).read_text(),end='')\n",
            serde_json::to_string(&root.join("report.json")).unwrap()
        ),
    )
    .unwrap();
    fs::set_permissions(&java, fs::Permissions::from_mode(0o700)).unwrap();
    let input = root.join("snapshot.xml");
    fs::write(&input, b"read-only adapter input").unwrap();
    let sha = durable::hash(b"read-only adapter input");
    let report = json!({"schema":1,"artifactSha256":sha,"mode":"plain","configurationCount":1,
        "factoryCount":0,"propertyCount":1,"passwordValueCount":1,"authenticatedPasswordCount":0,
        "legacyPasswordCount":0,"logicalPasswordCount":1,"passwordEncoding":"BASE64_LOGICAL_V1",
        "keyAuthenticated":false,"fullRecoveryVerified":false});
    let config = |policy: &str| {
        let path = root.join("validator.json");
        durable::json(
            &path,
            &json!({"schema":1,"java":java,"jar":root.join("validator.jar"),
            "mode":"plain","passwordPolicy":policy,"key":{"kind":"default"}}),
        )
        .unwrap();
        Validator::new(path).unwrap()
    };
    durable::json(&root.join("report.json"), &report).unwrap();
    assert!(config("logical-v1").validate(&input, &sha, None).is_ok());
    assert!(
        config("authenticated")
            .validate(&input, &sha, None)
            .is_err()
    );
    assert!(config("legacy").validate(&input, &sha, None).is_err());
    let validator = config("logical-v1");
    for patch in [
        json!({"keyAuthenticated":true}),
        json!({"passwordEncoding":"UNKNOWN_V2"}),
        json!({"logicalPasswordCount":0}),
        json!({"authenticatedPasswordCount":1,"logicalPasswordCount":0}),
        json!({"fullRecoveryVerified":true}),
    ] {
        let mut changed = report.clone();
        for (k, v) in patch.as_object().unwrap() {
            changed[k] = v.clone();
        }
        durable::json(&root.join("report.json"), &changed).unwrap();
        assert!(validator.validate(&input, &sha, None).is_err());
    }
    fs::remove_dir_all(root).unwrap();
}
