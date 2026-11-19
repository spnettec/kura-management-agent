use super::*;
use std::{collections::VecDeque, sync::Mutex};

struct Fake {
    replies: Mutex<VecDeque<Value>>,
    calls: Mutex<Vec<Vec<String>>>,
}
impl Wire for Fake {
    fn call(&self, call: &BusCall, _: Instant) -> Result<Value> {
        self.calls.lock().unwrap().push(vec![
            call.destination.clone(),
            call.path.clone(),
            call.interface.clone(),
            call.method.clone(),
        ]);
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .context("UNSUPPORTED: NM source unavailable")
    }
}
fn reply(signature: &str, data: Value) -> Value {
    json!({"type":signature,"data":data})
}
fn value(signature: &str, data: Value) -> Value {
    json!({"type":signature,"data":data})
}
fn identity() -> Vec<Value> {
    vec![
        reply("s", json!(["a".repeat(32)])),
        reply("s", json!([":1.7"])),
    ]
}
fn settings() -> Value {
    json!({"connection":{"uuid":value("s",json!("12345678-1234-4123-8123-123456789abc")),
        "type":value("s",json!("802-3-ethernet")),
        "id":value("s",json!("never-publish-profile-label"))},"ipv4":{"method":value("s",json!("auto"))}})
}
fn device(active: bool) -> Vec<Value> {
    let mut rows = vec![
        reply("o", json!([format!("{ROOT}/Devices/4")])),
        reply(
            "a{sv}",
            json!([{
        "Interface":value("s",json!("eth0")),"Managed":value("b",json!(true)),
        "DeviceType":value("u",json!(1)),"State":value("u",json!(if active{100}else{30})),
        "ActiveConnection":value("o",json!(if active{format!("{ROOT}/ActiveConnection/2")}else{"/".into()}))}]),
        ),
    ];
    if active {
        rows.extend([
            reply("a{sa{sv}}t", json!([settings(), 1])),
            reply(
                "v",
                json!([value("o", json!(format!("{ROOT}/Settings/3")))]),
            ),
            reply("a{sa{sv}}", json!([settings()])),
            reply(
                "a{sv}",
                json!([{"Flags":value("u",json!(0)),"Unsaved":value("b",json!(false)),"VersionId":value("t",json!(7))}]),
            ),
        ]);
    }
    rows
}
fn replies(active: bool) -> Vec<Value> {
    let mut rows = identity();
    rows.push(reply("v", json!([value("s", json!("1.46.0"))])));
    rows.extend(device(active));
    rows.extend(device(active));
    rows.extend(identity());
    rows
}
fn fixture(rows: Vec<Value>) -> (Nm, Arc<Fake>) {
    let wire = Arc::new(Fake {
        replies: Mutex::new(rows.into()),
        calls: Default::default(),
    });
    (
        Nm {
            config: Config {
                schema_version: 1,
                interfaces: vec!["eth0".into()],
                bus_address: None,
                write_enabled: false,
            },
            wire: wire.clone(),
            engine: None,
            ownership_observer: None,
            observation_root: None,
        },
        wire,
    )
}
fn read(nm: &Nm) -> Result<Value> {
    nm.snapshot(Instant::now() + Duration::from_secs(5))
}

#[test]
fn source_binds_bus_owner_applied_version_and_profile_without_values_or_write_grant() {
    let (nm, wire) = fixture(replies(true));
    let view = read(&nm).unwrap();
    assert_eq!(view["backend"], "NetworkManager");
    assert_eq!(view["writeEnabled"], false);
    let p = &view["source"]["devices"][0]["activeProfile"];
    assert_eq!(p["appliedVersion"], 1);
    assert_eq!(p["wiredShape"], true);
    assert_eq!(p["requiresAdoption"], true);
    assert_eq!(p["settingsSha256"], digest(&settings()).unwrap());
    assert!(!view.to_string().contains("never-publish-profile-label"));
    for args in wire.calls.lock().unwrap().iter() {
        assert!(
            [
                "GetId",
                "GetNameOwner",
                "Get",
                "GetAll",
                "GetDeviceByIpIface",
                "GetAppliedConnection",
                "GetSettings"
            ]
            .contains(&args[3].as_str())
        );
        assert!(args[0] == DBUS || args[0] == ":1.7");
    }
}
#[test]
fn no_active_profile_is_explicit_absence_and_never_an_editable_empty_profile() {
    let (nm, _) = fixture(replies(false));
    let view = read(&nm).unwrap();
    assert!(view["source"]["devices"][0]["activeProfile"].is_null());
    assert_eq!(view["writeEnabled"], false);
}
#[test]
fn bus_or_nm_owner_change_invalidates_the_complete_observation() {
    for bus in [false, true] {
        let mut rows = replies(false);
        let n = rows.len();
        if bus {
            rows[n - 2]["data"][0] = json!("b".repeat(32));
        } else {
            rows[n - 1]["data"][0] = json!(":1.8");
        }
        let (nm, _) = fixture(rows);
        assert!(read(&nm).unwrap_err().to_string().contains("owner changed"));
    }
}
#[test]
fn recheck_catches_applied_version_profile_and_active_connection_changes() {
    for change in ["version", "profile", "active"] {
        let mut rows = replies(true);
        match change {
            "version" => rows[11]["data"][1] = json!(2),
            "profile" => rows[13]["data"][0]["connection"]["id"]["data"] = json!("changed-label"),
            _ => {
                rows[10]["data"][0]["ActiveConnection"]["data"] =
                    json!(format!("{ROOT}/ActiveConnection/5"))
            }
        }
        let (nm, _) = fixture(rows);
        assert!(read(&nm).is_err(), "{change}");
    }
}
#[test]
fn path_interface_and_reply_type_are_checked_before_following_object_references() {
    let mut rows = replies(false);
    rows[3]["data"][0] = json!(format!("{ROOT}/Settings/4"));
    let (nm, wire) = fixture(rows);
    assert!(read(&nm).is_err());
    assert_eq!(wire.calls.lock().unwrap().len(), 4);
    let mut rows = replies(false);
    rows[4]["data"][0]["Interface"]["data"] = json!("eth1");
    assert!(read(&fixture(rows).0).is_err());
    let mut rows = replies(false);
    rows[4]["data"][0]["Managed"]["type"] = json!("s");
    assert!(read(&fixture(rows).0).is_err());
}
#[test]
fn active_profile_identity_mismatch_and_zero_applied_lease_are_rejected() {
    let mut rows = replies(true);
    rows[7]["data"][0]["connection"]["uuid"]["data"] =
        json!("22345678-1234-4123-8123-123456789abc");
    assert!(read(&fixture(rows).0).is_err());
    let mut rows = replies(true);
    rows[5]["data"][1] = json!(0);
    assert!(read(&fixture(rows).0).is_err());
}
#[test]
fn unknown_sensitive_profile_groups_are_unprojectable_and_never_returned() {
    let mut rows = replies(true);
    for index in [7, 13] {
        rows[index]["data"][0]["802-1x"] =
            json!({"password":value("s",json!("private-provider-value"))});
    }
    let view = read(&fixture(rows).0).unwrap();
    assert_eq!(
        view["source"]["devices"][0]["activeProfile"]["wiredShape"],
        false
    );
    assert!(!view.to_string().contains("private-provider-value"));
}
#[test]
fn absent_nm_and_expired_overall_deadline_do_not_fall_back_or_issue_other_calls() {
    let (nm, wire) = fixture(vec![]);
    assert!(
        read(&nm)
            .unwrap_err()
            .to_string()
            .starts_with("UNSUPPORTED")
    );
    assert_eq!(wire.calls.lock().unwrap().len(), 1);
    let (nm, wire) = fixture(replies(false));
    assert!(
        nm.snapshot(Instant::now() - Duration::from_secs(1))
            .unwrap_err()
            .to_string()
            .starts_with("TIMEOUT")
    );
    assert!(wire.calls.lock().unwrap().is_empty());
}
#[test]
fn config_is_bounded_explicit_and_cannot_inject_addresses_programs_or_interfaces() {
    for raw in [
        json!({"schemaVersion":1,"interfaces":[]}),
        json!({"schemaVersion":1,"interfaces":["eth0","eth0"]}),
        json!({"schemaVersion":1,"interfaces":["eth+"]}),
        json!({"schemaVersion":1,"interfaces":["eth0;id"]}),
        json!({"schemaVersion":1,"interfaces":["eth0"],"busAddress":"tcp:host=remote"}),
        json!({"schemaVersion":1,"interfaces":["eth0"],"busAddress":"unix:path=/run/bus,guid=other"}),
    ] {
        assert!(
            serde_json::from_value::<Config>(raw)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    assert!(
        serde_json::from_value::<Config>(
            json!({"schemaVersion":1,"interfaces":["eth0"],"program":"/bin/sh"})
        )
        .is_err()
    );
    let mut c:Config=serde_json::from_value(json!({"schemaVersion":1,"interfaces":["eth0"],"busAddress":"unix:path=/opt/owned/bus.sock"})).unwrap();
    assert!(c.validate().is_ok());
    c.interfaces = (0..17).map(|i| format!("eth{i}")).collect();
    assert!(c.validate().is_err());
}
#[test]
fn private_config_rejects_public_files_and_symlinks() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("nm-source-{}", uuid::Uuid::new_v4()));
    crate::durable::directory(&root).unwrap();
    let path = root.join("config.json");
    crate::durable::json(&path, &json!({"schemaVersion":1,"interfaces":["eth0"]})).unwrap();
    assert!(Nm::open(&path, None).is_ok());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Nm::open(&path, None).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(Nm::open(&link, None).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn applied_only_unknown_groups_cannot_report_a_supported_wired_shape() {
    let mut rows = replies(true);
    for index in [5, 11] {
        rows[index]["data"][0]["802-1x"] =
            json!({"password":value("s",json!("applied-private-value"))});
    }
    let view = read(&fixture(rows).0).unwrap();
    assert_eq!(
        view["source"]["devices"][0]["activeProfile"]["wiredShape"],
        false
    );
    assert_eq!(view["writeEnabled"], false);
    assert!(!view.to_string().contains("applied-private-value"));
}

fn preview_input(source: &Value) -> Value {
    json!({"sourceDigest":source["sourceDigest"],"changes":[{"interface":"eth0",
        "ipv4":{"method":"manual","addresses":[{"address":"192.0.2.10","prefix":24}],
        "gateway":"192.0.2.1","dns":["192.0.2.53"],"ignoreAutoDns":true,"ignoreAutoRoutes":false,"wanPriority":30},
        "ethernet":{"mtu":1500,"acceptAllMacAddresses":-1}}]})
}
#[test]
fn candidate_is_source_bound_read_only_and_never_publishes_raw_settings() {
    let (nm, wire) = fixture(replies(true));
    let (source, devices) = nm.capture(Instant::now() + Duration::from_secs(5)).unwrap();
    let result = preview::Preview::parse(preview_input(&source))
        .unwrap()
        .compile(&source, &devices)
        .unwrap();
    assert_eq!(result["writeEnabled"], false);
    assert_eq!(result["prepared"], false);
    assert_eq!(result["requiresAdoption"], true);
    assert!(!result.to_string().contains("never-publish-profile-label"));
    assert!(!source.to_string().contains("never-publish-profile-label"));
    assert_ne!(
        result["proposal"]["candidates"][0]["settingsSha256"],
        source["source"]["devices"][0]["activeProfile"]["settingsSha256"]
    );
    assert_eq!(
        devices[0].active_profile.as_ref().unwrap().settings,
        settings()
    );
    assert!(wire.calls.lock().unwrap().iter().all(|args| {
        ![
            "Update2",
            "Reapply",
            "CheckpointCreate",
            "ActivateConnection",
        ]
        .contains(&args[3].as_str())
    }));
    let mut stale = preview_input(&source);
    stale["sourceDigest"] = json!("0".repeat(64));
    assert!(
        preview::Preview::parse(stale)
            .unwrap()
            .compile(&source, &devices)
            .unwrap_err()
            .to_string()
            .starts_with("CONFLICT")
    );
}
#[tokio::test]
async fn preview_entry_rechecks_actual_source_before_compiling() {
    let source = read(&fixture(replies(true)).0).unwrap();
    let result = fixture(replies(true))
        .0
        .preview(preview_input(&source))
        .await
        .unwrap();
    assert_eq!(result["proposal"]["sourceDigest"], source["sourceDigest"]);
    let mut changed = replies(true);
    // Content changes are detected; NM-managed version counters are not part
    // of the source binding anymore.
    changed[7]["data"][0]["ipv4"]["method"]["data"] = json!("manual");
    changed[13]["data"][0]["ipv4"]["method"]["data"] = json!("manual");
    assert!(
        fixture(changed)
            .0
            .preview(preview_input(&source))
            .await
            .unwrap_err()
            .to_string()
            .starts_with("CONFLICT")
    );
}
#[test]
fn candidate_rejects_unconfigured_inactive_unmanaged_and_unsupported_sources() {
    for kind in [
        "interface",
        "inactive",
        "unmanaged",
        "group",
        "unsaved",
        "flags",
        "version",
    ] {
        let mut rows = replies(kind != "inactive");
        if kind == "unmanaged" {
            for i in [4, 10] {
                rows[i]["data"][0]["Managed"]["data"] = json!(false);
            }
        }
        if kind == "group" {
            for i in [7, 13] {
                rows[i]["data"][0]["802-1x"] = json!({});
            }
        }
        if kind == "unsaved" {
            for i in [8, 14] {
                rows[i]["data"][0]["Unsaved"]["data"] = json!(true);
            }
        }
        if kind == "flags" {
            for i in [8, 14] {
                rows[i]["data"][0]["Flags"]["data"] = json!(1);
            }
        }
        if kind == "version" {
            rows[2]["data"][0]["data"] = json!("1.32.0");
        }
        let (source, devices) = fixture(rows)
            .0
            .capture(Instant::now() + Duration::from_secs(5))
            .unwrap();
        let mut input = preview_input(&source);
        if kind == "interface" {
            input["changes"][0]["interface"] = json!("eth1");
        }
        assert!(
            preview::Preview::parse(input)
                .unwrap()
                .compile(&source, &devices)
                .is_err(),
            "{kind}"
        );
    }
}
#[test]
fn preview_rejects_unknown_fields_empty_duplicate_and_unbound_inputs() {
    let source = read(&fixture(replies(true)).0).unwrap();
    let mut input = preview_input(&source);
    input["program"] = json!("/tmp/override");
    assert!(preview::Preview::parse(input).is_err());
    let mut input = preview_input(&source);
    input["changes"][0]["automaticNat"] = json!(true);
    assert!(preview::Preview::parse(input).is_err());
    let mut input = preview_input(&source);
    input["changes"] = json!([]);
    assert!(preview::Preview::parse(input).is_err());
    let mut input = preview_input(&source);
    let c = input["changes"][0].clone();
    input["changes"].as_array_mut().unwrap().push(c);
    assert!(preview::Preview::parse(input).is_err());
    let mut input = preview_input(&source);
    input["sourceDigest"] = json!("not-a-lease");
    assert!(preview::Preview::parse(input).is_err());
}

#[test]
fn preview_mtu_respects_existing_ipv6_even_when_family_is_not_in_the_patch() {
    for mode in ["missing", "auto", "disabled"] {
        let mut rows = replies(true);
        if mode != "missing" {
            for i in [5, 7, 11, 13] {
                rows[i]["data"][0]["ipv6"] = json!({"method":{"type":"s","data":mode}});
            }
        }
        let (source, devices) = fixture(rows)
            .0
            .capture(Instant::now() + Duration::from_secs(5))
            .unwrap();
        let input = json!({"sourceDigest":source["sourceDigest"],"changes":[{"interface":"eth0","ethernet":{"mtu":600,"acceptAllMacAddresses":0}}]});
        let result = preview::Preview::parse(input)
            .unwrap()
            .compile(&source, &devices);
        assert_eq!(result.is_ok(), mode == "disabled", "{mode}");
    }
}

#[tokio::test]
async fn readonly_remote_contract_view_does_not_require_a_write_engine() {
    use yofc_management_protocol::v1::ReadCommand;
    let (nm,wire)=fixture(replies(true));
    let command=ReadCommand{command_id:uuid::Uuid::new_v4().to_string(),operation:34,..Default::default()};
    let view=nm.remote_request(&command,&"a".repeat(64),"authenticated-read-session",true).await.unwrap();
    assert_eq!(view["writeEnabled"],false);assert_eq!(view["confirmationReady"],false);
    assert_eq!(view["candidateDigest"],Value::Null);assert_eq!(view["transaction"],Value::Null);
    assert_eq!(view["sourceDigest"].as_str().unwrap().len(),64);
    assert!(!view.to_string().contains("never-publish-profile-label"));
    assert!(wire.calls.lock().unwrap().iter().all(|c|["GetId","GetNameOwner","Get","GetAll","GetDeviceByIpIface","GetAppliedConnection","GetSettings"].contains(&c[3].as_str())));
    assert!(nm.prepare(json!({})).await.is_err());
}

#[tokio::test]
async fn readonly_remote_contract_rejects_ungranted_malformed_and_write_commands_before_bus() {
    use yofc_management_protocol::v1::ReadCommand;
    let (nm,wire)=fixture(vec![]);
    let mut command=ReadCommand{command_id:uuid::Uuid::new_v4().to_string(),operation:34,..Default::default()};
    assert!(nm.remote_request(&command,&"a".repeat(64),"session",false).await.is_err());
    assert!(nm.remote_request(&command,"bad","session",true).await.is_err());
    command.command_id="wrong".into();assert!(nm.remote_request(&command,&"a".repeat(64),"session",true).await.is_err());
    for operation in [35,36,37] {command.operation=operation;assert!(nm.remote_request(&command,&"a".repeat(64),"session",true).await.is_err());}
    assert!(wire.calls.lock().unwrap().is_empty());
}
