use super::*;

#[tokio::test]
async fn renewal_requires_enrollment_and_channel_grants_and_rejects_extra_fields() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("renewal-roles-{}", Uuid::new_v4()));
    crate::durable::directory(&root).unwrap();
    let grant = root.join("kura");
    crate::durable::directory(&grant).unwrap();
    let db = crate::transport::database(root.join("db").to_str().unwrap())
        .await
        .unwrap();
    let mut local = Local::new(1000, 0);
    local.remote = Some(crate::remote::Remote::open(root.clone(), false, None).unwrap());
    local.enrollment = Some(
        crate::enrollment::Enrollment::open(
            root.clone(),
            None,
            Some(grant.clone()),
            1000,
            db.clone(),
            "boot".into(),
        )
        .unwrap(),
    );
    let mut frame = LocalFrame {
        version: 1,
        kind: "request".into(),
        request_id: Uuid::new_v4().to_string(),
        method: "remote.renewal-status".into(),
        params: Some(json!({})),
        result: None,
        error: None,
    };
    assert_eq!(
        local.local_request(&frame, 1000, true).await.unwrap_err(),
        "FORBIDDEN"
    );
    assert_eq!(
        local.local_request(&frame, 1000, false).await.unwrap_err(),
        "FORBIDDEN"
    );
    assert_eq!(
        local.local_request(&frame, 0, false).await.unwrap()["canRenew"],
        false
    );
    local.kura_remote_management = true;
    assert_eq!(
        local.local_request(&frame, 1000, true).await.unwrap()["canRenew"],
        false
    );
    let operation = Uuid::new_v4().to_string();
    frame.params = Some(json!({"operationId":operation}));
    assert_eq!(
        local.local_request(&frame, 1000, true).await.unwrap(),
        json!({"operationId":operation,"state":"UNKNOWN"})
    );
    frame.params = Some(json!({"operationId":operation,"enabled":true}));
    assert_eq!(
        local.local_request(&frame, 1000, true).await.unwrap_err(),
        "INVALID_ARGUMENT"
    );
    frame.params = Some(json!({"operationId":"../private"}));
    assert_eq!(
        local.local_request(&frame, 1000, true).await.unwrap_err(),
        "INVALID_ARGUMENT"
    );
    frame.method = "remote.renew-identity".into();
    frame.params = Some(json!({}));
    assert_eq!(
        local.local_request(&frame, 1000, true).await.unwrap_err(),
        "INVALID_ARGUMENT"
    );
    local.enrollment = Some(
        crate::enrollment::Enrollment::open(root.clone(), None, None, 1000, db, "boot".into())
            .unwrap(),
    );
    assert_eq!(
        local.local_request(&frame, 1000, true).await.unwrap_err(),
        "FORBIDDEN"
    );
    assert_eq!(
        local.local_request(&frame, 0, false).await.unwrap_err(),
        "FORBIDDEN"
    );
    frame.method = "remote.renewal-status".into();
    frame.params = Some(json!({"operationId":operation}));
    assert_eq!(
        local.local_request(&frame, 0, false).await.unwrap()["state"],
        "UNKNOWN"
    );
    assert_eq!(
        local.local_request(&frame, 1000, true).await.unwrap()["state"],
        "UNKNOWN"
    );
    assert_eq!(
        local.local_request(&frame, 1000, false).await.unwrap_err(),
        "FORBIDDEN"
    );
    assert!(!root.join("enrollment/renewals").exists());
}
