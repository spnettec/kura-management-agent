//! Explicit Root connection configuration. Identity receipts remain immutable.
use super::*;

const CONFIG: &str = "/etc/kura-management-runtime/transport-endpoint.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TransportEndpoint {
    schema_version: u32,
    profile: String,
    request_id: String,
    initialization_id: String,
    peer_authorization_id: String,
    peer_authorization_result_sha256: String,
    native_uid: u32,
    control_gid: u32,
    gateway_id: String,
    original_endpoint: String,
    endpoint: String,
    identity_receipt_sha256: String,
    minimum_binding_generation: u64,
    unit_started: bool,
    remote_enabled: bool,
}

fn endpoint_host(value: &str) -> Result<String> {
    ensure!(
        value.len() <= 512
            && value.is_ascii()
            && !value.trim_end_matches('/').ends_with(':')
            && !value.bytes().any(|b| b.is_ascii_whitespace()),
        "INVALID_ARGUMENT: transport HTTPS endpoint"
    );
    let parsed = tonic::transport::Endpoint::from_shared(value.to_owned())?;
    let uri = parsed.uri();
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT: transport authority"))?;
    // http::Uri may report no parsed port for an out-of-range numeric port.
    // Validate the explicit authority text instead of interpreting None as 443.
    let text = authority.as_str();
    let explicit_port = if text.starts_with('[') {
        let end = text
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT: IPv6 authority"))?;
        let tail = &text[end + 1..];
        if tail.is_empty() {
            None
        } else {
            Some(
                tail.strip_prefix(':')
                    .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT: transport port"))?,
            )
        }
    } else {
        text.rsplit_once(':').map(|(_, port)| port)
    };
    if let Some(port) = explicit_port {
        ensure!(
            !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|n| n > 0),
            "INVALID_ARGUMENT: transport port"
        );
    }
    ensure!(
        uri.scheme_str() == Some("https")
            && matches!(uri.path(), "" | "/")
            && uri.query().is_none()
            && !authority.as_str().contains('@'),
        "INVALID_ARGUMENT: fixed HTTPS host and port required"
    );
    Ok(uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT: transport host"))?
        .to_ascii_lowercase())
}

impl TransportEndpoint {
    fn select(
        &self,
        identity: &Identity,
        peer: &KuraPeer,
        original: &str,
        gateway: &str,
        generation: u64,
        receipt: &[u8],
    ) -> Result<String> {
        ensure!(
            self.schema_version == 1
                && self.profile == "native-transport-endpoint-v1"
                && self.initialization_id == peer.initialization_id
                && self.peer_authorization_id == peer.request_id
                && self.native_uid == identity.uid
                && self.control_gid == identity.gid
                && self.control_gid == peer.control_gid
                && self.native_uid > 0
                && self.control_gid > 0
                && self.native_uid != u32::MAX
                && self.control_gid != u32::MAX
                && self.gateway_id == gateway
                && self.minimum_binding_generation > 0
                && generation >= self.minimum_binding_generation
                && !self.unit_started
                && !self.remote_enabled,
            "FORBIDDEN: original Root transport configuration required"
        );
        for id in [
            &self.request_id,
            &self.initialization_id,
            &self.peer_authorization_id,
        ] {
            ensure!(
                uuid::Uuid::parse_str(id)?.to_string() == *id,
                "INVALID_ARGUMENT: original transport UUID"
            );
        }
        for digest in [
            &self.peer_authorization_result_sha256,
            &self.identity_receipt_sha256,
        ] {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "INVALID_ARGUMENT: original transport proof digest"
            );
        }
        ensure!(
            endpoint_host(&self.original_endpoint)? == endpoint_host(&self.endpoint)?
                && self.original_endpoint.trim_end_matches('/')
                    != self.endpoint.trim_end_matches('/')
                && [
                    self.original_endpoint.trim_end_matches('/'),
                    self.endpoint.trim_end_matches('/')
                ]
                .contains(&original.trim_end_matches('/')),
            "FORBIDDEN: configured transport must retain the original HTTPS host"
        );
        // Later, independently validated renewal generations may retain the same
        // gateway/center route; this never changes their identity or certificate.
        ensure!(
            generation != self.minimum_binding_generation
                || crate::durable::hash(receipt) == self.identity_receipt_sha256,
            "FORBIDDEN: original transport identity receipt changed"
        );
        Ok(self.endpoint.clone())
    }
}

pub(crate) fn enrolled_transport_endpoint(
    original: &str,
    gateway: &str,
    generation: u64,
    receipt: &[u8],
) -> Result<String> {
    let path = Path::new(CONFIG);
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(original.to_owned());
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let config: TransportEndpoint = serde_json::from_slice(&protected(path, 8192)?)?;
    let identity: Identity = serde_json::from_slice(&protected(Path::new(IDENTITY), 8192)?)?;
    let peer: KuraPeer = serde_json::from_slice(&protected(Path::new(KURA_PEER), 8192)?)?;
    config.select(&identity, &peer, original, gateway, generation, receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Identity, KuraPeer, serde_json::Value) {
        let identity = Identity {
            schema_version: 1,
            profile: "native-nonroot-v1".into(),
            user: USER.into(),
            uid: 997,
            gid: 995,
            reader_gid: 994,
            state_directory: STATE.into(),
            socket: SOCKET.into(),
            unit_sha256: "1".repeat(64),
            binary_sha256: "2".repeat(64),
            source_manifest_sha256: "3".repeat(64),
        };
        let peer = KuraPeer {
            schema_version: 1,
            profile: "native-kura-peer-v1".into(),
            request_id: uuid::Uuid::new_v4().to_string(),
            initialization_id: uuid::Uuid::new_v4().to_string(),
            native_identity_sha256: "4".repeat(64),
            control_gid: 995,
            kura_uid: 996,
            kura_gid: 993,
            core_unit_sha256: "5".repeat(64),
            core_networking_drop_in_sha256: None,
            core_loader_sha256: "6".repeat(64),
            java_bridge_metadata_sha256: "7".repeat(64),
        };
        let value = serde_json::json!({"schemaVersion":1,"profile":"native-transport-endpoint-v1","requestId":uuid::Uuid::new_v4().to_string(),
            "initializationId":peer.initialization_id,"peerAuthorizationId":peer.request_id,"peerAuthorizationResultSha256":"8".repeat(64),
            "nativeUid":997,"controlGid":995,"gatewayId":"retained-gateway","originalEndpoint":"https://center.invalid:18443",
            "endpoint":"https://center.invalid:18444","identityReceiptSha256":crate::durable::hash(b"original receipt"),
            "minimumBindingGeneration":1,"unitStarted":false,"remoteEnabled":false});
        (identity, peer, value)
    }
    #[test]
    fn explicit_root_port_configuration_retains_gateway_identity_and_never_enables_a_channel() {
        let (identity, peer, value) = fixture();
        let config: TransportEndpoint = serde_json::from_value(value).unwrap();
        assert_eq!(
            config
                .select(
                    &identity,
                    &peer,
                    "https://center.invalid:18443",
                    "retained-gateway",
                    1,
                    b"original receipt"
                )
                .unwrap(),
            "https://center.invalid:18444"
        );
        assert!(!config.remote_enabled);
        assert!(!config.unit_started);
        assert!(
            config
                .select(
                    &identity,
                    &peer,
                    "https://center.invalid:18443",
                    "other-gateway",
                    1,
                    b"original receipt"
                )
                .is_err()
        );
        assert!(
            config
                .select(
                    &identity,
                    &peer,
                    "https://center.invalid:18443",
                    "retained-gateway",
                    1,
                    b"changed receipt"
                )
                .is_err()
        );
        assert!(
            config
                .select(
                    &identity,
                    &peer,
                    "https://center.invalid:18443",
                    "retained-gateway",
                    0,
                    b"original receipt"
                )
                .is_err()
        );
    }
    #[test]
    fn root_configuration_cannot_follow_a_different_installation_or_role() {
        let (mut identity, mut peer, value) = fixture();
        let config: TransportEndpoint = serde_json::from_value(value).unwrap();
        peer.initialization_id = uuid::Uuid::new_v4().to_string();
        assert!(
            config
                .select(
                    &identity,
                    &peer,
                    "https://center.invalid:18443",
                    "retained-gateway",
                    1,
                    b"original receipt"
                )
                .is_err()
        );
        peer.initialization_id = config.initialization_id.clone();
        identity.uid = 0;
        assert!(
            config
                .select(
                    &identity,
                    &peer,
                    "https://center.invalid:18443",
                    "retained-gateway",
                    1,
                    b"original receipt"
                )
                .is_err()
        );
    }
    #[test]
    fn independently_validated_renewal_retains_only_the_same_gateway_and_center_route() {
        let (identity, peer, value) = fixture();
        let config: TransportEndpoint = serde_json::from_value(value).unwrap();
        assert_eq!(
            config
                .select(
                    &identity,
                    &peer,
                    "https://center.invalid:18443",
                    "retained-gateway",
                    2,
                    b"new validated receipt"
                )
                .unwrap(),
            config.endpoint
        );
        assert_eq!(
            config
                .select(
                    &identity,
                    &peer,
                    "https://center.invalid:18444",
                    "retained-gateway",
                    2,
                    b"new validated receipt"
                )
                .unwrap(),
            config.endpoint
        );
        assert!(
            config
                .select(
                    &identity,
                    &peer,
                    "https://other.invalid:18443",
                    "retained-gateway",
                    2,
                    b"new validated receipt"
                )
                .is_err()
        );
    }
    #[test]
    fn malformed_or_foreign_transport_address_never_becomes_a_fallback() {
        let (identity, peer, value) = fixture();
        for address in [
            "http://center.invalid:18444",
            "https://other.invalid:18444",
            "https://user@center.invalid:18444",
            "https://center.invalid:18444/path",
            "https://center.invalid:18444?q=1",
            "https://center.invalid:0",
            "https://center.invalid:",
            "https://center.invalid:65536",
        ] {
            let mut bad = value.clone();
            bad["endpoint"] = serde_json::json!(address);
            let config: TransportEndpoint = serde_json::from_value(bad).unwrap();
            assert!(
                config
                    .select(
                        &identity,
                        &peer,
                        "https://center.invalid:18443",
                        "retained-gateway",
                        1,
                        b"original receipt"
                    )
                    .is_err(),
                "{address}"
            );
        }
    }
    #[test]
    fn transport_json_rejects_extra_duplicate_boolean_or_noninteger_authority() {
        let (_, _, value) = fixture();
        for (field, new) in [
            ("schemaVersion", serde_json::json!(true)),
            ("nativeUid", serde_json::json!(true)),
            ("minimumBindingGeneration", serde_json::json!(1.5)),
            ("arbitraryPath", serde_json::json!("/tmp/other")),
        ] {
            let mut bad = value.clone();
            bad[field] = new;
            assert!(serde_json::from_value::<TransportEndpoint>(bad).is_err());
        }
        let raw = serde_json::to_string(&value).unwrap();
        let duplicate = raw.replacen('{', "{\"schemaVersion\":1,", 1);
        assert!(serde_json::from_str::<TransportEndpoint>(&duplicate).is_err());
    }
}
