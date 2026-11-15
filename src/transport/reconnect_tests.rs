//! A fresh, owned mTLS stream exercises the real connection worker. Cached
//! receipts avoid executing any system operation or requiring a real NM device.
use super::*;
use prost::Message;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tonic::transport::{
    Server, ServerTlsConfig,
    server::{TcpConnectInfo, TlsConnectInfo},
};
use tonic::{Request, Response, Status, Streaming};
use yofc_management_protocol::v1::control_server::{Control, ControlServer};

#[derive(Clone)]
struct Center {
    commands: Arc<Vec<ReadCommand>>,
    connections: Arc<AtomicUsize>,
    hellos: mpsc::UnboundedSender<usize>,
    results: mpsc::UnboundedSender<TaskResult>,
}

#[tonic::async_trait]
impl Control for Center {
    type ConnectStream = ReceiverStream<std::result::Result<ConsoleFrame, Status>>;

    async fn connect(
        &self,
        request: Request<Streaming<AgentFrame>>,
    ) -> std::result::Result<Response<Self::ConnectStream>, Status> {
        let tls = request
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .ok_or_else(|| Status::unauthenticated("TLS required"))?;
        if tls.peer_certs().is_none_or(|certs| certs.is_empty()) {
            return Err(Status::unauthenticated("client certificate required"));
        }
        let mut stream = request.into_inner();
        let Some(AgentFrame {
            payload: Some(agent_frame::Payload::Hello(hello)),
        }) = stream.message().await?
        else {
            return Err(Status::invalid_argument("hello required"));
        };
        if hello.gateway_id != "agent" || hello.binding_generation != 1 {
            return Err(Status::unauthenticated("fixture identity"));
        }
        let index = self.connections.fetch_add(1, Ordering::SeqCst);
        let command = self
            .commands
            .get(index)
            .cloned()
            .ok_or_else(|| Status::resource_exhausted("unexpected connection"))?;
        let (tx, rx) = mpsc::channel(4);
        tx.send(Ok(ConsoleFrame {
            payload: Some(console_frame::Payload::Welcome(Welcome {
                connection_epoch: format!("owned-epoch-{index}"),
                heartbeat_seconds: 1,
            })),
        }))
        .await
        .map_err(|_| Status::cancelled("closed"))?;
        tx.send(Ok(ConsoleFrame {
            payload: Some(console_frame::Payload::Command(command)),
        }))
        .await
        .map_err(|_| Status::cancelled("closed"))?;
        self.hellos
            .send(index)
            .map_err(|_| Status::cancelled("closed"))?;
        let results = self.results.clone();
        tokio::spawn(async move {
            let _keep_response_open = tx;
            while let Ok(Some(frame)) = stream.message().await {
                if let Some(agent_frame::Payload::Result(result)) = frame.payload {
                    let _ = results.send(result);
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn check_transfer_revocation(
        &self,
        _: Request<TransferRevocationCheck>,
    ) -> std::result::Result<Response<TransferRevocationStatus>, Status> {
        Err(Status::unimplemented("unused fixture RPC"))
    }
}

#[tokio::test]
#[ignore = "new owned local mTLS fixture; no real NM or nft writes"]
async fn nm_prepare_wait_confirm_reconnects_after_receipt_over_real_mtls() {
    let fixture = std::path::PathBuf::from(std::env::var("YOFC_NM_RECONNECT_FIXTURE").unwrap());
    let tag = std::env::var("YOFC_NM_RECONNECT_RUN").unwrap();
    assert!(matches!(tag.as_str(), "before" | "before-v2" | "after"));
    let work = fixture.join(&tag);
    std::fs::create_dir(&work).expect("retain each fixture attempt; do not overwrite");
    let db = database(work.join("agent.db").to_str().unwrap())
        .await
        .unwrap();
    let cases = [
        (Operation::NmPrepare, TaskState::WaitConfirm, "WAIT_CONFIRM"),
        (Operation::NmView, TaskState::Succeeded, "WAIT_CONFIRM"),
        (Operation::NmPrepare, TaskState::Unknown, "UNKNOWN"),
    ];
    let mut commands = Vec::new();
    let mut receipts = Vec::new();
    for (operation, state, body_state) in cases {
        let id = uuid::Uuid::new_v4().to_string();
        let command = ReadCommand {
            command_id: id.clone(),
            operation: operation as i32,
            idempotency_key: id.clone(),
            expires_at_unix_ms: i64::MAX,
            ..Default::default()
        };
        let receipt = TaskResult {
            command_id: id,
            state: state as i32,
            error: if state == TaskState::Unknown {
                ErrorCode::OutcomeUnknown as i32
            } else {
                0
            },
            result_json: serde_json::to_vec(
                &json!({"state":body_state,"operationId":"cached-original"}),
            )
            .unwrap(),
        };
        let hash = format!("{:x}", Sha256::digest(command.encode_to_vec()));
        sqlx::query("INSERT INTO results(command_id,operation,idempotency_key,result,created_at,request_hash) VALUES(?,?,?,?,0,?)")
            .bind(&command.command_id).bind(command.operation).bind(&command.idempotency_key)
            .bind(receipt.encode_to_vec()).bind(hash).execute(&db).await.unwrap();
        commands.push(command);
        receipts.push(receipt);
    }
    let (hello_tx, mut hello_rx) = mpsc::unbounded_channel();
    let (result_tx, mut result_rx) = mpsc::unbounded_channel();
    let count = Arc::new(AtomicUsize::new(0));
    let center = Center {
        commands: Arc::new(commands),
        connections: count.clone(),
        hellos: hello_tx,
        results: result_tx,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(
            fs::read(fixture.join("server.pem")).unwrap(),
            fs::read(fixture.join("server.key")).unwrap(),
        ))
        .client_ca_root(Certificate::from_pem(
            fs::read(fixture.join("ca.pem")).unwrap(),
        ));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(
        Server::builder()
            .tls_config(server_tls)
            .unwrap()
            .add_service(ControlServer::new(center))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = shutdown_rx.await;
                },
            ),
    );
    let config = Config {
        endpoint: format!("https://localhost:{}", address.port()),
        gateway: "agent".into(),
        binding_generation: 1,
        boot_id: uuid::Uuid::new_v4().to_string(),
        ca: fixture.join("ca.pem").to_str().unwrap().into(),
        cert: fixture.join("agent.pem").to_str().unwrap().into(),
        key: fixture.join("agent.key").to_str().unwrap().into(),
    };
    let remote = crate::remote::Remote::open(
        work.join("remote"),
        true,
        Some((config.endpoint.clone(), config.gateway.clone(), 1)),
    )
    .unwrap();
    let revision = remote.session().unwrap();
    let local = Local::new(unsafe { libc::geteuid() }, unsafe { libc::geteuid() });
    let slots = Arc::new(Semaphore::new(2));
    for (index, receipt) in receipts.iter().enumerate() {
        let connection = connect(&config, &local, &db, &slots, &remote, &revision);
        tokio::pin!(connection);
        if index == 0 {
            tokio::select! {
                result = &mut connection => panic!("connection ended before cached NM receipt: {result:?}"),
                received = result_rx.recv() => assert_eq!(received.unwrap(),*receipt),
                _ = tokio::time::sleep(Duration::from_secs(3)) => panic!("cached NM receipt missing"),
            }
            fs::write(
                work.join("nm-receipt-delivered.json"),
                serde_json::to_vec(&json!({"cachedNmReceiptDelivered":true,"systemWrites":false}))
                    .unwrap(),
            )
            .unwrap();
            let ended = tokio::time::timeout(Duration::from_secs(3), &mut connection).await;
            assert!(
                ended.is_ok(),
                "NM WAIT_CONFIRM receipt arrived but the management connection stayed old"
            );
            assert!(
                ended
                    .unwrap()
                    .unwrap_err()
                    .to_string()
                    .contains("requires a fresh management connection")
            );
        } else {
            tokio::select! {
                result = &mut connection => panic!("control connection ended before cached receipt: {result:?}"),
                received = result_rx.recv() => assert_eq!(received.unwrap(),*receipt),
                _ = tokio::time::sleep(Duration::from_secs(3)) => panic!("control receipt missing"),
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(800), &mut connection)
                    .await
                    .is_err(),
                "read-only or UNKNOWN result must not force reconnect"
            );
        }
        assert_eq!(hello_rx.recv().await.unwrap(), index);
    }
    let executions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM executions")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        executions, 0,
        "receipt replay must not claim or execute a system task"
    );
    assert_eq!(count.load(Ordering::SeqCst), 3);
    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    db.close().await;
    println!(
        "{}",
        json!({"realMtlsConnections":3,"nmPrepareWaitConfirmForcedFresh":true,
        "readOnlyAndUnknownKeptConnection":true,"cachedReceiptsDelivered":3,
        "systemTasksClaimed":0,"actualNmWrites":false,"run":tag})
    );
}
