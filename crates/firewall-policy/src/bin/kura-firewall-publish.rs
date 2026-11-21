//! One private pipe session per original operation. The supervising broker
//! authenticates Main before approval. This worker journals the approved wire before dispatch.
#[path = "kura-firewall-publish/admission.rs"]
mod admission;
#[path = "kura-firewall-publish/forwarding.rs"]
mod forwarding;
#[path = "kura-firewall-publish/journal.rs"]
mod journal;
#[path = "kura-firewall-publish/table.rs"]
mod table;
use anyhow::{Context, Result, ensure};
use kura_firewall_policy::{
    netlink::{attribute_text, attributes},
    publication::{FIRST_SEQUENCE, FamilyChange, RuleDump, plan},
    transport::{self, Outcome},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{self, BufRead, Read, Write},
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
enum Query {
    Scope {
        schema: u8,
    },
    Outcome {
        schema: u8,
        #[serde(rename = "operationId")]
        operation_id: String,
        #[serde(rename = "rootScope")]
        root_scope: String,
        #[serde(rename = "requestSha256")]
        request_sha256: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    schema: u8,
    operation_id: String,
    root_scope: String,
    changes: Vec<FamilyChange>,
    forwarding: Option<forwarding::Forwarding>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Authorize {
    operation_id: String,
    root_scope: String,
    request_sha256: String,
    wire_sha256: String,
}

fn frame(input: &mut impl BufRead, limit: usize) -> Result<Vec<u8>> {
    // This executable owns the process. A silent or partial pipe writer must release
    // journal and maintenance locks even if it never completes the approval frame.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::alarm(15);
    }
    let mut bytes = Vec::new();
    input.take(limit as u64 + 1).read_until(b'\n', &mut bytes)?;
    #[cfg(target_os = "linux")]
    unsafe {
        libc::alarm(0);
    }
    ensure!(
        bytes.len() <= limit && bytes.pop() == Some(b'\n'),
        "INVALID_ARGUMENT: firewall request frame"
    );
    Ok(bytes)
}
fn reply(value: Value) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &value)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(b.len() * 2);
    for v in b {
        write!(out, "{v:02x}").unwrap();
    }
    out
}
fn lower_hex(v: u8) -> bool {
    v.is_ascii_digit() || (b'a'..=b'f').contains(&v)
}
fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                lower_hex(b)
            }
        })
}
fn snapshot(deadline: Instant) -> Result<(u32, RuleDump)> {
    let generation = transport::generation(deadline)?;
    let mut rows = RuleDump::new();
    let mut count = 0;
    const SEQUENCE: u32 = 0x594f4630;
    transport::read_rules(SEQUENCE, deadline, |packet| {
        transport::visit_rule_packet(packet, SEQUENCE, |row| {
            count += 1;
            ensure!(
                count <= 8192 && row.len() >= 4,
                "RESOURCE_EXHAUSTED: Netfilter snapshot"
            );
            if !matches!(row[0], 2 | 10) {
                return Ok(());
            }
            let fields = attributes(&row[4..])?;
            let name = |tag| {
                let mut found = fields.iter().filter(|(t, _)| t & 0x3fff == tag);
                let name = attribute_text(found.next().context("missing rule name")?.1)?;
                ensure!(found.next().is_none(), "CONFLICT: duplicate rule name");
                Ok::<_, anyhow::Error>(name)
            };
            rows.entry((row[0], name(1)?, name(2)?))
                .or_default()
                .push(row.to_vec());
            Ok(())
        })
    })?;
    ensure!(
        transport::generation(deadline)? == generation,
        "CONFLICT: firewall changed during observation"
    );
    Ok((generation, rows))
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let readback = match args.as_slice() {
        [flag, family] if flag == "--read-family" => Some((family, None)),
        [flag, family, name] if flag == "--read-table" => {
            let table = name.to_str().context("Invalid table name")?;
            ensure!(
                matches!(table, "filter" | "nat" | "mangle" | "raw" | "security"),
                "Unknown legacy table"
            );
            Some((family, Some(table)))
        }
        _ => None,
    };
    if let Some((family, table)) = readback {
        let family = match family.to_str() {
            Some("ipv4") => 2,
            Some("ipv6") => 10,
            _ => anyhow::bail!("Unknown table family"),
        };
        println!(
            "{}",
            table::digest(family, table, Instant::now() + Duration::from_secs(5))?
        );
        return Ok(());
    }
    if args.as_slice() == [std::ffi::OsStr::new("--build-source")] {
        println!(
            "{}",
            option_env!("KURA_FIREWALL_SOURCE_ARCHIVE_SHA256").unwrap_or("workspace")
        );
        return Ok(());
    }
    if args.as_slice() == [std::ffi::OsStr::new("--check-receipt")] {
        let mut input = io::stdin().lock();
        let intent = frame(&mut input, 2 * 1024 * 1024)?;
        let result = frame(&mut input, 2 * 1024 * 1024)?;
        return journal::check_legacy_receipt(&intent, &result);
    }
    ensure!(
        std::env::args_os().len() == 1,
        "INVALID_ARGUMENT: firewall worker takes no arguments"
    );
    let mut input = io::stdin().lock();
    let bytes = frame(&mut input, 8 * 1024 * 1024)?;
    let store = journal::Journal::open()?;
    if let Ok(query) = serde_json::from_slice::<Query>(&bytes) {
        return match query {
            Query::Scope { schema: 1 } => reply(json!({"state":"SCOPE","rootScope":store.scope})),
            Query::Outcome {
                schema: 1,
                operation_id,
                root_scope,
                request_sha256,
            } => {
                ensure!(
                    request_sha256.len() == 64 && request_sha256.bytes().all(lower_hex),
                    "INVALID_ARGUMENT: original request hash"
                );
                reply(store.outcome(&operation_id, &root_scope, &request_sha256)?)
            }
            _ => anyhow::bail!("INVALID_ARGUMENT: firewall protocol version"),
        };
    }
    let request: Request = serde_json::from_slice(&bytes)?;
    ensure!(
        matches!(
            (request.schema, request.forwarding.is_some()),
            (1, false) | (2, true)
        ) && is_uuid(&request.operation_id)
            && request.root_scope.len() == 64
            && request.root_scope.bytes().all(lower_hex),
        "INVALID_ARGUMENT: firewall operation identity"
    );
    let request_hash = hex(&Sha256::digest(&bytes));
    let prior = store.outcome(&request.operation_id, &request.root_scope, &request_hash)?;
    if prior["state"] != "NOT_FOUND" {
        return reply(prior);
    }
    store.require_idle()?;
    let admission = admission::Admission::acquire()?;
    let (generation, rows) = snapshot(Instant::now() + Duration::from_secs(10))?;
    let batch = plan(generation, &request.changes, &rows)?;
    let control = request
        .forwarding
        .as_ref()
        .map(|f| f.prepare(&request.changes))
        .transpose()?;
    let wire = hex(&batch.wire);
    let wire_hash = hex(&Sha256::digest(&batch.wire));
    reply(
        json!({"state":"PREPARED","operationId":request.operation_id,"rootScope":request.root_scope,
        "requestSha256":request_hash,"wireSha256":wire_hash,"generation":generation,"commands":batch.commands}),
    )?;
    let authorize: Authorize = serde_json::from_slice(&frame(&mut input, 1024)?)?;
    ensure!(
        authorize.operation_id == request.operation_id
            && authorize.root_scope == request.root_scope
            && authorize.request_sha256 == request_hash
            && authorize.wire_sha256 == wire_hash,
        "CONFLICT: original publication approval"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut result = json!({"operationId":request.operation_id,"rootScope":request.root_scope,"wireSha256":wire_hash,"requestSha256":request_hash});
    let intent = journal::Intent {
        schema: request.schema,
        forwarding: request.forwarding,
        operation_id: request.operation_id.clone(),
        root_scope: store.scope.clone(),
        request_sha256: request_hash.clone(),
        wire_sha256: wire_hash.clone(),
        wire,
        commands: batch.commands,
        generation,
    };
    admission.validate()?;
    if let (Some(transition), Some(fd)) = (&intent.forwarding, &control) {
        transition.verify_before(fd)?;
    }
    if batch.commands == 0 {
        ensure!(
            transport::generation(deadline)? == generation,
            "CONFLICT: changed firewall observation"
        );
    }
    let intent_hash = store.begin(&intent)?;
    if batch.commands == 0 {
        result["state"] = json!("UNCHANGED");
    } else {
        match transport::dispatch(&batch.wire, FIRST_SEQUENCE, batch.end, deadline)? {
            Outcome::Committed { reply } => {
                result["state"] = json!("APPLIED");
                result["ack"] = json!(hex(&reply));
            }
            Outcome::Rejected {
                errno,
                sequence,
                reply,
            } => {
                result["state"] = json!("REJECTED");
                result["errno"] = json!(errno);
                result["sequence"] = json!(sequence);
                result["ack"] = json!(hex(&reply));
            }
        }
    }
    if let (Some(transition), Some(fd)) = (&intent.forwarding, &control)
        && result["state"] != "REJECTED"
    {
        // Do not enable routing if another ruleset superseded the approved batch.
        let expected = if batch.commands == 0 {
            generation
        } else {
            generation.wrapping_add(1).max(1)
        };
        admission.validate()?;
        ensure!(
            transport::generation(deadline)? == expected,
            "UNKNOWN: rules changed before forwarding"
        );
        transition.enable(fd)?;
        ensure!(
            transport::generation(deadline)? == expected,
            "UNKNOWN: rules changed during forwarding"
        );
        result["forwardingEnabled"] = json!(true);
        if !transition.before {
            result["state"] = json!("APPLIED");
        }
    }
    store.finish(&request.operation_id, intent_hash, &result)?;
    reply(result)
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Firewall publication failed: {error}");
        std::process::exit(1);
    }
}
