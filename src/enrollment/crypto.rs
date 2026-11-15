//! Independent OpenSSL validation of Kura's fixed local handoff format.
//! Private keys are converted from supplied PKCS8, never generated here.
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{path::Path, time::Duration};

pub(super) fn openssl() -> &'static Path {
    #[cfg(target_os = "macos")]
    {
        Path::new("/opt/homebrew/bin/openssl")
    }
    #[cfg(not(target_os = "macos"))]
    {
        Path::new("/usr/bin/openssl")
    }
}

/// Explicit enrollment anchors must not be supplemented by machine-wide or
/// inherited SSL_CERT_* defaults. All verify calls share the same boundary.
pub(super) fn arguments<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut result = args.to_vec();
    if args.first() == Some(&"verify") {
        result.splice(1..1, ["-no-CAfile", "-no-CApath", "-no-CAstore"]);
    }
    result
}

pub(super) fn command(args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
    let out = crate::process::run(openssl(), &arguments(args), input, Duration::from_secs(5))?;
    ensure!(
        out.status.success(),
        "INVALID_ARGUMENT: enrollment cryptographic validation"
    );
    Ok(out.stdout)
}

pub(super) fn pem(label: &str, bytes: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(bytes);
    let mut out = format!("-----BEGIN {label}-----\n").into_bytes();
    for line in encoded.as_bytes().chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    out
}

pub(super) fn blocks(bytes: &[u8], label: &str) -> Result<Vec<Vec<u8>>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 65536,
        "INVALID_ARGUMENT"
    );
    let begin = format!("-----BEGIN {label}-----\n");
    let end = format!("-----END {label}-----\n");
    let mut rest = std::str::from_utf8(bytes).map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT"))?;
    let mut result = Vec::new();
    while !rest.is_empty() {
        ensure!(
            result.len() < 8 && rest.starts_with(&begin),
            "INVALID_ARGUMENT"
        );
        let index = rest
            .find(&end)
            .ok_or_else(|| anyhow::anyhow!("INVALID_ARGUMENT"))?;
        let data = &rest[begin.len()..index];
        let decoded = STANDARD
            .decode(data.replace('\n', ""))
            .map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT"))?;
        let length = index + end.len();
        ensure!(
            pem(label, &decoded) == rest.as_bytes()[..length],
            "INVALID_ARGUMENT: noncanonical PEM"
        );
        result.push(decoded);
        rest = &rest[length..];
    }
    ensure!(!result.is_empty(), "INVALID_ARGUMENT");
    Ok(result)
}

const P256_SPKI: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

pub(super) fn private_pkcs8(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.first() == Some(&0x30) && bytes.len() >= 4,
        "INVALID_ARGUMENT"
    );
    let (header, length) = if bytes[1] < 128 {
        (2, usize::from(bytes[1]))
    } else {
        let count = usize::from(bytes[1] & 0x7f);
        ensure!(
            (1..=2).contains(&count) && bytes.len() > 2 + count && bytes[2] != 0,
            "INVALID_ARGUMENT"
        );
        let size = bytes[2..2 + count]
            .iter()
            .fold(0usize, |a, b| (a << 8) | usize::from(*b));
        ensure!(
            size >= 128 && (count == 1 || size > 255),
            "INVALID_ARGUMENT"
        );
        (2 + count, size)
    };
    ensure!(
        header + length == bytes.len()
            && bytes.len() > header + 24
            && bytes[header..header + 3] == [2, 1, 0]
            && bytes[header + 3..header + 24] == P256_SPKI[2..23],
        "INVALID_ARGUMENT: expected P256 PKCS8"
    );
    Ok(())
}

/// SunEC PKCS8 can omit the redundant EC public point. OpenSSL accepts that
/// legal encoding, while ring requires the point. Convert only in memory, from
/// the supplied scalar; never generate a key or replace retained identity files.
pub(super) fn tls_private_key(key: &[u8]) -> Result<Vec<u8>> {
    let Ok(mut decoded) = blocks(key, "PRIVATE KEY") else {
        return Ok(key.to_vec());
    };
    if decoded.len() != 1 {
        return Ok(key.to_vec());
    }
    let der = super::Secret(decoded.remove(0));
    if private_pkcs8(&der.0).is_err() {
        return Ok(key.to_vec());
    }
    let algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
    let random = ring::rand::SystemRandom::new();
    if ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, &der.0, &random).is_ok() {
        return Ok(key.to_vec());
    }
    let sec1 = super::Secret(command(&["ec", "-outform", "PEM"], Some(key))?);
    let normalized = command(&["pkcs8", "-topk8", "-nocrypt"], Some(&sec1.0))?;
    let mut converted = blocks(&normalized, "PRIVATE KEY")?;
    ensure!(
        converted.len() == 1,
        "INVALID_ARGUMENT: TLS private key encoding"
    );
    let normalized_der = super::Secret(converted.remove(0));
    ensure!(
        ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, &normalized_der.0, &random).is_ok(),
        "INVALID_ARGUMENT: TLS private key encoding"
    );
    // Independent public-key equality checks the conversion, including malformed
    // input with a conflicting embedded point. Never substitute a different key.
    ensure!(
        command(&["pkey", "-pubout", "-outform", "DER"], Some(key))?
            == command(&["pkey", "-pubout", "-outform", "DER"], Some(&normalized))?,
        "INVALID_ARGUMENT: TLS key changed"
    );
    Ok(normalized)
}

fn text(args: &[&str], input: Option<&[u8]>) -> Result<String> {
    String::from_utf8(command(args, input)?).map_err(|_| anyhow::anyhow!("INVALID_ARGUMENT"))
}

pub(super) fn validate(
    directory: &Path,
    manifest: &super::Manifest,
    allow_create: bool,
) -> Result<()> {
    let path = |name: &str| directory.join(name).to_string_lossy().into_owned();
    let private = super::Secret(std::fs::read(directory.join("private.pk8"))?);
    private_pkcs8(&private.0)?;
    let key = super::Secret(command(
        &["pkey", "-inform", "DER", "-in", &path("private.pk8")],
        None,
    )?);
    derived(&directory.join("agent-key.pem"), &key.0, allow_create)?;
    let public = command(
        &[
            "pkey",
            "-in",
            &path("agent-key.pem"),
            "-pubout",
            "-outform",
            "DER",
        ],
        None,
    )?;
    ensure!(
        public.len() == 91
            && public.starts_with(P256_SPKI)
            && crate::durable::hash(&public) == manifest.public_key_sha256
            && public == std::fs::read(directory.join("public.der"))?,
        "INVALID_ARGUMENT: key mismatch"
    );
    let csr = blocks(
        &std::fs::read(directory.join("request.pem"))?,
        "CERTIFICATE REQUEST",
    )?;
    ensure!(
        csr.len() == 1
            && command(&["req", "-inform", "DER", "-outform", "DER"], Some(&csr[0]))? == csr[0],
        "INVALID_ARGUMENT"
    );
    command(
        &["req", "-in", &path("request.pem"), "-verify", "-noout"],
        None,
    )?;
    let csr_pub = command(
        &["req", "-in", &path("request.pem"), "-pubkey", "-noout"],
        None,
    )?;
    ensure!(
        command(&["pkey", "-pubin", "-outform", "DER"], Some(&csr_pub))? == public,
        "INVALID_ARGUMENT"
    );
    let expected = format!("subject=CN={}", manifest.gateway_id);
    ensure!(
        text(
            &[
                "req",
                "-in",
                &path("request.pem"),
                "-subject",
                "-noout",
                "-nameopt",
                "RFC2253"
            ],
            None
        )?
        .trim()
            == expected,
        "INVALID_ARGUMENT"
    );
    let certs = directory.join("certificates");
    let client = certs
        .join("client-chain.pem")
        .to_string_lossy()
        .into_owned();
    let mut leaf = Vec::new();
    for name in ["client-chain.pem", "issuer-ca.pem", "console-ca.pem"] {
        let bytes = std::fs::read(certs.join(name))?;
        let entries = blocks(&bytes, "CERTIFICATE")?;
        let mut previous = None;
        let mut unique = std::collections::HashSet::new();
        let mut files = Vec::new();
        for (index, der) in entries.iter().enumerate() {
            ensure!(
                command(&["x509", "-inform", "DER", "-outform", "DER"], Some(der))? == *der,
                "INVALID_ARGUMENT"
            );
            ensure!(
                unique.insert(crate::durable::hash(der)),
                "INVALID_ARGUMENT: duplicate certificate"
            );
            let cert = pem("CERTIFICATE", der);
            let file = directory.join(format!("{name}-{index}.certificate.pem"));
            derived(&file, &cert, allow_create)?;
            files.push(file);
            let pubkey = command(&["x509", "-pubkey", "-noout"], Some(&cert))?;
            let public_text = text(&["pkey", "-pubin", "-text", "-noout"], Some(&pubkey))?;
            let line = public_text.lines().next().unwrap_or("");
            let bits = line
                .split('(')
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            ensure!(
                (public_text
                    .lines()
                    .any(|l| l.trim_start().starts_with("Modulus:"))
                    && bits >= 2048)
                    || (public_text
                        .lines()
                        .any(|l| l.trim_start().starts_with("ASN1 OID:"))
                        && bits >= 256),
                "INVALID_ARGUMENT: unsupported certificate key"
            );
            if name == "client-chain.pem" && index == 0 {
                leaf = der.clone();
                continue;
            }
            let constraints = text(&["x509", "-noout", "-ext", "basicConstraints"], Some(&cert))?;
            ensure!(
                constraints
                    .lines()
                    .any(|l| l.trim() == "CA:TRUE" || l.trim().starts_with("CA:TRUE, pathlen:")),
                "INVALID_ARGUMENT: CA constraints"
            );
            if name != "client-chain.pem" {
                let hash = crate::durable::hash(der);
                ensure!(
                    previous.as_ref().is_none_or(|p: &String| p < &hash),
                    "INVALID_ARGUMENT: CA ordering or duplicate"
                );
                previous = Some(hash);
                let usage = text(&["x509", "-noout", "-ext", "keyUsage"], Some(&cert))?;
                ensure!(
                    !usage.contains("X509v3 Key Usage") || usage.contains("Certificate Sign"),
                    "INVALID_ARGUMENT"
                );
                let anchor = directory.join(format!("{name}-{index}.anchor.pem"));
                derived(&anchor, &cert, allow_create)?;
                let anchor = anchor.to_string_lossy().into_owned();
                command(
                    &["verify", "-partial_chain", "-trusted", &anchor, &anchor],
                    None,
                )?;
            }
        }
        if name == "client-chain.pem" {
            for pair in files.windows(2) {
                command(
                    &[
                        "verify",
                        "-partial_chain",
                        "-trusted",
                        &pair[1].to_string_lossy(),
                        &pair[0].to_string_lossy(),
                    ],
                    None,
                )?;
            }
            let issuer = certs.join("issuer-ca.pem").to_string_lossy().into_owned();
            command(
                &[
                    "verify",
                    "-partial_chain",
                    "-CAfile",
                    &issuer,
                    &files.last().unwrap().to_string_lossy(),
                ],
                None,
            )?;
        }
    }
    ensure!(
        crate::durable::hash(&leaf) == manifest.client_certificate_sha256,
        "INVALID_ARGUMENT"
    );
    let leaf_pub = command(&["x509", "-in", &client, "-pubkey", "-noout"], None)?;
    ensure!(
        command(&["pkey", "-pubin", "-outform", "DER"], Some(&leaf_pub))? == public,
        "INVALID_ARGUMENT"
    );
    ensure!(
        text(
            &[
                "x509", "-in", &client, "-subject", "-noout", "-nameopt", "RFC2253"
            ],
            None
        )?
        .trim()
            == expected,
        "INVALID_ARGUMENT"
    );
    ensure!(
        !text(
            &["x509", "-in", &client, "-noout", "-ext", "basicConstraints"],
            None
        )?
        .contains("CA:TRUE"),
        "INVALID_ARGUMENT"
    );
    ensure!(
        text(
            &["x509", "-in", &client, "-noout", "-ext", "extendedKeyUsage"],
            None
        )?
        .contains("TLS Web Client Authentication"),
        "INVALID_ARGUMENT"
    );
    let leaf_usage = text(
        &["x509", "-in", &client, "-noout", "-ext", "keyUsage"],
        None,
    )?;
    ensure!(
        !leaf_usage.contains("X509v3 Key Usage") || leaf_usage.contains("Digital Signature"),
        "INVALID_ARGUMENT: client signing usage required"
    );
    let expiry = text(
        &[
            "x509", "-in", &client, "-noout", "-enddate", "-dateopt", "iso_8601",
        ],
        None,
    )?;
    ensure!(
        expiry
            .trim()
            .strip_prefix("notAfter=")
            .map(|s| s.replace(' ', "T"))
            .as_deref()
            == Some(&manifest.not_after),
        "INVALID_ARGUMENT: expiry metadata mismatch"
    );
    let issuer = certs.join("issuer-ca.pem").to_string_lossy().into_owned();
    command(
        &[
            "verify",
            "-partial_chain",
            "-auth_level",
            "2",
            "-purpose",
            "sslclient",
            "-CAfile",
            &issuer,
            "-untrusted",
            &client,
            &client,
        ],
        None,
    )?;
    Ok(())
}

fn derived(path: &Path, bytes: &[u8], allow_create: bool) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            let (old, metadata) = crate::durable::read(path, 65536)?;
            ensure!(
                metadata.uid == unsafe { libc::geteuid() }
                    && metadata.mode == 0o600
                    && old == bytes,
                "CONFLICT: managed material changed"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ensure!(allow_create, "CONFLICT: managed derived material missing");
            crate::durable::publish_new(path, bytes, crate::durable::FileMetadata::private())?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
