//! Native, explicitly granted staged-identity descriptors. Never a Core key reader.
use super::Secret;
use anyhow::{Result, bail, ensure};

pub(super) const SOCKET: &str = "/run/kura-management-enrollment-reader.sock";
pub(super) const SOURCE: &str = "/opt/eclipse/kura/data/management-enrollment";
pub(super) const FILES: [(&str, u64); 10] = [
    ("private.pk8", 16384),
    ("public.der", 16384),
    ("request.pem", 16384),
    ("gateway.id", 128),
    ("complete", 64),
    ("certificates/client-chain.pem", 65536),
    ("certificates/issuer-ca.pem", 65536),
    ("certificates/console-ca.pem", 65536),
    ("certificates/manifest.json", 16384),
    ("certificates/complete", 65),
];

pub(super) struct Snapshot(Vec<Secret>);

impl Snapshot {
    pub(super) fn bytes(&self, name: &str) -> Result<&[u8]> {
        let index = FILES
            .iter()
            .position(|(file, _)| *file == name)
            .ok_or_else(|| anyhow::anyhow!("PROTOCOL_MISMATCH: enrollment file label"))?;
        Ok(&self.0[index].0)
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn snapshot(_: &str, _: &str, _: u32) -> Result<Snapshot> {
    bail!("UNSUPPORTED: native enrollment stage publisher")
}

#[cfg(target_os = "linux")]
pub(super) fn snapshot(id: &str, digest: &str, uid: u32) -> Result<Snapshot> {
    native::snapshot(id, digest, uid)
}

#[cfg(target_os = "linux")]
mod native;
