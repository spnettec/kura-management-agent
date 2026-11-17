//! Native, explicitly granted staged-identity descriptors. Never a Core key reader.
use super::Secret;
use anyhow::{Result, bail, ensure};

pub(crate) const SOCKET: &str = "/run/kura-management-enrollment-reader.sock";
pub(crate) const SOURCE: &str = "/opt/eclipse/kura/data/management-enrollment";

#[derive(Clone, Copy)]
pub(super) enum Transport {
    RootPublisher,
    AgentRelay { group: u32 },
}

impl Transport {
    pub(super) fn endpoint(self) -> (&'static str, u32, u32) {
        match self {
            Self::RootPublisher => (SOCKET, 0, 0o600),
            Self::AgentRelay { group } => (crate::runtime_identity::READER_SOCKET, group, 0o660),
        }
    }
}
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
pub(super) fn snapshot(_: Transport, _: &str, _: &str, _: u32) -> Result<Snapshot> {
    bail!("UNSUPPORTED: native enrollment stage publisher")
}

#[cfg(target_os = "linux")]
pub(super) fn snapshot(transport: Transport, id: &str, digest: &str, uid: u32) -> Result<Snapshot> {
    native::snapshot(transport, id, digest, uid)
}

#[cfg(target_os = "linux")]
mod native;
