//! Forwarding is enabled only for the family and namespace of an approved Main request.
use anyhow::{Context, Result, ensure};
use kura_firewall_policy::{canonical_clause, parse_rendered, publication::FamilyChange};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{FileExt, MetadataExt},
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Forwarding {
    pub family: String,
    pub namespace: [u64; 2],
    pub before: bool,
}

impl Forwarding {
    pub fn prepare(&self, changes: &[FamilyChange]) -> Result<File> {
        let [change] = changes else {
            anyhow::bail!("INVALID_ARGUMENT: forwarding requires one firewall family");
        };
        ensure!(change.family == self.family, "UNPAIRED: forwarding family");
        let path = self.path()?;
        let ns = fs::metadata("/proc/self/ns/net")?;
        ensure!(
            self.namespace == [ns.dev(), ns.ino()],
            "UNPAIRED: forwarding network namespace"
        );
        let model = parse_rendered(&change.candidate)?;
        let filter = model
            .tables
            .iter()
            .find(|t| t.name == "filter")
            .context("Missing filter table")?;
        // The Java NAT and port-forward renderers emit ACCEPT rules with both interfaces.
        // Built-in jumps, site comments and the default RETURN cannot authorize this write.
        ensure!(
            filter.rules.iter().any(|row| {
                matches!(
                    row.chain.as_str(),
                    "forward-kura" | "forward-kura-pf" | "forward-kura-ipf"
                ) && canonical_clause(&row.specification).is_ok_and(|terms| {
                    terms
                        .get("jump")
                        .is_some_and(|(negated, target)| !negated && target == "ACCEPT")
                        && ["input", "output"]
                            .iter()
                            .all(|key| terms.get(*key).is_some_and(|(negated, _)| !negated))
                })
            }),
            "UNPAIRED: no original forwarding rule in candidate"
        );
        let fd = OpenOptions::new()
            .read(true)
            .write(!self.before)
            .open(path)?;
        self.verify_before(&fd)?;
        Ok(fd)
    }

    fn path(&self) -> Result<&'static str> {
        match self.family.as_str() {
            "ipv4" => Ok("/proc/sys/net/ipv4/ip_forward"),
            "ipv6" => Ok("/proc/sys/net/ipv6/conf/all/forwarding"),
            _ => anyhow::bail!("INVALID_ARGUMENT: forwarding family"),
        }
    }
    pub fn verify_enabled(&self) -> Result<()> {
        ensure!(
            Self::enabled(&File::open(self.path()?)?)?,
            "CONFLICT: boot forwarding is disabled"
        );
        Ok(())
    }

    fn enabled(fd: &File) -> Result<bool> {
        let mut value = [0; 8];
        let n = fd.read_at(&mut value, 0)?;
        match &value[..n] {
            b"1\n" => Ok(true),
            b"0\n" => Ok(false),
            _ => anyhow::bail!("CONFLICT: unexpected kernel forwarding value"),
        }
    }

    pub fn verify_before(&self, fd: &File) -> Result<()> {
        ensure!(
            Self::enabled(fd)? == self.before,
            "CONFLICT: kernel forwarding state changed"
        );
        Ok(())
    }

    pub fn enable(&self, fd: &File) -> Result<()> {
        self.verify_before(fd)?;
        if !self.before {
            ensure!(
                fd.write_at(b"1", 0)? == 1,
                "UNKNOWN: incomplete kernel forwarding write"
            );
        }
        ensure!(
            Self::enabled(fd)?,
            "UNKNOWN: kernel forwarding readback failed"
        );
        Ok(())
    }
}
