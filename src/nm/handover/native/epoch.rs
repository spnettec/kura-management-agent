//! Physical namespace provenance, captured before the original one-shot effect.
//! Serialized metadata is evidence only; callers must sample the fixed kernel
//! paths again. A matching rule name, handle or generation cannot replace it.
use super::*;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::nm) struct Epoch {
    boot_id: uuid::Uuid,
    namespace_device: u64,
    namespace_inode: u64,
}
#[cfg(test)]
thread_local! {
    static STORAGE_EPOCH: std::cell::RefCell<Option<Epoch>> = const { std::cell::RefCell::new(None) };
}
impl Epoch {
    pub(in crate::nm) fn from_boot_receipt(boot_id: uuid::Uuid, namespace_device: u64, namespace_inode: u64) -> Result<Self> {
        let epoch = Self { boot_id, namespace_device, namespace_inode };
        epoch.validate()?;
        Ok(epoch)
    }

    pub(in crate::nm) fn boot_id(&self) -> uuid::Uuid { self.boot_id }

    pub(super) fn identifies(&self, boot_id: uuid::Uuid, namespace_device: u64, namespace_inode: u64) -> bool {
        (self.boot_id, self.namespace_device, self.namespace_inode) == (boot_id, namespace_device, namespace_inode)
    }
    pub(in crate::nm) fn validate(&self) -> Result<()> {
        ensure!(
            !self.boot_id.is_nil() && self.namespace_device > 0 && self.namespace_inode > 0,
            "CONFLICT: native physical epoch identity"
        );
        Ok(())
    }
    pub(in crate::nm) fn require(&self, actual: &Self) -> Result<()> {
        self.validate()?;
        actual.validate()?;
        ensure!(
            self == actual,
            "OUTCOME_UNKNOWN: original native boot or network namespace changed;preserve original evidence"
        );
        Ok(())
    }
    #[cfg(any(target_os = "linux", test))]
    fn sample(
        mut boot: impl FnMut() -> Result<String>,
        mut namespace: impl FnMut() -> Result<(u64, u64)>,
    ) -> Result<Self> {
        let text = boot()?;
        ensure!(text.len() <= 64, "CONFLICT: native boot identity bounds");
        let canonical = text.strip_suffix('\n').unwrap_or(&text);
        let boot_id =
            uuid::Uuid::parse_str(canonical).context("CONFLICT: native boot identity encoding")?;
        ensure!(
            canonical == boot_id.to_string(),
            "CONFLICT: native boot identity is not canonical"
        );
        let (namespace_device, namespace_inode) = namespace()?;
        let value = Self {
            boot_id,
            namespace_device,
            namespace_inode,
        };
        value.validate()?;
        ensure!(
            boot()? == text && namespace()? == (namespace_device, namespace_inode),
            "CONFLICT: native physical epoch changed during observation"
        );
        Ok(value)
    }
    #[cfg(target_os = "linux")]
    pub(in crate::nm) fn capture() -> Result<Self> {
        #[cfg(test)]
        if let Some(epoch) = STORAGE_EPOCH.with(|slot| slot.borrow().clone()) {
            return Ok(epoch);
        }
        use std::os::unix::fs::MetadataExt;
        Self::sample(
            || {
                std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                    .context("UNSUPPORTED: actual native kernel boot identity unavailable")
            },
            || {
                // thread-self is the namespace in which this thread opens its
                // netlink socket. Holding the fd pins the sampled ns identity.
                let file = std::fs::File::open("/proc/thread-self/ns/net")
                    .context("UNSUPPORTED: actual native network namespace unavailable")?;
                let metadata = file.metadata()?;
                Ok((metadata.dev(), metadata.ino()))
            },
        )
    }
    #[cfg(not(target_os = "linux"))]
    pub(in crate::nm) fn capture() -> Result<Self> {
        #[cfg(test)]
        if let Some(epoch) = STORAGE_EPOCH.with(|slot| slot.borrow().clone()) {
            return Ok(epoch);
        }
        anyhow::bail!("UNSUPPORTED: native physical epoch requires actual Linux proc identity")
    }
    /// Explicit scoped dependency for controller tests whose JVM/kernel are
    /// already synthetic. No payload, environment or normal binary can select it.
    #[cfg(test)]
    pub(in crate::nm) fn with_storage_fixture<T>(callback: impl FnOnce() -> T) -> T {
        struct Reset(Option<Epoch>);
        impl Drop for Reset {
            fn drop(&mut self) {
                STORAGE_EPOCH.with(|slot| slot.replace(self.0.take()));
            }
        }
        let _reset = Reset(STORAGE_EPOCH.with(|slot| slot.replace(Some(Self::storage_fixture()))));
        callback()
    }
    #[cfg(test)]
    pub(in crate::nm) fn storage_fixture() -> Self {
        // Explicit injected storage fixture, never a registered/live authority.
        Self {
            boot_id: uuid::Uuid::from_u128(0xa5a5),
            namespace_device: 7,
            namespace_inode: 19,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const BOOT: &str = "00000000-0000-0000-0000-00000000a5a5\n";
    #[test]
    fn scoped_storage_epoch_is_explicit_nested_and_restored_even_after_panic() {
        let before = Epoch::capture();
        Epoch::with_storage_fixture(|| {
            Epoch::storage_fixture()
                .require(&Epoch::capture().unwrap())
                .unwrap();
            Epoch::with_storage_fixture(|| {
                Epoch::storage_fixture()
                    .require(&Epoch::capture().unwrap())
                    .unwrap()
            });
            Epoch::storage_fixture()
                .require(&Epoch::capture().unwrap())
                .unwrap();
        });
        let outcome = std::panic::catch_unwind(|| {
            Epoch::with_storage_fixture(|| {
                panic!("explicit interrupted storage fixture");
            });
        });
        assert!(outcome.is_err());
        match before {
            Ok(epoch) => epoch.require(&Epoch::capture().unwrap()).unwrap(),
            Err(_) => assert!(Epoch::capture().is_err()),
        }
    }
    #[test]
    fn physical_epoch_is_stable_and_rejects_reused_namespace_identity_on_a_new_boot() {
        let epoch = Epoch::sample(|| Ok(BOOT.into()), || Ok((7, 19))).unwrap();
        epoch.require(&Epoch::storage_fixture()).unwrap();
        for other in [
            Epoch {
                boot_id: uuid::Uuid::from_u128(0xa5a6),
                ..epoch.clone()
            },
            Epoch {
                namespace_device: 8,
                ..epoch.clone()
            },
            Epoch {
                namespace_inode: 20,
                ..epoch.clone()
            },
        ] {
            assert!(epoch.require(&other).is_err());
        }
    }
    #[test]
    fn epoch_sampling_rejects_noncanonical_nil_missing_or_racing_kernel_inputs() {
        for text in [
            "",
            "garbage",
            "00000000-0000-0000-0000-000000000000",
            "0000000000000000000000000000a5a5",
            "00000000-0000-0000-0000-00000000A5A5\n",
            " 00000000-0000-0000-0000-00000000a5a5\n",
        ] {
            assert!(Epoch::sample(|| Ok(text.into()), || Ok((7, 19))).is_err());
        }
        for identity in [(0, 19), (7, 0)] {
            assert!(Epoch::sample(|| Ok(BOOT.into()), || Ok(identity)).is_err());
        }
        let mut count = 0;
        assert!(
            Epoch::sample(
                || {
                    count += 1;
                    Ok(if count == 1 {
                        BOOT.into()
                    } else {
                        uuid::Uuid::new_v4().to_string()
                    })
                },
                || Ok((7, 19))
            )
            .is_err()
        );
        let mut count = 0;
        assert!(
            Epoch::sample(
                || Ok(BOOT.into()),
                || {
                    count += 1;
                    Ok((7, count))
                }
            )
            .is_err()
        );
        assert!(Epoch::sample(|| anyhow::bail!("missing"), || Ok((7, 19))).is_err());
    }
    #[test]
    fn serialized_epoch_remains_strict_evidence_and_cannot_supply_a_live_sample() {
        let epoch = Epoch::storage_fixture();
        let mut value = serde_json::to_value(&epoch).unwrap();
        value["ownerGrant"] = json!(true);
        assert!(serde_json::from_value::<Epoch>(value).is_err());
        let mut bad = epoch;
        bad.namespace_inode = 0;
        assert!(bad.validate().is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn actual_linux_epoch_capture_only_observes_the_current_kernel_namespace() {
        let first = Epoch::capture().unwrap();
        first.require(&Epoch::capture().unwrap()).unwrap();
    }
}
