use super::*;

impl Native {
    async fn unproven(self: &Arc<Self>, j: &mut Journal, reason: &str) -> Result<Value> {
        j.state = State::RecoveryRequired;
        j.error = Some(reason.into());
        let n = self.clone();
        let j = j.clone();
        tokio::task::spawn_blocking(move || n.persist(&j)).await??;
        anyhow::bail!(
            "OUTCOME_UNKNOWN: system control requires inspection; never repeat the action"
        )
    }
    fn deadline(j: &Journal, c: &Config) -> Result<u64> {
        Ok(j.issued_at.context("CONFLICT: system issue time missing")?
            + (c.restart_timeout_seconds
                + c.observation_seconds
                + if j.action == Action::Reboot { 120 } else { 0 })
                * 1000)
    }
    pub(super) async fn verify_and_complete(
        self: &Arc<Self>,
        j: &mut Journal,
        c: &Config,
        local: &crate::local::Local,
    ) -> Result<Value> {
        ensure!(
            j.request_accepted && j.after_boot_id.is_some(),
            "OUTCOME_UNKNOWN: action is not acknowledged"
        );
        let deadline = Self::deadline(j, c)?;
        let observation = if let Some(spec) = &j.probe {
            let mut report = None;
            loop {
                if now() >= deadline {
                    break json!({"configured":true,"verified":false,"error":"APPLICATION_READINESS_TIMEOUT","report":report});
                }
                let n = self.clone();
                let name = j.unit.clone();
                let (current, boot) = tokio::task::spawn_blocking(move || {
                    Ok::<_, anyhow::Error>((n.unit(&name)?, n.boot()?))
                })
                .await??;
                if Some(&current) != j.after.as_ref() || Some(&boot) != j.after_boot_id.as_ref() {
                    return self.unproven(j,"Mapped process or boot identity changed during application verification").await;
                }
                match local.ordinary_verification(spec.parameters()).await {
                    Ok((value, instance, epoch)) => {
                        if serde_json::to_vec(&value)?.len() > 128 << 10 {
                            break json!({"configured":true,"verified":false,"error":"APPLICATION_OBSERVATION_TOO_LARGE","report":null});
                        }
                        let decoded = serde_json::from_value::<crate::ordinary_observation::Report>(
                            value.clone(),
                        );
                        let valid = decoded.as_ref().is_ok_and(|r| {
                            r.schema == 2
                                && spec.validate(r, current.pid).is_ok()
                                && r.providers.iter().all(|p| !p.available || p.unique)
                        });
                        if !valid {
                            break json!({"configured":true,"verified":false,"error":"APPLICATION_OBSERVATION_INVALID","report":value});
                        }
                        let decoded = decoded.unwrap();
                        if decoded.ready {
                            let passed = decoded.checks.iter().all(|s| s.passed);
                            break json!({"configured":true,"verified":passed,"error":if passed{None}else{Some("APPLICATION_CHECK_FAILED")},"report":value,"agentInstanceId":instance,"bridgeEpoch":epoch});
                        }
                        report = Some(value);
                    }
                    Err("KURA_UNAVAILABLE" | "UNSUPPORTED" | "TIMEOUT") => {}
                    Err(_) => {
                        break json!({"configured":true,"verified":false,"error":"APPLICATION_BRIDGE_REJECTED","report":report});
                    }
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        } else {
            json!({"configured":false,"verified":false,"error":null,"report":null})
        };
        let n = self.clone();
        let unit = j.unit.clone();
        let raw = j.config_sha256.clone();
        let def = j.definition_sha256.clone();
        let after = j.after.clone();
        let boot = j.after_boot_id.clone();
        let unchanged = tokio::task::spawn_blocking(move || {
            let (_, bytes, definition, _) = n.inputs()?;
            ensure!(
                durable::hash(&bytes) == raw
                    && definition == def
                    && Some(n.unit(&unit)?) == after
                    && Some(n.boot()?) == boot,
                "CONFLICT: system verification inputs changed"
            );
            Ok::<_, anyhow::Error>(())
        })
        .await?;
        if unchanged.is_err() {
            return self
                .unproven(
                    j,
                    "Fixed service/grant/boot changed before system completion",
                )
                .await;
        }
        j.observation = Some(observation);
        let mut completed = j.clone();
        let n = self.clone();
        // The original observation is durable before the create-only receipt.
        tokio::task::spawn_blocking(move || {
            n.persist(&completed)?;
            n.commit_result(&mut completed)
        })
        .await?
    }
    pub(super) async fn observe_pending(
        self: &Arc<Self>,
        local: crate::local::Local,
    ) -> Result<()> {
        let n = self.clone();
        let saved = tokio::task::spawn_blocking(move || {
            let Some(j) = n.journal()? else {
                return Ok(None);
            };
            if matches!(
                j.state,
                State::Prepared | State::Completed | State::Cancelled | State::RecoveryRequired
            ) {
                return Ok(None);
            }
            let lease = match n.settlement_lock() {
                Ok(v) => v,
                Err(e) if e.to_string().starts_with("CONFLICT") => return Ok(None),
                Err(e) => return Err(e),
            };
            // Issuing/completion can finish between the first observation and
            // obtaining the OS lease. Never overwrite its newer durable state
            // with the pre-lock snapshot (including a stale ISSUING intent).
            let Some(j) = n.journal()? else {
                return Ok(None);
            };
            if matches!(
                j.state,
                State::Prepared | State::Completed | State::Cancelled | State::RecoveryRequired
            ) {
                return Ok(None);
            }
            // Never infer an action from a different current PID. A fully
            // persisted receipt can be completed without any live observation.
            if n.file(&j.id, ".completed.json").try_exists()? {
                let mut j = j;
                if n.recover_completed(&mut j).is_err() {
                    j.state = State::RecoveryRequired;
                    j.error = Some(
                        "Retained system completion evidence changed; preserve original files"
                            .into(),
                    );
                    n.persist(&j)?;
                }
                return Ok(None);
            }
            Ok::<_, anyhow::Error>(Some((lease, j)))
        })
        .await??;
        let Some((_lease, mut j)) = saved else {
            return Ok(());
        };
        if j.state == State::Issuing || !j.request_accepted {
            let _=self.unproven(&mut j,"Interrupted before a durable systemd acknowledgement; preserve original intent").await;
            return Ok(());
        }
        let n = self.clone();
        let inputs = tokio::task::spawn_blocking(move || n.inputs()).await?;
        let c = match inputs {
            Ok((c, raw, definition, profile))
                if durable::hash(&raw) == j.config_sha256
                    && definition == j.definition_sha256
                    && serde_json::to_value(&profile)? == serde_json::to_value(&j.profile)? =>
            {
                c
            }
            _ => {
                let _ = self
                    .unproven(
                        &mut j,
                        "System control grant or mapped unit changed after acknowledgement",
                    )
                    .await;
                return Ok(());
            }
        };
        let deadline = Self::deadline(&j, &c)?;
        if now() >= deadline
            && j.action == Action::Reboot
            && j.after_boot_id
                .as_ref()
                .is_some_and(|s| s != &j.before_boot_id)
        {
            let n = self.clone();
            let unit = j.unit.clone();
            let (boot, after) = tokio::task::spawn_blocking(move || {
                Ok::<_, anyhow::Error>((n.boot()?, n.unit(&unit)?))
            })
            .await??;
            if Some(&boot) == j.after_boot_id.as_ref() && !after.running() {
                j.after = Some(after);
                j.observation = Some(
                    json!({"configured":j.profile.is_some(),"verified":false,"error":"MAPPED_SERVICE_UNAVAILABLE_AFTER_BOOT","report":null}),
                );
                let n = self.clone();
                tokio::task::spawn_blocking(move || {
                    n.persist(&j)?;
                    n.commit_result(&mut j)
                })
                .await??;
                return Ok(());
            }
        }
        if now() < j.issued_at.unwrap() || now() >= deadline {
            let _ = self
                .unproven(
                    &mut j,
                    "System transition deadline or wall clock is unproven",
                )
                .await;
            return Ok(());
        }
        if j.action == Action::Reboot && j.state == State::AwaitingBoot {
            let n = self.clone();
            let name = j.unit.clone();
            let (boot, target) = tokio::task::spawn_blocking(move || {
                Ok::<_, anyhow::Error>((n.boot()?, n.unit(&name)?))
            })
            .await??;
            if boot == j.before_boot_id {
                return Ok(());
            }
            if j.after_boot_id.as_ref().is_some_and(|old| *old != boot) {
                let _ = self
                    .unproven(&mut j, "A second unexpected boot was observed")
                    .await;
                return Ok(());
            }
            j.after_boot_id = Some(boot);
            j.after = Some(target.clone());
            // Boot and service recovery are separate facts. Give an enabled
            // target its bounded startup window; failure never schedules again.
            if !target.running() {
                let n = self.clone();
                let saved = j.clone();
                tokio::task::spawn_blocking(move || n.persist(&saved)).await??;
                return Ok(());
            }
            j.state = State::VerifyingApplication;
            let n = self.clone();
            let snapshot = j.clone();
            tokio::task::spawn_blocking(move || n.persist(&snapshot)).await??;
        }
        if j.after.as_ref().is_some_and(Unit::running) {
            self.verify_and_complete(&mut j, &c, &local).await?;
        } else if j.action == Action::Reboot
            && j.after_boot_id.as_deref() != Some(&j.before_boot_id)
        {
            j.observation = Some(
                json!({"configured":j.profile.is_some(),"verified":false,"error":"MAPPED_SERVICE_UNAVAILABLE_AFTER_BOOT","report":null}),
            );
            let n = self.clone();
            tokio::task::spawn_blocking(move || {
                n.persist(&j)?;
                n.commit_result(&mut j)
            })
            .await??;
        } else {
            let _ = self
                .unproven(
                    &mut j,
                    "Acknowledged system transition has no bound process observation",
                )
                .await;
        }
        Ok(())
    }
}
