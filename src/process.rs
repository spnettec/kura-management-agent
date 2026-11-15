//! Bounded child execution. Call only from blocking workers, never a transport
//! reader. A timeout terminates the complete child process group and reaps it.
use anyhow::{Result, ensure};
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: u64 = 1_048_576;
#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub fn run(
    program: &Path,
    args: &[&str],
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Output> {
    run_inner(program, args, input, timeout, false)
}

/// Java must not inherit injection options (JAVA_TOOL_OPTIONS, CLASSPATH,
/// JDK_JAVA_OPTIONS or dynamic-loader variables) from the long-running agent.
pub fn run_isolated(program: &Path, args: &[&str], timeout: Duration) -> Result<Output> {
    run_inner(program, args, None, timeout, true)
}

fn run_inner(
    program: &Path,
    args: &[&str],
    input: Option<&[u8]>,
    timeout: Duration,
    isolated: bool,
) -> Result<Output> {
    let mut command = Command::new(program);
    if isolated {
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C");
    }
    let mut child = command
        .args(args)
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let stderr = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let writer = input.map(|bytes| {
        let bytes = bytes.to_vec();
        let mut stdin = child.stdin.take().unwrap();
        std::thread::spawn(move || stdin.write_all(&bytes))
    });
    let deadline = Instant::now() + timeout;
    let completion = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(Some(status)),
            Err(error) => break Err(error),
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            break Ok(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Kill/reap even on poll errors. Descendants must not hold inherited pipes.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let reaped = child.wait();
    let stdout_result = stdout.join();
    let stderr_result = stderr.join();
    let writer_result = writer.map(|worker| worker.join());
    let status = completion?
        .ok_or_else(|| anyhow::anyhow!("TIMEOUT: system command may have partially applied"))?;
    reaped?;
    let stdout = stdout_result.map_err(|_| anyhow::anyhow!("INTERNAL: output worker"))??;
    let stderr = stderr_result.map_err(|_| anyhow::anyhow!("INTERNAL: error worker"))??;
    if let Some(result) = writer_result {
        result.map_err(|_| anyhow::anyhow!("INTERNAL: input worker"))??;
    }
    ensure!(
        stdout.len() as u64 <= OUTPUT_LIMIT && stderr.len() as u64 <= OUTPUT_LIMIT,
        "RESOURCE_EXHAUSTED: system command output"
    );
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn isolated_java_child_receives_only_fixed_environment() {
        let output = run_isolated(Path::new("/usr/bin/env"), &[], Duration::from_secs(2)).unwrap();
        assert!(output.status.success());
        let mut lines: Vec<_> = std::str::from_utf8(&output.stdout)
            .unwrap()
            .lines()
            .collect();
        lines.sort();
        assert_eq!(lines, vec!["LC_ALL=C", "PATH=/usr/bin:/bin"]);
    }
    #[test]
    fn timeout_reaps_process_group_and_output_is_bounded() {
        let start = Instant::now();
        assert!(
            run(
                Path::new("/bin/sh"),
                &["-c", "sleep 30"],
                None,
                Duration::from_millis(40)
            )
            .unwrap_err()
            .to_string()
            .starts_with("TIMEOUT")
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        let result = run(
            Path::new("/bin/sh"),
            &["-c", "cat; printf error >&2"],
            Some(b"input"),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(result.stdout, b"input");
        assert_eq!(result.stderr, b"error");
    }
}
