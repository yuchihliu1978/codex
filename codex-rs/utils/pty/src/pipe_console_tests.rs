use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use winapi::um::winbase::DETACHED_PROCESS;
use winapi::um::wincon::GetConsoleProcessList;
use winapi::um::wincon::GetConsoleWindow;

use crate::SpawnedProcess;
use crate::spawn_pipe_process;
use crate::spawn_pipe_process_no_stdin;

const ROLE_ENV: &str = "CODEX_PTY_PIPE_CONSOLE_ROLE";
const NONCE_ENV: &str = "CODEX_PTY_PIPE_CONSOLE_NONCE";
const TEMP_ENV: &str = "CODEX_PTY_PIPE_CONSOLE_TEMP";
const CASE_ENV: &str = "CODEX_PTY_PIPE_CONSOLE_CASE";
const EXIT_ENV: &str = "CODEX_PTY_PIPE_CONSOLE_EXIT";
const WORKER_TEST: &str = "tests::pipe_console_tests::pipe_console_detached_worker";
const PROBE_TEST: &str = "tests::pipe_console_tests::pipe_console_probe";
const PROBE_STDOUT_PREFIX: &str = "__CODEX_PIPE_PROBE__";
const PROBE_STDERR_PREFIX: &str = "__CODEX_PIPE_PROBE_ERR__";
const WORKER_RESULT_FILE: &str = "worker-result.txt";

struct PipeConsoleCase {
    name: &'static str,
    piped: bool,
    payload: &'static [u8],
    exit_code: i32,
}

const PIPE_CONSOLE_CASES: [PipeConsoleCase; 2] = [
    PipeConsoleCase {
        name: "piped",
        piped: true,
        payload: b"piped-roundtrip",
        exit_code: 41,
    },
    PipeConsoleCase {
        name: "null",
        piped: false,
        payload: b"",
        exit_code: 43,
    },
];

struct ProbeReport {
    case_name: String,
    nonce: String,
    hwnd: usize,
    pid: u32,
    stdin_hex: String,
    eof: u32,
    cwd_ok: u32,
    clients: u32,
}

fn console_attachment() -> (usize, u32) {
    let hwnd = unsafe { GetConsoleWindow() as usize };
    let mut pids = [0u32; 1];
    let clients = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) };
    (hwnd, clients)
}

fn console_client_count() -> u32 {
    let mut pids = [0u32; 64];
    unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn cwd_matches(temp: &str) -> bool {
    let Ok(current) = std::env::current_dir() else {
        return false;
    };
    let Ok(expected) = std::fs::canonicalize(temp) else {
        return false;
    };
    let Ok(current) = std::fs::canonicalize(current) else {
        return false;
    };
    current == expected
}

fn report_and_exit(line: &str, err_line: &str, code: i32) -> ! {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let stdout_ok = writeln!(stdout, "{line}").is_ok() && stdout.flush().is_ok();
    let stderr_ok = writeln!(stderr, "{err_line}").is_ok() && stderr.flush().is_ok();
    std::process::exit(if stdout_ok && stderr_ok { code } else { 2 });
}

fn probe_report() -> anyhow::Result<(String, String, i32)> {
    let nonce = std::env::var(NONCE_ENV)?;
    let temp = std::env::var(TEMP_ENV)?;
    let case_name = std::env::var(CASE_ENV)?;
    let exit_code: i32 = std::env::var(EXIT_ENV)?.parse()?;
    let mut stdin = Vec::new();
    let limit = 64 * 1024;
    std::io::stdin().take(limit).read_to_end(&mut stdin)?;
    let eof = u32::from(stdin.len() < limit);
    let (hwnd, _) = console_attachment();
    let line = format!(
        "{PROBE_STDOUT_PREFIX} case={case_name} nonce={nonce} hwnd={hwnd} pid={} stdin={} eof={eof} cwd={} clients={}",
        std::process::id(),
        hex_encode(&stdin),
        u32::from(cwd_matches(&temp)),
        console_client_count(),
    );
    let err_line = format!("{PROBE_STDERR_PREFIX} case={case_name} nonce={nonce}");
    Ok((line, err_line, exit_code))
}

fn parse_probe_report(text: &str) -> anyhow::Result<ProbeReport> {
    let line = text
        .lines()
        .find_map(|line| line.trim().strip_prefix(PROBE_STDOUT_PREFIX))
        .context("missing probe report")?;
    let mut fields = HashMap::<String, String>::new();
    for token in line.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        fields.insert(key.to_string(), value.to_string());
    }
    let required = |key: &str| {
        fields
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("probe report missing {key}"))
    };
    Ok(ProbeReport {
        case_name: required("case")?,
        nonce: required("nonce")?,
        hwnd: required("hwnd")?.parse()?,
        pid: required("pid")?.parse()?,
        stdin_hex: required("stdin")?,
        eof: required("eof")?.parse()?,
        cwd_ok: required("cwd")?.parse()?,
        clients: required("clients")?.parse()?,
    })
}

async fn collect_chunks(mut receiver: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    let mut collected = Vec::new();
    while let Some(chunk) = receiver.recv().await {
        collected.extend_from_slice(&chunk);
    }
    collected
}

async fn run_pipe_console_case(
    case: &PipeConsoleCase,
    program: &Path,
    temp: &Path,
    nonce: &str,
) -> anyhow::Result<()> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    env.insert(ROLE_ENV.to_string(), "probe".to_string());
    env.insert(NONCE_ENV.to_string(), nonce.to_string());
    env.insert(TEMP_ENV.to_string(), temp.to_string_lossy().into_owned());
    env.insert(CASE_ENV.to_string(), case.name.to_string());
    env.insert(EXIT_ENV.to_string(), case.exit_code.to_string());
    let args = vec![
        PROBE_TEST.to_string(),
        "--exact".to_string(),
        "--ignored".to_string(),
        "--nocapture".to_string(),
        "--test-threads=1".to_string(),
    ];
    let spawned = if case.piped {
        spawn_pipe_process(program, &args, temp, &env, /*arg0*/ &None, &[]).await?
    } else {
        spawn_pipe_process_no_stdin(program, &args, temp, &env, /*arg0*/ &None, &[]).await?
    };
    let SpawnedProcess {
        session,
        stdout_rx,
        stderr_rx,
        exit_rx,
    } = spawned;
    if case.piped {
        let writer = session.writer_sender();
        writer.send(case.payload.to_vec()).await?;
        drop(writer);
        session.close_stdin();
    }
    let stdout_task = tokio::spawn(collect_chunks(stdout_rx));
    let stderr_task = tokio::spawn(collect_chunks(stderr_rx));
    let exit_code = tokio::time::timeout(Duration::from_secs(20), exit_rx)
        .await
        .context(format!("{} probe timed out", case.name))?
        .unwrap_or(-1);
    let stdout = tokio::time::timeout(Duration::from_secs(5), stdout_task)
        .await
        .context(format!("{} probe stdout timed out", case.name))??;
    let stderr = tokio::time::timeout(Duration::from_secs(5), stderr_task)
        .await
        .context(format!("{} probe stderr timed out", case.name))??;
    drop(session);

    let stdout_text = String::from_utf8_lossy(&stdout);
    let stderr_text = String::from_utf8_lossy(&stderr);
    let report = parse_probe_report(&stdout_text).with_context(|| {
        format!(
            "{} probe output stdout={stdout_text:?} stderr={stderr_text:?}",
            case.name
        )
    })?;
    anyhow::ensure!(
        report.case_name == case.name,
        "{} probe case was {}",
        case.name,
        report.case_name
    );
    anyhow::ensure!(
        report.nonce == nonce,
        "{} probe nonce was {}",
        case.name,
        report.nonce
    );
    anyhow::ensure!(
        report.hwnd == 0,
        "{} console window was present: hwnd={:#x} clients={}",
        case.name,
        report.hwnd,
        report.clients
    );
    anyhow::ensure!(report.pid != 0, "{} probe did not report a pid", case.name);
    anyhow::ensure!(
        report.eof == 1,
        "{} probe did not observe stdin EOF",
        case.name
    );
    anyhow::ensure!(
        report.stdin_hex == hex_encode(case.payload),
        "{} stdin was {}, expected {}",
        case.name,
        report.stdin_hex,
        hex_encode(case.payload)
    );
    anyhow::ensure!(
        report.cwd_ok == 1,
        "{} probe cwd did not match the pipe spawn cwd",
        case.name
    );
    anyhow::ensure!(
        stderr_text.contains(&format!(
            "{PROBE_STDERR_PREFIX} case={} nonce={nonce}",
            case.name
        )),
        "{} stderr marker missing: {stderr_text:?}",
        case.name
    );
    anyhow::ensure!(
        exit_code == case.exit_code,
        "{} probe exit code was {exit_code}",
        case.name
    );
    Ok(())
}

async fn read_pipe_to_end<R>(mut pipe: R) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut collected = Vec::new();
    pipe.read_to_end(&mut collected).await?;
    Ok(collected)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detached_parent_pipe_children_have_null_console_window() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let nonce = format!("{}-{nanos:x}", std::process::id());
    let program = std::env::current_exe()?;
    let mut command = Command::new(&program);
    command
        .arg("--exact")
        .arg(WORKER_TEST)
        .arg("--ignored")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .creation_flags(DETACHED_PROCESS)
        .env(ROLE_ENV, "worker")
        .env(NONCE_ENV, &nonce)
        .env(TEMP_ENV, temp.path());
    let mut child = command.spawn()?;
    drop(child.stdin.take());
    let stdout_pipe = child
        .stdout
        .take()
        .context("detached worker stdout was not piped")?;
    let stderr_pipe = child
        .stderr
        .take()
        .context("detached worker stderr was not piped")?;
    let finished = async {
        let (status, stdout, stderr) = tokio::try_join!(
            async { child.wait().await.map_err(anyhow::Error::from) },
            read_pipe_to_end(stdout_pipe),
            read_pipe_to_end(stderr_pipe),
        )?;
        Ok::<_, anyhow::Error>((status, stdout, stderr))
    };
    let (status, stdout, stderr) =
        match tokio::time::timeout(Duration::from_secs(60), finished).await {
            Ok(result) => result?,
            Err(_) => anyhow::bail!("detached pipe console worker timed out"),
        };
    let result = std::fs::read_to_string(temp.path().join(WORKER_RESULT_FILE)).unwrap_or_default();
    anyhow::ensure!(
        status.success() && result.trim() == format!("ok {nonce}"),
        "detached pipe console worker failed: status={status} result={result:?} stdout={} stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    Ok(())
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipe_console_detached_worker() -> anyhow::Result<()> {
    if std::env::var(ROLE_ENV).ok().as_deref() != Some("worker") {
        return Ok(());
    }
    let nonce = std::env::var(NONCE_ENV)?;
    let temp = std::env::var(TEMP_ENV)?;
    let temp = Path::new(&temp);
    let (hwnd, clients) = console_attachment();
    anyhow::ensure!(
        hwnd == 0 && clients == 0,
        "detached worker fixture is not detached: hwnd={hwnd:#x} clients={clients}"
    );
    let program = std::env::current_exe()?;
    for case in &PIPE_CONSOLE_CASES {
        run_pipe_console_case(case, &program, temp, &nonce).await?;
    }
    std::fs::write(temp.join(WORKER_RESULT_FILE), format!("ok {nonce}\n"))?;
    println!("__CODEX_PIPE_WORKER_OK__ {nonce}");
    Ok(())
}

#[ignore]
#[test]
fn pipe_console_probe() {
    if std::env::var(ROLE_ENV).ok().as_deref() != Some("probe") {
        return;
    }
    match probe_report() {
        Ok((line, err_line, code)) => report_and_exit(&line, &err_line, code),
        Err(_) => std::process::exit(2),
    }
}
