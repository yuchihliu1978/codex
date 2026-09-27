use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use codex_protocol::protocol::HookEventName;
use codex_protocol::protocol::HookSource;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_utils_pty::JobObject;
use futures::future::join;
use tempfile::tempdir;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::process::Child;
use tokio::process::Command;
use tokio::time::sleep;
use tokio::time::timeout;
use winapi::shared::minwindef::DWORD;
use winapi::um::consoleapi::GetConsoleCP;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::jobapi::IsProcessInJob;
use winapi::um::minwinbase::STILL_ACTIVE;
use winapi::um::processthreadsapi::GetExitCodeProcess;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::tlhelp32::CreateToolhelp32Snapshot;
use winapi::um::tlhelp32::PROCESSENTRY32W;
use winapi::um::tlhelp32::Process32FirstW;
use winapi::um::tlhelp32::Process32NextW;
use winapi::um::tlhelp32::TH32CS_SNAPPROCESS;
use winapi::um::winbase::CREATE_NO_WINDOW;
use winapi::um::winbase::DETACHED_PROCESS;
use winapi::um::wincon::AttachConsole;
use winapi::um::wincon::FreeConsole;
use winapi::um::wincon::GetConsoleProcessList;
use winapi::um::wincon::GetConsoleWindow;
use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;

use super::super::CommandShell;
use super::super::ConfiguredHandler;
use super::super::ConfiguredHandlerKind;
use super::super::WindowsHookLaunchFault;
use super::super::WindowsHookSpawnPath;
use super::super::run_command;
use super::super::set_hook_launch_fault;
use super::super::spawn_no_window_process;
use super::super::spawn_taskkill_tree;
use super::super::spawn_windows_command_hook;
use super::super::take_hook_spawn_path;
use super::runtime;
use super::schedule;

const FIXTURE: &str = "engine::command_runner::tests::windows_tests::windows_hook_process_fixture";
const ROLE_ENV: &str = "CODEX_HOOK_LAUNCH_ROLE";
const CASE_ENV: &str = "CODEX_HOOK_LAUNCH_CASE";
const NONCE_ENV: &str = "CODEX_HOOK_LAUNCH_NONCE";
const TEMP_ENV: &str = "CODEX_HOOK_LAUNCH_TEMP";
const EXIT_ENV: &str = "CODEX_HOOK_LAUNCH_EXIT";
const STDIN_ENV: &str = "CODEX_HOOK_LAUNCH_STDIN";
const PID_FILE_ENV: &str = "CODEX_HOOK_LAUNCH_PID_FILE";
const PROBE_PREFIX: &str = "__CODEX_HOOK_PROBE__";
const PROBE_ERR_PREFIX: &str = "__CODEX_HOOK_PROBE_ERR__";
const PIDS_PREFIX: &str = "__CODEX_HOOK_PIDS__";
const RESULT_FILE: &str = "worker-result.txt";
const STDIN_PAYLOAD: &[u8] = b"hook-stdin";

struct LaunchCase {
    name: &'static str,
    fault: WindowsHookLaunchFault,
    path: WindowsHookSpawnPath,
    expect_job: bool,
    exit_code: i32,
}

fn launch_cases() -> [LaunchCase; 3] {
    [
        LaunchCase {
            name: "contained",
            fault: WindowsHookLaunchFault::None,
            path: WindowsHookSpawnPath::Contained,
            expect_job: true,
            exit_code: 41,
        },
        LaunchCase {
            name: "job-unavailable",
            fault: WindowsHookLaunchFault::JobCreate,
            path: WindowsHookSpawnPath::JobUnavailable,
            expect_job: false,
            exit_code: 42,
        },
        LaunchCase {
            name: "contained-retry",
            fault: WindowsHookLaunchFault::ContainedAfterSuspend,
            path: WindowsHookSpawnPath::ContainedRetry,
            expect_job: false,
            exit_code: 43,
        },
    ]
}

fn fixture_args() -> Vec<String> {
    vec![
        "--exact".to_string(),
        FIXTURE.to_string(),
        "--ignored".to_string(),
        "--nocapture".to_string(),
        "--test-threads=1".to_string(),
    ]
}

fn io_err(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn console_state() -> (usize, u32, u32) {
    let hwnd = unsafe { GetConsoleWindow() as usize };
    let cp = unsafe { GetConsoleCP() };
    let mut pids = [0u32; 1];
    let clients = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) };
    (hwnd, cp, clients)
}

fn foreign_process_has_console(pid: u32) -> bool {
    let attached = unsafe { AttachConsole(pid) };
    if attached == 0 {
        return false;
    }
    // CREATE_NO_WINDOW may retain a headless console and a nonzero code page.
    // Attaching alone does not establish that a console window exists.
    let has_window = !unsafe { GetConsoleWindow() }.is_null();
    unsafe { FreeConsole() };
    has_window
}

fn process_is_active(pid: u32) -> bool {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            /*bInheritHandle*/ 0,
            pid,
        )
    };
    if handle.is_null() {
        return false;
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    let mut code: DWORD = 0;
    let ok = unsafe { GetExitCodeProcess(handle.as_raw_handle().cast(), &mut code) };
    ok != 0 && code == STILL_ACTIVE
}

fn direct_child_pids(parent: u32) -> io::Result<Vec<u32>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot.cast()) };
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    if unsafe { Process32FirstW(snapshot.as_raw_handle().cast(), &mut entry) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pids = Vec::new();
    loop {
        if entry.th32ParentProcessID == parent {
            pids.push(entry.th32ProcessID);
        }
        if unsafe { Process32NextW(snapshot.as_raw_handle().cast(), &mut entry) } == 0 {
            break;
        }
    }
    Ok(pids)
}

async fn wait_until_no_extra_children(root: u32, before: &[u32]) -> io::Result<()> {
    let mut extras = Vec::new();
    for _ in 0..40 {
        extras = direct_child_pids(std::process::id())?
            .into_iter()
            .filter(|pid| *pid != root && !before.contains(pid) && process_is_active(*pid))
            .collect();
        if extras.is_empty() {
            return Ok(());
        }
        sleep(Duration::from_millis(50)).await;
    }
    Err(io_err(format!(
        "extra child processes still active: {extras:?}"
    )))
}

async fn wait_until_inactive(pid: u32) -> io::Result<()> {
    for _ in 0..50 {
        if !process_is_active(pid) {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(io_err(format!("process {pid} was still active")))
}

fn cwd_matches(temp: &Path) -> bool {
    let Ok(current) = std::env::current_dir() else {
        return false;
    };
    let Ok(expected) = fs::canonicalize(temp) else {
        return false;
    };
    let Ok(current) = fs::canonicalize(current) else {
        return false;
    };
    current == expected
}

fn probe() -> ! {
    let expect_stdin = std::env::var(STDIN_ENV).ok().as_deref() == Some("1");
    let mut stdin = Vec::new();
    let eof = if expect_stdin {
        let limit = 64 * 1024;
        let _ = std::io::stdin().take(limit as u64).read_to_end(&mut stdin);
        u32::from(stdin.len() < limit)
    } else {
        1
    };
    let (hwnd, cp, clients) = console_state();
    let temp = std::env::var(TEMP_ENV).unwrap_or_default();
    let cwd_ok = u32::from(!temp.is_empty() && cwd_matches(Path::new(&temp)));
    let case_name = std::env::var(CASE_ENV).unwrap_or_default();
    let nonce = std::env::var(NONCE_ENV).unwrap_or_default();
    let exit_code = std::env::var(EXIT_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let line = format!(
        "{PROBE_PREFIX} case={case_name} nonce={nonce} hwnd={hwnd} cp={cp} pid={} stdin={} eof={eof} cwd={cwd_ok} clients={clients}",
        std::process::id(),
        hex_encode(&stdin),
    );
    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "\n{line}");
    let _ = stdout.flush();
    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "{PROBE_ERR_PREFIX} case={case_name} nonce={nonce}");
    let _ = stderr.flush();
    std::process::exit(exit_code);
}

fn spawn_sleeper() -> io::Result<std::process::Child> {
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args(fixture_args())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env(ROLE_ENV, "sleeper");
    command.creation_flags(CREATE_NO_WINDOW);
    command.spawn()
}

fn publish_tree(exit_after: bool) -> io::Result<()> {
    let child = spawn_sleeper()?;
    let child_pid = child.id();
    drop(child);
    let line = format!("{} {child_pid}", std::process::id());
    if let Ok(path) = std::env::var(PID_FILE_ENV) {
        fs::write(path, &line)?;
    }
    let mut stdout = std::io::stdout();
    writeln!(stdout, "\n{PIDS_PREFIX} {line}")?;
    stdout.flush()?;
    if exit_after {
        let code = std::env::var(EXIT_ENV)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(7);
        std::process::exit(code);
    }
    std::thread::sleep(Duration::from_secs(60));
    Ok(())
}

struct KillPid {
    pid: u32,
    handle: OwnedHandle,
}

impl KillPid {
    fn new(pid: u32) -> io::Result<Self> {
        Ok(Self {
            pid,
            handle: JobObject::open_process_handle(pid)?,
        })
    }
}

impl Drop for KillPid {
    fn drop(&mut self) {
        let _ = JobObject::terminate_process_handle(&self.handle);
    }
}

fn handler(
    temp: &Path,
    command: &str,
    env: HashMap<String, String>,
    timeout_sec: u64,
    r#async: bool,
) -> io::Result<ConfiguredHandler> {
    let source = AbsolutePathBuf::try_from(temp.join("hooks.json"))
        .map_err(|err| io_err(err.to_string()))?;
    Ok(ConfiguredHandler {
        builtin: false,
        event_name: if r#async {
            HookEventName::UserPromptSubmit
        } else {
            HookEventName::SessionStart
        },
        matcher: None,
        timeout_sec,
        status_message: None,
        additional_context_limit: Default::default(),
        source_path: source.into(),
        source: HookSource::User,
        display_order: 0,
        kind: ConfiguredHandlerKind::Command {
            command: command.to_string(),
            r#async,
            env,
        },
    })
}

fn shell_for_fixture(exe: &Path) -> CommandShell {
    CommandShell {
        program: exe.to_string_lossy().into_owned(),
        args: fixture_args(),
    }
}

fn probe_env(
    case_name: &str,
    nonce: &str,
    temp: &Path,
    exit_code: i32,
    read_stdin: bool,
) -> Vec<(&'static str, String)> {
    let mut env = vec![
        (ROLE_ENV, "probe".to_string()),
        (CASE_ENV, case_name.to_string()),
        (NONCE_ENV, nonce.to_string()),
        (TEMP_ENV, temp.to_string_lossy().into_owned()),
        (EXIT_ENV, exit_code.to_string()),
    ];
    if read_stdin {
        env.push((STDIN_ENV, "1".to_string()));
    }
    env
}

fn apply_env(command: &mut Command, env: &[(&str, String)]) {
    for (key, value) in env {
        command.env(key, value);
    }
}

struct ProbeReport {
    case_name: String,
    nonce: String,
    hwnd: usize,
    cp: u32,
    stdin_hex: String,
    eof: u32,
    cwd_ok: u32,
}

fn parse_probe_report(text: &str) -> io::Result<ProbeReport> {
    let line = text
        .lines()
        .find_map(|line| line.trim().strip_prefix(PROBE_PREFIX))
        .ok_or_else(|| io_err(format!("missing probe report in {text:?}")))?;
    let mut fields = HashMap::<String, String>::new();
    for token in line.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            fields.insert(key.to_string(), value.to_string());
        }
    }
    let required = |key: &str| -> io::Result<String> {
        fields
            .get(key)
            .cloned()
            .ok_or_else(|| io_err(format!("probe report missing {key}")))
    };
    Ok(ProbeReport {
        case_name: required("case")?,
        nonce: required("nonce")?,
        hwnd: required("hwnd")?.parse().map_err(|_| io_err("bad hwnd"))?,
        cp: required("cp")?.parse().map_err(|_| io_err("bad cp"))?,
        stdin_hex: required("stdin")?,
        eof: required("eof")?.parse().map_err(|_| io_err("bad eof"))?,
        cwd_ok: required("cwd")?.parse().map_err(|_| io_err("bad cwd"))?,
    })
}

fn parse_pids(text: &str) -> io::Result<(u32, u32)> {
    let line = text
        .lines()
        .find_map(|line| line.trim().strip_prefix(PIDS_PREFIX))
        .ok_or_else(|| io_err(format!("missing pid report in {text:?}")))?;
    let mut parts = line.split_whitespace();
    let root = parts
        .next()
        .ok_or_else(|| io_err("missing root pid"))?
        .parse()
        .map_err(|_| io_err("bad root pid"))?;
    let child = parts
        .next()
        .ok_or_else(|| io_err("missing child pid"))?
        .parse()
        .map_err(|_| io_err("bad child pid"))?;
    Ok((root, child))
}

async fn read_to_end(mut pipe: impl AsyncRead + Unpin) -> io::Result<Vec<u8>> {
    let mut collected = Vec::new();
    pipe.read_to_end(&mut collected).await?;
    Ok(collected)
}

async fn finish_child(mut child: Child) -> io::Result<(std::process::ExitStatus, String, String)> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io_err("missing stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io_err("missing stderr"))?;
    let joined = timeout(Duration::from_secs(15), async {
        tokio::try_join!(child.wait(), read_to_end(stdout), read_to_end(stderr))
    })
    .await
    .map_err(|_| io_err("child timed out"))?
    .map_err(|err| io_err(err.to_string()))?;
    let (status, stdout, stderr) = joined;
    Ok((
        status,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    ))
}

fn assert_probe_report(
    case_name: &str,
    nonce: &str,
    stdout: &str,
    stderr: &str,
    status: &std::process::ExitStatus,
    exit_code: i32,
    stdin: &[u8],
) -> io::Result<()> {
    let report = parse_probe_report(stdout)?;
    if report.case_name != case_name || report.nonce != nonce {
        return Err(io_err(format!(
            "{case_name} probe identity was {} {}",
            report.case_name, report.nonce
        )));
    }
    if report.hwnd != 0 {
        return Err(io_err(format!(
            "{case_name} console was present hwnd={:#x} cp={}",
            report.hwnd, report.cp
        )));
    }
    if report.eof != 1 || report.cwd_ok != 1 || report.stdin_hex != hex_encode(stdin) {
        return Err(io_err(format!(
            "{case_name} transport eof={} cwd={} stdin={}",
            report.eof, report.cwd_ok, report.stdin_hex
        )));
    }
    if !stderr.contains(&format!(
        "{PROBE_ERR_PREFIX} case={case_name} nonce={nonce}"
    )) {
        return Err(io_err(format!(
            "{case_name} stderr marker missing: {stderr:?}"
        )));
    }
    if status.code() != Some(exit_code) {
        return Err(io_err(format!(
            "{case_name} exit was {:?}, expected {exit_code}",
            status.code()
        )));
    }
    Ok(())
}

async fn run_direct_launch_case(
    exe: &Path,
    temp: &Path,
    nonce: &str,
    case: &LaunchCase,
) -> io::Result<()> {
    let before = direct_child_pids(std::process::id())?;
    let mut command = Command::new(exe);
    command
        .args(fixture_args())
        .current_dir(temp)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    apply_env(
        &mut command,
        &probe_env(case.name, nonce, temp, case.exit_code, true),
    );
    set_hook_launch_fault(case.fault);
    let (mut child, job) = spawn_windows_command_hook(command)?;
    let path = take_hook_spawn_path();
    if path != Some(case.path) || job.is_some() != case.expect_job {
        return Err(io_err(format!(
            "{} path={path:?} job={} expected {:?} job={}",
            case.name,
            job.is_some(),
            case.path,
            case.expect_job
        )));
    }
    let root = child.id().ok_or_else(|| io_err("missing root pid"))?;
    if foreign_process_has_console(root) {
        return Err(io_err(format!("{} root console was attachable", case.name)));
    }
    if let Some(job) = job.as_ref() {
        let process = child
            .raw_handle()
            .ok_or_else(|| io_err("missing root handle"))?;
        let mut in_job = 0;
        let checked =
            unsafe { IsProcessInJob(process.cast(), job.as_raw_handle().cast(), &mut in_job) };
        if checked == 0 || in_job == 0 {
            return Err(io_err(format!("{} root was not in its job", case.name)));
        }
    }
    wait_until_no_extra_children(root, &before).await?;
    {
        let mut stdin = child.stdin.take().ok_or_else(|| io_err("missing stdin"))?;
        stdin.write_all(STDIN_PAYLOAD).await?;
    }
    let (status, stdout, stderr) = finish_child(child).await?;
    assert_probe_report(
        case.name,
        nonce,
        &stdout,
        &stderr,
        &status,
        case.exit_code,
        STDIN_PAYLOAD,
    )?;
    drop(job);
    Ok(())
}

async fn run_cmd_launch_case(exe: &Path, temp: &Path, nonce: &str) -> io::Result<()> {
    let command_line = format!(
        "\"{}\" --exact {FIXTURE} --ignored --nocapture --test-threads=1",
        exe.display()
    );
    let mut command = Command::new("cmd.exe");
    command
        .arg("/D")
        .arg("/C")
        .raw_arg(format!("\"{command_line}\""))
        .current_dir(temp)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    apply_env(
        &mut command,
        &probe_env("cmd-contained", nonce, temp, 44, false),
    );
    let (mut child, job) = spawn_windows_command_hook(command)?;
    if take_hook_spawn_path() != Some(WindowsHookSpawnPath::Contained) || job.is_none() {
        return Err(io_err("cmd launch was not contained"));
    }
    let root = child.id().ok_or_else(|| io_err("missing cmd pid"))?;
    if foreign_process_has_console(root) {
        return Err(io_err("cmd root console was attachable"));
    }
    let (status, stdout, stderr) = finish_child(child).await?;
    let report = parse_probe_report(&stdout)?;
    if report.case_name != "cmd-contained"
        || report.nonce != nonce
        || report.cwd_ok != 1
        || status.code() != Some(44)
        || !stderr.contains(&format!(
            "{PROBE_ERR_PREFIX} case=cmd-contained nonce={nonce}"
        ))
    {
        return Err(io_err(format!(
            "cmd probe failed status={status:?} stdout={stdout:?} stderr={stderr:?}"
        )));
    }
    drop(job);
    Ok(())
}

async fn run_final_spawn_failure(temp: &Path) -> io::Result<()> {
    let before = direct_child_pids(std::process::id())?;
    let mut command = Command::new(temp.join("missing-hook-executable.exe"));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    set_hook_launch_fault(WindowsHookLaunchFault::None);
    let error = spawn_windows_command_hook(command).err();
    let path = take_hook_spawn_path();
    if error.is_none() || path != Some(WindowsHookSpawnPath::ContainedRetry) {
        return Err(io_err(format!(
            "final spawn failure path={path:?} err={}",
            error.is_some()
        )));
    }
    wait_until_no_extra_children(0, &before).await?;
    Ok(())
}

async fn run_command_probe(exe: &Path, temp: &Path, nonce: &str) -> io::Result<()> {
    let (runtime, _results) = runtime();
    let runtime = runtime.reconfigured(shell_for_fixture(exe));
    let input = r#"{"hook":"q7fe9"}"#;
    let env = HashMap::from([
        (ROLE_ENV.to_string(), "probe".to_string()),
        (STDIN_ENV.to_string(), "1".to_string()),
        (CASE_ENV.to_string(), "run-command".to_string()),
        (NONCE_ENV.to_string(), nonce.to_string()),
        (TEMP_ENV.to_string(), temp.to_string_lossy().into_owned()),
        (EXIT_ENV.to_string(), "0".to_string()),
    ]);
    let configured = handler(temp, FIXTURE, env.clone(), 10, false)?;
    let result = run_command(&runtime, &configured, FIXTURE, &env, input, temp).await;
    if result.exit_code != Some(0) || result.error.is_some() {
        return Err(io_err(format!(
            "run_command probe exit={:?} error={:?} stdout={} stderr={}",
            result.exit_code, result.error, result.stdout, result.stderr
        )));
    }
    let report = parse_probe_report(&result.stdout)?;
    if report.hwnd != 0
        || report.eof != 1
        || report.cwd_ok != 1
        || report.stdin_hex != hex_encode(input.as_bytes())
        || report.case_name != "run-command"
        || !result.stderr.contains(&format!(
            "{PROBE_ERR_PREFIX} case=run-command nonce={nonce}"
        ))
    {
        return Err(io_err(format!(
            "run_command probe transport stdout={} stderr={}",
            result.stdout, result.stderr
        )));
    }
    if take_hook_spawn_path() != Some(WindowsHookSpawnPath::Contained) {
        return Err(io_err("run_command probe was not contained"));
    }
    Ok(())
}

async fn run_command_spawn_error(temp: &Path) -> io::Result<()> {
    let (runtime, _results) = runtime();
    let runtime = runtime.reconfigured(CommandShell {
        program: temp
            .join("missing-hook-shell.exe")
            .to_string_lossy()
            .into_owned(),
        args: vec!["/C".to_string()],
    });
    let env = HashMap::new();
    let configured = handler(temp, "echo hook-ran", env.clone(), 10, false)?;
    let result = run_command(&runtime, &configured, "echo hook-ran", &env, "{}", temp).await;
    if result.exit_code.is_some() || result.error.is_none() || !result.stdout.is_empty() {
        return Err(io_err(format!(
            "spawn error was not reported: exit={:?} error={:?} stdout={}",
            result.exit_code, result.error, result.stdout
        )));
    }
    Ok(())
}

async fn wait_for_pid_file(path: &Path) -> io::Result<(u32, u32)> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(pids) = parse_pids(&format!("{PIDS_PREFIX} {text}")) {
                return Ok(pids);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io_err(format!(
                "pid file {} was not written",
                path.display()
            )));
        }
        sleep(Duration::from_millis(20)).await;
    }
}

fn tree_env(temp: &Path, role: &str, pid_file: &Path, exit_code: i32) -> HashMap<String, String> {
    HashMap::from([
        (ROLE_ENV.to_string(), role.to_string()),
        (
            PID_FILE_ENV.to_string(),
            pid_file.to_string_lossy().into_owned(),
        ),
        (TEMP_ENV.to_string(), temp.to_string_lossy().into_owned()),
        (EXIT_ENV.to_string(), exit_code.to_string()),
    ])
}

async fn run_timeout_case(
    exe: &Path,
    temp: &Path,
    name: &str,
    fault: WindowsHookLaunchFault,
    expected_path: WindowsHookSpawnPath,
) -> io::Result<KillPid> {
    let pid_file = temp.join(format!("{name}-pids.txt"));
    let _ = fs::remove_file(&pid_file);
    let (runtime, _results) = runtime();
    let runtime = runtime.reconfigured(shell_for_fixture(exe));
    let env = tree_env(temp, "tree-root", &pid_file, 0);
    let configured = handler(temp, FIXTURE, env.clone(), 2, false)?;
    set_hook_launch_fault(fault);
    let run_fut = run_command(&runtime, &configured, FIXTURE, &env, "{}", temp);
    let pid_fut = async {
        let (root, child) = wait_for_pid_file(&pid_file).await?;
        Ok::<_, io::Error>((root, KillPid::new(child)?))
    };
    let joined = timeout(Duration::from_secs(15), join(run_fut, pid_fut))
        .await
        .map_err(|_| io_err(format!("{name} timeout case hung")))?;
    let (result, pids) = joined;
    let (root, owned_child) = pids?;
    let path = take_hook_spawn_path();
    if result.error.as_deref() != Some("hook timed out after 2s")
        || result.exit_code.is_some()
        || path != Some(expected_path)
    {
        return Err(io_err(format!(
            "{name} timeout result error={:?} exit={:?} path={path:?}",
            result.error, result.exit_code
        )));
    }
    wait_until_inactive(root).await?;
    Ok(owned_child)
}

async fn run_live_taskkill_tree(exe: &Path, temp: &Path) -> io::Result<()> {
    let pid_file = temp.join("taskkill-pids.txt");
    let mut command = Command::new(exe);
    command
        .args(fixture_args())
        .envs(tree_env(temp, "tree-root", &pid_file, 0))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    set_hook_launch_fault(WindowsHookLaunchFault::JobCreate);
    let (mut root, job) = spawn_windows_command_hook(command)?;
    if job.is_some() {
        return Err(io_err("taskkill fixture unexpectedly has a job"));
    }
    let (root_pid, child_pid) = wait_for_pid_file(&pid_file).await?;
    let _owned_child = KillPid::new(child_pid)?;
    let mut cleanup = spawn_taskkill_tree(root_pid)?;
    let status = tokio::task::spawn_blocking(move || cleanup.wait())
        .await
        .map_err(|err| io_err(err.to_string()))??;
    if !status.success() {
        return Err(io_err(format!("taskkill failed: {status}")));
    }
    timeout(Duration::from_secs(5), root.wait())
        .await
        .map_err(|_| io_err("taskkill left the root alive"))??;
    wait_until_inactive(child_pid).await
}

async fn run_preserve_descendant(exe: &Path, temp: &Path, nonce: &str) -> io::Result<()> {
    let _ = nonce;
    let pid_file = temp.join("preserve-pids.txt");
    let (runtime, _results) = runtime();
    let runtime = runtime.reconfigured(shell_for_fixture(exe));
    let env = tree_env(temp, "tree-exit", &pid_file, 7);
    let configured = handler(temp, FIXTURE, env.clone(), 10, false)?;
    let result = run_command(&runtime, &configured, FIXTURE, &env, "{}", temp).await;
    if result.exit_code != Some(7) || result.error.is_some() {
        return Err(io_err(format!(
            "preserve hook exit={:?} error={:?} stdout={} stderr={}",
            result.exit_code, result.error, result.stdout, result.stderr
        )));
    }
    let (_root, child) = parse_pids(&result.stdout).or_else(|_| {
        fs::read_to_string(&pid_file)
            .map_err(|err| io_err(err.to_string()))
            .and_then(|text| parse_pids(&format!("{PIDS_PREFIX} {text}")))
    })?;
    let _kill = KillPid::new(child)?;
    if !process_is_active(child) {
        return Err(io_err("descendant did not survive normal nonzero exit"));
    }
    sleep(Duration::from_millis(400)).await;
    if !process_is_active(child) {
        return Err(io_err("descendant was cleaned up after normal exit"));
    }
    Ok(())
}

async fn run_async_shutdown(exe: &Path, temp: &Path) -> io::Result<()> {
    let pid_file = temp.join("shutdown-pids.txt");
    let (original_runtime, results) = runtime();
    let runtime = original_runtime.reconfigured(shell_for_fixture(exe));
    // The result channel closes only after every runtime sender is dropped.
    drop(original_runtime);
    let env = tree_env(temp, "tree-root", &pid_file, 0);
    let configured = handler(temp, FIXTURE, env, 30, true)?;
    schedule(&runtime, configured, temp).await;
    let (root, child) = wait_for_pid_file(&pid_file).await?;
    runtime.shutdown().await;
    drop(runtime);
    let received = timeout(Duration::from_millis(200), results.recv()).await;
    match received {
        Ok(Err(_)) => {}
        Ok(Ok(_)) => return Err(io_err("shutdown delivered a late async result")),
        Err(_) => return Err(io_err("shutdown left the result channel open")),
    }
    wait_until_inactive(root).await?;
    wait_until_inactive(child).await?;
    Ok(())
}

async fn run_cleanup_probe(exe: &Path, temp: &Path, nonce: &str) -> io::Result<()> {
    let mut command = std::process::Command::new(exe);
    command
        .args(fixture_args())
        .current_dir(temp)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in probe_env("cleanup-probe", nonce, temp, 45, true) {
        command.env(key, value);
    }
    let mut child = spawn_no_window_process(command)?;
    let root = child.id();
    if foreign_process_has_console(root) {
        return Err(io_err("cleanup probe console was attachable"));
    }
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(STDIN_PAYLOAD)?;
    }
    let output = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .map_err(|err| io_err(err.to_string()))??;
    assert_probe_report(
        "cleanup-probe",
        nonce,
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
        &output.status,
        45,
        STDIN_PAYLOAD,
    )?;
    Ok(())
}

async fn worker() -> io::Result<()> {
    let (hwnd, cp, clients) = console_state();
    if hwnd != 0 || cp != 0 || clients != 0 {
        return Err(io_err(format!(
            "detached worker has a console hwnd={hwnd:#x} cp={cp} clients={clients}"
        )));
    }
    let temp = PathBuf::from(std::env::var(TEMP_ENV).map_err(|err| io_err(err.to_string()))?);
    let nonce = std::env::var(NONCE_ENV).map_err(|err| io_err(err.to_string()))?;
    let exe = std::env::current_exe()?;
    for case in &launch_cases() {
        run_direct_launch_case(&exe, &temp, &nonce, case).await?;
    }
    run_cmd_launch_case(&exe, &temp, &nonce).await?;
    run_final_spawn_failure(&temp).await?;
    run_command_probe(&exe, &temp, &nonce).await?;
    run_command_spawn_error(&temp).await?;
    let contained_child = run_timeout_case(
        &exe,
        &temp,
        "contained-timeout",
        WindowsHookLaunchFault::None,
        WindowsHookSpawnPath::Contained,
    )
    .await?;
    wait_until_inactive(contained_child.pid).await?;
    let uncontained_child = run_timeout_case(
        &exe,
        &temp,
        "uncontained-timeout",
        WindowsHookLaunchFault::JobCreate,
        WindowsHookSpawnPath::JobUnavailable,
    )
    .await?;
    // The existing fallback is best effort: kill_on_drop can terminate the root
    // before taskkill discovers its descendants. Do not assert a new isolation
    // guarantee here; keep fixture cleanup owned and test a live tree separately.
    drop(uncontained_child);
    run_live_taskkill_tree(&exe, &temp).await?;
    run_preserve_descendant(&exe, &temp, &nonce).await?;
    run_async_shutdown(&exe, &temp).await?;
    run_cleanup_probe(&exe, &temp, &nonce).await?;
    fs::write(temp.join(RESULT_FILE), format!("ok {nonce}\n"))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detached_parent_command_hooks_hide_console_windows() -> io::Result<()> {
    let temp = tempdir()?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| io_err(err.to_string()))?
        .as_nanos();
    let nonce = format!("{}-{nanos:x}", std::process::id());
    let exe = std::env::current_exe()?;
    let mut command = Command::new(&exe);
    command
        .args(fixture_args())
        .current_dir(temp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .creation_flags(DETACHED_PROCESS)
        .env(ROLE_ENV, "worker")
        .env(NONCE_ENV, &nonce)
        .env(TEMP_ENV, temp.path());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io_err("missing worker stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io_err("missing worker stderr"))?;
    let joined = timeout(Duration::from_secs(90), async {
        tokio::try_join!(child.wait(), read_to_end(stdout), read_to_end(stderr))
    })
    .await
    .map_err(|_| io_err("detached command-hook worker timed out"))??;
    let (status, stdout, stderr) = joined;
    let stdout = String::from_utf8_lossy(&stdout);
    let stderr = String::from_utf8_lossy(&stderr);
    let result = fs::read_to_string(temp.path().join(RESULT_FILE)).unwrap_or_default();
    if !status.success() || result.trim() != format!("ok {nonce}") {
        return Err(io_err(format!(
            "detached command-hook worker failed status={status} result={result:?} stdout={stdout} stderr={stderr}"
        )));
    }
    Ok(())
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn windows_hook_process_fixture() -> io::Result<()> {
    match std::env::var(ROLE_ENV).ok().as_deref() {
        Some("worker") => worker().await,
        Some("probe") => probe(),
        Some("sleeper") => {
            std::thread::sleep(Duration::from_secs(60));
            Ok(())
        }
        Some("tree-root") => publish_tree(false),
        Some("tree-exit") => publish_tree(true),
        _ => Ok(()),
    }
}
