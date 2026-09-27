use std::collections::HashMap;
#[cfg(not(windows))]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::future::Future;
use std::io::ErrorKind;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;
use std::time::Instant;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use winapi::um::winbase::CREATE_NO_WINDOW;

use async_channel::Sender;
use codex_protocol::shell_environment::scrub_non_inheritable_env_vars;
#[cfg(windows)]
use codex_utils_pty::JobObject;
use futures::future::try_join;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::Span;

use super::CommandShell;
use super::ConfiguredHandler;
use super::ConfiguredHandlerKind;
use super::HandlerRunResult;
use super::dispatcher::ParsedHandler;
use super::dispatcher::hook_event_name_label;
use super::dispatcher::hook_execution_mode_label;
use super::dispatcher::hook_handler_type_label;
use super::dispatcher::hook_scope_label;
use super::dispatcher::hook_source_label;
use super::dispatcher::scope_for_event;
use crate::output_spill::AdditionalContext;
use crate::output_spill::HookOutputSpiller;
use codex_protocol::ThreadId;
use codex_protocol::protocol::HookCompletedEvent;
use codex_protocol::protocol::HookHandlerType;
use codex_protocol::protocol::HookOutputEntry;
use codex_protocol::protocol::HookOutputEntryKind;

const MAX_CONCURRENT_ASYNC_HOOKS: usize = 8;

/// Owns command execution and bounded asynchronous work for one session.
#[derive(Clone)]
pub(crate) struct CommandHookRuntime {
    shell: CommandShell,
    environment: Arc<Vec<(OsString, OsString)>>,
    result_sender: Sender<HookCompletedEvent>,
    state: Arc<Mutex<CommandHookRuntimeState>>,
    output_spiller: HookOutputSpiller,
}

struct CommandHookRuntimeState {
    concurrency_limit: Arc<Semaphore>,
    tasks: JoinSet<()>,
}

impl Default for CommandHookRuntimeState {
    fn default() -> Self {
        Self {
            concurrency_limit: Arc::new(Semaphore::new(MAX_CONCURRENT_ASYNC_HOOKS)),
            tasks: JoinSet::new(),
        }
    }
}

impl CommandHookRuntime {
    pub(crate) fn new(
        shell: CommandShell,
        environment: Arc<Vec<(OsString, OsString)>>,
        thread_id: ThreadId,
        result_sender: Sender<HookCompletedEvent>,
    ) -> Self {
        Self {
            shell,
            environment,
            result_sender,
            state: Arc::new(Mutex::new(CommandHookRuntimeState::default())),
            output_spiller: HookOutputSpiller::new(thread_id),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, CommandHookRuntimeState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn reconfigured(&self, shell: CommandShell) -> Self {
        Self {
            shell,
            environment: Arc::clone(&self.environment),
            result_sender: self.result_sender.clone(),
            state: Arc::clone(&self.state),
            output_spiller: self.output_spiller.clone(),
        }
    }

    pub(crate) fn output_spiller(&self) -> &HookOutputSpiller {
        &self.output_spiller
    }

    pub(crate) fn schedule_async_hook<T: 'static>(
        &self,
        handler: ConfiguredHandler,
        input_json: String,
        cwd: std::path::PathBuf,
        turn_id: Option<String>,
        parse: fn(&ConfiguredHandler, HandlerRunResult, Option<String>) -> ParsedHandler<T>,
    ) {
        if self.result_sender.is_closed() {
            return;
        }

        let result_sender = self.result_sender.clone();
        let runtime = self.clone();
        self.schedule_async_task(async move {
            let result = match &handler.kind {
                ConfiguredHandlerKind::Command { command, env, .. } => {
                    run_command(&runtime, &handler, command, env, &input_json, &cwd).await
                }
                ConfiguredHandlerKind::McpTool { .. } => return,
            };
            let mut hook_result = parse(&handler, result, turn_id).completed;
            let mut entries = Vec::new();
            let mut warnings = Vec::new();

            for entry in std::mem::take(&mut hook_result.run.entries) {
                match entry.kind {
                    HookOutputEntryKind::Context => {
                        if let Some(text) = runtime
                            .output_spiller
                            .maybe_spill_additional_contexts(vec![AdditionalContext {
                                text: entry.text,
                                limit: handler.additional_context_limit,
                            }])
                            .await
                            .into_iter()
                            .next()
                        {
                            entries.push(HookOutputEntry {
                                kind: HookOutputEntryKind::Context,
                                text,
                            });
                        }
                    }
                    HookOutputEntryKind::Warning => warnings.push(entry),
                    HookOutputEntryKind::Error => entries.push(entry),
                    HookOutputEntryKind::Stop | HookOutputEntryKind::Feedback => {}
                }
            }

            entries.extend(warnings);
            hook_result.run.entries = entries;
            let _ = result_sender.try_send(hook_result);
        });
    }

    pub(crate) fn schedule_async_task(&self, task: impl Future<Output = ()> + Send + 'static) {
        let mut state = self.lock_state();
        if state.concurrency_limit.is_closed() {
            return;
        }

        while state.tasks.try_join_next().is_some() {}
        let concurrency_limit = Arc::clone(&state.concurrency_limit);
        state.tasks.spawn(async move {
            let Ok(_permit) = concurrency_limit.acquire_owned().await else {
                return;
            };
            task.await;
        });
    }

    pub(crate) async fn shutdown(&self) {
        let mut tasks = {
            let mut state = self.lock_state();
            state.concurrency_limit.close();
            std::mem::take(&mut state.tasks)
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

#[tracing::instrument(
    name = "codex.hooks.command",
    level = "trace",
    skip_all,
    fields(
        hook.event_name = hook_event_name_label(handler.event_name),
        hook.handler_type = hook_handler_type_label(HookHandlerType::Command),
        hook.execution_mode = hook_execution_mode_label(handler.execution_mode()),
        hook.scope = hook_scope_label(scope_for_event(handler.event_name)),
        hook.source = hook_source_label(handler.source),
        hook.display_order = handler.display_order,
        hook.timeout_sec = handler.timeout_sec,
        hook.command_outcome = tracing::field::Empty,
    )
)]
pub(crate) async fn run_command(
    runtime: &CommandHookRuntime,
    handler: &ConfiguredHandler,
    command: &str,
    env: &HashMap<String, String>,
    input_json: &str,
    cwd: &Path,
) -> HandlerRunResult {
    let started_at = chrono::Utc::now().timestamp();
    let started = Instant::now();

    let mut command = build_command(&runtime.shell, command, &runtime.environment, env);
    command
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    #[cfg(unix)]
    // Keep process-group cleanup without inheriting the controlling terminal, where
    // shell startup can otherwise stop the hook on background terminal I/O.
    // SAFETY: detach_from_tty only performs async-signal-safe process setup.
    unsafe {
        command.pre_exec(codex_utils_pty::process_group::detach_from_tty);
    }

    let fail_spawn = |err: std::io::Error| {
        finish_command_run(
            started_at,
            started,
            CommandRunCompletion {
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(err.to_string()),
                outcome: "spawn_error",
            },
        )
    };

    #[cfg(windows)]
    let (mut child, process_tree_job) = match spawn_windows_command_hook(command) {
        Ok(spawned) => spawned,
        Err(err) => return fail_spawn(err),
    };
    #[cfg(not(windows))]
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => return fail_spawn(err),
    };

    let mut process_tree_guard = ProcessTreeGuard {
        process_id: child.id(),
        #[cfg(windows)]
        job: process_tree_job,
    };

    let stdin = child.stdin.take();
    let write_stdin = async {
        if let Some(mut stdin) = stdin
            && let Err(err) = stdin.write_all(input_json.as_bytes()).await
            && err.kind() != ErrorKind::BrokenPipe
        {
            return Err(("stdin_error", format!("failed to write hook stdin: {err}")));
        }
        Ok(())
    };
    let wait_with_output = async {
        child
            .wait_with_output()
            .await
            .map_err(|err| ("wait_error", err.to_string()))
    };

    let timeout_duration = Duration::from_secs(handler.timeout_sec);
    // Drain output while sending input so neither pipe can block the other, and
    // include stdin writes in the deadline even when the hook never reads them.
    match timeout(timeout_duration, try_join(write_stdin, wait_with_output)).await {
        Ok(Ok(((), output))) => {
            // Successfully completed hooks may intentionally leave detached helpers running.
            #[cfg(windows)]
            if let Some(job) = process_tree_guard.job.as_ref() {
                let _ = job.preserve_descendants();
            }
            process_tree_guard.process_id = None;
            finish_command_run(
                started_at,
                started,
                CommandRunCompletion {
                    exit_code: output.status.code(),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    error: None,
                    outcome: "completed",
                },
            )
        }
        Ok(Err((outcome, error))) => finish_command_run(
            started_at,
            started,
            CommandRunCompletion {
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(error),
                outcome,
            },
        ),
        Err(_) => finish_command_run(
            started_at,
            started,
            CommandRunCompletion {
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(format!("hook timed out after {}s", handler.timeout_sec)),
                outcome: "timeout",
            },
        ),
    }
}

// Needed only until command hooks move to the exec server, which owns process-tree cleanup.
struct ProcessTreeGuard {
    process_id: Option<u32>,
    #[cfg(windows)]
    job: Option<JobObject>,
}

impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        let Some(process_id) = self.process_id else {
            return;
        };

        #[cfg(unix)]
        {
            let _ = codex_utils_pty::process_group::kill_process_group(process_id);
        }

        #[cfg(windows)]
        {
            if let Some(job) = self.job.as_ref() {
                let _ = job.terminate();
            } else {
                let _ = spawn_taskkill_tree(process_id);
            }
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum WindowsHookLaunchFault {
    None,
    #[cfg(test)]
    JobCreate,
    #[cfg(test)]
    ContainedAfterSuspend,
}

#[cfg(all(windows, test))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WindowsHookSpawnPath {
    Contained,
    JobUnavailable,
    ContainedRetry,
}

#[cfg(all(windows, test))]
struct HookLaunchSeam {
    fault: WindowsHookLaunchFault,
    path: Option<WindowsHookSpawnPath>,
}

#[cfg(all(windows, test))]
fn hook_launch_seam() -> &'static Mutex<HookLaunchSeam> {
    static SEAM: Mutex<HookLaunchSeam> = Mutex::new(HookLaunchSeam {
        fault: WindowsHookLaunchFault::None,
        path: None,
    });
    &SEAM
}

#[cfg(all(windows, test))]
fn lock_hook_launch_seam() -> MutexGuard<'static, HookLaunchSeam> {
    hook_launch_seam()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(all(windows, test))]
fn set_hook_launch_fault(fault: WindowsHookLaunchFault) {
    lock_hook_launch_seam().fault = fault;
}

#[cfg(all(windows, test))]
fn take_hook_spawn_path() -> Option<WindowsHookSpawnPath> {
    lock_hook_launch_seam().path.take()
}

#[cfg(all(windows, test))]
fn note_hook_spawn_path(path: WindowsHookSpawnPath) {
    lock_hook_launch_seam().path = Some(path);
}

#[cfg(windows)]
fn spawn_windows_command_hook(
    mut command: Command,
) -> std::io::Result<(tokio::process::Child, Option<JobObject>)> {
    #[cfg(test)]
    let fault = {
        let mut seam = lock_hook_launch_seam();
        let fault = seam.fault;
        seam.fault = WindowsHookLaunchFault::None;
        seam.path = None;
        fault
    };
    #[cfg(not(test))]
    let fault = WindowsHookLaunchFault::None;

    #[cfg(test)]
    let mut assignment_block = None;
    let job = match fault {
        WindowsHookLaunchFault::None => JobObject::create().ok(),
        #[cfg(test)]
        WindowsHookLaunchFault::JobCreate => None,
        #[cfg(test)]
        WindowsHookLaunchFault::ContainedAfterSuspend => match JobObject::create() {
            Ok(job) => {
                assignment_block = Some(block_hook_job_assignment(&job)?);
                Some(job)
            }
            Err(_) => None,
        },
    };

    if let Some(job) = job {
        match job.spawn_background_contained(&mut command) {
            Ok(child) => {
                #[cfg(test)]
                note_hook_spawn_path(WindowsHookSpawnPath::Contained);
                return Ok((child, Some(job)));
            }
            Err(_) => {
                #[cfg(test)]
                note_hook_spawn_path(WindowsHookSpawnPath::ContainedRetry);
                drop(job);
            }
        }
    } else {
        #[cfg(test)]
        note_hook_spawn_path(WindowsHookSpawnPath::JobUnavailable);
    }

    #[cfg(test)]
    drop(assignment_block);
    command.creation_flags(CREATE_NO_WINDOW);
    command.spawn().map(|child| (child, None))
}

#[cfg(all(windows, test))]
fn block_hook_job_assignment(job: &JobObject) -> std::io::Result<tokio::process::Child> {
    use std::os::windows::io::AsRawHandle;

    use winapi::um::jobapi2::SetInformationJobObject;
    use winapi::um::winnt::JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    use winapi::um::winnt::JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    use winapi::um::winnt::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    use winapi::um::winnt::JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
    use winapi::um::winnt::JobObjectExtendedLimitInformation;

    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_BREAKAWAY_OK
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    let configured = unsafe {
        SetInformationJobObject(
            job.as_raw_handle().cast(),
            JobObjectExtendedLimitInformation,
            std::ptr::addr_of_mut!(limits).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if configured == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut ping = std::path::PathBuf::from(
        std::env::var_os("SystemRoot").unwrap_or_else(|| OsString::from(r"C:\Windows")),
    );
    ping.push("System32");
    ping.push("ping.exe");
    let mut occupant = Command::new(ping);
    occupant
        .arg("-n")
        .arg("30")
        .arg("127.0.0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    job.spawn_background_contained(&mut occupant)
}

#[cfg(windows)]
fn spawn_taskkill_tree(process_id: u32) -> std::io::Result<std::process::Child> {
    let mut command = std::process::Command::new("taskkill");
    command
        .args(["/PID", &process_id.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    spawn_no_window_process(command)
}

#[cfg(windows)]
fn spawn_no_window_process(
    mut command: std::process::Command,
) -> std::io::Result<std::process::Child> {
    command.creation_flags(CREATE_NO_WINDOW);
    command.spawn()
}

struct CommandRunCompletion {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    error: Option<String>,
    outcome: &'static str,
}

fn finish_command_run(
    started_at: i64,
    started: Instant,
    completion: CommandRunCompletion,
) -> HandlerRunResult {
    Span::current().record("hook.command_outcome", completion.outcome);
    HandlerRunResult {
        started_at,
        completed_at: chrono::Utc::now().timestamp(),
        duration_ms: started.elapsed().as_millis().try_into().unwrap_or(i64::MAX),
        exit_code: completion.exit_code,
        stdout: completion.stdout,
        stderr: completion.stderr,
        error: completion.error,
    }
}

fn build_command(
    shell: &CommandShell,
    command_line: &str,
    environment: &[(OsString, OsString)],
    env: &HashMap<String, String>,
) -> Command {
    let mut command = if shell.program.is_empty() {
        default_shell_command(environment)
    } else {
        Command::new(&shell.program)
    };
    if shell.program.is_empty() {
        #[cfg(windows)]
        command.raw_arg(format!(r#""{command_line}""#));

        #[cfg(not(windows))]
        command.arg(command_line);
    } else {
        command.args(&shell.args);

        #[cfg(windows)]
        if shell.args.iter().any(|arg| arg.eq_ignore_ascii_case("/c")) {
            command.raw_arg(format!(r#""{command_line}""#));
        } else {
            command.arg(command_line);
        }

        #[cfg(not(windows))]
        command.arg(command_line);
    }
    // Replay the session snapshot instead of inheriting the live process environment.
    command.env_clear();
    command.envs(environment.iter().cloned());
    command.envs(env);
    scrub_non_inheritable_env_vars(command.as_std_mut());
    command
}

fn default_shell_command(environment: &[(OsString, OsString)]) -> Command {
    #[cfg(windows)]
    let (environment_variable, fallback_program, argument) = ("COMSPEC", "cmd.exe", "/C");

    #[cfg(not(windows))]
    let (environment_variable, fallback_program, argument) = ("SHELL", "/bin/sh", "-lc");

    let program = environment
        .iter()
        .find(|(key, _)| {
            #[cfg(windows)]
            {
                key.to_str()
                    .is_some_and(|key| key.eq_ignore_ascii_case(environment_variable))
            }

            #[cfg(not(windows))]
            {
                key == OsStr::new(environment_variable)
            }
        })
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| OsString::from(fallback_program));

    let mut command = Command::new(program);
    command.arg(argument);
    command
}

#[cfg(test)]
#[path = "command_runner_tests.rs"]
mod tests;
