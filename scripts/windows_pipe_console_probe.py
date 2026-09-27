#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import platform
import queue
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path


DETACHED_PROCESS = 0x00000008
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001
PROCESS_SYNCHRONIZE = 0x00100000
STILL_ACTIVE = 259
TH32CS_SNAPPROCESS = 0x00000002
EVENT_OBJECT_CREATE = 0x8000
EVENT_OBJECT_DESTROY = 0x8001
EVENT_OBJECT_SHOW = 0x8002
EVENT_OBJECT_NAMECHANGE = 0x800C
WINEVENT_OUTOFCONTEXT = 0x0000
OBJID_WINDOW = 0
GW_OWNER = 4
GA_ROOTOWNER = 3
DWMWA_CLOAKED = 14
WM_QUIT = 0x0012
STARTUP_GRACE_SECONDS = 10
EXIT_GRACE_SECONDS = 10
TRACKED_EVENTS = (
    EVENT_OBJECT_CREATE,
    EVENT_OBJECT_SHOW,
    EVENT_OBJECT_NAMECHANGE,
    EVENT_OBJECT_DESTROY,
)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2_0", ctypes.c_void_p),
        ("Reserved2_1", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_size_t),
        ("InheritedFromUniqueProcessId", ctypes.c_size_t),
    ]


class ProbeFailure(Exception):
    pass


class ProbeInconclusive(Exception):
    pass


def configure_win32() -> None:
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.GetCurrentThreadId.restype = wintypes.DWORD
    kernel32.AttachConsole.argtypes = [wintypes.DWORD]
    kernel32.AttachConsole.restype = wintypes.BOOL
    kernel32.FreeConsole.restype = wintypes.BOOL
    kernel32.GetConsoleWindow.restype = wintypes.HWND
    kernel32.GetConsoleProcessList.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    kernel32.GetConsoleProcessList.restype = wintypes.DWORD
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetAncestor.restype = wintypes.HWND
    user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetWindow.restype = wintypes.HWND
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.EnumWindows.argtypes = [ctypes.c_void_p, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    user32.SetWinEventHook.argtypes = [
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HMODULE,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    user32.SetWinEventHook.restype = wintypes.HANDLE
    user32.UnhookWinEvent.argtypes = [wintypes.HANDLE]
    user32.UnhookWinEvent.restype = wintypes.BOOL
    user32.GetMessageW.argtypes = [
        ctypes.c_void_p,
        wintypes.HWND,
        wintypes.UINT,
        wintypes.UINT,
    ]
    user32.GetMessageW.restype = wintypes.BOOL
    user32.TranslateMessage.argtypes = [ctypes.c_void_p]
    user32.TranslateMessage.restype = wintypes.BOOL
    user32.DispatchMessageW.argtypes = [ctypes.c_void_p]
    user32.DispatchMessageW.restype = wintypes.LPARAM
    user32.PostThreadMessageW.argtypes = [
        wintypes.DWORD,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    user32.PostThreadMessageW.restype = wintypes.BOOL
    ntdll.NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    ntdll.NtQueryInformationProcess.restype = ctypes.c_long


def require_windows_apis() -> ctypes.WinDLL:
    if sys.platform != "win32":
        raise ProbeFailure("windows pipe console probe requires Windows")
    try:
        dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
    except OSError as error:
        raise ProbeFailure(f"observer unavailable: dwmapi missing: {error}") from error
    required = [
        (kernel32, "GetConsoleWindow"),
        (kernel32, "GetConsoleProcessList"),
        (kernel32, "AttachConsole"),
        (kernel32, "CreateToolhelp32Snapshot"),
        (user32, "SetWinEventHook"),
        (user32, "GetAncestor"),
        (user32, "EnumWindows"),
        (dwmapi, "DwmGetWindowAttribute"),
    ]
    for library, name in required:
        if not hasattr(library, name):
            raise ProbeFailure(f"observer unavailable: missing {name}")
    dwmapi.DwmGetWindowAttribute.argtypes = [
        wintypes.HWND,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long
    return dwmapi


def hwnd_int(value) -> int:
    if not value:
        return 0
    cast = getattr(value, "value", value)
    if cast is None:
        return 0
    return int(cast)


def filetime_int(value: FILETIME) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def close_handle(handle) -> None:
    if handle:
        kernel32.CloseHandle(handle)


def open_process(pid: int, rights: int):
    if pid <= 0:
        return None
    handle = kernel32.OpenProcess(rights, False, pid)
    if not handle:
        return None
    return handle


def process_alive(handle) -> bool:
    code = wintypes.DWORD()
    if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
        return False
    return code.value == STILL_ACTIVE


def process_creation(handle) -> int | None:
    created = FILETIME()
    exited = FILETIME()
    kernel_time = FILETIME()
    user_time = FILETIME()
    if not kernel32.GetProcessTimes(
        handle,
        ctypes.byref(created),
        ctypes.byref(exited),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    ):
        return None
    return filetime_int(created)


def process_image(handle) -> str:
    size = wintypes.DWORD(32768)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
        return ""
    return buffer.value


def process_parent(handle) -> int:
    info = PROCESS_BASIC_INFORMATION()
    returned = ctypes.c_ulong()
    status = ntdll.NtQueryInformationProcess(
        handle,
        0,
        ctypes.byref(info),
        ctypes.sizeof(info),
        ctypes.byref(returned),
    )
    if status < 0:
        return 0
    return int(info.InheritedFromUniqueProcessId)


def process_details(pid: int) -> dict:
    handle = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    if handle is None:
        return {"pid": pid, "creation": None, "parent": 0, "image": ""}
    try:
        return {
            "pid": pid,
            "creation": process_creation(handle),
            "parent": process_parent(handle),
            "image": process_image(handle),
        }
    finally:
        close_handle(handle)


def snapshot_processes() -> list[dict]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    value = ctypes.cast(snapshot, ctypes.c_void_p).value if snapshot else None
    invalid = ctypes.c_void_p(-1).value
    if not value or value == invalid:
        raise ProbeFailure("observer unavailable: process snapshot failed")
    rows = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        found = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while found:
            rows.append(
                {
                    "pid": int(entry.th32ProcessID),
                    "ppid": int(entry.th32ParentProcessID),
                    "name": entry.szExeFile,
                }
            )
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            found = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        close_handle(snapshot)
    return rows


def descendant_pids(root_pid: int, rows: list[dict]) -> list[int]:
    children: dict[int, list[int]] = {}
    for row in rows:
        children.setdefault(row["ppid"], []).append(row["pid"])
    found = []
    stack = [root_pid]
    seen = {root_pid}
    while stack:
        current = stack.pop()
        for child in children.get(current, []):
            if child not in seen:
                seen.add(child)
                found.append(child)
                stack.append(child)
    return found


def console_attachment() -> tuple[int, int]:
    hwnd = hwnd_int(kernel32.GetConsoleWindow())
    pids = (wintypes.DWORD * 1)()
    clients = int(kernel32.GetConsoleProcessList(pids, 1))
    return hwnd, clients


class TrackedProcess:
    def __init__(self, pid: int, handle, creation: int | None, image: str, parent: int):
        self.pid = pid
        self.handle = handle
        self.creation = creation
        self.image = image
        self.parent = parent

    def identity(self) -> dict:
        return {
            "pid": self.pid,
            "creation": self.creation,
            "image": self.image,
            "parent": self.parent,
            "alive": process_alive(self.handle),
        }


class ProcessTracker:
    def __init__(self):
        self.processes: dict[int, TrackedProcess] = {}
        self.console_hwnds: set[int] = set()

    def add_pid(self, pid: int) -> None:
        if pid in self.processes:
            return
        handle = open_process(
            pid,
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
        )
        if handle is None:
            return
        self.processes[pid] = TrackedProcess(
            pid,
            handle,
            process_creation(handle),
            process_image(handle),
            process_parent(handle),
        )

    def scan(self, root_pid: int) -> None:
        self.add_pid(root_pid)
        for pid in descendant_pids(root_pid, snapshot_processes()):
            self.add_pid(pid)

    def contains(self, pid: int, creation: int | None = None) -> bool:
        tracked = self.processes.get(pid)
        if tracked is None:
            return False
        return creation is None or tracked.creation == creation

    def identities(self) -> list[dict]:
        return [process.identity() for process in self.processes.values()]

    def alive_pids(self) -> list[int]:
        return [pid for pid, process in self.processes.items() if process_alive(process.handle)]

    def terminate_alive(self) -> list[int]:
        terminated = []
        for pid, process in self.processes.items():
            if process_alive(process.handle):
                if kernel32.TerminateProcess(process.handle, 1):
                    terminated.append(pid)
        return terminated

    def close(self) -> None:
        for process in self.processes.values():
            close_handle(process.handle)
        self.processes.clear()


WINEVENTPROC = ctypes.WINFUNCTYPE(
    None,
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.HWND,
    wintypes.LONG,
    wintypes.LONG,
    wintypes.DWORD,
    wintypes.DWORD,
)
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


class WinEventObserver:
    def __init__(self, dwmapi):
        self.dwmapi = dwmapi
        self.ready = threading.Event()
        self.failure = None
        self.events = []
        self.lock = threading.Lock()
        self.thread = None
        self.thread_id = 0
        self.hooks = []
        self.callback = WINEVENTPROC(self._callback)

    def start(self) -> None:
        self.ready.clear()
        self.failure = None
        with self.lock:
            self.events.clear()
        self.thread = threading.Thread(target=self._run, name="winevent-observer")
        self.thread.start()
        if not self.ready.wait(STARTUP_GRACE_SECONDS):
            self.stop()
            raise ProbeFailure("observer unavailable: WinEvent hook was not acknowledged")
        if self.failure:
            self.stop()
            raise ProbeFailure(f"observer unavailable: {self.failure}")

    def stop(self) -> list[dict]:
        if self.thread is not None and self.thread.is_alive() and self.thread_id:
            for _ in range(20):
                if user32.PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0):
                    break
                time.sleep(0.05)
            self.thread.join(EXIT_GRACE_SECONDS)
        events = self.snapshot_events()
        self.thread = None
        return events

    def snapshot_events(self) -> list[dict]:
        with self.lock:
            return list(self.events)

    def _run(self) -> None:
        self.thread_id = int(kernel32.GetCurrentThreadId())
        user32.SetWinEventHook.argtypes = [
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HMODULE,
            WINEVENTPROC,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        user32.GetMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG),
            wintypes.HWND,
            wintypes.UINT,
            wintypes.UINT,
        ]
        user32.GetMessageW.restype = ctypes.c_int
        hooks = []
        for event in TRACKED_EVENTS:
            hook = user32.SetWinEventHook(
                event,
                event,
                None,
                self.callback,
                0,
                0,
                WINEVENT_OUTOFCONTEXT,
            )
            if not hook:
                self.failure = f"SetWinEventHook failed for {event:#x}"
                for installed in hooks:
                    user32.UnhookWinEvent(installed)
                self.ready.set()
                return
            hooks.append(hook)
        self.hooks = hooks
        self.ready.set()
        message = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(message))
            user32.DispatchMessageW(ctypes.byref(message))
        for hook in hooks:
            user32.UnhookWinEvent(hook)
        self.hooks = []

    def _callback(self, _hook, event, hwnd, id_object, id_child, _thread, event_time) -> None:
        try:
            record = self._snapshot(int(event), hwnd, int(id_object), int(id_child), int(event_time))
        except Exception as error:
            record = {"event": int(event), "error": str(error)}
        with self.lock:
            self.events.append(record)

    def _snapshot(self, event, hwnd, id_object, id_child, event_time) -> dict:
        window = hwnd_int(hwnd)
        pid = 0
        if window:
            pid_value = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_value))
            pid = int(pid_value.value)
        details = process_details(pid) if pid else {"creation": None, "parent": 0, "image": ""}
        owner = hwnd_int(user32.GetWindow(hwnd, GW_OWNER)) if window else 0
        root = hwnd_int(user32.GetAncestor(hwnd, GA_ROOTOWNER)) if window else 0
        owner_pid = window_pid(owner)
        root_pid = window_pid(root)
        visible = bool(window and user32.IsWindowVisible(hwnd))
        cloaked = False
        if window:
            cloaked_value = wintypes.DWORD()
            hr = self.dwmapi.DwmGetWindowAttribute(
                hwnd,
                DWMWA_CLOAKED,
                ctypes.byref(cloaked_value),
                ctypes.sizeof(cloaked_value),
            )
            cloaked = hr == 0 and cloaked_value.value != 0
        return {
            "event": event,
            "event_time": event_time,
            "hwnd": window,
            "id_object": id_object,
            "id_child": id_child,
            "class": window_class(hwnd) if window else "",
            "title": window_title(hwnd) if window else "",
            "pid": pid,
            "creation": details.get("creation"),
            "parent_pid": details.get("parent", 0),
            "image": details.get("image", ""),
            "owner_hwnd": owner,
            "owner_pid": owner_pid,
            "root_owner_hwnd": root,
            "root_owner_pid": root_pid,
            "visible": visible and not cloaked,
            "cloaked": cloaked,
        }


def window_pid(hwnd: int) -> int:
    if not hwnd:
        return 0
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(ctypes.c_void_p(hwnd), ctypes.byref(pid))
    return int(pid.value)


def window_class(hwnd) -> str:
    buffer = ctypes.create_unicode_buffer(256)
    if user32.GetClassNameW(hwnd, buffer, 256) <= 0:
        return ""
    return buffer.value


def window_title(hwnd) -> str:
    length = int(user32.GetWindowTextLengthW(hwnd))
    if length <= 0:
        return ""
    buffer = ctypes.create_unicode_buffer(min(length, 200) + 1)
    user32.GetWindowTextW(hwnd, buffer, len(buffer))
    return buffer.value


def existing_windows() -> set[int]:
    found = []

    def callback(hwnd, _lparam):
        found.append(hwnd_int(hwnd))
        return True

    enum_callback = WNDENUMPROC(callback)
    user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
    user32.EnumWindows(enum_callback, 0)
    return {hwnd for hwnd in found if hwnd}


def preexisting_processes() -> dict[int, int | None]:
    identities = {}
    for row in snapshot_processes():
        details = process_details(row["pid"])
        identities[row["pid"]] = details["creation"]
    return identities


def classify_event(event: dict, tracker: ProcessTracker, preexisting: dict[int, int | None]) -> str:
    for key in ("hwnd", "owner_hwnd", "root_owner_hwnd"):
        window = event.get(key) or 0
        if window and window in tracker.console_hwnds:
            return "test"
    candidates = [
        event.get("pid") or 0,
        event.get("parent_pid") or 0,
        event.get("owner_pid") or 0,
        event.get("root_owner_pid") or 0,
    ]
    for pid in candidates:
        if tracker.contains(pid):
            return "test"
    walked = event.get("pid") or 0
    for _ in range(8):
        if not walked:
            break
        if tracker.contains(walked):
            return "test"
        details = process_details(walked)
        parent = details.get("parent") or 0
        if parent == walked:
            break
        walked = parent
    pid = event.get("pid") or 0
    creation = event.get("creation")
    if pid and pid in preexisting and preexisting[pid] == creation:
        return "separate"
    return "inconclusive"


def analyze_events(events: list[dict], preexisting_hwnds: set[int], tracker: ProcessTracker, preexisting) -> dict:
    visible_test = []
    visible_separate = []
    visible_unknown = []
    for event in events:
        if not event.get("visible"):
            continue
        if event.get("event") == EVENT_OBJECT_DESTROY:
            continue
        kind = classify_event(event, tracker, preexisting)
        if event.get("hwnd") in preexisting_hwnds and kind != "test":
            continue
        summary = {
            "hwnd": event.get("hwnd"),
            "class": event.get("class"),
            "pid": event.get("pid"),
            "parent_pid": event.get("parent_pid"),
            "image": event.get("image"),
            "owner_pid": event.get("owner_pid"),
            "root_owner_pid": event.get("root_owner_pid"),
            "classification": kind,
        }
        if kind == "test":
            visible_test.append(summary)
        elif kind == "separate":
            visible_separate.append(summary)
        else:
            visible_unknown.append(summary)
    return {
        "visible_test": visible_test,
        "visible_separate": visible_separate,
        "visible_unknown": visible_unknown,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_exe(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ProbeFailure(f"missing executable: {resolved}")
    return resolved


def same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def git_sha(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    try:
        completed = subprocess.run(
            ["git", "-C", str(Path(__file__).resolve().parent), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def command_text(argv: list[str], timeout: int, creationflags: int) -> str:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=creationflags,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"unavailable: {error}"
    text = (completed.stdout or completed.stderr).strip()
    return text or f"exit {completed.returncode}"


def host_info() -> dict:
    info = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "windows": platform.version(),
        "wt_session": bool(os.environ.get("WT_SESSION")),
        "terminal_version": None,
    }
    system_root = os.environ.get("SYSTEMROOT")
    if not system_root:
        return info
    powershell = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell.is_file():
        return info
    info["terminal_version"] = command_text(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "(Get-AppxPackage -Name Microsoft.WindowsTerminal).Version",
        ],
        15,
        CREATE_NO_WINDOW,
    )
    return info


def system_tool(name: str) -> Path | None:
    system_root = os.environ.get("SYSTEMROOT")
    if not system_root:
        return None
    path = Path(system_root) / "System32" / name
    if path.is_file():
        return path
    return None


def child_env() -> dict[str, str]:
    keys = [
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
        "PATH",
        "PATHEXT",
        "COMSPEC",
        "ComSpec",
        "TEMP",
        "TMP",
        "USERPROFILE",
    ]
    return {key: os.environ[key] for key in keys if key in os.environ}


def popen_detached(argv: list[str], creationflags: int, env: dict | None, cwd: Path | None):
    return subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        creationflags=creationflags,
        close_fds=True,
    )


def file_uri(path: Path) -> str:
    return path.resolve().as_uri()


class RpcClient:
    def __init__(self, process: subprocess.Popen):
        self.process = process
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.stderr = bytearray()
        self.next_id = 1
        self.notifications = []
        self.stdout_thread = threading.Thread(target=self._read_stdout)
        self.stderr_thread = threading.Thread(target=self._read_stderr)
        self.stdout_thread.start()
        self.stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        while True:
            line = self.process.stdout.readline()
            if not line:
                self.lines.put(None)
                return
            self.lines.put(line.decode("utf-8", "replace"))

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        while True:
            chunk = self.process.stderr.read(4096)
            if not chunk:
                return
            self.stderr.extend(chunk)

    def send(self, message: dict) -> None:
        assert self.process.stdin is not None
        payload = json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
        self.process.stdin.write(payload)
        self.process.stdin.flush()

    def request(self, method: str, params: dict, timeout: float) -> dict:
        request_id = self.next_id
        self.next_id += 1
        self.send({"id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeFailure(f"{method} timed out")
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty as error:
                raise ProbeFailure(f"{method} timed out") from error
            if line is None:
                raise ProbeFailure(f"{method} failed: exec-server stdout closed")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("method") and "id" not in message:
                self.notifications.append(message)
                continue
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise ProbeFailure(f"{method} failed: {message['error']}")
            result = message.get("result")
            if not isinstance(result, dict):
                raise ProbeFailure(f"{method} returned no result object")
            return result

    def notify(self, method: str, params: dict) -> None:
        self.send({"method": method, "params": params})

    def close_stdin(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
            self.process.stdin = None

    def join(self) -> None:
        self.stdout_thread.join(EXIT_GRACE_SECONDS)
        self.stderr_thread.join(EXIT_GRACE_SECONDS)


def decode_chunk(chunk) -> bytes:
    if not isinstance(chunk, str):
        return b""
    try:
        return base64.b64decode(chunk)
    except ValueError:
        return chunk.encode("utf-8", "replace")


def read_process_output(rpc: RpcClient, process_id: str) -> tuple[bytes, int | None]:
    collected = bytearray()
    exit_code = None
    after = None
    deadline = time.monotonic() + STARTUP_GRACE_SECONDS
    while time.monotonic() < deadline:
        result = rpc.request(
            "process/read",
            {
                "processId": process_id,
                "afterSeq": after,
                "maxBytes": None,
                "waitMs": 1000,
            },
            STARTUP_GRACE_SECONDS,
        )
        for chunk in result.get("chunks") or []:
            collected.extend(decode_chunk(chunk.get("chunk")))
        next_seq = result.get("nextSeq")
        if isinstance(next_seq, int) and next_seq > 0:
            after = next_seq - 1
        if result.get("exited"):
            exit_code = result.get("exitCode")
            break
    return bytes(collected), exit_code


def query_console(pid: int) -> dict:
    script = str(Path(__file__).resolve())
    flags = DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT
    try:
        completed = subprocess.run(
            [sys.executable, script, "--internal-role", "console-query", "--target-pid", str(pid)],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=flags,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"pid": pid, "attached": False, "error": str(error)}
    line = completed.stdout.strip().splitlines()
    if not line:
        return {"pid": pid, "attached": False, "error": completed.stderr.strip()}
    try:
        payload = json.loads(line[-1])
    except json.JSONDecodeError:
        return {"pid": pid, "attached": False, "error": line[-1]}
    payload["pid"] = pid
    return payload


def run_direct(observer: WinEventObserver, mode: str, output_dir: Path) -> dict:
    cmd = system_tool("cmd.exe")
    ping = system_tool("ping.exe")
    if cmd is None or ping is None:
        raise ProbeFailure("missing executable: cmd.exe or ping.exe")
    observer.start()
    preexisting_hwnds = existing_windows()
    preexisting = preexisting_processes()
    flags = DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT
    script = str(Path(__file__).resolve())
    process = popen_detached(
        [sys.executable, script, "--internal-role", "detached-spawn", "--spawn-mode", mode],
        flags,
        os.environ.copy(),
        output_dir,
    )
    tracker = ProcessTracker()
    tracker.add_pid(process.pid)
    try:
        assert process.stdout is not None
        line_bytes = read_stdout_line(process, STARTUP_GRACE_SECONDS)
        if line_bytes is None:
            raise ProbeFailure(f"direct {mode} helper did not report its child")
        line = line_bytes.decode("utf-8", "replace").strip()
        if "NOT_DETACHED" in line:
            raise ProbeFailure(f"direct {mode} parent was not detached: {line}")
        child_pid = 0
        if "pid=" in line:
            child_pid = int(line.split("pid=", 1)[1].strip())
            tracker.add_pid(child_pid)
        if child_pid:
            queried = query_console(child_pid)
            hwnd = int(queried.get("hwnd") or 0)
            if hwnd:
                tracker.console_hwnds.add(hwnd)
        else:
            queried = {"attached": False, "error": line}
        try:
            stdout, stderr = process.communicate(timeout=STARTUP_GRACE_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise ProbeFailure(f"direct {mode} helper timed out") from error
        time.sleep(1)
        events = observer.stop()
        tracker.scan(process.pid)
        analysis = analyze_events(events, preexisting_hwnds, tracker, preexisting)
        status = "pass"
        if analysis["visible_unknown"]:
            status = "inconclusive"
        elif mode == "visible" and not analysis["visible_test"]:
            status = "fail"
        elif mode == "hidden" and analysis["visible_test"]:
            status = "fail"
        if mode == "hidden" and int(queried.get("hwnd") or 0) and queried.get("visible"):
            status = "fail"
        record = {
            "name": f"direct-{mode}",
            "status": status,
            "parent_flags": flags,
            "helper_pid": process.pid,
            "child_pid": child_pid,
            "query": queried,
            "analysis": analysis,
            "stdout": stdout.decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace"),
        }
        (output_dir / f"direct-{mode}-events.json").write_text(
            json.dumps(events, indent=2),
            encoding="utf-8",
        )
        return record
    finally:
        if observer.thread is not None:
            observer.stop()
        if process.poll() is None:
            tracker.terminate_alive()
            process.kill()
            process.wait(timeout=EXIT_GRACE_SECONDS)
        tracker.close()


def server_env(home: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["CODEX_HOME"] = str(home)
    env["CODEX_PIPE_CONSOLE_PROBE"] = "1"
    for name in ("OPENAI_API_KEY", "CODEX_API_KEY"):
        env.pop(name, None)
    return env


def run_exec_case(
    observer: WinEventObserver,
    exe: Path,
    label: str,
    case: dict,
    output_dir: Path,
    expect_visible: bool,
) -> dict:
    home = output_dir / "homes" / f"{label}-{case['name']}"
    home.mkdir(parents=True, exist_ok=True)
    flags = DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT
    observer.start()
    preexisting_hwnds = existing_windows()
    preexisting = preexisting_processes()
    process = popen_detached(
        [str(exe), "exec-server", "--listen", "stdio"],
        flags,
        server_env(home),
        home,
    )
    tracker = ProcessTracker()
    tracker.add_pid(process.pid)
    rpc = RpcClient(process)
    transport = {}
    handshake = {}
    queries = []
    events: list[dict] = []
    analysis = {"visible_test": [], "visible_separate": [], "visible_unknown": []}
    forced: list[int] = []
    remaining: list[int] = []
    failure = None
    try:
        handshake_result = rpc.request(
            "initialize",
            {"clientName": "windows-pipe-console-probe"},
            STARTUP_GRACE_SECONDS,
        )
        handshake = {
            "session_id": handshake_result.get("sessionId"),
            "environment_info": handshake_result.get("environmentInfo"),
        }
        rpc.notify("initialized", {})
        process_id = f"{label}-{case['name']}"
        started = rpc.request(
            "process/start",
            {
                "processId": process_id,
                "argv": case["argv"],
                "cwd": file_uri(home),
                "env": child_env(),
                "tty": case["tty"],
                "pipeStdin": case["pipe_stdin"],
                "arg0": None,
            },
            STARTUP_GRACE_SECONDS,
        )
        if case.get("stdin") is not None:
            written = rpc.request(
                "process/write",
                {
                    "processId": process_id,
                    "chunk": base64.b64encode(case["stdin"]).decode("ascii"),
                    "writeId": f"{process_id}-stdin",
                },
                STARTUP_GRACE_SECONDS,
            )
            if written.get("status") != "accepted":
                raise ProbeFailure(f"process/write status {written.get('status')}")
        time.sleep(0.5)
        tracker.scan(process.pid)
        for pid in list(tracker.processes):
            if pid == process.pid:
                continue
            queried = query_console(pid)
            queries.append(queried)
            hwnd = int(queried.get("hwnd") or 0)
            if hwnd:
                tracker.console_hwnds.add(hwnd)
        output, exit_code = read_process_output(rpc, process_id)
        if exit_code is None:
            rpc.request("process/terminate", {"processId": process_id}, STARTUP_GRACE_SECONDS)
            output_after, exit_code = read_process_output(rpc, process_id)
            output += output_after
        text = output.decode("utf-8", "replace")
        transport = {
            "process_id": started.get("processId", process_id),
            "sandbox_type": started.get("sandboxType"),
            "exit_code": exit_code,
            "output": text,
            "marker": case["marker"] in text,
        }
        rpc.close_stdin()
        try:
            process.wait(timeout=EXIT_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            transport["server_exit"] = "timeout"
        time.sleep(1)
    except ProbeFailure as error:
        failure = str(error)
    finally:
        events = observer.stop() if observer.thread is not None else events
        try:
            tracker.scan(process.pid)
        except ProbeFailure:
            pass
        analysis = analyze_events(events, preexisting_hwnds, tracker, preexisting)
        alive = tracker.alive_pids()
        if alive or process.poll() is None:
            forced = tracker.terminate_alive()
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=EXIT_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        if forced:
            deadline = time.monotonic() + 2
            while tracker.alive_pids() and time.monotonic() < deadline:
                time.sleep(0.05)
        remaining = tracker.alive_pids()
        tracker.close()
        rpc.join()
    status = "pass"
    if analysis["visible_unknown"]:
        status = "inconclusive"
    elif expect_visible and not analysis["visible_test"]:
        status = "fail"
    elif not expect_visible and analysis["visible_test"] and not case["tty"]:
        status = "fail"
    elif case["tty"] and any(
        item["class"] not in {"ConsoleWindowClass", "PseudoConsoleWindow"}
        for item in analysis["visible_test"]
    ):
        status = "fail"
    if transport.get("exit_code") != 0 or not transport.get("marker"):
        if status == "pass":
            status = "fail"
    if forced or remaining:
        transport["failure_cleanup"] = {"terminated": forced, "remaining": remaining}
        if remaining:
            status = "fail"
    if failure:
        transport["error"] = failure
        if status == "pass":
            status = "fail"
    record = {
        "name": f"{label}-{case['name']}",
        "status": status,
        "exe": str(exe),
        "parent_flags": flags,
        "server_pid": process.pid,
        "handshake": handshake,
        "transport": transport,
        "queries": queries,
        "analysis": analysis,
        "stderr": bytes(rpc.stderr).decode("utf-8", "replace")[-4000:],
    }
    (output_dir / f"{label}-{case['name']}-events.json").write_text(
        json.dumps(events, indent=2),
        encoding="utf-8",
    )
    return record


def read_stdout_line(process: subprocess.Popen, timeout: float) -> bytes | None:
    holder: dict[str, bytes] = {}

    def target() -> None:
        assert process.stdout is not None
        holder["line"] = process.stdout.readline()

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return None
    return holder.get("line")


def cases() -> list[dict]:
    cmd = system_tool("cmd.exe")
    ping = system_tool("ping.exe")
    powershell = system_tool("WindowsPowerShell/v1.0/powershell.exe")
    if cmd is None or ping is None:
        raise ProbeFailure("missing executable: cmd.exe or ping.exe")
    if powershell is None:
        chain = f"\"{cmd}\" /D /C echo CHAIN_OK & \"{ping}\" -n 2 127.0.0.1 >NUL"
    else:
        chain = (
            f"\"{powershell}\" -NoLogo -NoProfile -Command \"Write-Output CHAIN_OK\" "
            f"& \"{ping}\" -n 2 127.0.0.1 >NUL"
        )
    return [
        {
            "name": "null",
            "tty": False,
            "pipe_stdin": False,
            "argv": [str(cmd), "/D", "/C", f"echo NULL_OUT& echo NULL_ERR 1>&2& \"{ping}\" -n 2 127.0.0.1 >NUL"],
            "marker": "NULL_OUT",
        },
        {
            "name": "piped",
            "tty": False,
            "pipe_stdin": True,
            "argv": [str(cmd), "/D", "/V:ON", "/C", f"set /p line=& echo PIPED:!line!& \"{ping}\" -n 2 127.0.0.1 >NUL"],
            "stdin": b"hello-pipe\r\n",
            "marker": "PIPED:hello-pipe",
        },
        {
            "name": "chain",
            "tty": False,
            "pipe_stdin": False,
            "argv": [str(cmd), "/D", "/C", chain],
            "marker": "CHAIN_OK",
        },
        {
            "name": "pty",
            "tty": True,
            "pipe_stdin": False,
            "argv": [str(cmd), "/D", "/C", f"echo PTY_OK& \"{ping}\" -n 2 127.0.0.1 >NUL"],
            "marker": "PTY_OK",
        },
    ]


def internal_main(args: argparse.Namespace) -> int:
    configure_win32()
    if args.internal_role == "console-query":
        hwnd, clients = console_attachment()
        if hwnd or clients:
            print(json.dumps({"attached": False, "error": "query helper was not detached"}))
            return 2
        if not kernel32.AttachConsole(args.target_pid):
            print(json.dumps({"attached": False, "error": ctypes.get_last_error()}))
            return 0
        try:
            console_hwnd = hwnd_int(kernel32.GetConsoleWindow())
            count_buffer = (wintypes.DWORD * 64)()
            count = int(kernel32.GetConsoleProcessList(count_buffer, 64))
            visible = False
            if console_hwnd:
                visible = bool(user32.IsWindowVisible(ctypes.c_void_p(console_hwnd)))
            print(
                json.dumps(
                    {
                        "attached": True,
                        "hwnd": console_hwnd,
                        "visible": visible,
                        "clients": count,
                    }
                )
            )
        finally:
            kernel32.FreeConsole()
        return 0
    hwnd, clients = console_attachment()
    if hwnd or clients:
        print("__CODEX_DIRECT_NOT_DETACHED__")
        return 2
    cmd = system_tool("cmd.exe")
    ping = system_tool("ping.exe")
    if cmd is None or ping is None:
        print("__CODEX_DIRECT_NOT_DETACHED__ missing-cmd")
        return 2
    flags = CREATE_UNICODE_ENVIRONMENT
    if args.spawn_mode == "hidden":
        flags |= CREATE_NO_WINDOW
    child = popen_detached(
        [str(cmd), "/D", "/C", f"echo DIRECT_OK& \"{ping}\" -n 3 127.0.0.1 >NUL"],
        flags,
        child_env(),
        None,
    )
    print(f"__CODEX_DIRECT_CHILD__ pid={child.pid}", flush=True)
    try:
        return child.wait(timeout=STARTUP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)
        return 1


def write_result(output_dir: Path, payload: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "result.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def public_main(args: argparse.Namespace) -> int:
    configure_win32()
    dwmapi = require_windows_apis()
    if not args.codex_exe or not args.control_exe or not args.output_dir:
        raise ProbeFailure("missing --codex-exe, --control-exe, or --output-dir")
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    candidate = require_exe(Path(args.codex_exe))
    control = require_exe(Path(args.control_exe))
    candidate_hash = sha256_file(candidate)
    control_hash = sha256_file(control)
    if same_path(candidate, control) or candidate_hash == control_hash:
        raise ProbeFailure("identity mismatch: candidate and control paths or hashes match")
    manifest = {
        "source_sha": git_sha(args.source_sha),
        "host": host_info(),
        "candidate": {
            "path": str(candidate),
            "sha256": candidate_hash,
            "version": command_text([str(candidate), "--version"], 10, CREATE_NO_WINDOW),
        },
        "control": {
            "path": str(control),
            "sha256": control_hash,
            "version": command_text([str(control), "--version"], 10, CREATE_NO_WINDOW),
        },
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    observer = WinEventObserver(dwmapi)
    scenario_records = []
    for mode in ("visible", "hidden"):
        record = run_direct(observer, mode, output_dir)
        scenario_records.append(record)
        if record["status"] != "pass":
            write_result(
                output_dir,
                {
                    "status": record["status"],
                    "manifest": manifest,
                    "scenarios": scenario_records,
                    "error": f"{record['name']} {record['status']}",
                },
            )
            raise_scenario(record)
    pipe_cases = [case for case in cases() if not case["tty"]]
    pty_cases = [case for case in cases() if case["tty"]]
    for case in pipe_cases:
        record = run_exec_case(observer, control, "control", case, output_dir, True)
        scenario_records.append(record)
        if record["status"] != "pass":
            write_result(
                output_dir,
                {
                    "status": record["status"],
                    "manifest": manifest,
                    "scenarios": scenario_records,
                    "error": f"{record['name']} {record['status']}",
                },
            )
            raise_scenario(record)
    for case in pipe_cases:
        record = run_exec_case(observer, candidate, "candidate", case, output_dir, False)
        scenario_records.append(record)
        if record["status"] != "pass":
            write_result(
                output_dir,
                {
                    "status": record["status"],
                    "manifest": manifest,
                    "scenarios": scenario_records,
                    "error": f"{record['name']} {record['status']}",
                },
            )
            raise_scenario(record)
    for case in pty_cases:
        record = run_exec_case(observer, candidate, "candidate", case, output_dir, False)
        scenario_records.append(record)
        if record["status"] != "pass":
            write_result(
                output_dir,
                {
                    "status": record["status"],
                    "manifest": manifest,
                    "scenarios": scenario_records,
                    "error": f"{record['name']} {record['status']}",
                },
            )
            raise_scenario(record)
    write_result(output_dir, {"status": "pass", "manifest": manifest, "scenarios": scenario_records})
    return 0


def raise_scenario(record: dict) -> None:
    message = f"{record['name']} {record['status']}"
    if record["status"] == "inconclusive":
        raise ProbeInconclusive(message)
    raise ProbeFailure(message)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex-exe")
    parser.add_argument("--control-exe")
    parser.add_argument("--output-dir")
    parser.add_argument("--source-sha")
    parser.add_argument("--internal-role", choices=["console-query", "detached-spawn"])
    parser.add_argument("--target-pid", type=int)
    parser.add_argument("--spawn-mode", choices=["visible", "hidden"])
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.internal_role:
        return internal_main(args)
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else None
    try:
        return public_main(args)
    except ProbeInconclusive as error:
        payload = {"status": "inconclusive", "error": str(error)}
        if output_dir is not None and not (output_dir / "result.json").exists():
            write_result(output_dir, payload)
        print(str(error), file=sys.stderr)
        return 2
    except ProbeFailure as error:
        payload = {"status": "fail", "error": str(error)}
        if output_dir is not None and not (output_dir / "result.json").exists():
            write_result(output_dir, payload)
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
