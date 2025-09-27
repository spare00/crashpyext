#!/usr/bin/env python3

import sys
from pykdump.API import *  # exec_crash_command, readSU, symbol_exists, crash, percpu, etc.

RHEL_VERSION = 8
kernel_version = "Unknown"
DEBUG = False

# ---------- Utilities ----------
def logging(msg):
    if DEBUG:
        print(f"[sem][DEBUG] {msg}")


def get_rhel_version():
    """Determines the major RHEL version from the kernel release."""
    global RHEL_VERSION, kernel_version
    sys_output = exec_crash_command("sys")
    for line in sys_output.splitlines():
        if "RELEASE" in line:
            kernel_version = line.split()[-1]
            if "el" in kernel_version:
                try:
                    RHEL_VERSION = int(kernel_version.split(".el")[1][0])
                except (IndexError, ValueError):
                    pass
    print(f"Detected RHEL Version: {RHEL_VERSION} (Kernel: {kernel_version})")
    return RHEL_VERSION


def resolve_address(input_value):
    try:
        if isinstance(input_value, int):
            return input_value
        if input_value.startswith("0x"):
            return int(input_value, 16)
        elif all(c in "0123456789abcdefABCDEF" for c in input_value):
            return int(input_value, 16)
        elif symbol_exists(input_value):
            return readSymbol(input_value)
        else:
            print(f"Error: '{input_value}' is neither a valid address nor a known symbol.")
            sys.exit(1)
    except Exception as e:
        print(f"Error resolving address for {input_value}: {e}")
        sys.exit(1)


# ---------- Task state helpers ----------
_task_state_map = {
    0x00: "TASK_RUNNING",
    0x01: "TASK_INTERRUPTIBLE",
    0x02: "TASK_UNINTERRUPTIBLE",
    0x04: "__TASK_STOPPED",
    0x08: "__TASK_TRACED",
    0x10: "EXIT_DEAD",
    0x20: "EXIT_ZOMBIE",
    0x40: "TASK_PARKED" if RHEL_VERSION >= 8 else "TASK_DEAD",
    0x80: "TASK_DEAD" if RHEL_VERSION >= 8 else "TASK_WAKEKILL",
    0x100: "TASK_WAKEKILL" if RHEL_VERSION >= 8 else "TASK_WAKING",
    0x200: "TASK_WAKING" if RHEL_VERSION >= 8 else "TASK_PARKED",
    0x400: "TASK_NOLOAD" if RHEL_VERSION >= 8 else "TASK_STATE_MAX",
    0x800: "TASK_NEW" if RHEL_VERSION >= 8 else "TASK_STATE_MAX",
    0x1000: "TASK_RTLOCK_WAIT" if RHEL_VERSION >= 8 else "TASK_STATE_MAX",
    0x2000: "TASK_STATE_MAX" if RHEL_VERSION >= 9 else "TASK_STATE_MAX",
}


def _task_state(task) -> str:
    try:
        val = task.state if RHEL_VERSION >= 8 else task.__state
        flags = [name for bit, name in _task_state_map.items() if val & bit]
        return " | ".join(flags) if flags else f"Unknown ({val})"
    except Exception:
        return "Unknown"


# ---------- Waiters ----------
def list_waiters(wait_list_addr) -> list:
    """Return list of (pid, comm, state, taddr) for tasks waiting on the semaphore."""
    result = []
    try:
        cmd = f"list -s semaphore_waiter.task -l semaphore_waiter.list {wait_list_addr:#x}"
        output = exec_crash_command(cmd)
        for line in (l.strip() for l in output.splitlines() if l.strip()):
            try:
                taddr = int(line, 16)
                task = readSU("struct task_struct", taddr)
                pid = task.pid
                comm = task.comm
                state = _task_state(task)
                result.append((pid, comm, state, taddr))
            except Exception:
                result.append(("?", line, "?", 0))
    except Exception as e:
        print(f"Error listing waiters for semaphore at {wait_list_addr:#x}: {e}")
    return result


# ---------- Core ----------
def _read_count(sem):
    """Handle kernels where semaphore.count is unsigned int vs atomic_t."""
    try:
        return int(sem.count.counter)
    except Exception:
        try:
            return int(sem.count)
        except Exception:
            raw = exec_crash_command(f"struct semaphore {int(sem):#x} -x")
            print(raw)
            raise


def get_semaphore_info(sem_addr: int, list_waiters_flag: bool = False):
    try:
        sem = readSU("struct semaphore", sem_addr)
    except Exception as e:
        print(f"Error accessing semaphore at {sem_addr:#x}: {e}")
        return None

    try:
        count_val = _read_count(sem)
    except Exception as e:
        print(f"Error reading semaphore.count at {sem_addr:#x}: {e}")
        return None

    info = {
        "address": f"{sem_addr:#x}",
        "count": count_val,
        "wait_list_next": f"{int(sem.wait_list.next):#x}",
        "wait_list_prev": f"{int(sem.wait_list.prev):#x}",
    }

    if list_waiters_flag:
        info["waiters"] = list_waiters(int(sem.wait_list)) if hasattr(sem, 'wait_list') else []

    return info


def _classify(count: int, waiter_len: int | None) -> tuple[str, str, list[str]]:
    """Return (state_type, description, issues[])"""
    issues = []
    if count > 0:
        state = "✅ Stable"
        desc = f"{count} slot(s) available."
        if waiter_len and waiter_len > 0:
            issues.append("⚠️ Waiters present while count > 0 — possible missed wakeup or transient race.")
    elif count == 0:
        state = "ℹ️ Contended / Fully held"
        desc = "No available slots."
    else:  # count < 0
        implied = -count
        state = "🌀 Contended"
        desc = f"Negative count implies ~{implied} waiter(s) (implementation detail)."
        if waiter_len is not None and waiter_len != implied:
            issues.append(f"ℹ️ Waiter list length ({waiter_len}) != implied ({implied}) — can be normal across kernels.")
    return state, desc, issues


def analyze_semaphore(info: dict, verbose: bool = False):
    if not info:
        print("No valid semaphore information.")
        return

    count = info["count"]
    print("\n=== Semaphore Status ===")
    print(f"Address: {info['address']}")
    print(f"Count:   0x{count:08X} ({count})")
    print(f"Wait List Next: {info['wait_list_next']}")
    print(f"Wait List Prev: {info['wait_list_prev']}")

    waiter_len = len(info.get("waiters", [])) if "waiters" in info else None
    state_type, desc, issues = _classify(count, waiter_len)

    print(f"\n  🧠 Inferred State:")
    print(f"  {state_type}: {desc}")

    if issues:
        for m in issues:
            print(m)

    if "waiters" in info:
        waiters = info["waiters"]
        if waiters:
            print("\nWaiting Tasks:")
            print(f"{'PID':<10} {'Command':<20} {'State':<25} Address")
            print("-" * 72)
            for pid, comm, state, taddr in waiters:
                print(f"{pid!s:<10} {comm:<20} {state:<25} {taddr:#x}")
            print(f"\nNumber of waiters: {len(waiters)}")
        else:
            print("\nWaiting Tasks: none")
