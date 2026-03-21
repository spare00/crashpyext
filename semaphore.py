#!/usr/bin/env python3
"""
semaphore.py — Classic counting semaphore (struct semaphore) analyzer.

Shared infrastructure (RHEL version, task state, address resolution) is
provided by chk_lock.py and injected before any analysis function is called.
This module only contains semaphore-specific logic.
"""
import sys
from pykdump.API import *
from typing import Optional, Tuple, List

# Shared globals — injected by chk_lock._push_globals() at startup.
RHEL_VERSION = 8
DEBUG        = False


def dbg(msg):
    if DEBUG:
        print(f"[sem][dbg] {msg}")


# Injected by chk_lock._push_globals() — stubs keep the module importable
# standalone (e.g. during testing) even if chk_lock hasn't run yet.
def get_task_state(task):  # pragma: no cover
    raise RuntimeError("get_task_state not injected by chk_lock")


# ---------------------------------------------------------------------------
# Waiter list
# ---------------------------------------------------------------------------
def list_waiters(wait_list_addr) -> list:
    """
    Return list of (pid, comm, state, task_addr) for tasks waiting on the
    semaphore.

    Uses 'list -s semaphore_waiter.task -l semaphore_waiter.list -H <addr>'
    which emits alternating lines: a node address, then 'task = <addr>,'.
    """
    result = []
    try:
        cmd = f"list -s semaphore_waiter.task -l semaphore_waiter.list -H {wait_list_addr:#x}"
        output = exec_crash_command(cmd)
        lines = [l.strip() for l in output.splitlines() if l.strip()]

        # Lines come in pairs: node_addr, then "task = 0x...,".
        # FIX #11: The original used range(0, len, 2) with lines[i+1] which
        # raises IndexError on an odd-length list (truncated crash output).
        # Now handled explicitly with a bounds check and a warning.
        i = 0
        while i < len(lines):
            if i + 1 >= len(lines):
                print(f"Warning: incomplete semaphore_waiter entry at line {i}: {lines[i]!r}")
                break
            try:
                task_line = lines[i + 1]
                if "task =" in task_line:
                    task_str  = task_line.split("=", 1)[1].strip().rstrip(",")
                    task_addr = int(task_str, 16)
                    task      = readSU("struct task_struct", task_addr)
                    state     = get_task_state(task)
                    result.append((task.pid, task.comm, state, task_addr))
                else:
                    result.append(("?", task_line, "?", 0))
            except Exception as e:
                dbg(f"list_waiters(): error at line {i}: {e}")
                result.append(("?", lines[i], "?", 0))
            i += 2

    except Exception as e:
        print(f"Error listing waiters for semaphore at {wait_list_addr:#x}: {e}")
    return result


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
def _read_count(sem):
    """
    Read semaphore.count, handling kernels where it is atomic_t (has .counter)
    vs kernels where it is a plain unsigned int.
    """
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
    """Read and decode a struct semaphore from the vmcore."""
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
        "address":        f"{sem_addr:#x}",
        "count":          count_val,
        "wait_list_next": f"{int(sem.wait_list.next):#x}",
        "wait_list_prev": f"{int(sem.wait_list.prev):#x}",
    }

    if list_waiters_flag:
        info["waiters"] = (
            list_waiters(int(sem.wait_list)) if hasattr(sem, "wait_list") else []
        )

    return info


def _classify(count: int, waiter_len: Optional[int]) -> Tuple[str, str, List[str]]:
    """Return (state_label, description, issues[]) for the given count value."""
    issues = []
    if count > 0:
        state = "✅ Stable"
        desc  = f"{count} slot(s) available."
        if waiter_len and waiter_len > 0:
            issues.append("⚠️ Waiters present while count > 0 — possible missed wakeup or transient race.")
    elif count == 0:
        state = "ℹ️ Contended / Fully held"
        desc  = "No available slots."
    else:
        implied = -count
        state   = "🌀 Contended"
        desc    = f"Negative count implies ~{implied} waiter(s) (implementation detail)."
        if waiter_len is not None and waiter_len != implied:
            issues.append(
                f"ℹ️ Waiter list length ({waiter_len}) != implied ({implied})"
                " — can be normal across kernels."
            )
    return state, desc, issues


def analyze_semaphore(info: dict, verbose: bool = False):
    """Print a human-readable analysis of a decoded semaphore."""
    if not info:
        print("No valid semaphore information.")
        return

    count = info["count"]
    print("\n=== Semaphore Status ===")
    print(f"Address:        {info['address']}")
    print(f"Count:          0x{count:08X} ({count})")
    print(f"Wait List Next: {info['wait_list_next']}")
    print(f"Wait List Prev: {info['wait_list_prev']}")

    waiter_len            = len(info["waiters"]) if "waiters" in info else None
    state_type, desc, issues = _classify(count, waiter_len)

    print(f"\n  🧠 Inferred State:")
    print(f"  {state_type}: {desc}")
    for msg in issues:
        print(f"  {msg}")

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

