#!/usr/bin/env python3
"""
chk_lock.py — Unified Lock Analyzer for Linux vmcore files.

Shared infrastructure (version detection, architecture detection, address
resolution, task-state decoding) lives here and is imported by each lock
module.  This avoids the copy-paste that previously existed across all four
modules and ensures every fix applies everywhere automatically.

Usage (inside crash):
    extend chk_lock.py
    chk_lock qspinlock  <addr|symbol> [-f] [-v] [-d]
    chk_lock spinlock   <addr|symbol> [-v] [-d]
    chk_lock mutex      <addr|symbol> [-l] [-v] [-d]
    chk_lock rwsem      <addr|symbol> [-l] [-v] [-d]
    chk_lock sem        <addr|symbol> [-l] [-v] [-d]
"""

import argparse
import sys
from pykdump.API import *

import qspinlock
import mutex
import rwsem
import semaphore as sem

# ---------------------------------------------------------------------------
# Shared globals — written once by _init_environment(), read by all modules.
# ---------------------------------------------------------------------------
RHEL_VERSION   = 8
KERNEL_VERSION = "Unknown"
ARCH           = "64-bit"
DEBUG          = False


# ---------------------------------------------------------------------------
# Debug helper
# ---------------------------------------------------------------------------
def dbg(msg):
    """Print msg only when DEBUG is True."""
    if DEBUG:
        print(f"[chk_lock][dbg] {msg}")


# ---------------------------------------------------------------------------
# One-time environment detection
# ---------------------------------------------------------------------------
def _init_environment(debug=False):
    """
    Parse 'sys' output once and populate the shared globals.
    Called at the top of main() before dispatching to any lock module,
    so every module receives consistent, already-detected values rather
    than each re-running exec_crash_command("sys") independently.
    """
    global RHEL_VERSION, KERNEL_VERSION, ARCH, DEBUG
    DEBUG = debug

    sys_output = exec_crash_command("sys")

    for line in sys_output.splitlines():
        # RELEASE line — e.g.  "RELEASE: 5.14.0-427.13.1.el9_4.x86_64"
        if "RELEASE" in line:
            KERNEL_VERSION = line.split()[-1]
            if "el" in KERNEL_VERSION:
                try:
                    RHEL_VERSION = int(KERNEL_VERSION.split(".el")[1][0])
                except (IndexError, ValueError) as e:
                    dbg(f"_init_environment(): could not parse RHEL version: {e}")

        # MACHINE line — e.g.  "MACHINE: x86_64  (3100 Mhz)"
        elif "MACHINE" in line:
            if any(isa in line for isa in ("x86_64", "aarch64", "ppc64", "s390x")):
                ARCH = "64-bit"
            elif any(isa in line for isa in ("i686", "i386")):
                ARCH = "32-bit"
            else:
                dbg(f"_init_environment(): unrecognised MACHINE line: {line.strip()!r}")

    print(f"Detected RHEL Version : {RHEL_VERSION} (Kernel: {KERNEL_VERSION})")
    print(f"Detected Architecture : {ARCH}")


# ---------------------------------------------------------------------------
# Shared: address resolution
# ---------------------------------------------------------------------------
def resolve_address(input_value):
    """
    Resolve a hex address string or kernel symbol name to an integer address.

    Accepts:
      - "0x"-prefixed hex strings
      - bare hex strings (all hex digits, e.g. "ffffa0001234abcd")
      - kernel symbol names (resolved via pykdump's symbol_exists/readSymbol)
    """
    try:
        if isinstance(input_value, int):
            return input_value
        if input_value.startswith("0x"):
            return int(input_value, 16)
        if all(c in "0123456789abcdefABCDEF" for c in input_value):
            return int(input_value, 16)
        if symbol_exists(input_value):
            return readSymbol(input_value)
        print(f"Error: '{input_value}' is neither a valid address nor a known symbol.")
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        print(f"Error resolving address for '{input_value}': {e}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Shared: task state decoding
# ---------------------------------------------------------------------------
def get_task_state_map():
    """
    Return the task-state bit->name dict for the currently detected RHEL version.

    This is a function (not a module-level dict) so the version-dependent
    entries are evaluated at call time, after _init_environment() has run,
    rather than at import time when RHEL_VERSION is still the default 8.
    """
    return {
        0x0000: "TASK_RUNNING",
        0x0001: "TASK_INTERRUPTIBLE",
        0x0002: "TASK_UNINTERRUPTIBLE",
        0x0004: "__TASK_STOPPED",
        0x0008: "__TASK_TRACED",
        0x0010: "EXIT_DEAD",
        0x0020: "EXIT_ZOMBIE",
        0x0040: "TASK_PARKED"       if RHEL_VERSION >= 8 else "TASK_DEAD",
        0x0080: "TASK_DEAD"         if RHEL_VERSION >= 8 else "TASK_WAKEKILL",
        0x0100: "TASK_WAKEKILL"     if RHEL_VERSION >= 8 else "TASK_WAKING",
        0x0200: "TASK_WAKING"       if RHEL_VERSION >= 8 else "TASK_PARKED",
        0x0400: "TASK_NOLOAD"       if RHEL_VERSION >= 8 else "TASK_STATE_MAX",
        0x0800: "TASK_NEW"          if RHEL_VERSION >= 8 else "TASK_STATE_MAX",
        0x1000: "TASK_RTLOCK_WAIT"  if RHEL_VERSION >= 8 else "TASK_STATE_MAX",
        0x2000: "TASK_STATE_MAX",
    }


def get_task_state(task):
    """
    Return a human-readable task state string for the given task_struct.

    Tries task.__state (RHEL8+) then task.state (RHEL7), then falls back to
    a crash 'p' command as a last resort (borrowed from semaphore.py, which
    had the most robust implementation across the original modules).
    """
    val = None

    for field in ("__state", "state"):
        try:
            val = int(getattr(task, field))
            dbg(f"get_task_state(): read '{field}' = {val:#x}")
            break
        except (KeyError, AttributeError):
            continue

    if val is None:
        # Last resort: ask crash directly.
        try:
            raw = exec_crash_command(
                f"p ((struct task_struct *){int(task):#x})->__state"
            )
            val = int(raw.strip().split()[-1], 0)
            dbg(f"get_task_state(): crash fallback returned {val:#x}")
        except Exception:
            dbg("get_task_state(): all methods failed")
            return "Unknown"

    if val == 0:
        return "TASK_RUNNING"

    task_state_map = get_task_state_map()
    flags = [name for bit, name in task_state_map.items() if bit and (val & bit)]
    return " | ".join(flags) if flags else f"Unknown({val:#x})"


# ---------------------------------------------------------------------------
# Shared: non-empty wait-list hint
# ---------------------------------------------------------------------------
def warn_if_waiters(next_addr, prev_addr, flag_set=False):
    """
    Print a hint when the wait list is non-empty but -l was not requested.

    next_addr / prev_addr are the raw integer addresses from list_head.next
    and list_head.prev.  A circular list is empty when next == prev (both
    point back to the list_head itself).
    """
    list_empty = (next_addr == prev_addr)
    if not list_empty and not flag_set:
        print("ℹ️  Wait list is non-empty — re-run with -l to list waiters.")


# ---------------------------------------------------------------------------
# Propagate shared state into each lock module before dispatching
# ---------------------------------------------------------------------------
def _push_globals():
    """Copy the shared globals into each lock module's namespace."""
    for mod in (qspinlock, mutex, rwsem, sem):
        # Every module exposes RHEL_VERSION; mutex uses lowercase rhel_version.
        if hasattr(mod, "RHEL_VERSION"):
            mod.RHEL_VERSION = RHEL_VERSION
        if hasattr(mod, "rhel_version"):
            mod.rhel_version = RHEL_VERSION
        if hasattr(mod, "DEBUG"):
            mod.DEBUG = DEBUG

    # rwsem also needs ARCH
    rwsem.ARCH = ARCH

    # Point each module's helper functions at the shared implementations so
    # they all benefit from the single detection pass and consistent logic.
    for mod in (qspinlock, mutex, rwsem, sem):
        mod.get_task_state     = get_task_state
        mod.get_task_state_map = get_task_state_map
        mod.resolve_address    = resolve_address
        mod.dbg                = dbg


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Unified Lock Analyzer for VMcore")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Enable debug output (all subcommands)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # qspinlock
    p_qs = subparsers.add_parser("qspinlock", help="Analyze qspinlock state")
    p_qs.add_argument("addr", help="Address or symbol")
    p_qs.add_argument("-f", "--flowchart", action="store_true")
    p_qs.add_argument("-v", "--verbose", action="store_true")

    # spinlock (wrapper around qspinlock)
    p_sl = subparsers.add_parser("spinlock", help="Analyze spinlock_t")
    p_sl.add_argument("addr", help="Address or symbol")
    p_sl.add_argument("-v", "--verbose", action="store_true")

    # mutex
    p_mx = subparsers.add_parser("mutex", help="Analyze mutex")
    p_mx.add_argument("addr", help="Address or symbol")
    p_mx.add_argument("-l", "--list", action="store_true",
                      help="List waiting tasks")
    p_mx.add_argument("-v", "--verbose", action="store_true")

    # rwsem
    p_rw = subparsers.add_parser("rwsem", help="Analyze rw_semaphore")
    p_rw.add_argument("addr", help="Address (hex)")
    p_rw.add_argument("-l", "--list", action="store_true",
                      help="List waiting tasks")
    p_rw.add_argument("-v", "--verbose", action="store_true")

    # sem (classic counting semaphore)
    p_sem = subparsers.add_parser("sem",
                                   help="Analyze classic semaphore (struct semaphore)")
    p_sem.add_argument("addr", help="Address or symbol")
    p_sem.add_argument("-l", "--list", action="store_true",
                       help="List waiting tasks")
    p_sem.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    # --- One-time environment detection ---
    _init_environment(debug=args.debug)

    # --- Push shared state into all modules ---
    _push_globals()

    # --- Dispatch ---
    if args.command in ("qspinlock", "spinlock"):
        if args.command == "qspinlock" and args.flowchart:
            qspinlock.show_qspinlock_flowchart()
        addr = resolve_address(args.addr)
        qspinlock.analyze_qspinlock(addr, getattr(args, "verbose", False), args.debug)

    elif args.command == "mutex":
        addr = resolve_address(args.addr)
        info = mutex.get_mutex_info(addr, args.list)
        if info:
            next_addr = int(info["wait_list_next"], 16)
            prev_addr = int(info["wait_list_prev"], 16)
            warn_if_waiters(next_addr, prev_addr, flag_set=args.list)
        mutex.analyze_mutex(info, verbose=args.verbose)

    elif args.command == "rwsem":
        addr = resolve_address(args.addr)
        rwsem.analyze_rw_semaphore_from_vmcore(addr, args.list, args.verbose, args.debug)

    elif args.command == "sem":
        addr = resolve_address(args.addr)
        info = sem.get_semaphore_info(addr, args.list)
        if info:
            next_addr = int(info["wait_list_next"], 16)
            prev_addr = int(info["wait_list_prev"], 16)
            warn_if_waiters(next_addr, prev_addr, flag_set=args.list)
        sem.analyze_semaphore(info, args.verbose)


if __name__ == "__main__":
    main()

