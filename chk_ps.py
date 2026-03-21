#!/usr/bin/env epython3
# -*- coding: utf-8 -*-

import argparse
import sys
from collections import defaultdict, Counter
import re

# pykdump/crash is only available inside crash epython
from pykdump.API import *
from LinuxDump import percpu

# ---------------------------------------------------------------------------
# FIX #2: Declare LIST_MAXEL at module level so walk_task_list() never hits
# a NameError if called before main() sets it (e.g. interactive/test use).
# ---------------------------------------------------------------------------
LIST_MAXEL = 200000

RHEL_VERSION = 8

# ---------------------------------------------------------------------------
# FIX #1: Declare the state-detection flags BEFORE get_state() so they are
# always in scope when get_state() is called, regardless of call order.
# ---------------------------------------------------------------------------
HAS_TASK_STATE   = False
HAS_TASK___STATE = False

# CPU-member detection flags
HAS_TASK_CPU  = False
HAS_TASK__CPU = False
HAS_TI_CPU    = False


def _is_tty():
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def get_rhel_version():
    """
    Detect RHEL major version from 'sys' command output.
    Uses re.search(r'\\.el(\\d+)') so multi-digit versions (el10, el11…)
    are parsed correctly — split('.el')[1][0] would truncate them to one digit.
    Falls back to the existing global value if parsing fails.
    """
    global RHEL_VERSION
    try:
        sys_output = exec_crash_command("sys")
    except Exception as e:
        print(f"[WARN] 'sys' command failed: {e}")
        return RHEL_VERSION

    for line in sys_output.splitlines():
        if "RELEASE" in line:
            # Examples:
            #   4.18.0-513.24.1.el8_9.x86_64
            #   3.10.0-1160.el7.x86_64
            #   6.x.y-z.el10.x86_64
            m = re.search(r'\.el(\d+)', line)
            if m:
                try:
                    RHEL_VERSION = int(m.group(1))
                except ValueError:
                    pass
            break

    return RHEL_VERSION


def _detect_state_member():
    """Probe which task_struct state field name this kernel uses."""
    global HAS_TASK_STATE, HAS_TASK___STATE
    # FIX #11: bare except: → except Exception:
    try:
        off = crash.member_offset("struct task_struct", "state")
        if off >= 0:
            HAS_TASK_STATE = True
    except Exception:
        pass

    try:
        off = crash.member_offset("struct task_struct", "__state")
        if off >= 0:
            HAS_TASK___STATE = True
    except Exception:
        pass


def _detect_cpu_members():
    """Probe which CPU-related fields are available in this kernel's task_struct."""
    global HAS_TASK_CPU, HAS_TASK__CPU, HAS_TI_CPU
    # FIX #11: bare except: → except Exception:
    try:
        crash.member_offset("struct task_struct", "cpu")
        HAS_TASK_CPU = True
    except Exception:
        pass
    try:
        crash.member_offset("struct task_struct", "_cpu")
        HAS_TASK__CPU = True
    except Exception:
        pass
    try:
        crash.member_offset("struct thread_info", "cpu")
        HAS_TI_CPU = True
    except Exception:
        pass


def get_state(task):
    """
    Read the numeric task state from a task_struct, using whichever field name
    this kernel exposes (__state on RHEL8+, state on RHEL7).
    Returns 0 (TASK_RUNNING) on any error so callers always get a valid int.
    """
    try:
        # Fast paths — use detected field names to avoid attribute-error overhead
        if HAS_TASK___STATE:
            return int(task.__state)
        if HAS_TASK_STATE:
            return int(task.state)

        # Fallback: try both names without prior detection
        try:
            return int(getattr(task, "__state"))
        except Exception:
            return int(getattr(task, "state"))
    except Exception:
        return 0


def _cpu_from_comm(comm):
    """Heuristic: extract CPU number from kworker thread name, e.g. kworker/3:1 → 3."""
    m = re.match(r'^kworker/(\d+):', comm)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return None


def get_cpu(task):
    """
    Robust CPU extraction, trying sources in order of reliability:
      1. task.cpu          — present on most kernels
      2. task._cpu         — older build variants
      3. thread_info.cpu   — via task.thread_info or task.stack pointer
      4. kworker name heuristic
    Returns the CPU number as an int, or -1 if not determinable.
    """
    # FIX #11: bare except: → except Exception: throughout
    if HAS_TASK_CPU:
        try:
            return int(task.cpu)
        except Exception:
            pass

    if HAS_TASK__CPU:
        try:
            return int(task._cpu)
        except Exception:
            pass

    if HAS_TI_CPU:
        try:
            return int(task.thread_info.cpu)
        except Exception:
            try:
                ti = readSU("struct thread_info", task.stack)
                return int(ti.cpu)
            except Exception:
                pass

    try:
        kcpu = _cpu_from_comm(str(task.comm))
        if kcpu is not None:
            return kcpu
    except Exception:
        pass

    return -1


def get_state_name(state):
    """
    Return a human-readable label for a raw task state value.

    FIX #5: The original used an elif chain, which silently dropped all but the
    first matching bit for combined states (e.g. 0x3 → only "TASK_INTERRUPTIBLE").
    Now builds a joined string so combined/transitional states are visible.
    """
    if state == 0:
        return "TASK_RUNNING"

    STATE_NAMES = [
        (0x0001, "TASK_INTERRUPTIBLE"),
        (0x0002, "TASK_UNINTERRUPTIBLE"),
        (0x0004, "__TASK_STOPPED"),
        (0x0008, "__TASK_TRACED"),
        (0x0010, "EXIT_DEAD"),
        (0x0020, "EXIT_ZOMBIE"),
        (0x0040, "TASK_DEAD"),
        (0x0080, "TASK_WAKEKILL"),
        (0x0100, "TASK_WAKING"),
        (0x0200, "TASK_PARKED"),
        (0x0400, "TASK_NOLOAD"),
        (0x0800, "TASK_NEW"),
        (0x1000, "TASK_RTLOCK_WAIT"),
    ]

    try:
        parts = [name for bit, name in STATE_NAMES if state & bit]
        return " | ".join(parts) if parts else f"UNKNOWN(0x{state:x})"
    except Exception:
        return "UNKNOWN"


def get_ps_code(task, debug=False):
    """
    Translate a task's state into a short two-letter ps-style code.

    Priority order matches the kernel's own logic:
      exit_state (ZO/DE) → stopped/traced (ST/TR) → parked (PA) →
      running (RU) → idle (ID) → waking (WA) → uninterruptible (UN) →
      interruptible (IN) → unknown (NE)
    """
    state = get_state(task)
    exit_state = int(getattr(task, "exit_state", 0))

    TASK_INTERRUPTIBLE   = 0x0001
    TASK_UNINTERRUPTIBLE = 0x0002
    __TASK_STOPPED       = 0x0004
    __TASK_TRACED        = 0x0008
    EXIT_DEAD            = 0x0010
    EXIT_ZOMBIE          = 0x0020
    TASK_PARKED          = 0x0040
    TASK_WAKING          = 0x0200
    TASK_NOLOAD          = 0x0400
    TASK_IDLE            = TASK_UNINTERRUPTIBLE | TASK_NOLOAD

    if debug:
        print(f"[DEBUG] pid={task.pid} comm={task.comm} "
              f"state=0x{state:x} exit_state=0x{exit_state:x}")

    if exit_state & EXIT_ZOMBIE:        return "ZO"
    if exit_state & EXIT_DEAD:          return "DE"
    if state & __TASK_STOPPED:          return "ST"
    if state & __TASK_TRACED:           return "TR"
    if state & TASK_PARKED:             return "PA"
    # state == 0 means the task is on a run queue (TASK_RUNNING).
    # This check comes after the flag-bit checks above because those bits
    # are mutually exclusive with state==0.
    if state == 0:                      return "RU"
    # TASK_IDLE must be tested before generic TASK_UNINTERRUPTIBLE because
    # IDLE is a strict subset of UNINTERRUPTIBLE (adds NOLOAD bit).
    if (state & TASK_IDLE) == TASK_IDLE: return "ID"
    if state & TASK_WAKING:             return "WA"
    if state & TASK_UNINTERRUPTIBLE:    return "UN"
    if state & TASK_INTERRUPTIBLE:      return "IN"
    return "NE"


def parse_bt_output(bt_output, max_depth=5):
    """
    Extract function names from crash's 'bt -s PID' output.

    'bt -s' lists frames from innermost (top of stack, most recent call) to
    outermost.  We take the top max_depth innermost frames and display them
    in caller → callee order (outermost → innermost of the slice) so the
    summary reads left-to-right as the call progression toward the sleep point.

    FIX #9: The original docstring said "last N (innermost) frames" but the
    code took funcs[:max_depth] which are the FIRST N lines = the INNERMOST
    frames.  Docstring and comment now match the code.

    Example (max_depth=5):
        schedule_hrtimeout_range -> schedule_hrtimeout -> do_sys_poll ->
        __se_sys_poll -> __x64_sys_poll
    """
    funcs = []
    for line in (bt_output or "").splitlines():
        m = re.search(r'\]\s+([a-zA-Z0-9_\.]+)', line)
        if not m:
            m = re.search(r'#\d+\s+([a-zA-Z0-9_\.]+)', line)
        if m:
            funcs.append(m.group(1))

    if not funcs:
        return None

    # Take the top max_depth innermost frames (first in bt output = deepest
    # in the stack = most recent calls), then reverse to show caller first.
    top = funcs[:max_depth]
    return ' -> '.join(reversed(top))


def colorize(s, color_code, enable=True):
    if not enable:
        return s
    return f"\033[{color_code}m{s}\033[0m"


def color_prio(prio, static_prio, sched, enable=True):
    """
    Colour-code the priority column:
      Green  — CFS task with a non-default nice value (static_prio != 120)
      Yellow — CFS task at default nice (120) but currently boosted (prio != static_prio)
               This indicates priority inheritance or a temporary boost.
      Cyan   — RT task (prio 0–99); distinct range from CFS
      Magenta— DL (deadline) task (prio conventionally -1)
      No colour — everything else (STOP, IDLE, unknown)

    FIX #10: RT and DL tasks were previously uncoloured, making them
    indistinguishable from normal CFS tasks at a glance.
    FIX #10: Added explanatory comments for each branch.
    """
    if sched == "RT":
        # RT priorities run 0–99; colour them cyan to stand out
        return colorize(f"{prio:>5}", "36", enable)
    if sched == "DL":
        # Deadline tasks report prio=-1; colour magenta
        return colorize(f"{prio:>5}", "35", enable)
    if sched == "CFS":
        if static_prio != 120:
            # Non-default nice value → green
            return colorize(f"{prio:>5}", "32", enable)
        if prio != static_prio:
            # Default nice but currently boosted (e.g. priority inheritance) → yellow
            return colorize(f"{prio:>5}", "33", enable)
    return f"{prio:>5}"


def get_idle_tasks():
    """Return the per-CPU idle tasks by reading rq->idle from each runqueue."""
    idle_tasks = []
    try:
        runqueue_addrs = percpu.get_cpu_var("runqueues")
        for addr in runqueue_addrs:
            rq = readSU("struct rq", addr)
            idle_tasks.append(rq.idle)
    except Exception as e:
        print(f"[ERROR] Failed to retrieve idle tasks: {e}")
    return idle_tasks


# FIX #7: _build_sched_classes() is now called lazily (on first use via
# get_sched_class) instead of at import time, so crash is guaranteed to be
# fully initialised when symbol resolution is attempted.
_SCHED_CLASSES = None

def _get_sched_classes():
    """
    Build and cache the sched_class address → name mapping.
    Called once on first use rather than at import time.
    """
    global _SCHED_CLASSES
    if _SCHED_CLASSES is not None:
        return _SCHED_CLASSES

    mapping = {}
    _KNOWN = [
        ("fair_sched_class",  "CFS"),
        ("rt_sched_class",    "RT"),
        ("stop_sched_class",  "STOP"),
        ("idle_sched_class",  "IDLE"),
        ("dl_sched_class",    "DL"),
    ]
    for sym, label in _KNOWN:
        try:
            if crash.symbol_exists(sym):
                mapping[crash.sym2addr(sym)] = label
        except Exception:
            pass

    _SCHED_CLASSES = mapping
    return _SCHED_CLASSES


def get_sched_class(task):
    try:
        addr = Addr(task.sched_class)
        return _get_sched_classes().get(addr, "UNKNOWN")
    except Exception:
        return "UNKNOWN"


# FIX #4: _read_thread_group() was a dead function — identical logic existed
# inside walk_task_list() as _walk_threads_legacy() but this standalone version
# was never called.  Removed to eliminate dead code and prevent the two
# implementations from silently diverging.


def walk_task_list(filter_code=None, only_active=False, debug=False,
                   collect_bt=False, depth=5):
    """
    Cross-version task walker (RHEL7–10+).

    RHEL7–9 : iterate init_task ring → for each leader walk thread_group list
    RHEL10+ : iterate init_task ring (contains all tasks) + optionally
              supplement via signal->thread_head / thread_node
    """
    results    = defaultdict(list)
    bt_counter = Counter()
    seen       = set()

    # FIX #8: _has_member() previously called readSymbol("init_task") and
    # discarded the result — the return value was determined solely by the
    # offset check.  Replaced with the simpler _has_member_type() logic.
    def _has_member(typename, member):
        """Return True if typename.member exists and has a non-negative offset."""
        try:
            off = crash.member_offset(typename, member)
            return isinstance(off, int) and off >= 0
        except Exception:
            return False

    def _has_member_type(typename, member):
        """Return True if typename.member exists (offset present)."""
        try:
            crash.member_offset(typename, member)
            return True
        except Exception:
            return False

    # --- init_task and global ring ---
    try:
        init_task = readSymbol("init_task")
    except Exception as e:
        print(f"[ERROR] Cannot read init_task: {e}")
        return results, bt_counter

    try:
        task_ring = readSUListFromHead(
            Addr(init_task.tasks),
            "tasks",
            "struct task_struct",
            maxel=LIST_MAXEL
        )
    except Exception as e:
        print(f"[ERROR] Error reading global task list: {e}")
        return results, bt_counter

    has_thread_group  = _has_member("struct task_struct", "thread_group")
    has_thread_node   = _has_member_type("struct task_struct", "thread_node")
    has_signal_ptr    = _has_member_type("struct task_struct", "signal")
    has_signal_head   = _has_member_type("struct signal_struct", "thread_head")
    modern_threadlist = (
        (not has_thread_group)
        and has_thread_node
        and has_signal_ptr
        and has_signal_head
    )

    # --- record helper ---
    def _record_task(task):
        addr = Addr(task)
        if addr in seen:
            return
        seen.add(addr)

        try:
            pid        = task.pid
            comm       = str(task.comm)
            state_val  = get_state(task)
            state_name = get_state_name(state_val)
            ppid       = 0
            try:
                if getattr(task, "real_parent", None):
                    ppid = task.real_parent.pid
                elif getattr(task, "parent", None):
                    ppid = task.parent.pid
                elif getattr(task, "group_leader", None):
                    ppid = task.group_leader.pid
            except Exception:
                ppid = 0
            on_cpu      = int(getattr(task, "on_cpu", 0))
            cpu         = get_cpu(task)
            ps_code     = get_ps_code(task, debug)
            sched_class = get_sched_class(task)
            prio        = task.prio
            static_prio = task.static_prio
        except Exception as e:
            if debug:
                print(f"[WARN] Error reading task at {addr:x}: {e}")
            return

        if filter_code and ps_code != filter_code:
            if debug:
                # FIX #3: was `task.state` — AttributeError on RHEL8+ where
                # the field is __state.  Use the already-computed state_val.
                print(
                    f"[DEBUG] Skipping {comm} (pid={pid}, state=0x{state_val:x}) "
                    f"ps_code={ps_code} != filter_code={filter_code}"
                )
            return

        if only_active and (ps_code != "RU" or on_cpu != 1):
            if debug:
                print(
                    f"[DEBUG] Skipping {comm} (pid={pid}) "
                    f"only_active failed: ps_code={ps_code}, on_cpu={on_cpu}"
                )
            return

        if debug:
            print(f"[DEBUG] PID={pid} COMM={comm} ST=0x{state_val:x} "
                  f"PS={ps_code} CPU={cpu} ON_CPU={on_cpu} "
                  f"SCHED={sched_class} PRIO={prio} ADDR={addr:x}")

        results[state_name].append({
            "pid":         pid,
            "ppid":        ppid,
            "comm":        comm,
            "state_val":   state_val,
            "on_cpu":      on_cpu,
            "cpu":         cpu,
            "ps":          ps_code,
            "sched":       sched_class,
            "prio":        prio,
            "static_prio": static_prio,
            "addr":        f"{addr:x}",
        })

        if collect_bt:
            try:
                bt_output = exec_crash_command(f"bt -s {pid}")
                trace = parse_bt_output(bt_output, max_depth=depth)
                if trace:
                    bt_counter[trace] += 1
            except Exception as e:
                if debug:
                    print(f"[WARN] Failed to collect bt for PID {pid}: {e}")

    # --- modern thread-group walker (RHEL10+) ---
    def _walk_threads_modern(leader):
        """
        Walk signal->thread_head list via thread_node member.
        Used on kernels where thread_group was removed (RHEL10+).
        """
        try:
            sig = leader.signal
            if not sig:
                return
            threads = readSUListFromHead(
                Addr(sig.thread_head),
                "thread_node",
                "struct task_struct",
                maxel=LIST_MAXEL
            )
            for th in threads:
                _record_task(th)
        except Exception as e:
            if debug:
                print(f"[WARN] RHEL10 thread walk failed for leader "
                      f"PID {getattr(leader, 'pid', -1)}: {e}")

    # --- legacy thread-group walker (RHEL7–9) ---
    def _walk_threads_legacy(leader):
        try:
            threads = readSUListFromHead(
                Addr(leader.thread_group),
                "thread_group",
                "struct task_struct",
                maxel=LIST_MAXEL
            )
            for th in threads:
                _record_task(th)
        except Exception as e:
            if debug:
                print(f"[WARN] Cannot read thread_group for "
                      f"PID {getattr(leader, 'pid', -1)}: {e}")

    # --- main traversal ---
    if has_thread_group:
        if debug:
            print("[DEBUG] Using thread_group traversal (RHEL7–9 mode)")
        for leader in task_ring:
            _record_task(leader)
            _walk_threads_legacy(leader)
    else:
        if debug:
            print("[DEBUG] Using global tasks traversal (RHEL10+ mode)")
        for t in task_ring:
            _record_task(t)

        if modern_threadlist:
            if debug:
                print("[DEBUG] Supplementing via signal->thread_head (RHEL10+)")
            for t in task_ring:
                try:
                    if getattr(t, "group_leader", None) == t:
                        _walk_threads_modern(t)
                except Exception:
                    continue
        else:
            if debug:
                print("[DEBUG] No modern per-thread list; relying on global ring only")

    # --- include per-CPU idle tasks ---
    for task in get_idle_tasks():
        _record_task(task)

    return results, bt_counter


def _default_sort_key(task):
    """Default sort: RU first, then on_cpu descending, then CPU, then PID."""
    ps_rank = {
        "RU": 0, "IN": 1, "UN": 2, "WA": 3, "ST": 4,
        "TR": 5, "ID": 6, "PA": 7, "DE": 8, "ZO": 9, "NE": 10,
    }
    return (
        ps_rank.get(task.get("ps"), 99),
        -int(task.get("on_cpu", 0)),
        int(task.get("cpu", -1)),
        int(task.get("pid", 0)),
    )


SORT_KEYS = {
    "pid":    lambda t: (int(t.get("pid", 0)),),
    "ppid":   lambda t: (int(t.get("ppid", 0)), int(t.get("pid", 0))),
    "st":     lambda t: (t.get("ps", ""), int(t.get("pid", 0))),
    "cpu":    lambda t: (int(t.get("cpu", -1)), int(t.get("pid", 0))),
    "task":   lambda t: (t.get("addr", ""),),
    "on_cpu": lambda t: (-int(t.get("on_cpu", 0)), int(t.get("pid", 0))),
    "sched":  lambda t: (t.get("sched", ""), int(t.get("pid", 0))),
    "prio":   lambda t: (int(t.get("prio", 0)), int(t.get("pid", 0))),
    "comm":   lambda t: (t.get("comm", ""), int(t.get("pid", 0))),
    "default": _default_sort_key,
}


def main():
    parser = argparse.ArgumentParser(description="Crash/epython task list analyzer")
    parser.add_argument("--state",  help="Filter tasks by state code (e.g. RU, IN, UN)")
    parser.add_argument("--active", action="store_true",
                        help="Only show active RU tasks (on_cpu==1)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-d", "--debug",   action="store_true", help="Debug output")
    parser.add_argument("--bt",    action="store_true",
                        help="Collect and group backtraces")
    parser.add_argument("--depth", type=int, default=5,
                        help="Depth of backtrace tail to group on (default: 5)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colours")
    parser.add_argument(
        "--sort",
        choices=list(SORT_KEYS.keys()),
        default="default",
        help="Sort order (pid, ppid, st, cpu, task, on_cpu, sched, prio, comm, default)",
    )
    parser.add_argument(
        "--maxel",
        type=int,
        default=200000,
        help="Safety bound when reading kernel lists (default: 200000)",
    )

    args = parser.parse_args()

    # One-time environment detection — must run before walk_task_list()
    get_rhel_version()
    _detect_cpu_members()
    _detect_state_member()

    # Allow the list guard to be tuned from the command line
    global LIST_MAXEL
    LIST_MAXEL = max(10000, int(args.maxel))

    print("Collecting task list...")
    results, bt_counter = walk_task_list(
        filter_code=args.state,
        only_active=args.active,
        debug=args.debug,
        collect_bt=args.bt,
        depth=args.depth,
    )

    if args.bt:
        # FIX #6: args.state is None when --state is not given; use "all" as
        # the label so the summary header never reads "summary(None tasks)".
        state_label = args.state or "all"
        print(f"\nBacktrace pattern summary ({state_label} tasks):")
        print("=" * 50)
        for trace, count in sorted(bt_counter.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"{count:<5}  {trace}")
        return

    # Flatten and sort
    all_tasks = []
    for _state, tasks in results.items():
        all_tasks.extend(tasks)

    keyfn = SORT_KEYS.get(args.sort, _default_sort_key)
    all_tasks.sort(key=keyfn)

    use_color = (not args.no_color) and _is_tty()
    print("\n   PID     PPID    ST  CPU        TASK       ON_CPU SCHED PRIO       COMM")
    print("==========================================================================")
    for t in all_tasks:
        prio_colored = color_prio(
            t["prio"], t["static_prio"], t["sched"], enable=use_color
        )
        print(
            f"{t['pid']:>8} {t['ppid']:>8}  {t['ps']:<3} {t['cpu']:>3} "
            f"{t['addr']:>14} {t['on_cpu']:>6} {t['sched']:>5} "
            f"{prio_colored}  {t['comm']:<16}"
        )


if __name__ == "__main__":
    main()

