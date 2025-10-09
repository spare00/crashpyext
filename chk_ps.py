#!/usr/bin/env epython3
# -*- coding: utf-8 -*-

import argparse
import sys
from collections import defaultdict, Counter
import re

# pykdump/crash is only available inside crash epython
from pykdump.API import *
from LinuxDump import percpu

RHEL_VERSION = 8

def _is_tty():
    try:
        return sys.stdout.isatty()
    except Exception:
        return False

def get_rhel_version():
    """
    Detect RHEL major from 'sys' command output.
    Falls back to existing global value if parsing fails.
    """
    global RHEL_VERSION
    kernel_version = "unknown"
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
            parts = line.split()
            if parts:
                kernel_version = parts[-1]
            m = re.search(r'\.el(\d+)', line)
            if m:
                try:
                    RHEL_VERSION = int(m.group(1))
                except ValueError:
                    pass
            break

    print(f"Detected RHEL Version: {RHEL_VERSION} (Kernel: {kernel_version})")
    return RHEL_VERSION

def _build_sched_classes():
    """
    Resolve known sched_class symbols present in this kernel.
    Avoids KeyError by conditionally inserting available ones.
    """
    mapping = {}
    try:
        mapping[crash.sym2addr("fair_sched_class")] = "CFS"
    except Exception:
        pass
    try:
        mapping[crash.sym2addr("rt_sched_class")] = "RT"
    except Exception:
        pass
    try:
        mapping[crash.sym2addr("stop_sched_class")] = "STOP"
    except Exception:
        pass
    try:
        if crash.symbol_exists("idle_sched_class"):
            mapping[crash.sym2addr("idle_sched_class")] = "IDLE"
    except Exception:
        pass
    try:
        if crash.symbol_exists("dl_sched_class"):
            mapping[crash.sym2addr("dl_sched_class")] = "DL"
    except Exception:
        pass
    return mapping

SCHED_CLASSES = _build_sched_classes()

def get_sched_class(task):
    try:
        addr = Addr(task.sched_class)
        return SCHED_CLASSES.get(addr, "UNKNOWN")
    except Exception:
        return "UNKNOWN"

def get_state(task):
    try:
        if RHEL_VERSION == 7:
            return task.state
        return task.__state
    except Exception:
        return -1

# Detect available members only once
HAS_TASK_CPU   = False
HAS_TASK__CPU  = False
HAS_TI_CPU     = False

def _detect_cpu_members():
    global HAS_TASK_CPU, HAS_TASK__CPU, HAS_TI_CPU
    try:
        crash.member_offset("struct task_struct", "cpu")
        HAS_TASK_CPU = True
    except:
        pass
    try:
        crash.member_offset("struct task_struct", "_cpu")
        HAS_TASK__CPU = True
    except:
        pass
    try:
        crash.member_offset("struct thread_info", "cpu")
        HAS_TI_CPU = True
    except:
        pass

def _cpu_from_comm(comm):
    # e.g. kworker/1:3 → CPU=1
    m = re.match(r'^kworker/(\d+):', comm)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return None

def get_cpu(task):
    """
    Robust + fast CPU extraction:
      1) task.cpu (if present)
      2) task._cpu (older builds)
      3) thread_info.cpu (if available; direct or via stack)
      4) heuristic from kworker name
    Returns int CPU, or -1 if unknown.
    """
    # 1) task.cpu
    if HAS_TASK_CPU:
        try:
            return int(task.cpu)
        except:
            pass

    # 2) task._cpu
    if HAS_TASK__CPU:
        try:
            return int(task._cpu)
        except:
            pass

    # 3) thread_info.cpu
    if HAS_TI_CPU:
        try:
            return int(task.thread_info.cpu)
        except:
            try:
                ti = readSU("struct thread_info", task.stack)
                return int(ti.cpu)
            except:
                pass

    # 4) heuristic for kworkers
    try:
        comm = str(task.comm)
        kcpu = _cpu_from_comm(comm)
        if kcpu is not None:
            return kcpu
    except:
        pass

    return -1

def get_state_name(state):
    # Basic mapping — keep behavior consistent with your original
    try:
        if state == 0:
            return "TASK_RUNNING"
        elif state & 0x1:
            return "TASK_INTERRUPTIBLE"
        elif state & 0x2:
            return "TASK_UNINTERRUPTIBLE"
        elif state & 0x4:
            return "__TASK_STOPPED"
        elif state & 0x8:
            return "__TASK_TRACED"
        elif state & 0x10:
            return "EXIT_DEAD"
        elif state & 0x20:
            return "EXIT_ZOMBIE"
        elif state & 0x40:
            return "TASK_DEAD"
        else:
            return "UNKNOWN"
    except Exception:
        return "UNKNOWN"

def get_ps_code(task, debug=False):
    """
    ps-like state code. On this RHEL7 build, crash treats TASK_DEAD (0x40)
    with any non-zero exit_state as ZO. Keep that behavior here.
    """
    try:
        es = None
        try:
            exit_state = int(getattr(task, 'exit_state', 0))
        except Exception:
            try:
                es = getattr(task, 'exit_state', 0)
                exit_state = int(getattr(es, 'value', 0))
            except Exception:
                try:
                    # only attempt if es was set successfully
                    if es is not None:
                        exit_state = int(str(es), 0)
                    else:
                        exit_state = 0
                except Exception:
                    exit_state = 0

        state = int(get_state(task))

        # Match crash behavior seen in your dump:
        # TASK_DEAD + any exit_state => ZO
        if (state & 0x40):  # TASK_DEAD
            if exit_state != 0:
                if debug: print(f"[DEBUG] classify ZO: state=0x{state:x} exit_state=0x{exit_state:x}")
                return "ZO"
            else:
                # Rare, but keep DE fallback if TASK_DEAD with no exit_state
                if debug: print(f"[DEBUG] classify DE: state=0x{state:x} exit_state=0x{exit_state:x}")
                return "DE"

        # Remaining mappings (same as before)
        if exit_state & 0x20:   # EXIT_ZOMBIE (classic)
            return "ZO"
        if exit_state & 0x10:   # EXIT_DEAD
            return "DE"
        if state == 0x0000:
            return "RU"
        if state == 0x0402:
            return "ID"
        if state & 0x0001:
            return "IN"
        if state & 0x0002:
            return "UN"
        if state & 0x0004:
            return "ST"
        if state & 0x0008:
            return "TR"
        if state & 0x0200:
            return "WA"
        if state & 0x0040:
            # If we ever get here (no exit_state), treat as DE
            return "DE"

        if not getattr(task, 'mm', None):
            return "ID"

        return "NE"
    except Exception:
        return "NE"

def parse_bt_output(bt_output, max_depth=5):
    """
    Extract the function names from crash's 'bt -s PID' output.
    Return the last N (innermost) frames, shown from earliest to latest.

    Example desired order:
        __bmhook_send_event_common -> bmhook_scan_wait -> schedule_timeout -> schedule -> __schedule
    """
    funcs = []
    for line in (bt_output or "").splitlines():
        # Match common crash bt line forms
        m = re.search(r'\]\s+([a-zA-Z0-9_\.]+)', line)
        if not m:
            m = re.search(r'#\d+\s+([a-zA-Z0-9_\.]+)', line)
        if m:
            funcs.append(m.group(1))

    if not funcs:
        return None

    # Keep the *first* max_depth frames (bottom of stack)
    tail = funcs[:max_depth]

    # Reverse them to show "earlier → later" (caller → callee)
    return ' -> '.join(reversed(tail))

def colorize(s, color_code, enable=True):
    if not enable:
        return s
    return f"\033[{color_code}m{s}\033[0m"

def color_prio(prio, static_prio, sched, enable=True):
    if sched == "CFS" and static_prio != 120:
        return colorize(f"{prio:>5}", "32", enable)  # green
    elif sched == "CFS" and prio != static_prio:
        return colorize(f"{prio:>5}", "33", enable)  # yellow
    else:
        return f"{prio:>5}"

def get_idle_tasks():
    idle_tasks = []
    try:
        runqueue_addrs = percpu.get_cpu_var("runqueues")
        for addr in runqueue_addrs:
            rq = readSU("struct rq", addr)
            idle_tasks.append(rq.idle)
    except Exception as e:
        print(f"[ERROR] Failed to retrieve idle tasks: {e}")
    return idle_tasks

def _read_thread_group(leader, seen, maxel=200000, debug=False):
    """
    Return all tasks in the thread_group of a leader.
    Uses seen-set to prevent duplicate or circular walks.
    """
    group = []
    try:
        threads = readSUListFromHead(
            Addr(leader.thread_group),
            "thread_group",
            "struct task_struct",
            maxel=maxel # raise guard but still bounded
        )
        for t in threads:
            if t is None:
                continue
            addr = Addr(t)
            if addr in seen:
                continue
            group.append(t)
    except Exception as e:
        if debug:
            print(f"[WARN] Cannot read thread group of PID {getattr(leader, 'pid', -1)}: {e}")
    return group

def walk_task_list(filter_code=None, only_active=False, debug=False, collect_bt=False, depth=5):
    results = defaultdict(list)
    bt_counter = Counter()
    seen = set()

    try:
        init_task = readSymbol("init_task")
    except Exception as e:
        print(f"[ERROR] Cannot read init_task: {e}")
        return results, bt_counter

    # Respect a higher limit via global or CLI (set in main via global var)
    global LIST_MAXEL
    try:
        leaders = readSUListFromHead(
            Addr(init_task.tasks),
            "tasks",
            "struct task_struct",
            maxel=LIST_MAXEL
        )
    except Exception as e:
        print(f"[ERROR] Error reading task list: {e}")
        return results, bt_counter

    def _record_task(task):
        addr = Addr(task)
        if addr in seen:
            return
        seen.add(addr)

        try:
            pid = task.pid
            comm = str(task.comm)
            state_val = get_state(task)
            state_name = get_state_name(state_val)
            ppid = task.real_parent.pid if task.real_parent else 0
            on_cpu = int(getattr(task, 'on_cpu', 0))
            cpu = get_cpu(task)
            ps_code = get_ps_code(task,debug)
            sched_class = get_sched_class(task)
            prio = task.prio
            static_prio = task.static_prio
        except Exception as e:
            if debug:
                print(f"[WARN] Error reading task at {addr:x}: {e}")
            return

        if filter_code and ps_code != filter_code:
            return
        if only_active and (ps_code != "RU" or on_cpu != 1):
            return

        if debug:
            print(f"[DEBUG] PID={pid} COMM={comm} ST=0x{state_val:x} PS={ps_code} CPU={cpu} "
                  f"ON_CPU={on_cpu} SCHED={sched_class} PRIO={prio} ADDR={addr:x}")

        results[state_name].append({
            "pid": pid,
            "ppid": ppid,
            "comm": comm,
            "state_val": state_val,
            "on_cpu": on_cpu,
            "cpu": cpu,
            "ps": ps_code,
            "sched": sched_class,
            "prio": prio,
            "static_prio": static_prio,
            "addr": f"{addr:x}"
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

    # Walk all leaders and their thread groups
    for leader in leaders:
        _record_task(leader)  # always include the leader
        for task in _read_thread_group(leader, seen, maxel=LIST_MAXEL, debug=debug):
            _record_task(task)

    # Ensure idle tasks are considered (some builds hide them from the lists)
    for task in get_idle_tasks():
        _record_task(task)

    return results, bt_counter

def _default_sort_key(task):
    # Sort RU tasks first, then on_cpu desc, then CPU, then PID
    ps_rank = {"RU": 0, "IN": 1, "UN": 2, "WA": 3, "ST": 4, "TR": 5, "ID": 6, "PA": 7, "DE": 8, "ZO": 9, "NE": 10}
    return (
        ps_rank.get(task.get("ps"), 99),
        -int(task.get("on_cpu", 0)),
        int(task.get("cpu", -1)),
        int(task.get("pid", 0)),
    )

SORT_KEYS = {
    "pid":   lambda t: (int(t.get("pid", 0)),),
    "ppid":  lambda t: (int(t.get("ppid", 0)), int(t.get("pid", 0))),
    "st":    lambda t: (t.get("ps", ""), int(t.get("pid", 0))),
    "cpu":   lambda t: (int(t.get("cpu", -1)), int(t.get("pid", 0))),
    "task":  lambda t: (t.get("addr", ""),),
    "on_cpu":lambda t: (-int(t.get("on_cpu", 0)), int(t.get("pid", 0))),
    "sched": lambda t: (t.get("sched", ""), int(t.get("pid", 0))),
    "prio":  lambda t: (int(t.get("prio", 0)), int(t.get("pid", 0))),
    "comm":  lambda t: (t.get("comm", ""), int(t.get("pid", 0))),
    "default": _default_sort_key,
}

def main():
    parser = argparse.ArgumentParser(description="Crash/epython task list analyzer")
    parser.add_argument("--state", help="Filter tasks by state code (e.g., RU, IN, UN)")
    parser.add_argument("--active", action="store_true", help="Only show active RU tasks (on_cpu==1)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug output")
    parser.add_argument("--bt", action="store_true", help="Collect and group backtraces")
    parser.add_argument("--depth", type=int, default=5, help="Depth of backtrace tail to group on")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument(
        "--sort",
        choices=list(SORT_KEYS.keys()),
        default="default",
        help="Sort order for text output (columns: pid, ppid, st, cpu, task, on_cpu, sched, prio, comm, default)",
    )
    parser.add_argument(
        "--maxel",
        type=int,
        default=200000,
        help="Safety bound when reading kernel lists (default: 200000)",
    )

    args = parser.parse_args()

    # Initialize kernel/RHEL detection first
    get_rhel_version()
    _detect_cpu_members()
    # make list guard configurable
    global LIST_MAXEL
    LIST_MAXEL = max(10000, int(args.maxel))

    print("Collecting task list...")
    results, bt_counter = walk_task_list(
        filter_code=args.state,
        only_active=args.active,
        debug=args.debug,
        collect_bt=args.bt,
        depth=args.depth
    )

    if args.bt:
        print(f"\nBacktrace pattern summary({args.state} tasks):")
        print("==========================")
        # Deterministic order: by count desc, then lexicographically
        for trace, count in sorted(bt_counter.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"{count:<5}  {trace}")
        return
    else:
        # Flatten results then sort deterministically
        all_tasks = []
        for _state, tasks in results.items():
            all_tasks.extend(tasks)

        keyfn = SORT_KEYS.get(args.sort, _default_sort_key)
        all_tasks.sort(key=keyfn)

        use_color = (not args.no_color) and _is_tty()
        print("\n   PID     PPID    ST  CPU        TASK       ON_CPU SCHED PRIO       COMM")
        print("==========================================================================")
        for t in all_tasks:
            prio_colored = color_prio(t['prio'], t['static_prio'], t['sched'], enable=use_color)
            print(f"{t['pid']:>8} {t['ppid']:>8}  {t['ps']:<3} {t['cpu']:>3} {t['addr']:>14} {t['on_cpu']:>6} {t['sched']:>5} {prio_colored}  {t['comm']:<16}")

if __name__ == "__main__":
    main()

