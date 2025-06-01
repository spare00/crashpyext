import argparse
from collections import defaultdict, Counter
from pykdump.API import *
from LinuxDump import percpu
import re

SCHED_CLASSES = {
    crash.sym2addr("fair_sched_class"): "CFS",
    crash.sym2addr("rt_sched_class"): "RT",
    crash.sym2addr("stop_sched_class"): "STOP",
    crash.sym2addr("idle_sched_class"): "IDLE" if crash.symbol_exists("idle_sched_class") else None,
    crash.sym2addr("dl_sched_class"): "DL" if crash.symbol_exists("dl_sched_class") else None,
}
SCHED_CLASSES = {k: v for k, v in SCHED_CLASSES.items() if k is not None}

def get_sched_class(task):
    try:
        addr = Addr(task.sched_class)
        return SCHED_CLASSES.get(addr, "UNKNOWN")
    except:
        return "UNKNOWN"

def get_state_name(state):
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

def get_ps_code(task):
    try:
        exit_state = task.exit_state
        state = task.__state

        if exit_state & 0x20:
            return "ZO"
        elif exit_state & 0x10:
            return "DE"
        elif state == 0x0000:
            return "RU"
        elif state == 0x0402:
            return "ID"
        elif state & 0x0001:
            return "IN"
        elif state & 0x0002:
            return "UN"
        elif state & 0x0004:
            return "ST"
        elif state & 0x0008:
            return "TR"
        elif state & 0x0200:
            return "WA"
        elif state & 0x0040:
            return "PA"
        elif not task.mm:
            return "ID"
        else:
            return "NE"
    except:
        return "NE"

def parse_bt_output(bt_output, max_depth=5):
    trace = []
    for line in bt_output.strip().splitlines():
        match = re.search(r']\s+([a-zA-Z0-9_\.]+)', line)
        if match:
            trace.append(match.group(1))
    if not trace:
        return None
    trace_tail = trace[:max_depth]
    trace_tail.reverse()
    return ' -> '.join(trace_tail)

def color_prio(prio, static_prio, sched):
    RESET = "\033[0m"
    if sched == "CFS" and static_prio != 120:
        return f"\033[32m{prio:>5}{RESET}"  # Green
    elif sched == "CFS" and prio != static_prio:
        return f"\033[33m{prio:>5}{RESET}"  # Yellow
    else:
        return f"{prio:>5}"

task_list_offset = crash.member_offset("struct task_struct", "tasks")
thread_group_offset = crash.member_offset("struct task_struct", "thread_group")

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

def walk_task_list(filter_code=None, only_active=False, debug=False, collect_bt=False, depth=5):
    results = defaultdict(list)
    bt_counter = Counter()
    seen = set()

    init_task = readSymbol("init_task")

    try:
        leaders = readSUListFromHead(Addr(init_task.tasks), "tasks", "struct task_struct")
    except Exception as e:
        print(f"Error reading task list: {e}")
        return results, bt_counter

    for leader in leaders:
        thread_group = [leader]

        try:
            threads = readSUListFromHead(Addr(leader.thread_group), "thread_group", "struct task_struct")
            thread_group.extend(threads)
        except Exception as e:
            if debug:
                print(f"[WARN] Cannot read thread group of PID {leader.pid}: {e}")
            continue

        for task in thread_group:
            addr = Addr(task)
            if addr in seen:
                continue
            seen.add(addr)

            try:
                pid = task.pid
                comm = str(task.comm)
                state_val = task.__state
                state_name = get_state_name(state_val)
                ppid = task.real_parent.pid if task.real_parent else 0
                on_cpu = getattr(task, 'on_cpu', 0)
                cpu = getattr(task, 'cpu', -1)
                ps_code = get_ps_code(task)
                sched_class = get_sched_class(task)
                prio = task.prio
                static_prio = task.static_prio
            except Exception as e:
                if debug:
                    print(f"[WARN] Error reading task at {addr:x}: {e}")
                continue

            if filter_code and ps_code != filter_code:
                continue
            if only_active and (ps_code != "RU" or on_cpu != 1):
                continue

            if debug:
                print(f"[DEBUG] PID={pid} COMM={comm} ST=0x{state_val:x} PS={ps_code} CPU={cpu} ON_CPU={on_cpu} SCHED={sched_class} PRIO={prio} ADDR={addr:x}")

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
                    continue

    for task in get_idle_tasks():
        addr = Addr(task)
        if addr in seen:
            continue
        seen.add(addr)

        try:
            pid = task.pid
            comm = str(task.comm)
            state_val = task.__state
            state_name = get_state_name(state_val)
            ppid = task.real_parent.pid if task.real_parent else 0
            on_cpu = getattr(task, 'on_cpu', 0)
            cpu = getattr(task, 'cpu', -1)
            ps_code = get_ps_code(task)
            sched_class = get_sched_class(task)
            prio = task.prio
            static_prio = task.static_prio
        except Exception as e:
            if debug:
                print(f"[WARN] Error reading idle task at {addr:x}: {e}")
            continue

        if filter_code and ps_code != filter_code:
            continue
        if only_active and (ps_code != "RU" or on_cpu != 1):
            continue

        if debug:
            print(f"[DEBUG] PID={pid} COMM={comm} ST=0x{state_val:x} PS={ps_code} CPU={cpu} ON_CPU={on_cpu} SCHED={sched_class} PRIO={prio} ADDR={addr:x}")

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
                continue

    return results, bt_counter

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", help="Filter tasks by state code (e.g., RU, IN, UN)")
    parser.add_argument("--active", action="store_true", help="Only show active RU tasks")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug output")
    parser.add_argument("--bt", action="store_true", help="Collect and group backtraces")
    parser.add_argument("--depth", type=int, default=5, help="Depth of backtrace tail to group on")
    args = parser.parse_args()

    print("Collecting task list...")
    results, bt_counter = walk_task_list(
        filter_code=args.state,
        only_active=args.active,
        debug=args.debug,
        collect_bt=args.bt,
        depth=args.depth
    )

    if args.bt:
        print("\nBacktrace pattern summary:")
        print("==========================")
        for trace, count in bt_counter.most_common():
            print(f"{count:<5}  {trace}")
    else:
        print("\n   PID     PPID    ST  CPU        TASK       ON_CPU SCHED PRIO       COMM")
        print("==========================================================================")
        for state, tasks in results.items():
            for t in tasks:
                prio_colored = color_prio(t['prio'], t['static_prio'], t['sched'])
                print(f"{t['pid']:>8} {t['ppid']:>8}  {t['ps']:<3} {t['cpu']:>3} {t['addr']:>14} {t['on_cpu']:>6} {t['sched']:>5} {prio_colored}  {t['comm']:<16}")

if __name__ == "__main__":
    main()

