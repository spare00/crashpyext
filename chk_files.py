#!/usr/bin/env python3
# chk_files.py - analyze open files from "foreach files" in crash(8)
#
# Modes:
#   -p / --perpid [-N <n>]   : top-N processes by FD count (default 10)
#   -c / --percmd [-N <n>]   : top-N commands by FD usage (aggregate)
#   -f / --filegroup [-N <n>]: top-N TYPE+PATH entries across all FDs
#   -s / --stat              : show only global files_stat (separate mode)
#
# Default mode (if no -p/-c/-f/-s given) is per-process (-p).

import argparse
import re
from pykdump import *

HEADER_LINE_RE = re.compile(r'^PID:\s+(\d+).*\bCOMMAND:\s*"([^"]*)"')

def foreach_files_output():
    return exec_crash_command("foreach files")

def parse_per_process_counts(text):
    """Return list of (pid, cmd, fd_slots)."""
    results = []
    pid, cmd, count = None, None, 0

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue

        m = HEADER_LINE_RE.match(line.strip())
        if m:
            if pid is not None:
                results.append((pid, cmd, count))
            pid = int(m.group(1))
            cmd = m.group(2) if m.group(2) else "?"
            count = 0
            continue

        s = line.lstrip()
        if s and s[0].isdigit():
            count += 1

    if pid is not None:
        results.append((pid, cmd, count))

    return results

def parse_unique_files_per_process(text):
    """Return dict {pid: set_of_file_ptrs} from foreach files output."""
    pid_to_files = {}
    current_pid = None

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue

        m = HEADER_LINE_RE.match(line.strip())
        if m:
            current_pid = int(m.group(1))
            if current_pid not in pid_to_files:
                pid_to_files[current_pid] = set()
            continue

        if current_pid is None:
            continue

        s = line.lstrip()
        if not s or not s[0].isdigit():
            continue

        cols = s.split()
        if len(cols) < 2:
            continue

        file_ptr = cols[1]
        pid_to_files[current_pid].add(file_ptr)

    return pid_to_files

def parse_type_path_counts(text):
    """For -f mode: group by TYPE+PATH."""
    fd_re = re.compile(r'^\s*\d+\s+\S+\s+\S+\s+\S+\s+(\S+)\s*(.*)$')
    counts = {}
    for raw in text.splitlines():
        s = raw.rstrip()
        if not s:
            continue
        m = fd_re.match(s)
        if not m:
            continue
        ftype = m.group(1)
        path = m.group(2).strip() if m.group(2) else ""
        key = f"{ftype} {path}".strip()
        counts[key] = counts.get(key, 0) + 1
    return counts

def show_files_stat():
    try:
        out = exec_crash_command("files_stat")
        print("\n=== Global files_stat ===")
        print(out)
    except Exception as e:
        print(f"Failed to get files_stat: {e}")

def show_topn_per_pid(results, topn, text):
    pid_to_files = parse_unique_files_per_process(text)

    enriched = []
    for pid, cmd, fdslots in results:
        uniq = len(pid_to_files.get(pid, set()))
        enriched.append((pid, cmd, fdslots, uniq))

    enriched.sort(key=lambda x: x[2], reverse=True)
    top_rows = enriched[:topn]

    # ---- Table ----
    print(f"{'COMMAND':<30} {'PID':<8} {'FD_SLOTS':<10} {'UNIQUE_FILE_OBJS':<16}")
    print("=" * 70)
    for pid, cmd, fdslots, uniq in top_rows:
        print(f"{cmd:<30} {pid:<8} {fdslots:<10} {uniq:<16}")

    # ---- Footer ----
    all_procs       = len(enriched)
    global_fdslots  = sum(fdslots for _, _, fdslots, _ in enriched)
    global_uniqs    = len(set().union(*(pid_to_files[pid] for pid in pid_to_files))) if pid_to_files else 0

    print("=" * 70)
    print(f"Processes: {all_procs:<6}")
    print(f"Global FD slots: {global_fdslots}")
    print(f"Global unique file objects: {global_uniqs}")

def show_group_by_command(results, topn, text):
    pid_to_files = parse_unique_files_per_process(text)

    # Aggregate per-command
    agg = {}
    for pid, cmd, fdslots in results:
        file_set = pid_to_files.get(pid, set())
        if cmd not in agg:
            agg[cmd] = [0, 0, set()]
        agg[cmd][0] += 1             # instances
        agg[cmd][1] += fdslots       # total fd slots
        agg[cmd][2].update(file_set) # union of FILE pointers

    rows_all = [(cmd, v[0], v[1], len(v[2])) for cmd, v in agg.items()]
    rows_all.sort(key=lambda x: x[2], reverse=True)
    rows_shown = rows_all[:topn]

    # ---- Table ----
    print(f"{'COMMAND':<40} {'INSTANCES':<10} {'TOTAL_FDs':<10} {'UNIQUE_FILE_OBJS':<16}")
    print("=" * 90)
    for cmd, nproc, total, uniq in rows_shown:
        print(f"{cmd:<40} {nproc:<10} {total:<10} {uniq:<16}")

    # ---- Footer ----
    all_cmds       = len(rows_all)
    global_fdslots = sum(total for _, _, total, _ in rows_all)
    global_uniqs   = len(set().union(*(pid_to_files[pid] for pid in pid_to_files))) if pid_to_files else 0

    print("=" * 90)
    print(f"Commands: {all_cmds:<6}")
    print(f"Global FD slots: {global_fdslots}")
    print(f"Global unique file objects: {global_uniqs}")

def show_top_type_path(counts, topn):
    rows = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:topn]
    print(f"{'TYPE PATH':<80} {'COUNT':<10}")
    print("=" * 92)
    for key, c in rows:
        print(f"{key:<80} {c:<10}")

    total = sum(counts.values())
    print("=" * 92)
    print(f"Unique TYPE PATH: {len(counts)}    Total FDs scanned: {total}")

def main():
    parser = argparse.ArgumentParser(description="Open FD accounting from 'foreach files' in crash")
    parser.add_argument("-N", type=int, default=10,
                        help="Top N entries to display (default 10)")
    parser.add_argument("-s", "--stat", action="store_true",
                        help="Show only global files_stat (separate mode)")
    parser.add_argument("-p", "--perpid", action="store_true",
                        help="Per-process: show top-N processes (default mode)")
    parser.add_argument("-c", "--percmd", action="store_true",
                        help="Per-command: aggregate processes with same COMMAND")
    parser.add_argument("-f", "--filegroup", action="store_true",
                        help="Group by 'TYPE PATH': show top-N entries across all files")
    args = parser.parse_args()

    if args.stat:
        show_files_stat()
        return

    text = foreach_files_output()
    results = parse_per_process_counts(text)

    if args.filegroup:
        counts = parse_type_path_counts(text)
        show_top_type_path(counts, args.N)
        return

    if args.percmd:
        show_group_by_command(results, args.N, text)
        return

    # Default mode is per-PID
    show_topn_per_pid(results, args.N, text)

if __name__ == "__main__":
    main()
