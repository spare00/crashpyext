#!/usr/bin/env python3
# chk_files_foreach.py - analyze open files from "foreach files" in crash(8)
# Modes:
#   (default / -N <num>)      : top-N processes by FD count (COMMAND, PID, #FDs)
#   -g / --group [-N <n>]     : top-N COMMANDs by total FDs, with instance counts
#   -f / --filegroup [-N <n>] : top-N 'TYPE PATH' pairs across all FDs
#   -s / --stat               : show only global files_stat (separate mode)

import argparse
import re
from pykdump import *

HEADER_LINE_RE = re.compile(r'^PID:\s+(\d+).*\bCOMMAND:\s*"([^"]*)"')

def foreach_files_output():
    """Run 'foreach files' once and return its raw text."""
    return exec_crash_command("foreach files")

def parse_per_process_counts(text):
    """Return list of (pid, command, fd_count)."""
    results = []
    pid, cmd, count = None, None, 0

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue

        m = HEADER_LINE_RE.match(line.strip())
        if m:
            # flush previous
            if pid is not None:
                results.append((pid, cmd, count))
            pid = int(m.group(1))
            cmd = m.group(2) if m.group(2) else "?"
            count = 0
            continue

        # FD rows: "  <FD> <FILE> <DENTRY> <INODE> <TYPE> <PATH>"
        # start with a digit
        s = line.lstrip()
        if s and s[0].isdigit():
            count += 1

    if pid is not None:
        results.append((pid, cmd, count))

    return results

def parse_type_path_counts(text):
    """
    Return dict mapping 'TYPE PATH' -> count across all FD lines.
    Matches lines like:
      '  6 ... REG  /var/log/messages'
      '  6 ... DIR  /proc/27393/fd'
      '  6 ... SOCK TCP'
      '  3 ... ANON anon_inode:[eventfd]'
    """
    counts = {}
    # Regex: FD, FILE, DENTRY, INODE, TYPE, (PATH rest)
    fd_re = re.compile(r'^\s*\d+\s+\S+\s+\S+\s+\S+\s+(\S+)\s*(.*)$')
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
    """Show output of crash> files_stat."""
    try:
        out = exec_crash_command("files_stat")
        print("\n=== Global files_stat ===")
        print(out)
    except Exception as e:
        print(f"Failed to get files_stat: {e}")

def show_topn_per_pid(results, topn):
    """Print top-N processes by FD count (COMMAND, PID, #FDs)."""
    results.sort(key=lambda x: x[2], reverse=True)
    top = results[:topn]

    print(f"{'COMMAND':<30} {'PID':<8} {'#FDs':<8}")
    print("=" * 56)
    for pid, cmd, cnt in top:
        print(f"{cmd:<30} {pid:<8} {cnt:<8}")

    total_fds = sum(r[2] for r in results)
    print("=" * 56)
    print(f"Total FDs across all processes: {total_fds}")

def show_group_by_command(results, topn):
    """Aggregate by command: total FDs and instance count."""
    agg = {}  # cmd -> [proc_count, total_fds]
    for pid, cmd, cnt in results:
        if cmd not in agg:
            agg[cmd] = [0, 0]
        agg[cmd][0] += 1
        agg[cmd][1] += cnt

    rows = [(cmd, v[0], v[1]) for cmd, v in agg.items()]
    rows.sort(key=lambda x: x[2], reverse=True)
    top = rows[:topn]

    print(f"{'COMMAND':<40} {'INSTANCES':<10} {'TOTAL_FDs':<10}")
    print("=" * 64)
    for cmd, nproc, total in top:
        print(f"{cmd:<40} {nproc:<10} {total:<10}")

    grand_total = sum(total for _, _, total in rows)
    n_cmds = len(rows)
    print("=" * 64)
    print(f"Commands: {n_cmds}    Total FDs: {grand_total}")

def show_top_type_path(counts, topn):
    """Show top-N TYPE PATH entries across all FDs."""
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
    parser.add_argument("-g", "--group", action="store_true",
                        help="Group by command: show total FDs per command and instance counts (respects -N)")
    parser.add_argument("-f", "--filegroup", action="store_true",
                        help="Group by 'TYPE PATH': show top-N entries across all files")
    args = parser.parse_args()

    if args.stat:
        show_files_stat()
        return

    text = foreach_files_output()

    if args.filegroup:
        counts = parse_type_path_counts(text)
        show_top_type_path(counts, args.N)
        return

    results = parse_per_process_counts(text)

    if args.group:
        show_group_by_command(results, args.N)
        return

    show_topn_per_pid(results, args.N)

if __name__ == "__main__":
    main()

