#!/usr/bin/env epython

"""
Parse OOM logs from 'log -T' inside crash tool, extract memory usage of
processes listed during each OOM event, and show top RSS/swap consumers.

Supports -s (include swap), -d (debug), -v (verbose).
"""

import re
import argparse
from collections import defaultdict
from crash import exec_crash_command

def format_value(kb, unit):
    if unit == 'KB':
        return kb
    elif unit == 'MB':
        return kb / 1024
    elif unit == 'GB':
        return kb / 1024 / 1024

def parse_oom_log(log_lines, debug=False, verbose=False):
    """
    Scans the log for OOM events and collects relevant lines per event.
    """
    oom_events = defaultdict(list)
    current_event = None
    collecting = False

    for line in log_lines:
        line = line.strip()

        if "invoked oom-killer" in line:
            current_event = line
            collecting = True
            if debug:
                print(f"[DEBUG] OOM event started: {line}")
            continue

        if collecting and current_event:
            oom_events[current_event].append(line)
            if "Out of memory: Killed process" in line or "Out of memory: Kill process" in line:
                if debug:
                    print(f"[DEBUG] OOM event ended: {line}")
                collecting = False

    if verbose:
        print(f"[INFO] Detected {len(oom_events)} OOM event(s).")

    return oom_events

def extract_rss_and_swap_usage(oom_events, include_swap, debug=False, verbose=False):
    """
    Parses each OOM event's lines and extracts process memory usage.
    """
    event_usage = defaultdict(lambda: defaultdict(lambda: {'rss_kb': 0, 'swap_kb': 0, 'count': 0}))
    usage_pattern = re.compile(
        r'\[\s*(\d+)]\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(-?\d+)\s+(.+)$'
    )

    for event, lines in oom_events.items():
        for line in lines:
            # Extract only the part after the second ']'
            # Example line:
            # [Mon Apr 28 01:11:17 UTC 2025] [1602653]     0   1602653  ...
            # Goal: Extract everything from the second '[' onward
            first = line.find('] ')
            second = line.find('[', first)
            if second == -1:
                continue
            process_line = line[second:]
            match = usage_pattern.match(process_line)
            if match:
                rss_pages = int(match.group(5))
                swapents = int(match.group(7))
                name = match.group(9).strip()
                rss_kb = rss_pages * 4
                swap_kb = swapents * 4
                event_usage[event][name]['rss_kb'] += rss_kb
                event_usage[event][name]['swap_kb'] += swap_kb
                event_usage[event][name]['count'] += 1
                if debug:
                    print(f"[DEBUG] Parsed: name={name}, rss_kb={rss_kb}, swap_kb={swap_kb}")
        if verbose:
            print(f"[INFO] Parsed {len(lines)} lines from event: {event[:80]}...")

    if not event_usage:
        print("No process memory usage matched any OOM events.")

    return event_usage

def display_usage(event_usage, include_swap, unit='GB'):
    """
    Displays top memory consumers per OOM event with formatting.
    """
    for event, usage in event_usage.items():
        print(f"\nEvent: {event}")
        if not usage:
            print("  No memory usage data found.")
            continue

        sorted_usage = sorted(usage.items(), key=lambda x: x[1]['rss_kb'], reverse=True)

        if include_swap:
            print(f"{f'RSS ({unit})':>10} {f'Swap ({unit})':>12} {'Count':>10} {'Name':<20}")
        else:
            print(f"{f'RSS ({unit})':>10} {'Count':>10} {'Name':<20}")

        total_rss_kb = total_swap_kb = 0

        for name, data in sorted_usage[:10]:
            rss = format_value(data['rss_kb'], unit)
            swap = format_value(data['swap_kb'], unit) if include_swap else 0
            count = data['count']
            if include_swap:
                print(f"{rss:>10.2f} {swap:>12.2f} {count:>10} {name:<20}")
            else:
                print(f"{rss:>10.2f} {count:>10} {name:<20}")

            total_rss_kb += data['rss_kb']
            total_swap_kb += data['swap_kb']

        print("-" * 50)
        total_rss = format_value(total_rss_kb, unit)
        if include_swap:
            total_swap = format_value(total_swap_kb, unit)
            print(f"{total_rss:>10.2f} {total_swap:>12.2f} {'RSS Total':>15}")
        else:
            print(f"{total_rss:>10.2f} {'RSS Total':>15}")

def main():
    parser = argparse.ArgumentParser(description="Parse OOM logs from crash log -T")
    parser.add_argument('-s', '--swap', action='store_true', help="Include swap usage")
    parser.add_argument('-d', '--debug', action='store_true', help="Enable debug output")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")

    unit_group = parser.add_mutually_exclusive_group()
    unit_group.add_argument('-K', '--kilobytes', action='store_const', const='KB', dest='unit', help="Display values in kilobytes")
    unit_group.add_argument('-M', '--megabytes', action='store_const', const='MB', dest='unit', help="Display values in megabytes")
    unit_group.add_argument('-G', '--gigabytes', action='store_const', const='GB', dest='unit', help="Display values in gigabytes")
    parser.set_defaults(unit='GB')  # Default to GB to match current behavior

    args = parser.parse_args()

    raw_log = exec_crash_command('log -T')
    log_lines = raw_log.splitlines()
    oom_events = parse_oom_log(log_lines, debug=args.debug, verbose=args.verbose)
    event_usage = extract_rss_and_swap_usage(oom_events, include_swap=args.swap, debug=args.debug, verbose=args.verbose)
    display_usage(event_usage, include_swap=args.swap, unit=args.unit)

main()

