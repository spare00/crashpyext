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

patterns = {
    'active_anon': r'active_anon:(\d+)',
    'inactive_anon': r'inactive_anon:(\d+)',
    'isolated_anon': r'isolated_anon:(\d+)',
    'active_file': r'active_file:(\d+)',
    'inactive_file': r'inactive_file:(\d+)',
    'isolated_file': r'isolated_file:(\d+)',
    'unevictable': r'unevictable:(\d+)',
    'dirty': r'dirty:(\d+)',
    'writeback': r'writeback:(\d+)',
    'slab_reclaimable': r'slab_reclaimable:(\d+)',
    'slab_unreclaimable': r'slab_unreclaimable:(\d+)',
    'mapped': r'mapped:(\d+)',
    'shmem': r'shmem:(\d+)',
    'pagetables': r'pagetables:(\d+)',
    'bounce': r'bounce:(\d+)',
    'free': r'free:(\d+)',
    'free_pcp': r'free_pcp:(\d+)',
    'free_cma': r'free_cma:(\d+)',
    'pagecache': r'(\d+) total pagecache pages',
    'swapcache': r'(\d+) pages in swap cache',
    'reserved': r'(\d+) pages reserved',
    'total_pages_ram': r'(\d+) pages RAM',
    'free_swap': r'Free swap\s*=\s*(\d+)kB',
    'total_swap': r'Total swap\s*=\s*(\d+)kB',
    'hugepages_total': r'hugepages_total=(\d+)',
    'hugepages_free': r'hugepages_free=(\d+)',
    'hugepages_surp': r'hugepages_surp=(\d+)',
    'hugepages_size': r'hugepages_size=(\d+)kB',
}

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

def extract_and_display_meminfo_blocks(log_lines, show_unaccounted=False, show_full=False, unit='MB', verbose=False):
    from collections import OrderedDict

    mem_blocks = []
    current_event = None
    collecting = False
    block = []

    # Collect Mem-Info blocks associated with OOM events
    for line in log_lines:
        if "invoked oom-killer" in line:
            current_event = line.strip()
            collecting = False
        elif "Mem-Info:" in line and current_event:
            collecting = True
            block = [current_event]
        elif collecting:
            if line.strip() == "" or "Unreclaimable slab info:" in line:
                mem_blocks.append((block[0], block[1:]))
                collecting = False
            else:
                block.append(line.strip())

    for timestamp, lines in mem_blocks:
        data = {}
        for field, pat in patterns.items():
            for line in lines:
                # Strip timestamp
                content = line.split("] ", 1)[-1].strip()

                match = re.search(pat, content)
                if not match:
                    continue

                val = int(match.group(1))

                if field in ('free_swap', 'total_swap'):
                    mb_val = val / 1024  # Already in kB
                else:
                    mb_val = val * 4 / 1024  # Convert pages to MB

                if field not in data or mb_val > data[field]:
                    data[field] = mb_val

        # Derived values
        data['swap_used'] = max(0, data.get('total_swap', 0) - data.get('free_swap', 0))
        data['hugepages_used'] = (
            data.get('hugepages_total', 0) - data.get('hugepages_free', 0)
        ) * (data.get('hugepages_size', 0) / 1024 / 1024)

        total = data.get('total_pages_ram', 0)

        base_fields = OrderedDict([
            ('Active Anon', data.get('active_anon', 0)),
            ('Inactive Anon', data.get('inactive_anon', 0)),
            ('Active File', data.get('active_file', 0)),
            ('Inactive File', data.get('inactive_file', 0)),
            ('Slab Reclaimable', data.get('slab_reclaimable', 0)),
            ('Slab Unreclaimable', data.get('slab_unreclaimable', 0)),
            ('Shmem', data.get('shmem', 0)),
            ('Pagetables', data.get('pagetables', 0)),
            ('Free', data.get('free', 0)),
            ('Free Pcp', data.get('free_pcp', 0)),
            ('Pagecache', data.get('pagecache', 0)),
            ('Reserved', data.get('reserved', 0)),
            ('Hugepages Total', data.get('hugepages_total', 0) * data.get('hugepages_size', 0) / 1024 / 1024),
            ('Hugepages Used', data.get('hugepages_used', 0)),
            ('Swap Total', data.get('total_swap', 0)),
            ('Swap Free', data.get('free_swap', 0)),
            ('Swap Used', data.get('swap_used', 0)),
        ])

        extended_fields = OrderedDict([
            ('Isolated Anon', data.get('isolated_anon', 0)),
            ('Isolated File', data.get('isolated_file', 0)),
            ('Unevictable', data.get('unevictable', 0)),
            ('Dirty', data.get('dirty', 0)),
            ('Writeback', data.get('writeback', 0)),
            ('Mapped', data.get('mapped', 0)),
            ('Bounce', data.get('bounce', 0)),
            ('Free CMA', data.get('free_cma', 0)),
            ('Swap cache', data.get('swapcache', 0)),
        ])

        sum_base = sum(base_fields.values())
        sum_extra = sum(extended_fields.values()) if show_unaccounted and show_full else 0
        accounted = sum_base + sum_extra
        unaccounted = total \
            - data.get('active_anon', 0) \
            - data.get('inactive_anon', 0) \
            - data.get('isolated_anon', 0) \
            - data.get('pagecache', 0) \
            - data.get('swapcache', 0) \
            - data.get('slab_reclaimable', 0) \
            - data.get('slab_unreclaimable', 0) \
            - data.get('pagetables', 0) \
            - data.get('free', 0) \
            - data.get('reserved', 0) \
            - data.get('unevictable', 0) \
            - data.get('bounce', 0) \
            - data.get('free_cma', 0) \
            - (data.get('hugepages_total', 0) * data.get('hugepages_size', 0) / 1024 / 1024)

        # Output
        print(f"\nTimestamp: {timestamp}")
        print(f"{'Category':<35}{unit:>8}")
        print("=" * 43)
        for k, v in base_fields.items():
            print(f"{k:<35}{format_value(v, unit):>8.2f}")
        if show_unaccounted and show_full:
            for k, v in extended_fields.items():
                print(f"{k:<35}{format_value(v, unit):>8.2f}")
        if show_unaccounted:
            print("-" * 43)
            print(f"{'Unaccounted Memory':<35}{format_value(unaccounted, unit):>8.2f}")
        print("=" * 43)
        print(f"{'Total Memory':<35}{format_value(total, unit):>8.2f}")

        if show_unaccounted and verbose:
            # For breakdown display
            components = OrderedDict([
                ('Active Anon', data.get('active_anon', 0)),
                ('Inactive Anon', data.get('inactive_anon', 0)),
                ('Isolated Anon', data.get('isolated_anon', 0)),
                ('Pagecache', data.get('pagecache', 0)),
                ('Swapcache', data.get('swapcache', 0)),
                ('Slab Reclaimable', data.get('slab_reclaimable', 0)),
                ('Slab Unreclaimable', data.get('slab_unreclaimable', 0)),
                ('Pagetables', data.get('pagetables', 0)),
                ('Free', data.get('free', 0)),
                ('Reserved', data.get('reserved', 0)),
                ('Unevictable', data.get('unevictable', 0)),
                ('Bounce', data.get('bounce', 0)),
                ('Free CMA', data.get('free_cma', 0)),
                ('Huge Pages', data.get('hugepages_total', 0) * data.get('hugepages_size', 0) / 1024 / 1024),
            ])

            terms_str = " - ".join(f"{format_value(v, unit):.2f}" for v in components.values())
            formula_str = " - ".join(components.keys())
            print(f"\nUnaccounted memory = Total Memory - {formula_str}")
            print(f"{format_value(unaccounted, unit):.2f} = {format_value(total, unit):.2f} - {terms_str}")

def extract_and_display_slab_info(log_lines, unit='MB'):
    current_event = None
    slab_entries = []
    collecting = False

    for line in log_lines:
        content = line.split("] ", 1)[-1].strip()

        if "invoked oom-killer" in content:
            current_event = content
            slab_entries = []
            collecting = False

        elif content.startswith("Unreclaimable slab info:"):
            collecting = True

        elif collecting and content.startswith("Name"):
            continue  # skip header

        elif collecting:
            if content.startswith("[") or content.startswith("Tasks state"):
                collecting = False
                if slab_entries:
                    print(f"\nEvent: {current_event}")
                    print(f"Top Slab Usage (Unreclaimable):")
                    print(f"{f'Used ({unit})':>12}   Name")
                    top_entries = sorted(slab_entries, key=lambda x: x[1], reverse=True)[:10]
                    total = sum(x[1] for x in top_entries)

                    for name, used_mb in top_entries:
                        print(f"{format_value(used_mb, unit):>12.2f}   {name}")

                    print("-" * 34)
                    print(f"{format_value(total, unit):>12.2f}   Total Slab Usage")

                continue

            parts = re.split(r'\s{2,}', content)
            if len(parts) >= 2:
                name = parts[0]
                used_kb = parts[1].strip().replace("KB", "")
                try:
                    used_mb = int(used_kb) / 1024
                    slab_entries.append((name, used_mb))
                except ValueError:
                    continue

def main():
    parser = argparse.ArgumentParser(description="Parse OOM logs from crash log -T")
    parser.add_argument('-p', '--process', action='store_true', help="Show per-process memory usage (optional with -i/-u)")
    parser.add_argument('-s', '--swap', action='store_true', help="Include swap usage")
    parser.add_argument('-d', '--debug', action='store_true', help="Enable debug output")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('-i', '--meminfo', action='store_true', help="Show memory info summary per event")
    parser.add_argument('-u', '--unaccounted', action='store_true', help="Include unaccounted memory")
    parser.add_argument('-f', '--full', action='store_true', help="With -u, include detailed fields")
    parser.add_argument('-l', '--slab', action='store_true', help="Show top unreclaimable slab usage")

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

    show_meminfo = args.meminfo or args.unaccounted or args.full
    show_process = not show_meminfo or args.process

    if show_process:
        oom_events = parse_oom_log(log_lines, debug=args.debug, verbose=args.verbose)
        event_usage = extract_rss_and_swap_usage(
            oom_events,
            include_swap=args.swap,
            debug=args.debug,
            verbose=args.verbose
        )
        display_usage(event_usage, include_swap=args.swap, unit=args.unit)

    if show_meminfo:
        extract_and_display_meminfo_blocks(
            log_lines,
            show_unaccounted=args.unaccounted,
            show_full=args.full,
            unit=args.unit,
            verbose=args.verbose
        )

    # Show slab info only if -i/-u/-f/-p are not set
    if args.slab and not (args.meminfo or args.unaccounted or args.full or args.process):
        extract_and_display_slab_info(log_lines, unit=args.unit)

main()

