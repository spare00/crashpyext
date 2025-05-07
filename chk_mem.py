#!/usr/bin/env python3
"""
chk_mem.py
Estimate unaccounted memory in a VMcore using crash commands.
Supports -v (verbose), -d (debug), -K/-M/-G for unit scaling.
Includes hugepages, percpu memory, and meminfo-style output.
"""

import argparse
from pykdump.API import *

# ANSI color codes
RED     = '\033[91m'
RESET   = '\033[0m'

PAGE_SIZE = 4096  # 4 KiB

def scale_value(kb, unit):
    if unit == "K": return kb
    if unit == "M": return kb / 1024
    if unit == "G": return kb / (1024 * 1024)

def pages_to_kb(pages): return pages * PAGE_SIZE // 1024

def bytes_to_kb(bytes_val): return bytes_val // 1024

def parse_kmem_V(debug=False):
    output = exec_crash_command("kmem -V")
    stats = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or ':' not in line:
            if debug:
                print(f"[debug] Skipping malformed/empty line: '{line}'")
            continue
        parts = line.split(':', 1)
        if len(parts) != 2:
            if debug:
                print(f"[debug] Skipping invalid split: '{line}'")
            continue
        key, val_part = parts[0].strip(), parts[1].strip()
        if not val_part:
            if debug:
                print(f"[debug] No value found for key '{key}'")
            continue
        val_str = val_part.split()[0]
        try:
            stats[key] = int(val_str)
        except ValueError:
            if debug:
                print(f"[debug] Value conversion failed for '{key}': '{val_str}'")
    return stats

def get_total_memory_from_kmem_i():
    output = exec_crash_command("kmem -i")
    for line in output.splitlines():
        if "TOTAL MEM" in line:
            parts = line.split()
            try:
                pages = int(parts[2])
                return pages_to_kb(pages)
            except (IndexError, ValueError):
                continue
    return 0

def get_hugepage_memory_kb(debug=False):
    output = exec_crash_command("kmem -h")
    total_kb = 0
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("HSTATE"):
            continue
        parts = line.split()
        try:
            size_str = parts[1]
            total_pages = int(parts[3])
            if size_str.lower().endswith("kb"):
                size_kb = int(size_str[:-2])
            elif size_str.lower().endswith("mb"):
                size_kb = int(size_str[:-2]) * 1024
            elif size_str.lower().endswith("gb"):
                size_kb = int(size_str[:-2]) * 1024 * 1024
            else:
                if debug:
                    print(f"[debug] Unknown hugepage size unit: {size_str}")
                continue
            total_kb += size_kb * total_pages
        except (IndexError, ValueError):
            if debug:
                print(f"[debug] Failed to parse hugepage line: {line}")
    return total_kb

def get_percpu_memory_kb():
    try:
        populated = readSymbol("pcpu_nr_populated")
        units = readSymbol("pcpu_nr_units")
        return pages_to_kb(populated * units)
    except Exception:
        return 0

def get_accounted_memory_kb(stats, hugepage_kb, percpu_kb):
    return sum([
        pages_to_kb(stats.get("NR_FREE_PAGES", 0)),
        bytes_to_kb(stats.get("NR_SLAB_RECLAIMABLE_B", 0) + stats.get("NR_SLAB_UNRECLAIMABLE_B", 0)),
        stats.get("NR_KERNEL_STACK_KB", 0),
        pages_to_kb(stats.get("NR_PAGETABLE", 0)),
        pages_to_kb(stats.get("NR_ANON_MAPPED", 0) + stats.get("NR_FILE_MAPPED", 0)),
        pages_to_kb(stats.get("NR_FILE_PAGES", 0)),
        pages_to_kb(stats.get("NR_SWAPCACHE", 0)),
        hugepage_kb,
        percpu_kb
    ])

def print_unaccounted_formula(stats, total_kb, hugepage_kb, percpu_kb, unit):
    def p(name): return stats.get(name, 0)
    def kb(pages): return pages_to_kb(pages)
    def b(bytes_val): return bytes_to_kb(bytes_val)
    def scale(val): return scale_value(val, unit)

    fields = [
        ("Free", kb(p("NR_FREE_PAGES"))),
        ("Slab Reclaimable", b(p("NR_SLAB_RECLAIMABLE_B"))),
        ("Slab Unreclaimable", b(p("NR_SLAB_UNRECLAIMABLE_B"))),
        ("KernelStack", p("NR_KERNEL_STACK_KB")),
        ("PageTables", kb(p("NR_PAGETABLE"))),
        ("Mapped", kb(p("NR_ANON_MAPPED") + p("NR_FILE_MAPPED"))),
        ("FilePages", kb(p("NR_FILE_PAGES"))),
        ("SwapCache", kb(p("NR_SWAPCACHE"))),
        ("HugePages", hugepage_kb),
        ("Percpu", percpu_kb),
    ]

    accounted = sum(val for _, val in fields)
    unaccounted = total_kb - accounted

    if percpu_kb > 0:
        try:
            populated = readSymbol("pcpu_nr_populated")
            units = readSymbol("pcpu_nr_units")
            print(f"\n[verbose] Percpu memory = pcpu_nr_populated({populated}) * pcpu_nr_units({units}) * PAGE_SIZE({PAGE_SIZE}) / 1024")
            print(f"[verbose] Percpu memory = {populated * units * PAGE_SIZE // 1024} KiB\n")
        except Exception:
            print("[verbose] Percpu memory: symbol not available or failed to read.\n")

    print("Unaccounted memory formula (approx):")
    print(f"{'Unaccounted':<15}= {'Total Memory':<15}- " + " - ".join(name for name, _ in fields))
    print(f"{scale(unaccounted):<15.2f}= {scale(total_kb):<15.2f}- " + " - ".join(f"{scale(val):.2f}" for _, val in fields))
    print("Note: This excludes reserved, vmalloc, directmap, early bootmem, and other special pools.\n")

def main():
    parser = argparse.ArgumentParser(description="Estimate unaccounted memory from VMcore.")
    parser.add_argument("-u", "--unaccounted", action="store_true", help="Show summarized usage breakdown include unaccounted memory(default view)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all parsed entries and meminfo-like summary")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-K", action="store_const", dest="unit", const="K", help="Show memory in KiB")
    parser.add_argument("-M", action="store_const", dest="unit", const="M", help="Show memory in MiB")
    parser.add_argument("-G", action="store_const", dest="unit", const="G", help="Show memory in GiB")
    parser.set_defaults(unit="K")
    args = parser.parse_args()

    if not any([args.unaccounted]):
        args.unaccounted = True

    stats = parse_kmem_V(debug=args.debug)
    unit = args.unit

    total_kb = get_total_memory_from_kmem_i()
    hugepage_kb = get_hugepage_memory_kb(debug=args.debug)
    percpu_kb = get_percpu_memory_kb()
    accounted_kb = get_accounted_memory_kb(stats, hugepage_kb, percpu_kb)
    unaccounted_kb = total_kb - accounted_kb
    scale = lambda val: scale_value(val, unit)
    unit_label = f"{unit}iB"

    print(f"{'Category':<30}{f'Memory ({unit_label})':>20}")
    print("-" * 50)
    print(f"{'Total Estimated Memory':<30}{scale(total_kb):>20.2f}")
    print(f"{'Free Pages':<30}{scale(pages_to_kb(stats.get('NR_FREE_PAGES', 0))):>20.2f}")
    print(f"{'Slab':<30}{scale(bytes_to_kb(stats.get('NR_SLAB_RECLAIMABLE_B', 0) + stats.get('NR_SLAB_UNRECLAIMABLE_B', 0))):>20.2f}")
    print(f"{'Kernel Stacks':<30}{scale(stats.get('NR_KERNEL_STACK_KB', 0)):>20.2f}")
    print(f"{'Page Tables':<30}{scale(pages_to_kb(stats.get('NR_PAGETABLE', 0))):>20.2f}")
    print(f"{'Anon + File Mapped':<30}{scale(pages_to_kb(stats.get('NR_ANON_MAPPED', 0) + stats.get('NR_FILE_MAPPED', 0))):>20.2f}")
    print(f"{'File Cache':<30}{scale(pages_to_kb(stats.get('NR_FILE_PAGES', 0))):>20.2f}")
    print(f"{'Swap Cache':<30}{scale(pages_to_kb(stats.get('NR_SWAPCACHE', 0))):>20.2f}")
    print(f"{'Hugepages':<30}{scale(hugepage_kb):>20.2f}")
    print(f"{'Per-CPU Allocations':<30}{scale(percpu_kb):>20.2f}")
    print("-" * 50)
    print(f"{'Accounted Memory':<30}{scale(accounted_kb):>20.2f}")
    unaccounted_pct = (unaccounted_kb / total_kb) * 100
    if unaccounted_pct > 10:
        color_start = RED  # red
        color_end = RESET
    else:
        color_start = color_end = ''
    print(f"{'Unaccounted Memory':<30}{scale(unaccounted_kb):>20.2f} {color_start}(%{unaccounted_pct:.2f}){color_end}")


    if args.debug:
        print("\n[debug] Parsed stats from 'kmem -V':")
        for k in sorted(stats):
            print(f"{k:<35}{stats[k]}")

    if args.verbose:
        print_unaccounted_formula(stats, total_kb, hugepage_kb, percpu_kb, unit)

if __name__ == "__main__":
    main()

