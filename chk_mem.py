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

def get_vmalloc_memory_kb(debug=False):
    """
    Parse `kmem -v` output and sum the SIZE column (vmalloc/vmap allocations).
    Returns total in KiB.
    """
    total_kb = 0
    try:
        output = exec_crash_command("kmem -v")
    except Exception as e:
        if debug:
            print(f"[debug] kmem -v failed: {e}")
        return 0

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("VMAP_AREA") or line.startswith("crash>"):
            continue
        parts = line.split()
        if len(parts) < 5:
            if debug:
                print(f"[debug] skipping line: {line}")
            continue
        try:
            size_val = int(parts[-1])  # SIZE column is last
            total_kb += size_val // 1024
        except ValueError:
            if debug:
                print(f"[debug] cannot parse size in line: {line}")
            continue
    return total_kb

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
            for token in parts:
                try:
                    pages = int(token)
                    return pages_to_kb(pages)
                except ValueError:
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
            # Format may be: HSTATE SIZE NODE TOTAL ...
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

def _fs_name_from_vma(vma):
    try:
        f = vma.vm_file
        if not f:
            return None
        dentry = f.f_path.dentry
        if not dentry or not dentry.d_sb or not dentry.d_sb.s_type:
            return None
        name = dentry.d_sb.s_type.name
        return str(name) if name is not None else None
    except Exception:
        return None

def get_process_shmem_kb(task_addr, debug=False):
    try:
        # Normalize to int for readSU
        if isinstance(task_addr, str):
            if task_addr.startswith("0x"):
                task_addr = int(task_addr, 16)
            else:
                task_addr = int("0x" + task_addr, 16)

        if debug:
            print(f"[debug] normalized task_addr -> {hex(task_addr)} ({type(task_addr)})")

        # Call readSU with int directly (no Addr())
        task = readSU("struct task_struct", task_addr)
        mm = task.mm
        if not mm:
            return 0

        total_kb = 0
        vma = mm.mmap
        while vma:
            flags = int(vma.vm_flags)
            if flags & 0x00000008:  # VM_SHARED
                total_kb += (int(vma.vm_end) - int(vma.vm_start)) // 1024
            vma = vma.vm_next
        return total_kb

    except Exception as e:
        if debug:
            print(f"[debug] get_process_shmem_kb failed for {hex(task_addr) if isinstance(task_addr,int) else task_addr}: {e}")
        return 0

def get_top_processes(n=10, debug=False):
    try:
        output = exec_crash_command("ps -G")
    except Exception as e:
        if debug:
            print(f"[debug] Failed to run ps -G: {e}")
        return []

    procs = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("PID"):
            continue

        if line.startswith(">"):
            line = line[1:].strip()

        parts = line.split()
        if len(parts) < 9:
            continue

        try:
            pid    = int(parts[0])
            ppid   = int(parts[1])
            cpu    = int(parts[2])
            task   = parts[3]   # save task_struct address
            state  = parts[4]
            mempct = parts[5]
            vsz    = int(parts[6])
            rss    = int(parts[7])
            comm   = " ".join(parts[8:])

            procs.append({
                "pid": pid, "ppid": ppid, "cpu": cpu,
                "task": task, "state": state,
                "mempct": mempct, "vsz": vsz, "rss": rss,
                "comm": comm
            })
        except Exception as e:
            if debug:
                print(f"[debug] parse error: {e} in line: {line}")
            continue

    # sort by RSS and trim
    procs.sort(key=lambda p: p["rss"], reverse=True)
    top = procs[:n]

    # now compute shm only for top-N
    for p in top:
        p["shm"] = get_process_shmem_kb(p["task"], debug)

    return top

def print_top_processes(n=10, unit="K", debug=False):
    top = get_top_processes(n, debug)
    if not top:
        print("No process data available.")
        return

    def scale(val):
        return scale_value(val, unit)

    unit_label = f"{unit}iB"

    print(f"\nTop processes by RSS (unit: {unit_label}):")
    print(f"{'PID':>8} {'PPID':>8} {'CPU':>4} "
          f"{'RSS':>12} {'VSZ':>12} {'SHM':>12}  COMM")
    print("-" * 80)

    for p in top:
        print(f"{p['pid']:>8} {p['ppid']:>8} {p['cpu']:>4} "
              f"{scale(p['rss']):>12.2f} {scale(p['vsz']):>12.2f} {scale(p.get('shm',0)):>12.2f}  {p['comm']}")

def normalize_stats(stats):

    if "NR_SLAB_RECLAIMABLE_B" not in stats and "NR_SLAB_RECLAIMABLE" in stats:
        stats["NR_SLAB_RECLAIMABLE_B"] = stats["NR_SLAB_RECLAIMABLE"] * PAGE_SIZE

    if "NR_SLAB_UNRECLAIMABLE_B" not in stats and "NR_SLAB_UNRECLAIMABLE" in stats:
        stats["NR_SLAB_UNRECLAIMABLE_B"] = stats["NR_SLAB_UNRECLAIMABLE"] * PAGE_SIZE

    if "NR_KERNEL_STACK_KB" not in stats and "NR_KERNEL_STACK" in stats:
        stats["NR_KERNEL_STACK_KB"] = stats["NR_KERNEL_STACK"] * PAGE_SIZE // 1024

def get_accounted_memory_kb(stats, hugepage_kb, percpu_kb):
    return sum([
        pages_to_kb(stats.get("NR_ACTIVE_ANON", 0)),
        pages_to_kb(stats.get("NR_INACTIVE_ANON", 0)),
        bytes_to_kb(stats.get("NR_SLAB_RECLAIMABLE_B", 0)),
        bytes_to_kb(stats.get("NR_SLAB_UNRECLAIMABLE_B", 0)),
        pages_to_kb(stats.get("NR_FREE_PAGES", 0)),
        pages_to_kb(stats.get("NR_FILE_PAGES", 0)),
        stats.get("NR_KERNEL_STACK_KB", 0),
        pages_to_kb(stats.get("NR_PAGETABLE", 0)),
        pages_to_kb(stats.get("NR_SWAPCACHE", 0)),
        hugepage_kb,
        percpu_kb,
        stats.get("VMALLOC_KB", 0)
    ])

def print_unaccounted_formula(stats, total_kb, hugepage_kb, percpu_kb, unit):
    def p(name): return stats.get(name, 0)
    def kb(pages): return pages_to_kb(pages)
    def b(bytes_val): return bytes_to_kb(bytes_val)
    def scale(val): return scale_value(val, unit)

    fields = [
        ("Active Anon", kb(p("NR_ACTIVE_ANON"))),
        ("Inactive Anon", kb(p("NR_INACTIVE_ANON"))),
        ("Slab Reclaimable", b(p("NR_SLAB_RECLAIMABLE_B"))),
        ("Slab Unreclaimable", b(p("NR_SLAB_UNRECLAIMABLE_B"))),
        ("Free", kb(p("NR_FREE_PAGES"))),
        ("PageCache", kb(p("NR_FILE_PAGES"))),
        ("KernelStack", p("NR_KERNEL_STACK_KB")),
        ("PageTables", kb(p("NR_PAGETABLE"))),
        ("SwapCache", kb(p("NR_SWAPCACHE"))),
        ("HugePages", hugepage_kb),
        ("Percpu", percpu_kb),
        ("Vmalloc/Vmap", stats.get("VMALLOC_KB", 0)),
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
    print("Note: This excludes reserved, memmap, directmap, early bootmem, and other special pools.\n")

def main():
    parser = argparse.ArgumentParser(description="Estimate unaccounted memory from VMcore.")
    parser = argparse.ArgumentParser(description="Estimate unaccounted memory from VMcore.")
    parser.add_argument("-i", "--info", action="store_true",
                        help="Show summarized usage breakdown (default view if no option is given)")
    parser.add_argument("-p", "--processes", action="store_true",
                        help="Show top 10 processes by RSS (like ps | sort -nrk8 | head)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all parsed entries and meminfo-like summary")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-K", action="store_const", dest="unit", const="K", help="Show memory in KiB")
    parser.add_argument("-M", action="store_const", dest="unit", const="M", help="Show memory in MiB")
    parser.add_argument("-G", action="store_const", dest="unit", const="G", help="Show memory in GiB")
    parser.add_argument("--extras", action="store_true", help="Also show raw 'kmem -v' style extras (vmalloc, ioremap, etc.)")
    parser.set_defaults(unit="G")
    args = parser.parse_args()

    # If no primary view option was chosen, default to -i
    if not any([args.info, args.processes, args.extras]):
        args.info = True

    stats = parse_kmem_V(debug=args.debug)
    normalize_stats(stats)
    unit = args.unit

    total_kb = get_total_memory_from_kmem_i()
    hugepage_kb = get_hugepage_memory_kb(debug=args.debug)
    percpu_kb = get_percpu_memory_kb()
    vmalloc_kb = get_vmalloc_memory_kb(debug=args.debug)
    stats["VMALLOC_KB"] = vmalloc_kb

    accounted_kb = get_accounted_memory_kb(stats, hugepage_kb, percpu_kb)
    unaccounted_kb = total_kb - accounted_kb
    scale = lambda val: scale_value(val, unit)
    unit_label = f"{unit}iB"

    if args.info:
        print(f"{'Category':<30}{f'Memory ({unit_label})':>20}")
        print("-" * 50)
        print(f"{'Total Memory':<30}{scale(total_kb):>20.2f}")
        print(f"{'Active Anon':<30}{scale(pages_to_kb(stats.get('NR_ACTIVE_ANON', 0))):>20.2f}")
        print(f"{'Inactive Anon':<30}{scale(pages_to_kb(stats.get('NR_INACTIVE_ANON', 0))):>20.2f}")
        print(f"{'Slab Reclaimable':<30}{scale(bytes_to_kb(stats.get('NR_SLAB_RECLAIMABLE_B', 0))):>20.2f}")
        print(f"{'Slab Unreclaimable':<30}{scale(bytes_to_kb(stats.get('NR_SLAB_UNRECLAIMABLE_B', 0))):>20.2f}")
        print(f"{'Free Pages':<30}{scale(pages_to_kb(stats.get('NR_FREE_PAGES', 0))):>20.2f}")
        print(f"{'Kernel Stacks':<30}{scale(stats.get('NR_KERNEL_STACK_KB', 0)):>20.2f}")
        print(f"{'Page Tables':<30}{scale(pages_to_kb(stats.get('NR_PAGETABLE', 0))):>20.2f}")
        print(f"{'Pagecache':<30}{scale(pages_to_kb(stats.get('NR_FILE_PAGES', 0))):>20.2f}")
        print(f"{'Swap Cache':<30}{scale(pages_to_kb(stats.get('NR_SWAPCACHE', 0))):>20.2f}")
        print(f"{'Hugepages':<30}{scale(hugepage_kb):>20.2f}")
        print(f"{'Per-CPU Allocations':<30}{scale(percpu_kb):>20.2f}")
        print(f"{'Vmalloc/Vmap':<30}{scale(vmalloc_kb):>20.2f}")
        print("-" * 50)
        print(f"{'Accounted Memory':<30}{scale(accounted_kb):>20.2f}")
        unaccounted_pct = (unaccounted_kb / total_kb) * 100 if total_kb else 0
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

    if args.verbose and args.info:
        print_unaccounted_formula(stats, total_kb, hugepage_kb, percpu_kb, unit)

    if args.extras:
        print("\n[extras] kmem -v output (raw pools not in accounted sum):\n")
        print(exec_crash_command("kmem -v"))

    if args.processes:
        print_top_processes(10, unit=args.unit, debug=args.debug)

if __name__ == "__main__":
    main()

