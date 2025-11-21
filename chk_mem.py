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

def get_tmpfs_superblocks(debug=False):
    all_tmpfs_sbs = set()
    visible_tmpfs_sbs = set()

    # First collect all visible tmpfs from `mount`
    try:
        output = exec_crash_command("mount")
        for line in output.splitlines():
            if "tmpfs" not in line or line.startswith("MOUNT"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            sb_addr = parts[1]
            if sb_addr.startswith("0x"):
                sb = int(sb_addr, 16)
            else:
                sb = int("0x" + sb_addr, 16)
            visible_tmpfs_sbs.add(sb)
    except Exception as e:
        if debug:
            print(f"[debug] Failed to parse mount output: {e}")

    # Now walk super_blocks to find all tmpfs
    try:
        head = readSymbol("super_blocks")
        offset = crash.member_offset("struct super_block", "s_list")
        node = readSU("struct list_head", head)
        ptr = node.next

        while ptr and int(ptr) != int(head):
            try:
                sb_addr = int(ptr) - offset
                sb = readSU("struct super_block", sb_addr)
                sid = str(sb.s_id).strip('"')
                if sid == "tmpfs":
                    all_tmpfs_sbs.add(sb_addr)
                    if debug and sb_addr not in visible_tmpfs_sbs:
                        print(f"[debug] Internal tmpfs superblock at {hex(sb_addr)}")
            except Exception as e:
                if debug:
                    print(f"[debug] Failed to parse super_block at {hex(int(ptr))}: {e}")
            ptr = ptr.next
    except Exception as e:
        if debug:
            print(f"[debug] Failed to iterate super_blocks list: {e}")

    return list(all_tmpfs_sbs), list(visible_tmpfs_sbs)

def get_tmpfs_memory_from_superblocks(debug=False):
    total_pages = 0
    visible_pages = 0

    all_sbs, visible_sbs = get_tmpfs_superblocks(debug)

    inode_offset = crash.member_offset("struct inode", "i_sb_list")
    nrpages_offset = crash.member_offset("struct address_space", "nrpages")
    i_data_offset = crash.member_offset("struct inode", "i_data")

    for sb_addr in all_sbs:
        try:
            sb = readSU("struct super_block", sb_addr)
            head = sb.s_inodes
            inode = head.next

            max_inodes = 100000
            count = 0
            sb_pages = 0

            while inode and int(inode) != int(head) and count < max_inodes:
                try:
                    inode_addr = int(inode) - inode_offset
                    i_data_addr = inode_addr + i_data_offset
                    nrpages_addr = i_data_addr + nrpages_offset

                    nrpages = readU64(nrpages_addr)
                    sb_pages += nrpages
                    count += 1
                except Exception as e:
                    if debug:
                        print(f"[debug] Failed inode @ {hex(int(inode))}: {e}")
                inode = inode.next

            total_pages += sb_pages
            if sb_addr in visible_sbs:
                visible_pages += sb_pages

            if count == max_inodes and debug:
                print(f"[debug] inode loop exceeded max_inodes for sb {hex(sb_addr)}")

        except Exception as e:
            if debug:
                print(f"[debug] Failed to process sb {hex(sb_addr)}: {e}")

    return (
        pages_to_kb(total_pages),
        pages_to_kb(visible_pages),
        pages_to_kb(total_pages - visible_pages)  # internal
    )

def get_sysv_shm_kb(debug=False):
    try:
        output = exec_crash_command("ipcs -M")
    except Exception as e:
        if debug:
            print(f"[debug] ipcs -M failed: {e}")
        return 0

    total_pages = 0
    for line in output.splitlines():
        if "PAGES ALLOCATED" in line:
            try:
                part = line.split(":")[1]
                allocated = int(part.strip().split("/")[0])
                total_pages += allocated
            except Exception as e:
                if debug:
                    print(f"[debug] Failed to parse ipc line: {line} ({e})")
                continue

    sysv_kb = pages_to_kb(total_pages)

    # Subtract HugePages_Used if it appears to overlap
    try:
        _, huge_used_kb = get_hugepage_info(debug)
        if huge_used_kb > 0:
            sysv_kb = max(sysv_kb - huge_used_kb, 0)
            if debug:
                print(f"[debug] Adjusted sysv_kb by subtracting HugePages_Used: -{huge_used_kb} KiB")
    except Exception as e:
        if debug:
            print(f"[debug] Failed to get hugepage info for SysV adjustment: {e}")

    return sysv_kb

def estimate_unique_shmem_kb(debug=False):
    tmpfs_total_kb, _, _ = get_tmpfs_memory_from_superblocks(debug)  # use only total for shared total
    sysv_kb = get_sysv_shm_kb(debug)
    total_shared_kb = tmpfs_total_kb + sysv_kb
    return total_shared_kb, tmpfs_total_kb, sysv_kb

def get_buffers_kb_from_blockdev(debug=False):
    total_pages = 0
    try:
        sb = readSymbol("blockdev_superblock")
        sb = readSU("struct super_block", int(sb))
        head = sb.s_inodes
        inode = head.next
        while inode and int(inode) != int(head):
            try:
                container_addr = int(inode) - crash.member_offset("struct inode", "i_sb_list")
                container = readSU("struct inode", container_addr)
                nrpages = int(container.i_data.nrpages)
                total_pages += nrpages
            except Exception as e:
                if debug:
                    print(f"[debug] Failed to read inode from {hex(int(inode))}: {e}")
            inode = inode.next
    except Exception as e:
        if debug:
            print(f"[debug] Failed to read blockdev_superblock: {e}")
    return pages_to_kb(total_pages)

def get_hugepage_info(debug=False):
    output = exec_crash_command("kmem -h")
    total_kb = 0
    used_kb = 0
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("HSTATE"):
            continue
        parts = line.split()
        try:
            size_str = parts[1]      # e.g., 2MB, 1GB
            free_pages = int(parts[2])
            total_pages = int(parts[3])
            used_pages = total_pages - free_pages

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
            used_kb  += size_kb * used_pages
        except Exception as e:
            if debug:
                print(f"[debug] Failed to parse line: {line} ({e})")
    return total_kb, used_kb

def get_swap_info(debug=False):
    try:
        total_addr = readSymbol("total_swap_pages")
        total_pages = int(total_addr)
        nr_swap = readSU("atomic_long_t", readSymbol("nr_swap_pages"))
        free_pages = int(nr_swap.counter)
        used = total_pages - free_pages
        return pages_to_kb(total_pages), pages_to_kb(used)
    except Exception as e:
        if debug:
            print(f"[debug] Failed to read swap info: {e}")
        return 0, 0
    except Exception as e:
        if debug:
            print(f"[debug] Failed to read swap info: {e}")
        return 0, 0

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
    # NR_SLAB_RECLAIMABLE_B implies to contain bytes value but it contains pages in RHEL7+
    # Compare 'NR_SLAB_RECLAIMABLE_B from kmem -V' and 'vm_node_stat[NR_SLAB_RECLAIMABLE_B]'
    if "NR_SLAB_RECLAIMABLE_B" not in stats and "NR_SLAB_RECLAIMABLE" in stats:
        stats["NR_SLAB_RECLAIMABLE_B"] = stats["NR_SLAB_RECLAIMABLE"] # * PAGE_SIZE

    if "NR_SLAB_UNRECLAIMABLE_B" not in stats and "NR_SLAB_UNRECLAIMABLE" in stats:
        stats["NR_SLAB_UNRECLAIMABLE_B"] = stats["NR_SLAB_UNRECLAIMABLE"] # * PAGE_SIZE

    if "NR_KERNEL_STACK_KB" not in stats and "NR_KERNEL_STACK" in stats:
        stats["NR_KERNEL_STACK_KB"] = stats["NR_KERNEL_STACK"] # * PAGE_SIZE // 1024

def get_accounted_memory_kb(stats, hugepage_kb, percpu_kb):
    return sum([
        pages_to_kb(stats.get("NR_ACTIVE_ANON", 0)),
        pages_to_kb(stats.get("NR_INACTIVE_ANON", 0)),
        pages_to_kb(stats.get("NR_SLAB_RECLAIMABLE_B", 0)),
        pages_to_kb(stats.get("NR_SLAB_UNRECLAIMABLE_B", 0)),
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
        ("Slab Reclaimable", kb(p("NR_SLAB_RECLAIMABLE_B"))),
        ("Slab Unreclaimable", kb(p("NR_SLAB_UNRECLAIMABLE_B"))),
        ("Free", kb(p("NR_FREE_PAGES"))),
        ("PageCache", kb(p("NR_FILE_PAGES"))),
        ("KernelStack", kp("NR_KERNEL_STACK_KB")),
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

def print_meminfo_style(stats, total_kb, hugepage_kb, percpu_kb, vmalloc_kb, unit, debug=False):
    unit_label = f"{unit}iB"
    scale = lambda val: scale_value(val, unit)

    memfree = pages_to_kb(stats.get("NR_FREE_PAGES", 0))
    active_anon = pages_to_kb(stats.get("NR_ACTIVE_ANON", 0))
    inactive_anon = pages_to_kb(stats.get("NR_INACTIVE_ANON", 0))
    anon_total = active_anon + inactive_anon
    file_pages = pages_to_kb(stats.get("NR_FILE_PAGES", 0))
    slab = pages_to_kb(stats.get("NR_SLAB_RECLAIMABLE_B", 0) + stats.get("NR_SLAB_UNRECLAIMABLE_B", 0))
    kernel_stack = stats.get("NR_KERNEL_STACK_KB", 0)
    pagetables = pages_to_kb(stats.get("NR_PAGETABLE", 0))
    swapcache = pages_to_kb(stats.get("NR_SWAPCACHE", 0))

    # Shmem Estimation
    shmem_kb_real = pages_to_kb(stats.get("NR_SHMEM", 0))
    shmem_kb, tmpfs_kb, sysv_kb = estimate_unique_shmem_kb(debug)
    _, visible_tmpfs_kb, internal_tmpfs_kb = get_tmpfs_memory_from_superblocks(debug)
    extra_kb = max(shmem_kb - shmem_kb_real, 0)

    unaccounted = total_kb - get_accounted_memory_kb(stats, hugepage_kb, percpu_kb)

    buffers_kb = get_buffers_kb_from_blockdev(debug=debug)
    cached_kb = max(
        pages_to_kb(stats.get("NR_FILE_PAGES", 0) - stats.get("NR_SWAPCACHE", 0)) - buffers_kb,
        0
    )
    pagecache_kb = pages_to_kb(
        stats.get("NLE", 0))
    swapcache = pages_to_kb(stats.get("NR_SWAPCACHE", 0))

    # Shmem Estimation
    shmem_kb_real = pages_to_kb(stats.get("NR_SHMEM", 0))
    shmem_kb, tmpfs_kb, sysv_kb = estimate_unique_shmem_kb(debug)
    _, visible_tmpfs_kb, internal_tmpfs_kb = get_tmpfs_memory_from_superblocks(debug)
    extra_kb = max(shmem_kb - shmem_kb_rea<30}{scale(memfree):>20.2f}")
    print(f"{'Buffers':<30}{scale(buffers_kb):>20.2f}")  # Placeholder
    print(f"{'Cached':<30}{scale(cached_kb):>20.2f}")
    print(f"  {'pagecache':<28}{scale(file_pages):>20.2f}")
    print(f"  {'Shmem':28}{scale(shmem_kb_real):>20.2f}  (extra={scale(extra_kb):.2f} GiB)")
    print(f"    {'SysV (non-Hugetlb)':<26}{scale(sysv_kb):>20.2f}")
    print(f"    {'tmpfs':<26}{scale(tmpfs_kb):>20.2f}  (internal: {scale(internal_tmpfs_kb):.2f} {unit_label})")
    print(f"{'SwapCached':<30}{scale(swapcache):>20.2f}")
    print(f"{'AnonPages':<30}{scale(anon_total):>20.2f}")
    print(f"  {'Active(anon)':<28}{scale(active_anon):>20.2f}")
    print(f"  {'Inactive(anon)':<28}{scale(inactive_anon):>20.2f}")
    print(f"{'Slab':<30}{scale(slab):>20.2f}")
    print(f"{'KernelStack':<30}{scale(kernel_stack):>20.2f}")
    print(f"{'PageTables':<30}{scale(pagetables):>20.2f}")
    print(f"{'Percpu':<30}{scale(percpu_kb):>20.2f}")
    print(f"{'Vmalloc/Vmap':<30}{scale(vmalloc_kb):>20.2f}")
    print(f"{'HugePages_Total':<30}{scale(huge_total_kb):>20.2f}")
    print(f"{'HugePages_Used':<30}{scale(huge_used_kb):>20.2f}")  # Approx; you could refine this
    print(f"{'SwapTotal':<30}{scale(swap_total_kb):>20.2f}")  # Placeholder for SwapTotal
    print(f"{'SwapUsed':<30}{scale(swap_used_kb):>20.2f}")  # Placeholder
    print("=" * 50)
    print(f"{'Unaccounted:':<30}{scale(unaccounted):>20.2f}")

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
    parser.set_defaults(unit="G")
    args = parser.parse_args()

    # If no primary view option was chosen, default to -i
    if not any([args.info, args.processes]):
        args.info = True

    stats = parse_kmem_V(debug=args.debug)
    normalize_stats(stats)
    unit = args.unit

    total_kb = get_total_memory_from_kmem_i()
    hugepage_kb,_ = get_hugepage_info(debug=args.debug)
    percpu_kb = get_percpu_memory_kb()
    vmalloc_kb = get_vmalloc_memory_kb(debug=args.debug)
    stats["VMALLOC_KB"] = vmalloc_kb

    accounted_kb = get_accounted_memory_kb(stats, hugepage_kb, percpu_kb)
    unaccounted_kb = total_kb - accounted_kb
    scale = lambda val: scale_value(val, unit)
    unit_label = f"{unit}iB"

    if args.info:
        print_meminfo_style(stats, total_kb, hugepage_kb, percpu_kb, vmalloc_kb, unit, debug=args.debug)

    if args.debug:
        print("\n[debug] Parsed stats from 'kmem -V':")
        for k in sorted(stats):
            print(f"{k:<35}{stats[k]}")

    if args.verbose and args.info:
        print_unaccounted_formula(stats, total_kb, hugepage_kb, percpu_kb, unit)

    if args.processes:
        print_top_processes(10, unit=args.unit, debug=args.debug)

if __name__ == "__main__":
    main()

