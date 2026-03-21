#!/usr/bin/env python3
"""
chk_mem.py
Estimate unaccounted memory in a VMcore using crash commands.
Supports -v (verbose), -d (debug), -K/-M/-G for unit scaling.
Includes hugepages, percpu memory, and meminfo-style output.
"""

import argparse
from pykdump.API import *

from collections import defaultdict

# ANSI color codes
RED     = '\033[91m'
YELLOW  = '\033[93m'
RESET   = '\033[0m'

PAGE_SIZE = 4096  # 4 KiB

# ---------------------------------------------------------------------------
# Unit helpers
# ---------------------------------------------------------------------------

def scale_value(kb, unit):
    if unit == "K": return kb
    if unit == "M": return kb / 1024
    if unit == "G": return kb / (1024 * 1024)
    return kb

def pages_to_kb(pages): return pages * PAGE_SIZE // 1024

def bytes_to_kb(bytes_val): return bytes_val // 1024

# ---------------------------------------------------------------------------
# Slab
# ---------------------------------------------------------------------------

def get_slab_usage(debug=False, top_n=10):
    try:
        output = exec_crash_command("kmem -s")
    except Exception as e:
        if debug:
            print(f"[debug] kmem -s failed: {e}")
        return [], 0

    slabs = []
    total_kb = 0

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("CACHE"):
            continue

        parts = line.split()
        if len(parts) < 7:
            continue

        try:
            # Parse right-to-left for stability across crash versions
            name      = parts[-1]
            ssize_str = parts[-2]   # e.g. 4k / 8k / 16k / 32k
            slabs_cnt = int(parts[-3])
            total_obj = int(parts[-4])
            allocated = int(parts[-5])
            objsize   = int(parts[-6])

            if not ssize_str.lower().endswith("k"):
                continue

            slab_kb = int(ssize_str[:-1])
            mem_kb = slabs_cnt * slab_kb
            total_kb += mem_kb

            slabs.append({
                "cache": name,
                "objsize": objsize,
                "allocated": allocated,
                "total": total_obj,
                "slabs": slabs_cnt,
                "slab_kb": slab_kb,
                "mem_kb": mem_kb,
            })

        except Exception as e:
            if debug:
                print(f"[debug] slab parse failed: {line} ({e})")

    slabs.sort(key=lambda x: x["mem_kb"], reverse=True)
    return slabs[:top_n], total_kb

def print_slab_usage(unit="G", debug=False, top_n=10):
    slabs, total_kb = get_slab_usage(debug=debug, top_n=top_n)
    if not slabs:
        print("No slab data available.")
        return

    scale = lambda v: scale_value(v, unit)
    unit_label = f"{unit}iB"

    print(f"\nTop {top_n} slab caches by memory usage (unit: {unit_label}):")
    print(f"{'SLABS':>10}"
          f"{'OBJSIZE':>12}"
          f"{'SSIZE':>10}"
          f"{'MEM':>12}  CACHE")
    print("-" * 70)

    for s in slabs:
        print(f"{s['slabs']:>10}"
              f"{s['objsize']:>12}"
              f"{s['slab_kb']:>10}"
              f"{scale(s['mem_kb']):>12.2f}  {s['cache']}")

    print("-" * 70)
    print(f"{'TOTAL SLAB MEMORY':>32}{scale(total_kb):>12.2f} {unit_label}")

# ---------------------------------------------------------------------------
# tmpfs superblock walk
# ---------------------------------------------------------------------------

def get_tmpfs_superblocks(debug=False):
    all_tmpfs_sbs     = set()
    visible_tmpfs_sbs = set()

    # Collect visible tmpfs mounts from `mount`
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

    # Walk super_blocks linked list to find ALL tmpfs superblocks,
    # including internal/hidden ones not visible in `mount`.
    # Use sym2addr() so we get the raw address of the list_head symbol
    # rather than dereferencing it (which breaks on some kernel builds).
    try:
        head_addr = sym2addr("super_blocks")
        offset    = crash.member_offset("struct super_block", "s_list")
        head      = readSU("struct list_head", head_addr)
        ptr       = head.next

        while ptr and int(ptr) != head_addr:
            try:
                sb_addr = int(ptr) - offset
                sb      = readSU("struct super_block", sb_addr)
                sid     = str(sb.s_id).strip('"')
                if sid == "tmpfs":
                    all_tmpfs_sbs.add(sb_addr)
                    if debug and sb_addr not in visible_tmpfs_sbs:
                        print(f"[debug] Internal tmpfs superblock at {hex(sb_addr)}")
            except Exception as e:
                if debug:
                    print(f"[debug] Failed to parse super_block at "
                          f"{hex(int(ptr))}: {e}")
            ptr = ptr.next
    except Exception as e:
        if debug:
            print(f"[debug] Failed to iterate super_blocks list: {e}")

    return list(all_tmpfs_sbs), list(visible_tmpfs_sbs)

def get_tmpfs_memory_from_superblocks(debug=False):
    """
    Walk every tmpfs superblock's inode list and sum nrpages.
    Returns (total_kb, visible_kb, internal_kb).
    Result is cached on the function object to avoid redundant inode walks.
    """
    cache = get_tmpfs_memory_from_superblocks
    if hasattr(cache, "_result"):
        return cache._result

    total_pages   = 0
    visible_pages = 0

    all_sbs, visible_sbs = get_tmpfs_superblocks(debug)

    inode_offset   = crash.member_offset("struct inode", "i_sb_list")
    nrpages_offset = crash.member_offset("struct address_space", "nrpages")
    i_data_offset  = crash.member_offset("struct inode", "i_data")

    MAX_INODES = 100000

    for sb_addr in all_sbs:
        try:
            sb    = readSU("struct super_block", sb_addr)
            head  = sb.s_inodes
            inode = head.next

            count    = 0
            sb_pages = 0

            while inode and int(inode) != int(head) and count < MAX_INODES:
                try:
                    inode_addr   = int(inode) - inode_offset
                    i_data_addr  = inode_addr + i_data_offset
                    nrpages_addr = i_data_addr + nrpages_offset

                    nrpages   = readU64(nrpages_addr)
                    sb_pages += nrpages
                    count    += 1
                except Exception as e:
                    if debug:
                        print(f"[debug] Failed inode @ {hex(int(inode))}: {e}")
                inode = inode.next

            if count >= MAX_INODES:
                # Warn unconditionally — results will be incomplete
                print(f"[warn] inode walk truncated at {MAX_INODES} for sb "
                      f"{hex(sb_addr)}; tmpfs totals will be underestimated.")

            total_pages += sb_pages
            if sb_addr in visible_sbs:
                visible_pages += sb_pages

        except Exception as e:
            if debug:
                print(f"[debug] Failed to process sb {hex(sb_addr)}: {e}")

    result = (
        pages_to_kb(total_pages),
        pages_to_kb(visible_pages),
        pages_to_kb(total_pages - visible_pages),  # internal
    )
    cache._result = result
    return result

# ---------------------------------------------------------------------------
# SysV shared memory
# ---------------------------------------------------------------------------

def get_sysv_shm_kb(debug=False):
    """
    Return SysV shared memory in KiB (resident pages only, hugepage-adjusted).

    NOTE: SysV shm segments are backed by tmpfs internally, so their pages
    are already counted in the tmpfs inode walk.  This function exists only
    to provide a display breakdown; callers must NOT add it on top of the
    tmpfs total — that would double-count SysV memory.
    """
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
                part     = line.split(":")[1]
                resident = int(part.strip().split("/")[1])
                total_pages += resident
            except Exception as e:
                if debug:
                    print(f"[debug] Failed to parse ipc line: {line} ({e})")
                continue

    sysv_kb = pages_to_kb(total_pages)

    # Subtract hugepage-backed SysV segments to avoid double-counting
    # with the hugepage total.
    try:
        _, huge_used_kb = get_hugepage_info(debug)
        if huge_used_kb > 0:
            sysv_kb = max(sysv_kb - huge_used_kb, 0)
            if debug:
                print(f"[debug] Adjusted sysv_kb by subtracting "
                      f"HugePages_Used: -{huge_used_kb} KiB")
    except Exception as e:
        if debug:
            print(f"[debug] Failed to get hugepage info for SysV adjustment: {e}")

    return sysv_kb

def estimate_unique_shmem_kb(debug=False):
    """
    Return (total_shared_kb, tmpfs_kb, sysv_kb).

    total_shared_kb == tmpfs_kb because SysV is backed by tmpfs and is
    already counted there — do NOT add sysv_kb to the total.
    sysv_kb is returned separately for display breakdown only.
    """
    tmpfs_total_kb, _, _ = get_tmpfs_memory_from_superblocks(debug)
    sysv_kb = get_sysv_shm_kb(debug)
    return tmpfs_total_kb, tmpfs_total_kb, sysv_kb

# ---------------------------------------------------------------------------
# Buffers (blockdev page cache)
# ---------------------------------------------------------------------------

def get_buffers_kb_from_blockdev(debug=False):
    total_pages = 0
    try:
        sb   = readSymbol("blockdev_superblock")
        sb   = readSU("struct super_block", int(sb))
        head = sb.s_inodes
        inode = head.next
        while inode and int(inode) != int(head):
            try:
                container_addr = (int(inode) -
                                  crash.member_offset("struct inode", "i_sb_list"))
                container  = readSU("struct inode", container_addr)
                nrpages    = int(container.i_data.nrpages)
                total_pages += nrpages
            except Exception as e:
                if debug:
                    print(f"[debug] Failed to read inode from "
                          f"{hex(int(inode))}: {e}")
            inode = inode.next
    except Exception as e:
        if debug:
            print(f"[debug] Failed to read blockdev_superblock: {e}")
    return pages_to_kb(total_pages)

# ---------------------------------------------------------------------------
# HugePages  (result cached to avoid redundant crash commands)
# ---------------------------------------------------------------------------

def get_hugepage_info(debug=False):
    """
    Parse `kmem -h` and return (total_kb, used_kb).
    Handles size suffixes: kB/KB, MB, GB (case-insensitive, mixed-case safe).
    Result is cached on the function object.
    """
    cache = get_hugepage_info
    if hasattr(cache, "_result"):
        return cache._result

    output   = exec_crash_command("kmem -h")
    total_kb = 0
    used_kb  = 0

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("HSTATE"):
            continue
        parts = line.split()
        try:
            size_str    = parts[1]       # e.g. 2MB, 1GB, 2048kB
            free_pages  = int(parts[2])
            total_pages = int(parts[3])
            used_pages  = total_pages - free_pages

            sl = size_str.lower()
            if sl.endswith("kb"):
                size_kb = int(size_str[:-2])
            elif sl.endswith("mb"):
                size_kb = int(size_str[:-2]) * 1024
            elif sl.endswith("gb"):
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

    cache._result = (total_kb, used_kb)
    return cache._result

# ---------------------------------------------------------------------------
# Swap  (result cached)
# ---------------------------------------------------------------------------

def get_swap_info(debug=False):
    """Return (total_kb, used_kb). Result is cached."""
    cache = get_swap_info
    if hasattr(cache, "_result"):
        return cache._result

    try:
        total_pages = int(readSymbol("total_swap_pages"))
        nr_swap     = readSU("atomic_long_t", readSymbol("nr_swap_pages"))
        free_pages  = int(nr_swap.counter)
        used        = total_pages - free_pages
        result = pages_to_kb(total_pages), pages_to_kb(used)
    except Exception as e:
        if debug:
            print(f"[debug] Failed to read swap info: {e}")
        result = 0, 0

    cache._result = result
    return result

# ---------------------------------------------------------------------------
# vmalloc / vmap  — parse by header column position
# ---------------------------------------------------------------------------

def get_vmalloc_memory_kb(debug=False):
    """
    Parse `kmem -v` and sum the SIZE column.
    Column index is determined from the header line for robustness across
    crash versions and kernel configurations.
    Returns total in KiB.
    """
    total_kb = 0
    size_col = None

    try:
        output = exec_crash_command("kmem -v")
    except Exception as e:
        if debug:
            print(f"[debug] kmem -v failed: {e}")
        return 0

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("crash>"):
            continue

        # Detect header to locate SIZE column
        if line.startswith("VMAP_AREA"):
            headers = line.split()
            if "SIZE" in headers:
                size_col = headers.index("SIZE")
            elif debug:
                print(f"[debug] SIZE column not found in kmem -v header: {line}")
            continue

        parts = line.split()
        col   = size_col if size_col is not None else -1  # fall back to last

        if abs(col) >= len(parts):
            if debug:
                print(f"[debug] skipping short line: {line}")
            continue

        try:
            size_val  = int(parts[col])
            total_kb += size_val // 1024
        except ValueError:
            if debug:
                print(f"[debug] cannot parse size in line: {line}")

    return total_kb

# ---------------------------------------------------------------------------
# Per-CPU memory
# ---------------------------------------------------------------------------

def get_percpu_memory_kb():
    """
    Per-CPU memory = pcpu_nr_populated * pcpu_nr_units pages.
    Both symbols count pages; convert to KiB with pages_to_kb().
    """
    try:
        populated = int(readSymbol("pcpu_nr_populated"))
        units     = int(readSymbol("pcpu_nr_units"))
        return pages_to_kb(populated * units)
    except Exception:
        return 0

# ---------------------------------------------------------------------------
# kmem -V parser and stat normalization
# ---------------------------------------------------------------------------

def parse_kmem_V(debug=False):
    output = exec_crash_command("kmem -V")
    stats  = {}
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
        val_str = val_part.split()[0].strip()
        try:
            stats[key] = int(val_str)
        except ValueError:
            if debug:
                print(f"[debug] Value conversion failed for '{key}': '{val_str}'")
    return stats

def normalize_stats(stats):
    """
    Normalise counter names across RHEL7 / RHEL8+ kernel variants.

    NR_SLAB_RECLAIMABLE_B / NR_SLAB_UNRECLAIMABLE_B: despite the '_B' suffix,
    these hold page counts in RHEL7+ (not bytes).  We treat them as pages and
    always convert with pages_to_kb() downstream.

    NR_KERNEL_STACK_KB / NR_KERNEL_STACK: already in KiB on all supported
    kernels.  Copy the old name verbatim — do NOT multiply by PAGE_SIZE.

    NR_ACTIVE_ANON / NR_INACTIVE_ANON: on RHEL8+ these do NOT include shmem
    (shmem was split off into NR_SHMEM).  On RHEL7 they DO include shmem.
    We set '_SHMEM_IN_ANON' so callers can subtract NR_SHMEM when needed.

    NR_ANON_PAGES: fallback for very old RHEL7 kernels lacking the
    active/inactive split.
    """
    # Slab counter aliases
    if "NR_SLAB_RECLAIMABLE_B" not in stats and "NR_SLAB_RECLAIMABLE" in stats:
        stats["NR_SLAB_RECLAIMABLE_B"] = stats["NR_SLAB_RECLAIMABLE"]

    if "NR_SLAB_UNRECLAIMABLE_B" not in stats and "NR_SLAB_UNRECLAIMABLE" in stats:
        stats["NR_SLAB_UNRECLAIMABLE_B"] = stats["NR_SLAB_UNRECLAIMABLE"]

    # KernelStack alias — value is already KiB in both old and new names
    if "NR_KERNEL_STACK_KB" not in stats and "NR_KERNEL_STACK" in stats:
        stats["NR_KERNEL_STACK_KB"] = stats["NR_KERNEL_STACK"]

    # Anon fallback for very old RHEL7 kernels
    if ("NR_ACTIVE_ANON" not in stats and
            "NR_INACTIVE_ANON" not in stats and
            "NR_ANON_PAGES" in stats):
        stats["NR_ACTIVE_ANON"]   = stats["NR_ANON_PAGES"]
        stats["NR_INACTIVE_ANON"] = 0
        print("[warn] NR_ACTIVE/INACTIVE_ANON not found; "
              "using NR_ANON_PAGES as Active(anon) approximation.")

    # On RHEL7, NR_SHMEM did not exist; anon counters included shmem pages.
    stats["_SHMEM_IN_ANON"] = "NR_SHMEM" not in stats

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

# ---------------------------------------------------------------------------
# Memory accounting
# ---------------------------------------------------------------------------

def get_accounted_memory_kb(stats, hugepage_kb, percpu_kb, vmalloc_kb):
    """
    Sum all known-accounted memory categories, in KiB.

    Anon handling:
      RHEL8+: NR_ACTIVE_ANON + NR_INACTIVE_ANON exclude shmem — use as-is.
      RHEL7:  they include shmem — subtract NR_SHMEM to avoid
              double-counting with NR_FILE_PAGES (which also includes shmem).
    """
    shmem_in_anon = stats.get("_SHMEM_IN_ANON", False)
    shmem_pages   = stats.get("NR_SHMEM", 0) if shmem_in_anon else 0

    anon_kb = pages_to_kb(
        stats.get("NR_ACTIVE_ANON", 0) +
        stats.get("NR_INACTIVE_ANON", 0) -
        shmem_pages
    )

    file_kb = pages_to_kb(stats.get("NR_FILE_PAGES", 0))

    slab_kb = pages_to_kb(
        stats.get("NR_SLAB_RECLAIMABLE_B", 0) +
        stats.get("NR_SLAB_UNRECLAIMABLE_B", 0)
    )

    return sum([
        anon_kb,
        file_kb,
        pages_to_kb(stats.get("NR_FREE_PAGES", 0)),
        slab_kb,
        stats.get("NR_KERNEL_STACK_KB", 0),  # already KiB — do NOT call pages_to_kb()
        pages_to_kb(stats.get("NR_PAGETABLE", 0)),
        pages_to_kb(stats.get("NR_SWAPCACHE", 0)),
        hugepage_kb,
        percpu_kb,
        # vmalloc_kb excluded — vmap ranges overlap with other categories
    ])

# ---------------------------------------------------------------------------
# Process / command memory
# ---------------------------------------------------------------------------

def get_process_shmem_kb(task_addr, debug=False):
    try:
        if isinstance(task_addr, str):
            task_addr = (int(task_addr, 16) if task_addr.startswith("0x")
                         else int("0x" + task_addr, 16))

        if debug:
            print(f"[debug] normalized task_addr -> {hex(task_addr)}")

        task = readSU("struct task_struct", task_addr)
        mm   = task.mm
        if not mm:
            return 0

        total_kb = 0
        vma      = mm.mmap
        while vma:
            flags = int(vma.vm_flags)
            if flags & 0x00000008:  # VM_SHARED
                total_kb += (int(vma.vm_end) - int(vma.vm_start)) // 1024
            vma = vma.vm_next
        return total_kb

    except Exception as e:
        if debug:
            addr_str = hex(task_addr) if isinstance(task_addr, int) else task_addr
            print(f"[debug] get_process_shmem_kb failed for {addr_str}: {e}")
        return 0

def _parse_ps_lines(debug=False):
    """Parse `ps -G` output into a list of process dicts (shm not computed)."""
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
            procs.append({
                "pid":    int(parts[0]),
                "ppid":   int(parts[1]),
                "cpu":    int(parts[2]),
                "task":   parts[3],
                "state":  parts[4],
                "mempct": parts[5],
                "vsz":    int(parts[6]),
                "rss":    int(parts[7]),
                "comm":   " ".join(parts[8:]),
            })
        except Exception as e:
            if debug:
                print(f"[debug] parse error: {e} in line: {line}")

    return procs

def get_top_processes(n=10, debug=False):
    procs = _parse_ps_lines(debug)
    procs.sort(key=lambda p: p["rss"], reverse=True)
    top = procs[:n]
    # Compute SHM only for the displayed top-N to limit VMA walk overhead
    for p in top:
        p["shm"] = get_process_shmem_kb(p["task"], debug)
    return top, procs

def print_top_processes(n=10, unit="G", debug=False):
    top, all_procs = get_top_processes(n, debug)
    if not top:
        print("No process data available.")
        return

    scale      = lambda val: scale_value(val, unit)
    unit_label = f"{unit}iB"

    print(f"\nTop processes by RSS (unit: {unit_label}):")
    print(f"{'PID':>8} {'PPID':>8} {'CPU':>4} "
          f"{'RSS':>12} {'VSZ':>12} {'SHM':>12}  COMM")
    print("-" * 80)

    for p in top:
        print(f"{p['pid']:>8} {p['ppid']:>8} {p['cpu']:>4} "
              f"{scale(p['rss']):>12.2f} {scale(p['vsz']):>12.2f} "
              f"{scale(p.get('shm', 0)):>12.2f}  {p['comm']}")

    total_rss = sum(p["rss"]        for p in all_procs)
    total_vsz = sum(p["vsz"]        for p in all_procs)
    total_shm = sum(p.get("shm", 0) for p in all_procs)

    print("-" * 80)
    print(f"{'TOTAL (all processes)':>22} "
          f"{scale(total_rss):>12.2f} {scale(total_vsz):>12.2f} "
          f"{scale(total_shm):>12.2f}")

def print_command_memory_usage(unit="G", debug=False, top_n=10):
    """
    Aggregate RSS/VSZ by command name.
    SHM walk is intentionally skipped here — walking every process's VMA list
    is very slow on large vmcores.  Use -p for per-process SHM on the top-N.
    """
    procs = _parse_ps_lines(debug)
    if not procs:
        print("No process data available.")
        return

    command_map = defaultdict(lambda: {"rss": 0, "vsz": 0, "count": 0})
    for p in procs:
        entry = command_map[p["comm"]]
        entry["rss"]   += p["rss"]
        entry["vsz"]   += p["vsz"]
        entry["count"] += 1

    scale      = lambda val: scale_value(val, unit)
    unit_label = f"{unit}iB"

    print(f"\nTop {top_n} commands by total RSS (unit: {unit_label}):")
    print(f"  (SHM column omitted; use -p for per-process SHM detail)")
    print(f"{'Count':>8}{'RSS':>15}{'VSZ':>15}  {'COMMAND'}")
    print("-" * 68)

    sorted_cmds = sorted(command_map.items(),
                         key=lambda x: x[1]["rss"], reverse=True)[:top_n]
    for comm, data in sorted_cmds:
        print(f"{data['count']:>8}{scale(data['rss']):>15.2f}"
              f"{scale(data['vsz']):>15.2f}  {comm}")

    total_rss   = sum(d["rss"]   for d in command_map.values())
    total_vsz   = sum(d["vsz"]   for d in command_map.values())
    total_count = sum(d["count"] for d in command_map.values())

    print("-" * 68)
    print(f"{total_count:>8}{scale(total_rss):>15.2f}"
          f"{scale(total_vsz):>15.2f}  TOTAL (all processes)")

# ---------------------------------------------------------------------------
# Verbose formula output
# ---------------------------------------------------------------------------

def print_unaccounted_formula(stats, total_kb, hugepage_kb, percpu_kb, unit):
    def p(name): return stats.get(name, 0)
    def kb(pages): return pages_to_kb(pages)
    def scale(val): return scale_value(val, unit)

    shmem_in_anon = stats.get("_SHMEM_IN_ANON", False)
    shmem_pages   = p("NR_SHMEM") if shmem_in_anon else 0

    fields = [
        ("Active Anon",        kb(p("NR_ACTIVE_ANON"))),
        ("Inactive Anon",      kb(p("NR_INACTIVE_ANON"))),
        ("(-Shmem)",           -kb(shmem_pages)),      # subtracted on RHEL7
        ("Slab Reclaimable",   kb(p("NR_SLAB_RECLAIMABLE_B"))),
        ("Slab Unreclaimable", kb(p("NR_SLAB_UNRECLAIMABLE_B"))),
        ("Free",               kb(p("NR_FREE_PAGES"))),
        ("PageCache",          kb(p("NR_FILE_PAGES"))),
        ("KernelStack",        p("NR_KERNEL_STACK_KB")),  # already KiB
        ("PageTables",         kb(p("NR_PAGETABLE"))),
        ("SwapCache",          kb(p("NR_SWAPCACHE"))),
        ("HugePages",          hugepage_kb),
        ("Percpu",             percpu_kb),
        # vmalloc excluded — overlaps with other categories
    ]

    # Drop zero/no-op fields for cleaner output (e.g. (-Shmem) on RHEL8+)
    fields = [(n, v) for n, v in fields if v != 0]

    accounted   = sum(val for _, val in fields)
    unaccounted = total_kb - accounted

    if percpu_kb > 0:
        try:
            populated = int(readSymbol("pcpu_nr_populated"))
            units_sym = int(readSymbol("pcpu_nr_units"))
            print(f"\n[verbose] Percpu = pcpu_nr_populated({populated}) * "
                  f"pcpu_nr_units({units_sym}) * PAGE_SIZE({PAGE_SIZE}) / 1024")
            print(f"[verbose] Percpu = {populated * units_sym * PAGE_SIZE // 1024} KiB\n")
        except Exception:
            print("[verbose] Percpu: symbol not available or failed to read.\n")

    unit_label = f"{unit}iB"

    print("Unaccounted memory formula (approx):")
    # Print in rows of up to 5 fields to avoid horizontal overflow
    CHUNK = 5
    chunks = [fields[i:i+CHUNK] for i in range(0, len(fields), CHUNK)]
    first  = True
    for chunk_fields in chunks:
        if first:
            name_prefix = f"{'Unaccounted':<15}= {'Total':<12}- "
            val_prefix  = f"{scale(unaccounted):<15.2f}  {scale(total_kb):<12.2f}  "
        else:
            name_prefix = " " * 30
            val_prefix  = " " * 30
        print(name_prefix + " - ".join(n          for n, _ in chunk_fields))
        print(val_prefix  + " - ".join(f"{scale(v):.2f}" for _, v in chunk_fields))
        first = False

    print(f"\nUnaccounted total: {scale(unaccounted):.2f} {unit_label}")
    print("Note: excludes reserved, memmap, directmap, early bootmem, "
          "and other special pools.\n")

# ---------------------------------------------------------------------------
# Main meminfo-style report
# ---------------------------------------------------------------------------

def print_meminfo_style(stats, total_kb, hugepage_kb, percpu_kb, vmalloc_kb,
                        unit, debug=False,
                        tmpfs_result=None, hugepage_result=None,
                        swap_result=None):
    unit_label = f"{unit}iB"
    scale      = lambda val: scale_value(val, unit)

    memfree       = pages_to_kb(stats.get("NR_FREE_PAGES", 0))
    active_anon   = pages_to_kb(stats.get("NR_ACTIVE_ANON", 0))
    inactive_anon = pages_to_kb(stats.get("NR_INACTIVE_ANON", 0))
    anon_total    = active_anon + inactive_anon
    slab          = pages_to_kb(stats.get("NR_SLAB_RECLAIMABLE_B", 0) +
                                stats.get("NR_SLAB_UNRECLAIMABLE_B", 0))
    kernel_stack  = stats.get("NR_KERNEL_STACK_KB", 0)  # already KiB
    pagetables    = pages_to_kb(stats.get("NR_PAGETABLE", 0))
    swapcache     = pages_to_kb(stats.get("NR_SWAPCACHE", 0))

    # Shmem
    shmem_kb_real = pages_to_kb(stats.get("NR_SHMEM", 0))

    # Use pre-computed tmpfs result to avoid a second expensive inode walk
    if tmpfs_result is None:
        tmpfs_result = get_tmpfs_memory_from_superblocks(debug)
    tmpfs_total_kb, visible_tmpfs_kb, internal_tmpfs_kb = tmpfs_result

    sysv_kb  = get_sysv_shm_kb(debug)
    # SysV is backed by tmpfs — extra = tmpfs above what NR_SHMEM reports
    extra_kb = max(tmpfs_total_kb - shmem_kb_real, 0)

    buffers_kb = get_buffers_kb_from_blockdev(debug=debug)

    # Cached = file pages minus swap cache minus buffers
    file_minus_swap = pages_to_kb(
        stats.get("NR_FILE_PAGES", 0) - stats.get("NR_SWAPCACHE", 0)
    )
    cached_kb    = max(file_minus_swap - buffers_kb, 0)
    cached_pages = max(cached_kb - shmem_kb_real, 0)

    # Use pre-computed hugepage / swap results (avoids redundant crash cmds)
    if hugepage_result is None:
        hugepage_result = get_hugepage_info(debug=debug)
    huge_total_kb, huge_used_kb = hugepage_result

    if swap_result is None:
        swap_result = get_swap_info(debug=debug)
    swap_total_kb, swap_used_kb = swap_result

    unaccounted     = total_kb - get_accounted_memory_kb(
        stats, hugepage_kb, percpu_kb, vmalloc_kb
    )
    unaccounted_pct = (unaccounted / total_kb * 100) if total_kb else 0

    # Colour the unaccounted line: red > 5 %, yellow > 1 %
    if unaccounted_pct > 5:
        color = RED
    elif unaccounted_pct > 1:
        color = YELLOW
    else:
        color = ""

    print(f"{'Field':<30}{'Size (' + unit_label + ')':>20}")
    print("=" * 50)
    print(f"{'MemTotal:':<30}{scale(total_kb):>20.2f}")
    print(f"{'MemFree':<30}{scale(memfree):>20.2f}")
    print(f"{'Buffers':<30}{scale(buffers_kb):>20.2f}")
    print(f"{'Cached':<30}{scale(cached_kb):>20.2f}")
    print(f"  {'pagecache(estimated)':<28}{scale(cached_pages):>20.2f}")
    print(f"  {'Shmem':<28}{scale(shmem_kb_real):>20.2f}"
          f"  (extra={scale(extra_kb):.2f} {unit_label})")
    print(f"    {'SysV (non-Hugetlb)':<26}{scale(sysv_kb):>20.2f}")
    print(f"    {'tmpfs':<26}{scale(tmpfs_total_kb):>20.2f}")
    print(f"      {'visible tmpfs':<24}{scale(visible_tmpfs_kb):>20.2f}")
    print(f"      {'internal tmpfs':<24}{scale(internal_tmpfs_kb):>20.2f}"
          f"  (including SysV: {scale(sysv_kb):.2f})")
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
    print(f"{'HugePages_Used':<30}{scale(huge_used_kb):>20.2f}")
    print(f"{'SwapTotal':<30}{scale(swap_total_kb):>20.2f}")
    print(f"{'SwapUsed':<30}{scale(swap_used_kb):>20.2f}")
    print("=" * 50)
    print(f"{color}"
          f"{'Unaccounted:':<30}{scale(unaccounted):>20.2f}"
          f"  ({unaccounted_pct:.1f}%)"
          f"{RESET if color else ''}")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Estimate unaccounted memory from VMcore."
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--info", action="store_true",
                       help="Show summarized usage breakdown (default)")
    group.add_argument("-p", "--processes", action="store_true",
                       help="Show top 10 processes by RSS")
    group.add_argument("-c", "--commands", action="store_true",
                       help="Show aggregated memory usage per command "
                            "(SHM omitted for performance; use -p for SHM detail)")
    group.add_argument("-s", "--slab", action="store_true",
                       help="Show slab cache memory usage (from kmem -s)")

    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-d", "--debug",   action="store_true")
    parser.add_argument("-K", action="store_const", dest="unit", const="K",
                        help="Show memory in KiB")
    parser.add_argument("-M", action="store_const", dest="unit", const="M",
                        help="Show memory in MiB")
    parser.add_argument("-G", action="store_const", dest="unit", const="G",
                        help="Show memory in GiB")
    parser.set_defaults(unit="G")

    args = parser.parse_args()
    unit = args.unit

    # Default to -i
    if not any([args.info, args.processes, args.commands, args.slab]):
        args.info = True

    # -p
    if args.processes:
        print_top_processes(10, unit=unit, debug=args.debug)
        return

    # -c
    if args.commands:
        print_command_memory_usage(unit=unit, debug=args.debug, top_n=10)
        return

    # -s
    if args.slab:
        print_slab_usage(unit=unit, debug=args.debug, top_n=10)
        return

    # -i / -v : full memory accounting
    stats = parse_kmem_V(debug=args.debug)
    normalize_stats(stats)

    total_kb   = get_total_memory_from_kmem_i()
    percpu_kb  = get_percpu_memory_kb()
    vmalloc_kb = get_vmalloc_memory_kb(debug=args.debug)
    stats["VMALLOC_KB"] = vmalloc_kb

    # Pre-compute all expensive/cached results once
    hugepage_result = get_hugepage_info(debug=args.debug)
    hugepage_kb     = hugepage_result[0]
    swap_result     = get_swap_info(debug=args.debug)
    tmpfs_result    = get_tmpfs_memory_from_superblocks(debug=args.debug)

    if args.info:
        print_meminfo_style(
            stats, total_kb, hugepage_kb, percpu_kb, vmalloc_kb,
            unit, debug=args.debug,
            tmpfs_result=tmpfs_result,
            hugepage_result=hugepage_result,
            swap_result=swap_result,
        )

    if args.verbose:
        print_unaccounted_formula(
            stats, total_kb, hugepage_kb, percpu_kb, unit
        )

    if args.debug:
        print("\n[debug] Parsed stats from 'kmem -V':")
        for k in sorted(stats):
            print(f"  {k:<35}{stats[k]}")

if __name__ == "__main__":
    main()
