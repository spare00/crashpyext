#!/usr/bin/env epython3
# -*- coding: utf-8 -*-
"""
chk_xfsbuf.py
Estimate memory used by XFS metadata buffer cache (xfs_buf) in a vmcore.

Approach:
  Fast mode (default):
    1) Discover the slab cache that holds struct xfs_buf objects.
    2) Read slab summary from `kmem -s <cache>`.
    3) Enumerate visible allocated objects with `kmem -S <cache>`.
    4) Read each xfs_buf and sum b_page_count * PAGE_SIZE.

  Full mode:
    Walk kmem_cache CPU/node slab pages and parse each slab page.
    This is slower, but can include FULL slabs when the kernel exposes them.
"""

import argparse
import re
from pykdump.API import *
from LinuxDump import crash

DEFAULT_PAGE_SIZE = 4096
PTR_SIZE = 8
_STRUCT_FIELD_CACHE = {}
_SYS_CACHE = None
_SECTIONS = None
DEFAULT_PAGES_PER_SECTION = 0x8000
SECTION_MAP_MASK_FALLBACK = ~0xFF


class CacheSummary:
    def __init__(self, cache_name, cache_addr=0, objsize=0, allocated=0, total=0,
                 slabs=0, ssize_kb=0):
        self.cache_name = cache_name
        self.cache_addr = cache_addr
        self.objsize = objsize
        self.allocated = allocated
        self.total = total
        self.slabs = slabs
        self.ssize_kb = ssize_kb

    @property
    def slab_footprint_kb(self):
        return self.slabs * self.ssize_kb

    @property
    def live_payload_kb(self):
        return (self.allocated * self.objsize) // 1024


class EstimateResult:
    def __init__(self, mode, summary, page_size, addrs, counted, total_kb, tops,
                 complete, note=None):
        self.mode = mode
        self.summary = summary
        self.page_size = page_size
        self.addrs = addrs
        self.counted = counted
        self.total_kb = total_kb
        self.tops = tops
        self.complete = complete
        self.note = note


class SectionRow:
    def __init__(self, nr, addr, pfn_base):
        self.nr = nr
        self.addr = addr
        self.pfn_base = pfn_base


def _read_sys_output():
    global _SYS_CACHE
    if _SYS_CACHE is None:
        _SYS_CACHE = exec_crash_command("sys")
    return _SYS_CACHE

def _is_tty():
    import sys
    try:
        return sys.stdout.isatty()
    except Exception:
        return False

def _color(s, code): return f"\033[{code}m{s}\033[0m" if _is_tty() else str(s)
def green(s):  return _color(s, "32")
def yellow(s): return _color(s, "33")
def cyan(s):   return _color(s, "36")


def fmt_mib_gib(kb):
    return f"{kb/1024:.2f} MiB / {kb/1024/1024:.2f} GiB"


def member_offset(typename, member):
    key = (typename, member)
    if key in _STRUCT_FIELD_CACHE:
        return _STRUCT_FIELD_CACHE[key]
    off = None
    try:
        import crash as _cr
        if hasattr(_cr, "member_offset"):
            off = _cr.member_offset(typename, member)
            if off is not None and off != -1:
                off = int(off)
            else:
                off = None
    except Exception:
        off = None
    if off is None:
        try:
            out = exec_crash_command(f"struct {typename} -o")
            m = re.search(
                rf'^\s*\[(0x[0-9a-fA-F]+|\d+)\]\s+.*\b{re.escape(member)}\b(?:\[.*\])?;',
                out,
                re.MULTILINE,
            )
            if m:
                off = int(m.group(1), 0)
        except Exception:
            off = None
    _STRUCT_FIELD_CACHE[key] = off
    return off


def has_member(typename, member):
    return member_offset(typename, member) is not None


def first_existing_member(typename, candidates):
    for member in candidates:
        if has_member(typename, member):
            return member
    return None


def parse_int_auto(tok):
    s = tok.strip().lower().strip(",")
    if s.startswith("0x"):
        return int(s, 16)
    if re.fullmatch(r"[0-9a-f]+", s):
        return int(s, 16)
    return int(s, 10)


def detect_ptr_size():
    out = _read_sys_output()
    for line in out.splitlines():
        if line.startswith("MACHINE:"):
            lower = line.lower()
            if "x86_64" in lower or "aarch64" in lower or "ppc64" in lower or "64" in lower:
                return 8
            break
    return PTR_SIZE


def get_cpu_count():
    out = _read_sys_output()
    for line in out.splitlines():
        m = re.search(r'CPUS:\s*(\d+)', line)
        if m:
            return int(m.group(1))
    for sym in ("nr_cpu_ids", "nr_cpumask_bits"):
        try:
            return int(readSymbol(sym))
        except Exception:
            pass
    return 1


def get_node_count():
    for sym in ("nr_node_ids",):
        try:
            val = int(readSymbol(sym))
            if val > 0:
                return val
        except Exception:
            pass
    out = _read_sys_output()
    for line in out.splitlines():
        m = re.search(r'available:\s*(\d+)\s+nodes', line)
        if m:
            return int(m.group(1))
    return 1


def parse_this_cpu_off(cpu):
    try:
        out = exec_crash_command(f"p this_cpu_off:{cpu}")
    except Exception:
        return None
    m = re.search(r'=\s*(0x[0-9a-fA-F]+|\d+)', out)
    if not m:
        return None
    return int(m.group(1), 0)


def get_percpu_struct_addr(cache_addr, field, cpu):
    off = member_offset("struct kmem_cache", field)
    if off is None:
        return None
    try:
        percpu_off = int(readULong(cache_addr + off))
    except Exception:
        return None
    cpu_base = parse_this_cpu_off(cpu)
    if cpu_base is None:
        return None
    addr = cpu_base + percpu_off
    return addr if addr else None


def get_struct_size(typename, default=0):
    try:
        out = exec_crash_command(f"p/x sizeof({typename})")
        m = re.search(r'=\s*(0x[0-9a-fA-F]+|\d+)', out)
        if m:
            return int(m.group(1), 0)
    except Exception:
        pass
    return default


def get_pages_per_section():
    rows = parse_kmem_n_sections_once()
    if len(rows) >= 2:
        diffs = []
        for i in range(1, min(len(rows), 8)):
            diff = rows[i].pfn_base - rows[i - 1].pfn_base
            if diff > 0:
                diffs.append(diff)
        if diffs:
            return diffs[0]
    return DEFAULT_PAGES_PER_SECTION


def parse_kmem_n_sections_once():
    global _SECTIONS
    if _SECTIONS is not None:
        return _SECTIONS

    out = exec_crash_command("kmem -n")
    rows = []
    in_table = False
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("NR") and "SECTION" in s and "PFN" in s:
            in_table = True
            continue
        if not in_table or not s or not s[0].isdigit():
            continue
        toks = re.split(r"\s+", s)
        try:
            nr = int(toks[0], 10)
            sec_addr = parse_int_auto(toks[1])
            pfn_base = parse_int_auto(toks[-1])
        except Exception:
            m = re.match(r"^(\d+)\s+([0-9A-Fa-fx]+)\s+.*?([0-9A-Fa-fx]+)\s*$", s)
            if not m:
                continue
            nr = int(m.group(1), 10)
            sec_addr = parse_int_auto(m.group(2))
            pfn_base = parse_int_auto(m.group(3))
        rows.append(SectionRow(nr, sec_addr, pfn_base))

    if not rows:
        raise RuntimeError("Could not parse sections from `kmem -n`.")
    rows.sort(key=lambda r: r.pfn_base)
    _SECTIONS = rows
    return rows


def get_page_size(debug=False):
    """Derive PAGE_SIZE from `sys` output, falling back to 4 KiB."""
    try:
        out = _read_sys_output()
        for line in out.splitlines():
            if "PAGE SIZE" not in line:
                continue
            match = re.search(r"PAGE SIZE:\s*(\d+)", line)
            if match:
                return int(match.group(1))
    except Exception as e:
        if debug:
            print(f"[debug] Failed to derive PAGE_SIZE from `sys`: {e}")
    return DEFAULT_PAGE_SIZE

def find_xfs_buf_cache_name(debug=False):
    """
    Parse `kmem -s list` to find the cache that stores struct xfs_buf.
    Prefer exact 'xfs_buf', but accept variants (e.g., SLUB merging names).
    """
    out = exec_crash_command("kmem -s list")
    names = []
    for line in out.splitlines():
        # Accept either:
        #   "ffff8db6f37e8500  912  547960  558900  16440  32k  xfs_inode"
        # or the shorter:
        #   "ffff95228cc5b640 xfs_buf"
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[-1]
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", name):
            continue
        names.append(name)

    # Try most likely names first
    candidates = []
    for n in names:
        if n == "xfs_buf":
            return "xfs_buf"
    # Fallback: regex match
    for n in names:
        if re.search(r'\bxfs[_-]?buf\b', n):
            candidates.append(n)

    if candidates:
        # choose the shortest/most canonical one
        candidates.sort(key=len)
        if debug:
            print(f"[debug] Using slab cache '{candidates[0]}' from candidates: {candidates}")
        return candidates[0]

    if debug:
        print("[debug] No xfs_buf-like cache found in `kmem -s list`.")
    return None


def get_cache_summary(cache_name, debug=False):
    """
    Parse `kmem -s <cache_name>` and return object/slab accounting.
    """
    try:
        out = exec_crash_command(f"kmem -s {cache_name}")
    except Exception as e:
        if debug:
            print(f"[debug] kmem -s {cache_name} failed: {e}")
        return None

    summary = None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 7:
            continue
        if parts[-1] != cache_name:
            continue
        try:
            cache_addr = int(parts[0], 16)
            objsize = int(parts[1], 0)
            allocated = int(parts[2], 0)
            total = int(parts[3], 0)
            slabs = int(parts[4], 0)
            ssize_tok = parts[5].lower()
            if ssize_tok.endswith("k"):
                ssize_kb = int(ssize_tok[:-1], 0)
            elif ssize_tok.endswith("m"):
                ssize_kb = int(float(ssize_tok[:-1]) * 1024)
            else:
                ssize_kb = int(ssize_tok, 0) // 1024
            summary = CacheSummary(
                cache_name=cache_name,
                cache_addr=cache_addr,
                objsize=objsize,
                allocated=allocated,
                total=total,
                slabs=slabs,
                ssize_kb=ssize_kb,
            )
            break
        except Exception as e:
            if debug:
                print(f"[debug] Failed to parse kmem -s row {line!r}: {e}")
    return summary

def parse_kmem_S_objects(cache_name, debug=False):
    """
    Return a list of object addresses from `kmem -S <cache_name>`.
    We only parse the object-address lines from the SLAB sections.
    """
    if not cache_name:
        return []
    try:
        out = exec_crash_command(f"kmem -S {cache_name}")
    except Exception as e:
        if debug:
            print(f"[debug] kmem -S {cache_name} failed: {e}")
        return []

    objs = []
    in_object_list = False
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("CPU ") or s.startswith("KMEM_CACHE_NODE") or s.startswith("NODE "):
            in_object_list = False
            continue
        if s.startswith("SLAB"):
            in_object_list = False
            continue
        if s.startswith("CACHE"):
            in_object_list = False
            continue
        if s.startswith("FREE /"):
            in_object_list = True
            continue
        if not in_object_list:
            continue
        if s == "(empty)" or s == "(not tracked)":
            continue

        # `FREE / [ALLOCATED]` is followed by mixed rows:
        #   ffff... (cpu N cache)   -> free/per-cpu cached object
        #  [ffff...]                -> allocated object
        # Keep scanning until the next section header and only collect
        # the bracketed allocated rows.
        match = re.fullmatch(r"\[\s*(0x)?([0-9a-fA-F]+)\s*\]", s)
        if match:
            objs.append(int(match.group(2), 16))

    # Deduplicate
    objs = list(dict.fromkeys(objs))
    if debug:
        print(f"[debug] kmem -S {cache_name}: found {len(objs)} objects")
    return objs


def parse_kmem_page_objects(page_addr, debug=False):
    """
    Return allocated object addresses from `kmem <page_addr>`.
    """
    try:
        out = exec_crash_command(f"kmem 0x{page_addr:x}")
    except Exception as e:
        if debug:
            print(f"[debug] kmem 0x{page_addr:x} failed: {e}")
        return []

    objs = []
    in_object_list = False
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("PAGE"):
            in_object_list = False
            continue
        if s.startswith("FREE /"):
            in_object_list = True
            continue
        if not in_object_list:
            continue
        match = re.fullmatch(r"\[\s*(0x)?([0-9a-fA-F]+)\s*\]", s)
        if match:
            objs.append(int(match.group(2), 16))
    return objs


def get_section_mem_map_base(sec_addr):
    sec = readSU("struct mem_section", sec_addr)
    raw = int(sec.section_mem_map)
    if raw == 0:
        return 0
    if (raw & 0x2) == 0:
        return 0
    return raw & SECTION_MAP_MASK_FALLBACK


def iter_cache_backed_slab_pages(summary, debug=False):
    """
    Globally scan struct page arrays and find pages whose mapping points to the
    target kmem_cache. This does not require kmem_cache_node/full lists.
    """
    rows = parse_kmem_n_sections_once()
    pages_per_section = get_pages_per_section()
    page_struct_sz = get_struct_size("struct page")
    mapping_off = member_offset("struct page", "mapping")
    if page_struct_sz <= 0 or mapping_off is None:
        if debug:
            print("[debug] global scan unavailable: sizeof(struct page) or mapping offset missing")
        return set()

    cache_addr_masked = int(summary.cache_addr) & SECTION_MAP_MASK_FALLBACK
    candidate_pages = set()
    chunk_pages = 2048

    for row in rows:
        base = get_section_mem_map_base(row.addr)
        if not base:
            continue
        for idx in range(0, pages_per_section, chunk_pages):
            count = min(chunk_pages, pages_per_section - idx)
            start = base + ((row.pfn_base + idx) * page_struct_sz)
            size = count * page_struct_sz
            try:
                blob = readmem(start, size)
            except Exception as e:
                if debug:
                    print(f"[debug] readmem section {row.nr} offset {idx} failed: {e}")
                continue
            for i in range(count):
                off = i * page_struct_sz + mapping_off
                try:
                    mapping = int.from_bytes(blob[off:off + PTR_SIZE], "little")
                except Exception:
                    continue
                if not mapping:
                    continue
                if (mapping & SECTION_MAP_MASK_FALLBACK) != cache_addr_masked:
                    continue
                pfn = row.pfn_base + idx + i
                page_addr = base + (pfn * page_struct_sz)
                candidate_pages.add(page_addr)

    if debug:
        print(f"[debug] global candidate pages  : {len(candidate_pages)}")
    return candidate_pages


def get_slab_struct_type():
    if has_member("struct slab", "slab_list"):
        return "struct slab"
    return "struct page"


def get_slab_list_field(struct_type):
    return first_existing_member(struct_type, ("slab_list", "lru", "list"))


def get_cpu_slab_pages(cache_addr, debug=False):
    pages = set()
    cpu_struct_field = "cpu_slab"
    cpu_count = get_cpu_count()
    active_field = None
    partial_field = None

    for candidate in ("slab", "page"):
        if has_member("struct kmem_cache_cpu", candidate):
            active_field = candidate
            break
    for candidate in ("partial",):
        if has_member("struct kmem_cache_cpu", candidate):
            partial_field = candidate
            break

    if active_field is None:
        if debug:
            print("[debug] struct kmem_cache_cpu has no slab/page field")
        return pages

    for cpu in range(cpu_count):
        percpu_addr = get_percpu_struct_addr(cache_addr, cpu_struct_field, cpu)
        if not percpu_addr:
            continue
        try:
            cpu_slab = readSU("struct kmem_cache_cpu", percpu_addr)
        except Exception as e:
            if debug:
                print(f"[debug] readSU(struct kmem_cache_cpu, 0x{percpu_addr:x}) failed: {e}")
            continue
        for field in (active_field, partial_field):
            if not field:
                continue
            try:
                page_addr = int(getattr(cpu_slab, field))
            except Exception:
                page_addr = 0
            if page_addr:
                pages.add(page_addr)
    if debug:
        print(f"[debug] cpu slab pages         : {len(pages)}")
    return pages


def get_node_slab_pages(cache_addr, debug=False):
    pages = set()
    list_counts = {}
    node_member_off = member_offset("struct kmem_cache", "node")
    if node_member_off is None:
        return pages

    node_count = get_node_count()
    ptr_size = detect_ptr_size()
    slab_struct = get_slab_struct_type()
    list_field = get_slab_list_field(slab_struct)
    if list_field is None:
        if debug:
            print(f"[debug] Could not find list field for {slab_struct}")
        return pages

    for nodeid in range(node_count):
        try:
            node_addr = readPtr(cache_addr + node_member_off + (nodeid * ptr_size))
        except Exception:
            continue
        if not node_addr:
            continue
        for list_name in ("partial", "full"):
            list_off = member_offset("struct kmem_cache_node", list_name)
            if list_off is None:
                continue
            head_addr = node_addr + list_off
            try:
                slabs = readSUListFromHead(head_addr, list_field, slab_struct, maxel=100000)
            except Exception as e:
                if debug:
                    print(f"[debug] readSUListFromHead({list_name}) failed for node {nodeid}: {e}")
                continue
            list_counts[list_name] = list_counts.get(list_name, 0) + len(slabs)
            for slab in slabs:
                try:
                    pages.add(int(slab))
                except Exception:
                    try:
                        pages.add(int(Addr(slab)))
                    except Exception:
                        pass
    if debug:
        partials = list_counts.get("partial", 0)
        fulls = list_counts.get("full", 0)
        print(f"[debug] node partial slabs     : {partials}")
        print(f"[debug] node full slabs        : {fulls}")
        print(f"[debug] node slab pages        : {len(pages)}")
    return pages


def get_full_mode_object_addrs(summary, debug=False):
    """
    Enumerate slab pages from kmem_cache internals, then parse `kmem <page>`
    to recover allocated objects from partial/full slabs.
    """
    if summary is None or not summary.cache_addr:
        return []

    pages = set()
    global_pages = iter_cache_backed_slab_pages(summary, debug=debug)
    if global_pages:
        pages.update(global_pages)
    else:
        cpu_pages = get_cpu_slab_pages(summary.cache_addr, debug=debug)
        node_pages = get_node_slab_pages(summary.cache_addr, debug=debug)
        pages.update(cpu_pages)
        pages.update(node_pages)

    objs = []
    for page_addr in sorted(pages):
        objs.extend(parse_kmem_page_objects(page_addr, debug=debug))

    objs = list(dict.fromkeys(objs))
    if debug:
        print(f"[debug] merged slab pages       : {len(pages)}")
        print(f"[debug] full mode slab pages     : {len(pages)}")
        print(f"[debug] full mode objects found : {len(objs)}")
    return objs

def buf_pages_kb(buf, page_size):
    try:
        pages = int(buf.b_page_count)
        return (pages * page_size) // 1024
    except Exception:
        return 0


def estimate_attached_pages(addrs, page_size, top_n=0, debug=False):
    total_kb = 0
    counted = 0
    tops = []

    for a in addrs:
        try:
            buf = readSU("struct xfs_buf", a)
        except Exception as e:
            if debug:
                print(f"[debug] readSU(struct xfs_buf, 0x{a:x}) failed: {e}")
            continue
        kb = buf_pages_kb(buf, page_size)
        total_kb += kb
        counted += 1
        if top_n:
            tops.append((kb, a))

    if top_n:
        tops.sort(reverse=True)
    return total_kb, counted, tops


def estimate_xfsbuf_fast(cache_name, page_size, top_n=0, debug=False):
    summary = get_cache_summary(cache_name, debug=debug)
    addrs = parse_kmem_S_objects(cache_name, debug=debug)
    total_kb, counted, tops = estimate_attached_pages(
        addrs, page_size, top_n=top_n, debug=debug
    )

    complete = bool(summary and counted == summary.allocated)
    note = None
    if summary and counted < summary.allocated:
        note = ("kmem -S did not enumerate all allocated objects; "
                "attached-page estimate is a lower bound.")

    return EstimateResult(
        mode="fast",
        summary=summary,
        page_size=page_size,
        addrs=addrs,
        counted=counted,
        total_kb=total_kb,
        tops=tops,
        complete=complete,
        note=note,
    )


def estimate_xfsbuf_full(cache_name, page_size, top_n=0, debug=False):
    """
    Walk kmem_cache CPU/node slab pages and parse each slab page with `kmem`.
    This is slower than `kmem -S`, but can include FULL slabs when the kernel
    exposes them via kmem_cache_node lists.
    """
    summary = get_cache_summary(cache_name, debug=debug)
    addrs = get_full_mode_object_addrs(summary, debug=debug)
    total_kb, counted, tops = estimate_attached_pages(
        addrs, page_size, top_n=top_n, debug=debug
    )

    complete = bool(summary and counted == summary.allocated)
    note = None
    if summary and counted < summary.allocated:
        note = ("Full mode still did not recover every allocated object; "
                "some slabs may not be reachable from the exposed cache lists.")

    return EstimateResult(
        mode="full",
        summary=summary,
        page_size=page_size,
        addrs=addrs,
        counted=counted,
        total_kb=total_kb,
        tops=tops,
        complete=complete,
        note=note,
    )


def print_summary(result, debug=False):
    summary = result.summary
    combined_kb = result.total_kb + (summary.live_payload_kb if summary else 0)

    print("-" * 60)
    print("XFS buffer cache summary")
    if summary:
        print(f"Objects allocated      : {yellow(summary.allocated)}")
    print(f"Objects parsed         : {yellow(result.counted)}")
    if summary:
        print(f"Object size            : {summary.objsize} B")
        print(f"Slab footprint         : {cyan(f'{summary.slab_footprint_kb/1024:.2f} MiB')}   (xfs_buf slab pages)")
        print(f"Object payload         : {cyan(f'{summary.live_payload_kb/1024:.2f} MiB')}   (allocated struct xfs_buf)")
    label = "Buffer pages"
    if not result.complete:
        label = "Buffer pages (partial)"
    print(f"{label:<23}: {green(f'{result.total_kb/1024:.2f} MiB')}   (sum of b_page_count * PAGE_SIZE)")
    if summary:
        total_label = "Combined estimate"
        if not result.complete:
            total_label = "Combined estimate*"
        print(f"{total_label:<23}: {green(f'{combined_kb/1024:.2f} MiB')}   (object payload + buffer pages)")
    print("-" * 60)
    if result.note:
        print(f"Note: {result.note}")
    if debug:
        print(f"[debug] mode                  : {result.mode}")
        print(f"[debug] PAGE_SIZE             : {cyan(result.page_size)}")
        print(f"[debug] enumerated addresses  : {len(result.addrs)}")

def main():
    ap = argparse.ArgumentParser(description="Estimate XFS buffer cache usage via slab enumeration")
    ap.add_argument("-d", "--debug", action="store_true", help="debug logging")
    ap.add_argument("--top", type=int, default=0, help="show top-N largest buffers")
    ap.add_argument(
        "--mode",
        choices=("fast", "full"),
        default="fast",
        help="fast=kmem -S lower-bound estimate, full=slab page walk",
    )
    args = ap.parse_args()
    page_size = get_page_size(debug=args.debug)

    cache = find_xfs_buf_cache_name(debug=args.debug)
    if not cache:
        print("No xfs_buf-like slab cache found (checked `kmem -s list`). "
              "This kernel may not expose xfs_buf via a named slab cache.")
        return

    try:
        if args.mode == "full":
            result = estimate_xfsbuf_full(cache, page_size, top_n=args.top, debug=args.debug)
        else:
            result = estimate_xfsbuf_fast(cache, page_size, top_n=args.top, debug=args.debug)
    except NotImplementedError as e:
        print(str(e))
        return

    if result.summary is None:
        print(f"Failed to parse slab summary for '{cache}' via `kmem -s {cache}`.")
        return

    if not result.addrs and args.mode == "fast":
        print(f"Slab cache '{cache}' has no enumerated objects via `kmem -S`. "
              "Cannot estimate attached XFS buffer pages in fast mode.")
        return
    if not result.addrs and args.mode == "full":
        print(f"Full mode could not recover slab pages for '{cache}'. "
              "This kernel may not expose enough kmem_cache internals.")
        return

    print_summary(result, debug=args.debug)

    if args.top and result.tops:
        print(f"Top {args.top} buffers (by size):")
        for kb, a in result.tops[:args.top]:
            print(f"  {kb:>12} KiB   0x{a:x}")

if __name__ == "__main__":
    main()
