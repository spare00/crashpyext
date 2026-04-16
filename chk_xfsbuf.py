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

  Full mode (planned):
    Walk slab internals directly so FULL slabs are included too.
"""

import argparse
import re
from pykdump.API import *
from LinuxDump import crash

DEFAULT_PAGE_SIZE = 4096


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

def get_page_size(debug=False):
    """Derive PAGE_SIZE from `sys` output, falling back to 4 KiB."""
    try:
        out = exec_crash_command("sys")
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
    Placeholder for a future slab-internal walk that includes FULL slabs.
    """
    raise NotImplementedError(
        "Full mode is not implemented yet; use the default fast mode for now."
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
        help="fast=kmem -S lower-bound estimate, full=slab walk (planned)",
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

    print_summary(result, debug=args.debug)

    if args.top and result.tops:
        print(f"Top {args.top} buffers (by size):")
        for kb, a in result.tops[:args.top]:
            print(f"  {kb:>12} KiB   0x{a:x}")

if __name__ == "__main__":
    main()
