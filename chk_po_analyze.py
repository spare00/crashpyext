#!/usr/bin/env python3
# analyze_po.py — Analyze page_owner NDJSON exported from chk_export_po.py
# Crash-only symbolization via `sym -l` using pykdump.API (preferred) or pykdump (fallback).
#
# Supported records:
#   RHEL7 inline traces: {"k":"r7","pfn":..., "o":order, "g":gfp, "t":[addr,...]}
#   RHEL8+ depot:        {"k":"r8","pfn":..., "o":order, "g":gfp, "h":handle, ["pid":pid]}
#
# CLI:
#   [-h] [-v] [-d] [-M] [-K] [-G] [-p] [-m] [-s] [-c] [-t]
#   [--calltrace-process PID] [--filter-module MOD] [--strict]
#   [--detect-lines N] file
#
import argparse
from collections import defaultdict, Counter, OrderedDict
import time, os

# ---- logging/time helpers ----
import sys, time, os, re, json
from typing import List, Tuple, Optional

def log(msg: str):
    print(msg, file=sys.stderr, flush=True)

def hms(sec: float) -> str:
    h = int(sec // 3600); m = int((sec % 3600) // 60); s = int(sec % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

# Canonical kernel-text check (RHEL7+)
def is_kernel_text64(a: int) -> bool:
    # accept ffffffffXXXXXXXX, reject -1 sentinel
    return (a >> 32) == 0xFFFFFFFF and a != 0xFFFFFFFFFFFFFFFF

# Sym parsing regexes (shared)
ADDRLINE_RE = re.compile(r'^\s*(ffffffff[0-9A-Fa-f]{8})\s+(?:\(\w\)\s+)?(.+?)\s*$')
RHS_RE      = re.compile(r'^(?P<sym>[^\s]+(?:\s+\[[^\]]+\])?)(?:\s+/.+?:\s*\d+)?\s*$')

def rhs_from_sym_line(line: str) -> str:
    """Return 'name+off[/size] [mod]' from a `sym` output line, drop trailing src:line."""
    if not line:
        return ""
    m = ADDRLINE_RE.match(line)
    rhs = m.group(2) if m else line.strip()
    m2 = RHS_RE.match(rhs)
    return m2.group("sym") if m2 else rhs

def _fmt_hms(sec: float) -> str:
    h = int(sec // 3600); m = int((sec % 3600) // 60); s = int(sec % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

def _file_size(path: str) -> int:
    try: return os.path.getsize(path)
    except Exception: return 0

def _file_pos(f) -> int:
    # Prefer the raw byte position of the underlying buffer
    try:
        buf = getattr(f, "buffer", None)
        if buf is not None: return buf.tell()
    except Exception:
        pass
    try: return f.tell()
    except Exception: return 0

def _fmt_dur(sec: float) -> str:
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    ms = int((sec - int(sec))*1000)
    return f"{h:02d}:{m:02d}:{s:02d}.{ms:03d}"

# -------- crash symbolization (pykdump.API first) --------
_HAS_CRASH = False
_CRASH_IMPORT_ERROR = None
_CRASH_PROBE = None
_crash_x = None  # exec_crash_command callable

def _try_import_crash(debug=False):
    """Prefer pykdump.API; fall back to pykdump."""
    global _HAS_CRASH, _CRASH_IMPORT_ERROR, _crash_x
    try:
        from pykdump.API import exec_crash_command as _exec
        _crash_x = _exec
        _HAS_CRASH = True
        if debug:
            print("[debug] using pykdump.API.exec_crash_command", file=sys.stderr)
        return
    except Exception as e_api:
        # fall back to legacy location
        try:
            from pykdump import exec_crash_command as _exec
            _crash_x = _exec
            _HAS_CRASH = True
            if debug:
                print("[debug] using pykdump.exec_crash_command (fallback)", file=sys.stderr)
            return
        except Exception as e_base:
            _HAS_CRASH = False
            _CRASH_IMPORT_ERROR = f"pykdump.API: {repr(e_api)} ; pykdump: {repr(e_base)}"
            _crash_x = None

def _probe_crash_env(debug=False):
    """Verify we can actually talk to crash."""
    global _HAS_CRASH, _CRASH_PROBE
    if not _HAS_CRASH or _crash_x is None:
        if debug and _CRASH_IMPORT_ERROR:
            print(f"[debug] pykdump import failed: {_CRASH_IMPORT_ERROR}", file=sys.stderr)
        return
    try:
        out = _crash_x("sys")
        _CRASH_PROBE = "\n".join(out.splitlines()[:3]) if isinstance(out, str) else str(out)[:200]
        _HAS_CRASH = True
        if debug:
            print("[debug] crash probe OK; first lines of `sys`:", file=sys.stderr)
            print(_CRASH_PROBE, file=sys.stderr)
    except Exception as e:
        _HAS_CRASH = False
        _CRASH_PROBE = f"probe error: {repr(e)}"
        if debug:
            print(f"[debug] crash probe failed: {_CRASH_PROBE}", file=sys.stderr)

def _is_kernel_addr(a: int) -> bool:
    return (a & 0xffff000000000000) == 0xffff000000000000

import re

# ---- robust symbol helpers using plain `sym <addr>` ----

_ADDRLINE_RE = re.compile(r'^\s*(ffffffff[0-9A-Fa-f]{8})\s+(?:\(\w\)\s+)?(.+?)\s*$')
# RHS parser: keep "name+off[/size]" and optional "[module]" only; drop trailing " /path: line"
_RHS_RE = re.compile(r'^(?P<sym>[^\s]+(?:\s+\[[^\]]+\])?)(?:\s+/.+?:\s*\d+)?\s*$')

def _sym_one_line(addr: int) -> str:
    """Return the line from `sym <addr>` that starts with a 16-hex address."""
    if addr == 0 or addr == 0xffffffffffffffff:
        return ""
    try:
        out = _crash_x(f"sym {addr:#x}")  # plain `sym` works best on your build
    except Exception:
        print("error")
        return ""
    if not isinstance(out, str):
        out = str(out)
    out = out.replace("\x00", "")  # sanitize any NULs
    for ln in out.splitlines():
        ln = ln.rstrip("\r\n")
        if _ADDRLINE_RE.match(ln):
            return ln
    # fallback: return first non-empty line
    for ln in out.splitlines():
        if ln.strip():
            return ln.strip()
    return ""

def _rhs_from_sym_line(line: str) -> str:
    """
    From a `sym <addr>` line, extract 'name+off[/size]' plus optional ' [module]'.
    Strip trailing source path and line numbers if present.
    """
    if not line:
        return ""
    m = _ADDRLINE_RE.match(line)
    rhs = m.group(2) if m else line  # everything after address & optional (X)
    m2 = _RHS_RE.match(rhs)
    return m2.group("sym") if m2 else rhs

def _display_for_addr(addr: int) -> str:
    """Render: [<ffffffff...>] name+off[/size] [module]."""
    if addr == 0xffffffffffffffff:
        return "[<ffffffffffffffff>] 0xffffffffffffffff"
    line = _sym_one_line(addr)
    rhs  = _rhs_from_sym_line(line) or f"{addr:#x}"
    hex_ = f"{addr:#x}"[2:]
    return f"[<{hex_}>] {rhs}"

# Accept only canonical kernel/module text addresses: ffffffffXXXXXXXX (16 hex, leading 8 'f')
def _is_kernel_text_addr(addr: int) -> bool:
    try:
        a = int(addr)
    except Exception:
        return False
    return (a >> 32) == 0xFFFFFFFF and a != 0xFFFFFFFFFFFFFFFF

# --- Heuristics: allocator detection (broad) and module-local alloc-likes ---

ALLOCATOR_FUNC_RE = re.compile(
    r'\b('
    # page allocator family
    r'__alloc_pages(?:_nodemask|_slowpath)?|alloc_pages(?:_current|_mpol)?|alloc_page_interleave|'
    r'__get_free_pages|'
    # page cache / folio family
    r'__page_cache_alloc|page_cache_alloc|pagecache_get_page|filemap_alloc_folio|'
    r'folio_alloc(?:_node|_nocma|_noprof)?|'
    # slab / kmalloc family
    r'kmem_cache_(?:alloc|zalloc)(?:_node)?|'
    r'k(?:m|vz|vm)alloc(?:_node)?|kzalloc(?:_node)?|kmalloc(?:_node)?|kvzalloc|kvmalloc|'
    r'kmalloc_array|kcalloc|__kmalloc(?:_node|_track_caller)?|'
    r'(?:__)?slab_alloc|___slab_alloc|allocate_slab|'
    # vmalloc
    r'__vmalloc|vmalloc|vzalloc|vmap|'
    # DMA / networking
    r'dma_alloc_[a-z_]*|'
    r'__alloc_skb|alloc_skb|__netdev_alloc_skb|napi_alloc_skb|netdev_alloc_skb|'
    r'page_frag_alloc|skb_page_frag_refill'
    r')\b',
    re.IGNORECASE
)

SLAB_ALLOCATOR_FUNC_RE = re.compile(
    r'\b('
    r'kmem_cache_(?:alloc|zalloc)(?:_node)?|'
    r'k(?:m|vz|vm)alloc(?:_node)?|kzalloc(?:_node)?|kmalloc(?:_node)?|'
    r'kmalloc_array|kcalloc|'
    r'__kmalloc(?:_node|_track_caller)?|'
    r'(?:__)?slab_alloc|___slab_alloc|allocate_slab'
    r')\b',
    re.IGNORECASE
)

# Module-local names that *look* like allocators (to credit a module even if we missed the generic wrapper)
MODULE_ALLOC_LIKE_RE = re.compile(
    r'(?<![A-Za-z0-9])('
    r'alloc|getblk|new(?:_|$)|buf(?:_|$)|reserve|grow|page(?:s)?_get|vm_alloc'
    r')(?![A-Za-z0-9])',
    re.IGNORECASE
)

def _symbol_base(rhs: str) -> str:
    """Return the function token from a pretty frame 'func+off[/size] [mod]'. """
    return rhs.split()[0] if rhs else ""

def _frame_mod(rhs: str):
    """Return module name from a pretty frame (or None)."""
    if rhs and rhs.endswith(']') and '[' in rhs:
        return rhs[rhs.rfind('[')+1:-1]
    return None

def _module_from_frames_rhs(rhs_list, strict=False):
    """
    Attribute memory to a module from pretty frames (strings), with heuristics:
      1) Find the first frame that matches ALLOCATOR_FUNC_RE; then return the
         first module-tagged frame *after* it.
      2) If not found, return the first module-tagged frame that also matches
         MODULE_ALLOC_LIKE_RE (e.g., vx_alloc, getblk, new_*).
      3) If still not found and not strict, return the first module-tagged frame.
      4) Else None -> count to (kernel).
    """
    # 1) arm on first allocator
    saw_alloc = False
    for rhs in rhs_list:
        base = _symbol_base(rhs)
        if not saw_alloc and ALLOCATOR_FUNC_RE.search(base):
            saw_alloc = True
            continue
        if saw_alloc:
            mod = _frame_mod(rhs)
            if mod:
                return mod

    # 2) module-local alloc-like name
    for rhs in rhs_list:
        mod = _frame_mod(rhs)
        if not mod:
            continue
        base = _symbol_base(rhs)
        if MODULE_ALLOC_LIKE_RE.search(base):
            return mod

    # 3) first module frame (unless strict)
    if not strict:
        for rhs in rhs_list:
            mod = _frame_mod(rhs)
            if mod:
                return mod

    # 4) give up
    return None

# --- Call-trace rendering helpers ---
def _dis_line(addr: int) -> str:
    """Fallback: first line of `dis -l <addr> 1` or empty string."""
    if addr == 0 or addr == 0xffffffffffffffff:
        return ""
    try:
        out = _crash_x(f"dis -l {addr:#x} 1")
        return out.strip().splitlines()[0] if isinstance(out, str) and out.strip() else ""
    except Exception:
        return ""

def _parse_sym_line(line: str):
    """
    Parse `sym -l` one-liner robustly.
    Examples:
      'ffffffffadfcb391 __alloc_pages_nodemask+0x12d/0x2c0'
      'ffffffffc1aca591 (t) vx_do_read_ahead+0x1c8 [vxfs]'
    Returns (name+offset/size, module|None)
    """
    if not line:
        return (None, None)
    toks = line.split()
    if len(toks) < 2:
        return (None, None)
    i = 1
    if i < len(toks) and toks[i].startswith("("):  # skip '(t)' etc.
        i += 1
    if i >= len(toks):
        return (None, None)
    name = toks[i]
    mod = None
    for t in toks[i+1:]:
        if t.startswith("[") and t.endswith("]"):
            mod = t.strip("[]")
            break
    return (name, mod)

class CrashSym:
    """Symbolize via `sym -l` with a small LRU cache."""
    def __init__(self, max_entries=4096):
        self.max = max_entries
        self.cache = OrderedDict()

    def _parse_one_line(self, txt: str):
        ln = txt.strip().splitlines()[0] if isinstance(txt, str) and txt.strip() else ""
        if not ln:
            return (None, None)
        m = re.search(r'([A-Za-z0-9_\.]+)(?:\+0x[0-9a-fA-F]+(?:/[0-9a-fA-Fx]+)?)?(?:\s+\[([^\]]+)\])?\s*$', ln)
        if not m:
            return (None, None)
        return (m.group(1), m.group(2))

    def lookup(self, addr: int):
        key = int(addr) & ((1<<64)-1)
        hit = self.cache.get(key)
        if hit is not None:
            self.cache.move_to_end(key)
            return hit
        name = mod = None
        if _HAS_CRASH and _crash_x is not None and _is_kernel_addr(key):
            try:
                out = _crash_x(f"sym -l {key:#x}")
                name, mod = self._parse_one_line(out)
            except Exception:
                name = mod = None
        self.cache[key] = (name, mod)
        if len(self.cache) > self.max:
            self.cache.popitem(last=False)
        return (name, mod)

SYM = CrashSym()

def fmt_addr_with_sym(addr: int) -> str:
    s = f"{addr:#x}"
    name, mod = SYM.lookup(addr)
    if name:
        base = name.split("+")[0]
        return f"{s}  {base}" + (f" [{mod}]" if mod else "")
    return s

# ----- Frame rendering helpers for grouping/printing -----

def _sym_first_line(addr: int) -> str:
    """Return the first line of `sym -l <addr>` or empty string on failure."""
    try:
        out = _crash_x(f"sym -l {addr:#x}")
        return out.strip().splitlines()[0] if isinstance(out, str) and out.strip() else ""
    except Exception:
        return ""

_sym_rhs_re = re.compile(
    r'^\s*(?:0x)?[0-9a-fA-F]+(?:\s+\(\w\))?\s*(.*)$'
)

def _frame_rhs(addr: int) -> str:
    """
    The canonical RHS for signature grouping, e.g.:
      '__alloc_pages_nodemask+0x12d/0x2c0'
      'vx_write+0x1e7/0x3b0 [vxfs]'
    """
    if addr == 0xffffffffffffffff:
        return "0xffffffffffffffff"
    line = _sym_first_line(addr)
    if not line:
        return f"{addr:#x}"
    m = _sym_rhs_re.match(line)
    return m.group(1) if m and m.group(1) else line

def _frame_display(addr: int) -> str:
    """
    Pretty, user-facing frame line:
      [<ffffffff86e25ab8>] alloc_pages_current+0x98/0x110
      [<ffffffffc0bb4e67>] vx_write+0x1e7/0x3b0 [vxfs]
    """
    if addr == 0xffffffffffffffff:
        return "[<ffffffffffffffff>] 0xffffffffffffffff"
    line = _sym_first_line(addr)
    rhs = _frame_rhs(addr) if line else f"{addr:#x}"
    # show address without "0x" inside the brackets (to match your style)
    hex_ = f"{addr:#x}"[2:]
    return f"[<{hex_}>] {rhs}"

# -------- CLI --------
def make_argparser():
    p = argparse.ArgumentParser(description="Analyze large page_owner file.")
    p.add_argument("file", help="Path to the page_owner file")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("-d", "--debug", action="store_true", help="Debug output")
    p.add_argument("-M", action="store_true", help="Show in MB")
    p.add_argument("-K", action="store_true", help="Show in KB")
    p.add_argument("-G", action="store_true", help="Show in GB")
    p.add_argument("-p", "--processes", action="store_true", help="Process report (varies by mode)")
    p.add_argument("-m", "--modules", action="store_true", help="Show top memory-using modules")
    p.add_argument("-s", "--slabs", action="store_true",
                   help="Show slab usage by process (Type-2 only). With -p, show slab vs non-slab breakdown")
    p.add_argument("-c", "--calltraces", action="store_true",
                   help="Show top 5 call trace patterns")
    p.add_argument("-t", "--total", action="store_true",
                   help="Show only total allocations/memory (with -v, also per-order breakdown)")
    p.add_argument("--calltrace-process", type=int, dest="ct_pid",
                   help="Show call traces only for this process")
    p.add_argument("--filter-module", dest="filter_module",
                   help="Show top processes using this module")
    p.add_argument("--strict", action="store_true",
                   help="Attribute only when a module-tagged frame at/under the first allocator looks allocation-like")
    p.add_argument("--detect-lines", type=int, default=5000,
                   help="Max lines to scan for dump kind detection before full parse (default: 5000)")
    # parser:
    p.add_argument("--top", type=int, default=5, help="Top-N call traces to print (default 5)")
    p.add_argument("--depth", type=int, default=8, help="Frames per call-trace signature (default 8)")
    p.add_argument("--min-order", type=int, default=0, help="Ignore records with order < N")
    p.add_argument("--sample", type=int, default=1, help="Sample every Nth record (default 1)")
    p.add_argument("--sym", action="store_true",
                   help="Allow crash symbolization fallback when enriched fields are missing (default: off)")
    p.add_argument("--progress", type=int, default=200000,
                   help="Print progress every N lines (default 200000; 0 = disable)")
    p.add_argument("--progress-sec", type=float, default=5.0,
                   help="Also print progress at least every N seconds (default 5.0)")
    return p

# -------- Units --------
def _unit_and_div(args):
    if args.G: return ("GB", 1024**3)
    if args.M: return ("MB", 1024**2)
    if args.K: return ("KB", 1024)
    return ("B", 1)

def _fmt_bytes(b, unit, div):
    return f"{(b/float(div)):.2f} {unit}"

# -------- Signature helpers --------
ALLOC_WRAPPERS = {
    "kmalloc_order_trace", "__kmalloc", "kmalloc", "kmalloc_node_trace",
    "kmalloc_large_node", "kzalloc", "kzalloc_node", "vzalloc",
    "__alloc_pages_nodemask", "alloc_pages_nodemask", "alloc_pages_current",
    "get_free_pages", "__get_free_pages", "pagecache_get_page",
    "dma_alloc_attrs", "dma_alloc_coherent",
}

def normalize_signature(addrs, depth=4):
    """Use first up-to-depth non-wrapper labeled frames as signature."""
    sig = []
    for a in addrs:
        if not _is_kernel_addr(a):  # ignore user-space or junk
            continue
        name, mod = SYM.lookup(a)
        label = None
        if name:
            base = name.split("+")[0]
            if base in ALLOC_WRAPPERS:
                continue
            label = base + (f" [{mod}]" if mod else "")
        else:
            label = f"{a:#x}"
        sig.append(label)
        if len(sig) >= depth:
            break
    return tuple(sig)

def first_allocator_module(addrs):
    """Find module right below first allocator wrapper (for --strict attribution)."""
    saw_alloc = False
    for a in addrs:
        if not _is_kernel_addr(a): continue
        name, mod = SYM.lookup(a)
        base = name.split("+")[0] if name else None
        if base in ALLOC_WRAPPERS:
            saw_alloc = True
            continue
        if saw_alloc and mod:
            return (base or f"{a:#x}", mod)
    return (None, None)

# -------- Detection --------
def detect_kind(path, detect_lines):
    r7 = r8 = 0
    with open(path, "r", errors="ignore") as f:
        for i, ln in enumerate(f, 1):
            if i > detect_lines: break
            try:
                o = json.loads(ln)
            except Exception:
                continue
            k = o.get("k")
            if k == "r7": r7 += 1
            elif k == "r8": r8 += 1
    return (r7, r8)

def report_modules_fast(path, unit, div, depth=8, topn=10, strict=False, verbose=False):
    """
    Fast '-m': consume enriched NDJSON ('s':[frames], optional 'mod').
      • Use record['mod'] if present.
      • Else use _module_from_frames_rhs(record['s'][:depth], strict).
      • Else (raw 't' only) → attribute to (kernel) to avoid slow sym.
    """
    by_allocs = {}
    by_pages  = {}
    total_allocs = 0
    total_pages  = 0

    def bump(modname, pages):
        nonlocal total_allocs, total_pages
        if not modname:
            modname = "(kernel)"
        by_allocs[modname] = by_allocs.get(modname, 0) + 1
        by_pages[modname]  = by_pages.get(modname, 0)  + pages
        total_allocs += 1
        total_pages  += pages

    with open(path, "r", errors="ignore") as f:
        for ln in f:
            if not ln or ln[0] != "{":
                continue
            try:
                o = json.loads(ln)
            except Exception:
                continue

            order = int(o.get("o", 0))
            if order < 0 or order > 20:
                continue
            pages = 1 << order

            # 1) explicit module tag from enrichment phase
            mod = o.get("mod")
            if mod:
                bump(mod, pages)
                continue

            # 2) pretty frames present → infer module locally (no sym)
            rhs_list = o.get("s")
            if rhs_list:
                mod = _module_from_frames_rhs(rhs_list[:depth], strict=strict)
                bump(mod, pages)
                continue

            # 3) raw PCs → we intentionally DO NOT symbolize here
            bump("(kernel)", pages)

    # print Top-N
    print("\nModule                       Allocations     Memory (G)")
    print("=======================================================")
    top = sorted(by_pages.items(), key=lambda kv: (-kv[1], kv[0]))[:max(1, topn)]
    for mod, pages in top:
        bytes_ = pages * 4096
        print(f"{mod:<30}{by_allocs.get(mod,0):>12}{bytes_/(1024**3):>15.2f}")
    print("=======================================================")
    print(f"Total{ '':<27}{total_allocs:>12}{(total_pages*4096)/(1024**3):>15.2f} GB")

# -------- Core analysis --------
def _valid_stack_for_print(addrs):
    pcs = [a for a in addrs if a and a != 0xffffffffffffffff]
    if not pcs:
        return False
    # must have at least one kernel-text PC and not all __per_cpu_start
    any_text = False; all_percpu = True
    for a in pcs[:8]:
        line = _crash_x(f"sym -l {a:#x}").strip()
        if line:
            any_text = True
            if not line.endswith("__per_cpu_start"):
                all_percpu = False
    return any_text and not all_percpu

def analyze(path, args):
    start_ts = time.perf_counter()
    total_size = _file_size(path)
    try:
        total_size = os.path.getsize(path)
    except Exception:
        total_size = 0

    unit, div = _unit_and_div(args)

    order_pages = defaultdict(int)
    total_pages = 0
    total_bytes = 0

    # PID-based (RHEL8+)
    per_pid_pages = defaultdict(int)
    per_pid_bytes = defaultdict(int)

    # Module-based
    per_module_pages = defaultdict(int)
    per_module_bytes = defaultdict(int)
    per_pid_module_bytes = defaultdict(int)  # (pid,module) -> bytes

    # Signatures (RHEL7 traces)
    sig_pages = Counter()
    sig_rep = {}

    # ---- before the read loop in analyze() add these counters ----
    # Exact call-trace signatures keyed by raw address tuples (fast, no sym during pass 1)
    sig_addr_bytes   = defaultdict(int)   # tuple(addrs[:DEPTH]) -> total bytes
    sig_addr_seen    = defaultdict(int)   # tuple(addrs[:DEPTH]) -> number of occurrences
    sig_addr_example = {}                 # tuple(addrs[:DEPTH]) -> exemplar full addrs (list) to print

    # in analyze(), replace constants and apply filters:
    DEPTH = max(1, int(args.depth))
    TOPN  = max(1, int(args.top))

    # Calltrace signature aggregators (prefer enriched frames 's')
    sig_key_counts = Counter()   # tuple[str] -> count
    sig_key_bytes  = Counter()   # tuple[str] -> total bytes
    sig_key_sample = {}          # tuple[str] -> exemplar list[str]

    with open(path, "r", errors="ignore") as f:
        lines_read = 0
        last_log_ts = start_ts
        for ln in f:
            lines_read += 1

            # periodic progress
            if args.progress or args.progress_sec > 0:
                do_log = False
                if args.progress and (lines_read % args.progress == 0):
                    do_log = True
                else:
                    now = time.perf_counter()
                    if args.progress_sec > 0 and (now - last_log_ts) >= args.progress_sec:
                        do_log = True
                if do_log:
                    pos = _file_pos(f)
                    elapsed = time.perf_counter() - start_ts
                    rate = lines_read / elapsed if elapsed > 0 else 0.0

                    pct_str = "   n/a"
                    eta_str = "   n/a"
                    if total_size > 0 and pos > 0:
                        pct = (pos / total_size) * 100.0
                        pct_str = f"{pct:5.1f}%"
                        if pos < total_size and rate > 0:
                            # ETA based on byte-rate when possible
                            byte_rate = pos / elapsed if elapsed > 0 else 0.0
                            if byte_rate > 0:
                                eta = (total_size - pos) / byte_rate
                                eta_str = _fmt_hms(eta)

                    print(
                        f"[analyze] {lines_read:,} lines  {pct_str}  "
                        f"elapsed {_fmt_hms(elapsed)}  rate {rate:,.0f}/s  ETA {eta_str}",
                        file=sys.stderr, flush=True
                    )
                    last_log_ts = time.perf_counter()

            if not ln or ln[0] != "{":
                continue
            try:
                o = json.loads(ln)
            except Exception:
                if args.debug: print("[debug] skip non-json line", file=sys.stderr)
                continue

            kind = o.get("k")
            order = int(o.get("o", 0))
            # inside loop:
            if args.sample > 1:
                # cheap sampler: use incrementing line index or a hash of PFN/order to subsample
                # e.g., skip N-1 out of N lines uniformly by count
                # (keep a simple counter outside the loop)
                pass  # implement if you want

            if order < args.min_order:
                continue

            pages = 1 << order
            bytes_ = pages * 4096  # exporter’s default (x86_64)

            total_pages += pages
            total_bytes += bytes_
            order_pages[order] += pages

            pid = int(o.get("pid", 0)) if (kind == "r8" and "pid" in o) else None
            if pid:
                per_pid_pages[pid] += pages
                per_pid_bytes[pid] += bytes_

            # RHEL7 traces → signatures
            # Signatures (prefer enriched frames 's')
            rhs_list = o.get("s")
            if rhs_list:
                key = tuple(rhs_list[:DEPTH])
                if key:
                    sig_key_counts[key] += 1
                    sig_key_bytes[key]  += bytes_
                    sig_key_sample.setdefault(key, rhs_list[:DEPTH])
            elif args.sym and kind == "r7":
                # optional crash fallback if user allowed
                addrs = [a for a in (o.get("t") or []) if _is_kernel_addr(a)]
                if addrs:
                    key = tuple(_frame_rhs(a) for a in addrs[:DEPTH])  # uses crash
                    if key:
                        sig_key_counts[key] += 1
                        sig_key_bytes[key]  += bytes_
                        sig_key_sample.setdefault(key, list(key))

            # Modules (best-effort when inline PCs exist)
            if args.modules or args.filter_module or args.strict:
                mod = o.get("mod")
                if not mod:
                    rhs_list = o.get("s")  # enriched frames
                    if rhs_list:
                        mod = _module_from_frames_rhs(rhs_list[:DEPTH], strict=args.strict)
                    elif args.sym and kind == "r7":
                        # only if user allowed crash fallback AND no enriched frames
                        addrs = [a for a in (o.get("t") or []) if _is_kernel_addr(a)]
                        if addrs:
                            if args.strict:
                                _, mod = first_allocator_module(addrs)
                            else:
                                # first module frame via crash, as last resort
                                for a in addrs:
                                    name, m = SYM.lookup(a)
                                    if m:
                                        mod = m; break
                if mod:
                    per_module_pages[mod] += pages
                    per_module_bytes[mod] += bytes_
                    if pid:
                        per_pid_module_bytes[(pid, mod)] += bytes_

    # ---- Reporting ----
    if args.total or (not any([args.processes, args.modules, args.slabs, args.calltraces])):
        print("=== Totals ===")
        print(f"Total pages : {total_pages}")

        kb = total_bytes / 1024
        gb = total_bytes / (1024**3)
        print(f"Total bytes : {kb:,} kB   ({gb:.2f} GB)")
        if args.verbose:
            print("\nPer-order pages:")
            for o in sorted(order_pages):
                per_b = (1 << o) * 4096
                tot_b = order_pages[o] * 4096
                print(f"  order {o:<2} : pages={order_pages[o]:>12}  bytes/page={per_b:<8} total={_fmt_bytes(tot_b, unit, div)}")

    if args.processes:
        print("\n=== Processes (by total bytes) ===")
        if not per_pid_bytes:
            print("(no pid information in file; likely RHEL7 export)")
        else:
            top = sorted(per_pid_bytes.items(), key=lambda kv: kv[1], reverse=True)
            for pid, b in top:
                print(f"PID {pid:<7}  bytes={b:>12} ({_fmt_bytes(b, unit, div)})  pages={per_pid_pages[pid]}")
            if args.filter_module and per_pid_module_bytes:
                mod = args.filter_module
                print(f"\n--- Top processes using module '{mod}' ---")
                filt = [(pid, b) for ((pid, m), b) in per_pid_module_bytes.items() if m == mod]
                filt.sort(key=lambda x: x[1], reverse=True)
                for pid, b in filt[:20]:
                    print(f"PID {pid:<7}  bytes={b:>12} ({_fmt_bytes(b, unit, div)})")

    if args.modules:
        print("\n=== Modules (by total bytes) ===")
        unit, div = _unit_and_div(args)
        # default Top-10; strict=False unless you want to be conservative
        report_modules_fast(args.file, unit, div, depth=8, topn=10, strict=args.strict, verbose=args.debug)
        return

    if args.slabs:
        print("\n=== Slabs ===")
        print("(slab vs non-slab classification not exported; not available)")

    if args.calltraces:
        print("\nTop 5 Call Traces:")
        print("=" * 50)
        if not sig_key_bytes:
            print("(no enriched frames; re-run with --sym to allow crash symbolization fallback)")
        else:
            top = sorted(sig_key_bytes.items(), key=lambda kv: kv[1], reverse=True)[:TOPN]
            for rank, (sig_key, tot_b) in enumerate(top, 1):
                seen = sig_key_counts.get(sig_key, 0)
                gb = tot_b / float(1024**3)
                print(f"#{rank}: Seen {seen} times, {gb:.2f} GB")
                for rhs in sig_key_sample.get(sig_key, sig_key):
                    print(rhs if rhs.startswith("[<") or "+" in rhs or " [" in rhs else str(rhs))
                print("-" * 50)

    # Final timing
    log(f"[analyze] DONE in {hms(time.perf_counter() - start_ts)}")

def main():
    ap = make_argparser()
    args = ap.parse_args()

    # Only initialize crash if user asked for it
    if args.sym:
        _try_import_crash(debug=args.debug)
        _probe_crash_env(debug=args.debug)
    else:
        # Ensure symbolization paths treat crash as unavailable
        globals()['_HAS_CRASH'] = False
        globals()['_crash_x'] = None
        if args.debug:
            print("[debug] --sym not set: analysis will avoid crash symbolization and prefer enriched fields.", file=sys.stderr, flush=True)

    if not _HAS_CRASH:
        msg = "[warn] Crash/pykdump API not available; symbolization will be minimal."
        if args.debug and _CRASH_IMPORT_ERROR:
            msg += f" (import: {_CRASH_IMPORT_ERROR}; probe: {_CRASH_PROBE})"
        print(msg, file=sys.stderr)
    elif args.debug:
        print("[debug] crash/epython detected; using `sym -l` for symbolization.", file=sys.stderr)
        try:
            test = _crash_x("sym schedule")
            print(f"[debug] `sym schedule` -> {test.strip().splitlines()[0]}", file=sys.stderr)
        except Exception as e:
            print(f"[debug] `sym schedule` failed: {repr(e)}", file=sys.stderr)

    if args.debug:
        print(f"[debug] analyzing: {args.file}", file=sys.stderr)

    r7, r8 = detect_kind(args.file, args.detect_lines)
    if args.verbose:
        print(f"[info] detected records (first {args.detect_lines} lines): RHEL7={r7} RHEL8+={r8}")

    analyze(args.file, args)

if __name__ == "__main__":
    main()

