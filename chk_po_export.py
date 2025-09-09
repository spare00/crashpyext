#!/usr/bin/env python3
# Fast page_owner exporter for crash/epython (RHEL7/8/9, x86_64).
# Uses pykdump.API, precomputes offsets once, and reads memory directly (no per-page 'p'/'sym').
#
# Output (NDJSON):
#   RHEL7: {"k":"r7","pfn":..., "o":order, "g":gfp_mask, "t":[pc0,...]}
#   RHEL8+:{"k":"r8","pfn":..., "o":order, "g":gfp_mask, "h":handle, ["pid":pid]}
#
# Usage:
#   crash> extend -p chk_export_po.py
#   crash> chk_export_po --out /tmp/page_owner.ndjson --state /tmp/po.state --progress 200000
#
import argparse, json, re, sys, os, struct

# -------- crash API (pykdump.API only) --------
from pykdump.API import exec_crash_command as crash_x, readSU, readmem

def x(cmd: str) -> str:
    return crash_x(cmd)

# -------- constants / config --------
DEFAULT_PPS = 0x8000     # pages per section (x86_64)
PAGE_SIZE   = 4096
MAX_INLINE_TRACE = 8
PLAUSIBLE_MAX_ORDER = 20

# -------- small helpers --------
def _find_hex(s: str):
    m = re.search(r'0x[0-9a-fA-F]+', s)
    if m: return int(m.group(0), 16)
    m = re.search(r'\b([0-9A-Fa-f]{8,})\b', s)
    return int(m.group(1), 16) if m else None

def _offsetof(expr: str) -> int:
    # Example: "&(((struct page_cgroup *)0)->ext.owner)"
    out = x(f"p {expr}")
    a = _find_hex(out)
    if a is None:
        raise RuntimeError(f"could not compute offset for: {expr}\n{out}")
    return a  # gdb prints this as an absolute offset from 0

def _u64_le(b: bytes) -> int:
    return struct.unpack("<Q", b)[0]

def _u32_le(b: bytes) -> int:
    return struct.unpack("<I", b)[0]

def _rd64(addr: int) -> int:
    return _u64_le(readmem(addr, 8))

def _rd32(addr: int) -> int:
    return _u32_le(readmem(addr, 4))

def _parse_int_auto(tok: str) -> int:
    """Parse ints that may be decimal, 0x-prefixed, or bare hex (kmem -n style)."""
    s = tok.strip().lower()
    # strip punctuation some crash builds add (rare)
    s = s.strip(",")
    if s.startswith("0x"):
        return int(s, 16)
    if re.fullmatch(r"[0-9a-f]+", s):
        return int(s, 16)
    return int(s, 10)

# -------- section parsing --------
class SectionRow(object):
    __slots__ = ("nr","addr","pfn_base")
    def __init__(self, nr, addr, pfn_base):
        self.nr = nr; self.addr = addr; self.pfn_base = pfn_base

_SECTIONS = None
def _parse_kmem_n_sections_once():
    global _SECTIONS
    if _SECTIONS is not None:
        return _SECTIONS
    out = x("kmem -n")
    rows = []
    in_table = False
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("NR") and "SECTION" in s and "PFN" in s:
            in_table = True
            continue
        if not in_table:
            continue
        if (not s) or s.startswith("---") or s.startswith("MEM_BLOCK") or s.startswith("ZONE") or s.startswith("NODE"):
            if rows:
                break
            else:
                continue

        toks = re.split(r"\s+", s)
        try:
            nr = int(toks[0], 10)
            sec_addr = _parse_int_auto(toks[1])   # <— changed
            pfn_base = _parse_int_auto(toks[-1])  # <— changed
        except Exception:
            m = re.match(r"^(\d+)\s+([0-9A-Fa-fx]+)\s+.*?([0-9A-Fa-fx]+)\s*$", s)
            if not m:
                continue
            nr = int(m.group(1), 10)
            sec_addr = _parse_int_auto(m.group(2))  # <— changed
            pfn_base = _parse_int_auto(m.group(3))  # <— changed

        rows.append(SectionRow(nr, sec_addr, pfn_base))

    if not rows:
        raise RuntimeError("Could not parse sections from 'kmem -n'.")
    rows.sort(key=lambda r: r.pfn_base)
    _SECTIONS = rows
    return rows

def _sections_slice(range_str: str):
    rows = _parse_kmem_n_sections_once()
    if not range_str:
        return rows
    a, b = [s.strip() for s in range_str.split(":", 1)]
    lo = int(a, 0); hi = int(b, 0)
    sel = [r for r in rows if lo <= r.nr <= hi]
    if not sel:
        raise RuntimeError(f"No sections in requested range {lo}:{hi}")
    return sel

# -------- page_cgroup / page_owner offsets (computed once) --------
_OFF = {
    "pc_owner": None,   # offsetof(struct page_cgroup, ext.owner)
    "pc_flags": None,   # offsetof(struct page_cgroup, ext.flags)
    "pc_handle": None,  # offsetof(struct page_cgroup, ext.handle) -- RHEL8+
    "pc_pid": None,     # optional pid/tgid field if present
    "po_order": None,   # offsetof(struct page_owner, order)
    "po_gfp": None,     # offsetof(struct page_owner, gfp_mask)
    "po_nr": None,      # offsetof(struct page_owner, nr_entries)
    "po_tr0": None,     # offsetof(struct page_owner, trace_entries[0])
    "page_cgroup_sz": None,
    "PAGE_EXT_OWNER_bit": -1,
}

def _compute_offsets_once():
    # page_cgroup size (optional)
    try:
        out = x("p/x sizeof(struct page_cgroup)")
        _OFF["page_cgroup_sz"] = _find_hex(out) or 0
    except Exception:
        _OFF["page_cgroup_sz"] = 0

    # page_cgroup.ext.* offsets
    _OFF["pc_owner"]  = _offsetof("&(((struct page_cgroup *)0)->ext.owner)")
    # flags may not exist in some backports; guard it
    try:
        _OFF["pc_flags"]  = _offsetof("&(((struct page_cgroup *)0)->ext.flags)")
    except Exception:
        _OFF["pc_flags"] = None
    # handle present in RHEL8+ only
    try:
        _OFF["pc_handle"] = _offsetof("&(((struct page_cgroup *)0)->ext.handle)")
    except Exception:
        _OFF["pc_handle"] = None
    # opportunistic pid field (name differs across backports, skip if absent)
    for fld in ("pid", "tgid", "tsk_pid"):
        try:
            _OFF["pc_pid"] = _offsetof(f"&(((struct page_cgroup *)0)->ext.{fld})")
            break
        except Exception:
            _OFF["pc_pid"] = None

    # page_owner fields
    _OFF["po_order"] = _offsetof("&(((struct page_owner *)0)->order)")
    _OFF["po_gfp"]   = _offsetof("&(((struct page_owner *)0)->gfp_mask)")
    _OFF["po_nr"]    = _offsetof("&(((struct page_owner *)0)->nr_entries)")
    _OFF["po_tr0"]   = _offsetof("&(((struct page_owner *)0)->trace_entries[0])")

    # PAGE_EXT_OWNER bit index (optional)
    try:
        out = x("p PAGE_EXT_OWNER")
        _OFF["PAGE_EXT_OWNER_bit"] = int(out.split()[-1], 0)
    except Exception:
        _OFF["PAGE_EXT_OWNER_bit"] = -1

# -------- page_cgroup base per section --------
_PC_BASE_CACHE = {}

def _pc_base_for_section(sec_addr: int) -> int:
    if sec_addr in _PC_BASE_CACHE:
        return _PC_BASE_CACHE[sec_addr]
    sec = readSU("struct mem_section", sec_addr)
    try:
        base = int(getattr(sec, "page_cgroup"))
    except Exception as e:
        raise RuntimeError(f"mem_section.page_cgroup not accessible at {sec_addr:#x}: {e}")
    _PC_BASE_CACHE[sec_addr] = base
    return base

def _pc_addr_by_offset(pc_base: int, offset: int) -> int:
    sz = _OFF["page_cgroup_sz"] or 0
    if sz > 0:
        return pc_base + offset * sz
    # last resort: ask gdb to compute (rare path)
    out = x(f"p &((struct page_cgroup *){pc_base:#x})[{offset}]")
    a = _find_hex(out)
    if not a:
        raise RuntimeError("Failed to compute &page_cgroup[offset]")
    return a

# -------- reading a single page_owner (fast path) --------
def _read_owner_record(pc_addr: int):
    """
    Use precomputed offsets and raw memory reads only.
    Returns:
      ("r7", {...})  or  ("r8", {...})  or  None
    """
    # If we can, filter on PAGE_EXT_OWNER quickly
    if _OFF["pc_flags"] is not None and _OFF["PAGE_EXT_OWNER_bit"] >= 0:
        try:
            flags = _rd64(pc_addr + _OFF["pc_flags"])
            if ((flags >> _OFF["PAGE_EXT_OWNER_bit"]) & 1) == 0:
                return None
        except Exception:
            pass  # continue

    # RHEL8+ handle?
    if _OFF["pc_handle"] is not None:
        try:
            handle = _rd64(pc_addr + _OFF["pc_handle"]) & 0xffffffff
            if handle:
                order = gfp = pid = 0
                # Best-effort order/gfp nearby (may be absent)
                try: order = _rd32(pc_addr + _OFF["po_order"]) & 0xffffffff
                except Exception: pass
                try: gfp   = _rd32(pc_addr + _OFF["po_gfp"]) & 0xffffffff
                except Exception: pass
                if _OFF["pc_pid"] is not None:
                    try:
                        pidv = _rd32(pc_addr + _OFF["pc_pid"]) & 0xffffffff
                        pid = pidv if pidv > 0 else 0
                    except Exception:
                        pid = 0
                rec = {"k":"r8","o":int(order),"g":int(gfp),"h":int(handle)}
                if pid:
                    rec["pid"] = int(pid)
                return ("r8", rec)
        except Exception:
            pass

    # RHEL7 inline owner: owner may be pointer or embedded.
    try:
        owner_field_addr = pc_addr + _OFF["pc_owner"]
        owner_val = _rd64(owner_field_addr)
        # decide pointer vs embedded
        use_ptr = bool(owner_val and owner_val != 0xffffffffffffffff)
        owner_ptr = owner_val if use_ptr else owner_field_addr

        o = _rd32(owner_ptr + _OFF["po_order"]) & 0xffffffff
        g = _rd32(owner_ptr + _OFF["po_gfp"])   & 0xffffffff
        nr= _rd32(owner_ptr + _OFF["po_nr"])    & 0xffffffff

        # Sanity & non-empty
        if not (0 <= o <= PLAUSIBLE_MAX_ORDER): return None
        if not (0 <= nr <= 64): return None
        nr = min(nr, MAX_INLINE_TRACE)

        # If looks empty, skip
        if nr == 0 and o == 0 and g == 0:
            return None

        pcs = []
        base_tr = owner_ptr + _OFF["po_tr0"]
        for i in range(nr):
            a = _rd64(base_tr + i*8)
            if a:
                pcs.append(int(a))

        return ("r7", {"k":"r7","o":int(o),"g":int(g),"t":pcs})
    except Exception:
        return None

# -------- main export loop --------
def export_page_owner(out_path: str,
                      sections_range: str,
                      stride: int,
                      max_records: int,
                      pps_override: int,
                      state_path: str,
                      resume: bool,
                      progress_every: int,
                      checkpoint_every: int,
                      force_mode: str):
    rows = _sections_slice(sections_range)
    pps  = pps_override if pps_override else DEFAULT_PPS

    mode = "a" if resume else "w"
    out_f = open(out_path, mode, buffering=1024*1024)

    # resume checkpoint
    state = {"sec_idx": 0, "offset": 0}
    if resume and state_path and os.path.exists(state_path):
        try:
            with open(state_path, "r") as sf:
                state = json.load(sf)
        except Exception:
            pass

    # precompute offsets once
    _compute_offsets_once()

    emitted = 0
    visited = 0
    since_ckpt = 0

    try:
        start_sec_idx = state.get("sec_idx", 0) if resume else 0
        start_off     = state.get("offset", 0) if resume else 0

        for si in range(start_sec_idx, len(rows)):
            sec = rows[si]
            pc_base = _pc_base_for_section(sec.addr)
            if pc_base == 0:
                start_off = 0
                continue

            off0 = start_off if si == start_sec_idx else 0
            if stride > 1 and off0 % stride != 0:
                off0 += (stride - (off0 % stride))

            for off in range(off0, pps, stride):
                visited += 1
                since_ckpt += 1
                pfn = sec.pfn_base + off
                pc_addr = _pc_addr_by_offset(pc_base, off)

                rec = _read_owner_record(pc_addr)
                if rec:
                    kind, payload = rec
                    if force_mode == "r7" and kind != "r7":
                        pass
                    elif force_mode == "r8" and kind != "r8":
                        pass
                    else:
                        payload["pfn"] = pfn
                        out_f.write(json.dumps(payload) + "\n")
                        emitted += 1
                        if (emitted % 8192) == 0:
                            out_f.flush()
                    if max_records and emitted >= max_records:
                        raise StopIteration

                if progress_every and (visited % progress_every) == 0:
                    print(f"[export_po] visited={visited} emitted={emitted} sec={sec.nr} off={off} pfn={pfn}", file=sys.stderr)

                if state_path and since_ckpt >= checkpoint_every:
                    with open(state_path, "w") as sf:
                        json.dump({"sec_idx": si, "offset": off}, sf)
                    since_ckpt = 0

            start_off = 0
            if state_path:
                with open(state_path, "w") as sf:
                    json.dump({"sec_idx": si+1, "offset": 0}, sf)

    except StopIteration:
        pass
    finally:
        out_f.flush()
        out_f.close()

    print(f"[export_po] DONE: visited={visited}, emitted={emitted}, output={out_path}", file=sys.stderr)

# -------- CLI --------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Export page_owner records (NDJSON) from vmcore via crash/epython.")
    ap.add_argument("--out", required=True, help="Output NDJSON file (append if --resume)")
    ap.add_argument("--sections", help="Section range A:B (from `kmem -n`), default: all")
    ap.add_argument("--stride", type=int, default=1, help="Visit every Nth page (default 1)")
    ap.add_argument("--max", type=int, default=0, help="Stop after N emitted records (0=unlimited)")
    ap.add_argument("--pps", type=lambda s: int(s, 0), help="Pages-per-section override (default 0x8000)")
    ap.add_argument("--state", help="Checkpoint file to save/restore progress (JSON)")
    ap.add_argument("--resume", action="store_true", help="Resume from --state and append to --out")
    ap.add_argument("--progress", type=int, default=0, help="Print progress every N pages visited (stderr)")
    ap.add_argument("--checkpoint", type=int, default=50000, help="Write state every N pages visited (default 50000)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--rhel7", action="store_true", help="Force RHEL7 inline owner mode only")
    g.add_argument("--rhel8", action="store_true", help="Force RHEL8+ stack-depot mode only")
    args = ap.parse_args(argv)

    force_mode = "auto"
    if args.rhel7: force_mode = "r7"
    if args.rhel8: force_mode = "r8"

    export_page_owner(out_path=args.out,
                      sections_range=args.sections,
                      stride=max(1, int(args.stride)),
                      max_records=max(0, int(args.max)),
                      pps_override=args.pps if args.pps else 0,
                      state_path=args.state if args.state else "",
                      resume=bool(args.resume),
                      progress_every=max(0, int(args.progress)),
                      checkpoint_every=max(1000, int(args.checkpoint)),
                      force_mode=force_mode)

# crash entrypoint
def chk_export_po(*argv):
    main(list(argv))

if __name__ == "__main__":
    import sys
    main(sys.argv[1:])

