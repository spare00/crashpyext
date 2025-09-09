#!/usr/bin/env python3
# Enrich page_owner NDJSON with resolved symbols/modules (crash/epython only).
# Input:  records from chk_export_po.py
# Output: same records plus:
#   RHEL7: "s": ["name+off[/size] [mod?]", ...], "mod": "<first-mod-after-alloc?>"
#   RHEL8: unchanged (unless you later add stack-depot decoding)
#
# Usage in crash:
#   crash> extend -p chk_enrich_po.py
#   crash> chk_enrich_po --in /tmp/page_owner.ndjson --out /tmp/page_owner.enriched.ndjson
#
import argparse, json, re, sys
from collections import OrderedDict

from pykdump.API import exec_crash_command as _crash_x

# ---------- robust sym parsing (plain `sym <addr>`) ----------
_ADDRLINE_RE = re.compile(r'^\s*(ffffffff[0-9A-Fa-f]{8})\s+(?:\(\w\)\s+)?(.+?)\s*$')
_RHS_RE      = re.compile(r'^(?P<sym>[^\s]+(?:\s+\[[^\]]+\])?)(?:\s+/.+?:\s*\d+)?\s*$')

def _rhs_from_line(line: str) -> str:
    if not line:
        return ""
    m = _ADDRLINE_RE.match(line)
    rhs = m.group(2) if m else line.strip()
    m2 = _RHS_RE.match(rhs)
    return m2.group("sym") if m2 else rhs

def _is_kernel_text_addr(a: int) -> bool:
    return 0xffffffff00000000 <= a < 0xffffffffffffffff

def _sym_batch(addrs, chunk=512, max_cmd_len=2000, verbose=False):
    """
    Resolve a set of kernel addresses with minimal crash calls, safely.
    - chunk: soft maximum addresses per batch (will be split further if needed)
    - max_cmd_len: maximum characters in a single `sym` invocation
    Returns: dict {addr:int -> "name+off[/size] [mod?]"}.
    """
    result = {}
    # keep only kernel-ish addrs
    addrs = [a for a in addrs if _is_kernel_text_addr(a)]

    def _run_one(addr):
        try:
            out1 = _crash_x(f"sym {addr:#x}")
            line = ""
            for ln in str(out1).splitlines():
                if _ADDRLINE_RE.match(ln):
                    line = ln; break
            result[addr] = _rhs_from_line(line) or f"{addr:#x}"
        except Exception:
            result[addr] = f"{addr:#x}"

    i = 0
    n = len(addrs)
    while i < n:
        # Start with up to 'chunk' addrs
        j = min(i + chunk, n)
        batch = addrs[i:j]

        # Also enforce a max command length
        cmd_prefix = "sym "
        args = []
        total_len = len(cmd_prefix)
        for a in batch:
            s = f"{a:#x} "
            if total_len + len(s) > max_cmd_len:
                break
            args.append(s)
            total_len += len(s)
        if not args:
            # single address too long? shouldn't happen; fallback to single run
            _run_one(addrs[i])
            i += 1
            continue
        # adjust j to reflect actual args selected
        j = i + len(args)

        # Try to run the batch
        try:
            out = _crash_x(cmd_prefix + "".join(args).strip())
            lines = str(out).splitlines()
            # Map back 1:1 by scanning lines that match our address pattern
            idx = 0
            for ln in lines:
                if idx >= len(args):
                    break
                if _ADDRLINE_RE.match(ln):
                    rhs = _rhs_from_line(ln) or f"{batch[idx]:#x}"
                    result[batch[idx]] = rhs
                    idx += 1
            # any misses → resolve individually
            while idx < len(batch):
                _run_one(batch[idx])
                idx += 1

        except Exception:
            # If batch fails, split it and retry; if tiny, fallback to singles
            if len(batch) <= 8:
                for a in batch:
                    _run_one(a)
            else:
                mid = len(batch) // 2
                # recurse on halves by re-inserting indices
                addrs[i:j] = batch[:mid] + batch[mid:]
                # continue loop; next iteration will pick up the smaller half
                continue

        if verbose and ((j // max(1, chunk)) % 8 == 0):
            print(f"[enrich] sym-resolved ~{j} / {n} addrs", file=sys.stderr)

        i = j

    return result

# ---------- allocator heuristics for module tag ----------
_ALLOC_NAMES = (
    "alloc_pages", "get_page_from_freelist", "__page_cache_alloc",
    "kmalloc", "kzalloc", "vzalloc"
)

def _first_module_below_allocator(sym_lines):
    """
    Given a list of pretty frame strings 'func+off[/size] [mod]',
    find the first module-tagged frame AFTER hitting an allocator wrapper.
    """
    saw_alloc = False
    for rhs in sym_lines:
        base = rhs.split()[0] if rhs else ""
        mod  = None
        if "[" in rhs and rhs.endswith("]"):
            mod = rhs[rhs.rfind("[")+1:-1]
        if any(base.startswith(pfx) for pfx in _ALLOC_NAMES):
            saw_alloc = True
            continue
        if saw_alloc and mod:
            return mod
    return None

# ---------- main enrichment ----------
def enrich(in_path, out_path, depth, batch, progress, modules):
    # First pass: collect unique addresses we need to symbolize
    uniq = set()
    total = 0
    with open(in_path, "r", errors="ignore") as f:
        for ln in f:
            if not ln or ln[0] != "{":
                continue
            try:
                o = json.loads(ln)
            except Exception:
                continue
            if o.get("k") != "r7":
                continue
            pcs = o.get("t") or []
            if not pcs:
                continue
            for a in pcs[:depth]:
                if a and a != 0xffffffffffffffff and _is_kernel_text_addr(a):
                    uniq.add(int(a))
            total += 1
            if progress and (total % progress == 0):
                print(f"[enrich] scanned {total} records, uniq_addrs={len(uniq)}", file=sys.stderr)

    # Resolve once per unique address (batched)
    print(f"[enrich] resolving {len(uniq)} unique PCs ...", file=sys.stderr)
    symmap = _sym_batch(list(uniq), chunk=max(64, batch))
    print(f"[enrich] resolved {len(symmap)} PCs", file=sys.stderr)

    # Second pass: write enriched NDJSON
    out_f = open(out_path, "w", buffering=1024*1024)
    wrote = 0
    with open(in_path, "r", errors="ignore") as f:
        for ln in f:
            if not ln or ln[0] != "{":
                continue
            try:
                o = json.loads(ln)
            except Exception:
                continue

            if o.get("k") == "r7":
                pcs = o.get("t") or []
                if pcs:
                    frames = []
                    for a in pcs[:depth]:
                        if a and a != 0xffffffffffffffff and _is_kernel_text_addr(a):
                            frames.append(symmap.get(int(a), f"{int(a):#x}"))
                    if frames:
                        o["s"] = frames
                        if modules:
                            mod = _first_module_below_allocator(frames)
                            if mod:
                                o["mod"] = mod
            # (leave r8 records as-is; they have 'h' handle)

            out_f.write(json.dumps(o) + "\n")
            wrote += 1
            if progress and (wrote % progress == 0):
                print(f"[enrich] wrote {wrote}", file=sys.stderr)

    out_f.flush(); out_f.close()
    print(f"[enrich] DONE: wrote={wrote}, out={out_path}", file=sys.stderr)

def main(argv=None):
    ap = argparse.ArgumentParser(description="Enrich page_owner NDJSON with symbols/modules (crash).")
    ap.add_argument("--in",  dest="in_path",  required=True, help="Input NDJSON from chk_export_po.py")
    ap.add_argument("--out", dest="out_path", required=True, help="Output enriched NDJSON")
    ap.add_argument("--depth", type=int, default=8, help="Frames per record to annotate (default 8)")
    ap.add_argument("--batch", type=int, default=512, help="Addresses per crash sym batch (default 512)")
    ap.add_argument("--progress", type=int, default=100000, help="Progress interval (records)")
    ap.add_argument("--modules", action="store_true",
                    help="Also infer 'mod' by scanning frames below first allocator")
    args = ap.parse_args(argv)
    enrich(args.in_path, args.out_path, max(1,args.depth), max(64,args.batch), max(0,args.progress), args.modules)

def chk_enrich_po(*argv):
    main(list(argv))

if __name__ == "__main__":
    main(sys.argv[1:])

