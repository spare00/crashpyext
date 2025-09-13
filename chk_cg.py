#!/usr/bin/env python3
# chk_cg.py — Inspect CPU/Memory cgroup limits for a task from a vmcore (crash epython).
# Works with crash via pykdump.API / pykdump.

import sys, re, argparse

class C:
    RED    = "\033[31m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    CYAN   = "\033[36m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

# ---------------- crash/pykdump glue ----------------
_CRASH = None
_CRASH_IMPORT_ERR = None
def _init_crash():
    global _CRASH, _CRASH_IMPORT_ERR
    try:
        from pykdump.API import exec_crash_command as _exec
        _CRASH = _exec; return
    except Exception as e_api:
        try:
            from pykdump import exec_crash_command as _exec
            _CRASH = _exec; return
        except Exception as e_base:
            _CRASH = None
            _CRASH_IMPORT_ERR = f"pykdump.API err={repr(e_api)} ; pykdump err={repr(e_base)}"

def x(cmd: str) -> str:
    if _CRASH is None: _init_crash()
    if _CRASH is None:
        print(f"[ERROR] pykdump not available; cannot run crash command.\n{_CRASH_IMPORT_ERR}", file=sys.stderr)
        sys.exit(2)
    out = _CRASH(cmd)
    return out if isinstance(out, str) else str(out)

# ---------------- helpers ----------------
def last_line(txt: str) -> str:
    lines = [l for l in (txt or "").splitlines() if l.strip()]
    return lines[-1].strip() if lines else ""

def parse_p(text: str) -> str:
    line = last_line(text)
    return line.split("=", 1)[1].strip() if "=" in line else line

ADDR_RE = re.compile(r'(0x)?([0-9a-fA-F]{16,})')
def addr_only(s: str) -> str:
    """Extract bare hex address (as '0x...') from crash/gdb output like '(type *) 0xffff...'."""
    if s is None: return None
    m = ADDR_RE.search(s)
    if not m: return None
    hexpart = m.group(2).lower()
    return "0x" + hexpart

def to_int(s: str):
    if s is None: return None
    # prefer raw address if present
    a = addr_only(s)
    if a:
        try: return int(a, 16)
        except Exception: pass
    t = re.sub(r'^\(.*?\)\s*', '', s.strip())
    tok = t.split()[-1]
    try:
        if tok.lower().startswith(("0x","ffff")): return int(tok, 16)
        return int(tok, 10)
    except Exception:
        return None

def is_ptr_text(s: str) -> bool:
    return addr_only(s) is not None

def p_eval(expr: str) -> str:
    return parse_p(x(f"p {expr}"))

def normalize_target(arg: str) -> str:
    if re.fullmatch(r'\d+', arg):
        tp = task_ptr_from_pid(int(arg))
        if not tp:
            print(f"[ERROR] Cannot resolve TASK pointer for PID {arg}", file=sys.stderr); sys.exit(1)
        return tp
    return arg if arg.startswith("0x") else ("0x" + arg)

def task_ptr_from_pid(pid: int) -> str:
    out = x(f"ps -p {pid}")
    ptr = None
    for ln in out.splitlines():
        toks = ln.split()
        if toks and toks[0].isdigit() and int(toks[0]) == pid:
            m = ADDR_RE.search(ln)
            if m:
                ptr = "0x" + m.group(2).lower()
                break
    if not ptr:
        out2 = x(f"task {pid}")
        m2 = re.search(r'TASK:\s*([0-9a-fx]+)', out2, re.IGNORECASE)
        if m2:
            raw = m2.group(1).strip()
            ptr = raw if raw.startswith("0x") else "0x" + raw
    return ptr

def fmt_ns(v) -> str:
    try: return f"{int(v)} ns"
    except Exception: return str(v)

def fmt_bytes(v) -> str:
    try: b = int(v)
    except Exception: return str(v)
    units = ["B","KiB","MiB","GiB","TiB"]; k=0; val=float(b)
    while val>=1024.0 and k<len(units)-1: val/=1024.0; k+=1
    return f"{val:.2f} {units[k]} ({b} bytes)"

def page_size():
    """Derive PAGE_SIZE without poking gdb symbols; parse `sys` output."""
    try:
        out = x("sys")
        # Typical line: "PAGE SIZE: 4096"
        for ln in out.splitlines():
            if "PAGE SIZE" in ln:
                m = re.search(r'PAGE SIZE:\s*(\d+)', ln)
                if m:
                    return int(m.group(1))
    except Exception:
        pass
    return 4096  # safe default for x86_64 if parsing fails

def scale_pages_to_bytes_if_needed(usage, limit, watermark):
    """
    If values look like page counts (small numbers), convert to bytes.
    Heuristic: if limit exists and is < 1<<20 and PAGE_SIZE in [4K..64K], treat as pages.
    """
    ps = page_size()
    def maybe_scale(v):
        if v is None:
            return None
        # If clearly a gigantic 'unlimited' value, leave as-is.
        if v >= (1 << 60):
            return v
        # Heuristic: numbers < ~1M are very likely page counts in this context.
        return v * ps if v < (1 << 20) else v
    return maybe_scale(usage), maybe_scale(limit), maybe_scale(watermark), ps

# ---------------- kernfs/cgroup helpers ----------------
def _extract_cstr(val: str) -> str:
    """From crash 'p' output like '0xffff... \"name\"' return 'name'."""
    if not isinstance(val, str):
        return str(val)
    m = re.search(r'"([^"]*)"', val)
    if m:
        return m.group(1)
    # if there are no quotes and it starts with an address, drop it
    if ADDR_RE.search(val):
        return ""
    return val.strip()

def cgroup_name_from_css(css_ptr_text: str):
    """Return (name, cgroup_ptr, kn_ptr). Accepts css text with casts."""
    css_addr = addr_only(css_ptr_text)
    if not css_addr: return (None, None, None)
    cg = p_eval(f"((struct cgroup_subsys_state *){css_addr})->cgroup")
    cg_addr = addr_only(cg)
    if not cg_addr: return (None, None, None)
    kn = p_eval(f"((struct cgroup *){cg_addr})->kn")
    kn_addr = addr_only(kn)
    if not kn_addr: return (None, cg_addr, None)
    nm = p_eval(f"((struct kernfs_node *){kn_addr})->name")
    name = _extract_cstr(nm)
    return (name, cg_addr, kn_addr)

def cgroup_path_from_kn(kn_addr: str):
    parts=[]; cur=kn_addr; hops=0
    while cur and hops<16:
        nm = _extract_cstr(p_eval(f"((struct kernfs_node *){cur})->name"))
        if nm and nm!="/" and not ADDR_RE.fullmatch(nm):
            parts.append(nm)
        parent = p_eval(f"((struct kernfs_node *){cur})->parent")
        cur = addr_only(parent); hops+=1
    return "/" + "/".join(reversed(parts)) if parts else None

# ---------------- CPU (CFS bandwidth) ----------------
def collect_cpu(task_ptr: str):
    out = {}
    cpu_css = p_eval(f"((struct task_struct *){task_ptr})->cgroups->subsys[1]")
    out["cpu_css"] = cpu_css
    tg = p_eval(f"((struct task_struct *){task_ptr})->sched_task_group")
    tg_addr = addr_only(tg) or tg
    out["tg"] = tg_addr
    thr = to_int(p_eval(f"((struct task_struct *){task_ptr})->se->cfs_rq->throttled"))
    out["throttled"] = thr

    per = to_int(p_eval(f"((struct task_group *){tg_addr})->cfs_bandwidth.period"))
    quo = to_int(p_eval(f"((struct task_group *){tg_addr})->cfs_bandwidth.quota"))
    run = to_int(p_eval(f"((struct task_group *){tg_addr})->cfs_bandwidth.runtime"))
    out["period_ns"] = per; out["quota_ns"] = quo; out["runtime_ns"] = run

    name, cg, kn = cgroup_name_from_css(cpu_css)
    out["name"] = name
    out["path"] = cgroup_path_from_kn(kn) if kn else None

    anc=[]; cur=tg_addr
    for _ in range(10):
        q = to_int(p_eval(f"((struct task_group *){cur})->cfs_bandwidth.quota"))
        p = to_int(p_eval(f"((struct task_group *){cur})->cfs_bandwidth.period"))
        anc.append((cur, q, p))
        pr = p_eval(f"((struct task_group *){cur})->parent")
        cur = addr_only(pr)
        if not cur: break
    out["ancestors"]=anc

    tight_ratio = None; tight_src = None
    for tg_i, q_i, p_i in anc:
        # consider huge q_i as unlimited (root/static)
        if q_i and p_i and q_i>0 and p_i>0 and q_i < 10**15:
            r = q_i/float(p_i)
            if tight_ratio is None or r<tight_ratio:
                tight_ratio=r; tight_src=tg_i
    out["tight_ratio"]=tight_ratio; out["tight_src"]=tight_src
    return out

# ---------------- Memory (memcg) ----------------
def collect_mem(task_ptr: str):
    out = {}
    mem_css = p_eval(f"((struct task_struct *){task_ptr})->cgroups->subsys[4]")
    out["mem_css"] = mem_css
    name, cg, kn = cgroup_name_from_css(mem_css)
    out["name"] = name
    out["path"] = cgroup_path_from_kn(kn) if kn else None

    css_addr = addr_only(mem_css)
    if not css_addr:
        out["note"] = "cannot parse mem css pointer"; return out

    # On RHEL, mem_cgroup embeds 'struct cgroup_subsys_state css;' as first member.
    # So memcg pointer == css address. Use bare address to avoid double casts.
    mc_addr = css_addr
    # Optional sanity (don’t fail script if it errors on this kernel):
    try:
        _ = p_eval(f"((struct mem_cgroup *){mc_addr})->css.cgroup")
    except Exception:
        pass

    def try_int(exprs):
        for e in exprs:
            try:
                v = to_int(p_eval(e))
                if v is not None: return v, e
            except Exception:
                pass
        return None, None

    usage, _ = try_int([
        f"((struct mem_cgroup *){mc_addr})->memory.usage.counter",  # your kernel
        f"((struct mem_cgroup *){mc_addr})->memory.usage",          # some builds
        f"((struct mem_cgroup *){mc_addr})->memory.usage.value",
        f"((struct mem_cgroup *){mc_addr})->memory.usage_in_bytes",
        f"((struct mem_cgroup *){mc_addr})->memory.local_usage",
    ])
    limit, _ = try_int([
        f"((struct mem_cgroup *){mc_addr})->memory.max",    # hard limit on your kernel
        f"((struct mem_cgroup *){mc_addr})->memory.limit",  # older trees
    ])
    fc, _ = try_int([f"((struct mem_cgroup *){mc_addr})->memory.failcnt"])
    wm, _ = try_int([f"((struct mem_cgroup *){mc_addr})->memory.watermark"])
    # Detect page-based fields and scale to bytes if needed
    usage_b, limit_b, wm_b, ps = scale_pages_to_bytes_if_needed(usage, limit, wm)
    out["usage_bytes"] = usage_b
    out["limit_bytes"] = limit_b
    out["failcnt"] = fc
    out["watermark"] = wm_b
    # Also keep the raw page counters for display
    out["usage_pages"] = usage
    out["limit_pages"] = limit
    out["watermark_pages"] = wm
    out["page_size"] = ps
    return out

# ---------------- printing ----------------
def print_cpu(cpu):
    print(f"{C.BOLD}== CPU (CFS bandwidth) =={C.RESET}")
    name = cpu.get("path") or cpu.get("name") or "(unknown)"
    print(f" cgroup : {C.CYAN}{name}{C.RESET}")
    print(f" css    : {cpu.get('cpu_css')}")
    print(f" tg     : {cpu.get('tg')}")
    per=cpu.get("period_ns"); quo=cpu.get("quota_ns")
    if per is not None: print(f" period : {fmt_ns(per)}")
    if quo is not None: print(f" quota  : {fmt_ns(quo)}")
    if per and quo:
        if quo > 0:
            pct = 100.0*(quo/float(per))
            if pct < 50:
                color = C.RED
            elif pct < 100:
                color = C.YELLOW
            else:
                color = C.GREEN
            print(f" budget : {color}{pct:.2f}% of one CPU{C.RESET}")
        else:
            print(f" budget : {C.GREEN}unlimited/disabled{C.RESET}")
    thr = cpu.get("throttled")
    if thr is not None:
        if thr:
            val = f"{C.BOLD}{C.YELLOW}YES{C.RESET}"
        else:
            val = f"{C.GREEN}no{C.RESET}"
        print(f" throttled now : {val}")
    anc = cpu.get("ancestors") or []
    if len(anc)>1:
        print(" ancestors (closest → root):")
        for tg, q, p in anc:
            if q is None:
                desc = f"  - tg={tg} quota=? period={p}"
            elif q == -1 or (q is not None and q >= 10**15):
                desc = f"  - tg={tg} quota=unlimited period={p} (unlimited)"
            elif p and p>0:
                desc = f"  - tg={tg} quota={q} period={p} (~{100.0*(q/float(p)):.2f}% CPU)"
            else:
                desc = f"  - tg={tg} quota={q} period={p}"
            print(desc)

def print_mem(mem):
    print(f"\n{C.BOLD}== Memory (memcg) =={C.RESET}")
    name = mem.get("path") or mem.get("name") or "(unknown)"
    print(f" cgroup : {C.CYAN}{name}{C.RESET}")
    print(f" css    : {mem.get('mem_css')}")
    usage = mem.get("usage_bytes"); limit = mem.get("limit_bytes")
    up = mem.get("usage_pages"); lp = mem.get("limit_pages")
    wm = mem.get("watermark"); wmp = mem.get("watermark_pages")
    ps = mem.get("page_size") or 4096
    if usage is not None:
        line = f" usage  : {fmt_bytes(usage)}"
        if up is not None and usage == up * ps:
            line += f"  (pages: {up})"
        print(line)
    else: print(" usage  : unavailable on this kernel (field layout differs)")
    if limit is not None:
        if limit == -1 or limit >= (1<<60):
            print(f" limit  : {C.GREEN}unlimited{C.RESET}")
        else:
            # warn if usage > 90% of limit
            if usage and limit and usage/float(limit) > 0.9:
                lim_str = f"{C.RED}{fmt_bytes(limit)}{C.RESET}"
            else:
                lim_str = f"{C.CYAN}{fmt_bytes(limit)}{C.RESET}"
            line = f" limit  : {lim_str}"
            if lp is not None and limit == lp * ps:
                line += f"  (pages: {lp})"
            print(line)
            # Show usage percentage when we know both
            if usage and limit and limit > 0:
                pct = 100.0 * (usage/float(limit))
                color = C.RED if pct >= 90.0 else (C.YELLOW if pct >= 75.0 else C.GREEN)
                print(f" usage% : {color}{pct:.2f}%{C.RESET}")
    else:
        print(" limit  : unavailable on this kernel (field layout differs)")
    if mem.get("failcnt") is not None:
        print(f" failcnt: {mem.get('failcnt')}")
    if mem.get("watermark") is not None:
        line = f" watermark: {fmt_bytes(mem.get('watermark'))}"
        if wmp is not None and mem.get("watermark") == wmp * ps:
            line += f"  (pages: {wmp})"
        print(line)

# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser(
        description="Show CPU/memory cgroup limits for a task (vmcore via crash epython)."
    )
    ap.add_argument("target", nargs=1, help="PID or task_struct pointer (e.g., 22774 or 0xffff...)")
    args = ap.parse_args()

    target = normalize_target(args.target[0])
    comm = p_eval(f"((struct task_struct *){target})->comm")
    pid  = to_int(p_eval(f"((struct task_struct *){target})->pid"))
    comm_clean = (comm or "").strip().strip('"')
    print(f"Task: {target}  PID: {pid}  COMM: {comm_clean}")

    cpu = collect_cpu(target); print_cpu(cpu)
    mem = collect_mem(target); print_mem(mem)

if __name__ == "__main__":
    main()

