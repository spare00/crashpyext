#!/usr/bin/env python3
# chk_cg.py — Inspect CPU/Memory cgroup limits for a task from a vmcore (crash epython).
# RHEL-focused, works inside crash via pykdump.API / pykdump.
#
# Usage inside crash:
#   epython chk_cg.py <PID|TASK_POINTER>
#
# Example:
#   epython chk_cg.py 22774
#   epython chk_cg.py 0xffffa0b8412e4000

import sys, re, argparse

# ---------------- colors ----------------
class C:
    RED    = "\033[31m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    CYAN   = "\033[36m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

# ---------------- kernel / RHEL version helpers ----------------
_RHEL_MAJOR = None

def _kernel_release_text():
    """Parse 'sys' output; avoid gdb p utsname()->release (may fail in some vmcores)."""
    try:
        out = x("sys")
        for ln in out.splitlines():
            if ln.startswith("RELEASE:"):
                return ln.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""  # keep empty; callers handle None-major

def rhel_major():
    """Return RHEL major as int (7, 8, 9...), or None if not detected."""
    global _RHEL_MAJOR
    if _RHEL_MAJOR is not None:
        return _RHEL_MAJOR
    rel = _kernel_release_text()
    m = re.search(r'\.el(\d+)', rel)
    _RHEL_MAJOR = int(m.group(1)) if m else None
    return _RHEL_MAJOR

# ---------------- crash/pykdump glue ----------------
_CRASH = None
_CRASH_IMPORT_ERR = None

def _init_crash():
    global _CRASH, _CRASH_IMPORT_ERR
    try:
        from pykdump.API import exec_crash_command as _exec
        _CRASH = _exec
        return
    except Exception as e_api:
        try:
            from pykdump import exec_crash_command as _exec
            _CRASH = _exec
            return
        except Exception as e_base:
            _CRASH = None
            _CRASH_IMPORT_ERR = f"pykdump.API err={repr(e_api)} ; pykdump err={repr(e_base)}"

def x(cmd: str) -> str:
    if _CRASH is None:
        _init_crash()
    if _CRASH is None:
        print(f"[ERROR] pykdump not available; cannot run crash command.\n{_CRASH_IMPORT_ERR}", file=sys.stderr)
        sys.exit(2)
    out = _CRASH(cmd)
    return out if isinstance(out, str) else str(out)

# ---------------- struct member probing (version-safe) ----------------
_STRUCT_FIELD_CACHE = {}

def member_offset(typename: str, member: str):
    """
    Return byte offset of 'member' in 'typename', or None if absent.
    Uses crash 'offset' command; if your epython exposes crash.member_offset, uses that.
    """
    # Try Python binding if present
    try:
        import crash as _cr
        if hasattr(_cr, "member_offset"):
            off = _cr.member_offset(typename, member)
            return int(off) if off is not None and off != -1 else None
    except Exception:
        pass
    # Fallback: textual 'offset <type> <member>' and parse
    out = x(f"offset {typename} {member}")
    line = out.strip().splitlines()[-1] if out.strip() else ""
    m = re.search(r'=\s*(0x[0-9a-fA-F]+|\d+)', line)
    if not m:
        return None
    return int(m.group(1), 0)

def has_member(typename: str, member: str) -> bool:
    key = (typename, member)
    if key in _STRUCT_FIELD_CACHE:
        return _STRUCT_FIELD_CACHE[key]
    off = member_offset(typename, member)
    ok = off is not None
    _STRUCT_FIELD_CACHE[key] = ok
    return ok

# ---- RT helpers ----
# Common policy constants (RHEL7/8/9)
SCHED_NORMAL = 0
SCHED_FIFO   = 1
SCHED_RR     = 2
SCHED_BATCH  = 3
SCHED_IDLE   = 5
SCHED_DEADLINE = 6  # if present

def is_rt_policy(pol: int) -> bool:
    return pol in (SCHED_FIFO, SCHED_RR)

def policy_name(pol: int) -> str:
    return {
        SCHED_NORMAL: "SCHED_NORMAL",
        SCHED_FIFO:   "SCHED_FIFO",
        SCHED_RR:     "SCHED_RR",
        SCHED_BATCH:  "SCHED_BATCH",
        SCHED_IDLE:   "SCHED_IDLE",
        SCHED_DEADLINE: "SCHED_DEADLINE",
    }.get(pol, f"{pol}")

# ---------------- small helpers ----------------
def last_line(txt: str) -> str:
    lines = [l for l in (txt or "").splitlines() if l.strip()]
    return lines[-1].strip() if lines else ""

def parse_p(text: str) -> str:
    line = last_line(text)
    return line.split("=", 1)[1].strip() if "=" in line else line

def p_eval(expr: str) -> str:
    return parse_p(x(f"p {expr}"))

ADDR_RE = re.compile(r'(0x)?([0-9a-fA-F]{16,})')

def addr_only(s: str) -> str:
    """Extract bare hex address (as '0x...') from strings like '(type *) 0xffff...'."""
    if s is None:
        return None
    m = ADDR_RE.search(s)
    if not m:
        return None
    return "0x" + m.group(2).lower()

def to_int(s: str):
    if s is None:
        return None
    # prefer raw address if present
    a = addr_only(s)
    if a:
        try:
            return int(a, 16)
        except Exception:
            pass
    t = re.sub(r'^\(.*?\)\s*', '', s.strip())
    tok = t.split()[-1]
    try:
        if tok.lower().startswith(("0x", "ffff")):
            return int(tok, 16)
        return int(tok, 10)
    except Exception:
        return None

def normalize_target(arg: str) -> str:
    # Pure PID
    if re.fullmatch(r'\d+', arg):
        tp = task_ptr_from_pid(int(arg))
        if not tp:
            print(f"[ERROR] Cannot resolve TASK pointer for PID {arg}", file=sys.stderr)
            sys.exit(1)
        return tp

    # task_struct pointer
    if arg.startswith("0x"):
        return arg

    # COMM / substring match via crash ps
    ps_out = x("ps")
    matches = []
    for ln in ps_out.splitlines():
        if arg in ln:
            toks = ln.split()
            if not toks: continue
            try:
                pid = int(toks[0])
            except ValueError:
                continue
            tp = task_ptr_from_pid(pid)
            if tp:
                matches.append((pid, tp, ln.strip()))
    if not matches:
        print(f"[ERROR] Cannot resolve target '{arg}' to a PID or task pointer", file=sys.stderr)
        sys.exit(1)
    if len(matches) > 1:
        print(f"[WARN] Multiple matches for '{arg}':")
        for pid, tp, line in matches:
            print(f"  PID={pid} TASK={tp} :: {line}")
        # Pick the first for now
    return matches[0][1]

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
    try:
        return f"{int(v)} ns"
    except Exception:
        return str(v)

def fmt_bytes(v) -> str:
    try:
        b = int(v)
    except Exception:
        return str(v)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    k, val = 0, float(b)
    while val >= 1024.0 and k < len(units) - 1:
        val /= 1024.0
        k += 1
    return f"{val:.2f} {units[k]} ({b} bytes)"

def rt_caps_for_tg(tg_addr: str):
    caps = {}
    if not tg_addr:
        return caps
    if has_member("task_group", "rt_bandwidth"):
        rb = f"((struct task_group *){tg_addr})->rt_bandwidth"
        if has_member("rt_bandwidth", "rt_runtime"):
            caps["rt_runtime_ns"] = to_int(p_eval(f"{rb}.rt_runtime"))
        if has_member("rt_bandwidth", "rt_period"):
            caps["rt_period_ns"]  = to_int(p_eval(f"{rb}.rt_period"))
    return caps

def print_hierarchy(cpu, policy):
    print(f"\n{C.BOLD}== Hierarchy =={C.RESET}")
    anc = cpu.get("ancestors") or []   # list of (tg_addr, cfs_quota, cfs_period), closest → root
    if not anc:
        print(" (no task_group ancestry discovered)")
        return

    for tg, cfs_q, cfs_p in anc:
        line = f" tg={tg}"
        # CFS view
        if cfs_q is None:
            cfs_desc = "CFS: quota=?"
        elif cfs_q == -1 or (isinstance(cfs_q, int) and cfs_q >= 10**15):
            cfs_desc = f"CFS: unlimited (period={cfs_p})"
        elif cfs_p and cfs_p > 0:
            pct = 100.0 * (cfs_q/float(cfs_p))
            cfs_desc = f"CFS: quota={cfs_q} period={cfs_p} (~{pct:.2f}% CPU)"
        else:
            cfs_desc = f"CFS: quota={cfs_q} period={cfs_p}"
        # RT view (guarded by offsets)
        rt = rt_caps_for_tg(tg)
        if "rt_runtime_ns" in rt and "rt_period_ns" in rt:
            rr, rp = rt["rt_runtime_ns"], rt["rt_period_ns"]
            if rr is not None and rp:
                if rr < 0:
                    rt_desc = "RT: unlimited"
                else:
                    rt_pct = 100.0 * (rr/float(rp))
                    rt_desc = f"RT: runtime={rr} period={rp} (~{rt_pct:.2f}% CPU)"
            else:
                rt_desc = "RT: n/a"
            line += f"  ;  {cfs_desc}  ;  {rt_desc}"
        else:
            line += f"  ;  {cfs_desc}"
        print(" " + line)

# ---------------- kernfs/cgroup helpers ----------------
def _extract_cstr(val: str) -> str:
    """Best-effort to extract the printable name from crash output.
       Accepts: '0xffff... "name"', '"name"', or plain 'name'.
       Returns '' if we only see an address (no printable string)."""
    if not isinstance(val, str):
        return str(val)
    txt = val.strip()
    # Prefer quoted content if present
    m = re.search(r'"([^"]*)"', txt)
    if m:
        return m.group(1)
    # If it looks like: 0xffff... <maybe>name — try the last token
    toks = txt.split()
    if toks:
        last = toks[-1].strip()
        # Drop trailing commas/semicolons
        last = last.rstrip(",;")
        # If it's not a hex-looking token, take it as a name
        if not ADDR_RE.fullmatch(last):
            return last.strip('"')
    # Address only or nothing printable
    return ""

def cgroup_name_from_css(css_ptr_text: str):
    """Return (name, cgroup_ptr_addr, kn_or_none).
       RHEL8+/kernels with cgroup v2 kernfs: use ->kn.
       RHEL7/v1: use ->dentry and ->name (no kn)."""
    css_addr = addr_only(css_ptr_text)
    if not css_addr:
        return (None, None, None)

    # First resolve struct cgroup * from css or task_group
    cg_addr = None
    # Try CSS path
    try:
        cg = p_eval(f"((struct cgroup_subsys_state *){css_addr})->cgroup")
        cg_addr = addr_only(cg)
    except Exception:
        pass
    if not cg_addr:
        # Fallback: treat input as task_group and go via ->css.cgroup
        try:
            cg2 = p_eval(f"((struct task_group *){css_addr})->css.cgroup")
            cg_addr = addr_only(cg2)
        except Exception:
            pass
    if not cg_addr:
        return (None, None, None)

    # Decide based on struct layout rather than only RHEL: probe member
    use_kn = has_member("cgroup", "kn")
    if not use_kn:
        # RHEL7/v1 path: derive leaf name and path from dentry/name
        name = None
        # Prefer cgroup->name (if present)
        if has_member("cgroup", "name"):
            try:
                nm = p_eval(f"((struct cgroup *){cg_addr})->name->name")
                name = _extract_cstr(nm)
            except Exception:
                name = None
        # Fallback to dentry->d_name.name
        dentry_addr = None
        if has_member("cgroup", "dentry"):
            try:
                dentry = p_eval(f"((struct cgroup *){cg_addr})->dentry")
                dentry_addr = addr_only(dentry)
                if not name and dentry_addr:
                    name = _qstr_name_from_dentry(dentry_addr) or None
            except Exception:
                pass
        # Build a v1 path if we have dentry
        path = cgroup_path_from_dentry(dentry_addr) if dentry_addr else None
        # Return without kn (v1 has none)
        return (name, cg_addr, None if not use_kn else None)

    # v2/kernfs path (RHEL8+ and any kernel with cgroup->kn)
    kn = p_eval(f"((struct cgroup *){cg_addr})->kn")
    kn_addr = addr_only(kn)
    name = None
    if kn_addr:
        nm = p_eval(f"((struct kernfs_node *){kn_addr})->name")
        name = _extract_cstr(nm)
    return (name, cg_addr, kn_addr)

def cgroup_path_from_kn(kn_addr: str):
    parts = []
    cur = kn_addr
    hops = 0
    while cur and hops < 16:
        nm = _extract_cstr(p_eval(f"((struct kernfs_node *){cur})->name"))
        if nm and nm != "/" and not ADDR_RE.fullmatch(nm):
            parts.append(nm)
        parent = p_eval(f"((struct kernfs_node *){cur})->parent")
        cur = addr_only(parent)
        hops += 1
    # Build only if we actually have components
    return ("/" + "/".join(reversed(parts))) if parts else None

def cgroup_path_for(cg_addr: str, kn_addr: str):
    if kn_addr:
        return cgroup_path_from_kn(kn_addr)
    # v1 fallback via dentry (requires cg->dentry)
    try:
        if cg_addr and has_member("cgroup", "dentry"):
            dentry = p_eval(f"((struct cgroup *){cg_addr})->dentry")
            daddr = addr_only(dentry)
            return cgroup_path_from_dentry(daddr) if daddr else None
    except Exception:
        pass
    return None

def _qstr_name_from_dentry(dentry_addr: str) -> str:
    try:
        nm = p_eval(f"((struct dentry *){dentry_addr})->d_name.name")
        return _extract_cstr(nm)
    except Exception:
        return ""

def cgroup_path_from_dentry(dentry_addr: str):
    """Build a cgroup v1 path by walking dentry->d_parent up to root."""
    parts = []
    cur = dentry_addr
    hops = 0
    while cur and hops < 64:
        name = _qstr_name_from_dentry(cur)
        if name and name not in ("/",):
            parts.append(name)
        parent = addr_only(p_eval(f"((struct dentry *){cur})->d_parent"))
        # stop at root (parent == self) or NULL
        if not parent or parent == cur:
            break
        cur = parent
        hops += 1
    return ("/" + "/".join(reversed([p for p in parts if p]))) if parts else None

# ---------------- page size & scaling ----------------
def page_size():
    """Derive PAGE_SIZE without poking symbols; parse `sys` output."""
    try:
        out = x("sys")
        for ln in out.splitlines():
            if "PAGE SIZE" in ln:
                m = re.search(r'PAGE SIZE:\s*(\d+)', ln)
                if m:
                    return int(m.group(1))
    except Exception:
        pass
    return 4096  # safe default for x86_64

def scale_pages_to_bytes_if_needed(usage, limit, watermark):
    """
    If values look like page counts (small integers), convert to bytes.
    Heuristic: values < 2^20 are treated as page counts.
    """
    ps = page_size()
    def maybe_scale(v):
        if v is None:
            return None
        if v >= (1 << 60):
            return v
        return v * ps if v < (1 << 20) else v
    return maybe_scale(usage), maybe_scale(limit), maybe_scale(watermark), ps

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
    # classify unlimited quota here for later prints
    out["quota_unlimited"] = (quo is None) or (quo == -1) or (isinstance(quo, int) and quo >= 10**15)

    name, cg, kn = cgroup_name_from_css(cpu_css)
    out["name"] = name
    out["path"] = cgroup_path_for(cg, kn)
    out["cgroup"] = cg
    out["kn"] = kn

    # record task policy for display (normal/RT/deadline etc.)
    try:
        out["policy"] = to_int(p_eval(f"((struct task_struct *){task_ptr})->policy"))
    except Exception:
        pass

    # Ancestors (closest → root)
    anc = []
    cur = tg_addr
    for _ in range(10):
        q = to_int(p_eval(f"((struct task_group *){cur})->cfs_bandwidth.quota"))
        p = to_int(p_eval(f"((struct task_group *){cur})->cfs_bandwidth.period"))
        anc.append((cur, q, p))
        pr = p_eval(f"((struct task_group *){cur})->parent")
        cur = addr_only(pr)
        if not cur:
            break
    out["ancestors"] = anc

    # Tightest finite cap
    tight_ratio = None; tight_src = None
    for tg_i, q_i, p_i in anc:
        if q_i and p_i and q_i > 0 and p_i > 0 and q_i < 10**15:
            r = q_i / float(p_i)
            if tight_ratio is None or r < tight_ratio:
                tight_ratio = r; tight_src = tg_i
    out["tight_ratio"] = tight_ratio; out["tight_src"] = tight_src

    # --- Per-rq snapshot (only read members that exist on this kernel) ---
    try:
        rq = p_eval(f"((struct task_struct *){task_ptr})->se->cfs_rq")
        rq_addr = addr_only(rq) or rq
        out["cfs_rq"] = rq_addr
        if rq_addr:
            if has_member("cfs_rq", "runtime_remaining") and not out.get("quota_unlimited"):
                rr = to_int(p_eval(f"((struct cfs_rq *){rq_addr})->runtime_remaining"))
                out["rq_runtime_remaining"] = rr
                quo_ns = out.get("quota_ns"); per_ns = out.get("period_ns")
                if quo_ns and quo_ns > 0 and rr is not None and rr >= -(1<<62):
                    used = quo_ns - (rr if rr > 0 else 0)
                    if used < 0: used = 0
                    if used > quo_ns: used = quo_ns
                    out["rq_period_used_ns"] = used
                    out["rq_period_used_pct"] = 100.0 * (used/float(quo_ns))
            if has_member("cfs_rq", "nr_running"):
                out["rq_nr_running"] = to_int(p_eval(f"((struct cfs_rq *){rq_addr})->nr_running"))
            if has_member("cfs_rq", "throttled"):
                out["rq_throttled_flag"] = to_int(p_eval(f"((struct cfs_rq *){rq_addr})->throttled"))
            if has_member("cfs_rq", "throttle_count"):
                out["rq_throttle_count"] = to_int(p_eval(f"((struct cfs_rq *){rq_addr})->throttle_count"))
    except Exception:
        pass

    # --- Stable bandwidth stats from task_group->cfs_bandwidth ---
    try:
        bw = f"((struct task_group *){tg_addr})->cfs_bandwidth"
        if has_member("cfs_bandwidth", "nr_periods"):
            out["bw_nr_periods"] = to_int(p_eval(f"{bw}.nr_periods"))
        if has_member("cfs_bandwidth", "nr_throttled"):
            out["bw_nr_throttled"] = to_int(p_eval(f"{bw}.nr_throttled"))
        if has_member("cfs_bandwidth", "throttled_time"):
            out["bw_throttled_time"] = to_int(p_eval(f"{bw}.throttled_time"))
    except Exception:
        pass
    return out

def collect_rt(task_ptr: str):
    """Gather RT policy/priority and RT bandwidth (group) if this is an RT task."""
    out = {}
    pol = to_int(p_eval(f"((struct task_struct *){task_ptr})->policy"))
    out["policy"] = pol
    out["policy_name"] = policy_name(pol)
    if not is_rt_policy(pol):
        return out

    # Basic RT task attributes
    if has_member("task_struct", "rt_priority"):
        out["rt_priority"] = to_int(p_eval(f"((struct task_struct *){task_ptr})->rt_priority"))
    if has_member("task_struct", "prio"):
        out["prio"] = to_int(p_eval(f"((struct task_struct *){task_ptr})->prio"))

    # RT bandwidth is anchored in the task_group
    tg = p_eval(f"((struct task_struct *){task_ptr})->sched_task_group")
    tg_addr = addr_only(tg) or tg
    out["tg"] = tg_addr

    rb = f"((struct task_group *){tg_addr})->rt_bandwidth"
    if has_member("task_group", "rt_bandwidth"):
        # These names are stable: rt_runtime (ns) and rt_period (ns)
        if has_member("rt_bandwidth", "rt_runtime"):
            out["rt_runtime_ns"] = to_int(p_eval(f"{rb}.rt_runtime"))
        if has_member("rt_bandwidth", "rt_period"):
            out["rt_period_ns"] = to_int(p_eval(f"{rb}.rt_period"))

    # Optional per-CPU rt_rq glimpses (version-dependent; probe first)
    # If we can reach an rq pointer from the task (via its CFS rq->rq, which exists even for RT on many builds),
    # we can then read rq->rt fields.
    try:
        # Re-use se->cfs_rq->rq to get the rq (works across classes on many RHEL kernels)
        if has_member("task_struct", "se") and has_member("sched_entity", "cfs_rq"):
            cfsrq = p_eval(f"((struct task_struct *){task_ptr})->se->cfs_rq")
            cfsrq_addr = addr_only(cfsrq)
            if cfsrq_addr and has_member("cfs_rq", "rq"):
                rq = p_eval(f"((struct cfs_rq *){cfsrq_addr})->rq")
                rq_addr = addr_only(rq)
                if rq_addr and has_member("rq", "rt"):
                    # rq->rt is the embedded struct rt_rq
                    # read a few safe members if they exist
                    out["rt_rq_addr"] = rq_addr  # show the rq that hosts rt_rq
                    if has_member("rt_rq", "rt_nr_running"):
                        out["rt_nr_running"] = to_int(p_eval(f"((struct rq *){rq_addr})->rt.rt_nr_running"))
                    if has_member("rt_rq", "rt_time"):
                        out["rt_time"] = to_int(p_eval(f"((struct rq *){rq_addr})->rt.rt_time"))
                    if has_member("rt_rq", "rt_throttled"):
                        out["rt_throttled"] = to_int(p_eval(f"((struct rq *){rq_addr})->rt.rt_throttled"))
    except Exception:
        pass

    return out

# ---------------- Memory (memcg) ----------------
def collect_mem(task_ptr: str):
    out = {}
    mem_css = p_eval(f"((struct task_struct *){task_ptr})->cgroups->subsys[4]")
    out["mem_css"] = mem_css

    # Name/path (v1/v2 safe)
    name, cg, kn = cgroup_name_from_css(mem_css)
    out["name"] = name
    out["path"] = cgroup_path_for(cg, kn) if (cg or kn) else None
    out["cgroup"] = cg
    out["kn"] = kn

    css_addr = addr_only(mem_css)
    if not css_addr:
        out["note"] = "cannot parse mem css pointer"
        return out

    mc_addr = css_addr

    def try_int(expr):
        try:
            v = to_int(p_eval(expr))
            return v
        except Exception:
            return None

    usage_b = limit_b = wm_b = None
    up = lp = wmp = None
    fc = None
    ps = page_size()

    used_style = None  # "res" | "count" | "page"

    maj = rhel_major()
    has_res    = has_member("mem_cgroup", "res")
    has_memory = has_member("mem_cgroup", "memory")
    v2_hint    = has_member("cgroup", "kn") and kn is not None  # el8+/v2-style

    # --------- Decide order without causing failed probes ----------
    # If v2-ish (kn present) or RHEL8+, go straight to page_counter.
    # If RHEL7, prefer res_counter, then count-style.
    # If undetected, use structure hints: res → count → page.
    try_page_first = (maj is not None and maj >= 8) or v2_hint

    if try_page_first and has_memory:
        # Style C: page_counter (el8+)
        u = (try_int(f"((struct mem_cgroup *){mc_addr})->memory.usage.counter")
             or try_int(f"((struct mem_cgroup *){mc_addr})->memory.usage")
             or try_int(f"((struct mem_cgroup *){mc_addr})->memory.usage.value")
             or try_int(f"((struct mem_cgroup *){mc_addr})->memory.usage_in_bytes")
             or try_int(f"((struct mem_cgroup *){mc_addr})->memory.local_usage"))
        l = (try_int(f"((struct mem_cgroup *){mc_addr})->memory.max")
             or try_int(f"((struct mem_cgroup *){mc_addr})->memory.limit"))
        f = try_int(f"((struct mem_cgroup *){mc_addr})->memory.failcnt")
        w = try_int(f"((struct mem_cgroup *){mc_addr})->memory.watermark")
        if any(v is not None for v in (u, l, w, f)):
            usage_b, limit_b, wm_b, ps = scale_pages_to_bytes_if_needed(u, l, w)
            up, lp, wmp = u, l, w
            fc = f
            used_style = "page"

    if used_style is None:
        # RHEL7 preference / or unknown: res_counter first if present
        if has_res:
            u = try_int(f"((struct mem_cgroup *){mc_addr})->res.usage")
            l = try_int(f"((struct mem_cgroup *){mc_addr})->res.limit")
            f = try_int(f"((struct mem_cgroup *){mc_addr})->res.failcnt")
            if any(v is not None for v in (u, l, f)):
                usage_b, limit_b, fc = u, l, f
                used_style = "res"

    if used_style is None and (maj == 7 or maj is None):
        # Style B: legacy count-style (only on el7/unknown; skip entirely on el8+)
        # Sentinel *once* — but only when we didn't pre-select page style
        cnt = try_int(f"((struct mem_cgroup *){mc_addr})->memory.count.counter")
        if cnt is not None:
            lim = try_int(f"((struct mem_cgroup *){mc_addr})->memory.limit")
            f   = try_int(f"((struct mem_cgroup *){mc_addr})->memory.failcnt")
            wm  = try_int(f"((struct mem_cgroup *){mc_addr})->memory.watermark")

            up, lp, wmp = cnt, lim, wm
            usage_b, limit_b, wm_b, ps = scale_pages_to_bytes_if_needed(up, lp, wmp)
            fc = f
            used_style = "count"

            # Hide absurd watermarks sometimes seen in vmcores
            if wm_b is not None and wm_b > (1 << 56):
                wm_b = None
                wmp = None
            if up is not None and up < 0:
                up = 0
                usage_b, _, _, _ = scale_pages_to_bytes_if_needed(up, lp, wmp)

    # Finalize
    out["usage_bytes"] = usage_b
    out["limit_bytes"] = limit_b
    out["watermark"]   = wm_b
    out["failcnt"]     = fc

    out["usage_pages"] = up if used_style in ("count", "page") else None
    out["limit_pages"] = lp if used_style in ("count", "page") else None
    out["watermark_pages"] = wmp if used_style in ("count", "page") else None

    out["page_size"] = ps
    return out

# ---------------- printing ----------------
def print_cpu(cpu):
    # Policy-agnostic CPU identity block
    print(f"{C.BOLD}== CPU =={C.RESET}")

    # Prefer full path; else leaf name; else root only if kernel says so
    name = cpu.get("path") or (cpu.get("name") if cpu.get("name") not in (None, "",) else None) or "/"
    print(f" cgroup : {C.CYAN}{name}{C.RESET}")
    print(f" css    : {cpu.get('cpu_css')}")
    if cpu.get("cgroup"): print(f" cgrp   : {cpu.get('cgroup')}")
    if cpu.get("kn"):     print(f" kn     : {cpu.get('kn')}")
    print(f" tg     : {cpu.get('tg')}")
    if cpu.get("cfs_rq"): print(f" rq     : {cpu.get('cfs_rq')}")

    # Show policy name (helps decide which section to print next)
    polmap = {0:"SCHED_NORMAL",1:"SCHED_FIFO",2:"SCHED_RR",3:"SCHED_BATCH",5:"SCHED_IDLE",6:"SCHED_DEADLINE"}
    policy = cpu.get("policy")
    if policy is not None:
        print(f" policy : {polmap.get(policy, str(policy))}")

def print_cfs(cpu):
    print(f"\n{C.BOLD}== CFS =={C.RESET}")

    per = cpu.get("period_ns")
    quo = cpu.get("quota_ns")
    quo_unl = cpu.get("quota_unlimited")

    # Prefer a clean statement when unlimited/disabled
    if quo_unl or (quo is not None and quo == 0):
        if per is not None:
            print(" budget : " + C.GREEN + "unlimited/disabled" + C.RESET)
        else:
            print(" budget : " + C.GREEN + "unlimited/disabled" + C.RESET + " (period: n/a)")
    else:
        if per is not None: print(f" period : {fmt_ns(per)}")
        if quo is not None: print(f" quota  : {fmt_ns(quo)}")
        if per and quo is not None and quo > 0:
            pct = 100.0 * (quo / float(per))
            color = C.RED if pct < 50 else (C.YELLOW if pct < 100 else C.GREEN)
            print(f" budget : {color}{pct:.2f}% of one CPU{C.RESET}")

    # Instantaneous throttle flag on this rq
    thr = cpu.get("throttled")
    if thr is not None:
        val = f"{C.BOLD}{C.YELLOW}YES{C.RESET}" if thr else f"{C.GREEN}no{C.RESET}"
        print(f" throttled now  : {val}")

    # Per-period usage snapshot (only when quota is finite)
    if cpu.get("rq_period_used_ns") is not None and not quo_unl:
        pct  = cpu["rq_period_used_pct"]
        used = cpu["rq_period_used_ns"]
        color = C.RED if pct >= 90.0 else (C.YELLOW if pct >= 50.0 else C.GREEN)
        print(f" period usage    : {color}{pct:.2f}%{C.RESET}  ({fmt_ns(used)} of {fmt_ns(quo)})")

    if cpu.get("rq_runtime_remaining") is not None and not quo_unl:
        rr = cpu["rq_runtime_remaining"]
        rr_line = f"{fmt_ns(rr)}"
        if rr <= 0: rr_line = f"{C.YELLOW}{rr_line}{C.RESET}"
        print(f" runtime remain  : {rr_line}")

    if cpu.get("rq_nr_running") is not None:
        print(f" rq nr_running   : {cpu['rq_nr_running']}")

    if cpu.get("rq_throttle_count") is not None:
        print(f" throttle_count  : {cpu['rq_throttle_count']}")

    if cpu.get("rq_throttled_flag") is not None:
        print(f" rq throttled    : {'YES' if cpu['rq_throttled_flag'] else 'no'}")

    # Stable CFS bandwidth stats
    if any(k in cpu for k in ("bw_nr_periods", "bw_nr_throttled", "bw_throttled_time")):
        parts = []
        if cpu.get("bw_nr_periods")    is not None: parts.append(f"periods={cpu['bw_nr_periods']}")
        if cpu.get("bw_nr_throttled")  is not None: parts.append(f"throttled={cpu['bw_nr_throttled']}")
        if cpu.get("bw_throttled_time")is not None: parts.append(f"throttled_time={cpu['bw_throttled_time']} ns")
        print(" bw stats        : " + ", ".join(parts))

def print_rt(rtinfo):
    if rtinfo.get("policy") is None or rtinfo["policy"] not in (1, 2):
        return  # not RT
    print(f"\n{C.BOLD}== RT =={C.RESET}")
    print(f" policy : {C.CYAN}{rtinfo.get('policy_name')}{C.RESET}")
    if rtinfo.get("rt_priority") is not None: print(f" rt_prio: {rtinfo['rt_priority']}")
    if rtinfo.get("prio")        is not None: print(f" prio   : {rtinfo['prio']}")
    if rtinfo.get("rt_period_ns")  is not None: print(f" rt_period : {fmt_ns(rtinfo['rt_period_ns'])}")
    if rtinfo.get("rt_runtime_ns") is not None: print(f" rt_runtime: {fmt_ns(rtinfo['rt_runtime_ns'])}")
    if rtinfo.get("rt_period_ns") and rtinfo.get("rt_runtime_ns") is not None:
        rt_per = rtinfo["rt_period_ns"]; rt_qu = rtinfo["rt_runtime_ns"]
        if rt_qu < 0:
            print(" rt budget : unlimited")
        else:
            pct = 100.0 * (rt_qu/float(rt_per))
            color = C.RED if pct < 50 else (C.YELLOW if pct < 100 else C.GREEN)
            print(f" rt budget : {color}{pct:.2f}% of one CPU{C.RESET}")
    if rtinfo.get("rt_rq_addr"):       print(f" rq      : {rtinfo['rt_rq_addr']}")
    if rtinfo.get("rt_nr_running") is not None: print(f" rt_nr_running : {rtinfo['rt_nr_running']}")
    if rtinfo.get("rt_throttled") is not None:  print(f" RT rq throttled : {'YES' if rtinfo['rt_throttled'] else 'no'}")
    if rtinfo.get("rt_time") is not None:       print(f" rt_time       : {rtinfo['rt_time']} ns")

def print_mem(mem):
    print(f"\n{C.BOLD}== Memory =={C.RESET}")
    name = mem.get("path") or (mem.get("name") if mem.get("name") not in (None, "",) else None) or "/"
    print(f" cgroup : {C.CYAN}{name}{C.RESET}")
    print(f" css    : {mem.get('mem_css')}")
    if mem.get("cgroup"): print(f" cgrp   : {mem.get('cgroup')}")
    if mem.get("kn"):     print(f" kn     : {mem.get('kn')}")

    usage = mem.get("usage_bytes")
    limit = mem.get("limit_bytes")
    up = mem.get("usage_pages")
    lp = mem.get("limit_pages")
    wm = mem.get("watermark")
    wmp = mem.get("watermark_pages")
    ps = mem.get("page_size") or 4096

    # ---- usage ----
    if usage is not None:
        line = f" usage  : {fmt_bytes(usage)}"
        if up is not None and usage == up * ps:
            line += f"  (pages: {up})"
        print(line)
    else:
        print(" usage  : unavailable on this kernel (field layout differs)")

    # ---- limit ----
    if limit is not None:
        # Legacy quirk: some el7 builds show limit=1 page meaning "no explicit limit"
        if lp == 1 and usage is not None:
            print(f" limit  : {C.GREEN}unlimited (legacy 1-page quirk){C.RESET}")
        elif limit == -1 or limit >= (1 << 60):
            print(f" limit  : {C.GREEN}unlimited{C.RESET}")
        else:
            if usage and limit and usage / float(limit) > 0.9:
                lim_str = f"{C.RED}{fmt_bytes(limit)}{C.RESET}"
            else:
                lim_str = f"{C.CYAN}{fmt_bytes(limit)}{C.RESET}"
            line = f" limit  : {lim_str}"
            if lp is not None and limit == lp * ps:
                line += f"  (pages: {lp})"
            print(line)
            if usage and limit and limit > 0:
                pct = 100.0 * (usage / float(limit))
                color = C.RED if pct >= 90.0 else (C.YELLOW if pct >= 75.0 else C.GREEN)
                print(f" usage% : {color}{pct:.2f}%{C.RESET}")
    else:
        print(" limit  : unavailable on this kernel (field layout differs)")

    # ---- failcnt ----
    if mem.get("failcnt") is not None:
        fc = mem.get("failcnt")
        fc_str = f"{C.RED}{fc}{C.RESET}" if fc and fc > 0 else str(fc)
        print(f" failcnt: {fc_str}")

    # ---- watermark ----
    if wm is not None:
        # Suppress absurd bogus watermarks seen in some el7 dumps
        if wm > (1 << 56):  # ~64 PiB
            print(" watermark: unavailable/invalid (bogus value in dump)")
        else:
            line = f" watermark: {fmt_bytes(wm)}"
            if wmp is not None and wm == wmp * ps:
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
    comm = p_eval(f"((struct task_struct *){target})->comm") or ""
    pid  = to_int(p_eval(f"((struct task_struct *){target})->pid"))
    # strip quotes and any trailing NULs crash prints
    raw_comm = p_eval(f"((struct task_struct *){target})->comm") or ""
    comm_s = raw_comm.strip().strip('"')
    comm_clean = comm_s.split('\x00', 1)[0]
    # drop non-printables
    comm_clean = ''.join(ch for ch in comm_clean if 32 <= ord(ch) < 127)
    print(f"Task: {target}  PID: {pid}  COMM: {comm_clean}")

    cpu = collect_cpu(target); print_cpu(cpu)
    rt  = collect_rt(target)

    # Always show the hierarchy (both CFS and RT caps per tg when available)
    print_hierarchy(cpu, rt.get("policy") if rt else cpu.get("policy"))

    # Then class-specific section
    if rt.get("policy") in (1, 2):
        print_rt(rt)
    else:
        print_cfs(cpu)

    mem = collect_mem(target); print_mem(mem)

if __name__ == "__main__":
    main()

