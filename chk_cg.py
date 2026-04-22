#!/usr/bin/env python3
# chk_cg.py — Inspect CPU/Memory cgroup limits for a task from a vmcore (crash epython).
# RHEL-focused, works inside crash via pykdump.API / pykdump.
#
# Usage inside crash:
#   epython chk_cg.py -p <PID|TASK_POINTER>
#   epython chk_cg.py -l [--controller cpu|memory|both]
#   epython chk_cg.py -l --all
#   epython chk_cg.py -l --summary
#
# Example:
#   epython chk_cg.py -p 22774
#   epython chk_cg.py -p 0xffffa0b8412e4000
#   epython chk_cg.py -l
#   epython chk_cg.py -l --all
#   epython chk_cg.py -l --summary

import sys, re, argparse

VERBOSE = False
DEBUG = False

def vmsg(msg):
    if VERBOSE or DEBUG:
        print(f"[INFO] {msg}", file=sys.stderr)

def dmsg(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)

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
_READPTR = None
_READMEM = None
_CRASH_IMPORT_ERR = None

def _init_crash():
    global _CRASH, _READPTR, _READMEM, _CRASH_IMPORT_ERR
    try:
        from pykdump.API import exec_crash_command as _exec
        _CRASH = _exec
        try:
            from pykdump.API import readPtr as _rp
            _READPTR = _rp
        except Exception:
            _READPTR = None
        try:
            from pykdump.API import readmem as _rm
            _READMEM = _rm
        except Exception:
            _READMEM = None
        return
    except Exception as e_api:
        try:
            from pykdump import exec_crash_command as _exec
            _CRASH = _exec
            try:
                from pykdump import readPtr as _rp
                _READPTR = _rp
            except Exception:
                _READPTR = None
            try:
                from pykdump import readmem as _rm
                _READMEM = _rm
            except Exception:
                _READMEM = None
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

def addr_int(s: str):
    a = addr_only(s)
    return int(a, 16) if a else None

def addr_hex(v: int) -> str:
    return f"0x{int(v):016x}"

def ptr_hex(v):
    try:
        i = int(v)
    except Exception:
        return None
    return addr_hex(i) if i else None

def _readmem_bytes(addr, size):
    if _CRASH is None:
        _init_crash()
    if _READMEM is None:
        return None
    data = _READMEM(addr, size)
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("latin1", "ignore")
    return bytes(data)

def read_cstring(addr, maxlen=256):
    if not addr:
        return None
    try:
        data = _readmem_bytes(int(addr, 16) if isinstance(addr, str) else int(addr), maxlen)
        if not data:
            return None
        data = data.split(b"\x00", 1)[0]
        return data.decode("utf-8", "replace")
    except Exception as e:
        dmsg(f"read_cstring({addr}) failed: {e}")
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
            pid = pid_from_ps_line(ln)
            if pid is None:
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

def pid_from_ps_line(line: str):
    toks = line.split()
    if not toks:
        return None
    idx = 1 if toks[0] == ">" else 0
    if idx >= len(toks):
        return None
    try:
        return int(toks[idx])
    except ValueError:
        return None

def iter_ps_tasks():
    """Yield (pid, task_ptr, comm) from crash `ps` output."""
    out = x("ps")
    for ln in out.splitlines():
        toks = ln.split()
        pid = pid_from_ps_line(ln)
        if pid is None:
            continue
        m = ADDR_RE.search(ln)
        if not m:
            continue
        task_ptr = "0x" + m.group(2).lower()
        comm = toks[-1] if len(toks) > 1 else ""
        yield pid, task_ptr, comm

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
        name_ptr = read_member_ptr("dentry", dentry_addr, "d_name.name")
        if name_ptr:
            name = read_cstring(name_ptr)
            if name:
                return name
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

# ---------------- cgroup listing ----------------
_CGROUP_ID_CACHE = {}
_TG_BUDGET_CACHE = {}
_CGROUP_CHILD_LIST_MEMBERS = None

CGROUP_SUBSYS_BITS = {
    "cpuset": 0,
    "cpu": 1,
    "cpuacct": 2,
    "memory": 4,
    "devices": 5,
    "freezer": 6,
    "net_cls": 7,
    "blkio": 8,
    "perf_event": 9,
    "hugetlb": 10,
    "pids": 11,
    "rdma": 12,
}

def _budget_desc(quota, period):
    if quota is None:
        return "quota=?"
    if quota == -1 or (isinstance(quota, int) and quota >= 10**15):
        return "unlimited"
    if quota == 0:
        return "disabled"
    if period and period > 0:
        return f"{100.0 * (quota / float(period)):.2f}% CPU"
    return f"quota={quota} period={period}"

def _limit_desc(limit):
    if limit is None:
        return "limit=?"
    if limit == -1 or limit >= (1 << 60):
        return "unlimited"
    return fmt_bytes(limit)

def _cg_key(controller, info):
    path = info.get("path") or (info.get("name") if info.get("name") not in (None, "") else None) or "/"
    return (controller, path, info.get("cgroup") or "", info.get("kn") or "")

def _remember_task(row, pid, comm):
    row["tasks"] += 1
    if len(row["samples"]) < 5:
        row["samples"].append(f"{pid}:{comm}")

def cgroup_identity_from_css_cached(css):
    css_addr = addr_only(css) or str(css)
    if css_addr in _CGROUP_ID_CACHE:
        return _CGROUP_ID_CACHE[css_addr]
    name, cg, kn = cgroup_name_from_css(css)
    path = cgroup_path_for(cg, kn) if (cg or kn) else None
    ident = (name, path, cg, kn)
    _CGROUP_ID_CACHE[css_addr] = ident
    return ident

def cpu_budget_from_tg_cached(tg_addr):
    if not tg_addr:
        return (None, None)
    if tg_addr in _TG_BUDGET_CACHE:
        return _TG_BUDGET_CACHE[tg_addr]
    period = quota = None
    try:
        period = to_int(p_eval(f"((struct task_group *){tg_addr})->cfs_bandwidth.period"))
        quota = to_int(p_eval(f"((struct task_group *){tg_addr})->cfs_bandwidth.quota"))
    except Exception as e:
        dmsg(f"task_group {tg_addr} cpu budget read failed: {e}")
    _TG_BUDGET_CACHE[tg_addr] = (quota, period)
    return quota, period

def collect_cpu_list_entry(task_ptr):
    """Cheap CPU cgroup snapshot for list mode.

    Avoid per-runqueue scheduler fields here. On some vmcores those reads are
    slow or fail noisily when repeated across every task.
    """
    out = {}
    cpu_css = p_eval(f"((struct task_struct *){task_ptr})->cgroups->subsys[1]")
    out["cpu_css"] = cpu_css

    name, path, cg, kn = cgroup_identity_from_css_cached(cpu_css)
    out["name"] = name
    out["path"] = path
    out["cgroup"] = cg
    out["kn"] = kn

    tg = p_eval(f"((struct task_struct *){task_ptr})->sched_task_group")
    tg_addr = addr_only(tg) or tg
    out["tg"] = tg_addr
    if tg_addr:
        quota, period = cpu_budget_from_tg_cached(tg_addr)
        out["period_ns"] = period
        out["quota_ns"] = quota
    return out

def collect_mem_list_entry(task_ptr):
    """Cheap memory cgroup identity snapshot for list mode."""
    out = {}
    mem_css = p_eval(f"((struct task_struct *){task_ptr})->cgroups->subsys[4]")
    out["mem_css"] = mem_css

    name, path, cg, kn = cgroup_identity_from_css_cached(mem_css)
    out["name"] = name
    out["path"] = path
    out["cgroup"] = cg
    out["kn"] = kn
    return out

def list_head_next(head_addr):
    if _CRASH is None:
        _init_crash()
    if _READPTR is not None:
        try:
            return ptr_hex(_READPTR(int(head_addr, 16)))
        except Exception as e:
            dmsg(f"readPtr(list_head.next {head_addr}) failed, falling back to p: {e}")
    nxt = p_eval(f"((struct list_head *){head_addr})->next")
    return addr_only(nxt)

def struct_member_addr(typename, obj_addr, member):
    return addr_only(p_eval(f"&((struct {typename} *){obj_addr})->{member}"))

def member_addr_offset(typename, member):
    off = member_offset(typename, member)
    if off is not None:
        return off
    if "." not in member:
        return None
    try:
        return to_int(p_eval(f"(unsigned long)&(((struct {typename} *)0)->{member})"))
    except Exception:
        return None

def symbol_addr(name):
    try:
        return addr_only(p_eval(f"&{name}"))
    except Exception:
        try:
            out = x(f"sym {name}")
            return addr_only(out)
        except Exception as e:
            dmsg(f"symbol lookup failed for {name}: {e}")
            return None

def read_member_ptr(typename, obj_addr, member):
    if _CRASH is None:
        _init_crash()
    if _READPTR is not None:
        off = member_offset(typename, member)
        if off is None and "." in member:
            off = member_addr_offset(typename, member)
        if off is not None:
            try:
                return ptr_hex(_READPTR(int(obj_addr, 16) + off))
            except Exception as e:
                dmsg(f"readPtr({typename}.{member} {obj_addr}) failed, falling back to p: {e}")
    return addr_only(p_eval(f"((struct {typename} *){obj_addr})->{member}"))

def cgroup_identity_from_cgrp_cached(cg_addr):
    key = "cg:" + str(cg_addr)
    if key in _CGROUP_ID_CACHE:
        return _CGROUP_ID_CACHE[key]
    kn = None
    name = None
    if has_member("cgroup", "kn"):
        try:
            kn = read_member_ptr("cgroup", cg_addr, "kn")
            if kn:
                name_ptr = read_member_ptr("kernfs_node", kn, "name")
                name = read_cstring(name_ptr) if name_ptr else None
                if not name:
                    name = _extract_cstr(p_eval(f"((struct kernfs_node *){kn})->name"))
        except Exception as e:
            dmsg(f"cgroup {cg_addr} kernfs identity failed: {e}")
    if not name and has_member("cgroup", "dentry"):
        try:
            dentry = read_member_ptr("cgroup", cg_addr, "dentry")
            name = _qstr_name_from_dentry(dentry) if dentry else None
        except Exception as e:
            dmsg(f"cgroup {cg_addr} dentry identity failed: {e}")
    path = cgroup_path_for(cg_addr, kn)
    ident = (name, path, cg_addr, kn)
    _CGROUP_ID_CACHE[key] = ident
    return ident

def cgroup_leaf_from_cgrp(cg_addr):
    key = "leaf:" + str(cg_addr)
    if key in _CGROUP_ID_CACHE:
        return _CGROUP_ID_CACHE[key]
    name = None
    kn = None
    if has_member("cgroup", "kn"):
        try:
            kn = read_member_ptr("cgroup", cg_addr, "kn")
            if kn:
                name_ptr = read_member_ptr("kernfs_node", kn, "name")
                name = read_cstring(name_ptr) if name_ptr else None
                if not name:
                    name = _extract_cstr(p_eval(f"((struct kernfs_node *){kn})->name"))
        except Exception as e:
            dmsg(f"cgroup {cg_addr} leaf kernfs read failed: {e}")
    if not name and has_member("cgroup", "dentry"):
        try:
            dentry = read_member_ptr("cgroup", cg_addr, "dentry")
            name = _qstr_name_from_dentry(dentry) if dentry else None
        except Exception as e:
            dmsg(f"cgroup {cg_addr} leaf dentry read failed: {e}")
    if not name or name == "/":
        name = ""
    leaf = (name, kn)
    _CGROUP_ID_CACHE[key] = leaf
    return leaf

def join_cgroup_path(parent_path, leaf):
    if not leaf:
        return parent_path or "/"
    if not parent_path or parent_path == "/":
        return "/" + leaf
    return parent_path.rstrip("/") + "/" + leaf

def root_cgroup_from_root_addr(root_addr, root_type):
    if has_member(root_type, "cgrp"):
        cg = struct_member_addr(root_type, root_addr, "cgrp")
        if cg:
            return cg
    if has_member(root_type, "top_cgroup"):
        cg = p_eval(f"((struct {root_type} *){root_addr})->top_cgroup")
        return addr_only(cg)
    return None

def read_member_int(typename, obj_addr, member):
    try:
        return to_int(p_eval(f"((struct {typename} *){obj_addr})->{member}"))
    except Exception:
        return None

def root_subsystems(root_addr, root_type):
    names = []
    mask = None
    for field in ("subsys_mask", "subsys_bits"):
        if has_member(root_type, field):
            mask = read_member_int(root_type, root_addr, field)
            if mask is not None:
                break
    if mask is not None:
        for name, bit in CGROUP_SUBSYS_BITS.items():
            if mask & (1 << bit):
                names.append(name)
    return names, mask

def discover_cgroup_roots():
    roots = []
    seen = set()

    dfl_root = symbol_addr("cgrp_dfl_root")
    if dfl_root:
        cg = root_cgroup_from_root_addr(dfl_root, "cgroup_root")
        if cg and cg not in seen:
            subsys, mask = root_subsystems(dfl_root, "cgroup_root")
            roots.append({"cgroup": cg, "root": dfl_root, "type": "cgroup_root", "subsystems": subsys, "mask": mask})
            seen.add(cg)
            dmsg(f"found default cgroup root: root={dfl_root} cgrp={cg} subsystems={','.join(subsys) or '-'}")

    root_list_head = None
    for sym in ("cgroup_roots", "cgroup_root_list"):
        root_list_head = symbol_addr(sym)
        if root_list_head:
            dmsg(f"found cgroup root list via {sym}: {root_list_head}")
            break

    if root_list_head:
        for root_type in ("cgroup_root", "cgroupfs_root"):
            if not has_member(root_type, "root_list"):
                continue
            for root_addr in walk_list_entries(root_list_head, root_type, "root_list", limit=128):
                cg = root_cgroup_from_root_addr(root_addr, root_type)
                if cg and cg not in seen:
                    subsys, mask = root_subsystems(root_addr, root_type)
                    roots.append({"cgroup": cg, "root": root_addr, "type": root_type, "subsystems": subsys, "mask": mask})
                    seen.add(cg)
                    dmsg(f"found cgroup root from root list: type={root_type} root={root_addr} cgrp={cg} subsystems={','.join(subsys) or '-'}")
                if not cg:
                    dmsg(f"could not derive top cgroup from {root_type} {root_addr}")
            if roots:
                break

    return roots

def walk_list_entries(head_addr, typename, member, limit=100000):
    off = member_addr_offset(typename, member)
    if off is None:
        return
    head_i = addr_int(head_addr)
    cur = list_head_next(head_addr)
    seen = set()
    count = 0
    while cur:
        cur_i = addr_int(cur)
        if cur_i is None or cur_i == head_i or cur in seen:
            break
        seen.add(cur)
        yield addr_hex(cur_i - off)
        count += 1
        if count >= limit:
            dmsg(f"stopped walking {typename}.{member} at limit={limit}")
            break
        cur = list_head_next(cur)

def cgroup_child_list_members():
    global _CGROUP_CHILD_LIST_MEMBERS
    if _CGROUP_CHILD_LIST_MEMBERS is not None:
        return _CGROUP_CHILD_LIST_MEMBERS
    for head_member, entry_member in (
        ("children", "sibling"),
        ("children", "sibling_node"),
        ("self.children", "self.sibling"),
        ("self.children", "self.sibling_node"),
    ):
        if member_addr_offset("cgroup", head_member) is not None and member_addr_offset("cgroup", entry_member) is not None:
            _CGROUP_CHILD_LIST_MEMBERS = (head_member, entry_member)
            dmsg(f"using cgroup child list members: {head_member}/{entry_member}")
            return _CGROUP_CHILD_LIST_MEMBERS
    _CGROUP_CHILD_LIST_MEMBERS = (None, None)
    dmsg("no cgroup child list members discovered")
    return _CGROUP_CHILD_LIST_MEMBERS

def walk_cgroup_tree(root_cg, limit=100000):
    stack = [root_cg]
    seen = set()
    head_member, entry_member = cgroup_child_list_members()
    while stack:
        cg = stack.pop()
        if not cg or cg in seen:
            continue
        seen.add(cg)
        yield cg
        if len(seen) >= limit:
            dmsg(f"stopped walking cgroup tree at limit={limit}")
            break
        if not head_member or not entry_member:
            continue
        try:
            head = struct_member_addr("cgroup", cg, head_member)
            children = list(walk_list_entries(head, "cgroup", entry_member, limit=limit))
            stack.extend(reversed(children))
        except Exception as e:
            dmsg(f"children walk failed for cgroup {cg}: {e}")

def walk_cgroup_tree_paths(root_cg, limit=100000):
    stack = [(root_cg, "/")]
    seen = set()
    head_member, entry_member = cgroup_child_list_members()
    while stack:
        cg, path = stack.pop()
        if not cg or cg in seen:
            continue
        seen.add(cg)
        leaf, kn = cgroup_leaf_from_cgrp(cg)
        cur_path = "/" if path == "/" and not leaf else path
        yield cg, cur_path, kn
        if DEBUG and len(seen) % 1000 == 0:
            dmsg(f"walked {len(seen)} cgroups under root {root_cg}; current={cur_path}")
        if len(seen) >= limit:
            dmsg(f"stopped walking cgroup tree at limit={limit}")
            break
        if not head_member or not entry_member:
            continue
        try:
            head = struct_member_addr("cgroup", cg, head_member)
            children = []
            for child in walk_list_entries(head, "cgroup", entry_member, limit=limit):
                child_leaf, _child_kn = cgroup_leaf_from_cgrp(child)
                children.append((child, join_cgroup_path(cur_path, child_leaf)))
            stack.extend(reversed(children))
        except Exception as e:
            dmsg(f"children path walk failed for cgroup {cg}: {e}")

def collect_task_cgroup_counts(controller="both"):
    counts = {}
    total_tasks = 0
    for pid, task_ptr, comm in iter_ps_tasks():
        total_tasks += 1
        seen_for_task = set()
        ctl_exprs = (
            ("cpu", f"((struct task_struct *){task_ptr})->cgroups->subsys[1]"),
            ("memory", f"((struct task_struct *){task_ptr})->cgroups->subsys[4]"),
        )
        for ctl, expr in ctl_exprs:
            if controller not in ("both", ctl):
                continue
            try:
                css = p_eval(expr)
                cg = cgroup_ptr_from_css(css)
                if not cg:
                    continue
                row = counts.setdefault(cg, {"tasks": 0, "samples": [], "controllers": set()})
                row["controllers"].add(ctl)
                if cg in seen_for_task:
                    continue
                seen_for_task.add(cg)
                row["tasks"] += 1
                if len(row["samples"]) < 5:
                    row["samples"].append(f"{pid}:{comm}")
            except Exception as e:
                dmsg(f"PID {pid} {ctl} count failed: {e}")
    return counts, total_tasks

def cgroup_ptr_from_css(css_ptr_text):
    css_addr = addr_only(css_ptr_text)
    if not css_addr:
        return None
    try:
        return read_member_ptr("cgroup_subsys_state", css_addr, "cgroup")
    except Exception as e:
        dmsg(f"css {css_addr} cgroup pointer read failed: {e}")
        return None

def root_matches_controller(root, controller):
    if controller in (None, "both"):
        return True
    subsys = set(root.get("subsystems") or [])
    if controller == "cpu":
        return bool(subsys & {"cpu", "cpuacct"})
    if controller == "memory":
        return "memory" in subsys
    return True

def collect_all_cgroups(controller="both"):
    rows = {}
    roots = discover_cgroup_roots()
    selected_roots = [r for r in roots if root_matches_controller(r, controller)]
    counts, total_tasks = collect_task_cgroup_counts(controller)

    if controller not in (None, "both"):
        dmsg(f"selected {len(selected_roots)} of {len(roots)} roots for controller={controller}")

    for root in selected_roots:
        for cg, path, kn in walk_cgroup_tree_paths(root["cgroup"]):
            task_info = counts.get(cg, {})
            rows[cg] = {
                "path": path or "/",
                "cgroup": cg,
                "kn": kn,
                "tasks": task_info.get("tasks", 0),
                "samples": task_info.get("samples", []),
                "controllers": ",".join(sorted(task_info.get("controllers", []))),
            }

    for cg_addr, task_info in counts.items():
        if cg_addr in rows:
            continue
        name, path, _cg, kn = cgroup_identity_from_cgrp_cached(cg_addr)
        rows[cg_addr] = {
            "path": path or name or "/",
            "cgroup": cg_addr,
            "kn": kn,
            "tasks": task_info.get("tasks", 0),
            "samples": task_info.get("samples", []),
            "controllers": ",".join(sorted(task_info.get("controllers", []))),
        }

    return rows, selected_roots, total_tasks

def collect_cgroup_list(controller="both"):
    groups = {}
    total_tasks = 0
    errors = []

    vmsg(f"scanning tasks from crash ps for {controller} cgroups")
    for pid, task_ptr, comm in iter_ps_tasks():
        total_tasks += 1
        if DEBUG and (total_tasks == 1 or total_tasks % 100 == 0):
            dmsg(f"visited {total_tasks} tasks; current PID={pid} TASK={task_ptr} COMM={comm}")
        if controller in ("cpu", "both"):
            try:
                cpu = collect_cpu_list_entry(task_ptr)
                key = _cg_key("cpu", cpu)
                row = groups.setdefault(key, {
                    "controller": "cpu",
                    "path": key[1],
                    "cgroup": key[2],
                    "kn": key[3],
                    "tasks": 0,
                    "samples": [],
                    "quota": cpu.get("quota_ns"),
                    "period": cpu.get("period_ns"),
                })
                _remember_task(row, pid, comm)
            except Exception as e:
                err = f"PID {pid} cpu: {e}"
                errors.append(err)
                dmsg(err)

        if controller in ("memory", "both"):
            try:
                mem = collect_mem_list_entry(task_ptr)
                key = _cg_key("memory", mem)
                row = groups.setdefault(key, {
                    "controller": "memory",
                    "path": key[1],
                    "cgroup": key[2],
                    "kn": key[3],
                    "tasks": 0,
                    "samples": [],
                })
                _remember_task(row, pid, comm)
            except Exception as e:
                err = f"PID {pid} memory: {e}"
                errors.append(err)
                dmsg(err)

    vmsg(f"discovered {len(groups)} {controller} cgroup entries from {total_tasks} tasks")
    return groups, total_tasks, errors

def print_cgroup_list(controller="both", debug=False):
    groups, total_tasks, errors = collect_cgroup_list(controller)
    print(f"{C.BOLD}== Cgroups =={C.RESET}")
    print(f" source : tasks from crash ps")
    print(f" tasks  : {total_tasks}")
    print(f" groups : {len(groups)}")
    if errors:
        print(f" errors : {len(errors)} task/controller reads failed")
        if debug:
            for err in errors[:20]:
                print(f"   {err}")
            if len(errors) > 20:
                print(f"   ... {len(errors) - 20} more")

    by_ctl = {"cpu": [], "memory": []}
    for row in groups.values():
        by_ctl.setdefault(row["controller"], []).append(row)

    for ctl in ("cpu", "memory"):
        rows = by_ctl.get(ctl) or []
        if controller != "both" and ctl != controller:
            continue
        print(f"\n{C.BOLD}== {ctl.upper()} cgroups =={C.RESET}")
        if not rows:
            print(" (none discovered)")
            continue
        rows.sort(key=lambda r: (r["path"], r["cgroup"]))
        for row in rows:
            print(f" {C.CYAN}{row['path']}{C.RESET}")
            print(f"   tasks : {row['tasks']}  samples: {', '.join(row['samples'])}")
            if row.get("cgroup"):
                print(f"   cgrp  : {row['cgroup']}")
            if row.get("kn"):
                print(f"   kn    : {row['kn']}")
            if ctl == "cpu":
                print(f"   budget: {_budget_desc(row.get('quota'), row.get('period'))}")
            else:
                print(f"   memcg : {row['cgroup'] or 'unknown'}")

def print_all_cgroups(controller="both", debug=False):
    rows, roots, total_tasks = collect_all_cgroups(controller)
    print(f"{C.BOLD}== All Cgroups =={C.RESET}")
    print(" source : kernel cgroup tree")
    print(f" controller: {controller}")
    print(f" roots  : {len(roots)}")
    print(f" tasks  : {total_tasks}")
    print(f" groups : {len(rows)}")
    if not roots:
        print(" note   : no cgroup roots discovered; falling back to task-visible cgroups only")

    for row in sorted(rows.values(), key=lambda r: (r["path"], r["cgroup"])):
        empty = row["tasks"] == 0
        marker = f" {C.YELLOW}(empty){C.RESET}" if empty else ""
        print(f" {C.CYAN}{row['path']}{C.RESET}{marker}")
        samples = ", ".join(row["samples"]) if row["samples"] else "-"
        print(f"   tasks : {row['tasks']}  samples: {samples}")
        if row.get("controllers"):
            print(f"   seen  : {row['controllers']}")
        print(f"   cgrp  : {row['cgroup']}")
        if row.get("kn"):
            print(f"   kn    : {row['kn']}")

def unit_suffix(path):
    leaf = (path or "/").rstrip("/").split("/")[-1]
    if "." not in leaf:
        return "(no suffix)"
    suffix = leaf.rsplit(".", 1)[-1]
    return "." + suffix if suffix else "(no suffix)"

def top_bucket(path):
    parts = [p for p in (path or "/").split("/") if p]
    if not parts:
        return "/"
    if parts[0] in ("system.slice", "user.slice", "machine.slice"):
        return parts[0]
    return "/" + parts[0]

def inc_counter(d, key, n=1):
    d[key] = d.get(key, 0) + n

def print_counter(title, counts, limit=None):
    print(f"\n{C.BOLD}== {title} =={C.RESET}")
    if not counts:
        print(" (none)")
        return
    rows = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    if limit is not None:
        rows = rows[:limit]
    for key, val in rows:
        print(f" {key:32s} {val}")

def print_cgroup_summary(controller="both", debug=False):
    rows, roots, total_tasks = collect_all_cgroups(controller)
    total = len(rows)
    empty = sum(1 for r in rows.values() if r.get("tasks", 0) == 0)
    non_empty = total - empty

    suffix_counts = {}
    empty_suffix_counts = {}
    top_counts = {}
    empty_top_counts = {}
    mount_parent_counts = {}
    empty_mount_parent_counts = {}

    for row in rows.values():
        path = row.get("path") or "/"
        suffix = unit_suffix(path)
        bucket = top_bucket(path)
        inc_counter(suffix_counts, suffix)
        inc_counter(top_counts, bucket)
        if row.get("tasks", 0) == 0:
            inc_counter(empty_suffix_counts, suffix)
            inc_counter(empty_top_counts, bucket)
        if suffix == ".mount":
            parts = [p for p in path.split("/") if p]
            parent = parts[0] if parts else "/"
            inc_counter(mount_parent_counts, parent)
            if row.get("tasks", 0) == 0:
                inc_counter(empty_mount_parent_counts, parent)

    print(f"{C.BOLD}== Cgroup Summary =={C.RESET}")
    print(" source : kernel cgroup tree (--all implied)")
    print(f" controller: {controller}")
    print(f" roots  : {len(roots)}")
    print(f" tasks  : {total_tasks}")
    print(f" groups : {total}")
    print(f" empty  : {empty}")
    print(f" active : {non_empty}")
    if total:
        print(f" empty% : {100.0 * empty / float(total):.2f}%")
    if not roots:
        print(" note   : no cgroup roots discovered; summary is task-visible cgroups only")

    print_counter("By Unit Suffix", suffix_counts)
    print_counter("Empty By Unit Suffix", empty_suffix_counts)
    print_counter("Mount Units By Parent", mount_parent_counts, limit=20)
    print_counter("Empty Mount Units By Parent", empty_mount_parent_counts, limit=20)
    print_counter("By Top Path", top_counts, limit=20)
    print_counter("Empty By Top Path", empty_top_counts, limit=20)

# ---------------- main ----------------
def main():
    global VERBOSE, DEBUG

    ap = argparse.ArgumentParser(
        description="Show CPU/memory cgroup limits for a task (vmcore via crash epython)."
    )
    ap.add_argument("-p", "--pid", dest="target", metavar="PID|TASK",
                    help="PID, COMM substring, or task_struct pointer to inspect")
    ap.add_argument("-l", "--list-cgroups", action="store_true",
                    help="List cgroups discovered from all tasks in crash ps")
    ap.add_argument("--all", action="store_true",
                    help="With -l, walk kernel cgroup trees so empty cgroups are included")
    ap.add_argument("--summary", action="store_true",
                    help="With -l, print all-cgroup counts by suffix and top path; implies --all")
    ap.add_argument("-c", "--controller", choices=("cpu", "memory", "both"), default="both",
                    help="Controller to show with --list-cgroups (default: both)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Print progress messages to stderr")
    ap.add_argument("-d", "--debug", action="store_true",
                    help="Print debug messages and detailed read failures to stderr")
    args = ap.parse_args()

    VERBOSE = args.verbose
    DEBUG = args.debug

    if args.list_cgroups:
        if args.summary:
            print_cgroup_summary(args.controller, debug=args.debug)
            return
        if args.all:
            print_all_cgroups(args.controller, debug=args.debug)
            return
        print_cgroup_list(args.controller, debug=args.debug)
        return

    if args.all:
        ap.error("--all is only valid with -l/--list-cgroups")
    if args.summary:
        ap.error("--summary is only valid with -l/--list-cgroups")

    if not args.target:
        ap.error("-p/--pid is required unless --list-cgroups is used")

    target = normalize_target(args.target)
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
