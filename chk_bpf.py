#!/usr/bin/env epython
"""
chk_bpf.py — Resolve BPF program ID(s) from a ftrace_ops or bpf_trampoline address.

fentry/fexit/fmodify_return (BPF_PROG_TYPE_TRACING) attach through a
bpf_trampoline.  Each trampoline owns a dedicated ftrace_ops whose
->private pointer is the trampoline itself:

    ftrace_ops.private  ---->  bpf_trampoline
    bpf_trampoline.fops ---->  ftrace_ops
    bpf_trampoline.progs_hlist[kind]  --hlist-->  bpf_tramp_link  --> bpf_prog
                                                                   --> aux->id

On older kernels the hlist node lives in bpf_prog_aux.tramp_hlist instead
of bpf_tramp_link.

Usage (inside crash, after setup_chk_tools.py):
    crash> chk_bpf <addr>
    crash> chk_bpf -f <ftrace_ops>
    crash> chk_bpf -t <bpf_trampoline>
    crash> chk_bpf -p <id>
    crash> chk_bpf -p <id> -m
    crash> chk_bpf -n <function or trampoline name>
    crash> chk_bpf -n bpf_trampoline_6442501095
    crash> chk_bpf -h
"""

import argparse
import re
import sys
from pykdump.API import *


DEBUG = False

TRAMPOLINE_TABLE_SIZE = 1024  # 1 << TRAMPOLINE_HASH_BITS (10)
HLIST_WALK_MAX = 64

TRAMP_KIND_NAMES = {
    0: "FENTRY",
    1: "FEXIT",
    2: "MODIFY_RETURN",
    3: "MAX/REPLACE",
}

# Subset of uapi/linux/bpf.h; unknown values fall back to the integer.
BPF_PROG_TYPES = {
    0: "UNSPEC",
    1: "SOCKET_FILTER",
    2: "KPROBE",
    3: "SCHED_CLS",
    4: "SCHED_ACT",
    5: "TRACEPOINT",
    6: "XDP",
    7: "PERF_EVENT",
    8: "CGROUP_SKB",
    9: "CGROUP_SOCK",
    10: "LWT_IN",
    11: "LWT_OUT",
    12: "LWT_XMIT",
    13: "SOCK_OPS",
    14: "SK_SKB",
    15: "CGROUP_DEVICE",
    16: "SK_MSG",
    17: "RAW_TRACEPOINT",
    18: "CGROUP_SOCK_ADDR",
    19: "LWT_SEG6LOCAL",
    20: "LIRC_MODE2",
    21: "SK_REUSEPORT",
    22: "FLOW_DISSECTOR",
    23: "CGROUP_SYSCTL",
    24: "RAW_TRACEPOINT_WRITABLE",
    25: "CGROUP_SOCKOPT",
    26: "TRACING",
    27: "STRUCT_OPS",
    28: "EXT",
    29: "LSM",
    30: "SK_LOOKUP",
    31: "SYSCALL",
    32: "NETFILTER",
}

BPF_ATTACH_TYPES = {
    0: "CGROUP_INET_INGRESS",
    25: "TRACE_RAW_TP",
    26: "TRACE_FENTRY",
    27: "TRACE_FEXIT",
    28: "MODIFY_RETURN",
    29: "LSM_MAC",
    30: "TRACE_ITER",
    34: "PERF_EVENT",
    35: "TRACE_KPROBE_MULTI",
    37: "LSM_CGROUP",
    38: "STRUCT_OPS",
    40: "TRACE_UPROBE_MULTI",
    41: "TRACE_KPROBE_SESSION",
}

BPF_MAP_TYPES = {
    0: "UNSPEC",
    1: "HASH",
    2: "ARRAY",
    3: "PROG_ARRAY",
    4: "PERF_EVENT_ARRAY",
    5: "PERCPU_HASH",
    6: "PERCPU_ARRAY",
    7: "STACK_TRACE",
    8: "CGROUP_ARRAY",
    9: "LRU_HASH",
    10: "LRU_PERCPU_HASH",
    11: "LPM_TRIE",
    12: "ARRAY_OF_MAPS",
    13: "HASH_OF_MAPS",
    14: "DEVMAP",
    15: "SOCKMAP",
    16: "CPUMAP",
    17: "XSKMAP",
    18: "SOCKHASH",
    19: "CGROUP_STORAGE",
    20: "REUSEPORT_SOCKARRAY",
    21: "PERCPU_CGROUP_STORAGE",
    22: "QUEUE",
    23: "STACK",
    24: "SK_STORAGE",
    25: "DEVMAP_HASH",
    26: "STRUCT_OPS",
    27: "RINGBUF",
    28: "INODE_STORAGE",
    29: "TASK_STORAGE",
    30: "BLOOM_FILTER",
    31: "USER_RINGBUF",
    32: "CGRP_STORAGE",
    33: "ARENA",
}

PERCPU_MAP_TYPES = frozenset({5, 6, 10, 21})
FD_MAP_TYPES = frozenset({3, 4, 8, 12, 13})

FTRACE_OPS_FL = (
    (1 << 0, "ENABLED"),
    (1 << 1, "DYNAMIC"),
    (1 << 2, "SAVE_REGS"),
    (1 << 3, "SAVE_REGS_IF_SUPPORTED"),
    (1 << 4, "RECURSION"),
    (1 << 5, "STUB"),
    (1 << 6, "INITIALIZED"),
    (1 << 7, "DELETED"),
    (1 << 8, "ADDING"),
    (1 << 9, "REMOVING"),
    (1 << 10, "MODIFYING"),
    (1 << 11, "ALLOC_TRAMP"),
    (1 << 12, "IPMODIFY"),
    (1 << 13, "PID"),
    (1 << 14, "RCU"),
    (1 << 15, "TRACE_ARRAY"),
    (1 << 16, "PERMANENT"),
    (1 << 17, "DIRECT"),
)

_STRUCT_FIELD_CACHE = {}


def dbg(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")


def ptr_int(val):
    """Coerce a pykdump pointer / SmartString / int to a Python int."""
    if val is None:
        return 0
    try:
        iv = int(val)
        return iv if iv >= 0 else iv & 0xFFFFFFFFFFFFFFFF
    except (TypeError, ValueError):
        pass
    text = str(val).split()[0].strip()
    if not text or text in ("(nil)", "NULL", "0x0"):
        return 0
    try:
        return int(text, 0)
    except ValueError:
        return 0


def is_kptr(addr):
    """True for a plausible kernel virtual address (x86_64 / aarch64)."""
    try:
        addr = int(addr)
    except (TypeError, ValueError):
        return False
    if addr == 0:
        return False
    # Canonical kernel range; also accept module/JIT space (ffffc...).
    return addr >= 0xFFFF800000000000


def member_offset(typename, member):
    key = (typename, member)
    if key in _STRUCT_FIELD_CACHE:
        return _STRUCT_FIELD_CACHE[key]
    off = None
    names = (typename,)
    if not typename.startswith("struct "):
        names = (f"struct {typename}", typename)
    try:
        import crash as _cr
        if hasattr(_cr, "member_offset"):
            for name in names:
                try:
                    raw = _cr.member_offset(name, member)
                    if raw is not None and raw != -1:
                        off = int(raw)
                        break
                except Exception:
                    continue
    except Exception:
        off = None
    if off is None:
        for name in names:
            try:
                out = exec_crash_command(f"struct {name} -o")
                m = re.search(
                    rf"^\s*\[(0x[0-9a-fA-F]+|\d+)\]\s+.*\b{re.escape(member)}\b",
                    out,
                    re.MULTILINE,
                )
                if m:
                    off = int(m.group(1), 0)
                    break
            except Exception:
                continue
    _STRUCT_FIELD_CACHE[key] = off
    return off


def has_member(typename, member):
    return member_offset(typename, member) is not None


def struct_size(typename):
    names = (typename,)
    if not typename.startswith("struct "):
        names = (f"struct {typename}", typename)
    try:
        import crash as _cr
        if hasattr(_cr, "struct_size"):
            for name in names:
                try:
                    sz = _cr.struct_size(name)
                    if sz and sz > 0:
                        return int(sz)
                except Exception:
                    continue
    except Exception:
        pass
    for name in names:
        try:
            out = exec_crash_command(f"struct {name} -o")
            m = re.search(r"SIZE:\s*(0x[0-9a-fA-F]+|\d+)", out)
            if m:
                return int(m.group(1), 0)
        except Exception:
            continue
    return None


def read_cstr(addr, maxlen=128):
    addr = ptr_int(addr)
    if not addr:
        return ""
    for call in (
        lambda: readStr(addr, maxlen),
        lambda: readStr(addr),
    ):
        try:
            s = call()
            if s:
                return str(s).split("\x00")[0]
        except Exception:
            continue
    try:
        out = exec_crash_command(f"rd -a {addr:#x}")
        line = out.strip().splitlines()[0] if out.strip() else ""
        if ":" in line:
            return line.split(":", 1)[1].strip().strip('"')
        return line.strip().strip('"')
    except Exception:
        return ""


def addr2name(addr):
    addr = ptr_int(addr)
    if not addr:
        return ""
    try:
        name = addr2sym(addr)
        if name:
            return str(name)
    except Exception:
        pass
    try:
        out = exec_crash_command(f"sym {addr:#x}").strip()
        if out:
            return out.splitlines()[0]
    except Exception:
        pass
    return ""


def enum_name(val, mapping):
    """Return a short name (e.g. TRACING, TRACE_FEXIT) for a C enum field."""
    text = str(val).strip()
    token = text.split()[0] if text else ""
    if token.startswith("BPF_PROG_TYPE_"):
        return token[len("BPF_PROG_TYPE_"):]
    if token.startswith("BPF_MAP_TYPE_"):
        return token[len("BPF_MAP_TYPE_"):]
    if token.startswith("BPF_"):
        return token[len("BPF_"):]
    try:
        iv = int(val)
    except (TypeError, ValueError):
        try:
            iv = int(token, 0)
        except ValueError:
            return text or "?"
    return mapping.get(iv, str(iv))


def decode_ftrace_ops_flags(flags):
    flags = int(flags) & 0xFFFFFFFFFFFFFFFF
    names = [name for bit, name in FTRACE_OPS_FL if flags & bit]
    extra = flags & ~sum(bit for bit, _ in FTRACE_OPS_FL)
    if extra:
        names.append(f"unknown:{extra:#x}")
    return "|".join(names) if names else "0"


def getattr_ptr(obj, *names):
    for name in names:
        try:
            return ptr_int(getattr(obj, name))
        except Exception:
            continue
    return 0


def resolve_address(value):
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.startswith("0x") or text.startswith("0X"):
        return int(text, 16)
    if all(c in "0123456789abcdefABCDEF" for c in text):
        return int(text, 16)
    try:
        if symbol_exists(text):
            return ptr_int(readSymbol(text))
    except Exception:
        pass
    raise ValueError(f"'{value}' is neither a valid address nor a known symbol")


def read_su(typename, addr):
    names = (typename,)
    if not typename.startswith("struct "):
        names = (f"struct {typename}", typename)
    last = None
    for name in names:
        try:
            return readSU(name, addr)
        except Exception as e:
            last = e
    raise last


def walk_hlist(head_addr, maxel=HLIST_WALK_MAX):
    """Yield hlist_node addresses starting from hlist_head.first."""
    seen = set()
    try:
        head = read_su("hlist_head", head_addr)
        node = ptr_int(head.first)
    except Exception as e:
        dbg(f"walk_hlist: cannot read hlist_head {head_addr:#x}: {e}")
        return
    while node:
        if node in seen:
            dbg(f"walk_hlist: cycle at {node:#x}")
            break
        if not is_kptr(node):
            dbg(f"walk_hlist: stopping on non-kptr {node:#x}")
            break
        seen.add(node)
        yield node
        if len(seen) >= maxel:
            dbg(f"walk_hlist: hit max {maxel}")
            break
        try:
            hnode = read_su("hlist_node", node)
            nxt = ptr_int(hnode.next)
        except Exception as e:
            dbg(f"walk_hlist: cannot read hlist_node {node:#x}: {e}")
            break
        if nxt == node:
            break
        node = nxt


def walk_list_head(head_addr, node_offset, maxel=100000):
    """Yield containing-object addresses from a list_head at head_addr."""
    seen = set()
    try:
        head = read_su("list_head", head_addr)
        node = ptr_int(head.next)
    except Exception as e:
        dbg(f"walk_list_head: cannot read list_head {head_addr:#x}: {e}")
        return
    while node and node != head_addr:
        if node in seen:
            dbg(f"walk_list_head: cycle at {node:#x}")
            break
        if not is_kptr(node):
            break
        seen.add(node)
        yield node - node_offset
        if len(seen) >= maxel:
            dbg(f"walk_list_head: hit max {maxel}")
            break
        try:
            lh = read_su("list_head", node)
            node = ptr_int(lh.next)
        except Exception as e:
            dbg(f"walk_list_head: cannot read list_head {node:#x}: {e}")
            break


def tramp_kind_count(tr):
    try:
        return len(tr.progs_hlist)
    except Exception:
        return 3


def looks_like_bpf_prog(addr):
    if not is_kptr(addr):
        return False
    try:
        prog = read_su("bpf_prog", addr)
        ptype = int(prog.type)
        length = int(prog.len)
        aux = ptr_int(prog.aux)
        if ptype < 0 or ptype > 64:
            return False
        if length <= 0 or length > 1_000_000:
            return False
        if not is_kptr(aux):
            return False
        aux_obj = read_su("bpf_prog_aux", aux)
        back = ptr_int(aux_obj.prog)
        return back == 0 or back == addr
    except Exception as e:
        dbg(f"looks_like_bpf_prog({addr:#x}) failed: {e}")
        return False


def looks_like_trampoline(addr):
    if not is_kptr(addr):
        return False
    try:
        tr = read_su("bpf_trampoline", addr)
    except Exception as e:
        dbg(f"looks_like_trampoline: read failed {addr:#x}: {e}")
        return False
    try:
        nkind = tramp_kind_count(tr)
        if nkind < 1 or nkind > 8:
            return False
    except Exception:
        return False
    fops = getattr_ptr(tr, "fops")
    if fops:
        if not is_kptr(fops):
            return False
        try:
            ops = read_su("ftrace_ops", fops)
            priv = ptr_int(ops.private)
            if priv == addr:
                return True
        except Exception:
            pass
    # No fops field (vanilla 5.14) — accept if progs_cnt looks sane.
    try:
        for i in range(tramp_kind_count(tr)):
            cnt = int(tr.progs_cnt[i])
            if cnt < 0 or cnt > HLIST_WALK_MAX:
                return False
        return True
    except Exception:
        return False


def looks_like_ftrace_ops(addr):
    if not is_kptr(addr):
        return False
    try:
        ops = read_su("ftrace_ops", addr)
        flags = int(ops.flags)
        # Completely unused ops are possible, but garbage flags are not.
        if flags > 0xFFFFFFFF:
            return False
        func = ptr_int(ops.func)
        priv = ptr_int(ops.private)
        if func and not is_kptr(func) and func > 0x1000:
            return False
        if priv and not is_kptr(priv):
            return False
        return True
    except Exception as e:
        dbg(f"looks_like_ftrace_ops({addr:#x}) failed: {e}")
        return False


def prog_info(prog_addr):
    """Return a dict describing a bpf_prog, or None."""
    prog_addr = ptr_int(prog_addr)
    if not is_kptr(prog_addr):
        return None
    try:
        prog = read_su("bpf_prog", prog_addr)
        aux_addr = ptr_int(prog.aux)
        aux = read_su("bpf_prog_aux", aux_addr) if is_kptr(aux_addr) else None
    except Exception as e:
        dbg(f"prog_info({prog_addr:#x}) failed: {e}")
        return None

    info = {
        "prog": prog_addr,
        "aux": aux_addr,
        "id": None,
        "name": "",
        "type": "",
        "attach": "",
        "attach_func": "",
        "jited": None,
        "len": None,
        "jited_len": None,
    }
    try:
        info["type"] = enum_name(prog.type, BPF_PROG_TYPES)
    except Exception:
        pass
    try:
        info["attach"] = enum_name(prog.expected_attach_type, BPF_ATTACH_TYPES)
    except Exception:
        pass
    try:
        info["jited"] = int(prog.jited)
        info["len"] = int(prog.len)
        info["jited_len"] = int(prog.jited_len)
    except Exception:
        pass

    if aux is not None:
        try:
            info["id"] = int(aux.id)
        except Exception:
            pass
        try:
            raw_name = aux.name
            name = str(raw_name).split("\x00")[0].strip()
            # pykdump may print the char array as a quoted string
            info["name"] = name.strip('"')
        except Exception:
            pass
        try:
            info["attach_func"] = read_cstr(aux.attach_func_name)
        except Exception:
            pass
    return info


def collect_progs_from_trampoline(tr_addr):
    """Return list of (kind_index, kind_name, prog_info [, link_id])."""
    tr = read_su("bpf_trampoline", tr_addr)
    results = []
    nkind = tramp_kind_count(tr)
    use_tramp_link = has_member("bpf_tramp_link", "tramp_hlist")
    use_aux_hlist = has_member("bpf_prog_aux", "tramp_hlist")
    hlist_base = member_offset("bpf_trampoline", "progs_hlist")
    head_sz = struct_size("hlist_head") or 8
    dbg(f"trampoline {tr_addr:#x}: kinds={nkind} "
        f"tramp_link={use_tramp_link} aux_hlist={use_aux_hlist} "
        f"progs_hlist_off={hlist_base}")

    # freplace / BPF_PROG_TYPE_EXT lives on extension_prog, not the hlist.
    ext = getattr_ptr(tr, "extension_prog")
    if looks_like_bpf_prog(ext):
        info = prog_info(ext)
        if info:
            results.append((None, "REPLACE", info, None))

    for kind in range(nkind):
        try:
            cnt = int(tr.progs_cnt[kind])
        except Exception:
            cnt = None
        head_addr = None
        if hlist_base is not None:
            head_addr = tr_addr + hlist_base + kind * head_sz
        else:
            try:
                head_addr = int(tr.progs_hlist[kind])
            except Exception as e:
                dbg(f"progs_hlist[{kind}] unavailable: {e}")
                continue
        kind_name = TRAMP_KIND_NAMES.get(kind, f"kind{kind}")
        dbg(f"kind {kind} ({kind_name}) cnt={cnt} head={head_addr:#x}")
        if cnt == 0:
            # Still walk in case the counter is stale.
            pass
        hlist_off = None
        if use_tramp_link:
            hlist_off = member_offset("bpf_tramp_link", "tramp_hlist")
        elif use_aux_hlist:
            hlist_off = member_offset("bpf_prog_aux", "tramp_hlist")
        if hlist_off is None:
            # Last resort: assume hlist node is at a known offset after bpf_link.
            if use_tramp_link:
                hlist_off = struct_size("bpf_link") or 0x30
            else:
                dbg("cannot determine tramp_hlist offset")
                continue

        for node in walk_hlist(head_addr):
            obj_addr = node - hlist_off
            link_id = None
            paddr = 0
            if use_tramp_link:
                try:
                    tlink = read_su("bpf_tramp_link", obj_addr)
                    paddr = ptr_int(tlink.link.prog)
                    try:
                        link_id = int(tlink.link.id)
                    except Exception:
                        link_id = None
                except Exception as e:
                    dbg(f"bpf_tramp_link {obj_addr:#x} failed: {e}")
                    continue
            else:
                try:
                    aux = read_su("bpf_prog_aux", obj_addr)
                    paddr = ptr_int(aux.prog)
                except Exception as e:
                    dbg(f"bpf_prog_aux {obj_addr:#x} failed: {e}")
                    continue
            info = prog_info(paddr)
            if info:
                results.append((kind, kind_name, info, link_id))
            else:
                dbg(f"skip unreadable prog {paddr:#x} from node {node:#x}")
    return results


def trampoline_table_symbol():
    for name in ("trampoline_table", "trampoline_key_table"):
        try:
            if symbol_exists(name):
                return name
        except Exception:
            continue
        # symbol_exists may miss static arrays; try readSymbol anyway.
        try:
            readSymbol(name)
            return name
        except Exception:
            continue
    return None


def iter_all_trampolines():
    """Yield bpf_trampoline addresses from trampoline_table[]."""
    sym = trampoline_table_symbol()
    if not sym:
        dbg("trampoline_table symbol not found")
        return
    try:
        table = readSymbol(sym)
    except Exception as e:
        dbg(f"readSymbol({sym}) failed: {e}")
        return
    hlist_off = member_offset("bpf_trampoline", "hlist")
    if hlist_off is None:
        hlist_off = member_offset("bpf_trampoline", "hlist_key")
    if hlist_off is None:
        hlist_off = 0
    head_size = struct_size("hlist_head") or 8
    table_addr = ptr_int(table)
    dbg(f"scanning {sym} at {table_addr:#x}, hlist_off={hlist_off}")
    for i in range(TRAMPOLINE_TABLE_SIZE):
        head_addr = table_addr + i * head_size
        for node in walk_hlist(head_addr, maxel=256):
            yield node - hlist_off


def find_trampoline_by_fops(fops_addr):
    for tr_addr in iter_all_trampolines():
        try:
            tr = read_su("bpf_trampoline", tr_addr)
            if getattr_ptr(tr, "fops") == fops_addr:
                return tr_addr
        except Exception:
            continue
    return None


_TRAMPOLINE_LIST = None


def all_trampoline_addrs():
    global _TRAMPOLINE_LIST
    if _TRAMPOLINE_LIST is None:
        _TRAMPOLINE_LIST = list(iter_all_trampolines())
        dbg(f"cached {len(_TRAMPOLINE_LIST)} bpf_trampoline object(s)")
    return _TRAMPOLINE_LIST


def find_trampoline_by_key(key):
    key = int(key)
    for tr_addr in all_trampoline_addrs():
        try:
            tr = read_su("bpf_trampoline", tr_addr)
            if int(tr.key) == key:
                return tr_addr
        except Exception:
            continue
    return None


def find_trampoline_by_image(image_addr):
    image_addr = ptr_int(image_addr)
    if not image_addr:
        return None
    for tr_addr in all_trampoline_addrs():
        try:
            tr = read_su("bpf_trampoline", tr_addr)
            if getattr_ptr(tr, "cur_image") == image_addr:
                return tr_addr
        except Exception:
            continue
    return None


def embedded_cstr(obj_addr, typename, member, maxlen=512):
    off = member_offset(typename, member)
    if off is not None:
        s = read_cstr(obj_addr + off, maxlen)
        if s:
            return s
    return ""


def ksym_name_at(ksym_addr, ksym=None):
    s = embedded_cstr(ksym_addr, "bpf_ksym", "name", 512)
    if s:
        return s
    if ksym is not None:
        try:
            return str(ksym.name).split("\x00")[0].strip().strip('"')
        except Exception:
            pass
    return ""


def symbol_basename(text):
    if not text:
        return ""
    s = str(text).replace("<", " ").replace(">", " ").strip()
    tok = s.split()[-1] if s.split() else s
    return tok.split("+")[0].split("/")[-1]


def name_matches(candidate, needle):
    if not candidate or not needle:
        return False
    if candidate == needle:
        return True
    return len(needle) >= 4 and needle in candidate


def trampoline_image_name(tr):
    img = getattr_ptr(tr, "cur_image")
    if not is_kptr(img):
        return "", img
    ksym_off = member_offset("bpf_tramp_image", "ksym")
    if ksym_off is None:
        ksym_off = 0x10
    return ksym_name_at(img + ksym_off), img


def try_kprobe_multi_from_ops(ops_addr):
    """
    fprobe.ops is the first field of struct fprobe when FUNCTION_TRACER is
    set, and bpf_kprobe_multi_link is { bpf_link; fprobe fp; ... }.
    """
    link_sz = struct_size("bpf_link")
    if not link_sz:
        return None
    ops_off = member_offset("fprobe", "ops")
    if ops_off is None:
        ops_off = 0
    fp_addr = ops_addr - ops_off
    link_addr = fp_addr - link_sz
    if not is_kptr(link_addr):
        return None
    try:
        link = read_su("bpf_link", link_addr)
        paddr = ptr_int(link.prog)
        if not looks_like_bpf_prog(paddr):
            return None
        info = prog_info(paddr)
        if not info:
            return None
        try:
            link_id = int(link.id)
        except Exception:
            link_id = None
        return {
            "link": link_addr,
            "link_id": link_id,
            "info": info,
        }
    except Exception as e:
        dbg(f"try_kprobe_multi_from_ops failed: {e}")
        return None


def classify_address(addr, force=None):
    """
    Return (kind, payload) where kind is 'ftrace_ops', 'bpf_trampoline',
    'kprobe_multi', or 'bpf_prog'.
    """
    if force == "ftrace_ops":
        if not looks_like_ftrace_ops(addr):
            raise ValueError(f"{addr:#x} does not look like struct ftrace_ops")
        kind, payload = resolve_from_ftrace_ops(addr)
        if not kind:
            raise ValueError(
                f"{addr:#x} looks like ftrace_ops but is not linked to a "
                "BPF trampoline, bpf_prog, or kprobe-multi link"
            )
        return kind, payload
    if force == "trampoline":
        if not looks_like_trampoline(addr):
            raise ValueError(
                f"{addr:#x} does not look like struct bpf_trampoline"
            )
        return ("bpf_trampoline", addr)

    # Auto-detect.  Prefer the back-pointer check (fops <-> private).
    ops_hit = looks_like_ftrace_ops(addr)
    tr_hit = looks_like_trampoline(addr)

    if ops_hit:
        kind, payload = resolve_from_ftrace_ops(addr)
        if kind:
            return kind, payload

    if tr_hit:
        return ("bpf_trampoline", addr)

    if ops_hit:
        km = try_kprobe_multi_from_ops(addr)
        if km:
            return ("kprobe_multi", km)

    raise ValueError(
        f"{addr:#x} is not a recognisable ftrace_ops or bpf_trampoline"
    )


def resolve_from_ftrace_ops(ops_addr):
    ops = read_su("ftrace_ops", ops_addr)
    priv = ptr_int(ops.private)

    ops_func = getattr_ptr(ops, "ops_func")
    ops_func_name = addr2name(ops_func) if ops_func else ""
    dbg(f"ftrace_ops {ops_addr:#x} private={priv:#x} "
        f"ops_func={ops_func_name or hex(ops_func)}")

    # Canonical trampoline path: private is the bpf_trampoline.
    if looks_like_trampoline(priv):
        try:
            tr = read_su("bpf_trampoline", priv)
            fops = getattr_ptr(tr, "fops")
            if fops in (0, ops_addr) or "bpf_tramp_ftrace_ops_func" in ops_func_name:
                return ("ftrace_ops", priv)
            # private looks like a trampoline even if fops doesn't match
            return ("ftrace_ops", priv)
        except Exception:
            return ("ftrace_ops", priv)

    # Some attachments stash the bpf_prog directly in private.
    if looks_like_bpf_prog(priv):
        return ("bpf_prog", priv)

    # Shared / unmatched fops: search trampoline_table.
    tr_addr = find_trampoline_by_fops(ops_addr)
    if tr_addr:
        return ("ftrace_ops", tr_addr)

    km = try_kprobe_multi_from_ops(ops_addr)
    if km:
        return ("kprobe_multi", km)

    return (None, None)


def print_ftrace_ops(ops_addr, verbose=False):
    ops = read_su("ftrace_ops", ops_addr)
    flags = int(ops.flags)
    func = ptr_int(ops.func)
    priv = ptr_int(ops.private)
    saved = getattr_ptr(ops, "saved_func")
    tramp = getattr_ptr(ops, "trampoline")
    ops_func = getattr_ptr(ops, "ops_func")
    print(f"struct ftrace_ops *        {ops_addr:#x}")
    print(f"  func                     {func:#x}  {addr2name(func)}")
    print(f"  flags                    {flags:#x}  ({decode_ftrace_ops_flags(flags)})")
    print(f"  private                  {priv:#x}")
    if verbose:
        print(f"  saved_func               {saved:#x}  {addr2name(saved)}")
        print(f"  trampoline (code)        {tramp:#x}  {addr2name(tramp)}")
        print(f"  ops_func                 {ops_func:#x}  {addr2name(ops_func)}")


def print_trampoline(tr_addr, verbose=False):
    tr = read_su("bpf_trampoline", tr_addr)
    fops = getattr_ptr(tr, "fops")
    key = getattr_ptr(tr, "key")
    flags = getattr_ptr(tr, "flags")
    try:
        refcnt = int(tr.refcnt.refs.counter)
    except Exception:
        try:
            refcnt = int(tr.refcnt.counter)
        except Exception:
            refcnt = None
    func_addr = 0
    ftrace_managed = None
    try:
        func_addr = ptr_int(tr.func.addr)
        ftrace_managed = bool(int(tr.func.ftrace_managed))
    except Exception:
        pass
    print(f"struct bpf_trampoline *    {tr_addr:#x}")
    if key:
        print(f"  key                      {key:#x}")
    if refcnt is not None:
        print(f"  refcnt                   {refcnt}")
    if flags:
        print(f"  flags                    {flags:#x}")
    print(f"  func.addr                {func_addr:#x}  {addr2name(func_addr)}")
    if ftrace_managed is not None:
        print(f"  func.ftrace_managed      {ftrace_managed}")
    if fops:
        print(f"  fops                     {fops:#x}")
    ext = getattr_ptr(tr, "extension_prog")
    if ext:
        print(f"  extension_prog           {ext:#x}")
    if verbose:
        nkind = tramp_kind_count(tr)
        for i in range(nkind):
            try:
                cnt = int(tr.progs_cnt[i])
            except Exception:
                cnt = "?"
            hlist_base = member_offset("bpf_trampoline", "progs_hlist")
            head_sz = struct_size("hlist_head") or 8
            if hlist_base is not None:
                head = tr_addr + hlist_base + i * head_sz
            else:
                head = 0
            print(f"  progs_hlist[{i}] {TRAMP_KIND_NAMES.get(i, '?'):<14}  "
                  f"cnt={cnt}  head={head:#x}")


def print_prog_table(rows, verbose=False):
    if not rows:
        print("\nNo attached BPF programs found.")
        return []

    print("\nAttached BPF program(s):")
    hdr = (f"{'KIND':<16} {'ID':>6}  {'BPF_PROG':<18} {'NAME':<20} "
           f"{'TYPE':<22} {'ATTACH':<22} {'TARGET'}")
    print(hdr)
    print("-" * len(hdr))
    ids = []
    for kind, kind_name, info, link_id in rows:
        pid = info.get("id")
        if pid is not None:
            ids.append(pid)
        pid_s = "-" if pid is None else str(pid)
        print(f"{kind_name:<16} {pid_s:>6}  {info['prog']:#018x} "
              f"{(info.get('name') or '-'):<20} "
              f"{(info.get('type') or '-'):<22} "
              f"{(info.get('attach') or '-'):<22} "
              f"{info.get('attach_func') or '-'}")
        if verbose:
            extra = []
            if link_id is not None:
                extra.append(f"link_id={link_id}")
            if info.get("aux"):
                extra.append(f"aux={info['aux']:#x}")
            if info.get("jited") is not None:
                extra.append(f"jited={info['jited']}")
            if info.get("len") is not None:
                extra.append(f"xlated_len={info['len']}")
            if info.get("jited_len") is not None:
                extra.append(f"jited_len={info['jited_len']}")
            if extra:
                print(f"{'':16}        " + "  ".join(extra))

    uniq = []
    for i in ids:
        if i not in uniq:
            uniq.append(i)
    print()
    if len(uniq) == 1:
        print(f"BPF ID: {uniq[0]}")
        print(f"Hint:   crash> bpf -p {uniq[0]} -s")
        print(f"        crash> chk_bpf -p {uniq[0]} -m")
    elif uniq:
        print("BPF IDs: " + ", ".join(str(i) for i in uniq))
        print("Hint:    crash> bpf -p <ID> -s")
        print("         crash> chk_bpf -p <ID> -m")
    return uniq


def crash_cmd(cmd):
    """Run a crash command and return stdout, or None on failure."""
    try:
        out = exec_crash_command(cmd)
    except Exception as e:
        dbg(f"crash '{cmd}' failed: {e}")
        return None
    if out is None:
        return None
    return out if isinstance(out, str) else str(out)


def parse_bpf_prog_output(text):
    """Parse `bpf -p ID` output into prog/aux addresses and used-map IDs."""
    info = {
        "id": None,
        "prog": None,
        "aux": None,
        "type": "",
        "tag": "",
        "used_map_ids": [],
    }
    if not text:
        return info
    low = text.lower()
    if "invalid program id" in low:
        return info
    for line in text.splitlines():
        if "BPF_PROG" in line and "USED_MAPS" in line:
            continue
        m = re.match(
            r"^\s*(\d+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S+)\s+"
            r"([0-9a-fA-F]{8,})\s*(.*)$",
            line,
        )
        if not m:
            continue
        info["id"] = int(m.group(1))
        info["prog"] = int(m.group(2), 16)
        info["aux"] = int(m.group(3), 16)
        info["type"] = m.group(4)
        info["tag"] = m.group(5)
        rest = m.group(6).strip()
        if rest:
            ids = []
            for tok in rest.split(","):
                tok = tok.strip()
                if tok.isdigit():
                    ids.append(int(tok))
            info["used_map_ids"] = ids
        break
    return info


def page_size():
    try:
        import crash as _cr
        if hasattr(_cr, "PAGESIZE"):
            return int(_cr.PAGESIZE)
    except Exception:
        pass
    return 4096


def cpu_count():
    try:
        out = exec_crash_command("sys")
        m = re.search(r"\bCPUS:\s*(\d+)\b", out)
        if m:
            return int(m.group(1))
        m = re.search(r"\bCPUS:\s*0-(\d+)\b", out)
        if m:
            return int(m.group(1)) + 1
    except Exception:
        pass
    return 1


def round_up(n, align):
    if align <= 0:
        return n
    return (n + align - 1) // align * align


def map_type_code(val):
    try:
        return int(val)
    except (TypeError, ValueError):
        name = enum_name(val, BPF_MAP_TYPES)
        for code, n in BPF_MAP_TYPES.items():
            if n == name or n == str(val) or str(val).endswith(n):
                return code
        return -1


def map_memlock_bytes(bpf_map):
    """Match crash's bpf MEMLOCK: memory.pages, pages, or size estimate."""
    ps = page_size()
    try:
        pages = int(bpf_map.memory.pages)
        if pages > 0:
            return pages * ps
    except Exception:
        pass
    try:
        pages = int(bpf_map.pages)
        if pages > 0:
            return pages * ps
    except Exception:
        pass
    try:
        key_size = int(bpf_map.key_size)
        value_size = int(bpf_map.value_size)
        max_entries = int(bpf_map.max_entries)
        mtype = map_type_code(bpf_map.map_type)
    except Exception:
        return None
    if mtype == 27:  # RINGBUF — leave to crash if possible
        return None
    if mtype in PERCPU_MAP_TYPES:
        valsize = round_up(value_size, 8) * max(cpu_count(), 1)
    elif mtype in FD_MAP_TYPES:
        valsize = 4
    else:
        valsize = value_size
    size = round_up(key_size + valsize, 8) * max_entries
    return round_up(size, ps)


def map_uid_string(bpf_map):
    user = 0
    try:
        user = ptr_int(bpf_map.memory.user)
    except Exception:
        pass
    if not user:
        user = getattr_ptr(bpf_map, "user")
    if not user or not is_kptr(user):
        return "(unused)"
    try:
        us = read_su("user_struct", user)
        return str(int(us.uid))
    except Exception:
        try:
            us = read_su("user_struct", user)
            return str(int(us.uid.val))
        except Exception:
            return "(unknown)"


def map_name_string(bpf_map):
    try:
        name = str(bpf_map.name).split("\x00")[0].strip().strip('"')
        return f'"{name}"' if name else "(unused)"
    except Exception:
        return "(unknown)"


def iter_used_maps(aux_addr):
    """Yield dicts {id, addr} from bpf_prog_aux.used_maps[] in program order."""
    aux_addr = ptr_int(aux_addr)
    if not is_kptr(aux_addr):
        return
    try:
        aux = read_su("bpf_prog_aux", aux_addr)
        cnt = int(aux.used_map_cnt)
        maps_ptr = ptr_int(aux.used_maps)
    except Exception as e:
        dbg(f"iter_used_maps: aux {aux_addr:#x} failed: {e}")
        return
    if cnt <= 0 or not is_kptr(maps_ptr):
        dbg(f"iter_used_maps: cnt={cnt} used_maps={maps_ptr:#x}")
        return
    if cnt > 512:
        dbg(f"iter_used_maps: capping used_map_cnt {cnt} to 512")
        cnt = 512
    psz = 8
    for i in range(cnt):
        try:
            maddr = ptr_int(readPtr(maps_ptr + i * psz))
        except Exception as e:
            dbg(f"iter_used_maps[{i}]: readPtr failed: {e}")
            continue
        if not is_kptr(maddr):
            continue
        mid = None
        try:
            mmap = read_su("bpf_map", maddr)
            mid = int(mmap.id)
        except Exception as e:
            dbg(f"iter_used_maps[{i}]: bpf_map {maddr:#x} failed: {e}")
        yield {"id": mid, "addr": maddr}


def print_map_from_struct(map_addr):
    """Crash-style bpf -m dump from struct bpf_map (fallback)."""
    bpf_map = read_su("bpf_map", map_addr)
    try:
        mid = int(bpf_map.id)
    except Exception:
        mid = 0
    mtype = enum_name(bpf_map.map_type, BPF_MAP_TYPES)
    try:
        flags = int(bpf_map.map_flags) & 0xFFFFFFFF
    except Exception:
        flags = 0
    try:
        key_s = str(int(bpf_map.key_size))
    except Exception:
        key_s = "(unknown)"
    try:
        value_s = str(int(bpf_map.value_size))
    except Exception:
        value_s = "(unknown)"
    try:
        max_s = str(int(bpf_map.max_entries))
    except Exception:
        max_s = "(unknown)"
    memlock = map_memlock_bytes(bpf_map)
    mem_s = str(memlock) if memlock is not None else "(unknown)"
    print(" ID      BPF_MAP               BPF_MAP_TYPE           MAP_FLAGS")
    print(f"{mid:3d}  {map_addr:016x}  {mtype:>20s}               {flags:08x}")
    print(f"     KEY_SIZE: {key_s}  VALUE_SIZE: {value_s}  "
          f"MAX_ENTRIES: {max_s}  MEMLOCK: {mem_s}")
    print(f"     NAME: {map_name_string(bpf_map)}  UID: {map_uid_string(bpf_map)}")


def dump_one_map(map_id=None, map_addr=None):
    """Print one map, preferring crash `bpf -m ID` for identical formatting."""
    if map_id is not None:
        out = crash_cmd(f"bpf -m {map_id}")
        if out and "invalid map id" not in out.lower():
            print(out.rstrip("\n"))
            return True
        dbg(f"bpf -m {map_id} unavailable, falling back to struct")
    if map_addr and is_kptr(map_addr):
        try:
            print_map_from_struct(map_addr)
            return True
        except Exception as e:
            dbg(f"print_map_from_struct({map_addr:#x}) failed: {e}")
            print(f"Error: cannot dump map id={map_id} addr={map_addr:#x}: {e}")
            return False
    print(f"Error: cannot dump map id={map_id}")
    return False


def lookup_prog(prog_id):
    """Return (raw bpf -p output, parsed dict). Raises ValueError if missing."""
    out = crash_cmd(f"bpf -p {prog_id}")
    if not out or "invalid program id" in out.lower():
        raise ValueError(f"invalid program ID: {prog_id}")
    parsed = parse_bpf_prog_output(out)
    if parsed.get("id") is None and parsed.get("aux") is None:
        raise ValueError(f"invalid program ID: {prog_id}")
    return out, parsed


def show_prog(prog_id):
    """Wrapper for crash `bpf -p ID`."""
    out, _ = lookup_prog(prog_id)
    print(out.rstrip("\n"))


def collect_prog_maps(parsed):
    """Return used-map list [{id, addr}, ...] in bpf_prog_aux.used_maps order."""
    maps = []
    seen = set()
    if parsed.get("aux"):
        for m in iter_used_maps(parsed["aux"]):
            key = m.get("id") if m.get("id") is not None else m.get("addr")
            if key in seen:
                continue
            seen.add(key)
            maps.append(m)
    if not maps:
        for mid in parsed.get("used_map_ids") or []:
            if mid in seen:
                continue
            seen.add(mid)
            maps.append({"id": mid, "addr": None})
    return maps


def show_prog_maps(prog_id):
    """Dump every map referenced by bpf_prog_aux.used_maps for program ID."""
    _, parsed = lookup_prog(prog_id)
    maps = collect_prog_maps(parsed)
    if not maps:
        print(f"Program {prog_id} has no used maps.")
        return
    dbg(f"program {prog_id}: {len(maps)} used map(s)")
    first = True
    for m in maps:
        if not first:
            print()
        first = False
        dump_one_map(map_id=m.get("id"), map_addr=m.get("addr"))


def symbol_kaddr(name):
    """Kernel address of a symbol; prefer `sym` so list_head is the object, not .next."""
    try:
        out = exec_crash_command(f"sym {name}")
        m = re.search(r"\b(ffff[0-9a-fA-F]+|ffffffff[0-9a-fA-F]+)\b", out)
        if m:
            return int(m.group(1), 16)
        m = re.search(r"0x([0-9a-fA-F]+)", out)
        if m:
            return int(m.group(1), 16)
    except Exception as e:
        dbg(f"sym {name} failed: {e}")
    try:
        return ptr_int(readSymbol(name))
    except Exception:
        return 0


def bpf_kallsyms_head():
    return symbol_kaddr("bpf_kallsyms")


def aux_from_prog_ksym(ksym_addr):
    """container_of(ksym, bpf_prog_aux, ksym) if it looks valid."""
    off = member_offset("bpf_prog_aux", "ksym")
    if off is None:
        return None
    aux_addr = ksym_addr - off
    if not is_kptr(aux_addr):
        return None
    try:
        aux = read_su("bpf_prog_aux", aux_addr)
        paddr = ptr_int(aux.prog)
        if looks_like_bpf_prog(paddr):
            return aux_addr, paddr
    except Exception as e:
        dbg(f"aux_from_prog_ksym({ksym_addr:#x}) failed: {e}")
    return None


def trampoline_from_ksym(ksym_addr, kname=""):
    """
    bpf_ksym is embedded in bpf_tramp_image.  Find the owning bpf_trampoline
    via cur_image (trampoline_table walk) or the key encoded in the ksym name.
    """
    off = member_offset("bpf_tramp_image", "ksym")
    if off is None:
        off = 0x10
    image_addr = ksym_addr - off
    tr = find_trampoline_by_image(image_addr) if is_kptr(image_addr) else None
    if tr:
        return tr, image_addr
    m = re.fullmatch(r"bpf_trampoline_(\d+)", kname or "")
    if m:
        tr = find_trampoline_by_key(int(m.group(1)))
        if tr:
            return tr, image_addr
    return None, image_addr


def find_by_name(needle):
    """
    Resolve a function / trampoline / program name to trampolines and programs.

    Better than `search -k` / `kmem`: walk trampoline_table (by key, func.addr
    symbol, cur_image.ksym.name, attach_func_name) and bpf_kallsyms (prog vs
    trampoline ksyms) using DWARF member offsets.
    """
    tramp_hits = {}  # tr_addr -> list of reasons
    prog_hits = {}   # prog_addr -> {info, reasons}

    def add_tramp(tr_addr, reason):
        if not tr_addr:
            return
        tramp_hits.setdefault(tr_addr, [])
        if reason not in tramp_hits[tr_addr]:
            tramp_hits[tr_addr].append(reason)

    def add_prog(paddr, reason, info=None):
        if not paddr:
            return
        info = info or prog_info(paddr)
        if not info:
            return
        ent = prog_hits.setdefault(paddr, {"info": info, "reasons": []})
        if reason not in ent["reasons"]:
            ent["reasons"].append(reason)

    key_m = re.fullmatch(r"bpf_trampoline_(\d+)", needle)
    if key_m:
        tr = find_trampoline_by_key(int(key_m.group(1)))
        if tr:
            add_tramp(tr, f"trampoline_table key={key_m.group(1)}")

    # trampoline_table: func.addr symbol, image ksym name, attached names
    for tr_addr in all_trampoline_addrs():
        try:
            tr = read_su("bpf_trampoline", tr_addr)
        except Exception:
            continue
        reasons = []
        try:
            key = int(tr.key)
            if needle == str(key) or needle == f"bpf_trampoline_{key}":
                reasons.append(f"key={key}")
        except Exception:
            key = None
        func_addr = 0
        try:
            func_addr = ptr_int(tr.func.addr)
        except Exception:
            pass
        func_sym = symbol_basename(addr2name(func_addr)) if func_addr else ""
        if name_matches(func_sym, needle):
            reasons.append(f"func.addr {func_sym} ({func_addr:#x})")
        img_name, img = trampoline_image_name(tr)
        if name_matches(img_name, needle):
            reasons.append(f"cur_image.ksym.name {img_name}")
        # Attached program names / attach targets
        try:
            rows = collect_progs_from_trampoline(tr_addr)
        except Exception:
            rows = []
        for _kind, _kname, info, _lid in rows:
            if not info:
                continue
            if name_matches(info.get("attach_func") or "", needle):
                reasons.append(f"attach_func_name {info.get('attach_func')}")
            if name_matches(info.get("name") or "", needle):
                reasons.append(f"prog name {info.get('name')}")
        if reasons:
            add_tramp(tr_addr, "; ".join(dict.fromkeys(reasons)))

    # bpf_kallsyms: JIT program ksyms and trampoline image ksyms
    head = bpf_kallsyms_head()
    lnode_off = member_offset("bpf_ksym", "lnode")
    if head and lnode_off is not None:
        dbg(f"walking bpf_kallsyms at {head:#x}, lnode_off={lnode_off}")
        n = 0
        for ksym_addr in walk_list_head(head, lnode_off):
            n += 1
            try:
                ksym = read_su("bpf_ksym", ksym_addr)
            except Exception:
                continue
            kname = ksym_name_at(ksym_addr, ksym)
            if not name_matches(kname, needle):
                continue
            is_prog = False
            try:
                is_prog = bool(int(ksym.prog))
            except Exception:
                is_prog = kname.startswith("bpf_prog_")
            if is_prog:
                got = aux_from_prog_ksym(ksym_addr)
                if got:
                    aux_addr, paddr = got
                    add_prog(paddr, f"bpf_kallsyms prog ksym {kname} "
                             f"(ksym {ksym_addr:#x}, aux {aux_addr:#x})")
            else:
                tr, image = trampoline_from_ksym(ksym_addr, kname)
                if tr:
                    add_tramp(tr, f"bpf_kallsyms trampoline ksym {kname} "
                              f"(ksym {ksym_addr:#x}, image {image:#x})")
                elif image:
                    dbg(f"kallsyms trampoline ksym {kname} image {image:#x} "
                        "has no trampoline_table entry")
        dbg(f"walked {n} bpf_kallsyms entries")
    else:
        dbg("bpf_kallsyms not available")

    return tramp_hits, prog_hits


def analyze_name(needle, verbose=False, show_maps=False):
    print()
    print(f"Search name: {needle}")
    tramp_hits, prog_hits = find_by_name(needle)
    if not tramp_hits and not prog_hits:
        print("No match in trampoline_table or bpf_kallsyms.")
        return

    ids = []
    shown_progs = set()

    for i, (tr_addr, reasons) in enumerate(tramp_hits.items()):
        if i or prog_hits:
            print()
        print(f"Trampoline match via {reasons[0]}")
        for extra in reasons[1:]:
            print(f"  also: {extra}")
        print()
        print_trampoline(tr_addr, verbose=verbose)
        fops = getattr_ptr(read_su("bpf_trampoline", tr_addr), "fops")
        if fops and verbose:
            print()
            print_ftrace_ops(fops, verbose=True)
        rows = collect_progs_from_trampoline(tr_addr)
        found = print_prog_table(rows, verbose=verbose)
        ids.extend(found)
        for _k, _n, info, _l in rows:
            if info and info.get("prog"):
                shown_progs.add(info["prog"])

    orphan_rows = []
    for paddr, ent in prog_hits.items():
        if paddr in shown_progs:
            continue
        orphan_rows.append((None, "ksym", ent["info"], None))
        if verbose:
            print()
            print(f"Program ksym match: {'; '.join(ent['reasons'])}")

    if orphan_rows:
        print()
        print("Additional program ksym match(es) (not shown via a trampoline):")
        for paddr, ent in prog_hits.items():
            if paddr in shown_progs:
                continue
            print(f"  {'; '.join(ent['reasons'])}")
        found = print_prog_table(orphan_rows, verbose=verbose)
        ids.extend(found)

    uniq = []
    for i in ids:
        if i not in uniq:
            uniq.append(i)
    if show_maps and uniq:
        for pid in uniq:
            print()
            show_prog_maps(pid)


def analyze(addr, force=None, verbose=False, show_maps=False):
    kind, payload = classify_address(addr, force=force)
    print()
    print(f"Input address: {addr:#x}")

    ids = []
    if kind == "bpf_trampoline":
        print("Detected as:   struct bpf_trampoline *")
        print()
        print_trampoline(addr, verbose=verbose)
        fops = getattr_ptr(read_su("bpf_trampoline", addr), "fops")
        if fops and verbose:
            print()
            print_ftrace_ops(fops, verbose=True)
        rows = collect_progs_from_trampoline(addr)
        ids = print_prog_table(rows, verbose=verbose)
    elif kind == "ftrace_ops":
        print("Detected as:   struct ftrace_ops *  (BPF trampoline)")
        print()
        print_ftrace_ops(addr, verbose=verbose)
        print()
        print_trampoline(payload, verbose=verbose)
        rows = collect_progs_from_trampoline(payload)
        ids = print_prog_table(rows, verbose=verbose)
    elif kind == "bpf_prog":
        print("Detected as:   struct ftrace_ops *  (private -> bpf_prog)")
        print()
        print_ftrace_ops(addr, verbose=verbose)
        info = prog_info(payload)
        rows = [(None, "private", info, None)] if info else []
        ids = print_prog_table(rows, verbose=verbose)
    elif kind == "kprobe_multi":
        print("Detected as:   struct ftrace_ops *  (embedded in fprobe / "
              "kprobe-multi)")
        print()
        print_ftrace_ops(addr, verbose=verbose)
        print(f"  bpf_link                 {payload['link']:#x}")
        info = payload["info"]
        rows = [(None, "KPROBE_MULTI", info, payload.get("link_id"))]
        ids = print_prog_table(rows, verbose=verbose)
    else:
        raise ValueError(f"could not resolve BPF program from {addr:#x}")

    if show_maps and ids:
        for pid in ids:
            print()
            show_prog_maps(pid)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="chk_bpf",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Find BPF program ID(s) from a ftrace_ops or bpf_trampoline "
            "address, a program ID, or a function / trampoline name."
        ),
        epilog="""\
How it works
  BPF fentry/fexit/fmodify_return programs attach through struct bpf_trampoline.
  The trampoline's ftrace_ops.private pointer is the trampoline, and attached
  programs are linked on trampoline->progs_hlist[].  The program ID is
  bpf_prog->aux->id (the same ID shown by crash's `bpf` command).

  chk_bpf -p ID is a wrapper for crash `bpf -p ID`.  With -m, every map in
  bpf_prog_aux.used_maps is dumped (crash `bpf -m ID` per map).

  chk_bpf -n NAME looks up a kernel function, BPF program, or trampoline
  ksym name without `search`/`kmem`:
    - bpf_trampoline_<key>  -> trampoline_table keyed by that u64
    - trampoline_table walk -> func.addr symbol, cur_image.ksym.name,
                               attach_func_name, prog name
    - bpf_kallsyms walk     -> bpf_prog_aux.ksym (prog) or
                               bpf_tramp_image.ksym (trampoline), using
                               DWARF member offsets (not hardcoded 0x10/0xa8)

  If ADDR is not forced with -f/-t, the type is auto-detected using the
  fops <-> private back-pointer.  kprobe-multi attachments (fprobe-embedded
  ftrace_ops) are also recognised.

Examples
  crash> chk_bpf 0xffff8adde0fed000
  crash> chk_bpf -f 0xffff8adc8a9a4000
  crash> chk_bpf -t 0xffff8adc8a9a3f00 -v
  crash> chk_bpf -p 298
  crash> chk_bpf -p 298 -m
  crash> chk_bpf -n bpf_trampoline_6442501095
  crash> chk_bpf -n __ia32_sys_write
  crash> chk_bpf -n fs_write___ia32 -m
""",
    )
    parser.add_argument(
        "addr",
        nargs="?",
        metavar="ADDR",
        help="ftrace_ops or bpf_trampoline address (hex) or symbol",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-f", "--ftrace-ops",
        action="store_true",
        help="treat ADDR as struct ftrace_ops *",
    )
    group.add_argument(
        "-t", "--trampoline",
        action="store_true",
        help="treat ADDR as struct bpf_trampoline *",
    )
    parser.add_argument(
        "-p", "--prog",
        type=int,
        metavar="ID",
        help="BPF program ID (wrapper for crash `bpf -p ID`)",
    )
    parser.add_argument(
        "-n", "--name",
        metavar="NAME",
        help="kernel function, BPF prog, or bpf_trampoline_<key> ksym name",
    )
    parser.add_argument(
        "-m", "--maps",
        action="store_true",
        help="dump all maps used by the program (bpf_prog_aux.used_maps)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="print extra ftrace_ops / trampoline / prog fields",
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="debug output for struct walks",
    )
    return parser


def main(argv=None):
    global DEBUG
    parser = build_parser()
    args = parser.parse_args(argv)
    DEBUG = args.debug

    if args.prog is not None and args.addr:
        print("Error: use either ADDR or -p ID, not both")
        return 1
    if args.name and (args.addr or args.prog is not None):
        print("Error: use either -n NAME, ADDR, or -p ID")
        return 1
    if (args.ftrace_ops or args.trampoline) and (
            args.prog is not None or args.name):
        print("Error: -f/-t cannot be combined with -p or -n")
        return 1

    if args.name:
        try:
            analyze_name(args.name, verbose=args.verbose, show_maps=args.maps)
        except Exception as e:
            print(f"Error: name lookup for '{args.name}' failed: {e}")
            if DEBUG:
                raise
            return 1
        return 0

    if args.prog is not None:
        try:
            if args.maps:
                show_prog_maps(args.prog)
            else:
                show_prog(args.prog)
        except ValueError as e:
            print(f"Error: {e}")
            return 1
        except Exception as e:
            print(f"Error: failed to dump program {args.prog}: {e}")
            if DEBUG:
                raise
            return 1
        return 0

    if not args.addr:
        if args.maps:
            print("Error: -m requires -p ID, -n NAME, or ADDR")
            return 1
        parser.print_help()
        return 0

    try:
        addr = resolve_address(args.addr)
    except ValueError as e:
        print(f"Error: {e}")
        return 1

    force = None
    if args.ftrace_ops:
        force = "ftrace_ops"
    elif args.trampoline:
        force = "trampoline"

    try:
        analyze(addr, force=force, verbose=args.verbose, show_maps=args.maps)
    except ValueError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Error: failed to analyse {addr:#x}: {e}")
        if DEBUG:
            raise
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
