#!/usr/bin/env epython
"""
chk_cpu.py — CPU topology from a vmcore (crash / epython).

Default listing is --topo: physical id, core id, and cpu index.

    crash> chk_cpu
    crash> chk_cpu --topo
    crash> chk_cpu --topo -v
    crash> chk_cpu --highlight 0,64,127
    crash> chk_cpu --filter-cpu-index 0,64,127

x86 field names depend on the kernel:

    RHEL 9.6+ (cpuinfo_topology): topo.pkg_id, topo.core_id, cpu_index
    RHEL 7/8 and early RHEL 9:    phys_proc_id, cpu_core_id, cpu_index

aarch64 and s390 use cpu_topology (package_id or socket_id, plus core_id).
The cpu index there is the logical CPU number.
"""

import argparse
import re
import sys
from collections import namedtuple

from pykdump.API import *
from LinuxDump import percpu


DEBUG = False

Topo = namedtuple("Topo", "phys core cpu die apic")
_OFFSET_CACHE = {}
_SIZE_CACHE = {}

_FIELD_RE = re.compile(
    r"\b(pkg_id|phys_proc_id|package_id|socket_id|"
    r"core_id|cpu_core_id|cpu_index|"
    r"die_id|cpu_die_id|apicid|initialized)\s*=\s*"
    r"(-?(?:0x[0-9a-fA-F]+|\d+))"
)
_MODEL_RE = re.compile(r'x86_model_id\s*=\s*"([^"]*)"')
_PERCPU_ADDR_RE = re.compile(r"^\s*\[(\d+)\]:\s*(?:0x)?([0-9a-fA-F]{6,})\s*$")

_PHYS_FIELDS = ("pkg_id", "phys_proc_id", "package_id", "socket_id")
_CORE_FIELDS = ("core_id", "cpu_core_id")


def dbg(msg):
    if DEBUG:
        print(f"[chk_cpu][dbg] {msg}")


def member_offset(typename, member):
    """Byte offset of member, or None when the member is not in the type."""
    key = (typename, member)
    if key in _OFFSET_CACHE:
        return _OFFSET_CACHE[key]
    off = None
    try:
        import crash as _cr
        raw = _cr.member_offset(typename, member)
        if raw is not None and int(raw) >= 0:
            off = int(raw)
    except Exception:
        off = None
    _OFFSET_CACHE[key] = off
    return off


def has_member(typename, member):
    return member_offset(typename, member) is not None


def struct_size(typename):
    if typename in _SIZE_CACHE:
        return _SIZE_CACHE[typename]
    if typename.startswith("struct "):
        names = (typename, typename[7:])
    else:
        names = (f"struct {typename}", typename)
    size = None
    try:
        import crash as _cr
        for name in names:
            try:
                raw = _cr.struct_size(name)
            except Exception:
                continue
            if raw:
                size = int(raw)
                break
    except Exception:
        size = None
    _SIZE_CACHE[typename] = size
    return size


def struct_exists(typename):
    sz = struct_size(typename)
    return bool(sz)


def symbol_addr(name):
    try:
        if not symbol_exists(name):
            return None
    except Exception:
        return None
    try:
        return int(sym2addr(name))
    except Exception as e:
        dbg(f"sym2addr({name}): {e}")
    try:
        out = exec_crash_command(f"sym {name}")
    except Exception:
        return None
    m = re.search(r"\b([0-9a-fA-F]{6,})\b", out or "")
    if not m:
        return None
    return int(m.group(1), 16)


def _int_field(obj, name):
    if obj is None:
        return None
    try:
        val = getattr(obj, name)
    except Exception:
        return None
    try:
        if isinstance(val, str):
            return int(val.strip().rstrip(","), 0)
        return int(val)
    except Exception:
        return None


def _text_field(obj, name):
    if obj is None:
        return None
    try:
        val = getattr(obj, name)
    except Exception:
        return None
    if isinstance(val, str):
        text = val
    elif isinstance(val, (bytes, bytearray)):
        text = val.split(b"\x00", 1)[0].decode("ascii", "replace")
    elif isinstance(val, (list, tuple)):
        chars = []
        for item in val:
            try:
                code = int(item)
            except Exception:
                break
            if code == 0:
                break
            if code < 0 or code > 0x10FFFF:
                break
            chars.append(chr(code))
        text = "".join(chars)
    else:
        try:
            text = val.string
        except Exception:
            text = None
    if not text:
        return None
    text = text.split("\x00", 1)[0].strip().strip('"')
    return text or None


def plausible_model(text):
    if not text or len(text) < 4 or len(text) > 80:
        return False
    if not any(ch.isalpha() for ch in text):
        return False
    return all(32 <= ord(ch) <= 126 for ch in text)


def parse_cpuinfo_text(text):
    """Pull topology fields out of `p cpu_info:N` / `struct cpuinfo_x86` output."""
    found = {}
    for match in _FIELD_RE.finditer(text or ""):
        found.setdefault(match.group(1), int(match.group(2), 0))
    model = None
    model_match = _MODEL_RE.search(text or "")
    if model_match:
        raw = re.split(r"\\0(?:00)?|\\x00", model_match.group(1), maxsplit=1)[0]
        raw = raw.strip()
        if plausible_model(raw):
            model = raw
    return found, model


def _pick(found, names):
    for name in names:
        if name in found:
            return name, found[name]
    return None, None


def parse_percpu_addrs(text):
    """Parse crash's per-cpu symbol display (`cpu_info` with no arguments)."""
    addrs = {}
    in_addrs = False
    for line in (text or "").splitlines():
        if "PER-CPU ADDRESSES" in line:
            in_addrs = True
            continue
        if not in_addrs:
            continue
        if not line.strip():
            if addrs:
                break
            continue
        match = _PERCPU_ADDR_RE.match(line)
        if match:
            addrs[int(match.group(1))] = int(match.group(2), 16)
        elif addrs:
            break
    return addrs


def _cpu_count():
    try:
        count = int(readSymbol("nr_cpu_ids"))
        if count > 0:
            return min(count, 8192)
    except Exception as e:
        dbg(f"nr_cpu_ids: {e}")
    try:
        out = exec_crash_command("sys")
    except Exception:
        return 1
    for line in out.splitlines():
        match = re.search(r"\bCPUS:\s*(\d+)\b", line)
        if match:
            return int(match.group(1))
        match = re.search(r"\bCPUS:\s*0-(\d+)\b", line)
        if match:
            return int(match.group(1)) + 1
    return 1


def _addrs_from_percpu_module(symbol):
    try:
        var = percpu.get_cpu_var(symbol)
    except Exception as e:
        dbg(f"get_cpu_var({symbol}): {e}")
        return {}
    if isinstance(var, dict):
        pairs = var.items()
    else:
        pairs = enumerate(var)
    addrs = {}
    for cpu, addr in pairs:
        try:
            cpu = int(cpu)
            addr = int(addr)
        except Exception:
            continue
        if addr:
            addrs[cpu] = addr
    return addrs


def _command_percpu_addrs(symbol):
    try:
        text = exec_crash_command(symbol)
    except Exception as e:
        dbg(f"command {symbol}: {e}")
        return {}
    addrs = parse_percpu_addrs(text)
    if addrs:
        dbg(f"{symbol}: {len(addrs)} per-cpu addresses from command output")
    return addrs


def load_percpu_addrs(symbol):
    """
    Map logical CPU -> address for a per-cpu symbol.

    Prefer LinuxDump.percpu (same path as the other chk_* tools). If that
    returns nothing, parse crash's per-cpu symbol display.
    """
    addrs = _addrs_from_percpu_module(symbol)
    if addrs:
        dbg(f"{symbol}: {len(addrs)} per-cpu addresses from get_cpu_var")
        return addrs
    return _command_percpu_addrs(symbol)


def _is_struct(obj):
    return obj is not None and not isinstance(obj, (int, str, bytes, bytearray))


def _topo_object(info, addr):
    """Return the embedded cpuinfo topo struct, or None."""
    if not has_member("struct cpuinfo_x86", "topo"):
        return None
    topo = None
    try:
        topo = getattr(info, "topo")
    except Exception as e:
        dbg(f"cpu_info.topo: {e}")
    if _is_struct(topo):
        return topo
    off = member_offset("struct cpuinfo_x86", "topo")
    if off is None or not struct_exists("struct cpuinfo_topology"):
        return None
    try:
        return readSU("struct cpuinfo_topology", addr + off)
    except Exception as e:
        dbg(f"readSU(cpuinfo_topology): {e}")
        return None


def _read_spec(info, addr, spec):
    """spec is (container, field). container 'topo' reads info.topo."""
    if spec is None:
        return None
    container, field = spec
    obj = info
    if container == "topo":
        obj = _topo_object(info, addr)
    return _int_field(obj, field)


def _normalized_initialized(value):
    """Bitfield is 0 or 1. Anything else is not a trustworthy read."""
    if value in (0, 1):
        return value
    return None


def _include_x86(slot, cpu_index, initialized):
    """
    A CPU that never came online has a zeroed cpu_info, so cpu_index stays 0
    on every slot except the boot CPU. Keep a slot when its cpu_index matches,
    or when the initialized bit is set. A bad read of that bitfield (always 0)
    still keeps CPUs whose cpu_index matches the per-cpu slot.
    """
    initialized = _normalized_initialized(initialized)
    if cpu_index is not None and cpu_index == slot:
        return True
    if initialized == 1:
        return True
    if cpu_index is None and initialized != 0:
        return True
    return False


def _choose_x86_layout(info, addr):
    """
    Return (phys_spec, core_spec, die_spec, apic_spec) using names that
    this cpu_info object actually has.
    """
    topo = _topo_object(info, addr)
    if (topo is not None
            and _int_field(topo, "pkg_id") is not None
            and _int_field(topo, "core_id") is not None):
        die = ("topo", "die_id") if _optional_int(topo, "struct cpuinfo_topology", "die_id") else None
        apic = ("topo", "apicid") if _optional_int(topo, "struct cpuinfo_topology", "apicid") else None
        return ("topo", "pkg_id"), ("topo", "core_id"), die, apic

    if _has_or_readable(info, "struct cpuinfo_x86", "phys_proc_id"):
        core = (None, "cpu_core_id") if _has_or_readable(info, "struct cpuinfo_x86", "cpu_core_id") else None
        die = (None, "cpu_die_id") if has_member("struct cpuinfo_x86", "cpu_die_id") else None
        apic = (None, "apicid") if has_member("struct cpuinfo_x86", "apicid") else None
        return (None, "phys_proc_id"), core, die, apic
    return None, None, None, None


def _has_or_readable(obj, typename, member):
    if has_member(typename, member):
        return True
    return _int_field(obj, member) is not None


def _optional_int(obj, typename, member):
    """True when an optional integer member exists, including a value of 0."""
    if has_member(typename, member):
        return True
    if has_member("struct cpuinfo_x86", "topo." + member):
        return True
    return _int_field(obj, member) is not None


def _spec_label(spec):
    if spec is None:
        return None
    container, field = spec
    if container:
        return f"{container}.{field}"
    return field


def _row_from_values(slot, phys, core, cpu_index, die, apic, initialized, x86_filter):
    if phys is None or core is None:
        return None
    if phys < 0 or core < 0:
        return None
    if x86_filter and not _include_x86(slot, cpu_index, initialized):
        return None
    if cpu_index is None:
        cpu_index = slot
    return Topo(phys, core, cpu_index, die, apic)


def _index_map_looks_wrong(compared, mismatched):
    """True when non-zero cpu_index values disagree with the per-cpu slot."""
    return compared >= 4 and mismatched * 2 > compared


def _read_x86_su(addrs):
    """
    Read topology through pykdump struct access.

    Returns (rows, model, sources, ok, bad_index). bad_index means the address
    list is probably not indexed by logical CPU.
    """
    if not addrs:
        return [], None, {}, False, False

    probe_cpu = 0 if 0 in addrs else sorted(addrs)[0]
    try:
        probe = readSU("struct cpuinfo_x86", addrs[probe_cpu])
    except Exception as e:
        dbg(f"readSU cpu_info[{probe_cpu}]: {e}")
        return [], None, {}, False, False

    phys_s, core_s, die_s, apic_s = _choose_x86_layout(probe, addrs[probe_cpu])
    if phys_s is None or core_s is None:
        dbg("cpu_info has neither topo.pkg_id nor phys_proc_id")
        return [], None, {}, False, False
    if _read_spec(probe, addrs[probe_cpu], core_s) is None:
        dbg(f"{_spec_label(core_s)} unreadable")
        return [], None, {}, False, False

    has_init = has_member("struct cpuinfo_x86", "initialized")
    has_cpu_index = has_member("struct cpuinfo_x86", "cpu_index")
    if not has_cpu_index and _int_field(probe, "cpu_index") is not None:
        has_cpu_index = True
    has_model = has_member("struct cpuinfo_x86", "x86_model_id")
    sources = {
        "physical id": _spec_label(phys_s),
        "core id": _spec_label(core_s),
        "cpu index": "cpu_index" if has_cpu_index else "cpu number",
    }
    dbg("x86 fields: " + " ".join(f"{k}={v}" for k, v in sources.items()))

    rows = []
    model = _text_field(probe, "x86_model_id") if has_model else None
    if not plausible_model(model):
        model = None
    failed = 0
    skipped = 0
    compared = 0
    mismatched = 0

    for cpu in sorted(addrs):
        try:
            info = probe if cpu == probe_cpu else readSU("struct cpuinfo_x86", addrs[cpu])
        except Exception as e:
            failed += 1
            dbg(f"cpu {cpu}: {e}")
            continue
        phys = _read_spec(info, addrs[cpu], phys_s)
        core = _read_spec(info, addrs[cpu], core_s)
        cpu_index = _int_field(info, "cpu_index") if has_cpu_index else None
        if cpu_index not in (None, 0) and cpu_index != cpu:
            compared += 1
            mismatched += 1
        elif cpu_index == cpu:
            compared += 1
        initialized = _int_field(info, "initialized") if has_init else None
        die = _read_spec(info, addrs[cpu], die_s)
        apic = _read_spec(info, addrs[cpu], apic_s)
        row = _row_from_values(cpu, phys, core, cpu_index, die, apic, initialized, True)
        if row is None:
            skipped += 1
            dbg(f"cpu {cpu}: skipped (initialized={initialized} cpu_index={cpu_index})")
            continue
        if model is None and has_model:
            model = _text_field(info, "x86_model_id")
            if not plausible_model(model):
                model = None
        rows.append(row)

    if failed and rows:
        print(f"warning: failed to read cpu_info for {failed} CPUs")
    dbg(f"skipped {skipped} uninitialized CPUs")
    bad_index = _index_map_looks_wrong(compared, mismatched)
    if not rows and failed:
        return [], model, sources, False, bad_index
    return rows, model, sources, True, bad_index


def _dump_cpuinfo_text(cpu, addr):
    """Fallback: ask crash to print one cpu_info and parse the text."""
    commands = [f"p cpu_info:{cpu}"]
    if addr:
        commands.append(f"struct cpuinfo_x86 {addr:#x}")
    last_err = None
    for cmd in commands:
        try:
            text = exec_crash_command(cmd)
        except Exception as e:
            last_err = e
            dbg(f"{cmd}: {e}")
            continue
        if text and ("pkg_id" in text or "phys_proc_id" in text or "cpu_index" in text):
            return text
    if last_err is not None:
        dbg(f"cpu {cpu}: text dump failed: {last_err}")
    return ""


def _read_x86_text(addrs):
    rows = []
    model = None
    sources = {}
    failed = 0
    skipped = 0
    phys_name = core_name = None

    if not addrs:
        count = _cpu_count()
        addrs = {cpu: 0 for cpu in range(count)}

    for cpu in sorted(addrs):
        text = _dump_cpuinfo_text(cpu, addrs[cpu])
        if not text:
            failed += 1
            continue
        found, found_model = parse_cpuinfo_text(text)
        if model is None and found_model:
            model = found_model
        pname, phys = _pick(found, _PHYS_FIELDS)
        cname, core = _pick(found, _CORE_FIELDS)
        cpu_index = found.get("cpu_index")
        initialized = found.get("initialized")
        die = found.get("die_id", found.get("cpu_die_id"))
        apic = found.get("apicid")
        if phys_name is None and pname:
            phys_name = pname
            core_name = cname
        row = _row_from_values(cpu, phys, core, cpu_index, die, apic, initialized, True)
        if row is None:
            skipped += 1
            continue
        rows.append(row)

    if phys_name:
        sources = {
            "physical id": phys_name,
            "core id": core_name,
            "cpu index": "cpu_index",
        }
    if failed and rows:
        print(f"warning: failed to read cpu_info for {failed} CPUs")
    elif failed and not rows:
        print(f"Failed to read cpu_info for {failed} CPUs.")
    dbg(f"text fallback skipped {skipped}, failed {failed}")
    return rows, model, sources, bool(rows)


def read_x86():
    addrs = _addrs_from_percpu_module("cpu_info")
    if not addrs:
        addrs = _command_percpu_addrs("cpu_info")
    rows, model, sources, ok, bad_index = _read_x86_su(addrs)
    if bad_index:
        cmd_addrs = _command_percpu_addrs("cpu_info")
        if cmd_addrs and cmd_addrs != addrs:
            dbg("cpu_index does not match per-cpu slot; using cpu_info addresses")
            rows2, model2, sources2, ok2, _bad = _read_x86_su(cmd_addrs)
            if ok2 and rows2:
                return rows2, model2, sources2
    if ok and rows:
        return rows, model, sources
    if ok:
        dbg("struct reads succeeded but no CPU was initialized")
        return [], model, sources
    dbg("falling back to crash struct text for cpu_info")
    print(f"Reading cpu_info from crash output ({len(addrs) or _cpu_count()} CPUs)...")
    rows, model, sources, _ok = _read_x86_text(addrs)
    return rows, model, sources


def _is_percpu_symbol(name):
    addr = symbol_addr(name)
    start = symbol_addr("__per_cpu_start")
    end = symbol_addr("__per_cpu_end")
    if None in (addr, start, end):
        return False
    return start <= addr < end


def _topology_type_name():
    try:
        out = exec_crash_command("whatis cpu_topology")
    except Exception as e:
        dbg(f"whatis cpu_topology: {e}")
        out = ""
    match = re.search(r"struct \w+", out or "")
    if match:
        return match.group(0)
    for name in ("struct cpu_topology", "struct cpu_topology_s390"):
        if struct_exists(name):
            return name
    return None


def _first_field(typename, names):
    for name in names:
        if has_member(typename, name):
            return name
    return None


def read_cpu_topology():
    """
    aarch64 keeps struct cpu_topology cpu_topology[NR_CPUS].
    s390 keeps a per-cpu struct cpu_topology_s390.
    """
    typename = _topology_type_name()
    if not typename:
        return [], None, {}
    phys_field = _first_field(typename, ("package_id", "pkg_id", "socket_id", "phys_proc_id"))
    core_field = _first_field(typename, ("core_id", "cpu_core_id"))
    die_field = _first_field(typename, ("die_id",))
    if not phys_field or not core_field:
        dbg(f"{typename} has no package/core id members")
        return [], None, {}

    sources = {
        "physical id": phys_field,
        "core id": core_field,
        "cpu index": "cpu number",
    }
    dbg(f"{typename}: " + " ".join(f"{k}={v}" for k, v in sources.items()))

    rows = []
    if _is_percpu_symbol("cpu_topology"):
        addrs = load_percpu_addrs("cpu_topology")
        for cpu in sorted(addrs):
            try:
                obj = readSU(typename, addrs[cpu])
            except Exception as e:
                dbg(f"cpu {cpu}: {e}")
                continue
            row = _row_from_values(
                cpu,
                _int_field(obj, phys_field),
                _int_field(obj, core_field),
                cpu,
                _int_field(obj, die_field) if die_field else None,
                None,
                None,
                False,
            )
            if row is not None:
                rows.append(row)
        return rows, None, sources

    base = symbol_addr("cpu_topology")
    stride = struct_size(typename)
    if base is None or not stride:
        dbg(f"cpu_topology array base={base} stride={stride}")
        return [], None, sources

    for cpu in range(_cpu_count()):
        try:
            obj = readSU(typename, base + cpu * stride)
        except Exception as e:
            dbg(f"cpu {cpu}: {e}")
            continue
        row = _row_from_values(
            cpu,
            _int_field(obj, phys_field),
            _int_field(obj, core_field),
            cpu,
            _int_field(obj, die_field) if die_field else None,
            None,
            None,
            False,
        )
        if row is not None:
            rows.append(row)
    return rows, None, sources


def collect_topo():
    try:
        x86 = struct_exists("struct cpuinfo_x86")
    except Exception:
        x86 = False
    try:
        have_info = x86 and symbol_exists("cpu_info")
    except Exception:
        have_info = x86

    if have_info:
        return read_x86()

    try:
        have_topo = symbol_exists("cpu_topology")
    except Exception:
        have_topo = False
    if have_topo:
        return read_cpu_topology()

    return [], None, {}


def _cpu_word(count, singular, plural):
    return f"{count} {singular if count == 1 else plural}"


def summarize(rows):
    """One-line description of packages, cores, and SMT."""
    per_pkg = {}
    threads = {}
    for row in rows:
        per_pkg.setdefault(row.phys, set()).add(row.core)
        key = (row.phys, row.core)
        threads[key] = threads.get(key, 0) + 1

    pkg_counts = sorted({len(cores) for cores in per_pkg.values()})
    if len(pkg_counts) == 1:
        ncores = pkg_counts[0]
        core_txt = _cpu_word(ncores, "core", "cores") + "/package"
    else:
        core_txt = _cpu_word(len(threads), "core", "cores")

    smt = sorted(set(threads.values()))
    if len(smt) == 1:
        smt_txt = _cpu_word(smt[0], "thread", "threads") + "/core"
    else:
        smt_txt = "threads/core " + ",".join(str(n) for n in smt)

    return (
        f"{_cpu_word(len(rows), 'logical CPU', 'logical CPUs')}, "
        f"{_cpu_word(len(per_pkg), 'physical id', 'physical ids')}, "
        f"{core_txt}, {smt_txt}"
    )


def _column_values(rows, verbose):
    show_die = verbose and any(row.die is not None for row in rows)
    show_apic = verbose and any(row.apic is not None for row in rows)
    headers = ["physical id", "core id", "cpu index"]
    if show_die:
        headers.append("die id")
    if show_apic:
        headers.append("apicid")

    body = []
    for row in rows:
        vals = [str(row.phys), str(row.core), str(row.cpu)]
        if show_die:
            vals.append("-" if row.die is None else str(row.die))
        if show_apic:
            vals.append("-" if row.apic is None else str(row.apic))
        body.append(vals)
    return headers, body


# Bold black on yellow. The "<<" stays visible if the pager drops color.
_HL_ON = "\033[1;30;43m"
_HL_OFF = "\033[0m"


def _paint(line):
    return f"{_HL_ON}{line} <<{_HL_OFF}"


def format_table(rows, verbose, highlight=None):
    highlight = highlight or set()
    headers, body = _column_values(rows, verbose)
    widths = [len(header) for header in headers]
    for vals in body:
        for i, val in enumerate(vals):
            if len(val) > widths[i]:
                widths[i] = len(val)

    def fmt(vals):
        return "  ".join(val.rjust(widths[i]) for i, val in enumerate(vals))

    lines = [fmt(headers)]
    prev = None
    for row, vals in zip(rows, body):
        if prev is not None and row.phys != prev:
            lines.append("")
        line = fmt(vals)
        if row.cpu in highlight:
            line = _paint(line)
        lines.append(line)
        prev = row.phys
    return "\n".join(lines)


def _highlight_note(rows, highlight):
    return _cpu_list_note("highlight", highlight, rows)


def _cpu_list_note(label, requested, rows):
    shown = ",".join(str(cpu) for cpu in sorted(requested))
    present = {row.cpu for row in rows}
    missing = [cpu for cpu in sorted(requested) if cpu not in present]
    if missing:
        miss = ",".join(str(cpu) for cpu in missing)
        return f"{label}: {shown}  (not found: {miss})"
    return f"{label}: {shown}"


def show_topo(verbose, highlight=None, cpu_filter=None):
    rows, model, sources = collect_topo()
    if not rows:
        print(
            "No CPUs with topology information were found "
            "(expected per-cpu cpu_info, or cpu_topology)."
        )
        return False

    rows.sort(key=lambda row: (row.phys, row.core, row.cpu))
    total = len(rows)
    filter_note = None
    if cpu_filter:
        filter_note = _cpu_list_note("filter cpu index", cpu_filter, rows)
        rows = [row for row in rows if row.cpu in cpu_filter]
        if not rows:
            print(filter_note)
            return False

    if model:
        print(model)
    if cpu_filter:
        print(filter_note)
        print(f"{_cpu_word(len(rows), 'logical CPU', 'logical CPUs')} of {total}")
    else:
        print(summarize(rows))
    if verbose and sources:
        print("fields: " + "  ".join(f"{label}={name}" for label, name in sources.items()))
    if highlight:
        print(_highlight_note(rows, highlight))
    print()
    print(format_table(rows, verbose, highlight))
    return True


def parse_cpu_list(text):
    """Comma-separated cpu indexes: 0,64,127."""
    if text is None or not str(text).strip():
        raise argparse.ArgumentTypeError("expected a comma-separated cpu index list")
    cpus = set()
    for part in str(text).split(","):
        part = part.strip()
        if not part:
            raise argparse.ArgumentTypeError(f"empty cpu index in '{text}'")
        try:
            cpu = int(part, 0)
        except ValueError:
            raise argparse.ArgumentTypeError(f"not a cpu index: {part}")
        if cpu < 0:
            raise argparse.ArgumentTypeError(f"not a cpu index: {part}")
        cpus.add(cpu)
    return cpus


def main(argv=None):
    global DEBUG

    parser = argparse.ArgumentParser(
        prog="chk_cpu",
        description="Show CPU topology from a vmcore.",
        epilog=(
            "examples:\n"
            "  chk_cpu\n"
            "  chk_cpu --topo\n"
            "  chk_cpu --topo -v\n"
            "  chk_cpu --highlight 0,64,127\n"
            "  chk_cpu --filter-cpu-index 0,64,127\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--topo",
        action="store_true",
        help="list physical id, core id, and cpu index (default)",
    )
    parser.add_argument(
        "--highlight",
        metavar="CPU,...",
        type=parse_cpu_list,
        help="comma-separated cpu indexes to highlight, e.g. 0,64,127",
    )
    parser.add_argument(
        "--filter-cpu-index",
        metavar="CPU,...",
        type=parse_cpu_list,
        help="show only these comma-separated cpu indexes, e.g. 0,64,127",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="also show die id and apicid when the kernel has them",
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="print field names and skipped CPUs",
    )
    args = parser.parse_args(argv)
    DEBUG = args.debug

    # --topo is the default when no mode option is given.
    modes = []
    if args.topo:
        modes.append("topo")
    if not modes:
        modes.append("topo")

    ok = True
    for mode in modes:
        if mode == "topo":
            ok = show_topo(
                verbose=args.verbose,
                highlight=args.highlight,
                cpu_filter=args.filter_cpu_index,
            ) and ok
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
