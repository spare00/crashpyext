#!/usr/bin/env epython

"""
Disassembly + stack annotation for Linux arm64 (aarch64) vmcores in crash(8).

Mirrors chk_dis.py (x86_64) but understands AArch64 `bt -f` / exception banners,
AAPCS64 prologue idioms (stp/ldp/str/ldr on sp), and generic 64-bit `sym` lines.
"""

from pykdump.API import *
import sys
import argparse
import re

EXCEPTION_SP = None  # populated dynamically when needed (faulting context SP)

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Callee-saved GPRs in the AArch64 ABI (informational; same as chk_dis.py, unused today)
CALLEE_SAVED_REGS = {
    "x19",
    "x20",
    "x21",
    "x22",
    "x23",
    "x24",
    "x25",
    "x26",
    "x27",
    "x28",
    "x29",
    "x30",
}

# `sym <addr>`: leading hex address (8–16 digits; arm64 kernel VA is not `ffffffff`-prefixed)
_SYM_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]{8,16})\s+(?:\(\w\)\s+)?(.+?)\s*$")
_DIS_S_FILE_RE = re.compile(r"^\s*FILE:\s*(.+?)\s*$", re.I)
_DIS_S_LINE_RE = re.compile(r"^\s*LINE:\s*(\d+)\s*$", re.I)
_SYM_OUTLINE_SUFFIX_RE = re.compile(
    r"\.(?:cold|part\.\d+|isra\.\d+|constprop\.\d+)$"
)


def _parse_hex_addr(s):
    s = s.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    return int(s, 16)


def _kaddr_str(addr):
    """
    Format a kernel address for crash/gdb subcommands. Crash accepts at most 16 hex digits
    for dis/sym; Python's default int formatting is decimal and breaks `dis`/`sym`.
    """
    if isinstance(addr, str):
        t = addr.strip()
        if t.startswith(("0x", "0X")):
            return t
        return f"0x{t}"
    return f"{int(addr):#x}"


def _crash_bt_exception_banner(line):
    """True at the start of an exception register dump in `bt` / `bt -f` output."""
    if "[exception RIP" in line:
        return True
    # crash arm64_print_exception_frame (KERNEL_MODE): first line is "     PC: ..."
    if re.match(r"^\s+PC:\s+[0-9a-fA-F]{8,16}\b", line):
        return True
    return False


def parse_dis_s(addr):
    """
    Run `dis -s <addr>` and return (source_file, line_num) from FILE:/LINE: headers,
    or (None, None) if not found.
    """
    out = exec_crash_command(f"dis -s {_kaddr_str(addr)}")
    src_file = None
    line_no = None
    for ln in out.splitlines():
        m = _DIS_S_FILE_RE.match(ln)
        if m:
            src_file = m.group(1).strip()
            continue
        m = _DIS_S_LINE_RE.match(ln)
        if m:
            line_no = int(m.group(1))
            continue
    return src_file, line_no


def sym_line_for_addr(addr):
    """First interesting line from `sym <addr>` (address + RHS)."""
    out = exec_crash_command(f"sym {_kaddr_str(addr)}")
    for ln in out.splitlines():
        ln = ln.rstrip("\r\n")
        if _SYM_LINE_RE.match(ln):
            return ln
    for ln in out.splitlines():
        if ln.strip():
            return ln.strip()
    return ""


def sym_rhs_base_name(addr):
    """
    From `sym <addr>`, get the symbol base name suitable for `sym <name>` / `gdb list <name>`
    (strip +offset and trailing source annotation).
    """
    line = sym_line_for_addr(addr)
    if not line:
        return ""
    m = _SYM_LINE_RE.match(line)
    rhs = m.group(2) if m else line
    rhs = re.sub(r"\s+/.+?:\s*\d+\s*$", "", rhs).strip()
    moff = re.match(r"^(.+?)(\+0x[0-9a-fA-F]+)", rhs)
    if moff:
        return moff.group(1).strip()
    return rhs.split()[0] if rhs else ""


def sym_name_to_addr(symbol):
    """Resolve a kernel text symbol to its start address via `sym <symbol>`."""
    if not symbol:
        return None
    try:
        out = exec_crash_command(f"sym {symbol}")
    except Exception:
        return None
    for tok in out.split():
        clean = tok.rstrip(":")
        try:
            val = int(clean, 16)
            if val > 0x1000:
                return val
        except ValueError:
            continue
    return None


def sym_outline_parent_name(symbol_base):
    """
    Strip gcc/clang suffix like `.cold` / `.isra.0` so we can resolve the enclosing C function
    for source listings (cold/out-of-line IR shares line info with the split symbol entry).
    """
    if not symbol_base:
        return None
    m = _SYM_OUTLINE_SUFFIX_RE.search(symbol_base)
    if not m:
        return None
    return symbol_base[: m.start()] or None


def entry_line_before_pc(file_pc, line_pc, symbol_base, debug=False):
    """
    First source line of `sym <symbol>` in the same file as the PC, using symbol_base
    and then a stripped parent (e.g. check_heap_object.cold → check_heap_object) if the
    split symbol's `dis -s` entry line is not strictly before line_pc.
    """
    if not symbol_base:
        return None, None
    names = [symbol_base]
    parent = sym_outline_parent_name(symbol_base)
    if parent and parent not in names:
        names.append(parent)

    for name in names:
        entry_addr = sym_name_to_addr(name)
        if entry_addr is None:
            if debug:
                print(f"[DEBUG] sym {name!r} has no address, try next")
            continue
        file_ent, line_ent = parse_dis_s(entry_addr)
        if not file_ent or line_ent is None:
            continue
        if file_ent != file_pc:
            if debug:
                print(
                    f"[DEBUG] entry for {name!r} is {file_ent!r} != PC file {file_pc!r}, try next"
                )
            continue
        if line_ent < line_pc:
            if debug:
                print(f"[DEBUG] entry line {line_ent} from sym {name!r} (file {file_pc})")
            return line_ent, name
    return None, None


def gdb_list_range(src_file, start_line, end_line, debug=False):
    """`gdb list file:start,end` — inclusive line range."""
    if start_line < 1:
        start_line = 1
    if end_line < start_line:
        end_line = start_line
    cmd = f"gdb list {src_file}:{start_line},{end_line}"
    if debug:
        print(f"[DEBUG] {cmd}")
    return exec_crash_command(cmd)


_GDB_LIST_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)$")


def parse_gdb_list_numbered_lines(gdb_out):
    """Parse `gdb list` lines into {lineno: text} (last wins if duplicated)."""
    mmap = {}
    for ln in gdb_out.splitlines():
        m = _GDB_LIST_LINE_RE.match(ln)
        if m:
            mmap[int(m.group(1))] = m.group(2).rstrip("\r")
    return mmap


def _brace_delta_raw(line):
    """Net `{` minus `}` on a line; strips // comments and naive C strings first."""
    if not line:
        return 0
    if "//" in line:
        line = line.split("//", 1)[0]
    s = line
    s = re.sub(r'"(\\.|[^"\\])*"', '""', s)
    s = re.sub(r"'(\\.|[^'\\])*'", "''", s)
    return s.count("{") - s.count("}")


def _is_lone_open_brace(text):
    """Kernel style: function body often starts with a line containing only `{`."""
    return bool(re.match(r"^\s*\{\s*$", text.rstrip()))


def find_close_brace_line_from_gdb_list(gdb_out, min_line):
    """
    After the first lone `{` on or after min_line, walk lines in order and run a brace
    balance until depth returns to zero — that line is the matching outer `}`.
    """
    mmap = parse_gdb_list_numbered_lines(gdb_out)
    if not mmap:
        return None
    nums = sorted(mmap.keys())
    open_line = None
    for n in nums:
        if n < min_line:
            continue
        if _is_lone_open_brace(mmap[n]):
            open_line = n
            break
    if open_line is None:
        return None

    depth = 1
    for n in nums:
        if n <= open_line:
            continue
        depth += _brace_delta_raw(mmap[n])
        if depth <= 0:
            return n if depth == 0 else None
    return None


def source_context_for_address(
    addr_str,
    whole_function=False,
    fallback_before=80,
    listsize=400,
    entry_pad_before=6,
    max_probe_lines=2500,
    debug=False,
):
    """
    Given a kernel text address, show C source context without knowing the function name.
    (Same behavior as chk_dis.py --src.)
    """
    try:
        addr_int = _parse_hex_addr(addr_str)
    except ValueError:
        print(f"[ERROR] Not a valid address: {addr_str!r}")
        return

    file_pc, line_pc = parse_dis_s(addr_int)
    if not file_pc or line_pc is None:
        print(
            f"[ERROR] No FILE:/LINE: in `dis -s {addr_str}` — build has no line info for this PC?"
        )
        return

    base = sym_rhs_base_name(addr_int)
    if debug:
        print(f"[DEBUG] sym base name: {base!r}")

    line_start, entry_sym = entry_line_before_pc(file_pc, line_pc, base, debug=debug)
    resolved_by_sym = line_start is not None
    if not resolved_by_sym:
        line_start = max(1, line_pc - fallback_before)
    elif line_start > line_pc:
        if debug:
            print(f"[DEBUG] entry line {line_start} > PC line {line_pc}; using fallback window")
        resolved_by_sym = False
        line_start = max(1, line_pc - fallback_before)
    elif resolved_by_sym and entry_pad_before > 0:
        if debug:
            print(
                f"[DEBUG] entry from sym/dis is first executable line; "
                f"pad start by {entry_pad_before} line(s) for signature"
            )
        line_start = max(1, line_start - entry_pad_before)

    line_end = line_pc
    end_note = ""
    if whole_function:
        if not base:
            print("[WARN] No symbol name for --whole; using entry-based range only.")
        probe_hi = line_start + max(1, max_probe_lines) - 1
        if debug:
            print(f"[DEBUG] brace probe: {file_pc}:{line_start}–{probe_hi}")
        probe_out = gdb_list_range(file_pc, line_start, probe_hi, debug=debug)
        end_brace = find_close_brace_line_from_gdb_list(probe_out, line_start)
        if end_brace is not None:
            line_end = max(line_pc, end_brace)
            end_note = "  |  end: matching `}` (brace balance)"
        else:
            line_end = max(line_pc, line_start + listsize - 1)
            end_note = "  |  end: fallback (no lone `{`/balanced `}` in probe)"

    if whole_function:
        print(f"{BOLD}--- gdb list (wide range from entry){RESET}  {base or '?'}")
    else:
        print(f"{BOLD}--- gdb list (function entry → PC line){RESET}")
    entry_note = ""
    if entry_sym and base and entry_sym != base:
        entry_note = f"  |  entry sym: {entry_sym}"
    print(f"symbol: {base or '?'}{entry_note}{end_note}  |  {file_pc}:{line_start}–{line_end}")
    out = gdb_list_range(file_pc, line_start, line_end, debug=debug)
    print(out.rstrip() if out else "(no output)")


def get_dis_symbol_context(addr, before_lines=1, debug=False):
    """
    Run 'dis -s <addr>' and return `*` line with N lines before it.
    """
    output = exec_crash_command(f"dis -s {_kaddr_str(addr)}")
    lines = output.strip().splitlines()

    for i, line in enumerate(lines):
        if line.strip().startswith("*"):
            start = max(i - before_lines, 0)
            selected = lines[start : i + 1]
            if debug:
                print(f"[DEBUG] Symbol context for {_kaddr_str(addr)}")
                print(f"start: {start}")
                print(f"selected: {selected}")
                print(f"before_lines: {before_lines}")
            return "\n".join(selected)

    return ""


def parse_bt_frame_stack(frame_num, debug=False):
    bt_output = exec_crash_command("bt -f")
    lines = bt_output.splitlines()
    stack_vals = []

    MAX_PUSHES = 6  # prologue depth heuristic (matches chk_dis.py)

    if frame_num == "exception":
        found = False
        for line in lines:
            if _crash_bt_exception_banner(line):
                found = True
                continue
            if found:
                if line.strip().startswith("#"):  # next frame
                    break
                if ":" in line:
                    try:
                        _, data = line.strip().split(":", 1)
                        matches = re.findall(r"[0-9a-fA-F]{8,16}", data)
                        if matches:
                            if debug:
                                print(
                                    f"[DEBUG] Exception stack line: {line.strip()} => {matches}"
                                )
                            stack_vals.extend(matches)
                    except Exception:
                        continue
        stack_vals = stack_vals[::-1]
        trimmed = stack_vals[: MAX_PUSHES + 1]
        if debug:
            print(
                f"[DEBUG] Parsed {len(trimmed)} exception stack entries (including return address)"
            )
        return trimmed

    # Normal frame
    frame_pattern = re.compile(rf"^#{frame_num}\b")
    found = False
    for line in lines:
        if not found and frame_pattern.match(line.strip()):
            found = True
            continue
        if found:
            if line.strip().startswith("#"):
                break
            parts = line.strip().split(":", 1)
            if len(parts) != 2:
                continue
            data = parts[1].strip()
            matches = re.findall(r"[0-9a-fA-F]{8,16}", data)
            if matches:
                if debug:
                    print(f"[DEBUG] Line: {line.strip()} => {matches}")
                stack_vals.extend(matches)

    stack_vals = stack_vals[::-1]
    trimmed = stack_vals[: MAX_PUSHES + 1]
    if debug:
        print(
            f"[DEBUG] Parsed {len(trimmed)} stack values from frame #{frame_num} (including return addr)"
        )
    return trimmed


def get_frame_sp(frame_num):
    if frame_num == "exception":
        if EXCEPTION_SP is not None:
            return EXCEPTION_SP
        raise ValueError("Exception SP not initialized.")

    bt_output = exec_crash_command("bt -f")
    lines = bt_output.splitlines()
    frame_pattern = re.compile(rf"^#{frame_num}\s+\[([0-9a-fA-F]+)\]")
    found = False

    for line in lines:
        if not found and frame_pattern.search(line.strip()):
            found = True
            continue
        if found:
            if ":" in line:
                addr_str = line.strip().split(":")[0]
                return int(addr_str, 16)
            elif line.strip().startswith("#"):
                break

    raise ValueError(f"Could not find stack base for frame #{frame_num}")


def _get_reg_x29():
    for name in ("x29", "fp"):
        try:
            return get_reg(name)
        except Exception:
            continue
    return None


def annotate_mov_sp_fp(instr_line, debug=False):
    """Annotate `mov sp, x29` / `mov sp, fp` epilogue restore."""
    instr = instr_line.strip().split(":", 1)[-1].strip()
    if not re.match(r"mov\s+sp\s*,\s*(x29|fp)\b", instr, re.I):
        return instr_line
    try:
        fp_val = _get_reg_x29()
        if fp_val is None:
            return instr_line
        msg = (
            f"{instr_line.rstrip():<60} {MAGENTA}; sp ← fp ({fp_val:#x}){RESET}"
        )
        return msg
    except Exception as e:
        if debug:
            print(f"[DEBUG] mov sp, fp annotation failed: {e}")
    return instr_line


def _a64_ldst_size(disas):
    """Best-effort access size in bytes for a load/store mnemonic + operands."""
    d = disas.lower()
    if re.search(r"\b(ldrb|strb|sturb|ldurb)\b", d):
        return 1
    if re.search(r"\b(ldrh|strh|ldurh|sturh|ldrsh|strh)\b", d):
        return 2
    if re.search(r"\b(ldr|str|ldur|stur)\s+w\d", d):
        return 4
    return 8


_SP_OFFSET_RE = re.compile(
    r"\[sp\s*,\s*#\s*([-+]?)((?:0x)?[0-9a-fA-F]+)\s*\]",
    re.I,
)


def _parse_sp_imm_operand(op):
    """Return signed byte offset for [sp, #imm] or None."""
    m = _SP_OFFSET_RE.search(op)
    if not m:
        return None
    sign = m.group(1)
    num = m.group(2)
    if num.lower().startswith("0x"):
        v = int(num, 16)
    else:
        v = int(num, 10)
    if sign == "-":
        v = -v
    return v


def disassemble_addresses_with_push_values(addresses, frames, deepest_frame, debug=False):
    for addr, frame in zip(reversed(addresses), reversed(frames)):
        frame_str = f"frame #{frame}" if isinstance(frame, int) else f"frame {frame}"
        comm = f"dis -rl {addr}"
        print(f"\n\033[96m\033[1m--- {comm} ({frame_str}) ---\033[0m\n")
        if debug:
            print(f"[DEBUG] Running: {comm}")

        output = exec_crash_command(comm)
        if not output.strip():
            print("[WARNING] No disassembly output.")
            continue

        stack_vals = []
        if frame != deepest_frame:
            stack_vals = parse_bt_frame_stack(frame, debug=debug)
            if debug:
                print(f"[DEBUG] stack_vals (raw): {stack_vals}")

        stack_vals = stack_vals[1:]
        push_index = 0
        pop_index = len(stack_vals) - 1

        prev_line_was_source = False

        for line in output.splitlines():
            stripped = line.strip()

            if stripped.startswith("/"):  # Source line from kernel debug info
                prev_line_was_source = True
                print(line)
                continue

            if stripped.startswith("0x"):
                if prev_line_was_source:
                    addr_match = re.match(r"0x[0-9a-fA-F]+", stripped)
                    if addr_match:
                        sym_output = get_dis_symbol_context(
                            addr_match.group(0),
                            before_lines=args.lines - 1,
                            debug=debug,
                        )
                        if sym_output:
                            print(f"{sym_output}")
                prev_line_was_source = False

            disas = ""
            if ":" in line:
                disas = line.split(":", 1)[1].strip()
                disas = re.sub(r"^(lock|dmb|dsb|isb)\s+", "", disas, flags=re.I)

            # stp Rt, Rt2, [sp, ...]  — stores two words (prologue)
            if disas and re.search(r"\bstp\b", disas, re.I) and "[sp" in disas.lower():
                m = re.search(r"\bstp\s+(\w+)\s*,\s*(\w+)\s*,\s*\[sp", disas, re.I)
                if m and push_index + 1 < len(stack_vals):
                    v0 = stack_vals[push_index]
                    v1 = stack_vals[push_index + 1]
                    print(
                        f"{line:<60} {YELLOW}; {m.group(1)}={v0}  {m.group(2)}={v1}{RESET}"
                    )
                    push_index += 2
                    continue

            # str X/W, [sp, ...]  — single store
            if (
                disas
                and re.search(r"\bstr\b", disas, re.I)
                and "[sp" in disas.lower()
                and not re.search(r"\bstp\b", disas, re.I)
            ):
                if push_index < len(stack_vals):
                    val = stack_vals[push_index]
                    print(f"{line:<60} {YELLOW}; {val}{RESET}")
                    push_index += 1
                    continue

            # ldp Rt, Rt2, [sp ...]  — loads two words (epilogue)
            if disas and re.search(r"\bldp\b", disas, re.I) and "[sp" in disas.lower():
                m = re.search(r"\bldp\s+(\w+)\s*,\s*(\w+)\s*,\s*\[sp", disas, re.I)
                if m and pop_index >= 1:
                    v0 = stack_vals[pop_index - 1]
                    v1 = stack_vals[pop_index]
                    print(
                        f"{line:<60} {YELLOW}; {m.group(1)}←{v0}  {m.group(2)}←{v1}{RESET}"
                    )
                    pop_index -= 2
                    continue

            # ldr ..., [sp, #...]
            if (
                disas
                and re.search(r"\bldr\b", disas, re.I)
                and "[sp" in disas.lower()
                and not re.search(r"\bldp\b", disas, re.I)
            ):
                if pop_index >= 0:
                    val = stack_vals[pop_index]
                    print(f"{line:<60} {YELLOW}; ←{val}{RESET}")
                    pop_index -= 1
                    continue

            if disas and re.match(r"mov\s+sp\s*,\s*(x29|fp)\b", disas, re.I):
                print(annotate_mov_sp_fp(line, debug=debug))
                continue

            # SP-relative memory access (annotate loaded/stored value at effective address)
            if ":" in line and disas:
                sp_off = _parse_sp_imm_operand(disas)
                if sp_off is not None:
                    try:
                        sp_addr = get_frame_sp(frame)
                        mem_addr = sp_addr + sp_off
                        sz = _a64_ldst_size(disas)
                        if sz == 1:
                            mem_val = readU8(mem_addr)
                            disp = f"{mem_val:#04x} (8-bit)"
                        elif sz == 2:
                            mem_val = readU16(mem_addr)
                            disp = f"{mem_val:#06x} (16-bit)"
                        elif sz == 4:
                            mem_val = readU32(mem_addr)
                            disp = f"{mem_val:#010x} (32-bit)"
                        else:
                            mem_val = readU64(mem_addr)
                            disp = f"{mem_val:#018x} (64-bit)"

                        if debug:
                            print(
                                f"[DEBUG] SP: {hex(sp_addr)} offset: {sp_off} → addr: {hex(mem_addr)} = {disp}"
                            )

                        line = line.rstrip() + f"    {BLUE}; 0x{mem_addr:x} = {disp}{RESET}"
                    except Exception as e:
                        if debug:
                            print(f"[DEBUG] Memory read failed: {e}")

            print(line)


def get_deepest_frame_number_from_bt_lines(lines):
    deepest = 0
    for line in lines:
        if line.strip().startswith("#"):
            try:
                frame_num = int(line.strip().split()[0][1:])
                deepest = max(deepest, frame_num)
            except Exception:
                continue
    return deepest


def get_bt_addresses_exception_to_frame(upto_frame, debug=False):
    lines = exec_crash_command("bt -f").splitlines()
    deepest_frame = get_deepest_frame_number_from_bt_lines(lines)

    start_index = None
    end_marker = f"#{upto_frame}"
    addresses = []
    frames = []

    for idx, line in enumerate(lines):
        if start_index is None and _crash_bt_exception_banner(line):
            start_index = idx
        if start_index is not None and line.strip().startswith(end_marker):
            target_lines = lines[start_index : idx + 1]
            break
    else:
        if start_index is None:
            print(
                "[WARN] No exception banner (x86 'exception RIP' or arm64 'PC:' block) found. "
                "Starting from the first frame."
            )
            start_index = 0
            for idx, line in enumerate(lines):
                if line.strip().startswith(end_marker):
                    target_lines = lines[start_index : idx + 1]
                    break
            else:
                print(f"[ERROR] Could not find frame #{upto_frame} from start of backtrace.")
                return [], [], None
        else:
            print(f"[ERROR] Could not find frame #{upto_frame} after exception banner.")
            return [], [], None

    for line in target_lines:
        tokens = line.strip().split()
        if tokens and tokens[0].startswith("#") and len(tokens) > 4:
            frames.append(int(tokens[0][1:]))
            addresses.append(tokens[4])
            if debug:
                print(f"[DEBUG] Frame #{frames[-1]} => {addresses[-1]}")

    return addresses, frames, deepest_frame


def get_bt_addresses_range(start_frame, end_frame, debug=False):
    lines = exec_crash_command("bt -f").splitlines()
    deepest_frame = get_deepest_frame_number_from_bt_lines(lines)

    addresses = []
    frames = []
    capturing = False

    for line in lines:
        line = line.strip()
        if line.startswith(f"#{start_frame}"):
            capturing = True

        if capturing and line.startswith("#"):
            tokens = line.split()
            if len(tokens) > 4:
                frames.append(int(tokens[0][1:]))
                addresses.append(tokens[4])
                if line.startswith(f"#{end_frame}"):
                    break

    if not addresses and debug:
        print(f"[DEBUG] No addresses found between #{start_frame} and #{end_frame}")

    return addresses, frames, deepest_frame


# --- Main ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="arm64: disassemble and annotate stack stores/loads, or list C source (--src).",
    )
    parser.add_argument(
        "frames",
        metavar="N",
        type=int,
        nargs="*",
        help="One frame number (exception → frame), or start and end range (default mode)",
    )
    parser.add_argument(
        "-S",
        "--src",
        metavar="ADDR",
        help="List C source for kernel text ADDR (same as chk_dis.py --src)",
    )
    parser.add_argument(
        "-w",
        "--whole",
        action="store_true",
        help="With --src: extend listing to matching `}` (brace balance), else fallback window",
    )
    parser.add_argument(
        "-F",
        "--fallback-before",
        type=int,
        default=80,
        help="With --src: lines before PC if symbol entry unresolved (default: 80)",
    )
    parser.add_argument(
        "-G",
        "--listsize",
        type=int,
        default=400,
        help="With --src -w: fallback listing length (default: 400)",
    )
    parser.add_argument(
        "-M",
        "--max-probe",
        type=int,
        default=2500,
        metavar="LINES",
        help="With --src -w: gdb list probe size (default: 2500)",
    )
    parser.add_argument(
        "-P",
        "--entry-pad",
        type=int,
        default=6,
        metavar="N",
        help="With --src: extra lines above sym/dis entry (default: 6, 0 disables)",
    )
    parser.add_argument(
        "-l",
        "--lines",
        type=int,
        default=3,
        help="Backtrace disassembly: dis -s context lines before `*` (default: 3)",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.src:
        source_context_for_address(
            args.src,
            whole_function=args.whole,
            fallback_before=args.fallback_before,
            listsize=args.listsize,
            entry_pad_before=args.entry_pad,
            max_probe_lines=args.max_probe,
            debug=args.debug,
        )
        sys.exit(0)

    if not args.frames:
        parser.error("specify frame number(s) or use --src ADDR")

    if len(args.frames) == 1:
        addrs, frame_ids, deepest_frame = get_bt_addresses_exception_to_frame(
            args.frames[0], debug=args.debug
        )

        bt_lines = exec_crash_command("bt").splitlines()
        exception_pc = None
        in_exception_banner = False
        for line in bt_lines:
            if _crash_bt_exception_banner(line):
                in_exception_banner = True
            if in_exception_banner:
                mrip = re.search(r"RIP:\s+([0-9a-fA-F]+)", line)
                mpc = re.search(r"\bPC:\s+([0-9a-fA-F]+)", line)
                if mrip:
                    exception_pc = mrip.group(1)
                    in_exception_banner = False
                    break
                if mpc:
                    exception_pc = mpc.group(1)
                    in_exception_banner = False
                    break

        if exception_pc:
            first_addr = addrs[0] if addrs else None
            if first_addr and exception_pc.lower() != first_addr.lower():
                exc_sp = None
                in_exc = False
                for line in bt_lines:
                    if _crash_bt_exception_banner(line):
                        in_exc = True
                        continue
                    if in_exc:
                        if line.strip().startswith("#"):
                            break
                        m = re.search(r"RSP:\s+([0-9a-fA-F]+)", line)
                        if not m:
                            m = re.search(r"\bSP:\s+([0-9a-fA-F]+)", line)
                        if m and exc_sp is None:
                            exc_sp = int(m.group(1), 16)
                            if args.debug:
                                print(f"[DEBUG] Captured exception SP: {hex(exc_sp)}")
                if exc_sp is not None:
                    EXCEPTION_SP = exc_sp

                if EXCEPTION_SP is not None:
                    if args.debug:
                        print(f"[DEBUG] Adding exception PC disassembly: {exception_pc}")
                    addrs.insert(0, exception_pc)
                    frame_ids.insert(0, "exception")

    elif len(args.frames) == 2:
        addrs, frame_ids, deepest_frame = get_bt_addresses_range(
            args.frames[0], args.frames[1], debug=args.debug
        )
    else:
        print("[ERROR] Use chk_dis_aarch64 <frame> or chk_dis_aarch64 <start> <end>")
        sys.exit(1)

    disassemble_addresses_with_push_values(addrs, frame_ids, deepest_frame, debug=args.debug)
