#!/usr/bin/env epython

from pykdump.API import *
import sys
import argparse
import re

EXCEPTION_RSP = None  # populated dynamically when needed

# ANSI color codes
RED     = '\033[91m'
GREEN   = '\033[92m'
YELLOW  = '\033[93m'
BLUE    = '\033[94m'
MAGENTA = '\033[95m'
CYAN    = '\033[96m'
RESET   = '\033[0m'
BOLD    = '\033[1m'

# Callee-saved registers we care about, for validation
CALLEE_SAVED_REGS = {"%r15", "%r14", "%r13", "%r12", "%rbp", "%rbx"}

# `sym <addr>` line: leading address then symbol (see chk_po_analyze._ADDRLINE_RE)
_SYM_LINE_RE = re.compile(r"^\s*(ffffffff[0-9a-fA-F]{8})\s+(?:\(\w\)\s+)?(.+?)\s*$")
_DIS_S_FILE_RE = re.compile(r"^\s*FILE:\s*(.+?)\s*$", re.I)
_DIS_S_LINE_RE = re.compile(r"^\s*LINE:\s*(\d+)\s*$", re.I)
# gcc/clang out-of-line splits: .cold, .isra.N, .constprop.N, .part.N
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
                print(f"[DEBUG] entry for {name!r} is {file_ent!r} != PC file {file_pc!r}, try next")
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

    This matches the common kernel pattern (signature lines then `{{` then ... `}}`).
    Fails if no lone `{{`, depth goes negative, or listing ends before depth hits 0.
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

    Modes:
      whole_function=False (default): from the enclosing symbol's entry line (via sym + dis -s)
        up to and including the line for the PC. If the PC is in a gcc `.cold` / split symbol whose
        entry maps to the same line as the PC, falls back to the parent symbol (e.g.
        `check_heap_object`) so the range reaches the real function body.
      whole_function=True: same resolved start line, probe source with `gdb list`, locate the first
        lone opening-brace line (kernel style: `{` alone after the signature), then match `{`/`}`
        until brace depth returns to 0 (equivalent to finding the matching lone closing `}`). If
        that fails, end = max(PC line, start + listsize - 1); use -G / -M to widen.

    If symbol entry cannot be resolved, falls back to gdb list file:(line-fallback_before),line.

    `entry_pad_before`: when the start line comes from sym/dis (not the fallback window), move the
    listing start up by this many lines so multi-line `static inline` / `void foo(` declarations
    and `{` are included; DWARF often attributes the symbol address to the first executable line
    only (e.g. 164) and omits the signature (161--163). Set to 0 to disable.
    """
    try:
        addr_int = _parse_hex_addr(addr_str)
    except ValueError:
        print(f"[ERROR] Not a valid address: {addr_str!r}")
        return

    file_pc, line_pc = parse_dis_s(addr_int)
    if not file_pc or line_pc is None:
        print(f"[ERROR] No FILE:/LINE: in `dis -s {addr_str}` — build has no line info for this PC?")
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
            selected = lines[start:i + 1]
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

    MAX_PUSHES = 6  # for tg3_poll_work and similar prologues

    if frame_num == "exception":
        found = False
        for line in lines:
            if "[exception RIP:" in line:
                found = True
                continue
            if found:
                if line.strip().startswith("#"):  # next frame
                    break
                if ":" in line:
                    try:
                        _, data = line.strip().split(":", 1)
                        matches = re.findall(r"[0-9a-fA-F]{16}", data)
                        if matches:
                            if debug:
                                print(f"[DEBUG] Exception stack line: {line.strip()} => {matches}")
                            stack_vals.extend(matches)
                    except:
                        continue
        stack_vals = stack_vals[::-1]
        trimmed = stack_vals[:MAX_PUSHES + 1]
        if debug:
            print(f"[DEBUG] Parsed {len(trimmed)} exception stack entries (including return address)")
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
            matches = re.findall(r"[0-9a-fA-F]{16}", data)
            if matches:
                if debug:
                    print(f"[DEBUG] Line: {line.strip()} => {matches}")
                stack_vals.extend(matches)

    stack_vals = stack_vals[::-1]
    trimmed = stack_vals[:MAX_PUSHES + 1]
    if debug:
        print(f"[DEBUG] Parsed {len(trimmed)} stack values from frame #{frame_num} (including return addr)")
    return trimmed

def get_frame_rsp(frame_num):
    if frame_num == "exception":
        if EXCEPTION_RSP is not None:
            return EXCEPTION_RSP
        else:
            raise ValueError("Exception RSP not initialized.")

    bt_output = exec_crash_command("bt -f")
    lines = bt_output.splitlines()
    frame_pattern = re.compile(rf"^#{frame_num}\s+\[([0-9a-fA-F]+)\]")
    found = False

    for idx, line in enumerate(lines):
        if not found and frame_pattern.search(line.strip()):
            found = True
            continue
        if found:
            if ":" in line:
                addr_str = line.strip().split(":")[0]
                return int(addr_str, 16)
            elif line.strip().startswith("#"):
                break

    raise ValueError(f"Could not find RSP for frame #{frame_num}")

def annotate_pop_or_lea(instr_line, rsp, debug=False):
    instr = instr_line.strip().split(":", 1)[-1].strip()
    try:
        if instr.startswith("pop"):
            match = re.search(r"pop\s+(%\w+)", instr)
            if not match:
                return instr_line
            reg = match.group(1)
            val = readU64(rsp)
            annotated = f"{instr_line.rstrip():<60} {YELLOW}; {val:#018x}{RESET}"
            return annotated

        elif instr.startswith("lea"):
            rbp = get_reg("rbp")
            popped_val = readU64(rsp)
            msg = f"{instr_line.rstrip():<60} {MAGENTA}; %rsp ← %rbp ({rbp:#x}), pop %rbp = {popped_val:#018x}{RESET}"
            return msg

    except Exception as e:
        if debug:
            print(f"[DEBUG] pop/lea annotation failed: {e}")
    return instr_line

def disassemble_addresses_with_push_values(addresses, frames, deepest_frame, debug=False):
    for addr, frame in zip(addresses, frames):
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
                        sym_output = get_dis_symbol_context(addr_match.group(0), before_lines=args.lines - 1, debug=debug)
                        if sym_output:
                            print(f"{sym_output}")
                prev_line_was_source = False

            # Annotate push
            if 'push' in line and push_index < len(stack_vals):
                val = stack_vals[push_index]
                print(f"{line:<60} {YELLOW}; {val}{RESET}")
                push_index += 1
                continue

            # Annotate pop (reverse order)
            if 'pop' in line and pop_index >= 0:
                val = stack_vals[pop_index]
                print(f"{line:<60} {YELLOW}; {val}{RESET}")
                pop_index -= 1
                continue

            # RSP-relative mem access
            if ':' in line:
                disas = line.split(':', 1)[1].strip()
                disas = re.sub(r"^(lock|rep[nz]?)\s+", "", disas)

                rsp_offset_match = re.search(r"([-+]?)0x([0-9a-fA-F]+)\(%rsp\)", disas)
                if rsp_offset_match:
                    try:
                        sign = rsp_offset_match.group(1)
                        offset_hex = rsp_offset_match.group(2)
                        offset = int(offset_hex, 16)
                        if sign == "-":
                            offset = -offset

                        rsp_addr = get_frame_rsp(frame)
                        mem_addr = rsp_addr + offset

                        instr_match = re.search(r"\b(\w+)", disas)
                        instr_full = instr_match.group(1).lower() if instr_match else ""

                        suffix = ""
                        if instr_full[-1] in ("b", "w", "l", "q"):
                            instr, suffix = instr_full[:-1], instr_full[-1]
                        else:
                            instr = instr_full

                        if suffix == "b":
                            mem_val = readU8(mem_addr)
                            disp = f"{mem_val:#04x} (8-bit)"
                        elif suffix == "w":
                            mem_val = readU16(mem_addr)
                            disp = f"{mem_val:#06x} (16-bit)"
                        elif suffix == "l":
                            mem_val = readU32(mem_addr)
                            disp = f"{mem_val:#010x} (32-bit)"
                        elif suffix == "q":
                            mem_val = readU64(mem_addr)
                            disp = f"{mem_val:#018x} (64-bit)"
                        else:
                            mem_val = readU64(mem_addr)
                            disp = f"{mem_val:#018x}"

                        if debug:
                            print(f"[DEBUG] RSP: {hex(rsp_addr)} offset: {offset} → addr: {hex(mem_addr)} = {disp}")

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
            except:
                continue
    return deepest

def get_bt_addresses_exception_to_frame(upto_frame, debug=False):
    """
    Single-frame mode policy:
      - Start from requested frame N and walk toward 0 (stack grows bottom-up).
      - If an exception frame is encountered on that walk, stop there and use exception RIP
        as a synthetic "exception" frame entry.
      - If there is no exception on that path, return down to frame 0.
    """
    lines = exec_crash_command("bt -f").splitlines()
    deepest_frame = get_deepest_frame_number_from_bt_lines(lines)

    frame_addr = {}
    exception_anchor_frame = None  # frame number associated with [exception RIP: ...]
    last_seen_frame = None

    frame_line_re = re.compile(r"^#(\d+)\b")

    for raw in lines:
        line = raw.strip()
        m = frame_line_re.match(line)
        if m:
            fnum = int(m.group(1))
            toks = line.split()
            if len(toks) > 4:
                frame_addr[fnum] = toks[4]
            last_seen_frame = fnum
            continue

        if "[exception RIP:" in line and last_seen_frame is not None:
            exception_anchor_frame = last_seen_frame

    if upto_frame not in frame_addr:
        print(f"[ERROR] Could not find frame #{upto_frame} in backtrace.")
        return [], [], None

    addresses = []
    frames = []

    for fnum in range(upto_frame, -1, -1):
        if fnum not in frame_addr:
            continue

        if exception_anchor_frame is not None and fnum == exception_anchor_frame:
            # Replace anchor frame with synthetic exception frame and stop.
            addresses.append(frame_addr[fnum])  # temporary; may be replaced by parsed RIP below
            frames.append("exception")
            break

        frames.append(fnum)
        addresses.append(frame_addr[fnum])
        if debug:
            print(f"[DEBUG] Frame #{fnum} => {frame_addr[fnum]}")

    return addresses, frames, deepest_frame

def get_bt_addresses_range(start_frame, end_frame, debug=False):
    lines = exec_crash_command("bt -f").splitlines()
    deepest_frame = get_deepest_frame_number_from_bt_lines(lines)

    lo = min(start_frame, end_frame)
    hi = max(start_frame, end_frame)

    addresses = []
    frames = []
    frame_line_re = re.compile(r"^#(\d+)\b")

    for raw in lines:
        line = raw.strip()
        m = frame_line_re.match(line)
        if not m:
            continue
        fnum = int(m.group(1))
        if fnum < lo or fnum > hi:
            continue
        tokens = line.split()
        if len(tokens) > 4:
            frames.append(fnum)
            addresses.append(tokens[4])

    if not addresses and debug:
        print(f"[DEBUG] No addresses found between #{start_frame} and #{end_frame}")

    return addresses, frames, deepest_frame


def reorder_for_display(addresses, frames):
    """
    Display order policy:
      - numeric frames in descending order (human reading order)
      - synthetic exception frame last
    """
    pairs = list(zip(frames, addresses))
    normal = [(f, a) for f, a in pairs if isinstance(f, int)]
    exc = [(f, a) for f, a in pairs if not isinstance(f, int)]

    normal.sort(key=lambda x: x[0], reverse=True)
    ordered = normal + exc

    out_frames = [f for f, _ in ordered]
    out_addrs = [a for _, a in ordered]
    return out_addrs, out_frames


def parse_exception_rip_rsp_from_bt(bt_lines, debug=False):
    """
    Parse exception RIP/RSP from bt/bt -f output.
    We only trust the register dump line (e.g. 'RIP: <addr>  RSP: <addr>'),
    not the '[exception RIP: symbol+offset]' descriptor.
    """
    in_exception_block = False
    exception_rip = None
    exception_rsp = None

    for raw in bt_lines:
        line = raw.strip()
        if "[exception RIP:" in line:
            in_exception_block = True
            continue

        if not in_exception_block:
            continue

        if line.startswith("#"):
            break

        rip_match = re.search(r"\bRIP:\s+([0-9a-fA-F]{16})\b", line)
        rsp_match = re.search(r"\bRSP:\s+([0-9a-fA-F]{16})\b", line)
        if rip_match:
            exception_rip = rip_match.group(1)
        if rsp_match:
            exception_rsp = int(rsp_match.group(1), 16)
        if exception_rip and exception_rsp is not None:
            break

    if debug:
        print(
            f"[DEBUG] Parsed exception context: "
            f"RIP={exception_rip or 'None'} "
            f"RSP={hex(exception_rsp) if exception_rsp is not None else 'None'}"
        )
    return exception_rip, exception_rsp

# --- Main ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Disassemble and annotate pushed register values, or list C source for an address (gdb list).",
    )
    parser.add_argument("frames", metavar="N", type=int, nargs="*",
                        help="One frame number (exception RIP to frame), or a start and end range (default mode)")
    parser.add_argument(
        "-S", "--src",
        metavar="ADDR",
        help="List C source for kernel text ADDR: from function entry to this line (default), or a wider range with -w",
    )
    parser.add_argument(
        "-w", "--whole",
        action="store_true",
        help="With --src: from the same entry as default, extend listing to the matching `}` of the function "
        "body (brace-balance on gdb list output), else fall back to end = max(PC, start+G-1) within a -M line probe",
    )
    parser.add_argument(
        "-F", "--fallback-before",
        type=int,
        default=80,
        help="With --src: if symbol entry cannot be resolved, list this many lines before the PC line (default: 80)",
    )
    parser.add_argument(
        "-G", "--listsize",
        type=int,
        default=400,
        help="With --src -w: if brace-matching fails, use end = max(PC, start+G-1) (default: 400)",
    )
    parser.add_argument(
        "-M", "--max-probe",
        type=int,
        default=2500,
        metavar="LINES",
        help="With --src -w: gdb list this many source lines from entry for brace matching (default: 2500)",
    )
    parser.add_argument(
        "-P", "--entry-pad",
        type=int,
        default=6,
        metavar="N",
        help="With --src: when start line is from sym/dis, include N extra lines above it "
        "(signature/static inline; default: 6). Use 0 to disable, or 3 if only a few lines are missing.",
    )
    parser.add_argument("-l", "--lines", type=int, default=3,
                    help="In backtrace disassembly mode: lines to show from dis -s <addr> (default: 3)")
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
        addrs, frame_ids, deepest_frame = get_bt_addresses_exception_to_frame(args.frames[0], debug=args.debug)

        bt_lines = exec_crash_command("bt -f").splitlines()
        exception_rip, exception_rsp = parse_exception_rip_rsp_from_bt(bt_lines, debug=args.debug)

        if exception_rsp is not None:
            EXCEPTION_RSP = exception_rsp
            if args.debug:
                print(f"[DEBUG] Captured exception RSP: {hex(EXCEPTION_RSP)}")

        if "exception" in frame_ids:
            ex_idx = frame_ids.index("exception")
            if exception_rip:
                prev_addr = addrs[ex_idx - 1] if ex_idx > 0 else None
                if prev_addr and prev_addr.lower() == exception_rip.lower():
                    # Requested behavior: do not duplicate when previous frame already points at RIP.
                    if args.debug:
                        print(f"[DEBUG] Dropping duplicate exception RIP: {exception_rip}")
                    del addrs[ex_idx]
                    del frame_ids[ex_idx]
                else:
                    if args.debug:
                        print(f"[DEBUG] Using exception RIP for exception frame: {exception_rip}")
                    addrs[ex_idx] = exception_rip
            else:
                # Could not parse RIP; avoid disassembling a misleading frame address.
                if args.debug:
                    print("[DEBUG] No exception RIP parsed; dropping synthetic exception frame")
                del addrs[ex_idx]
                del frame_ids[ex_idx]

    elif len(args.frames) == 2:
        addrs, frame_ids, deepest_frame = get_bt_addresses_range(args.frames[0], args.frames[1], debug=args.debug)
    else:
        print("[ERROR] Use chk_dis <frame> or chk_dis <start> <end>")
        sys.exit(1)

    addrs, frame_ids = reorder_for_display(addrs, frame_ids)
    disassemble_addresses_with_push_values(addrs, frame_ids, deepest_frame, debug=args.debug)

