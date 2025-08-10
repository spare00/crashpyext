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

def get_dis_symbol_context(addr, before_lines=1, debug=False):
    """
    Run 'dis -s <addr>' and return `*` line with N lines before it.
    """
    output = exec_crash_command(f"dis -s {addr}")
    lines = output.strip().splitlines()

    for i, line in enumerate(lines):
        if line.strip().startswith("*"):
            start = max(i - before_lines, 0)
            selected = lines[start:i + 1]
            if debug:
                print(f"[DEBUG] Symbol context for {addr}")
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
    lines = exec_crash_command("bt -f").splitlines()
    deepest_frame = get_deepest_frame_number_from_bt_lines(lines)

    start_index = None
    end_marker = f"#{upto_frame}"
    addresses = []
    frames = []

    for idx, line in enumerate(lines):
        if start_index is None and 'exception RIP' in line:
            start_index = idx
        if start_index is not None and line.strip().startswith(end_marker):
            target_lines = lines[start_index:idx + 1]
            break
    else:
        # If no 'exception RIP' found, start from the beginning
        if start_index is None:
            print("[WARN] 'exception RIP' not found. Starting from the first frame.")
            start_index = 0
            for idx, line in enumerate(lines):
                if line.strip().startswith(end_marker):
                    target_lines = lines[start_index:idx + 1]
                    break
            else:
                print(f"[ERROR] Could not find frame #{upto_frame} from start of backtrace.")
                return [], [], None
        else:
            print(f"[ERROR] Could not find frame #{upto_frame} after 'exception RIP'.")
            return [], [], None

    for line in target_lines:
        tokens = line.strip().split()
        if tokens and tokens[0].startswith('#') and len(tokens) > 4:
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
    parser = argparse.ArgumentParser(description="Disassemble and annotate pushed register values")
    parser.add_argument("frames", metavar="N", type=int, nargs="+",
                        help="One frame number (exception RIP to frame), or a start and end range")
    parser.add_argument("-l", "--lines", type=int, default=3,
                    help="Number of lines to show from dis -s <addr> (default: 3)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if len(args.frames) == 1:
        addrs, frame_ids, deepest_frame = get_bt_addresses_exception_to_frame(args.frames[0], debug=args.debug)

        # Check for exception RIP
        bt_lines = exec_crash_command("bt").splitlines()
        exception_rip = None
        for line in bt_lines:
            if 'RIP:' in line:
                match = re.search(r'RIP:\s+([0-9a-fA-F]+)', line)
                if match:
                    exception_rip = match.group(1)
                    break

        if exception_rip:
            first_addr = addrs[0] if addrs else None
            if first_addr and exception_rip.lower() != first_addr.lower():
                # Also extract RSP
                for line in bt_lines:
                    if 'RIP:' in line and 'RSP:' in line:
                        m = re.search(r'RSP:\s+([0-9a-fA-F]+)', line)
                        if m:
                            EXCEPTION_RSP = int(m.group(1), 16)
                            if args.debug:
                                print(f"[DEBUG] Captured exception RSP: {hex(EXCEPTION_RSP)}")
                        break

                if EXCEPTION_RSP:
                    if args.debug:
                        print(f"[DEBUG] Adding exception RIP disassembly: {exception_rip}")
                    addrs.insert(0, exception_rip)
                    frame_ids.insert(0, "exception")

    elif len(args.frames) == 2:
        addrs, frame_ids, deepest_frame = get_bt_addresses_range(args.frames[0], args.frames[1], debug=args.debug)
    else:
        print("[ERROR] Use chk_dis <frame> or chk_dis <start> <end>")
        sys.exit(1)

    disassemble_addresses_with_push_values(addrs, frame_ids, deepest_frame, debug=args.debug)


