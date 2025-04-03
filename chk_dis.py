#!/usr/bin/env epython

from pykdump.API import *
import sys
import argparse
import re

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

def parse_bt_frame_stack(frame_num, debug=False):
    bt_output = exec_crash_command("bt -f")
    lines = bt_output.splitlines()
    stack_vals = []
    frame_pattern = re.compile(rf"^#{frame_num}\b")
    found = False

    for line in lines:
        if not found and frame_pattern.match(line.strip()):
            found = True
            continue
        if found:
            if line.strip().startswith("#"):
                break  # end of this frame
            parts = line.strip().split(":", 1)
            if len(parts) != 2:
                continue
            data = parts[1].strip()
            matches = re.findall(r"[0-9a-fA-F]{16}", data)
            if matches:
                if debug:
                    print(f"[DEBUG] Line: {line.strip()} => {matches}")
                stack_vals.extend(matches)

    # reverse the full stack to go bottom-to-top
    stack_vals = stack_vals[::-1]

    if debug:
        print(f"[DEBUG] Parsed {len(stack_vals)} stack values from frame #{frame_num}")
        print(f"[DEBUG] Skipping return address: {stack_vals[0] if stack_vals else 'N/A'}")
        print(f"[DEBUG] Stack values before slicing: {stack_vals}")

    if len(stack_vals) < 2:
        return []

    return stack_vals[1:]  # skip return address (first word from bottom-right)

def get_frame_rsp(frame_num):
    bt_output = exec_crash_command("bt -f")
    lines = bt_output.splitlines()
    frame_pattern = re.compile(rf"^#{frame_num}\s+\[([0-9a-fA-F]+)\]")
    found = False

    for idx, line in enumerate(lines):
        if not found and frame_pattern.search(line.strip()):
            found = True
            continue
        if found:
            # Find first stack line after frame header
            if ":" in line:
                addr_str = line.strip().split(":")[0]
                return int(addr_str, 16)
            elif line.strip().startswith("#"):
                break  # Next frame started, nothing found

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
            # lea = mov %rbp, %rsp; pop %rbp
            rbp = get_reg("rbp")
            popped_val = readU64(rbp)
            msg = f"{instr_line.rstrip():<60} {MAGENTA}; %rsp ← %rbp ({rbp:#x}), pop %rbp = {popped_val:#018x}{RESET}"
            return msg

    except Exception as e:
        if debug:
            print(f"[DEBUG] pop/lea annotation failed: {e}")
    return instr_line

def disassemble_addresses_with_push_values(addresses, frames, deepest_frame, debug=False):
    for addr, frame in zip(reversed(addresses), reversed(frames)):
        comm = f"dis -rl {addr}"
        print(f"\n\033[96m\033[1m--- {comm} (frame #{frame}) ---\033[0m\n")
        if debug:
            print(f"[DEBUG] Running: {comm}")

        output = exec_crash_command(comm)
        if not output.strip():
            print("[WARNING] No disassembly output.")
            continue

        if frame == deepest_frame:  # skip the deepest frame (e.g., entry_SYSCALL_64)
            stack_vals = []
            if debug:
                print(f"[DEBUG] Skipping deepest frame #{frame}")
        else:
            stack_vals = parse_bt_frame_stack(frame, debug=debug)

        # Track push order dynamically
        push_index = 0
        push_instructions = []
        for line in output.splitlines():
            # Highlight push values if available
            match = re.search(r"push\s+(%\w+)", line)
            if match and push_index < len(stack_vals):
                reg = match.group(1)
                val = stack_vals[push_index]
                print(f"{line:<60} \033[93m; {val}\033[0m")
                push_index += 1
                continue

            # Handle pop/leave
            if any(op in line for op in ("pop", "leave")):
                rsp = get_frame_rsp(frame)
                annotated = annotate_pop_or_lea(line, rsp, debug=debug)
                print(annotated)
                continue

            # Highlight RSP-relative memory references
            if '%rsp' in line:
                print(f"[DEBUG] Potential RSP line: {line}")
            # Clean out prefixes and extract just the disassembly part
            if ':' in line:
                disas = line.split(':', 1)[1].strip()
                disas = re.sub(r"^(lock|rep[nz]?)\s+", "", disas)

                # Match offset relative to %rsp
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

                        # Extract the instruction name (e.g., movl, addq, cmp)
                        instr_match = re.search(r"\b(\w+)", disas)
                        instr_full = instr_match.group(1).lower() if instr_match else ""

                        # Determine suffix from instruction name
                        suffix = ""
                        if instr_full[-1] in ("b", "w", "l", "q"):
                            instr, suffix = instr_full[:-1], instr_full[-1]
                        else:
                            instr = instr_full  # no suffix, assume default

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
                            # Default to 64-bit for 64-bit kernel work
                            mem_val = readU64(mem_addr)
                            disp = f"{mem_val:#018x}"

                        if debug:
                            print(f"[DEBUG] instr: {instr_full}, parsed: {instr}, suffix: {suffix}")
                            print(f"[DEBUG] RSP: {hex(rsp_addr)} offset: {offset} → addr: {hex(mem_addr)} = {disp}")

                        line = line.rstrip() + f"    \033[94m; 0x{mem_addr:x} = {disp}\033[0m"

                    except Exception as e:
                        if debug:
                            print(f"[DEBUG] Memory read failed: {e}")

            print(line)

        for line, reg in push_instructions:
            if reg and push_index < len(stack_vals):
                val = stack_vals[push_index]
                print(f"{line:<60} {YELLOW}; {val}{RESET}")
                push_index += 1
            else:
                print(line)

def get_deepest_frame_number_from_bt_lines(lines):
    """Extract the highest frame number from a bt -f output."""
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
        print(f"[ERROR] Could not find 'exception RIP' or frame #{upto_frame}")
        return [], [], None

    for line in target_lines:
        tokens = line.strip().split()
        if tokens and tokens[0].startswith('#') and len(tokens) > 4:
            frames.append(int(tokens[0][1:]))
            addresses.append(tokens[4])
            if debug:
                print(f"[DEBUG] Frame #{frames[-1]} => {addresses[-1]}")

    return addresses, frames, deepest_frame  # deepest frame #


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
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if len(args.frames) == 1:
        addrs, frame_ids, deepest_frame = get_bt_addresses_exception_to_frame(args.frames[0], debug=args.debug)
    elif len(args.frames) == 2:
        addrs, frame_ids, deepest_frame = get_bt_addresses_range(args.frames[0], args.frames[1], debug=args.debug)
    else:
        print("[ERROR] Use chk_dis <frame> or chk_dis <start> <end>")
        sys.exit(1)

    disassemble_addresses_with_push_values(addrs, frame_ids, deepest_frame, debug=args.debug)
