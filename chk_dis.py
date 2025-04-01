#!/usr/bin/env epython

from pykdump.API import *
import sys
import argparse

# ANSI color codes
RED     = '\033[91m'
GREEN   = '\033[92m'
YELLOW  = '\033[93m'
BLUE    = '\033[94m'
MAGENTA = '\033[95m'
CYAN    = '\033[96m'
RESET   = '\033[0m'
BOLD    = '\033[1m'

def get_bt_addresses_exception_to_frame(upto_frame, debug=False):
    lines = exec_crash_command("bt").splitlines()
    start_index = None
    end_marker = f"#{upto_frame}"
    addresses = []

    for idx, line in enumerate(lines):
        if start_index is None and 'exception RIP' in line:
            start_index = idx
            if debug:
                print(f"[DEBUG] Found 'exception RIP' at line {idx}")
        if start_index is not None and line.strip().startswith(end_marker):
            target_lines = lines[start_index:idx + 1]
            break
    else:
        print(f"[ERROR] Could not find 'exception RIP' or frame #{upto_frame}")
        return []

    for line in target_lines:
        tokens = line.strip().split()
        if tokens and tokens[0].startswith('#') and len(tokens) > 4:
            addresses.append(tokens[4])
            if debug:
                print(f"[DEBUG] Captured address: {tokens[4]}")

    return addresses

def get_bt_addresses_range(start_frame, end_frame, debug=False):
    lines = exec_crash_command("bt").splitlines()
    addresses = []
    start_tag = f"#{start_frame}"
    end_tag = f"#{end_frame}"
    capturing = False

    for line in lines:
        line = line.strip()
        if line.startswith(start_tag):
            capturing = True

        if capturing and line.startswith("#"):
            tokens = line.split()
            if len(tokens) > 4:
                addresses.append(tokens[4])
                if debug:
                    print(f"[DEBUG] Captured address: {tokens[4]}")

        if line.startswith(end_tag) and capturing:
            break

    if not addresses and debug:
        print(f"[DEBUG] No addresses found between #{start_frame} and #{end_frame}")

    return addresses

def disassemble_addresses(addresses, debug=False):
    for addr in reversed(addresses):
        comm = f"dis -rl {addr}"
        print(f"\n{CYAN}{BOLD}--- {comm} ---{RESET}\n")
        if debug:
            print(f"{RED}[DEBUG]{RESET} Running: {comm}")
        output = exec_crash_command(comm)
        print(output if output.strip() else f"{RED}[WARNING]{RESET} No disassembly output.")

# --- Main ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Disassemble stack frame addresses")
    parser.add_argument("frames", metavar="N", type=int, nargs="+",
                        help="One frame number (exception RIP to frame), or a start and end range")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if len(args.frames) == 1:
        addrs = get_bt_addresses_exception_to_frame(args.frames[0], debug=args.debug)
    elif len(args.frames) == 2:
        addrs = get_bt_addresses_range(args.frames[0], args.frames[1], debug=args.debug)
    else:
        print("[ERROR] Invalid number of frame arguments. Use: chk_dis <end> OR chk_dis <start> <end>")
        sys.exit(1)

    for a in addrs:
        print(a)

    disassemble_addresses(addrs, debug=args.debug)

