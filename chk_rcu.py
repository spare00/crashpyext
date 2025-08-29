#!/usr/bin/env python3

import argparse
import re
from pykdump import *
from LinuxDump import percpu

# Threshold used ONLY for flagging very long per-CPU waits (cosmetic)
QS_WAIT_WARN_JIFFIES_DEFAULT = 10_000

def parse_sys():
    """Parse 'crash> sys' to obtain HZ, CPU count, panic time/msg, release."""
    out = exec_crash_command("sys")
    hz = None
    cpus = None
    panic_time = "Unknown"
    panic_message = "Unknown"
    kernel_version = "Unknown"

    for line in out.splitlines():
        line = line.strip()
        m = re.search(r'\bHZ:\s*(\d+)', line)
        if m:
            hz = int(m.group(1))
        m = re.search(r'\bCPUS:\s*(\d+)\b', line)
        if m:
            cpus = int(m.group(1))
        else:
            m = re.search(r'\bCPUS:\s*0-(\d+)\b', line)
            if m:
                cpus = int(m.group(1)) + 1
        if line.startswith("PANIC:"):
            panic_message = line.replace("PANIC:", "").strip()
        if line.startswith("UPTIME:"):
            panic_time = line.replace("UPTIME:", "").strip()
        if "RELEASE" in line:
            # e.g., "RELEASE: 4.18.0-553.66.1.el8_10.x86_64"
            parts = line.split()
            if parts:
                kernel_version = parts[-1]

    # Sensible fallbacks
    if hz is None:
        hz = 1000
    if cpus is None:
        # Final fallback: try /sys output again in a simpler way
        m = re.search(r'CPUS:\s*(\d+)', out)
        cpus = int(m.group(1)) if m else 0

    return out, hz, cpus, panic_time, panic_message, kernel_version

def detect_rhel_version(kernel_version: str) -> int:
    """Rough map of kernel major to RHEL generation."""
    # RHEL7 ~ 3.10, RHEL8 ~ 4.18, RHEL9 ~ 5.14
    if kernel_version.startswith("3."):
        return 7
    elif kernel_version.startswith("4."):
        return 8
    elif kernel_version.startswith("5."):
        return 9
    else:
        # Default to latest we know
        return 9

def get_current_jiffies():
    try:
        return int(readSymbol("jiffies"))
    except Exception:
        print("Warning: Could not read jiffies.")
        return None

def get_symbol_addr(symbol):
    try:
        output = exec_crash_command(f"sym {symbol}")
        addr = output.split()[0]  # e.g., "ffffffff815a1234"
        return int(addr, 16)
    except Exception:
        return None

def get_rcu_state(rhel_version, verbose=False, debug=False):
    # Symbol names differ for RHEL7 vs 8/9
    rcu_state_symbol = "rcu_sched_state" if rhel_version == 7 else "rcu_state"
    rcu_state_addr = get_symbol_addr(rcu_state_symbol)
    if not rcu_state_addr:
        print(f"Error: {rcu_state_symbol} symbol not found.")
        return None

    try:
        rcu_state = readSU("struct rcu_state", rcu_state_addr)
        if debug:
            print(f"[Debug] {rcu_state_symbol} @ 0x{rcu_state_addr:x}")

        # Common fields we need on 4.18+ (RHEL8/9). RHEL7 handled via different logic below.
        if rhel_version == 7:
            # 7.x has completed/gpnum (numbers) and optionally gp_start in backports.
            completed = int(getattr(rcu_state, "completed"))
            gpnum = int(getattr(rcu_state, "gpnum"))
            gp_in_progress = (completed != gpnum)
            gp_start = getattr(rcu_state, "gp_start", 0)
            jiffies_stall = getattr(rcu_state, "jiffies_stall", 0)
            gp_seq = gpnum  # for display
            state_bits = 1 if gp_in_progress else 0
        else:
            gp_seq = int(getattr(rcu_state, "gp_seq"))
            gp_start = int(getattr(rcu_state, "gp_start"))
            jiffies_stall = int(getattr(rcu_state, "jiffies_stall"))
            # Lower 2 bits encode state; 0 == idle
            state_bits = gp_seq & 0x3
            gp_in_progress = (state_bits != 0)

        print("\n=== Global RCU State ===")
        print(f"Current GP Sequence Number: {gp_seq}")
        print(f"Grace Period Start Timestamp (jiffies): {gp_start}")
        print(f"Next Stall-Check Deadline (jiffies_stall): {jiffies_stall}")
        if gp_in_progress:
            print("⏳ RCU grace period is currently in progress.")
        else:
            print("✔️  No active RCU grace period detected.")

        if verbose:
            print(f"\n[Verbose] Raw RCU State:\n{rcu_state}")

        return {
            "rcu_state": rcu_state,
            "gp_seq": gp_seq,
            "gp_start": gp_start,
            "jiffies_stall": jiffies_stall,
            "gp_in_progress": gp_in_progress,
            "state_bits": state_bits,
        }
    except Exception as e:
        print(f"Failed to read RCU state: {e}")
        return None

def get_per_cpu_rcu_data(rcu_ctx, rhel_version, hz, verbose=False, debug=False):
    # Pull sys info for CPUs/HZ
    _sys_out, sys_hz, cpu_count_val, *_ = parse_sys()
    if hz is None:
        hz = sys_hz
    if cpu_count_val == 0:
        print("Error: No CPUs detected, cannot proceed with per-CPU data.")
        return

    jiffies_now = get_current_jiffies()
    gp_start = rcu_ctx["gp_start"]
    gp_in_progress = rcu_ctx["gp_in_progress"]
    jiffies_stall = rcu_ctx["jiffies_stall"]

    gp_duration = (jiffies_now - gp_start) if (jiffies_now is not None and gp_start) else None
    qs_warn_jiffies = QS_WAIT_WARN_JIFFIES_DEFAULT

    if gp_duration is not None:
        print(f"\n🕒 GP Duration: {gp_duration} jiffies (~{gp_duration/float(hz):.3f}s @ HZ={hz})")

    print("\n=== Per-CPU RCU Status ===")
    print(f"{'CPU':<5} {'GP-Seq':<18} {'Awaiting-QS':<12} {'GP-State':<10} {'Since-GP-Start':<20}")

    any_qs_pending = False

    for cpu in range(cpu_count_val):
        try:
            if rhel_version == 7:
                addr = percpu.get_cpu_var("rcu_sched_data")[cpu]
                rcu_data = readSU("struct rcu_data", addr)
                gp_value = int(getattr(rcu_data, "gpnum"))
                qs_pending = bool(getattr(rcu_data, "qs_pending"))
                in_prog_cpu = (gp_value != int(getattr(rcu_ctx["rcu_state"], "completed")))
            else:
                addr = percpu.get_cpu_var("rcu_data")[cpu]
                rcu_data = readSU("struct rcu_data", addr)
                gp_value = int(getattr(rcu_data, "gp_seq"))
                # In 4.18+, core_needs_qs indicates CPU must report a QS
                qs_pending = bool(getattr(rcu_data, "core_needs_qs"))
                in_prog_cpu = ((gp_value & 0x3) != 0)

            any_qs_pending = any_qs_pending or qs_pending

            since_gp = (jiffies_now - gp_start) if (jiffies_now is not None and gp_start) else None
            since_gp_str = f"{since_gp} j (~{since_gp/float(hz):.3f}s)" if isinstance(since_gp, int) else "N/A"

            warn_flag = ""
            if qs_pending and isinstance(since_gp, int) and since_gp >= qs_warn_jiffies:
                warn_flag = " ⚠️"

            gp_state_str = "In progress" if in_prog_cpu else "idle"
            print(f"{cpu:<5} {gp_value:<18} {str(qs_pending):<12} {gp_state_str:<10} {since_gp_str:<20}{warn_flag}")

            if debug:
                print(f"   [Debug] rcu_data[{cpu}] @ {addr:#x}")

        except Exception as e:
            print(f"{cpu:<5} ❌ Failed to read RCU data: {e}")

    # Final stall assessment:
    # A stall is plausible only if:
    #   (1) GP is in progress,
    #   (2) we are at/past the stall-check deadline, and
    #   (3) at least one CPU still needs a QS.
    stalled = bool(gp_in_progress and (jiffies_now is not None)
                   and jiffies_stall and (jiffies_now >= jiffies_stall) and any_qs_pending)

    if stalled:
        print("\n⚠️  RCU stall suspected: GP in progress, past stall-check deadline, and some CPUs still await QS.")
    else:
        # Avoid a false positive when the GP just started or all CPUs have already QS'd.
        if gp_in_progress and not any_qs_pending:
            # Give a small slack window before declaring anything suspicious.
            slack_ok = (gp_duration is not None and gp_duration < max(hz // 2, 50))
            if slack_ok:
                print("\nℹ️  All CPUs have reported QS; GP likely between aggregation and completion (normal).")
            else:
                print("\nℹ️  All CPUs appear to have QS; if GP remains in-progress for a long time, re-check later.")

def show_info():
    print("""
🔍 RCU Terminology Reference
=============================

📌 Grace Period (GP):
    - A grace period is a timeframe during which all CPUs must pass through a "quiescent state."
    - RCU defers freeing or modifying data until the grace period ends to ensure all pre-existing readers are done.

🛑 Quiescent State (QS):
    - A state in which a CPU is guaranteed not to be accessing any RCU-protected data.
    - Typical quiescent states include:
        - Returning to user space
        - Going idle
        - Context switches (for kernel RCU)

✅ RCU Progress:
    - A new grace period starts -> CPUs are marked as needing a QS
    - Once all CPUs report QS -> GP completes -> deferred actions proceed

🧠 Why it Matters:
    - If a CPU doesn't report QS, the GP stalls
    - This could cause hangs, memory leaks, or delayed cleanup

🧭 Visual Workflow
==================

                      🧠 RCU Grace Period Workflow
                      ============================

                    [RCU Subsystem Starts GP]
                              |
                              v
            +-------------------------------------------+
            | Mark all CPUs as needing Quiescence State |
            +-------------------------------------------+
                              |
                              v
     +-------------------+   +-------------------+   +-------------------+
     | CPU 0 in kernel   |   | CPU 1 to userspace|   | CPU 2 idle        |
     | -> no QS yet      |   | -> reports QS ✅   |   | -> reports QS ✅   |
     +-------------------+   +-------------------+   +-------------------+
                              |
     <=== Waiting for all CPUs to report QS ===>
                              |
                              v
                  +-----------------------------+
                  | All CPUs reached QS ✅        |
                  | Grace Period Completed ✅     |
                  +-----------------------------+
                              |
                              v
                 [Deferred callbacks executed 🧹]

Tip: Use '-v' to see raw structure contents for advanced debugging.
""")

def main():
    parser = argparse.ArgumentParser(description="RCU state checker for crash VMcore analysis.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-d", "--debug", action="store_true", help="Show debug info (struct addresses, symbols)")
    args = parser.parse_args()

    print("=== 🛠️ RCU Status Check ===")
    sys_out, hz, cpus, panic_time, panic_message, kernel_version = parse_sys()
    rhel_version = detect_rhel_version(kernel_version)

    print(f"⏱️ UPtime: {panic_time}")
    print(f"⚠️ Panic Message: {panic_message}")
    print(f"🖥️ Kernel Version: {kernel_version} (Detected RHEL {rhel_version})")
    print(f"🧮 HZ: {hz}   🧵 CPUs: {cpus}")

    rcu_ctx = get_rcu_state(rhel_version, args.verbose, args.debug)
    if rcu_ctx:
        get_per_cpu_rcu_data(rcu_ctx, rhel_version, hz, args.verbose, args.debug)

    if args.verbose:
        show_info()

if __name__ == "__main__":
    main()
