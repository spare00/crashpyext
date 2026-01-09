#!/usr/bin/env python3

import argparse
import re
from pykdump import *
from LinuxDump import percpu

# Threshold used ONLY for flagging very long per-CPU waits (cosmetic)
QS_WAIT_WARN_JIFFIES_DEFAULT = 10_000

MAX_JIFFIES_BITS = 64  # x86_64 kernels use 64-bit jiffies; adjust if needed

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
        # Some crash builds show "CPUS: <min>-<max> (<count> total)"
        if cpus is None:
            m = re.search(r'\bCPUS:\s*\d+-\d+\s*\((\d+)\s+total\)', line)
            if m:
                cpus = int(m.group(1))
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

def jiffies_mask(bits=MAX_JIFFIES_BITS):
    return (1 << bits) - 1

def jiffies_diff(now, then, bits=MAX_JIFFIES_BITS):
    """Return unsigned jiffies delta handling wraparound like time_after()."""
    if now is None or then is None:
        return None
    mask = jiffies_mask(bits)
    return (now - then) & mask

def get_current_jiffies():
    try:
        return int(readSymbol("jiffies"))
    except Exception:
        print("Warning: Could not read jiffies.")
        return None

def get_symbol_addr(symbol):
    try:
        output = exec_crash_command(f"sym {symbol}")
        # Expect first token to be address, tolerate leading symbol name on some builds
        tokens = output.split()
        addr_token = tokens[0] if tokens and tokens[0].startswith(("0x","ffff","fffff")) else (tokens[1] if len(tokens) > 1 else None)
        addr = addr_token if addr_token is not None else tokens[0]
        return int(addr, 16)
    except Exception:
        return None

def decode_gp_seq_v4(gp_seq: int):
    """On 4.18+ low 2 bits are state, upper bits are sequence."""
    state_bits = gp_seq & 0x3
    seq = gp_seq >> 2
    return seq, state_bits

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
            gp_seq = gpnum  # for display (no bit encoding on 3.10)
            state_bits = 1 if gp_in_progress else 0
            disp_gp_seq = gp_seq
            completed_val = completed
        else:
            gp_seq = int(getattr(rcu_state, "gp_seq"))
            gp_start = int(getattr(rcu_state, "gp_start"))
            jiffies_stall = int(getattr(rcu_state, "jiffies_stall"))
            # Lower 2 bits encode state; 0 == idle
            state_bits = gp_seq & 0x3
            gp_in_progress = (state_bits != 0)
            disp_gp_seq, _ = decode_gp_seq_v4(gp_seq)

        print("\n=== Global RCU State ===")
        if rhel_version == 7:
            print(f"Current GP Number: {disp_gp_seq} (completed={completed_val}, in_progress={bool(state_bits)})")
        else:
            print(f"Current GP Sequence Number: {disp_gp_seq} (raw=0x{gp_seq:x}, state_bits={state_bits})")
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

def get_per_cpu_rcu_data(rcu_ctx, rhel_version, hz, verbose=False, debug=False, qs_warn_jiffies=None, cpu_filter=None, do_stall_check=True):
    # Pull sys info for CPUs/HZ
    _sys_out, sys_hz, cpu_count_val, *_ = parse_sys()
    if hz is None:
        hz = sys_hz
    if cpu_count_val == 0:
        print("Error: No CPUs detected, cannot proceed with per-CPU data.")
        return {"any_qs_pending": False, "qs_pending_cpus": set(), "cpu_count": 0}

    jiffies_now = get_current_jiffies()
    gp_start = rcu_ctx["gp_start"]
    gp_in_progress = rcu_ctx["gp_in_progress"]
    jiffies_stall = rcu_ctx["jiffies_stall"]

    gp_duration = jiffies_diff(jiffies_now, gp_start) if (jiffies_now is not None and gp_start) else None
    if qs_warn_jiffies is None:
        qs_warn_jiffies = QS_WAIT_WARN_JIFFIES_DEFAULT

    if gp_duration is not None:
        print(f"\n🕒 GP Duration: {gp_duration} jiffies (~{gp_duration/float(hz):.3f}s @ HZ={hz})")
    if jiffies_now is not None and jiffies_stall:
        until_stall = jiffies_diff(jiffies_stall, jiffies_now)
        print(f"⏱️ Now jiffies: {jiffies_now}   Stall deadline: {jiffies_stall}   Δ(now→stall): {until_stall} j")

    print("\n=== Per-CPU RCU Status ===")
    print(f"{'CPU':<5} {'GP-Seq':<18} {'QS-Reported':<12} {'GP-State':<10} {'Since-GP-Start':<20}")

    any_qs_pending = False
    qs_pending_cpus = set()

    for cpu in range(cpu_count_val):
        if cpu_filter is not None and cpu not in cpu_filter:
            continue
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
            if qs_pending:
                qs_pending_cpus.add(cpu)

            since_gp = jiffies_diff(jiffies_now, gp_start) if (jiffies_now is not None and gp_start) else None
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

    if not do_stall_check:
        return {"any_qs_pending": any_qs_pending, "qs_pending_cpus": qs_pending_cpus, "cpu_count": cpu_count_val}

    # Final stall assessment:
    # A stall is plausible only if:
    #   (1) GP is in progress,
    #   (2) we are at/past the stall-check deadline, and
    #   (3) at least one CPU still needs a QS.
    at_or_past_deadline = False
    if jiffies_now is not None and jiffies_stall:
        # time_after_eq(jiffies_now, jiffies_stall)
        at_or_past_deadline = (jiffies_diff(jiffies_now, jiffies_stall) < (1 << (MAX_JIFFIES_BITS - 1)))
    stalled = bool(gp_in_progress and at_or_past_deadline and any_qs_pending)

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
    return {"any_qs_pending": any_qs_pending, "qs_pending_cpus": qs_pending_cpus, "cpu_count": cpu_count_val}

def _format_cpu_list(cpus):
    """Format a sorted iterable of CPU IDs into compact ranges: [0-3,5,7-9]."""
    if not cpus:
        return "[]"
    s = sorted(cpus)
    ranges = []
    start = prev = s[0]
    for x in s[1:]:
        if x == prev + 1:
            prev = x
        else:
            ranges.append((start, prev))
            start = prev = x
    ranges.append((start, prev))
    parts = [f"{a}" if a == b else f"{a}-{b}" for a, b in ranges]
    return "[" + ",".join(parts) + "]"

def last_rcu_stall_summary():
    """
    Parse 'crash> log' for the most recent 'rcu_sched self-detected stall on CPU' block.
    Returns dict with keys: t_jiffies, g, c, cpus (set), raw_lines (optional), or None if not found.
    """
    try:
        out = exec_crash_command("log")
    except Exception:
        return None
    lines = out.splitlines()
    # Find all indices where a stall begins
    start_idxs = [i for i, l in enumerate(lines) if "rcu_sched self-detected stall on CPU" in l]
    if not start_idxs:
        return None
    # Take the last stall block
    i = start_idxs[-1]
    # Collect until we hit next stall start, "Task dump", or a big gap
    end = len(lines)
    for j in range(i + 1, min(i + 400, len(lines))):
        if "rcu_sched self-detected stall on CPU" in lines[j]:
            end = j
            break
        if "Task dump for CPU" in lines[j]:
            end = j  # stop before task dump spam
            break
    block = lines[i:end]
    # Extract CPUs listed between braces and the (t=..., g=..., c=...) tuple(s)
    cpu_set = set()
    t_val = g_val = c_val = None
    for l in block:
        if "(t=" in l and "g=" in l and "c=" in l:
            m = re.search(r't=(\d+)\s*jiffies.*?g=(\d+)\s*c=(\d+)', l)
            if m:
                t_val, g_val, c_val = map(int, m.groups())
        # Try to pick integers that look like CPU IDs; ignore absurdly large numbers
        if "{" in l or "}" in l:
            for m in re.finditer(r'\b(\d{1,4})\b', l):
                try:
                    cpu = int(m.group(1))
                    # we’ll bound-check against actual CPU count in main()
                    cpu_set.add(cpu)
                except Exception:
                    pass
    return {"t_jiffies": t_val, "g": g_val, "c": c_val, "cpus": cpu_set, "raw_lines": block}

def show_info():
    print("""
🔍 RCU Terminology Reference
=============================

📌 Grace Period (GP):
    - A grace period is a timeframe during which all CPUs must pass through a "quiescent state."
    - RCU defers freeing or modifying data until the grace period ends to ensure all pre-existing readers are done.

🛑 Quiescent State (QS):
    - A state in which a CPU is guaranteed to have exited any RCU read-side critical sections that began before this point
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
    parser.add_argument("--qs-warn", type=int, default=QS_WAIT_WARN_JIFFIES_DEFAULT,
                        help=f"Warn threshold for per-CPU QS wait in jiffies (default {QS_WAIT_WARN_JIFFIES_DEFAULT})")
    parser.add_argument("--cpu", type=str, help="Comma/Range list to limit CPUs (e.g. '0,2,5-8')")
    parser.add_argument("--no-stall-check", action="store_true", help="Skip final stall assessment")
    args = parser.parse_args()

    print("=== 🛠️ RCU Status Check ===")
    sys_out, hz, cpus, panic_time, panic_message, kernel_version = parse_sys()
    rhel_version = detect_rhel_version(kernel_version)

    print(f"⏱️ UPtime: {panic_time}")
    print(f"⚠️ Panic Message: {panic_message}")
    print(f"🖥️ Kernel Version: {kernel_version} (Detected RHEL {rhel_version})")
    print(f"🧮 HZ: {hz}   🧵 CPUs: {cpus}")

    # Summarize last RCU stall, if any
    stall = last_rcu_stall_summary()
    if stall:
        # Filter CPU IDs to the detected CPU count to avoid stray numbers
        cpus_in_log = sorted([x for x in stall["cpus"] if isinstance(x, int) and 0 <= x < max(cpus, 1)])
        t_j = stall.get("t_jiffies")
        g = stall.get("g")
        c = stall.get("c")
        t_sec = (t_j / float(hz)) if (t_j is not None and hz) else None
        print("\n=== Last RCU stall (from log) ===")
        if t_j is not None:
            print(f"Duration at report: {t_j} jiffies (~{t_sec:.3f}s @ HZ={hz})")
        if g is not None and c is not None:
            print(f"GP numbers: g={g}  c={c}  (in_progress={g != c})")
        print(f"CPUs listed: {_format_cpu_list(cpus_in_log)}")

    rcu_ctx = get_rcu_state(rhel_version, args.verbose, args.debug)
    if rcu_ctx:
        cpu_filter = None
        if args.cpu:
            # parse "0,2,5-8"
            s = args.cpu.replace(" ", "")
            sel = set()
            for part in s.split(","):
                if "-" in part:
                    a, b = part.split("-", 1)
                    sel.update(range(int(a), int(b) + 1))
                elif part:
                    sel.add(int(part))
            cpu_filter = sorted(sel)
        per_cpu = get_per_cpu_rcu_data(rcu_ctx, rhel_version, hz, args.verbose, args.debug,
                                       qs_warn_jiffies=args.qs_warn, cpu_filter=cpu_filter,
                                       do_stall_check=not args.no_stall_check)
        # If we had a stall in logs, show overlap with current QS pending set
        if stall and isinstance(per_cpu, dict):
            pending = sorted(per_cpu.get("qs_pending_cpus", []))
            overlap = sorted(set(pending).intersection(stall["cpus"]))
            print("\n=== Correlation ===")
            print(f"Currently QS-Reported CPUs: {_format_cpu_list(pending)}")
            print(f"Overlap with last-stall CPUs: {_format_cpu_list(overlap)}")

    if args.verbose:
        show_info()

if __name__ == "__main__":
    main()
