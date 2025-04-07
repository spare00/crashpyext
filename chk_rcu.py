import argparse
from pykdump import *
from LinuxDump import percpu

QS_WAIT_WARN_JIFFIES = 10000  # Example threshold for flagging long waits (adjustable)
HZ = 1000  # Jiffies per second (can be system-specific)

def get_current_jiffies():
    """Read the current jiffies value."""
    try:
        return int(readSymbol("jiffies"))
    except Exception:
        print("Warning: Could not read jiffies.")
        return None

def get_symbol_addr(symbol):
    """Get the address of a kernel symbol."""
    try:
        output = exec_crash_command(f"sym {symbol}")
        addr = output.split()[0]  # e.g., "ffffffff815a1234"
        return int(addr, 16)
    except Exception:
        return None

def get_cpu_count():
    """Get the number of CPUs from sys output."""
    try:
        sys_output = exec_crash_command("sys")
        for line in sys_output.splitlines():
            if "CPUS" in line:
                return int(line.split()[-1])  # e.g., "CPUS: 4" -> 4
        print("Error: Could not determine CPU count from sys output.")
        return 0
    except Exception as e:
        print(f"Failed to get CPU count: {e}")
        return 0

def get_panic_info():
    """Extract panic time, message, and kernel version from sys output."""
    sys_output = exec_crash_command("sys")
    panic_time = "Unknown"
    panic_message = "Unknown"
    kernel_version = "Unknown"

    for line in sys_output.splitlines():
        if "PANIC:" in line:
            panic_message = line.strip().replace("PANIC:", "").strip()
        elif "TIME:" in line:
            panic_time = line.strip().replace("TIME:", "").strip()
        elif "RELEASE" in line:
            kernel_version = line.split()[-1]

    return panic_time, panic_message, kernel_version

def detect_rhel_version(kernel_version):
    """Determine RHEL major version from kernel version."""
    if kernel_version.startswith("3."):
        return 7
    elif kernel_version.startswith("4.") or kernel_version.startswith("5."):
        return 8
    else:
        return 9  # Default to RHEL9+ if unknown

def get_rcu_state(rhel_version, verbose=False, debug=False):
    rcu_state_symbol = "rcu_sched_state" if rhel_version == 7 else "rcu_state"
    rcu_state_addr = get_symbol_addr(rcu_state_symbol)
    if not rcu_state_addr:
        print(f"Error: {rcu_state_symbol} symbol not found.")
        return None

    try:
        rcu_state = readSU("struct rcu_state", rcu_state_addr)
        print("\n=== Global RCU State ===")

        if debug:
            print(f"[Debug] {rcu_state_symbol} @ 0x{rcu_state_addr:x}")

        if rhel_version == 7:
            in_progress = rcu_state.completed != rcu_state.gpnum
            gp_start = getattr(rcu_state, "gp_start", None)
            print(f"Last Completed Grace Period: {rcu_state.completed}")
            print(f"Current Grace Period: {rcu_state.gpnum}")
        else:
            gs1 = rcu_state.gp_seq
            gps = rcu_state.gp_start
            js = rcu_state.jiffies_stall
            gs2 = rcu_state.gp_seq
            print(f"gps: {gps}")
            in_progress = gs1 & 0b11
            stalled = (gs1 == gs2) and (gps < js)
            gp_start = gps

            print(f"Current GP Sequence Number: {gs1}")
            print(f"Grace Period Start Timestamp: {gps}")
            print(f"Last Jiffies Stall Check: {js}")

            if stalled:
                print("⚠️ Warning: RCU stall detected! The grace period may not be progressing.")

        if in_progress:
            print("✅ RCU grace period is currently in progress.")
        else:
            print("⛔ No active RCU grace period detected.")

        if verbose:
            print(f"\n[Verbose] Raw RCU State:\n{rcu_state}")

        return rcu_state, in_progress, gp_start
    except Exception as e:
        print(f"Failed to read RCU state: {e}")
        return None

def get_per_cpu_rcu_data(rcu_state, rhel_version, verbose=False, debug=False, gp_in_progress=False, gp_start=None):
    cpu_count_val = get_cpu_count()
    if cpu_count_val == 0:
        print("Error: No CPUs detected, cannot proceed with per-CPU data.")
        return

    jiffies_now = get_current_jiffies()
    if jiffies_now is not None and gp_start is not None:
        gp_duration = jiffies_now - gp_start
        print(f"\n🕒 GP Duration (jiffies): {gp_duration}")
    else:
        gp_duration = None

    print("\n=== Per-CPU RCU Status ===")
    print(f"{'🔹 CPU':<6} {'📌 GP Sequence':<16} {'🚦 Awaiting QS':<14} {'🚦 GP In Progress':<20} {'⏱️ Time since GP start(jiffies)'}")

    any_qs_pending = False

    for cpu in range(cpu_count_val):
        try:
            if rhel_version == 7:
                addr = percpu.get_cpu_var("rcu_sched_data")[cpu]
                rcu_data = readSU("struct rcu_data", addr)
                gp_field = "gpnum"
                qs_field = "qs_pending"
                in_progress = rcu_data.gpnum != rcu_state.completed
            else:
                addr = percpu.get_cpu_var("rcu_data")[cpu]
                rcu_data = readSU("struct rcu_data", addr)
                gp_field = "gp_seq"
                qs_field = "core_needs_qs"
                in_progress = (rcu_data.gp_seq & 0b11) != 0

            gp_value = getattr(rcu_data, gp_field, 'N/A')
            qs_value = getattr(rcu_data, qs_field, 'N/A') if hasattr(rcu_data, qs_field) else "⚠️ Unknown"

            qs_value = getattr(rcu_data, qs_field, 'N/A') if hasattr(rcu_data, qs_field) else "⚠️ Unknown"
            qs_pending = bool(qs_value)

            if qs_pending:
                any_qs_pending = True

            time_in_gp = (jiffies_now - gp_start) if (jiffies_now and gp_start) else "N/A"

            if not qs_pending:
                wait_after_qs = (jiffies_now - gp_start) if (jiffies_now and gp_start) else "N/A"
            else:
                wait_after_qs = 0

            # Calculate human-readable time
            if isinstance(wait_after_qs, int) and wait_after_qs > 0:
                wait_sec = round(wait_after_qs / HZ, 1)
                wait_str = f"{wait_sec}s ({wait_after_qs})"
            else:
                wait_str = "0s (0)" if wait_after_qs == 0 else "N/A"

            # Highlight long waits
            if isinstance(wait_after_qs, int) and wait_after_qs >= QS_WAIT_WARN_JIFFIES:
                wait_flag = "⚠️"
            else:
                wait_flag = ""

            print(f"   {cpu:<7} {gp_value:<17} {'True' if qs_pending else 'False':<15} "
                    f"{'⏳' if in_progress else '✔️':16}  ⏱️ {wait_str} {wait_flag}")

            if debug:
                print(f"      [Debug] rcu_data[{cpu}]: <struct rcu_data {addr:#x}>")

        except Exception as e:
            print(f"   {cpu:<10} ❌ Failed to read RCU data: {e}")

    # 🛑 Add warning if no CPUs have QS pending, but GP still in progress
    if not any_qs_pending and gp_in_progress:
        print("\n⚠️ Warning: All CPUs have reported QS, but GP has not completed.")
        print("   → This may indicate an RCU stall or scheduling issue (common on virtualized guests).")

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
    verbose = args.verbose
    debug = args.debug

    print("=== 🛠️ RCU Status Check ===")
    panic_time, panic_message, kernel_version = get_panic_info()
    rhel_version = detect_rhel_version(kernel_version)

    print(f"⏱️ Crash Time: {panic_time}")
    print(f"⚠️ Panic Message: {panic_message}")
    print(f"🖥️ Kernel Version: {kernel_version} (Detected RHEL {rhel_version})")

    rcu_state, in_progress, gp_start = get_rcu_state(rhel_version, verbose, debug)
    if rcu_state:
        get_per_cpu_rcu_data(rcu_state, rhel_version, verbose, debug, in_progress, gp_start)

    if verbose:
        show_info()

if __name__ == "__main__":
    main()

