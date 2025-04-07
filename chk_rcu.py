import argparse
from pykdump import *
from LinuxDump import percpu

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

def get_rcu_state(rhel_version, verbose=False):
    rcu_state_symbol = "rcu_sched_state" if rhel_version == 7 else "rcu_state"
    rcu_state_addr = get_symbol_addr(rcu_state_symbol)
    if not rcu_state_addr:
        print(f"Error: {rcu_state_symbol} symbol not found.")
        return None

    try:
        rcu_state = readSU("struct rcu_state", rcu_state_addr)
        print("\n=== Global RCU State ===")
        if verbose:
            print(f"RCU symbol: {rcu_state_symbol}")
            print(f"Address: 0x{rcu_state_addr:x}")

        if rhel_version == 7:
            in_progress = rcu_state.completed != rcu_state.gpnum
            print(f"Last Completed Grace Period: {rcu_state.completed}")
            print(f"Current Grace Period: {rcu_state.gpnum}")
        else:
            gs1 = rcu_state.gp_seq
            gps = rcu_state.gp_start
            js = rcu_state.jiffies_stall
            gs2 = rcu_state.gp_seq  # Re-check for stall detection

            in_progress = gs1 & 0b11  # Lower 2 bits indicate state
            stalled = (gs1 == gs2) and (gps < js)

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

        return rcu_state
    except Exception as e:
        print(f"Failed to read RCU state: {e}")
        return None

def get_per_cpu_rcu_data(rcu_state, rhel_version, verbose=False):
    cpu_count_val = get_cpu_count()
    if cpu_count_val == 0:
        print("Error: No CPUs detected, cannot proceed with per-CPU data.")
        return

    print("\n=== Per-CPU RCU Status ===")
    print(f"{'🔹 CPU':<10} {'📌 GP Sequence':<16} {'🚦 Awaiting Quiescence':<22} {'🚦 GP In Progress'}")

    for cpu in range(cpu_count_val):
        try:
            if rhel_version == 7:
                rcu_data = readSU("struct rcu_data", percpu.get_cpu_var("rcu_sched_data")[cpu])
                gp_field = "gpnum"
                qs_field = "qs_pending"
                in_progress = rcu_data.gpnum != rcu_state.completed
            else:
                rcu_data = readSU("struct rcu_data", percpu.get_cpu_var("rcu_data")[cpu])
                gp_field = "gp_seq"
                qs_field = "core_needs_qs"
                in_progress = (rcu_data.gp_seq & 0b11) != 0

            gp_value = getattr(rcu_data, gp_field, 'N/A')
            qs_value = getattr(rcu_data, qs_field, 'N/A') if hasattr(rcu_data, qs_field) else "⚠️ Unknown"

            print(f"   {cpu:<11} {gp_value:<17} {'True' if qs_value else 'False':<23} {'✅' if in_progress else '⛔'}")

            if verbose:
                print(f"      [Verbose] rcu_data[{cpu}]: {rcu_data}")

        except Exception as e:
            print(f"   {cpu:<10} ❌ Failed to read RCU data: {e}")

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
                +-----------------------------+
                | Mark all CPUs as needing QS |
                +-----------------------------+
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
    args = parser.parse_args()
    verbose = args.verbose

    print("=== 🛠️ RCU Status Check ===")
    panic_time, panic_message, kernel_version = get_panic_info()
    rhel_version = detect_rhel_version(kernel_version)

    print(f"⏱️ Crash Time: {panic_time}")
    print(f"⚠️ Panic Message: {panic_message}")
    print(f"🖥️ Kernel Version: {kernel_version} (Detected RHEL {rhel_version})")

    rcu_state = get_rcu_state(rhel_version, verbose)
    if rcu_state:
        get_per_cpu_rcu_data(rcu_state, rhel_version, verbose)

    if verbose:
        show_info()

if __name__ == "__main__":
    main()

