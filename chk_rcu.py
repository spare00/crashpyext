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

def get_rcu_state():
    rcu_state_addr = get_symbol_addr("rcu_sched_state")
    if not rcu_state_addr:
        print("Error: rcu_sched_state symbol not found.")
        return None

    try:
        rcu_state = readSU("struct rcu_state", rcu_state_addr)
        print("\n=== Global RCU-Sched State ===")
        print(f"Last Completed Grace Period: {rcu_state.gpnum}")
        print(f"Current Grace Period: {rcu_state.completed}")
        if rcu_state.gpnum == rcu_state.completed:
            print("Warning: Grace period not advancing - possible RCU stall.")
        return rcu_state
    except Exception as e:
        print(f"Failed to read RCU state: {e}")
        return None

def get_per_cpu_rcu_data(rcu_state):
    cpu_count_val = get_cpu_count()
    if cpu_count_val == 0:
        print("Error: No CPUs detected, cannot proceed with per-CPU data.")
        return

    rcu_data_base = get_symbol_addr("rcu_sched_data")
    if rcu_data_base:
        print("\n=== Per-CPU RCU Data (via rcu_sched_data) ===")
        for cpu in range(cpu_count_val):
            try:
                rcu_data_addr = percpu.get_cpu_var("rcu_sched_data")[cpu]
                rcu_data = readSU("struct rcu_data", rcu_data_addr)

                print(f"CPU {cpu}:")
                print(f"  Grace Period: {rcu_data.gpnum}")
                print(f"  Completed: {rcu_data.completed}")
                print(f"  Quiescent State Pending: {rcu_data.qs_pending}")
                if rcu_data.gpnum != rcu_data.completed:
                    print("  Warning: CPU may be stalled - grace period mismatch.")
                if rcu_data.qs_pending != 0:
                    print("  Note: Quiescent state still pending.")
            except AttributeError as e:
                print(f"  Failed to access RCU fields for CPU {cpu}: {e}")
                print("  Run 'crash> struct rcu_data' to verify fields.")
            except Exception as e:
                print(f"  Failed to read rcu_data for CPU {cpu}: {e}")
    else:
        print("Error: Could not access per-CPU RCU data - rcu_sched_data not available.")

def main():
    print("=== RCU Status Check ===")
    sys_output = exec_crash_command("sys")
    panic_time = "Unknown"
    kernel_version = "Unknown"
    for line in sys_output.splitlines():
        if "PANIC" in line:
            panic_time = line.strip() if line.strip() != 'PANIC: ""' else "Unknown"
        elif "RELEASE" in line:
            kernel_version = line.split()[-1]

    print(f"Crash Time: {panic_time}")
    print(f"Kernel Version: {kernel_version}")

    rcu_state = get_rcu_state()
    get_per_cpu_rcu_data(rcu_state)

if __name__ == "__main__":
    main()

