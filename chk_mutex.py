import pykdump.API as api
import sys
import argparse

def get_rhel_version():
    """Determines the major RHEL version from the kernel release."""
    sys_output = exec_crash_command("sys")
    kernel_version = "Unknown"
    rhel_version = 8  # Default to RHEL 8+

    for line in sys_output.splitlines():
        if "RELEASE" in line:
            kernel_version = line.split()[-1]
            if "el" in kernel_version:
                try:
                    rhel_version = int(kernel_version.split(".el")[1][0])
                except (IndexError, ValueError):
                    pass

    print(f"Detected RHEL Version: {rhel_version} (Kernel: {kernel_version})")
    return rhel_version


task_state_array = {
    0x00: "R (running)",
    0x01: "S (sleeping)",
    0x02: "D (disk sleep)",
    0x04: "T (stopped)",
    0x08: "t (tracing stop)",
    0x10: "X (dead)",
    0x20: "Z (zombie)",
    0x40: "P (parked)",
    0x80: "I (idle)"
}

def resolve_address(input_value):
    try:
        if input_value.startswith("0x"):
            return int(input_value, 16)
        elif all(c in "0123456789abcdefABCDEF" for c in input_value):
            return int(input_value, 16)
        elif symbol_exists(input_value):
            return readSymbol(input_value)
        else:
            print(f"Error: '{input_value}' is neither a valid address nor a known symbol.")
            sys.exit(1)
    except Exception as e:
        print(f"Error resolving address for {input_value}: {e}")
        sys.exit(1)

def get_waiters(mutex, rhel_version):
    waiters = []
    wait_list = ListHead(int(mutex.wait_list), "struct mutex_waiter")
    for waiter in wait_list.list:
        task = waiter.task
        if task:
            state = task_state_array.get(task.__state, f"Unknown ({task.__state})")
            waiters.append((task.pid, task.comm, state))
    return waiters

def get_owner_info(owner_address):
    try:
        owner_address = int(owner_address, 16) if isinstance(owner_address, str) else owner_address
        owner_task = readSU("struct task_struct", owner_address)
        pid = owner_task.pid
        comm = owner_task.comm
        state = task_state_array.get(owner_task.__state, f"Unknown ({owner_task.__state})")
        return f"{hex(owner_address)} (PID: {pid}, COMM: {comm}, {state})"
    except Exception:
        return hex(owner_address)

def get_mutex_info(mutex_addr, list_waiters, rhel_version):
    try:
        mutex = readSU("struct mutex", mutex_addr)
    except Exception as e:
        print(f"Error accessing mutex at {hex(mutex_addr)}: {e}")
        return None

    owner_raw = mutex.owner.counter if rhel_version >= 8 else mutex.owner
    owner_address = owner_raw & ~0x07
    owner_address = owner_address & (2**64 - 1)
    flags = owner_raw & 0x07

    flag_status = []
    if flags & 0x01:
        flag_status.append("WAITERS - Unlock must issue a wakeup")
    if flags & 0x02:
        flag_status.append("HANDOFF - Unlock needs to hand the lock to the top-waiter")
    if flags & 0x04:
        flag_status.append("PICKUP - Handoff has been done, waiting for pickup")

    wait_lock_val = (mutex.wait_lock.raw_lock.val.counter if rhel_version >= 8
                     else mutex.wait_lock.rlock.raw_lock.val.counter)
    lock_state = "Locked" if wait_lock_val != 1 else "Unlocked"

    mutex_info = {
        "address": hex(mutex_addr),
        "owner": get_owner_info(owner_address) if owner_address else "None",
        "flags": flag_status if flag_status else ["NONE"],
        "wait_lock_val": wait_lock_val,
        "wait_list_next": hex(mutex.wait_list.next),
        "wait_list_prev": hex(mutex.wait_list.prev),
        "locked": lock_state,
    }

    if list_waiters:
        mutex_info["waiters"] = get_waiters(mutex, rhel_version)

    return mutex_info

def analyze_mutex(mutex_info):
    if not mutex_info:
        print("No valid mutex information found.")
        return

    print("\nMutex Analysis:")
    print("Address: ", mutex_info["address"])
    print("Owner Address: ", mutex_info["owner"])
    print("Flags: ", ", ".join(mutex_info["flags"]))
    print("Wait Lock Value: ", mutex_info["wait_lock_val"])
    print("Wait List Next: ", mutex_info["wait_list_next"])
    print("Wait List Prev: ", mutex_info["wait_list_prev"])
    print("Status: ", mutex_info["locked"])

    if "waiters" in mutex_info and mutex_info["waiters"]:
        print("\nWaiting Tasks:")
        print("{:<10} {:<20} {:<15}".format("PID", "Command", "State"))
        print("-" * 50)
        for pid, comm, state in mutex_info["waiters"]:
            print("{:<10} {:<20} {:<15}".format(pid, comm, state))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze mutex state in a VMcore.")
    parser.add_argument("mutex", help="Mutex address or symbol name")
    parser.add_argument("-l", "--list", action="store_true", help="List tasks waiting on the mutex")
    args = parser.parse_args()

    rhel_version = get_rhel_version()
    mutex_addr = resolve_address(args.mutex)
    mutex_info = get_mutex_info(mutex_addr, args.list, rhel_version)
    analyze_mutex(mutex_info)

