import pykdump.API as api
import sys
import argparse

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
    """
    Resolves an address from a given input, which could be a symbol or a raw address.
    Handles hex addresses with or without '0x' prefix.
    """
    try:
        # Check if input is a valid hex address (with or without '0x')
        if input_value.startswith("0x"):
            return int(input_value, 16)
        elif all(c in "0123456789abcdefABCDEF" for c in input_value):
            return int(input_value, 16)
        elif api.symbol_exists(input_value):
            # Retrieve symbol address if it exists
            return api.readSymbol(input_value)
        else:
            print(f"Error: '{input_value}' is neither a valid address nor a known symbol.")
            sys.exit(1)
    except Exception as e:
        print(f"Error resolving address for {input_value}: {e}")
        sys.exit(1)

def get_waiters(mutex):
    """
    Retrieves the list of tasks waiting on the mutex.
    """
    waiters = []
    wait_list = api.ListHead(int(mutex.wait_list), "struct mutex_waiter")
    for waiter in wait_list.list:
        task = waiter.task
        if task:
            state = task_state_array.get(task.__state, f"Unknown ({task.__state})")
            waiters.append((task.pid, task.comm, state))
    return waiters

def get_owner_info(owner_address):
    """
    Retrieves the PID, command name, and state of the owner task.
    """
    try:
        owner_address = int(owner_address, 16) if isinstance(owner_address, str) else owner_address
        owner_task = api.readSU("struct task_struct", owner_address)
        pid = owner_task.pid
        comm = owner_task.comm
        state = task_state_array.get(owner_task.__state, f"Unknown ({owner_task.__state})")
        return f"{hex(owner_address)} (PID: {pid}, COMM: {comm}, {state})"
    except Exception:
        return hex(owner_address)

def get_mutex_info(mutex_addr, list_waiters):
    """
    Fetches and analyzes mutex information from the VMcore based on RHEL9 structure.
    """
    try:
        mutex = api.readSU("struct mutex", mutex_addr)
    except Exception as e:
        print(f"Error accessing mutex at {hex(mutex_addr)}: {e}")
        return None
    
    # Extract owner address by masking out the flags
    owner_raw = mutex.owner.counter
    owner_address = owner_raw & ~0x07
    owner_address = owner_address & (2**64 - 1)  # Ensure unsigned 64-bit representation
    flags = owner_raw & 0x07
    
    flag_status = []
    if flags & 0x01:
        flag_status.append("WAITERS - Unlock must issue a wakeup")
    if flags & 0x02:
        flag_status.append("HANDOFF - Unlock needs to hand the lock to the top-waiter")
    if flags & 0x04:
        flag_status.append("PICKUP - Handoff has been done, waiting for pickup")
    
    lock_state = "Locked" if mutex.wait_lock.raw_lock.val.counter != 1 else "Unlocked"
    
    mutex_info = {
        "address": hex(mutex_addr),
        "owner": get_owner_info(owner_address) if owner_address else "None",  # Owner with PID and COMM
        "flags": flag_status if flag_status else ["NONE"],
        "wait_lock_val": mutex.wait_lock.raw_lock.val.counter,
        "wait_list_next": hex(mutex.wait_list.next),
        "wait_list_prev": hex(mutex.wait_list.prev),
        "locked": lock_state,
    }
    
    if list_waiters:
        mutex_info["waiters"] = get_waiters(mutex)
    
    return mutex_info

def analyze_mutex(mutex_info):
    """
    Analyzes mutex state and prints relevant information.
    """
    if not mutex_info:
        print("No valid mutex information found.")
        return
    
    print("\nMutex Analysis:")
    print("Address: ", mutex_info["address"])
    print("Owner Address: ", mutex_info["owner"])  # Properly formatted with PID and COMM
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
    
    mutex_addr = resolve_address(args.mutex)
    mutex_info = get_mutex_info(mutex_addr, args.list)
    analyze_mutex(mutex_info)

