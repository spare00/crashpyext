import pykdump.API as api
import sys

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

def get_mutex_info(mutex_addr):
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
        "owner": hex(owner_address) if owner_address else "None",  # Correctly formatted unsigned 64-bit hex
        "flags": flag_status if flag_status else ["NONE"],
        "wait_lock_val": mutex.wait_lock.raw_lock.val.counter,
        "wait_list_next": hex(mutex.wait_list.next),
        "wait_list_prev": hex(mutex.wait_list.prev),
        "locked": lock_state
    }

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
    print("Owner Address: ", mutex_info["owner"])  # Properly formatted
    print("Flags: ", ", ".join(mutex_info["flags"]))
    print("Wait Lock Value: ", mutex_info["wait_lock_val"])
    print("Wait List Next: ", mutex_info["wait_list_next"])
    print("Wait List Prev: ", mutex_info["wait_list_prev"])
    print("Status: ", mutex_info["locked"])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python chk_mutex.py <mutex_address_or_symbol>")
        sys.exit(1)

    mutex_addr = resolve_address(sys.argv[1])
    mutex_info = get_mutex_info(mutex_addr)
    analyze_mutex(mutex_info)

