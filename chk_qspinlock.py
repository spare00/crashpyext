import argparse
import sys
from pykdump.API import *

RHEL_VERSION = 8

def get_rhel_version():
    """Determines the major RHEL version from the kernel release."""
    sys_output = exec_crash_command("sys")

    for line in sys_output.splitlines():
        if "RELEASE" in line:
            kernel_version = line.split()[-1]
            if "el" in kernel_version:
                try:
                    RHEL_VERSION = int(kernel_version.split(".el")[1][0])
                except (IndexError, ValueError) as e:
                    logging(f"Error retrieving RHEL version: {e}")
                    pass

    print(f"Detected RHEL Version: {RHEL_VERSION} (Kernel: {kernel_version})")
    return RHEL_VERSION

def to_binary(value, bits):
    """ Convert a value to a zero-padded binary string of given bit length. """
    return f"{value:0{bits}b}"

def format_binary(counter, bitfield):
    """ Format the binary representation with correct spacing, including unused bits. """
    bin_str = to_binary(counter, 32)

    locked_bits = bin_str[-8:]  # Bits 0-7 (8 bits for locked byte)
    pending_bits = bin_str[-(bitfield["pending_start"] + 1):-bitfield["pending_start"]]  # Bit 8 (1 bit)
    unused_bits = bin_str[-(bitfield["unused_start"] + bitfield["unused_bits"]):-bitfield["unused_start"]]  # Unused Bits
    tail_index_bits = bin_str[-(bitfield["tail_index_start"] + bitfield["tail_index_bits"]):-bitfield["tail_index_start"]]  # Tail Index
    tail_cpu_bits = bin_str[:-(bitfield["tail_cpu_start"])]  # Tail CPU

    return f"{tail_cpu_bits} {tail_index_bits} {unused_bits} {pending_bits} {locked_bits}"

def show_qspinlock_flowchart():
    """ Display the qspinlock state transition flowchart. """
    print("\n=== QSpinlock Flowchart ===")
    print(r"""
(queue tail, pending bit, lock value)

                fast     :    slow                                  :    unlock
                         :                                          :
 uncontended    (0,0,0) -:--> (0,0,1) ------------------------------:--> (*,*,0)
                         :       | ^--------.------.             /  :
                         :       v           \      \            |  :
 pending                 :    (0,1,1) +--> (0,1,0)   \           |  :
                         :       | ^--'              |           |  :
                         :       v                   |           |  :
 uncontended             :    (n,x,y) +--> (n,0,0) --'           |  :
   queue                 :       | ^--'                          |  :
                         :       v                               |  :
 contended               :    (*,x,y) +--> (*,0,0) ---> (*,0,1) -'  :
   queue                 :         ^--'                             :
    """)
    print("========================\n")

def analyze_qspinlock(qspinlock_addr, verbose=False, debug=False):
    """ Analyze qspinlock status based on the given counter value and RHEL version. """
    qspinlock = readSU("struct qspinlock", qspinlock_addr)

    # Convert counter to 32-bit unsigned integer
    counter = qspinlock.val.counter & 0xFFFFFFFF

    if RHEL_VERSION == 7:
        bitfield = {
            "locked_start": 0,  # Bits 0-7 (Locked byte)
            "pending_start": 8,  # Bit 8
            "unused_start": 9,   # Bits 9-15 unused
            "tail_index_start": 16,  # Bits 16-18 (3 bits) for NR_CPUS <= 8K
            "tail_cpu_start": 19,  # Bits 19-31 (13 bits)
            "unused_bits": 7,  # 7 bits unused (9-15)
            "tail_index_bits": 3,  # 3-bit tail index
            "tail_cpu_bits": 13,  # 13-bit tail CPU
            "tail_cpu_offset": 0  # No +1 for tail CPU in RHEL7
        }
    else:  # Default: RHEL 8/9 (NR_CPUS < 16K)
        bitfield = {
            "locked_start": 0,  # Bits 0-7 (Locked byte)
            "pending_start": 8,  # Bit 8
            "unused_start": 9,   # Bits 9-15 unused
            "tail_index_start": 16,  # Bits 16-17 (2 bits)
            "tail_cpu_start": 18,  # Bits 18-31 (14 bits)
            "unused_bits": 7,  # 7 bits unused (9-15)
            "tail_index_bits": 2,  # 2-bit tail index
            "tail_cpu_bits": 14,  # 14-bit tail CPU
            "tail_cpu_offset": 1  # Tail CPU is stored as (CPU ID + 1) in RHEL8/9
        }

    # Extract bit fields
    locked = (counter >> bitfield["locked_start"]) & 0xFF
    pending = (counter >> bitfield["pending_start"]) & 0x1
    unused_bits = (counter >> bitfield["unused_start"]) & ((1 << bitfield["unused_bits"]) - 1)
    tail_index = (counter >> bitfield["tail_index_start"]) & ((1 << bitfield["tail_index_bits"]) - 1)
    tail_cpu_raw = (counter >> bitfield["tail_cpu_start"]) & ((1 << bitfield["tail_cpu_bits"]) - 1)
    tail_cpu = tail_cpu_raw - bitfield["tail_cpu_offset"]

    print("\n=== QSpinlock Status (RHEL {}) ===".format(RHEL_VERSION))
    print(f"Counter Value:   0x{counter:X} ({counter})")
    print(f"Binary:          {format_binary(counter, bitfield)}")
    print(f"Locked Byte:     0x{locked:02X}  ({to_binary(locked, 8)})")
    print(f"Pending:         {'Yes' if pending else 'No'}  ({to_binary(pending, 1)})")
    print(f"Unused Bits:     {to_binary(unused_bits, bitfield['unused_bits'])}")
    print(f"Tail Index:      {tail_index}  ({to_binary(tail_index, bitfield['tail_index_bits'])})")
    print(f"Tail CPU:        {tail_cpu if tail_cpu >= 0 else 'None'}  ({to_binary(tail_cpu_raw, bitfield['tail_cpu_bits'])})")
    print("========================\n")

    print("=== Possible Scenarios ===")

    if locked == 0:
        if tail_index == 0:
            print("✅ Lock is FREE. No CPUs are waiting.")
        else:
            print("⚠️ Lock is free, but tail index is non-zero. This could indicate a release race condition.")

    elif locked != 0:
        if tail_index == 0:
            if pending == 0:
                print("🔒 Lock is HELD, but NO CPUs are waiting. The current owner may be executing a critical section.")
            else:
                print("⚠️ Inconsistent state detected! Pending bit is set, but no CPUs are queued. Possible race condition or spinlock corruption.")
        elif tail_index > 0 and tail_cpu >= 0:
            print(f"🔄 Lock is HELD, and {tail_index} CPU(s) are WAITING.")
            print(f"  - The last CPU to join the queue is CPU {tail_cpu}.")
            if pending:
                print("  - A pending waiter is actively spinning (indicating contention).")
            else:
                print("  - No active waiter spinning; queued CPUs may be sleeping or scheduled to wake up.")

        if tail_index > 5:
            print("⚠️ High contention detected! More than 5 CPUs are waiting. Consider optimizing locking strategies.")

    if pending == 1 and tail_index > 0:
        print("⚠️ Lock is held, and a waiter is in a pending loop. This indicates potential contention.")

    if pending == 1 and tail_index == 0:
        print("❗ Warning: Pending bit is set, but no CPUs are queued. This may indicate a race condition.")

    if tail_cpu < 0 and tail_index > 0:
        print("⚠️ Invalid tail CPU detected! This could indicate a corrupted spinlock state.")

    print("========================\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze qspinlock status in RHEL")
    parser.add_argument("qspinlock_addr", type=lambda x: int(x, 16), help="Memory address of qspinlock (hex)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed data")
    parser.add_argument("-d", "--debug", action="store_true", help="Show debug data.")
    parser.add_argument("-f", "--flowchart", action="store_true", help="Display qspinlock flowchart.")

    args = parser.parse_args()

    # Get basic info
    RHEL_VERSION = get_rhel_version()

    if args.flowchart:
        show_qspinlock_flowchart()

    analyze_qspinlock(args.qspinlock_addr, args.verbose, args.debug)

