#!/usr/bin/env python3

import sys
import argparse
from pykdump.API import readSU  # Importing ePython API for VMcore analysis

# Global variable
kernel_version = "Unknown"
RHEL_VERSION = 8
DEBUG = False

def logging(str):
    if DEBUG:
        print(f"{str}")

def get_rhel_version():
    """Determines the major RHEL version from the kernel release."""
    sys_output = exec_crash_command("sys")

    for line in sys_output.splitlines():
        if "RELEASE" in line:
            kernel_version = line.split()[-1]
            if "el" in kernel_version:
                logging(int(kernel_version.split(".el")[1][0]))
                try:
                    RHEL_VERSION = int(kernel_version.split(".el")[1][0])
                except (IndexError, ValueError) as e:
                    logging(f"Error retrieving RHEL version: {e}")
                    pass

    print(f"Detected RHEL Version: {RHEL_VERSION} (Kernel: {kernel_version})")
    return RHEL_VERSION

def get_architecture():
    """Determines the system architecture from VMcore."""
    sys_output = exec_crash_command("sys")
    arch = "64-bit"  # Default to 64-bit

    for line in sys_output.splitlines():
        if "BIOS" in line or "Kernel" in line:
            if "x86_64" in line:
                arch = "64-bit"
            elif "i686" in line or "i386" in line:
                arch = "32-bit"

    print(f"Detected Architecture: {arch}")
    return arch

task_state_array = {
    0x00: "TASK_RUNNING",
    0x01: "TASK_INTERRUPTIBLE",
    0x02: "TASK_UNINTERRUPTIBLE",
    0x04: "__TASK_STOPPED",
    0x08: "__TASK_TRACED",
    0x10: "EXIT_DEAD",
    0x20: "EXIT_ZOMBIE",
    0x40: "TASK_PARKED" if RHEL_VERSION >= 8 else "TASK_DEAD",
    0x80: "TASK_DEAD" if RHEL_VERSION >= 8 else "TASK_WAKEKILL",
    0x100: "TASK_WAKEKILL" if RHEL_VERSION >= 8 else "TASK_WAKING",
    0x200: "TASK_WAKING" if RHEL_VERSION >= 8 else "TASK_PARKED",
    0x400: "TASK_NOLOAD" if RHEL_VERSION >= 8 else "TASK_STATE_MAX",
    0x800: "TASK_NEW" if RHEL_VERSION >= 8 else "TASK_STATE_MAX",
    0x1000: "TASK_RTLOCK_WAIT" if RHEL_VERSION  >= 8 else "TASK_STATE_MAX",
    0x2000: "TASK_STATE_MAX" if RHEL_VERSION >= 9 else "TASK_STATE_MAX",
}

def check_integrity(count, owner, signed_count, reader_owned, writer_task_struct):
    """ Perform logical integrity checks on rw_semaphore values. """

    issues = []

    RWSEM_FLAG_READFAIL = 1 << 63
    RWSEM_WRITER_LOCKED = 1 << 0
    RWSEM_FLAG_WAITERS  = 1 << 1
    RWSEM_FLAG_HANDOFF  = 1 << 2
    RWSEM_READER_BIAS   = 1 << 8

    # Check if RWSEM_FLAG_READFAIL is set
    if count & RWSEM_FLAG_READFAIL:
        flags = []
        if count & RWSEM_WRITER_LOCKED:
            flags.append("WRITER_LOCKED")
        if count & RWSEM_FLAG_WAITERS:
            flags.append("WAITERS_PRESENT")
        if count & RWSEM_FLAG_HANDOFF:
            flags.append("HANDOFF")

        if flags:
            issues.append(f"ℹ️ RWSEM_FLAG_READFAIL set with: {', '.join(flags)} — likely a transitional contention state.")
        else:
            issues.append("ℹ️ RWSEM_FLAG_READFAIL set — benign reader acquisition failure (no other flags set).")

        # ✅ Transitional state — skip strict checks
        return issues

    # Reader-held state
    if signed_count > 0:
        if RHEL_VERSION == 8:
            if not reader_owned:
                issues.append("⚠️ Inconsistent: `count` is positive (read-held), but `owner` does not indicate reader ownership.")
            if writer_task_struct != 0 and not reader_owned:
                issues.append("⚠️ Suspicious Owner: Nonzero `owner` without RWSEM_READER_OWNED while read-locked.")
        elif RHEL_VERSION == 7:
            if writer_task_struct != 0:
                issues.append("⚠️ Unexpected: `owner` should be 0 in RHEL 7 when read-locked.")

        if signed_count % RWSEM_READER_BIAS != 0:
            issues.append("⚠️ Reader count not aligned to RWSEM_READER_BIAS (256). Possible corruption.")

    # Writer-held or invalid state
    elif signed_count < 0:
        if writer_task_struct == 0:
            issues.append("⚠️ Missing Owner: `count` is negative but `owner` is 0 (expected writer task).")
        if reader_owned:
            issues.append("⚠️ Conflict: `owner` marked as reader, but `count` is negative (write-lock).")
        if signed_count < -1:
            issues.append("🚨 INVALID STATE: `count < -1` suggests multiple writers — this is a BUG.")

    # Free lock
    elif signed_count == 0:
        if writer_task_struct != 0:
            issues.append("⚠️ `owner` field not cleared: lock is free but `owner` is set.")

    # Reserved bits check (bits 3–7)
    reserved_mask = 0b11111000
    if count & reserved_mask:
        issues.append("⚠️ Reserved bits (3–7) are set — should be 0.")

    return issues

def to_binary(value, bits=64):
    """Convert signed integer to 64-bit two's complement binary string."""
    unsigned_count = value & 0xFFFFFFFFFFFFFFFF
    return f"{unsigned_count:0{bits}b}"

def format_binary(count, arch="64-bit"):
    """Properly extract and format individual bitfields from rw_semaphore.count"""
    bits = 64 if arch == "64-bit" else 32

    # Convert signed count to unsigned representation
    if count < 0:
        count_unsigned = (1 << bits) + count
    else:
        count_unsigned = count

    # Extract fields using shift/mask
    read_fail_bit   = (count_unsigned >> 63) & 0x1
    reader_count    = (count_unsigned >> 8) & ((1 << (63 - 8)) - 1)  # bits 8–62
    reserved_bits   = (count_unsigned >> 3) & 0x1F  # bits 3–7 = 5 bits
    lock_handoff    = (count_unsigned >> 2) & 0x1
    waiters_present = (count_unsigned >> 1) & 0x1
    writer_locked   = count_unsigned & 0x1

    # Format full 64-bit binary string
    raw_binary = f"{count_unsigned:064b}"

    # Construct grouped output like: 1 [reader] [reserved] 1 1 0
    formatted_binary = (
        f"{read_fail_bit} "
        f"{reader_count:055b} "
        f"{reserved_bits:05b} "
        f"{lock_handoff} {waiters_present} {writer_locked}"
    )

    return (
        formatted_binary,
        str(read_fail_bit),
        f"{reader_count:055b}",
        f"{reserved_bits:05b}",
        str(lock_handoff),
        str(waiters_present),
        str(writer_locked),
    )

def format_owner(owner):
    """ Format the owner field into its binary components. """
    bin_str = to_binary(owner, 64)
    # Extract bit fields
    reader_owned = bin_str[-1]  # Bit 0 (RWSEM_READER_OWNED)
    nonspinnable = bin_str[-2]  # Bit 1 (RWSEM_NONSPINNABLE)
    task_ptr = owner & ~0x3
    task_address_bits = f"{task_ptr:064b}"[:-2]
    #task_address_bits = bin_str[:-2]  # Remaining bits (task_struct address)

    formatted_binary = f"{task_address_bits} {nonspinnable} {reader_owned}"

    return formatted_binary, reader_owned, nonspinnable, task_address_bits

def analyze_rw_semaphore(count, owner, owner_info, arch="64-bit", verbose=False):
    """ Analyze the rw_semaphore state based on the given count and owner values. """

    RWSEM_WRITER_LOCKED = 0x1  # Bit 0
    RWSEM_FLAG_WAITERS = 0x2    # Bit 1
    RWSEM_FLAG_HANDOFF = 0x4    # Bit 2
    RWSEM_FLAG_READFAIL = 1 << (63 if arch == "64-bit" else 31)  # Bit 63 (64-bit) or Bit 31 (32-bit)

    RWSEM_READER_SHIFT = 8
    RWSEM_READER_BIAS = 1 << RWSEM_READER_SHIFT

    RWSEM_READER_MASK = ~(RWSEM_READER_BIAS - 1)
    RWSEM_WRITER_MASK = RWSEM_WRITER_LOCKED
    RWSEM_LOCK_MASK = RWSEM_WRITER_MASK | RWSEM_READER_MASK
    RWSEM_READ_FAILED_MASK = (RWSEM_WRITER_MASK | RWSEM_FLAG_WAITERS | RWSEM_FLAG_HANDOFF | RWSEM_FLAG_READFAIL)

    RWSEM_READER_OWNED = 0x1
    RWSEM_NONSPINNABLE = 0x2
    RWSEM_OWNER_FLAGS_MASK = (RWSEM_READER_OWNED | RWSEM_NONSPINNABLE)

    writer_locked = count & RWSEM_WRITER_LOCKED
    waiters_present = (count >> 1) & 1  # ✅ FIXED Extraction of Bit 1
    lock_handoff = (count >> 2) & 1  # ✅ FIXED Extraction of Bit 2
    read_fail_bit = (count >> 63) & 1  # ✅ Extract Bit 63

    reader_count = (count >> RWSEM_READER_SHIFT) if count >= 0 else 0

    reader_owned = owner & RWSEM_READER_OWNED
    writer_task_struct = owner & ~RWSEM_OWNER_FLAGS_MASK

    print(f"\n🚨 **RW Semaphore Integrity Check** 🚨")

    # ✅ Run the logical consistency checks
    integrity_issues = check_integrity(count, owner, count, reader_owned, writer_task_struct)

    if integrity_issues:
        for issue in integrity_issues:
            print(issue)
    else:
        print("✅ **Semaphore state is logically consistent.**")

    # ✅ FIX: Restore `Binary Count` Output
    binary_output, b_read_fail, b_reader_count, b_reserved, b_handoff, b_waiters, b_writer_locked = format_binary(count,  arch)

    unsigned_count = count & 0xFFFFFFFFFFFFFFFF

    print(f"\n=== RW Semaphore Status ({arch}) ===")
    print(f"Count Value:     0x{unsigned_count:016X} ({count})")

    owner_address = owner & (2**64 - 1)

    print(f"Owner Value:     {hex(owner_address)}")
    print("========================\n")

    # **Breakdown of RW Semaphore Count Field**
    print("🔍 **Breakdown of RW Semaphore Count Field**")
    print(f"Binary Count:    {binary_output}")

    print(f"  🟢 **Read Fail Bit (Bit 63):** `{b_read_fail}`")
    if verbose:
        print("      - 1 = Rare failure case (potential semaphore corruption)")
        print("      - 0 = Normal operation")

    print(f"  📖 **Reader Count (Bits 8-62):** `{b_reader_count}`")
    if verbose:
        print("      - Number of active readers currently holding the lock")

    print(f"  🔹 **Reserved Bits (Bits 3-7):** `{b_reserved}`")
    if verbose:
        print("      - Reserved for future use")

    print(f"  🔄 **Lock Handoff Bit (Bit 2):** `{b_handoff}`")
    if verbose:
        print("      - 1 = Next writer is guaranteed to acquire the lock")
        print("      - 0 = Normal contention handling")

    print(f"  ⏳ **Waiters Present Bit (Bit 1):** `{b_waiters}`")
    if verbose:
        print("      - 1 = Other threads are waiting for the lock")
        print("      - 0 = No other threads are queued")

    print(f"  🔒 **Writer Locked Bit (Bit 0):** `{b_writer_locked}`")
    if verbose:
        print("      - 1 = A writer is currently holding the lock")
        print("      - 0 = Lock is free or held by readers")

    if unsigned_count == 0xFFFFFFFFFFFFFF06:
        print("\n  💡 Known transitional state: Reader failed to acquire during writer handoff (bit 63 + bit 1 + bit 2 set)")

    # ✅ NEW: Breakdown of RW Semaphore Owner Field
    binary_owner, b_reader_owned, b_nonspinnable, b_task_address = format_owner(owner)

    print("\n🔍 **Breakdown of RW Semaphore Owner Field**")
    print(f"  🔢 **Binary Owner Value:** `{binary_owner}`")

    # Get formatted owner info for display
    print(f"  🏷 **Owner Task:** `{ owner_info }`")

    if RHEL_VERSION == 8:
        print(f"  🔄 **Non-Spinnable Bit (Bit 1):** `{b_nonspinnable}`")
        if verbose:
            print("     - 1 = A waiting writer has stopped spinning")
            print("     - 0 = Normal behavior")

        print(f"  📖 **Reader Owned Bit (Bit 0):** `{b_reader_owned}`")
        if verbose:
            print("     - 1 = A reader currently owns the lock")
            print("     - 0 = Not reader-owned (could be a writer or empty)")
    else:
        print("  ℹ️ **(RHEL 7)** The `owner` field should only be set by writers.")

def get_task_state(task):
    task_state_value = task.state if RHEL_VERSION < 8 else task.__state
    state_flags = [name for bit, name in task_state_array.items() if task_state_value & bit]
    state = " | ".join(state_flags) if state_flags else f"Unknown ({task_state_value})"
    return state

def get_owner_info(owner_address):
    try:
        owner_address = int(owner_address, 16) if isinstance(owner_address, str) else owner_address
        owner_task = readSU("struct task_struct", owner_address)
        pid = owner_task.pid
        comm = owner_task.comm
        state = get_task_state(owner_task)
        return f"{hex(owner_address)} (PID: {pid}, COMM: {comm}, {state})"
    except Exception as e:
        print(f"Error accessing owner task at {hex(owner_address)}: {e}")
        return hex(owner_address)

def analyze_rw_semaphore_from_vmcore(rw_semaphore_addr, verbose=False, debug=False):
    """ Read rw_semaphore structure from VMcore and analyze its state. """

    # Read rw_semaphore struct from VMcore
    rwsem = readSU("struct rw_semaphore", rw_semaphore_addr)

    # Extract fields
    count = rwsem.count.counter  # Ensure correct extraction of counter value

    # Detect RHEL version and architecture automatically
    arch = get_architecture()

    # Get formatted owner info for display
    owner_raw = rwsem.owner.counter if RHEL_VERSION >= 8 else rwsem.owner
    owner_raw = owner_raw & 0xFFFFFFFFFFFFFFFF  # 💡 Unsigned conversion

    owner_address = owner_raw & ~0x07
    owner_address = owner_address & (2**64 - 1)

    owner_info = get_owner_info(owner_address)

    # Print raw structure data if debug mode is enabled
    if debug:
        print("\n🔍 **Raw rw_semaphore Structure Data:**")
        raw_output = exec_crash_command(f"struct rw_semaphore {rw_semaphore_addr:#x} -x")
        print(raw_output)

    # Call existing analysis function with both raw owner and formatted owner info
    analyze_rw_semaphore(count, owner_raw, owner_info, arch, verbose)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze rw_semaphore from VMcore.")
    parser.add_argument("rw_semaphore_addr", type=lambda x: int(x, 16), help="Memory address of rw_semaphore (hex)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed breakdown of bit fields.")
    parser.add_argument("-d", "--raw", action="store_true", help="Show raw rw_semaphore structure data.")

    args = parser.parse_args()
    DEBUG = args.raw

    # Get basic info
    RHEL_VERSION = get_rhel_version()

    analyze_rw_semaphore_from_vmcore(args.rw_semaphore_addr, args.verbose, args.raw)

