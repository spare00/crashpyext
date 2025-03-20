#!/usr/bin/env python3

import sys
import argparse
from pykdump.API import readSU  # Importing ePython API for VMcore analysis

# Global variable
kernel_version = "Unknown"
rhel_version = 8

def get_rhel_version():
    """Determines the major RHEL version from the kernel release."""
    sys_output = exec_crash_command("sys")

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
    0x40: "TASK_PARKED" if rhel_version >= 8 else "TASK_DEAD",
    0x80: "TASK_DEAD" if rhel_version >= 8 else "TASK_WAKEKILL",
    0x100: "TASK_WAKEKILL" if rhel_version >= 8 else "TASK_WAKING",
    0x200: "TASK_WAKING" if rhel_version >= 8 else "TASK_PARKED",
    0x400: "TASK_NOLOAD" if rhel_version >= 8 else "TASK_STATE_MAX",
    0x800: "TASK_NEW" if rhel_version >= 8 else "TASK_STATE_MAX",
    0x1000: "TASK_RTLOCK_WAIT" if rhel_version >= 8 else "TASK_STATE_MAX",
    0x2000: "TASK_STATE_MAX" if rhel_version >= 9 else "TASK_STATE_MAX",
}


def check_integrity(count, owner, signed_count, reader_owned, writer_task_struct):
    """ Perform logical integrity checks on rw_semaphore values. """

    issues = []

    # 1️⃣ **Check for Read-Lock Consistency**
    if signed_count > 0:
        if rhel_version == 8:
            if not reader_owned:
                issues.append("⚠️ **Inconsistent State:** `count` is positive (read-locked), "
                              "but `owner` does not indicate reader ownership.")
            if writer_task_struct != 0 and not reader_owned:
                issues.append("⚠️ **Suspicious Owner:** `count` is positive (read-locked), "
                              "but `owner` is nonzero without `RWSEM_READER_OWNED`. "
                              "A writer may have failed to clear it.")
        elif rhel_version == 7:
            if writer_task_struct != 0:
                issues.append("⚠️ **Suspicious Owner:** `count` is positive (read-locked), "
                              "but `owner` is nonzero. In RHEL 7, only writers set `owner`, "
                              "so this is unexpected.")

    # 2️⃣ **Check for Write-Lock Consistency**
    elif signed_count < 0:  # Negative count means write-locked
        if writer_task_struct == 0:
            issues.append("  ⚠️ **Unexpected Missing Owner:** `count` is negative (write-locked), "
                          "but `owner` is 0. A writer should be listed.")

        if reader_owned:
            issues.append("  ⚠️ **Conflicting Owner:** `count` is negative (write-locked), "
                          "but `owner` is marked as reader-owned.")

        # ✅ NEW: Detecting Multiple Writers (`count < -1`)
        if signed_count < -1:
            issues.append("  🚨 **INVALID STATE:** `count` is less than -1, meaning multiple writers "
                          "are holding the lock simultaneously, which should never happen.")

    # 3️⃣ **Check for Free Semaphore Consistency**
    elif signed_count == 0:  # Semaphore is free
        if writer_task_struct != 0:
            issues.append("  ⚠️ **Owner Field Not Cleared:** `count` is 0 (free), "
                          "but `owner` is nonzero. The last owner should have cleared it.")

    # 4️⃣ **Check for Reserved Bits Being Set**
    reserved_mask = 0b11111000  # Bits 3-7 should be 0
    if count & reserved_mask:
        issues.append("  ⚠️ **Unexpected Reserved Bits Set:** Reserved bits (3-7) should be 0, "
                      "but some are set.")

    return issues

def to_binary(value, bits=64):
    """ Convert a value to a zero-padded binary string of given bit length. """
    return f"{value:0{bits}b}"

def format_binary(count, bitfield, arch="64-bit"):
    """ Format the binary representation with correct spacing. """

    # Convert count to unsigned 64-bit two’s complement representation if negative
    if count < 0:
        count = (1 << 64) + count

    # Generate 64-bit or 32-bit binary representation
    bin_str = f"{count:064b}" if arch == "64-bit" else f"{count:032b}"

    # Extract bit fields
    read_fail_bit = bin_str[0]  # Bit 63
    reader_count_bits = bin_str[bitfield["reader_count"][0]:bitfield["reader_count"][1] + 1]
    reserved_bits = bin_str[bitfield["reserved_bits"][0]:bitfield["reserved_bits"][1] + 1]
    lock_handoff = bin_str[bitfield["lock_handoff"]]  # Bit 2
    waiters_present = bin_str[bitfield["waiters_present"]]  # Bit 1
    writer_locked = bin_str[bitfield["writer_locked"]]  # Bit 0

    # Correctly formatted binary output
    formatted_binary = (
        f"{read_fail_bit} {reader_count_bits} {reserved_bits} {lock_handoff} {waiters_present} {writer_locked}"
    )

    return (
        formatted_binary,
        read_fail_bit, reader_count_bits, reserved_bits, lock_handoff, waiters_present, writer_locked
    )

def format_owner(owner):
    """ Format the owner field into its binary components. """
    bin_str = to_binary(owner, 64)

    # Extract bit fields
    reader_owned = bin_str[-1]  # Bit 0 (RWSEM_READER_OWNED)
    nonspinnable = bin_str[-2]  # Bit 1 (RWSEM_NONSPINNABLE)
    task_address_bits = bin_str[:-2]  # Remaining bits (task_struct address)

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

    # ✅ FIX: Properly Convert `count` to Signed 64-bit
    signed_count = count if count < (1 << 63) else count - (1 << 64)

    writer_locked = count & RWSEM_WRITER_LOCKED
    waiters_present = (count >> 1) & 1  # ✅ FIXED Extraction of Bit 1
    lock_handoff = (count >> 2) & 1  # ✅ FIXED Extraction of Bit 2
    read_fail_bit = (count >> 63) & 1  # ✅ Extract Bit 63

    reader_count = (count >> RWSEM_READER_SHIFT) if signed_count >= 0 else 0

    reader_owned = owner & RWSEM_READER_OWNED
    writer_task_struct = owner & ~RWSEM_OWNER_FLAGS_MASK

    print(f"\n🚨 **RW Semaphore Integrity Check** 🚨")

    # ✅ Run the logical consistency checks
    integrity_issues = check_integrity(count, owner, signed_count, reader_owned, writer_task_struct)

    if integrity_issues:
        for issue in integrity_issues:
            print(issue)
    else:
        print("✅ **Semaphore state is logically consistent.**")

    # ✅ FIX: Restore `Binary Count` Output
    binary_output, b_read_fail, b_reader_count, b_reserved, b_handoff, b_waiters, b_writer_locked = format_binary(
        count, {
            "writer_locked": 0,
            "waiters_present": 1,
            "lock_handoff": 2,
            "reserved_bits": (3, 7),
            "reader_count": (8, 62 if arch == "64-bit" else 30),
            "read_fail_bit": 63 if arch == "64-bit" else 31
        }, arch)

    formatted_count = f"0x{signed_count & 0xFFFFFFFFFFFFFFFF:016X}"

    print(f"\n=== RW Semaphore Status ({arch}) ===")
    print(f"Count Value:     {formatted_count} ({signed_count})")

    owner_address = owner & (2**64 - 1)

    print(f"Owner Value:     {hex(owner_address)}")
    print(f"Binary Count:    {binary_output}")
    print("========================\n")

    # **Breakdown of RW Semaphore Count Field**
    print("🔍 **Breakdown of RW Semaphore Count Field**")
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

    # ✅ NEW: Breakdown of RW Semaphore Owner Field
    binary_owner, b_reader_owned, b_nonspinnable, b_task_address = format_owner(owner)

    print("\n🔍 **Breakdown of RW Semaphore Owner Field**")
    print(f"  🔢 **Binary Owner Value:** `{binary_owner}`")

    # Get formatted owner info for display
    print(f"  🏷 **Owner Task:** `{ owner_info }`")

    if rhel_version == 8:
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
    task_state_value = task.state if rhel_version >= 8 else task.__state
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

    # Correct sign extension for count
    if count & (1 << 63):  # Check if the sign bit (bit 63) is set
        count -= (1 << 64)  # Convert to signed 64-bit integer

    # Detect RHEL version and architecture automatically
    arch = get_architecture()

    # Get formatted owner info for display
    owner_raw = rwsem.owner.counter if rhel_version >= 8 else rwsem.owner
    owner_address = owner_raw & ~0x07
    owner_address = owner_address & (2**64 - 1)

    owner_info = get_owner_info(owner_address)

    # Print raw structure data if debug mode is enabled
    if debug:
        print("\n🔍 **Raw rw_semaphore Structure Data:**")
        raw_output = exec_crash_command(f"struct rw_semaphore {rw_semaphore_addr:#x} -x")
        print(raw_output)

    print(f"owner:::: {hex(owner_address)}")
    # Call existing analysis function with both raw owner and formatted owner info
    analyze_rw_semaphore(count, owner_raw, owner_info, arch, verbose)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze rw_semaphore from VMcore.")
    parser.add_argument("rw_semaphore_addr", type=lambda x: int(x, 16), help="Memory address of rw_semaphore (hex)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed breakdown of bit fields.")
    parser.add_argument("-d", "--raw", action="store_true", help="Show raw rw_semaphore structure data.")

    args = parser.parse_args()

    # Get basic info
    get_rhel_version()

    analyze_rw_semaphore_from_vmcore(args.rw_semaphore_addr, args.verbose, args.raw)

