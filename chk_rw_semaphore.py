#!/usr/bin/env python3

import sys
import argparse

def check_integrity(count, owner, signed_count, reader_owned, writer_task_struct, rhel_version):
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

def analyze_rw_semaphore(count, owner, arch="64-bit", verbose=False, rhel_version=8):
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
    integrity_issues = check_integrity(count, owner, signed_count, reader_owned, writer_task_struct, rhel_version)

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
    print(f"Owner Value:     0x{owner:X} ({owner})")
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
    print(f"  🏷 **Task Struct Address:** `{b_task_address}`")

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

# Main Execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze rw_semaphore status in Linux.")
    parser.add_argument("count", type=lambda x: int(x, 0))
    parser.add_argument("owner", type=lambda x: int(x, 0))
    parser.add_argument("-a", "--arch", choices=["32-bit", "64-bit"], default="64-bit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed breakdown of bit fields.")
    parser.add_argument("-r", "--rhel-version", type=int, choices=[7, 8], default=8,
                    help="Specify RHEL version (7 or 8). Default is 8.")

    args = parser.parse_args()

    analyze_rw_semaphore(args.count, args.owner, args.arch, args.verbose, args.rhel_version)

