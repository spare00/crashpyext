#!/usr/bin/env python3
import sys
import argparse
from pykdump.API import *

# Global variable
kernel_version = "Unknown"
RHEL_VERSION = 8
DEBUG = False
is_readfail_reliable = True

RWSEM_WRITER_LOCKED = 1 << 0
RWSEM_FLAG_WAITERS  = 1 << 1
RWSEM_FLAG_HANDOFF  = 1 << 2
RWSEM_FLAG_READFAIL = 1 << 63
RWSEM_READER_BIAS   = 1 << 8
RWSEM_READER_SHIFT  = 8

RWSEM_READER_MASK = ~(RWSEM_READER_BIAS - 1)
RWSEM_WRITER_MASK = RWSEM_WRITER_LOCKED
RWSEM_LOCK_MASK = RWSEM_WRITER_MASK | RWSEM_READER_MASK
RWSEM_READ_FAILED_MASK = (RWSEM_WRITER_MASK | RWSEM_FLAG_WAITERS | RWSEM_FLAG_HANDOFF | RWSEM_FLAG_READFAIL)

RWSEM_READER_OWNED = 0x1
RWSEM_NONSPINNABLE = 0x2
RWSEM_OWNER_FLAGS_MASK = (RWSEM_READER_OWNED | RWSEM_NONSPINNABLE)

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

def chk_readfail(count_raw):
    bitwise_count = count_raw & 0xFFFFFFFFFFFFFFFF
    logging(f"{count_raw} -> {bitwise_count}")

    count_hex = hex(bitwise_count)
    logging(F"RWSEM_FLAG_READFAIL: {RWSEM_FLAG_READFAIL}")
    return (count_raw & RWSEM_FLAG_READFAIL) and not count_hex.startswith("0xf")

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

# Known combinations for reference/diagnostics
KNOWN_RWSEM_STATES = [
    {"value": 0, "desc": "Unlocked"},
    {"value": 1, "desc": "Writer holds lock"},
    {"value": 256, "desc": "1 reader"},
    {"value": 512, "desc": "2 readers"},
    {"value": 258, "desc": "1 reader + waiters"},
    {"value": 2, "desc": "Waiters only"},
    {"value": 6, "desc": "Waiters + handoff"},
    {"value": 3, "desc": "Writer + waiters"},
    {"value": 7, "desc": "Writer + waiters + handoff"},
    {"value": -9223372036854775802, "desc": "READFAIL + waiters + handoff"},
    {"value": -9223372036854775808, "desc": "READFAIL only"},
    {"value": -256, "desc": "Reader released (-1 reader)"},
    {"value": -254, "desc": "Reader released (-1 reader)+ waiters"},
    {"value": -250, "desc": "Reader released (-1 reader)+ waiters + handoff"},
    {"value": -1, "desc": "All bits set — likely corrupted"},
    {"value": -9223372036854775801, "desc": "All flags + READFAIL"},
    {"value": 518, "desc": "2 readers + waiters + handoff"},
    {"value": -9223372036854775553, "desc": "READFAIL + writer + 1 reader"},
    {"value": 4, "desc": "HANDOFF only"},
    {"value": -9223372036854775807, "desc": "WRITER + READFAIL"},
    {"value": 5, "desc": "WRITER + HANDOFF"}
]

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

    # Construct grouped output like: 1 [reader] [reserved] 1 1 0
    formatted_binary = (
        f"{read_fail_bit} "
        f"{reader_count:055b} "
        f"{reserved_bits:05b} "
        f"{lock_handoff} {waiters_present} {writer_locked}"
    )

    return formatted_binary

def format_owner(owner):
    """ Format the owner field into its binary components. """
    bin_str = to_binary(owner, 64)
    # Extract bit fields
    reader_owned = bin_str[-1]  # Bit 0 (RWSEM_READER_OWNED)
    nonspinnable = bin_str[-2]  # Bit 1 (RWSEM_NONSPINNABLE)
    task_ptr = owner & ~0x3
    task_address_bits = f"{task_ptr:064b}"[:-2]

    formatted_binary = f"{task_address_bits} {nonspinnable} {reader_owned}"

    return formatted_binary

def get_task_state(task):
    try:
        # RHEL8+ kernels expose __state
        return task.__state
    except KeyError:
        # On RHEL7 only "state" exists
        return task.state

def get_owner_info(owner_flag_masked):
    try:
        owner_address = int(owner_flag_masked, 16) if isinstance(owner_flag_masked, str) else owner_flag_masked
        owner_task = readSU("struct task_struct", owner_address)
        pid = owner_task.pid
        comm = owner_task.comm
        state = get_task_state(owner_task)
        return f"{hex(owner_flag_masked)} (PID: {pid}, COMM: {comm}, {state})"
    except Exception as e:
        print(f"Error accessing owner task at {hex(owner_flag_masked)}: {e}")
        return hex(owner_flag_masked)

def get_reader_count(count_raw, is_readfail_reliable):
    """
    Correctly extract reader count from rwsem.count using bitfields.
    This fixes negative reader count issues.
    """
    bitwise_count = count_raw & 0xFFFFFFFFFFFFFFFF

    # Extract bits 8–62 (reader count)
    reader_count = (bitwise_count >> 8) & ((1 << (63 - 8)) - 1)

    logging(f"get_reader_count(): count: {count_raw}, readers: {reader_count}")
    return reader_count

def get_reader_count(count_raw, is_readfail_reliable):
    """
    Extract reader count correctly while respecting READFAIL semantics.
    """

    bitwise_count = count_raw & 0xFFFFFFFFFFFFFFFF

    # Extract raw reader bits (always correct encoding)
    reader_count = (bitwise_count >> 8) & ((1 << (63 - 8)) - 1)

    # Handle READFAIL interpretation
    if is_readfail_reliable:
        # READFAIL means reader acquisition failed → not active readers
        if bitwise_count & RWSEM_FLAG_READFAIL:
            logging("READFAIL set: treating reader count as 0 (no active readers)")
            return 0

    logging(f"get_reader_count(): count: {count_raw}, readers: {reader_count}")
    return reader_count

def list_waiting_tasks(wait_list_addr):
    """Return a list of tasks in the rw_semaphore's wait_list."""
    print("\n**List of waiters in s wait_list**\n")
    try:
        command = f"list -s rwsem_waiter.task,type -l rwsem_waiter.list {wait_list_addr:#x}"
        print(f"Executing: {command}\n")
        output = exec_crash_command(command)
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        grouped = []
        i = 0
        while i < len(lines):
            if i + 2 < len(lines):
                print(f"{lines[i]}  {lines[i+1]}  {lines[i+2]}")
                i += 3
            else:
                break
    except Exception as e:
        print(f"Error listing waiters for rw_semaphore at {hex(wait_list_addr)}: {e}")
        return []

def check_integrity(count, owner, reader_owned, owner_task_addr, is_readfail_reliable, reader_count, verbose=False):
    """ Perform logical integrity checks on rw_semaphore values. """

    issues = []

    writer_task_struct = None
    if owner_task_addr:
        try:
            writer_task_struct = readSU("struct task_struct", owner_task_addr)
        except Exception:
            writer_task_struct = None

    # Check if reliable RWSEM_FLAG_READFAIL is set
    if is_readfail_reliable and (count & RWSEM_FLAG_READFAIL) == RWSEM_FLAG_READFAIL:
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

        # ✅ Transitional state with racing or corrupted — skip strict checks
        return issues

    # Reader-associated state (not guaranteed active readers)
    reader_bias_count = count & RWSEM_READER_MASK
    if reader_bias_count > 0 and not (count & RWSEM_WRITER_LOCKED):
        if RHEL_VERSION == 8:
            if not reader_owned:
                issues.append("ℹ️ Reader bias is present in `.count`, but RWSEM_READER_OWNED bit is not set — may be valid (fastpath), or worth reviewing.")
            if writer_task_struct is not None and not reader_owned:
                issues.append("⚠️ Owner field is nonzero but RWSEM_READER_OWNED not set — possible stale writer, or early reader acquisition.")

        elif RHEL_VERSION == 7:
            if writer_task_struct != 0:
                issues.append("⚠️ Unexpected: `.owner` should be 0 in RHEL 7 when readers hold the lock.")

        if reader_bias_count % RWSEM_READER_BIAS != 0:
            issues.append("⚠️ Reader count not aligned to RWSEM_READER_BIAS (256) — possible corruption or misinterpretation.")

    # Transitional or negative count state (not strictly writer-held)
    elif count < 0:
        if reader_count > 0:
            issues.append("🌀 `.count` is negative with negative reader bias. Reader release may not be properly completed due to racing.")

        elif reader_count == 0:
            issues.append("🌀 `.count` is negative without reader bias. Transitional state ipossibly with waiters or handoff or writer racing.")

        else: # reader_count < 0
            logging("Unexpected error state!")

        if owner_task_addr == 0:
            issues.append("🌀 `.count` is negative — transitional state or race possible. `owner` is null, which may be valid during unlock or reader release.")

        if reader_owned:
            issues.append("🌀 transitional: `owner` marked as reader, and `count` is negative. Reader release may not be properly completed due to racing.")

        if count == -1:
            issues.append("🌀 `.count < -1` likely indicates a writer release racing with unlock which be impossible as only 1 writer can hold the rw_semaphore.")

    # Free lock
    elif count == 0:
        if owner_task_addr != 0:
            issues.append("⚠️ `owner` field not cleared: lock is free but `owner` is set.")

    # Reserved bits check (bits 3–7)
    reserved_mask = 0b11111000
    if count & reserved_mask:
        issues.append("⚠️ Reserved bits (3–7) are set — should be 0.")

    return issues

def chk_count_bits(count_raw):
    # Interpret count bitwise (64-bit) to extract flags regardless of sign
    bitwise_count = count_raw & 0xFFFFFFFFFFFFFFFF
    logging(f"bitwise_count: {bitwise_count}")
    writer_b = bool(bitwise_count & RWSEM_WRITER_LOCKED)
    waiters_b = bool(bitwise_count & RWSEM_FLAG_WAITERS)
    handoff_b = bool(bitwise_count & RWSEM_FLAG_HANDOFF)
    readfail_b = bool(bitwise_count & RWSEM_FLAG_READFAIL)

    return bitwise_count, writer_b, waiters_b, handoff_b, readfail_b

def explain_bits_combination(count, reader_count, is_readfail_reliable):
    """Return list of active flags and interpreted description from .count"""
    # Interpret count bitwise (64-bit) to extract flags regardless of sign
    bitwise_count, writer, waiters, handoff, readfail = chk_count_bits(count)

    count_bits = []
    if writer: count_bits.append("1(WRITER_LOCKED)")
    if waiters: count_bits.append("2(WAITERS)")
    if handoff: count_bits.append("4(HANDOFF)")
    if is_readfail_reliable & readfail: count_bits.append("9223372036854775808(READFAIL)")

    desc_parts = []
    if count_bits:
        desc_parts.append(" + ".join(count_bits) )
    logging(f"reader_count: {reader_count}")
    if reader_count > 0:
        if is_readfail_reliable:
            desc_parts.append(f"+ {RWSEM_READER_BIAS * reader_count} ({reader_count} reader(s))")
        else:
            desc_parts.append(f"- {RWSEM_READER_BIAS * reader_count} ({reader_count} reader(s))")

    if not desc_parts:
        desc_parts.append("no bits or readers set")

    return " ".join(desc_parts)

def classify_rwsem_state(count_raw, is_readfail_reliable, reader_count, verbose=False):
    """Extended logic to classify the rw_semaphore count value"""

    flags = []
    state = ""

    # Interpret count bitwise (64-bit)
    bitwise_count, writer, waiters, handoff, readfail = chk_count_bits(count_raw)

    count_hex = hex(bitwise_count)

    reserved_bits = (bitwise_count >> 3) & 0x1F

    # ✅ Always use fixed reader extraction (ignore passed reader_count)
    reader_count = get_reader_count(count_raw, is_readfail_reliable)

    reader_note = f"{reader_count} reader(s)"
    reader_count_valid = True

    # Flags
    if writer: flags.append("WRITER_LOCKED")
    if waiters: flags.append("WAITERS")
    if handoff: flags.append("HANDOFF")
    if readfail: flags.append("READFAIL")

    # --- Explicit edge case handling (from known combinations) ---

    # READFAIL + writer (invalid)
    if readfail and writer:
        state_type = "❗ Invalid"
        description = "READFAIL + WRITER combination — invalid state."
        return build_result(...)

    # Negative values (transient states)
    if count_raw < 0 and not readfail:
        state_type = "🌀 Transitional"
        description = "Negative count — transient state during reader release or race."
        return build_result(...)

    # READFAIL = real transitional condition
    if readfail:
        reader_note = "🌀 Reader acquisition failed (READFAIL)"
        reader_count_valid = False

    # Classify known edge case first
    if count_raw == -1:
        state_type = "🌀 Transitional / Invalid"
        description = "Race condition or corrupted state."

    elif count_raw == 0:
        state_type = "✅ Stable"
        description = "Lock is free."

    # ✅ Readers hold lock (VALID even with waiters)
    elif reader_count > 0 and not writer:
        state_type = "✅ Stable"
        if waiters:
            description = f"{reader_count} reader(s) hold the lock with waiters queued."
        else:
            description = f"{reader_count} reader(s) hold the lock."

    # ❌ Invalid: writer + readers
    elif writer and reader_count > 0:
        state_type = "❗ Invalid"
        description = f"Writer and {reader_note} both hold the lock — impossible state."

    # ✅ Writer holds lock
    elif writer and reader_count == 0:
        state_type = "✅ Stable"
        if waiters:
            description = "Writer holds the lock with waiters queued."
        else:
            description = "Writer holds the lock."

    # 🌀 Transitional states (real ones only)
    elif readfail:
        state_type = "🌀 Transitional"
        description = "Reader failed to acquire lock (READFAIL)."

    elif reader_count == 0 and (waiters or handoff):
        state_type = "🌀 Transitional"
        description = "No active holders, but waiters or handoff pending."

    else:
        state_type = "🌀 Unknown or Rare"
        description = "Unclassified state. Possibly due to race, partial update, or corruption."

    # Reserved bits warning
    if reserved_bits:
        description += " Reserved bits (3–7) are set — unexpected."

    # Known pattern match
    matched_known = next((entry['desc'] for entry in KNOWN_RWSEM_STATES if count_raw == entry['value']), None)

    # Bit combination explanation (keep your existing function)
    combined_bits_desc = explain_bits_combination(count_raw, reader_count, is_readfail_reliable)
    description += f"\n  🧩  Possible Bits Combination: {combined_bits_desc}"

    return {
        "flags": flags,
        "reader_count": reader_count,
        "reader_note": reader_note,
        "reserved_bits": f"{reserved_bits:05b}",
        "state_type": state_type,
        "description": description + (f"\n  🔎  Matched known pattern: {matched_known}" if matched_known else ""),
        "raw_value": f"0x{bitwise_count:016x}"
    }

def print_owner_bitfield(owner, owner_info, verbose=False):
    # ✅ NEW: Breakdown of RW Semaphore Owner Field
    binary_owner = format_owner(owner)

    print("\n=== Breakdown of RW Semaphore Owner Field ===")
    print(f"Binary:       {binary_owner}")
    print("                                                                             ^ ^")
    print("  🔄 Non-Spinnable Bit               ────────────────────────────────────────┘ |")
    print("  📖 Reader Owned Bit (Bit 0):       ──────────────────────────────────────────┘")
    print(f"  🏷  Owner Task: {owner_info}")

    if RHEL_VERSION == 8:
        if verbose:
            print("\nVerbose Explanation:")
            print("  - Reader Owned Bit: 1 = A reader currently owns the lock")
            print("  - Non-Spinnable: 1 = Writer stopped spinning and went to sleep")
    else:
        print("  ℹ️ (RHEL 7) The `owner` field should only be set by writers.")

def print_count_bitfield_breakdown(count_raw, arch="64-bit", verbose=False):

    # ✅ FIX: Restore `Binary Count` Output
    binary_output = format_binary(count_raw,  arch)

    print("\n=== Breakdown of RW Semaphore Count Field ===")
    print(f"Binary:    {binary_output}")
    print("           ^                                       ^                   ^   ^ ^ ^")
    print("  🟢 Read Fail Bit (Bit 63):                       |                   |   | | |")
    print("  📖 Reader Count (Bits 8-62):       ──────────────┘                   |   | | |")
    print("  🔹 Reserved Bits (Bits 3-7):       ──────────────────────────────────┘   | | |")
    print("  🔄 Lock Handoff Bit (Bit 2):       ──────────────────────────────────────┘ | |")
    print("  ⏳ Waiters Present Bit (Bit 1):    ────────────────────────────────────────┘ |")
    print("  🔒 Writer Locked Bit (Bit 0):      ──────────────────────────────────────────┘")

    if verbose:
        print("\nVerbose Explanation:")
        print("  - Read Fail Bit: 1 = Reader acquisition failed (e.g. under contention or downgrade path)")
        print("  - Reader Count: Number of readers holding the semaphore, encoded in multiples of 256")
        print("  - Reserved Bits: Should be zero in valid states")
        print("  - Handoff: 1 = Lock handoff to another task is pending")
        print("  - Waiters: 1 = Tasks are waiting for the semaphore")
        print("  - Writer Locked: 1 = Semaphore is held exclusively by a writer")

def analyze_rw_semaphore(count, is_readfail_reliable, owner, arch="64-bit", verbose=False):
    """ Analyze the rw_semaphore state based on the given count and owner values. """

    # Interpret count bitwise (64-bit) to extract flags regardless of sign
    bitwise_count, _, _, _, readfail = chk_count_bits(count)

    print(f"\n=== RW Semaphore Status ({arch}) ===")
    print(f"Count Value:     0x{bitwise_count:016X} ({count})")

    owner_address = owner & (2**64 - 1)

    print(f"Owner Value:     {hex(owner_address)}")
    print("====================================")

    print_count_bitfield_breakdown(count, arch, verbose)

    # Find a reliable reader count
    reader_count = get_reader_count(count, is_readfail_reliable)

    result = classify_rwsem_state(count, is_readfail_reliable, reader_count)
    if result:
        print("\n  🧠 Inferred State:")
        print(f"  Flags Set: {', '.join(result['flags']) if result['flags'] else 'None'}")
        print(f"  Number of Readers: {result['reader_count']}")
        print(f"  {result['state_type']}: {result['description']}")

    reader_owned = owner & RWSEM_READER_OWNED
    owner_task_addr = owner & ~RWSEM_OWNER_FLAGS_MASK

    owner_info = get_owner_info(owner_task_addr)

    print_owner_bitfield(owner, owner_info, verbose)

    print(f"\n🚨 **RW Semaphore Integrity Check** 🚨")

    # ✅ Run the logical consistency checks
    integrity_issues = check_integrity(count, owner, reader_owned, owner_task_addr, is_readfail_reliable, reader_count, verbose)

    if integrity_issues:
        for issue in integrity_issues:
            print(issue)
    else:
        print("✅ **Semaphore state is logically consistent.**")

def analyze_rw_semaphore_from_vmcore(rw_semaphore_addr, list_waiters=False, verbose=False, debug=False):
    """ Read rw_semaphore structure from VMcore and analyze its state. """

    # Read rw_semaphore struct from VMcore
    rwsem = readSU("struct rw_semaphore", rw_semaphore_addr)

    # Extract fields
    count_raw = rwsem.count.counter  # Ensure correct extraction of counter value

    # See if the readfail is reliable before using the readfail bit
    is_readfail_reliable = chk_readfail(count_raw)
    logging(f"is_readfail_reliable: {is_readfail_reliable}")

    # Detect RHEL version and architecture automatically
    arch = get_architecture()

    # Get formatted owner info for display
    owner_raw = rwsem.owner.counter if RHEL_VERSION >= 8 else rwsem.owner
    owner_raw = owner_raw & 0xFFFFFFFFFFFFFFFF  # 💡 Unsigned conversion

    owner_address = owner_raw & ~0x07
    owner_address = owner_address & (2**64 - 1)

    # Print raw structure data if debug mode is enabled
    if verbose:
        print("\n🔍 **Raw rw_semaphore Structure Data:**")
        raw_output = exec_crash_command(f"struct rw_semaphore {rw_semaphore_addr:#x} -x")
        print(raw_output)

    # Call existing analysis function with both raw owner and formatted owner info
    analyze_rw_semaphore(count_raw, is_readfail_reliable, owner_raw, arch, verbose)

    if list_waiters:
        list_waiting_tasks(rwsem.wait_list)

