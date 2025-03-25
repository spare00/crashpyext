#!/usr/bin/env python3

import sys
import argparse
from pykdump.API import readSU  # Importing ePython API for VMcore analysis

# Global variable
kernel_version = "Unknown"
RHEL_VERSION = 8
DEBUG = False

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

def check_integrity(count, owner, signed_count, reader_owned, writer_task_struct):
    """ Perform logical integrity checks on rw_semaphore values. """

    issues = []

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

    # Reader-associated state (not guaranteed active readers)
    reader_bias_count = count & RWSEM_READER_MASK
    if reader_bias_count > 0 and not (count & RWSEM_WRITER_LOCKED):
        if RHEL_VERSION == 8:
            if not reader_owned:
                issues.append("ℹ️ Reader bias is present in `.count`, but RWSEM_READER_OWNED bit is not set — may be valid (fastpath), or worth reviewing.")
            if writer_task_struct != 0 and not reader_owned:
                issues.append("⚠️ Owner field is nonzero but RWSEM_READER_OWNED not set — possible stale writer, or early reader acquisition.")

        elif RHEL_VERSION == 7:
            if writer_task_struct != 0:
                issues.append("⚠️ Unexpected: `.owner` should be 0 in RHEL 7 when readers hold the lock.")

        if reader_bias_count % RWSEM_READER_BIAS != 0:
            issues.append("⚠️ Reader count not aligned to RWSEM_READER_BIAS (256) — possible corruption or misinterpretation.")

    # Transitional or negative count state (not strictly writer-held)
    elif signed_count < 0:
        if writer_task_struct == 0:
            issues.append("🌀 `.count` is negative — transitional state or race possible. `owner` is null, which may be valid during unlock or reader release.")

        if reader_owned:
            issues.append("⚠️ Conflict: `owner` marked as reader, but `count` is negative — inconsistent state.")

        if signed_count < -1:
            issues.append("🌀 `.count < -1` likely indicates a reader release racing with unlock, not multiple writers. Check flags (WAITERS, HANDOFF).")

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

# Extension to analyze more realistic rw_semaphore.count states
# Replaces or enhances a part of analyze_rw_semaphore()

def explain_bits_combination(count, adjusted_reader_bias, is_readfail_real):
    """Return list of active flags and interpreted description from .count"""
    bitwise_count = count & 0xFFFFFFFFFFFFFFFF

    flags = []
    if bitwise_count & RWSEM_WRITER_LOCKED:
        flags.append("1(WRITER_LOCKED)")
    if bitwise_count & RWSEM_FLAG_WAITERS:
        flags.append("2(WAITERS)")
    if bitwise_count & RWSEM_FLAG_HANDOFF:
        flags.append("4(HANDOFF)")
    if is_readfail_real & bitwise_count & RWSEM_FLAG_READFAIL:
        flags.append("9223372036854775808(READFAIL)")

    reader_count = adjusted_reader_bias if not is_readfail_real else (bitwise_count & RWSEM_READER_MASK) >> 8
    desc_parts = []
    if flags:
        desc_parts.append(" + ".join(flags) )
    if reader_count > 0:
        if is_readfail_real:
            desc_parts.append(f"+{RWSEM_READER_BIAS * reader_count} ({reader_count} reader(s))")
        else:
            desc_parts.append(f"{-RWSEM_READER_BIAS * reader_count} ({reader_count} reader(s))")

    if not desc_parts:
        desc_parts.append("no bits or readers set")

    return flags, reader_count, " ".join(desc_parts)

def classify_rwsem_state(count):
    """Extended logic to classify the rw_semaphore count value"""

    flags = []
    state = ""

    # Interpret count bitwise (64-bit) to extract flags regardless of sign
    bitwise_count = count & 0xFFFFFFFFFFFFFFFF
    logging(f"bitwise_count: {bitwise_count}")
    writer = bool(bitwise_count & RWSEM_WRITER_LOCKED)
    waiters = bool(bitwise_count & RWSEM_FLAG_WAITERS)
    handoff = bool(bitwise_count & RWSEM_FLAG_HANDOFF)
    readfail = bool(bitwise_count & RWSEM_FLAG_READFAIL)

    count_hex = hex(bitwise_count)
    is_readfail_real = (count & RWSEM_FLAG_READFAIL) and not count_hex.startswith("0xf")

    reserved_bits = (bitwise_count >> 3) & 0x1F
    raw_reader_bits = (bitwise_count >> 8) & ((1 << (63 - 8)) - 1)
    reader_count = raw_reader_bits
    reader_note = ""
    reader_count_valid = True

    if writer: flags.append("WRITER_LOCKED")
    if waiters: flags.append("WAITERS")
    if handoff: flags.append("HANDOFF")
    if readfail: flags.append("READFAIL")

    adjusted_reader_bias = 0

    # 🧠 Special case: treat large negative counts with flags as likely race (e.g., -256, -1018)
    logging(f"count: {count}, {(count & 0xFF)}, {readfail}")
    if(waiters or handoff) and not is_readfail_real:
        adjusted_reader_bias = ((-count + (count & 0xFF)) & RWSEM_READER_MASK) >> 8
        logging(f"adjusted_reader_bias: {adjusted_reader_bias}")
        reader_note = f"🌀 Transitional: derived {adjusted_reader_bias} reader(s) released during flag state."
        reader_count_valid = False

    # Reader count validity analysis
    elif not is_readfail_real:
        reader_note = "⚠️ Suspicious: extremely high reader count, likely due to corruption or race."
        reader_count_valid = False
    elif reader_count == 0 and (count < 0) and not is_readfail_real:
        reader_note = "⚠️ Reader count is zero, but count is negative — possibly transitional or corrupted."
        reader_count_valid = False
    else:
        reader_note = f"{reader_count} reader(s)"
        reader_count_valid = True

    # Classify known edge case first
    if count == -1:
        state_type = "🌀 Transitional / Invalid"
        description = "-1 observed due to race condition between reader release and writer unlock — likely transient and invalid in steady state."

    elif count == 0:
        state_type = "✅ Stable"
        description = "Lock is free."

    elif reader_count > 0 and not writer and reader_count_valid:
        state_type = "✅ Stable"
        description = f"{reader_note} hold the lock."

    elif reader_count > 0 and not writer and not reader_count_valid:
        state_type = "❗ Invalid or Corrupted"
        description = f"{reader_note} — unlikely valid state."

    elif writer and reader_count == 0:
        state_type = "✅ Stable"
        description = "Writer holds the lock."

    elif writer and reader_count > 0:
        state_type = "❗ Invalid"
        description = f"Writer and {reader_note} both appear to hold the lock — should not happen."

    elif is_readfail_real:
        state_type = "🌀 Transitional"
        description = "Reader failed to acquire the lock — likely fallback to queue."

    elif reader_count == 0 and (waiters or handoff):
        state_type = "🌀 Transitional"
        description = "No current holders, but waiters or handoff is pending."

    elif reader_count == 0 and writer and (waiters or handoff):
        state_type = "🌀 Transitional"
        description = "Writer holds the lock with queued waiters and handoff pending."

    elif reader_count == 0 and not (writer or waiters or handoff or readfail):
        state_type = "✅ Stable"
        description = "Zero state with no active flags — likely unlocked."

    else:
        state_type = "🌀 Unknown or Rare"
        description = "Unclassified state. Possibly due to race, partial update, or corruption."

    if reserved_bits:
        description += " Reserved bits (3–7) are set — unexpected."

    matched_known = next((entry['desc'] for entry in KNOWN_RWSEM_STATES if count == entry['value']), None)

    # 🔍 Append breakdown from flag analyzer
    _, _, combined_bits_desc = explain_bits_combination(count, adjusted_reader_bias, is_readfail_real)
    description += f"\n  🧩  Bits Combination: {combined_bits_desc}"

    return {
        "flags": flags,
        "reader_count": reader_count,
        "reader_note": reader_note,
        "reserved_bits": f"{reserved_bits:05b}",
        "state_type": state_type,
        "description": description + (f"🔎 Matched known pattern: {matched_known}" if matched_known else ""),
        "raw_value": f"0x{bitwise_count:016x}"
    }

def print_owner_bitfield(binary_owner, b_reader_owned, b_nonspinnable, owner_info, verbose=False):
    print("\n🔍 **Breakdown of RW Semaphore Owner Field**")
    print(f"Binary Value: {binary_owner}")
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

def print_bitfield_breakdown(binary_output, b_read_fail, b_reader_count, b_reserved, b_handoff, b_waiters, b_writer_locked, verbose=False):
    print("\n🔍 **Breakdown of RW Semaphore Count Field**")
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

def analyze_rw_semaphore(count, owner, owner_info, arch="64-bit", verbose=False):
    """ Analyze the rw_semaphore state based on the given count and owner values. """

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

    print_bitfield_breakdown(binary_output, b_read_fail, b_reader_count, b_reserved, b_handoff, b_waiters, b_writer_locked, verbose)

    result = classify_rwsem_state(count)
    if result:
        print("\n  🧠 Inferred State:")
        print(f"  Flags Set: {', '.join(result['flags']) if result['flags'] else 'None'}")
        print(f"  Reader Count: {result['reader_count']}")
        print(f"  Reserved Bits: {result['reserved_bits']}")
        print(f"  Raw Value: {result['raw_value']}")
        print(f"  {result['state_type']}: {result['description']}")

    # ✅ NEW: Breakdown of RW Semaphore Owner Field
    binary_owner, b_reader_owned, b_nonspinnable, b_task_address = format_owner(owner)

    print_owner_bitfield(binary_owner, b_reader_owned, b_nonspinnable, owner_info, verbose)

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

def analyze_rw_semaphore_from_vmcore(rw_semaphore_addr, list_waiters=False, verbose=False, debug=False):
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
    if verbose:
        print("\n🔍 **Raw rw_semaphore Structure Data:**")
        raw_output = exec_crash_command(f"struct rw_semaphore {rw_semaphore_addr:#x} -x")
        print(raw_output)

    # Call existing analysis function with both raw owner and formatted owner info
    analyze_rw_semaphore(count, owner_raw, owner_info, arch, verbose)

    if list_waiters:
        list_waiting_tasks(rwsem.wait_list)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze rw_semaphore from VMcore.")
    parser.add_argument("rw_semaphore_addr", type=lambda x: int(x, 16), help="Memory address of rw_semaphore (hex)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed breakdown of bit fields.")
    parser.add_argument("-d", "--raw", action="store_true", help="Show raw rw_semaphore structure data.")
    parser.add_argument("-l", "--list", action="store_true", help="List tasks waiting on the rw_semaphore")

    args = parser.parse_args()
    DEBUG = args.raw

    # Get basic info
    RHEL_VERSION = get_rhel_version()

    analyze_rw_semaphore_from_vmcore(args.rw_semaphore_addr, args.list, args.verbose, args.raw)

