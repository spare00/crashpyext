#!/usr/bin/env python3
"""
rwsem.py — Linux kernel rw_semaphore analyzer.

Shared infrastructure (RHEL version, architecture, task state, address
resolution) is provided by chk_lock.py and injected before any analysis
function is called.  This module only contains rwsem-specific logic.
"""
from pykdump.API import *

# Shared globals — injected by chk_lock._push_globals() at startup.
RHEL_VERSION = 8
ARCH         = "64-bit"
DEBUG        = False
is_readfail_reliable = True

RWSEM_WRITER_LOCKED = 1 << 0
RWSEM_FLAG_WAITERS  = 1 << 1
RWSEM_FLAG_HANDOFF  = 1 << 2
RWSEM_FLAG_READFAIL = 1 << 63
RWSEM_READER_BIAS   = 1 << 8
RWSEM_READER_SHIFT  = 8

RWSEM_READER_MASK      = ~(RWSEM_READER_BIAS - 1)
RWSEM_WRITER_MASK      = RWSEM_WRITER_LOCKED
RWSEM_LOCK_MASK        = RWSEM_WRITER_MASK | RWSEM_READER_MASK
RWSEM_READ_FAILED_MASK = (RWSEM_WRITER_MASK | RWSEM_FLAG_WAITERS | RWSEM_FLAG_HANDOFF | RWSEM_FLAG_READFAIL)

RWSEM_READER_OWNED     = 0x1
RWSEM_NONSPINNABLE     = 0x2
RWSEM_OWNER_FLAGS_MASK = (RWSEM_READER_OWNED | RWSEM_NONSPINNABLE)


def dbg(msg):
    if DEBUG:
        print(f"[rwsem][dbg] {msg}")


# Injected by chk_lock._push_globals() — stubs keep the module importable standalone.
def get_task_state_map():  # pragma: no cover
    raise RuntimeError("get_task_state_map not injected by chk_lock")

def get_task_state(task):  # pragma: no cover
    raise RuntimeError("get_task_state not injected by chk_lock")


# Known combinations for reference/diagnostics
KNOWN_RWSEM_STATES = [
    {"value": 0,                    "desc": "Unlocked"},
    {"value": 1,                    "desc": "Writer holds lock"},
    {"value": 256,                  "desc": "1 reader"},
    {"value": 512,                  "desc": "2 readers"},
    {"value": 258,                  "desc": "1 reader + waiters"},
    {"value": 2,                    "desc": "Waiters only"},
    {"value": 6,                    "desc": "Waiters + handoff"},
    {"value": 3,                    "desc": "Writer + waiters"},
    {"value": 7,                    "desc": "Writer + waiters + handoff"},
    {"value": -9223372036854775802, "desc": "READFAIL + waiters + handoff"},
    {"value": -9223372036854775808, "desc": "READFAIL only"},
    {"value": -256,                 "desc": "Reader released (-1 reader)"},
    {"value": -254,                 "desc": "Reader released (-1 reader) + waiters"},
    {"value": -250,                 "desc": "Reader released (-1 reader) + waiters + handoff"},
    {"value": -1,                   "desc": "All bits set — likely corrupted"},
    {"value": -9223372036854775801, "desc": "All flags + READFAIL"},
    {"value": 518,                  "desc": "2 readers + waiters + handoff"},
    {"value": -9223372036854775553, "desc": "READFAIL + writer + 1 reader"},
    {"value": 4,                    "desc": "HANDOFF only"},
    {"value": -9223372036854775807, "desc": "WRITER + READFAIL"},
    {"value": 5,                    "desc": "WRITER + HANDOFF"},
]


def to_binary(value, bits=64):
    """Convert signed integer to a zero-padded two's-complement binary string."""
    unsigned_count = value & 0xFFFFFFFFFFFFFFFF
    return f"{unsigned_count:0{bits}b}"


def format_binary(count, arch="64-bit"):
    """Properly extract and format individual bitfields from rw_semaphore.count."""
    count_unsigned = count & 0xFFFFFFFFFFFFFFFF

    read_fail_bit   = (count_unsigned >> 63) & 0x1
    reader_count    = (count_unsigned >> 8) & ((1 << (63 - 8)) - 1)  # bits 8-62
    reserved_bits   = (count_unsigned >> 3) & 0x1F                    # bits 3-7
    lock_handoff    = (count_unsigned >> 2) & 0x1
    waiters_present = (count_unsigned >> 1) & 0x1
    writer_locked   =  count_unsigned & 0x1

    return (
        f"{read_fail_bit} "
        f"{reader_count:055b} "
        f"{reserved_bits:05b} "
        f"{lock_handoff} {waiters_present} {writer_locked}"
    )


def format_owner(owner):
    """Format the owner field into its binary components."""
    bin_str = to_binary(owner, 64)
    reader_owned = bin_str[-1]   # Bit 0 (RWSEM_READER_OWNED)
    nonspinnable = bin_str[-2]   # Bit 1 (RWSEM_NONSPINNABLE)
    task_ptr = owner & ~0x3
    task_address_bits = f"{task_ptr:064b}"[:-2]
    return f"{task_address_bits} {nonspinnable} {reader_owned}"


def chk_readfail(count_raw):
    """
    Determine whether the READFAIL bit (bit 63) is set in count_raw.

    The kernel sets RWSEM_FLAG_READFAIL as a guard bit when reader acquisition
    fails under contention.  The bit can coexist with active reader bits (8-62)
    — e.g. 0x8000_0100 (READFAIL + 1 reader) is a legitimate kernel-produced
    state — so we simply test the bit directly.
    """
    bitwise_count = count_raw & 0xFFFFFFFFFFFFFFFF
    dbg(f"chk_readfail(): count_raw={count_raw}, bitwise={bitwise_count:#018x}")
    result = bool(bitwise_count & RWSEM_FLAG_READFAIL)
    dbg(f"chk_readfail(): READFAIL bit set = {result}")
    return result


# Injected by chk_lock._push_globals() — stub keeps module importable standalone.
def get_task_state(task):  # pragma: no cover
    raise RuntimeError("get_task_state not injected by chk_lock")


def get_owner_info(owner_task_addr):
    """
    Given a task_struct pointer (flags already masked off), return a
    human-readable string describing the owning task.
    """
    # FIX #5: Parameter is always an int by this point; removed the misleading
    # isinstance-str branch.
    if not owner_task_addr:
        return "None"
    try:
        owner_task = readSU("struct task_struct", owner_task_addr)
        pid   = owner_task.pid
        comm  = owner_task.comm
        state = get_task_state(owner_task)
        return f"{owner_task_addr:#x} (PID: {pid}, COMM: {comm}, {state})"
    except Exception as e:
        dbg(f"get_owner_info(): could not read task_struct at {owner_task_addr:#x}: {e}")
        return f"{owner_task_addr:#x}"


# FIX #2: Removed the first (dead) definition of get_reader_count().
# Only the second definition — which correctly handles READFAIL — is kept.
def get_reader_count(count_raw, is_readfail_reliable):
    """
    Extract the reader count from rwsem.count.

    Bits 8-62 encode the number of active readers.  When READFAIL is reliably
    set it means reader acquisition failed and there are no active readers, so
    we return 0 in that case.
    """
    bitwise_count = count_raw & 0xFFFFFFFFFFFFFFFF
    reader_count  = (bitwise_count >> RWSEM_READER_SHIFT) & ((1 << (63 - RWSEM_READER_SHIFT)) - 1)

    if is_readfail_reliable and (bitwise_count & RWSEM_FLAG_READFAIL):
        dbg("get_reader_count(): READFAIL set — returning 0 (no active readers)")
        return 0

    dbg(f"get_reader_count(): count={count_raw}, readers={reader_count}")
    return reader_count


def list_waiting_tasks(wait_list_addr):
    """
    Return list of (pid, comm, state, task_addr, waiter_type) for tasks waiting on the
    rw_semaphore.

    Uses the same parsed waiter format as semaphore analysis so both lock
    analyzers print a consistent waiter table, with rwsem-specific waiter type.
    """
    result = []
    try:
        cmd = f"list -s rwsem_waiter.task,type -l rwsem_waiter.list -H {wait_list_addr:#x}"
        output = exec_crash_command(cmd)
        lines = [line.strip() for line in output.splitlines() if line.strip()]

        # Lines come in triplets: node_addr, "task = 0x...,", "type = ...,".
        i = 0
        while i < len(lines):
            if i + 2 >= len(lines):
                print(f"Warning: incomplete rwsem_waiter entry at line {i}: {lines[i]!r}")
                break
            try:
                task_line = lines[i + 1]
                type_line = lines[i + 2]
                if "task =" in task_line:
                    task_str = task_line.split("=", 1)[1].strip().rstrip(",")
                    task_addr = int(task_str, 16)
                    task = readSU("struct task_struct", task_addr)
                    state = get_task_state(task)
                    waiter_type = "Unknown"
                    if "type =" in type_line:
                        type_str = type_line.split("=", 1)[1].strip().rstrip(",")
                        try:
                            waiter_type = "Write" if int(type_str, 0) else "Read"
                        except Exception:
                            lowered = type_str.lower()
                            if "write" in lowered:
                                waiter_type = "Write"
                            elif "read" in lowered:
                                waiter_type = "Read"
                            else:
                                waiter_type = type_str
                    result.append((task.pid, task.comm, state, task_addr, waiter_type))
                else:
                    result.append(("?", task_line, "?", 0, "?"))
            except Exception as e:
                dbg(f"list_waiting_tasks(): error at line {i}: {e}")
                result.append(("?", lines[i], "?", 0, "?"))
            i += 3
    except Exception as e:
        print(f"Error listing waiters for rw_semaphore at {wait_list_addr:#x}: {e}")
    return result


def check_integrity(count, owner, reader_owned, owner_task_addr, is_readfail_reliable, reader_count, verbose=False):
    """Perform logical integrity checks on rw_semaphore values."""

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
        if count & RWSEM_WRITER_LOCKED: flags.append("WRITER_LOCKED")
        if count & RWSEM_FLAG_WAITERS:  flags.append("WAITERS_PRESENT")
        if count & RWSEM_FLAG_HANDOFF:  flags.append("HANDOFF")

        if flags:
            issues.append(f"ℹ️ RWSEM_FLAG_READFAIL set with: {', '.join(flags)} — likely a transitional contention state.")
        else:
            issues.append("ℹ️ RWSEM_FLAG_READFAIL set — benign reader acquisition failure (no other flags set).")

        # Transitional state — skip strict checks
        return issues

    # Reader-associated state (not guaranteed active readers)
    reader_bias_count = count & RWSEM_READER_MASK
    if reader_bias_count > 0 and not (count & RWSEM_WRITER_LOCKED):
        if RHEL_VERSION >= 8:
            # RWSEM_READER_OWNED / RWSEM_NONSPINNABLE flag bits in the owner
            # field only exist on RHEL 8+ (where owner is atomic_long_t).
            if not reader_owned:
                issues.append("ℹ️ Reader bias is present in `.count`, but RWSEM_READER_OWNED bit is not set — may be valid (fastpath), or worth reviewing.")
            if writer_task_struct is not None and not reader_owned:
                issues.append("⚠️ Owner field is nonzero but RWSEM_READER_OWNED not set — possible stale writer, or early reader acquisition.")

        elif RHEL_VERSION == 7:
            # On RHEL 7, owner is a plain task_struct pointer (no flag bits).
            # A non-null owner while readers hold the lock is unexpected.
            if writer_task_struct is not None:
                issues.append("⚠️ Unexpected: `.owner` should be 0 in RHEL 7 when readers hold the lock.")

        if reader_bias_count % RWSEM_READER_BIAS != 0:
            issues.append("⚠️ Reader count not aligned to RWSEM_READER_BIAS (256) — possible corruption or misinterpretation.")

    # Transitional or negative count state (not strictly writer-held)
    elif count < 0:
        if reader_count > 0:
            issues.append("🌀 `.count` is negative with reader bias. Reader release may not be properly completed due to racing.")
        elif reader_count == 0:
            issues.append("🌀 `.count` is negative without reader bias. Transitional state possibly with waiters or handoff or writer racing.")
        else:
            dbg("check_integrity(): unexpected: reader_count < 0")

        if owner_task_addr == 0:
            issues.append("🌀 `.count` is negative — transitional state or race possible. `owner` is null, which may be valid during unlock or reader release.")

        # reader_owned flag bits only exist in RHEL 8+ atomic_long_t owner
        if RHEL_VERSION >= 8 and reader_owned:
            issues.append("🌀 Transitional: `owner` marked as reader, and `count` is negative. Reader release may not be properly completed due to racing.")

        # FIX #9: Condition is `count == -1` but message said "< -1". Corrected.
        if count == -1:
            issues.append("🌀 `.count == -1` (all bits set) likely indicates a race during writer release, or lock corruption.")

    # Free lock
    elif count == 0:
        if owner_task_addr != 0:
            issues.append("⚠️ `owner` field not cleared: lock is free but `owner` is set.")

    # Reserved bits check (bits 3-7)
    reserved_mask = 0b11111000
    if count & reserved_mask:
        issues.append("⚠️ Reserved bits (3-7) are set — should be 0.")

    return issues


def chk_count_bits(count_raw):
    """Extract and return the boolean flags encoded in rwsem.count."""
    bitwise_count = count_raw & 0xFFFFFFFFFFFFFFFF
    dbg(f"chk_count_bits(): bitwise_count={bitwise_count:#018x}")
    writer_b   = bool(bitwise_count & RWSEM_WRITER_LOCKED)
    waiters_b  = bool(bitwise_count & RWSEM_FLAG_WAITERS)
    handoff_b  = bool(bitwise_count & RWSEM_FLAG_HANDOFF)
    readfail_b = bool(bitwise_count & RWSEM_FLAG_READFAIL)
    return bitwise_count, writer_b, waiters_b, handoff_b, readfail_b


def explain_bits_combination(count, reader_count, is_readfail_reliable):
    """Return a human-readable description of the active flag bits in .count."""
    bitwise_count, writer, waiters, handoff, readfail = chk_count_bits(count)

    count_bits = []
    if writer:  count_bits.append("1(WRITER_LOCKED)")
    if waiters: count_bits.append("2(WAITERS)")
    if handoff: count_bits.append("4(HANDOFF)")
    # FIX #8: was `is_readfail_reliable & readfail` (bitwise AND on booleans).
    # Corrected to `and` for proper boolean logic.
    if is_readfail_reliable and readfail:
        count_bits.append("9223372036854775808(READFAIL)")

    desc_parts = []
    if count_bits:
        desc_parts.append(" + ".join(count_bits))

    dbg(f"explain_bits_combination(): reader_count={reader_count}")
    if reader_count > 0:
        bias = RWSEM_READER_BIAS * reader_count
        if is_readfail_reliable:
            desc_parts.append(f"+ {bias} ({reader_count} reader(s))")
        else:
            desc_parts.append(f"- {bias} ({reader_count} reader(s))")

    if not desc_parts:
        desc_parts.append("no bits or readers set")

    return " ".join(desc_parts)


def _build_classify_result(flags, reader_count, reader_note, reserved_bits,
                            state_type, description,
                            count_raw, bitwise_count, is_readfail_reliable):
    """Assemble and return the classification result dict."""
    matched_known = next(
        (entry['desc'] for entry in KNOWN_RWSEM_STATES if count_raw == entry['value']),
        None
    )
    combined_bits_desc = explain_bits_combination(count_raw, reader_count, is_readfail_reliable)
    description += f"\n  🧩  Possible Bits Combination: {combined_bits_desc}"
    if matched_known:
        description += f"\n  🔎  Matched known pattern: {matched_known}"

    return {
        "flags":         flags,
        "reader_count":  reader_count,
        "reader_note":   reader_note,
        "reserved_bits": f"{reserved_bits:05b}",
        "state_type":    state_type,
        "description":   description,
        "raw_value":     f"0x{bitwise_count:016x}",
    }


def classify_rwsem_state(count_raw, is_readfail_reliable, reader_count, verbose=False):
    """Classify the rw_semaphore count value into a human-readable state."""

    flags = []
    bitwise_count, writer, waiters, handoff, readfail = chk_count_bits(count_raw)
    reserved_bits = (bitwise_count >> 3) & 0x1F

    # Always re-derive reader count from the raw value for consistency
    reader_count = get_reader_count(count_raw, is_readfail_reliable)

    reader_note = f"{reader_count} reader(s)"

    if writer:   flags.append("WRITER_LOCKED")
    if waiters:  flags.append("WAITERS")
    if handoff:  flags.append("HANDOFF")
    if readfail: flags.append("READFAIL")

    def build(state_type, description):
        if reserved_bits:
            description += " Reserved bits (3-7) are set — unexpected."
        return _build_classify_result(
            flags, reader_count, reader_note, reserved_bits,
            state_type, description,
            count_raw, bitwise_count, is_readfail_reliable,
        )

    # --- Explicit edge cases ---

    # FIX: READFAIL + writer is a transitional state, not an invalid one.
    # The kernel can produce this when a reader's atomic_long_fetch_add trips
    # the READFAIL guard bit while a writer holds the lock.  It is listed in
    # KNOWN_RWSEM_STATES as a real, observable value.
    if readfail and writer:
        return build("🌀 Transitional",
                     "READFAIL guard tripped while writer holds lock — contended transitional state.")

    # FIX: count_raw == -1 (all bits set) must be checked BEFORE the generic
    # count_raw < 0 branch, which would otherwise shadow it and prevent the
    # more specific diagnosis from ever being reached.
    if count_raw == -1:
        return build("🌀 Transitional / Invalid", "All bits set — race condition or corrupted state.")

    # Negative count without READFAIL = transient reader-release or race
    if count_raw < 0 and not readfail:
        return build("🌀 Transitional",
                     "Negative count — transient state during reader release or race.")

    # READFAIL alone = reader acquisition failed
    if readfail:
        reader_note = "🌀 Reader acquisition failed (READFAIL)"

    if count_raw == 0:
        return build("✅ Stable", "Lock is free.")

    # Readers hold lock (valid even with waiters)
    if reader_count > 0 and not writer:
        desc = (f"{reader_count} reader(s) hold the lock with waiters queued."
                if waiters else f"{reader_count} reader(s) hold the lock.")
        return build("✅ Stable", desc)

    # Invalid: writer and readers simultaneously
    if writer and reader_count > 0:
        return build("❗ Invalid",
                     f"Writer and {reader_note} both hold the lock — impossible state.")

    # Writer holds lock
    if writer and reader_count == 0:
        desc = ("Writer holds the lock with waiters queued."
                if waiters else "Writer holds the lock.")
        return build("✅ Stable", desc)

    # READFAIL without writer
    if readfail:
        return build("🌀 Transitional", "Reader failed to acquire lock (READFAIL).")

    # No holders but waiters or handoff pending
    if reader_count == 0 and (waiters or handoff):
        return build("🌀 Transitional", "No active holders, but waiters or handoff pending.")

    return build("🌀 Unknown or Rare",
                 "Unclassified state. Possibly due to race, partial update, or corruption.")


def print_owner_bitfield(owner, owner_info, verbose=False):
    """Print a breakdown of the rw_semaphore owner field."""
    binary_owner = format_owner(owner)

    print("\n=== Breakdown of RW Semaphore Owner Field ===")
    print(f"Binary:       {binary_owner}")
    print("                                                                             ^ ^")
    print("  🔄 Non-Spinnable Bit               ────────────────────────────────────────┘ |")
    print("  📖 Reader Owned Bit (Bit 0):       ──────────────────────────────────────────┘")
    print(f"  🏷  Owner Task: {owner_info}")

    if RHEL_VERSION >= 8:
        if verbose:
            print("\nVerbose Explanation:")
            print("  - Reader Owned Bit: 1 = A reader currently owns the lock")
            print("  - Non-Spinnable: 1 = Writer stopped spinning and went to sleep")
    else:
        print("  ℹ️ (RHEL 7) The `owner` field should only be set by writers.")


def print_count_bitfield_breakdown(count_raw, arch="64-bit", verbose=False):
    """Print a human-readable breakdown of the count bitfield."""
    binary_output = format_binary(count_raw, arch)

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
    """Analyze the rw_semaphore state based on the given count and owner values."""

    bitwise_count, _, _, _, _ = chk_count_bits(count)

    print(f"\n=== RW Semaphore Status ({arch}) ===")
    print(f"Count Value:     0x{bitwise_count:016X} ({count})")

    owner_address = owner & 0xFFFFFFFFFFFFFFFF
    print(f"Owner Value:     {owner_address:#x}")
    print("====================================")

    print_count_bitfield_breakdown(count, arch, verbose)

    reader_count = get_reader_count(count, is_readfail_reliable)
    result = classify_rwsem_state(count, is_readfail_reliable, reader_count)
    if result:
        print("\n  🧠 Inferred State:")
        print(f"  Flags Set: {', '.join(result['flags']) if result['flags'] else 'None'}")
        print(f"  Number of Readers: {result['reader_count']}")
        print(f"  {result['state_type']}: {result['description']}")

    # FIX: On RHEL 7 the owner field is a plain struct task_struct pointer with
    # no embedded flag bits.  RWSEM_READER_OWNED / RWSEM_NONSPINNABLE were
    # introduced alongside the atomic_long_t owner in RHEL 8+.  Extracting
    # flag bits from a RHEL 7 owner produces meaningless values and will
    # trigger false integrity warnings.
    if RHEL_VERSION >= 8:
        reader_owned    = owner & RWSEM_READER_OWNED
        owner_task_addr = owner & ~RWSEM_OWNER_FLAGS_MASK
    else:
        reader_owned    = 0          # flags don't exist in RHEL 7 owner
        owner_task_addr = owner      # raw pointer, no bits to strip

    owner_info = get_owner_info(owner_task_addr)
    print_owner_bitfield(owner, owner_info, verbose)

    print("\n🚨 **RW Semaphore Integrity Check** 🚨")

    integrity_issues = check_integrity(
        count, owner, reader_owned, owner_task_addr,
        is_readfail_reliable, reader_count, verbose
    )

    if integrity_issues:
        for issue in integrity_issues:
            print(issue)
    else:
        print("✅ **Semaphore state is logically consistent.**")


def analyze_rw_semaphore_from_vmcore(rw_semaphore_addr, list_waiters=False, verbose=False, debug=False):
    """Read rw_semaphore structure from VMcore and analyze its state."""

    global DEBUG
    DEBUG = debug

    rwsem = readSU("struct rw_semaphore", rw_semaphore_addr)
    count_raw = rwsem.count.counter

    is_readfail_reliable = chk_readfail(count_raw)
    dbg(f"is_readfail_reliable: {is_readfail_reliable}")

    arch = ARCH  # injected by chk_lock._push_globals()

    owner_raw = rwsem.owner.counter if RHEL_VERSION >= 8 else rwsem.owner
    owner_raw = owner_raw & 0xFFFFFFFFFFFFFFFF

    if verbose:
        print("\n🔍 **Raw rw_semaphore Structure Data:**")
        raw_output = exec_crash_command(f"struct rw_semaphore {rw_semaphore_addr:#x} -x")
        print(raw_output)

    analyze_rw_semaphore(count_raw, is_readfail_reliable, owner_raw, arch, verbose)

    if list_waiters:
        waiters = list_waiting_tasks(int(rwsem.wait_list))
        if waiters:
            print("\nWaiting Tasks:")
            print(f"{'PID':<10} {'State':<25} {'Type':<8} {'Address':<18} Command")
            print("-" * 81)
            for pid, comm, state, task_addr, waiter_type in waiters:
                print(f"{pid!s:<10} {state:<25} {waiter_type:<8} {task_addr:#018x} {comm}")
            print(f"\nNumber of waiters: {len(waiters)}")
        else:
            print("\nWaiting Tasks: none")
