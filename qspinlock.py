#!/usr/bin/env python3
"""
qspinlock.py — qspinlock / spinlock_t analyzer.

Shared infrastructure (RHEL version, architecture, task state, address
resolution) is provided by chk_lock.py and injected before analyze_qspinlock()
is called.  This module only contains qspinlock-specific logic.
"""
from pykdump.API import *

# Shared globals — injected by chk_lock._push_globals() at startup.
RHEL_VERSION = 8
DEBUG        = False


def dbg(msg):
    if DEBUG:
        print(f"[qspinlock][dbg] {msg}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _to_binary(value, bits):
    """Convert value to a zero-padded binary string of given bit length."""
    return f"{value:0{bits}b}"


def _format_binary(counter, bitfield):
    """Format the 32-bit counter as a grouped binary string matching the field layout."""
    bin_str = _to_binary(counter, 32)

    locked_bits     = bin_str[-8:]
    pending_bits    = bin_str[-(bitfield["pending_start"] + 1):-bitfield["pending_start"]]
    unused_bits     = bin_str[-(bitfield["unused_start"] + bitfield["unused_bits"]):-bitfield["unused_start"]]
    tail_index_bits = bin_str[-(bitfield["tail_index_start"] + bitfield["tail_index_bits"]):-bitfield["tail_index_start"]]
    tail_cpu_bits   = bin_str[:-(bitfield["tail_cpu_start"])]

    return f"{tail_cpu_bits} {tail_index_bits} {unused_bits} {pending_bits} {locked_bits}"


def _get_bitfield():
    """Return the bitfield layout dict for the current RHEL version."""
    if RHEL_VERSION == 7:
        return {
            "locked_start":     0,
            "pending_start":    8,
            "unused_start":     9,
            "tail_index_start": 16,   # 3 bits for NR_CPUS <= 8K
            "tail_cpu_start":   19,
            "unused_bits":      7,
            "tail_index_bits":  3,
            "tail_cpu_bits":    13,
            "tail_cpu_offset":  0,    # tail CPU stored as-is on RHEL7
        }
    else:  # RHEL 8/9 (NR_CPUS < 16K)
        return {
            "locked_start":     0,
            "pending_start":    8,
            "unused_start":     9,
            "tail_index_start": 16,   # 2 bits
            "tail_cpu_start":   18,
            "unused_bits":      7,
            "tail_index_bits":  2,
            "tail_cpu_bits":    14,
            "tail_cpu_offset":  1,    # tail CPU stored as (CPU ID + 1) on RHEL8/9
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def show_qspinlock_flowchart():
    """Display the qspinlock state-transition flowchart."""
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
    """Decode and print the state of a qspinlock at the given address."""
    global DEBUG
    DEBUG = debug

    try:
        qs = readSU("struct qspinlock", qspinlock_addr)
    except Exception as e:
        print(f"Error reading qspinlock at {qspinlock_addr:#x}: {e}")
        return

    counter  = qs.val.counter & 0xFFFFFFFF
    bitfield = _get_bitfield()

    locked        = (counter >> bitfield["locked_start"])     & 0xFF
    pending       = (counter >> bitfield["pending_start"])    & 0x1
    unused        = (counter >> bitfield["unused_start"])     & ((1 << bitfield["unused_bits"])      - 1)
    tail_index    = (counter >> bitfield["tail_index_start"]) & ((1 << bitfield["tail_index_bits"])  - 1)
    tail_cpu_raw  = (counter >> bitfield["tail_cpu_start"])   & ((1 << bitfield["tail_cpu_bits"])    - 1)
    tail_cpu      = tail_cpu_raw - bitfield["tail_cpu_offset"]

    print(f"\n=== QSpinlock Status (RHEL {RHEL_VERSION}) ===")
    print(f"Counter Value:   0x{counter:X} ({counter})")
    print(f"Binary:          {_format_binary(counter, bitfield)}")
    print(f"Locked Byte:     0x{locked:02X}  ({_to_binary(locked, 8)})")
    print(f"Pending:         {'Yes' if pending else 'No'}  ({_to_binary(pending, 1)})")
    print(f"Unused Bits:     {_to_binary(unused, bitfield['unused_bits'])}")
    print(f"Tail Index:      {tail_index}  ({_to_binary(tail_index, bitfield['tail_index_bits'])})")
    print(f"Tail CPU:        {tail_cpu if tail_cpu >= 0 else 'None'}  ({_to_binary(tail_cpu_raw, bitfield['tail_cpu_bits'])})")
    print("========================\n")

    print("=== Possible Scenarios ===")

    if locked == 0:
        if tail_index == 0:
            print("✅ Lock is FREE. No CPUs are waiting.")
        else:
            print("⚠️ Lock is free but tail index is non-zero — possible release race condition.")

    else:  # locked != 0
        if tail_index == 0:
            if pending == 0:
                print("🔒 Lock is HELD with no CPUs waiting. Owner may be in a critical section.")
            else:
                print("⚠️ Pending bit set but no CPUs queued — possible race condition or corruption.")
        elif tail_cpu >= 0:
            print(f"🔄 Lock is HELD, {tail_index} CPU(s) waiting. Last to queue: CPU {tail_cpu}.")
            if pending:
                print("  - A pending waiter is actively spinning (contention).")
            else:
                print("  - No active spinning waiter; queued CPUs may be sleeping.")

        if tail_index > 5:
            print("⚠️ High contention: more than 5 CPUs waiting.")

    if pending == 1 and tail_index > 0:
        print("⚠️ Lock held with a pending-loop waiter — contention detected.")
    if pending == 1 and tail_index == 0:
        print("❗ Pending bit set but no CPUs queued — possible race condition.")
    if tail_cpu < 0 and tail_index > 0:
        print("⚠️ Invalid tail CPU — possible corrupted spinlock state.")

    print("========================\n")

