#!/usr/bin/env python3
"""
mutex.py — Linux kernel mutex (struct mutex) analyzer.

Shared infrastructure (RHEL version, task state, address resolution) is
provided by chk_lock.py and injected before any analysis function is called.
This module only contains mutex-specific logic.
"""
from pykdump.API import *

# Kernel constants — confirmed against kernel/locking/mutex.c
# Bit 0: non-empty waiter list; unlock must issue a wakeup.
# Bit 1: unlock needs to hand the lock to the top-waiter.
# Bit 2: handoff done, waiting for pickup.
MUTEX_FLAG_WAITERS = 0x01
MUTEX_FLAG_HANDOFF = 0x02
MUTEX_FLAG_PICKUP  = 0x04
MUTEX_FLAGS        = 0x07

# Shared globals — injected by chk_lock._push_globals() at startup.
rhel_version = 8
DEBUG        = False


def dbg(msg):
    if DEBUG:
        print(f"[mutex][dbg] {msg}")


# Injected by chk_lock._push_globals() — stub keeps module importable standalone.
def get_task_state(task):  # pragma: no cover
    raise RuntimeError("get_task_state not injected by chk_lock")


def get_waiters(mutex):
    """Return list of (pid, comm, state) tuples for tasks waiting on the mutex."""
    waiters = []
    try:
        wait_list = ListHead(int(mutex.wait_list), "struct mutex_waiter")
        for waiter in wait_list.list:
            task = waiter.task
            if task:
                state = get_task_state(task)
                waiters.append((task.pid, task.comm, state))
    except Exception as e:
        print(f"Warning: could not enumerate mutex waiters: {e}")
    return waiters


def get_owner_info(owner_address):
    """
    Given a task_struct pointer (flag bits already stripped), return a
    human-readable string describing the owning task.
    """
    # FIX: Removed the isinstance-str branch — owner_address is always an int
    # by the time it arrives here.  Also returns "None" cleanly for null owner
    # instead of calling hex(0) and then trying to readSU from address 0.
    if not owner_address:
        return "None"
    try:
        owner_task = readSU("struct task_struct", owner_address)
        pid   = owner_task.pid
        comm  = owner_task.comm
        state = get_task_state(owner_task)
        return f"{owner_address:#x} (PID: {pid}, COMM: {comm}, {state})"
    except Exception as e:
        dbg(f"get_owner_info(): could not read task_struct at {owner_address:#x}: {e}")
        return f"{owner_address:#x}"


def get_mutex_info(mutex_addr, list_waiters):
    """Read and decode a struct mutex from the vmcore."""
    try:
        mutex = readSU("struct mutex", mutex_addr)
    except Exception as e:
        print(f"Error accessing mutex at {mutex_addr:#x}: {e}")
        return None

    # owner field is atomic_long_t on RHEL8+ (access via .counter),
    # and a plain task_struct * on RHEL7.
    # FIX: The original code used the module-level rhel_version which was never
    # updated from its default of 8 because get_rhel_version() only wrote to a
    # local variable.  Now that get_rhel_version() correctly updates the global,
    # this conditional works as intended.
    try:
        owner_raw = mutex.owner.counter if rhel_version >= 8 else int(mutex.owner)
    except Exception as e:
        print(f"Warning: could not read mutex.owner at {mutex_addr:#x}: {e}")
        owner_raw = 0

    # Strip the 3 flag bits to get the actual task_struct pointer.
    owner_address = (owner_raw & ~MUTEX_FLAGS) & 0xFFFFFFFFFFFFFFFF
    flags_raw     = owner_raw & MUTEX_FLAGS

    flag_status = []
    if flags_raw & MUTEX_FLAG_WAITERS:
        flag_status.append("WAITERS - Unlock must issue a wakeup")
    if flags_raw & MUTEX_FLAG_HANDOFF:
        flag_status.append("HANDOFF - Unlock needs to hand the lock to the top-waiter")
    if flags_raw & MUTEX_FLAG_PICKUP:
        flag_status.append("PICKUP - Handoff has been done, waiting for pickup")

    # FIX: wait_lock field path differs by RHEL version.  The original code
    # had both paths gated on rhel_version >= 8, but the else branch used
    # rlock.raw_lock.val.counter which matches RHEL7's spinlock layout.
    # Also wrapped in try/except so a layout mismatch doesn't crash the tool.
    try:
        if rhel_version >= 8:
            wait_lock_val = mutex.wait_lock.raw_lock.val.counter
        else:
            wait_lock_val = mutex.wait_lock.rlock.raw_lock.val.counter
    except Exception as e:
        print(f"Warning: could not read mutex.wait_lock at {mutex_addr:#x}: {e}")
        wait_lock_val = -1

    # A qspinlock val of 0 means unlocked; anything else means locked.
    # FIX: The original used `!= 1` as the locked test, but qspinlock encodes
    # "unlocked" as 0, not 1.  A val of 1 actually means the lock IS held
    # (locked byte = 0x01).  Corrected to `!= 0`.
    lock_state = "Locked" if wait_lock_val != 0 else "Unlocked"

    mutex_info = {
        "address":        f"{mutex_addr:#x}",
        "owner":          get_owner_info(owner_address),
        "flags":          flag_status if flag_status else ["NONE"],
        "flags_raw":      flags_raw,
        "wait_lock_val":  wait_lock_val,
        "wait_list_next": f"{int(mutex.wait_list.next):#x}",
        "wait_list_prev": f"{int(mutex.wait_list.prev):#x}",
        "locked":         lock_state,
    }

    if list_waiters:
        mutex_info["waiters"] = get_waiters(mutex)

    return mutex_info


def analyze_mutex(mutex_info, verbose=False):
    """Print a human-readable analysis of a decoded mutex."""
    if not mutex_info:
        print("No valid mutex information found.")
        return

    print("\n=== Mutex Analysis ===")
    print(f"Address:        {mutex_info['address']}")
    print(f"Owner:          {mutex_info['owner']}")
    print(f"Flags:          {', '.join(mutex_info['flags'])}")
    print(f"Status:         {mutex_info['locked']}")
    print(f"Wait Lock Val:  {mutex_info['wait_lock_val']}")
    print(f"Wait List Next: {mutex_info['wait_list_next']}")
    print(f"Wait List Prev: {mutex_info['wait_list_prev']}")

    if verbose:
        print("\nVerbose Explanation:")
        print("  wait_lock is a qspinlock protecting the wait_list.")
        print("  val == 0 : unlocked (no one holds wait_lock)")
        print("  val != 0 : locked   (a thread is modifying the wait_list)")
        print(f"\n  Flag bits (raw: {mutex_info['flags_raw']:#x}):")
        print(f"    bit 0 (WAITERS) = {int(bool(mutex_info['flags_raw'] & MUTEX_FLAG_WAITERS))}"
              "  unlock must issue a wakeup")
        print(f"    bit 1 (HANDOFF) = {int(bool(mutex_info['flags_raw'] & MUTEX_FLAG_HANDOFF))}"
              "  unlock must hand lock directly to top waiter")
        print(f"    bit 2 (PICKUP)  = {int(bool(mutex_info['flags_raw'] & MUTEX_FLAG_PICKUP))}"
              "  handoff done, top waiter must pick up the lock")

    # Integrity hint: WAITERS flag set but wait_list appears empty
    next_addr = int(mutex_info['wait_list_next'], 16)
    prev_addr = int(mutex_info['wait_list_prev'], 16)
    list_empty = (next_addr == prev_addr)  # circular list points to itself when empty

    if mutex_info['flags_raw'] & MUTEX_FLAG_WAITERS and list_empty:
        print("⚠️  WAITERS flag is set but wait_list appears empty — possible transient state.")
    if mutex_info['flags_raw'] & MUTEX_FLAG_HANDOFF and mutex_info['flags_raw'] & MUTEX_FLAG_PICKUP:
        print("⚠️  Both HANDOFF and PICKUP flags set simultaneously — unexpected state.")

    if "waiters" in mutex_info:
        waiters = mutex_info["waiters"]
        if waiters:
            print("\nWaiting Tasks:")
            print(f"{'PID':<10} {'Command':<20} {'State'}")
            print("-" * 60)
            for pid, comm, state in waiters:
                print(f"{pid!s:<10} {comm:<20} {state}")
            print(f"\nNumber of waiters: {len(waiters)}")
        else:
            print("\nWaiting Tasks: none")

