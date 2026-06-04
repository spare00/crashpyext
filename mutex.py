#!/usr/bin/env python3
"""
mutex.py — Linux kernel mutex (struct mutex) analyzer.

Shared infrastructure (RHEL version, task state, address resolution) is
provided by chk_lock.py and injected before any analysis function is called.
This module only contains mutex-specific logic.

Layout variants:
  rhel7     — count-based mutex (RHEL7)
  standard  — owner + wait_list (RHEL8/9 non-RT)
  rt        — rt_mutex_base embedded in struct mutex (PREEMPT_RT)
"""
import re
from pykdump.API import *

# Kernel constants — confirmed against kernel/locking/mutex.c
# Bit 0: non-empty waiter list; unlock must issue a wakeup.
# Bit 1: unlock needs to hand the lock to the top-waiter.
# Bit 2: handoff done, waiting for pickup.
MUTEX_FLAG_WAITERS = 0x01
MUTEX_FLAG_HANDOFF = 0x02
MUTEX_FLAG_PICKUP  = 0x04
MUTEX_FLAGS        = 0x07

# RT-mutex uses only bit 0 of owner for "has waiters".
RT_MUTEX_HAS_WAITERS = 0x01

# Shared globals — injected by chk_lock._push_globals() at startup.
rhel_version   = 8
kernel_version = ""
DEBUG          = False

MUTEX_LAYOUT     = None
_RTMUTEX_OFFSET  = None
_CRASH_MUTEX_CACHE = {}


def dbg(msg):
    if DEBUG:
        print(f"[mutex][dbg] {msg}")


# Injected by chk_lock._push_globals() — stub keeps module importable standalone.
def get_task_state(task):  # pragma: no cover
    raise RuntimeError("get_task_state not injected by chk_lock")


def _init_mutex_layout():
    """Detect struct mutex layout once from kernel metadata."""
    global MUTEX_LAYOUT
    if MUTEX_LAYOUT is not None:
        return MUTEX_LAYOUT

    if "+rt" in kernel_version.lower():
        MUTEX_LAYOUT = "rt"
        dbg(f"_init_mutex_layout(): RT kernel detected ({kernel_version!r})")
        return MUTEX_LAYOUT

    try:
        out = exec_crash_command("struct mutex -o")
        if re.search(r"\brtmutex\b", out):
            MUTEX_LAYOUT = "rt"
        elif re.search(r"\bfirst_waiter\b", out):
            MUTEX_LAYOUT = "first_waiter"
        elif re.search(r"\bcount\b", out) and not re.search(r"\bowner\b", out):
            MUTEX_LAYOUT = "rhel7"
        else:
            MUTEX_LAYOUT = "standard"
        dbg(f"_init_mutex_layout(): struct mutex -o => {MUTEX_LAYOUT}")
    except Exception as e:
        dbg(f"_init_mutex_layout(): fallback to standard: {e}")
        MUTEX_LAYOUT = "standard"

    return MUTEX_LAYOUT


def _rtmutex_base_addr(mutex_addr):
    """Return the address of the embedded rt_mutex_base within struct mutex."""
    global _RTMUTEX_OFFSET
    if _RTMUTEX_OFFSET is None:
        _RTMUTEX_OFFSET = 0
        try:
            out = exec_crash_command("struct mutex -o")
            m = re.search(
                r"^\s*\[(0x[0-9a-fA-F]+|\d+)\].*\brtmutex\b",
                out,
                re.MULTILINE,
            )
            if m:
                _RTMUTEX_OFFSET = int(m.group(1), 0)
        except Exception as e:
            dbg(f"_rtmutex_base_addr(): offset lookup failed: {e}")
    return int(mutex_addr) + _RTMUTEX_OFFSET


def _crash_mutex_output(mutex_addr):
    addr = int(mutex_addr)
    if addr not in _CRASH_MUTEX_CACHE:
        _CRASH_MUTEX_CACHE[addr] = exec_crash_command(f"struct mutex {addr:#x}")
    return _CRASH_MUTEX_CACHE[addr]


def _parse_rt_owner_from_crash(mutex_addr):
    """Parse rtmutex.owner from crash 'struct mutex' output."""
    out = _crash_mutex_output(mutex_addr)
    m = re.search(
        r"rtmutex\s*=\s*\{.*?owner\s*=\s*(0x[0-9a-fA-F]+|\d+)",
        out,
        re.DOTALL,
    )
    if m:
        return int(m.group(1), 0) & 0xFFFFFFFFFFFFFFFF
    return 0


def _read_wait_lock_val(wait_lock):
    """Read raw_spinlock_t / qspinlock counter from a wait_lock member."""
    try:
        return int(wait_lock.raw_lock.val.counter)
    except Exception:
        try:
            return int(wait_lock.rlock.raw_lock.val.counter)
        except Exception:
            return -1


def get_waiters(mutex):
    """Return list of (pid, comm, state) tuples for standard mutex wait_list."""
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


def get_waiters_first_waiter(mutex):
    """Return waiters when struct mutex uses first_waiter instead of wait_list."""
    waiters = []
    try:
        first = int(mutex.first_waiter)
        if not first:
            return waiters
        wait_list = ListHead(first, "struct mutex_waiter")
        for waiter in wait_list.list:
            task = waiter.task
            if task:
                state = get_task_state(task)
                waiters.append((task.pid, task.comm, state))
    except Exception as e:
        print(f"Warning: could not enumerate mutex waiters: {e}")
    return waiters


def get_rt_mutex_waiters(mutex_addr):
    """
    Return waiters for PREEMPT_RT mutexes (rbtree-backed rt_mutex_base.waiters).

    Uses crash's tree command to walk rt_mutex_waiter nodes in priority order.
    """
    waiters = []
    rtmutex_addr = _rtmutex_base_addr(mutex_addr)
    try:
        cmd = (
            f"tree -t rbtree -r rt_mutex_base.waiters {rtmutex_addr:#x} "
            f"-o rt_mutex_waiter.tree.node -l -S rt_mutex_waiter.task"
        )
        output = exec_crash_command(cmd)
        lines = [l.strip() for l in output.splitlines() if l.strip()]

        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("tree:") or line.startswith("***"):
                i += 1
                continue
            if i + 1 < len(lines) and "task =" in lines[i + 1]:
                try:
                    task_str = lines[i + 1].split("=", 1)[1].strip().rstrip(",")
                    task_addr = int(task_str, 0)
                    task = readSU("struct task_struct", task_addr)
                    state = get_task_state(task)
                    waiters.append((task.pid, task.comm, state))
                except Exception as e:
                    dbg(f"get_rt_mutex_waiters(): parse error at line {i}: {e}")
                i += 2
                continue
            i += 1
    except Exception as e:
        print(f"Warning: could not enumerate RT mutex waiters: {e}")
    return waiters


def get_owner_info(owner_address):
    """
    Given a task_struct pointer (flag bits already stripped), return a
    human-readable string describing the owning task.
    """
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


def _rt_waiters_empty(mutex):
    try:
        waiters = mutex.rtmutex.waiters
        return int(waiters.rb_root.rb_node) == 0
    except Exception:
        return True


def _get_mutex_info_rt(mutex, mutex_addr, list_waiters):
    """Decode PREEMPT_RT struct mutex (rt_mutex_base via rtmutex member)."""
    try:
        owner_raw = int(mutex.rtmutex.owner)
    except Exception as e:
        print(f"Warning: could not read mutex.rtmutex.owner at {mutex_addr:#x}: {e}")
        owner_raw = _parse_rt_owner_from_crash(mutex_addr)

    owner_address = (owner_raw & ~RT_MUTEX_HAS_WAITERS) & 0xFFFFFFFFFFFFFFFF
    flags_raw = owner_raw & RT_MUTEX_HAS_WAITERS

    flag_status = []
    if flags_raw & RT_MUTEX_HAS_WAITERS:
        flag_status.append("HAS_WAITERS - Lock has tasks waiting on rt_mutex waiters tree")

    try:
        wait_lock_val = _read_wait_lock_val(mutex.rtmutex.wait_lock)
    except Exception as e:
        print(f"Warning: could not read mutex.rtmutex.wait_lock at {mutex_addr:#x}: {e}")
        wait_lock_val = -1

    locked = "Locked" if owner_address != 0 else "Unlocked"
    wait_list_empty = _rt_waiters_empty(mutex)

    try:
        rb_node = int(mutex.rtmutex.waiters.rb_root.rb_node)
    except Exception:
        rb_node = 0

    mutex_info = {
        "address":         f"{mutex_addr:#x}",
        "layout":          "rt",
        "owner":           get_owner_info(owner_address),
        "flags":           flag_status if flag_status else ["NONE"],
        "flags_raw":       flags_raw,
        "count_val":       None,
        "wait_lock_val":   wait_lock_val,
        "wait_list_next":  f"{rb_node:#x}",
        "wait_list_prev":  f"{rb_node:#x}",
        "wait_list_empty": wait_list_empty,
        "locked":          locked,
    }

    if list_waiters:
        waiters = get_rt_mutex_waiters(mutex_addr)
        mutex_info["waiters"] = waiters
        if waiters and locked == "Locked":
            mutex_info["locked"] = f"Locked (with ~{len(waiters)} waiter(s))"

    return mutex_info


def _get_mutex_info_standard(mutex, mutex_addr, list_waiters, layout):
    """Decode owner-based struct mutex (wait_list or first_waiter)."""
    try:
        owner_raw = mutex.owner.counter if rhel_version >= 8 else int(mutex.owner)
    except Exception as e:
        print(f"Warning: could not read mutex.owner at {mutex_addr:#x}: {e}")
        owner_raw = 0

    owner_address = (owner_raw & ~MUTEX_FLAGS) & 0xFFFFFFFFFFFFFFFF
    flags_raw = owner_raw & MUTEX_FLAGS

    flag_status = []
    if flags_raw & MUTEX_FLAG_WAITERS:
        flag_status.append("WAITERS - Unlock must issue a wakeup")
    if flags_raw & MUTEX_FLAG_HANDOFF:
        flag_status.append("HANDOFF - Unlock needs to hand the lock to the top-waiter")
    if flags_raw & MUTEX_FLAG_PICKUP:
        flag_status.append("PICKUP - Handoff has been done, waiting for pickup")

    try:
        wait_lock_val = _read_wait_lock_val(mutex.wait_lock)
    except Exception as e:
        print(f"Warning: could not read mutex.wait_lock at {mutex_addr:#x}: {e}")
        wait_lock_val = -1

    locked = "Locked" if owner_address != 0 else "Unlocked"
    count_val = None

    if layout == "first_waiter":
        try:
            first = int(mutex.first_waiter)
            wait_list_next = f"{first:#x}"
            wait_list_prev = f"{first:#x}"
            wait_list_empty = first == 0
        except Exception as e:
            print(f"Warning: could not read mutex.first_waiter at {mutex_addr:#x}: {e}")
            wait_list_next = "0x0"
            wait_list_prev = "0x0"
            wait_list_empty = True
    else:
        try:
            wait_list_next = f"{int(mutex.wait_list.next):#x}"
            wait_list_prev = f"{int(mutex.wait_list.prev):#x}"
            wait_list_empty = int(mutex.wait_list.next) == int(mutex.wait_list.prev)
        except Exception as e:
            print(f"Warning: could not read mutex.wait_list at {mutex_addr:#x}: {e}")
            wait_list_next = "0x0"
            wait_list_prev = "0x0"
            wait_list_empty = True

    mutex_info = {
        "address":         f"{mutex_addr:#x}",
        "layout":          layout,
        "owner":           get_owner_info(owner_address),
        "flags":           flag_status if flag_status else ["NONE"],
        "flags_raw":       flags_raw,
        "count_val":       count_val,
        "wait_lock_val":   wait_lock_val,
        "wait_list_next":  wait_list_next,
        "wait_list_prev":  wait_list_prev,
        "wait_list_empty": wait_list_empty,
        "locked":          locked,
    }

    if list_waiters:
        if layout == "first_waiter":
            waiters = get_waiters_first_waiter(mutex)
        else:
            waiters = get_waiters(mutex)
        mutex_info["waiters"] = waiters
        if waiters and locked == "Locked":
            mutex_info["locked"] = f"Locked (with ~{len(waiters)} waiter(s))"

    return mutex_info


def _get_mutex_info_rhel7(mutex, mutex_addr, list_waiters):
    """Decode count-based struct mutex (RHEL7)."""
    owner_raw = 0
    owner_address = 0
    flags_raw = 0

    try:
        wait_lock_val = _read_wait_lock_val(mutex.wait_lock)
    except Exception as e:
        print(f"Warning: could not read mutex.wait_lock at {mutex_addr:#x}: {e}")
        wait_lock_val = -1

    try:
        count_val = mutex.count.counter
        if count_val == 1:
            locked = "Unlocked"
        elif count_val == 0:
            locked = "Locked (no waiters)"
        elif count_val <= -1:
            locked = "Locked (with waiters)"
        else:
            locked = f"Unknown (count={count_val})"
    except Exception as e:
        print(f"Warning: could not read mutex.count at {mutex_addr:#x}: {e}")
        count_val = None
        locked = "Unknown"

    try:
        wait_list_next = f"{int(mutex.wait_list.next):#x}"
        wait_list_prev = f"{int(mutex.wait_list.prev):#x}"
        wait_list_empty = int(mutex.wait_list.next) == int(mutex.wait_list.prev)
    except Exception as e:
        print(f"Warning: could not read mutex.wait_list at {mutex_addr:#x}: {e}")
        wait_list_next = "0x0"
        wait_list_prev = "0x0"
        wait_list_empty = True

    mutex_info = {
        "address":         f"{mutex_addr:#x}",
        "layout":          "rhel7",
        "owner":           get_owner_info(owner_address),
        "flags":           ["NONE"],
        "flags_raw":       flags_raw,
        "count_val":       count_val,
        "wait_lock_val":   wait_lock_val,
        "wait_list_next":  wait_list_next,
        "wait_list_prev":  wait_list_prev,
        "wait_list_empty": wait_list_empty,
        "locked":          locked,
    }

    if list_waiters:
        waiters = get_waiters(mutex)
        mutex_info["waiters"] = waiters
        if count_val is not None and count_val <= -1:
            mutex_info["locked"] = f"Locked (with ~{len(waiters)} waiter(s))"

    return mutex_info


def get_mutex_info(mutex_addr, list_waiters):
    """Read and decode a struct mutex from the vmcore."""
    layout = _init_mutex_layout()

    try:
        mutex = readSU("struct mutex", mutex_addr)
    except Exception as e:
        print(f"Error accessing mutex at {mutex_addr:#x}: {e}")
        return None

    if layout == "rt":
        return _get_mutex_info_rt(mutex, mutex_addr, list_waiters)
    if layout == "rhel7":
        return _get_mutex_info_rhel7(mutex, mutex_addr, list_waiters)
    return _get_mutex_info_standard(mutex, mutex_addr, list_waiters, layout)


def analyze_mutex(mutex_info, verbose=False):
    """Print a human-readable analysis of a decoded mutex."""
    if not mutex_info:
        print("No valid mutex information found.")
        return

    layout = mutex_info.get("layout", "standard")

    print("\n=== Mutex Analysis ===")
    print(f"Address:        {mutex_info['address']}")
    if layout == "rt":
        print("Layout:         PREEMPT_RT (rt_mutex_base)")
    print(f"Owner:          {mutex_info['owner']}")
    print(f"Flags:          {', '.join(mutex_info['flags'])}")
    print(f"Status:         {mutex_info['locked']}")
    if mutex_info['count_val'] is not None:
        print(f"Count Val:      {mutex_info['count_val']} (RHEL7 atomic count)")
    print(f"Wait Lock Val:  {mutex_info['wait_lock_val']}")
    if layout == "rt":
        print(f"Waiters Tree:   rb_root.rb_node = {mutex_info['wait_list_next']}")
    elif layout == "first_waiter":
        print(f"First Waiter:   {mutex_info['wait_list_next']}")
    else:
        print(f"Wait List Next: {mutex_info['wait_list_next']}")
        print(f"Wait List Prev: {mutex_info['wait_list_prev']}")

    if verbose:
        print("\nVerbose Explanation:")
        if layout == "rt":
            print("  PREEMPT_RT mutexes embed struct rt_mutex_base (rtmutex).")
            print("  wait_lock protects the rt_mutex waiters rbtree.")
            print("  owner is a task_struct * with bit 0 used as HAS_WAITERS.")
            print(f"\n  Flag bits (raw: {mutex_info['flags_raw']:#x}):")
            print(f"    bit 0 (HAS_WAITERS) = "
                  f"{int(bool(mutex_info['flags_raw'] & RT_MUTEX_HAS_WAITERS))}"
                  "  tasks are waiting on this mutex")
        else:
            print("  wait_lock is a qspinlock protecting the wait_list.")
            print("  val == 0 : unlocked (no one holds wait_lock)")
            print("  val != 0 : locked   (a thread is modifying the wait_list)")
            print(f"\n  Flag bits (raw: {mutex_info['flags_raw']:#x}):")
            print(f"    bit 0 (WAITERS) = "
                  f"{int(bool(mutex_info['flags_raw'] & MUTEX_FLAG_WAITERS))}"
                  "  unlock must issue a wakeup")
            print(f"    bit 1 (HANDOFF) = "
                  f"{int(bool(mutex_info['flags_raw'] & MUTEX_FLAG_HANDOFF))}"
                  "  unlock must hand lock directly to top waiter")
            print(f"    bit 2 (PICKUP)  = "
                  f"{int(bool(mutex_info['flags_raw'] & MUTEX_FLAG_PICKUP))}"
                  "  handoff done, top waiter must pick up the lock")

    list_empty = mutex_info.get("wait_list_empty")
    if list_empty is None:
        next_addr = int(mutex_info['wait_list_next'], 16)
        prev_addr = int(mutex_info['wait_list_prev'], 16)
        list_empty = (next_addr == prev_addr)

    if layout == "rt":
        if mutex_info['flags_raw'] & RT_MUTEX_HAS_WAITERS and list_empty:
            print("⚠️  HAS_WAITERS flag is set but waiters tree appears empty — "
                  "possible transient state.")
    else:
        if mutex_info['flags_raw'] & MUTEX_FLAG_WAITERS and list_empty:
            print("⚠️  WAITERS flag is set but wait_list appears empty — "
                  "possible transient state.")
        if (mutex_info['flags_raw'] & MUTEX_FLAG_HANDOFF
                and mutex_info['flags_raw'] & MUTEX_FLAG_PICKUP):
            print("⚠️  Both HANDOFF and PICKUP flags set simultaneously — "
                  "unexpected state.")

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
