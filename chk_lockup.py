"""
chk_lockup.py — Soft and hard lockup detector for crash/pykdump.

Usage:
    crash> chk_lockup -s          # soft lockup only
    crash> chk_lockup -H          # hard lockup only
    crash> chk_lockup -s -H       # both

Compatibility: RHEL 7 (kernel 3.10) through RHEL 10 (kernel 6.x+).

Timestamp units note:
    watchdog_touch_ts and watchdog_report_ts are written by get_timestamp(),
    which is defined as:  running_clock() >> 30  (~= ns / 1e9 ~= seconds).
    rq->clock is in nanoseconds, so rq_time_sec = rq->clock / 1e9.
    Both sides are therefore in approximate seconds and are directly comparable.

RHEL version matrix:
    RHEL 7  (el7, ~3.10): watchdog_enabled is a plain int (0/1), not a bitmask.
                           watchdog_report_ts does NOT exist.
                           watchdog_touch_ts == 0 means "touch pending" (reset
                           by touch_softlockup_watchdog; hrtimer updates on next
                           tick). Also 0 before the watchdog has ever run.
    RHEL 8  (el8, ~4.18): watchdog_enabled is a bitmask (0x01=hard, 0x02=soft).
                           watchdog_report_ts does NOT exist.
                           Same touch_ts == 0 semantics as RHEL 7.
    RHEL 9+ (el9+, ~5.14+): watchdog_enabled bitmask.
                           watchdog_report_ts EXISTS, but is a *reporting
                           suppression flag* only: touch_softlockup_watchdog()
                           writes ULONG_MAX here but does NOT reset touch_ts.
                           The hrtimer still writes touch_ts on every tick,
                           making touch_ts the correct elapsed-time clock on
                           all versions.
"""

import argparse
import re
from pykdump.API import *
from LinuxDump import percpu


# ---------------------------------------------------------------------------
# Idle call-stack symbols -- any of these in a CPU's bt output means the CPU
# was in the idle path when the NMI/crash occurred.  The watchdog timestamp
# going stale during idle is intentional and must not be flagged.
# ---------------------------------------------------------------------------
_IDLE_STACK_RE = re.compile(
    r"\b(do_idle|cpu_idle|cpu_startup_entry|cpuidle_enter|cpuidle_enter_state|"
    r"cpuidle_idle_call|intel_idle|acpi_idle_enter|"
    r"hlt_play_dead|mwait_play_dead|native_safe_halt|arch_cpu_idle)\b"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def if_bit_clear(rflags_str: str) -> bool:
    """Return True if the Interrupt Flag (bit 9) is clear; False if parsing fails."""
    try:
        return (int(rflags_str, 16) & 0x200) == 0
    except Exception:
        return False


def _safe_read_symbol(name):
    """Read a global symbol, returning None on any failure."""
    try:
        return readSymbol(name)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ANSI colour helpers


# ---------------------------------------------------------------------------
# RHEL version detection
# ---------------------------------------------------------------------------

def get_rhel_version():
    """
    Determine the major RHEL version from the kernel release string.

    Handles el7, el8, el9, el10, el10_1, etc.
    Returns an int (e.g. 7, 8, 9, 10).  Defaults to 8 if unparseable.
    """
    sys_output = exec_crash_command("sys")
    kernel_version = "Unknown"
    rhel_version = 8  # safe default

    el_re = re.compile(r"\.el(\d+)(?:[._]|$)")

    for line in sys_output.splitlines():
        if "RELEASE" in line:
            kernel_version = line.split()[-1]
            m = el_re.search(kernel_version)
            if m:
                try:
                    rhel_version = int(m.group(1))
                except ValueError:
                    pass

    print(f"Detected RHEL Version: {rhel_version} (Kernel: {kernel_version})")
    return rhel_version


# ---------------------------------------------------------------------------
# watchdog_enabled interpretation
# ---------------------------------------------------------------------------

def _is_soft_watchdog_enabled(rhel_version: int) -> bool:
    """
    Return True if the soft watchdog is enabled.

    RHEL 7 (3.10): watchdog_enabled is a plain int -- 1 means both enabled.
    RHEL 8+: watchdog_enabled is a bitmask; bit 1 (0x02) = soft watchdog.

    Defaults to True (permissive) when the symbol is absent.
    """
    val = _safe_read_symbol("watchdog_enabled")
    if val is None:
        return True
    if rhel_version <= 7:
        return val != 0
    return (val & 0x02) != 0


def _is_hard_watchdog_enabled(rhel_version: int) -> bool:
    """
    Return True if the hard watchdog is enabled.

    RHEL 7: watchdog_enabled plain int -- 1 means both enabled.
    RHEL 8+: watchdog_enabled bitmask; bit 0 (0x01) = hard watchdog.

    Defaults to True when symbol is absent.
    """
    val = _safe_read_symbol("watchdog_enabled")
    if val is None:
        return True
    if rhel_version <= 7:
        return val != 0
    return (val & 0x01) != 0


# ---------------------------------------------------------------------------
# bt -a parser  (one call, shared by both detectors)
# ---------------------------------------------------------------------------

def parse_bt_all():
    """
    Parse 'bt -a' once and return a dict keyed by CPU number.

    Each value is a dict:
        rflags   : hex string or 'N/A'
        cs       : hex string or 'N/A'
        comm     : task name string or 'Unknown'
        is_idle  : bool -- True if swapper task OR idle symbols in call stack
        bt_lines : list of raw backtrace lines for this CPU (for later printing)
    """
    out = exec_crash_command("bt -a")
    lines = out.splitlines()
    result = {}
    i = 0

    while i < len(lines):
        m = re.search(r"\bCPU:\s*(\d+)\b", lines[i])
        if not m:
            i += 1
            continue

        cpu = int(m.group(1))

        # COMMAND lives on the same CPU header line.
        mco = re.search(r'\bCOM(?:M|MAND):\s*"([^"]+)"', lines[i])
        comm = mco.group(1) if mco else "Unknown"

        rflags = "N/A"
        cs = "N/A"
        idle_in_stack = False
        bt_lines = [lines[i]]
        i += 1

        while i < len(lines) and not re.search(r"\bCPU:\s*\d+\b", lines[i]):
            line = lines[i]
            bt_lines.append(line)
            if rflags == "N/A":
                mrf = re.search(r"\bRFLAGS:\s*([0-9a-fA-F]+)\b", line)
                if mrf:
                    rflags = mrf.group(1)
            if cs == "N/A":
                mcs = re.search(r"\bCS:\s*([0-9a-fA-F]{4})\b", line)
                if mcs:
                    cs = mcs.group(1)
            # Fallback: some crash versions print COMMAND in the body.
            if comm == "Unknown":
                mco2 = re.search(r'\bCOM(?:M|MAND):\s*"([^"]+)"', line)
                if mco2:
                    comm = mco2.group(1)
            if not idle_in_stack and _IDLE_STACK_RE.search(line):
                idle_in_stack = True
            i += 1

        is_idle = comm.startswith("swapper") or idle_in_stack

        result[cpu] = {
            "rflags":   rflags,
            "cs":       cs,
            "comm":     comm,
            "is_idle":  is_idle,
            "bt_lines": bt_lines,
        }

    return result


# ---------------------------------------------------------------------------
# Soft lockup detection
# ---------------------------------------------------------------------------

def _get_softlockup_timestamps(rhel_version):
    """
    Read all per-CPU watchdog timestamps and the soft lockup threshold.

    Returns (rq_time_sec, touch_ts, report_ts, softlockup_thresh) or None on error.

    rq_time_sec  : list of float (rq->clock converted to seconds)
    touch_ts     : list of int   (watchdog_touch_ts, in ~seconds)
    report_ts    : list of int   (watchdog_report_ts, in ~seconds) or None
    softlockup_thresh : float    (seconds)

    Timestamp semantics by RHEL version:
        ALL versions: watchdog_touch_ts is written by the watchdog hrtimer on
                  every tick. It is the correct clock for elapsed-time on all
                  versions.  elapsed = rq_time_sec[cpu] - touch_ts[cpu].

        RHEL 7/8: touch_softlockup_watchdog() resets touch_ts to 0 as a
                  "please reset on next hrtimer tick" signal.  touch_ts == 0
                  means recently touched -- not a lockup.

        RHEL 9+:  touch_softlockup_watchdog() instead writes ULONG_MAX to
                  watchdog_report_ts only.  touch_ts is NOT reset -- it keeps
                  its hrtimer-tick value.  watchdog_report_ts == ULONG_MAX
                  means the kernel will suppress its own warning this tick
                  (because a reschedule occurred), but the elapsed time from
                  touch_ts is still valid and must be checked independently.
    """
    required = ["runqueues", "watchdog_thresh", "watchdog_touch_ts"]
    for sym in required:
        if not symbol_exists(sym):
            print(f"Warning: Required symbol '{sym}' is missing.")
            return None

    try:
        runqueue_addrs = percpu.get_cpu_var("runqueues")
        rq_clock       = [readSU("struct rq", addr).clock for addr in runqueue_addrs]
        rq_time_sec    = [c / 1e9 for c in rq_clock]

        watchdog_thresh   = readSymbol("watchdog_thresh")
        softlockup_thresh = watchdog_thresh * 2

        touch_ts_addrs = percpu.get_cpu_var("watchdog_touch_ts")
        touch_ts       = [readULong(addr) for addr in touch_ts_addrs]

        report_ts = None
        if rhel_version >= 9 and symbol_exists("watchdog_report_ts"):
            report_ts_addrs = percpu.get_cpu_var("watchdog_report_ts")
            report_ts       = [readULong(addr) for addr in report_ts_addrs]

        return rq_time_sec, touch_ts, report_ts, float(softlockup_thresh)

    except Exception as e:
        print(f"Error reading softlockup values: {e}")
        return None


def detect_soft_lockup(rhel_version, bt_map, verbose=False):
    """Detect soft lockups using per-CPU rq->clock and watchdog timestamps."""
    print(f"\n=== Soft Lockup Check (RHEL {rhel_version}) ===\n")

    if not _is_soft_watchdog_enabled(rhel_version):
        print("Soft watchdog is disabled -- skipping.")
        return

    data = _get_softlockup_timestamps(rhel_version)
    if data is None:
        print("Failed to read required values. Exiting.")
        return

    rq_time, touch_ts, report_ts, thresh = data
    ncpus   = len(rq_time)
    max_now = max(rq_time)
    has_report_ts = report_ts is not None

    print(f"  Soft lockup threshold : {thresh:.0f} seconds")
    print(f"  Timestamp source      : watchdog_touch_ts" +
          (" + watchdog_report_ts (RHEL 9+)" if has_report_ts else " (RHEL 7/8)"))
    print(f"  Max rq->clock         : {max_now:.2f} sec")
    print()

    # Plain ASCII status keeps column alignment intact regardless of terminal.
    HDR = f"{'CPU':<5} {'rq_clk(s)':>10} {'behind(s)':>10} {'elapsed(s)':>11} {'RFLAGS':>18} {'CS':>6}  {'Task':<20} Status"
    print(HDR)
    print("-" * len(HDR))

    locked_cpus = []

    ULONG_MAX = (1 << 64) - 1

    for cpu in range(ncpus):
        delta = max_now - rq_time[cpu]

        if cpu not in bt_map:
            print(f"{cpu:<5} {'N/A':>10} {'N/A':>10} {'N/A':>11} {'N/A':>18} {'N/A':>6}  {'N/A':<20} ⚠️  WARN: not in bt -a")
            continue

        info    = bt_map[cpu]
        rflags  = info["rflags"]
        cs      = info["cs"]
        comm    = info["comm"]
        is_idle = info["is_idle"]

        # Skip idle CPUs: the watchdog is intentionally not touched during
        # intel_idle/cpuidle, so a stale timestamp is expected and normal.
        if is_idle:
            idle_reason = "swapper" if comm.startswith("swapper") else "idle stack"
            print(f"{cpu:<5} {rq_time[cpu]:>10.2f} {delta:>10.2f} {'--':>11} {rflags:>18} {cs:>6}  {comm:<20} Idle ({idle_reason})")
            continue

        # --- Elapsed time calculation ---
        # watchdog_touch_ts is written by the watchdog hrtimer on every tick
        # on ALL RHEL versions. It is the correct clock for measuring how long
        # the CPU has gone without the watchdog firing.
        #
        # RHEL 7/8: touch_ts == 0 means touch_softlockup_watchdog() was called
        #           (i.e. the kernel requested a reset on the next hrtimer tick).
        #           This is a "recently touched" signal -- not a lockup.
        #
        # RHEL 9+:  touch_ts is purely the hrtimer-tick timestamp.
        #           touch_softlockup_watchdog() instead writes ULONG_MAX to
        #           watchdog_report_ts to suppress the *report*, but does NOT
        #           reset touch_ts. So elapsed time from touch_ts is still valid
        #           and must still be checked -- the suppression only means the
        #           kernel wouldn't have printed a warning this particular tick.
        tts = touch_ts[cpu]

        if not has_report_ts:
            # RHEL 7/8 path.
            # touch_ts == 0 has two distinct meanings:
            #   (a) touch_softlockup_watchdog() was called -- "touch pending",
            #       hrtimer will update the timestamp on its next tick. Not a lockup.
            #   (b) The watchdog hrtimer has never run on this CPU (e.g. CPU came
            #       online after boot, or watchdog was just enabled). Also not a lockup.
            # Both are handled the same way: skip the elapsed check, infer only from
            # scheduler lag if it is large enough to be unambiguous.
            if tts == 0:
                if delta > thresh:
                    elapsed = delta
                    print(f"{cpu:<5} {rq_time[cpu]:>10.2f} {delta:>10.2f} {elapsed:>11.2f} {rflags:>18} {cs:>6}  {comm:<20} ⚠️  INFERRED SOFT LOCKUP (touch_ts=0)")
                    locked_cpus.append(cpu)
                else:
                    print(f"{cpu:<5} {rq_time[cpu]:>10.2f} {delta:>10.2f} {'--':>11} {rflags:>18} {cs:>6}  {comm:<20} OK (touch_ts=0, watchdog not yet run or touch pending)")
                continue
            elapsed = rq_time[cpu] - tts
        else:
            # RHEL 9+ path: touch_ts is written by the hrtimer on every tick.
            # It should always be a real timestamp for any CPU that has been
            # running, but guard against 0 in case the watchdog never started
            # on this CPU (e.g. hotplugged CPU, or watchdog enabled mid-run).
            if tts == 0:
                print(f"{cpu:<5} {rq_time[cpu]:>10.2f} {delta:>10.2f} {'--':>11} {rflags:>18} {cs:>6}  {comm:<20} ⚠️  WARN (touch_ts=0, watchdog never ran on this CPU)")
                continue
            elapsed = rq_time[cpu] - tts
            # Check whether reporting was suppressed by a recent reschedule.
            report_suppressed = (report_ts[cpu] == ULONG_MAX)

        if elapsed > thresh:
            rflags_suspicious = if_bit_clear(rflags)
            cs_kernel         = cs == "0010"
            irq_note = " [IRQ-off+kernel]" if (rflags_suspicious and cs_kernel) else ""
            if has_report_ts and report_suppressed:
                # Elapsed exceeds threshold but a reschedule suppressed the
                # kernel's own report.  Still flag it -- the CPU was stuck
                # even if the kernel hadn't printed a warning yet.
                status = f"⚠️  SOFT LOCKUP (report suppressed by reschedule){irq_note}"
            else:
                status = f"⚠️  SOFT LOCKUP{irq_note}"
            print(f"{cpu:<5} {rq_time[cpu]:>10.2f} {delta:>10.2f} {elapsed:>11.2f} {rflags:>18} {cs:>6}  {comm:<20} {status}")
            locked_cpus.append(cpu)
        else:
            if has_report_ts and report_suppressed:
                status = "OK (reschedule reset report timer)"
            else:
                status = "OK"
            print(f"{cpu:<5} {rq_time[cpu]:>10.2f} {delta:>10.2f} {elapsed:>11.2f} {rflags:>18} {cs:>6}  {comm:<20} {status}")

    # Summary
    print()
    if locked_cpus:
        print(f"⚠️  Soft lockup detected on CPU(s): {', '.join(map(str, locked_cpus))}")
        if verbose:
            for cpu in locked_cpus:
                print(f"\n--- bt -c {cpu} " + "-" * 60)
                print(exec_crash_command(f"bt -c {cpu}"))
        else:
            print("    (run with -v to show backtraces for affected CPUs)")
    else:
        print("✅ No soft lockup detected.")


# ---------------------------------------------------------------------------
# Hard lockup detection
# ---------------------------------------------------------------------------

def _get_hrtimer_values():
    """
    Fetch hrtimer_interrupts and hrtimer_interrupts_saved for each CPU.
    Returns (interrupts, saved) or (None, None) on failure.
    """
    for sym in ("hrtimer_interrupts", "hrtimer_interrupts_saved"):
        if not symbol_exists(sym):
            print(f"Warning: Required symbol '{sym}' is missing.")
            return None, None
    try:
        intr  = [readULong(a) for a in percpu.get_cpu_var("hrtimer_interrupts")]
        saved = [readULong(a) for a in percpu.get_cpu_var("hrtimer_interrupts_saved")]
        return intr, saved
    except Exception as e:
        print(f"Error reading hrtimer values: {e}")
        return None, None


def _hard_lockup_verdict(interrupts, saved, rflags, cs, hard_wd_on):
    """
    Classify a single CPU's hard lockup state.

    The kernel's NMI watchdog works as follows:
      - A per-CPU hrtimer fires every watchdog_thresh seconds and increments
        hrtimer_interrupts.
      - On each NMI, is_hardlockup() compares hrtimer_interrupts against
        hrtimer_interrupts_saved.  If they are equal, the hrtimer has not
        fired since the last NMI check -- the CPU is hard-locked.
      - hrtimer_interrupts_saved is then updated to hrtimer_interrupts.

    In a vmcore, we see a snapshot.  The counters being equal is the primary
    lockup signal, but we cross-check with RFLAGS and CS to assess confidence:

      IF=0 (bit 9 clear), CS=0010 (kernel):
          Classic hard lockup -- CPU stuck in kernel with IRQs disabled.
          Verdict: CONFIRMED.

      IF=1 (bit 9 set), CS=0010 (kernel):
          CPU was in kernel with IRQs nominally enabled, but the hrtimer still
          did not fire.  This can happen when spinning inside an IRQ handler
          that re-enables interrupts, or in an sti+hlt race.
          The equal counters are still a valid hard lockup signal.
          Verdict: CONFIRMED (IRQs-on variant -- note this explicitly).

      CS != 0010 (user-space):
          Counters equal but CPU was in user space.  The NMI watchdog should
          still fire even in user space on modern kernels, so this is possible
          but less certain -- could be a sampling artifact.
          Verdict: SUSPECT.

      Both counters are 0:
          The watchdog hrtimer never ran on this CPU (e.g. CPU came online
          late, or watchdog was never started).  Not a lockup.
          Verdict: WARN (never ran).

      Counters differ by 1:
          Normal -- exactly one hrtimer tick fired between the save and the
          NMI that captured the vmcore.
          Verdict: OK  (diff noted for transparency).

      Counters differ by >1:
          Clearly normal -- multiple ticks fired.
          Verdict: OK.

    Returns (verdict_str, category) where category is one of:
        'confirmed', 'suspect', 'warn', 'ok'
    """
    irqs_off  = if_bit_clear(rflags)
    kernel_cs = (cs == "0010")
    equal     = (interrupts == saved)
    both_zero = (interrupts == 0 and saved == 0)
    diff      = abs(interrupts - saved)

    if both_zero:
        return "WARN: watchdog never ran on this CPU", "warn"

    if not equal:
        note = f"(diff={diff})" if diff == 1 else f"(diff={diff})"
        return f"OK {note}", "ok"

    # Counters are equal -- potential hard lockup.
    if not hard_wd_on:
        return "❓ INCONCLUSIVE (hard watchdog disabled)", "suspect"

    if not kernel_cs:
        return "❓ SUSPECT (equal counters, user-space CS)", "suspect"

    # Kernel CS + equal counters = hard lockup.
    if irqs_off:
        return "⚠️  CONFIRMED (IRQs off, kernel)", "confirmed"
    else:
        return "⚠️  CONFIRMED (IRQs ON in kernel -- spinloop or IRQ-handler hang)", "confirmed"


def detect_hard_lockup(rhel_version, bt_map, verbose=False):
    """Detect hard lockups and classify them as CONFIRMED / SUSPECT / WARN / OK."""
    print(f"\n=== Hard Lockup Check (RHEL {rhel_version}) ===\n")

    hard_wd_on = _is_hard_watchdog_enabled(rhel_version)
    if not hard_wd_on:
        print("Hard watchdog appears disabled -- results may be inconclusive.\n")

    interrupts, saved = _get_hrtimer_values()
    if interrupts is None:
        print("Failed to read hrtimer values. Exiting.")
        return

    HDR = f"{'CPU':<5} {'hrtimer_intr':<16} {'hrtimer_saved':<16} {'RFLAGS':<18} {'CS':<6}  {'Task':<20} Verdict"
    print(HDR)
    print("-" * len(HDR))

    suspects, confirmed = [], []

    for cpu in range(len(interrupts)):
        info   = bt_map.get(cpu, {})
        rflags = info.get("rflags", "N/A")
        cs     = info.get("cs",     "N/A")
        comm   = info.get("comm",   "Unknown")

        verdict, category = _hard_lockup_verdict(
            interrupts[cpu], saved[cpu], rflags, cs, hard_wd_on
        )

        if category == "confirmed":
            confirmed.append(cpu)
        elif category == "suspect":
            suspects.append(cpu)

        row = f"{cpu:<5} {interrupts[cpu]:<16} {saved[cpu]:<16} {rflags:<18} {cs:<6}  {comm:<20} {verdict}"
        if category == "confirmed":
            print(row)
        elif category in ("suspect", "warn"):
            print(row)
        else:
            print(row)

    # Summary
    print()
    if confirmed:
        print(f"⚠️  Hard lockup CONFIRMED on CPU(s) : {', '.join(map(str, confirmed))}")
    if suspects:
        print(f"❓ Hard lockup SUSPECT on CPU(s)   : {', '.join(map(str, suspects))}")
    if not confirmed and not suspects:
        print("✅ No hard lockup indicated.")

    if verbose:
        for cpu in confirmed + suspects:
            print(f"\n--- bt -c {cpu} " + "-" * 60)
            print(exec_crash_command(f"bt -c {cpu}"))
    elif confirmed or suspects:
        print("    (run with -v to show backtraces for affected CPUs)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Detect soft and hard lockups in a vmcore (RHEL 7+)"
    )
    parser.add_argument("-s", "--soft-lockup", action="store_true", help="Detect soft lockup")
    parser.add_argument("-H", "--hard-lockup",  action="store_true", help="Detect hard lockup")
    parser.add_argument("-v", "--verbose",      action="store_true",
                        help="Print bt -c <N> backtraces for all affected CPUs")
    args = parser.parse_args()

    if not args.soft_lockup and not args.hard_lockup:
        parser.print_help()
    else:
        rhel_version = get_rhel_version()
        # Parse bt -a once and share across both detectors.
        print("\nParsing CPU backtraces (bt -a)...")
        bt_map = parse_bt_all()
        print(f"Found {len(bt_map)} CPU(s) in bt output.\n")

        if args.soft_lockup:
            detect_soft_lockup(rhel_version, bt_map, verbose=args.verbose)

        if args.hard_lockup:
            detect_hard_lockup(rhel_version, bt_map, verbose=args.verbose)
