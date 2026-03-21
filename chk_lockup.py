import argparse
import re
from pykdump.API import *
from LinuxDump import percpu


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def if_bit_clear(rflags_str: str) -> bool:
    """Return True if the Interrupt Flag (bit 9) is clear; False if parsing fails."""
    try:
        return (int(rflags_str, 16) & 0x200) == 0
    except Exception:
        return False


def is_hard_watchdog_enabled() -> bool:
    """Best-effort read of watchdog_enabled hard-bit (0x01). Defaults to True if unknown."""
    try:
        if not symbol_exists("watchdog_enabled"):
            return True
        val = readSymbol("watchdog_enabled")
        return (val & 0x01) != 0
    except Exception:
        return True


# ---------------------------------------------------------------------------
# RHEL version detection
# ---------------------------------------------------------------------------

def get_rhel_version():
    """Determine the major RHEL version from the kernel release string (handles el10+)."""
    sys_output = exec_crash_command("sys")
    kernel_version = "Unknown"
    rhel_version = 8  # sensible default

    # Match patterns like: 6.12.0-55.28.1.el10_0.x86_64
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
# bt -a parsers
# ---------------------------------------------------------------------------

def get_cpu_rflags_cs_and_comm_via_bt():
    """
    Robustly parse 'bt -a' by CPU block.

    Returns a list of (cpu, rflags_hex|'N/A', cs_hex|'N/A', comm|'Unknown', is_idle).

    comm is extracted from the CPU header line (e.g. COMMAND: "swapper/0") first;
    body lines are also scanned as a fallback.

    is_idle is True when the task is a swapper/idle thread OR the call stack
    contains idle-path symbols (do_idle, cpu_startup_entry, intel_idle, etc.).
    This correctly handles NMI-interrupted idle CPUs where the watchdog timestamp
    is stale by design, not because of a real lockup.
    """
    # Symbols that unambiguously indicate a CPU is in the idle path.
    IDLE_STACK_SYMS = re.compile(
        r"\b(do_idle|cpu_startup_entry|cpuidle_enter|cpuidle_idle_call|intel_idle|"
        r"acpi_idle_enter|hlt_play_dead|mwait_play_dead|native_safe_halt)\b"
    )

    out = exec_crash_command("bt -a")
    lines = out.splitlines()
    cpu_info = []
    i = 0
    while i < len(lines):
        m = re.search(r"\bCPU:\s*(\d+)\b", lines[i])
        if not m:
            i += 1
            continue

        cpu = int(m.group(1))
        rflags = "N/A"
        cs = "N/A"

        # The COMMAND field lives on the same CPU header line.
        mco = re.search(r'\bCOM(?:M|MAND):\s*"([^"]+)"', lines[i])
        comm = mco.group(1) if mco else "Unknown"

        idle_in_stack = False
        i += 1

        while i < len(lines) and "CPU:" not in lines[i]:
            line = lines[i]
            if rflags == "N/A":
                mrf = re.search(r"\bRFLAGS:\s*([0-9a-fA-F]+)\b", line)
                if mrf:
                    rflags = mrf.group(1)
            if cs == "N/A":
                mcs = re.search(r"\bCS:\s*([0-9a-fA-F]{4})\b", line)
                if mcs:
                    cs = mcs.group(1)
            # Fallback: body may also carry COMM/COMMAND in some crash versions.
            if comm == "Unknown":
                mco2 = re.search(r'\bCOM(?:M|MAND):\s*"([^"]+)"', line)
                if mco2:
                    comm = mco2.group(1)
            if not idle_in_stack and IDLE_STACK_SYMS.search(line):
                idle_in_stack = True
            i += 1

        is_idle = comm.startswith("swapper") or idle_in_stack
        cpu_info.append((cpu, rflags, cs, comm, is_idle))
    return cpu_info


def get_cpu_rflags_cs_via_bt_robust():
    """
    Robustly parse 'bt -a' by CPU block (no task name).

    Returns a list of (cpu, rflags_hex|'N/A', cs_hex|'N/A').
    """
    out = exec_crash_command("bt -a")
    lines = out.splitlines()
    cpu_info = []
    i = 0
    while i < len(lines):
        m = re.search(r"\bCPU:\s*(\d+)\b", lines[i])
        if not m:
            i += 1
            continue
        cpu = int(m.group(1))
        rflags = "N/A"
        cs = "N/A"
        i += 1
        while i < len(lines) and "CPU:" not in lines[i]:
            if rflags == "N/A":
                mrf = re.search(r"\bRFLAGS:\s*([0-9a-fA-F]+)\b", lines[i])
                if mrf:
                    rflags = mrf.group(1)
            if cs == "N/A":
                mcs = re.search(r"\bCS:\s*([0-9a-fA-F]{4})\b", lines[i])
                if mcs:
                    cs = mcs.group(1)
            i += 1
        cpu_info.append((cpu, rflags, cs))
    return cpu_info


# ---------------------------------------------------------------------------
# Soft lockup detection
# ---------------------------------------------------------------------------

def get_softlockup_values(rhel_version):
    """Read per-CPU watchdog timestamps and threshold from kernel symbols."""
    if not symbol_exists("runqueues") or not symbol_exists("watchdog_thresh") or not symbol_exists("watchdog_enabled"):
        print("⚠️ Warning: Required symbols are missing.")
        return None, None, None, None, None

    try:
        runqueue_addrs = percpu.get_cpu_var("runqueues")
        rq_clock = [readSU("struct rq", addr).clock for addr in runqueue_addrs]
        rq_time_sec = [clock_value / 1e9 for clock_value in rq_clock]

        watchdog_thresh = readSymbol("watchdog_thresh")
        softlockup_thresh = watchdog_thresh * 2

        watchdog_enabled = readSymbol("watchdog_enabled")
        soft_watchdog_enabled = 0x02

        if rhel_version >= 9:
            if not symbol_exists("watchdog_report_ts") or not symbol_exists("watchdog_touch_ts"):
                print("⚠️ Warning: Required watchdog symbols are missing.")
                return None, None, None, None, None
            period_ts_addrs = percpu.get_cpu_var("watchdog_report_ts")
            period_ts = [readULong(addr) for addr in period_ts_addrs]
            touch_ts_addrs = percpu.get_cpu_var("watchdog_touch_ts")
            touch_ts = [readULong(addr) for addr in touch_ts_addrs]
            return rq_time_sec, touch_ts, period_ts, softlockup_thresh, watchdog_enabled & soft_watchdog_enabled
        else:
            if not symbol_exists("watchdog_touch_ts"):
                print("⚠️ Warning: watchdog_touch_ts symbol is missing.")
                return None, None, None, None, None
            watchdog_touch_ts_addrs = percpu.get_cpu_var("watchdog_touch_ts")
            watchdog_touch_ts = [readULong(addr) for addr in watchdog_touch_ts_addrs]
            return rq_time_sec, watchdog_touch_ts, None, softlockup_thresh, watchdog_enabled & soft_watchdog_enabled

    except Exception as e:
        print(f"❌ Error: {e}")
        return None, None, None, None, None


def detect_soft_lockup():
    """Detect soft lockups using per-CPU rq->clock and watchdog timestamps."""
    rhel_version = get_rhel_version()
    print(f"\n🔍 Checking for soft lockups in vmcore (RHEL {rhel_version})...")

    rq_time, touch_ts, period_ts, softlockup_thresh, is_watchdog_enabled = get_softlockup_values(rhel_version)
    cpu_info = get_cpu_rflags_cs_and_comm_via_bt()

    if None in (rq_time, touch_ts, softlockup_thresh):
        print("❌ Failed to read required values. Exiting.")
        return

    if not is_watchdog_enabled:
        print("⚠️ Soft watchdog is disabled.")
        return

    print(f"Soft Lockup Threshold: {softlockup_thresh} seconds\n")

    max_now = max(rq_time)
    print(f"⏱️  Max rq->clock across CPUs: {max_now:.2f} sec\n")

    header = f"{'CPU':<5} {'now (sec)':>10} {'behind(s)':>12} {'Since touch(s)':>16} {'RFLAGS':>18} {'CS':>8} {'Status':>16}"
    print(header)
    print("=" * len(header))

    locked_cpus = []

    for cpu in range(len(rq_time)):
        delta = max_now - rq_time[cpu]
        behind_by_str = f"{delta:>12.2f}"

        rflags = cs = task_comm = "N/A"
        is_idle = False
        for entry in cpu_info:
            if entry[0] == cpu:
                rflags, cs, task_comm, is_idle = entry[1], entry[2], entry[3], entry[4]
                break

        # Skip idle CPUs — the watchdog is intentionally not touched during
        # intel_idle / cpuidle, so a stale touch_ts is expected and normal.
        # We detect idle both by task name (swapper) and by call-stack symbols
        # so that NMI-interrupted idle CPUs are not falsely flagged.
        if is_idle:
            idle_reason = "swapper" if task_comm.startswith("swapper") else "idle stack"
            status = f"Idle ({idle_reason}) - Skip"
            elapsed_str = "-"
            line = f"{cpu:<5} {rq_time[cpu]:>10.2f} {'-':>12} {elapsed_str:>16} {rflags:>18} {cs:>8} {status:>20}"
            print(line)
            continue

        if touch_ts[cpu] == 0:
            # watchdog_touch_ts not valid — infer from scheduler lag
            if delta > softlockup_thresh:
                elapsed_str = f"\033[91m{delta:>16.2f}\033[0m"
                status = "⚠️ Inferred Soft Lockup"
                locked_cpus.append(cpu)
            else:
                elapsed_str = "-"
                status = "Ignored (no touch_ts)"
        else:
            elapsed = rq_time[cpu] - touch_ts[cpu]
            if elapsed > softlockup_thresh:
                elapsed_str = f"\033[91m{elapsed:>16.2f}\033[0m"
                status = "⚠️ Soft Lockup"
                locked_cpus.append(cpu)
            else:
                elapsed_str = f"{elapsed:>16.2f}"
                status = "✅ Normal"

        # Highlight CPUs that are locked with interrupts off in kernel mode
        rflags_suspicious = if_bit_clear(rflags)
        cs_suspicious = cs == "0010"
        highlight = status == "⚠️ Soft Lockup" and rflags_suspicious and cs_suspicious

        line = f"{cpu:<5} {rq_time[cpu]:>10.2f} {behind_by_str} {elapsed_str} {rflags:>18} {cs:>8} {status:>16}"
        if highlight:
            line = f"\033[91m{line}\033[0m"

        print(line)

    print("\n🔍 Analysis Complete.")
    if locked_cpus:
        print(f"⚠️ Soft lockup detected on CPUs: {', '.join(map(str, locked_cpus))}")
    else:
        print("✅ No soft lockup detected.")


# ---------------------------------------------------------------------------
# Hard lockup detection
# ---------------------------------------------------------------------------

def get_hrtimer_values():
    """Fetch hrtimer_interrupts and hrtimer_interrupts_saved for each CPU."""
    if not symbol_exists("hrtimer_interrupts") or not symbol_exists("hrtimer_interrupts_saved"):
        print("⚠️ Warning: Required symbols 'hrtimer_interrupts' or 'hrtimer_interrupts_saved' are missing.")
        return None, None

    try:
        hrtimer_interrupts_addrs = percpu.get_cpu_var("hrtimer_interrupts")
        hrtimer_interrupts_saved_addrs = percpu.get_cpu_var("hrtimer_interrupts_saved")

        hrtimer_interrupts = [readULong(addr) for addr in hrtimer_interrupts_addrs]
        hrtimer_interrupts_saved = [readULong(addr) for addr in hrtimer_interrupts_saved_addrs]

        return hrtimer_interrupts, hrtimer_interrupts_saved

    except Exception as e:
        print(f"❌ Error: Failed to read hrtimer values: {e}")
        return None, None


def detect_hard_lockup():
    """Detect hard lockups and classify them as CONFIRMED / SUSPECT / NORMAL."""
    print("\n🔍 Checking for hard lockups in vmcore...\n")

    hard_wd_on = is_hard_watchdog_enabled()
    if not hard_wd_on:
        print("⚠️ Hard watchdog appears disabled; equality may be inconclusive.\n")

    interrupts, saved = get_hrtimer_values()
    if interrupts is None or saved is None:
        print("❌ Failed to read hrtimer values. Exiting.")
        return

    cpu_info = get_cpu_rflags_cs_via_bt_robust()
    info_map = {c: (rf, cs) for c, rf, cs in cpu_info}

    print(f"{'CPU':<5} {'hrtimer_interrupts':<20} {'hrtimer_saved':<20} {'RFLAGS':<18} {'CS':<6} {'Verdict'}")
    print("=" * 98)

    suspects, confirmed = [], []
    for cpu in range(len(interrupts)):
        rflags, cs = info_map.get(cpu, ("N/A", "N/A"))
        equal = interrupts[cpu] == saved[cpu]
        kernel_cs = (cs == "0010")
        irqs_off = if_bit_clear(rflags)

        if equal:
            if kernel_cs:
                if hard_wd_on:
                    verdict = "⚠️ CONFIRMED hard lockup"
                    if not irqs_off:
                        verdict += " (IF=1)"
                    confirmed.append(cpu)
                else:
                    verdict = "❓ INCONCLUSIVE (watchdog disabled)"
                    suspects.append(cpu)
            else:
                verdict = "❓ SUSPECT (user CS)"
                suspects.append(cpu)
        else:
            verdict = "✅ Normal"

        print(f"{cpu:<5} {interrupts[cpu]:<20} {saved[cpu]:<20} {rflags:<18} {cs:<6} {verdict}")

    print("\n🔍 Analysis Complete.")
    if confirmed:
        print(f"⚠️ Hard lockup (CONFIRMED) on CPUs: {', '.join(map(str, confirmed))}")
    if suspects:
        print(f"❓ Hard lockup (SUSPECT/INCONCLUSIVE) on CPUs: {', '.join(map(str, suspects))}")
    if not confirmed and not suspects:
        print("✅ No hard lockup indicated.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect soft and hard lockups in a vmcore")
    parser.add_argument("-s", "--soft-lockup", action="store_true", help="Detect soft lockup")
    parser.add_argument("-H", "--hard-lockup", action="store_true", help="Detect hard lockup")

    args = parser.parse_args()

    if args.soft_lockup:
        detect_soft_lockup()

    if args.hard_lockup:
        detect_hard_lockup()
