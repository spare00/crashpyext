import argparse
from pykdump.API import *
from LinuxDump import percpu

def get_rhel_version():
    """Determines the major RHEL version from the kernel release."""
    sys_output = exec_crash_command("sys")
    kernel_version = "Unknown"
    rhel_version = 8  # Default to RHEL 8

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

def get_softlockup_values(rhel_version):
    """Fetches per-CPU rq->clock and relevant timestamps to check for soft lockups."""

    if not symbol_exists("runqueues") or not symbol_exists("watchdog_thresh") or not symbol_exists("watchdog_enabled"):
        print("⚠️ Warning: Required symbols are missing.")
        return None, None, None, None, None

    try:
        runqueue_addrs = percpu.get_cpu_var("runqueues")
        rq_clock = [readSU("struct rq", addr).clock for addr in runqueue_addrs]
        rq_time_sec = [int(clock_value / 1e9) for clock_value in rq_clock]

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
    """Detects soft lockups in a vmcore."""
    rhel_version = get_rhel_version()
    print(f"🔍 Checking for soft lockups in vmcore (RHEL {rhel_version})...\n")

    rq_time, touch_ts, period_ts, softlockup_thresh, is_watchdog_enabled = get_softlockup_values(rhel_version)
    if None in (rq_time, touch_ts, softlockup_thresh):
        print("❌ Failed to read required values. Exiting.")
        return

    if not is_watchdog_enabled:
        print("⚠️ Soft watchdog is disabled.")
        return

    print(f"Soft Lockup Threshold: {softlockup_thresh} seconds\n")
    if rhel_version >= 9:
        print(f"{'CPU':<5} {'now (sec)':<15} {'touch_ts':<20} {'period_ts + ' + str(softlockup_thresh):<20} {'Difference':<15} {'Status'}")
    else:
        print(f"{'CPU':<5} {'now (sec)':<20} {'touch_ts + ' + str(softlockup_thresh):<20} {'Difference':<15} {'Status'}")
    print("=" * 100)

    locked_cpus = []
    ULONG_MAX = 18446744073709551615

    for cpu in range(len(rq_time)):
        if rhel_version >= 9:
            if period_ts[cpu] == ULONG_MAX:
                status = "Ignored"
            else:
                diff = rq_time[cpu] - (period_ts[cpu] + softlockup_thresh)
                status = "✅ Normal" if rq_time[cpu] <= period_ts[cpu] + softlockup_thresh else "⚠️ Soft Lockup"
                if status == "⚠️ Soft Lockup":
                    locked_cpus.append(cpu)
            print(f"{cpu:<5} {rq_time[cpu]:<15} {touch_ts[cpu]:<20} {period_ts[cpu] + softlockup_thresh if period_ts[cpu] != ULONG_MAX else 'N/A':<20} {'-' if period_ts[cpu] == ULONG_MAX else diff:<15} {status}")
        else:
            if touch_ts[cpu] == 0:
                status = "Ignored"
            else:
                diff = rq_time[cpu] - (touch_ts[cpu] + softlockup_thresh)
                status = "✅ Normal" if rq_time[cpu] <= touch_ts[cpu] + softlockup_thresh else "⚠️ Soft Lockup"
                if status == "⚠️ Soft Lockup":
                    locked_cpus.append(cpu)
            print(f"{cpu:<5} {rq_time[cpu]:<20} {touch_ts[cpu] + softlockup_thresh if touch_ts[cpu] != 0 else 'N/A':<20} {'-' if touch_ts[cpu] == 0 else diff:<15} {status}")

    print("\n🔍 Analysis Complete.")
    if locked_cpus:
        print(f"⚠️ Soft lockup detected on CPUs: {', '.join(map(str, locked_cpus))}")
    else:
        print("✅ No soft lockup detected.")

def get_hrtimer_values():
    """Fetches hrtimer_interrupts and hrtimer_interrupts_saved for each CPU correctly."""
    if not symbol_exists("hrtimer_interrupts") or not symbol_exists("hrtimer_interrupts_saved"):
        print("⚠️ Warning: Required symbols 'hrtimer_interrupts' or 'hrtimer_interrupts_saved' are missing.")
        return None, None

    try:
        # Get the per-CPU addresses of hrtimer_interrupts and hrtimer_interrupts_saved
        hrtimer_interrupts_addrs = percpu.get_cpu_var("hrtimer_interrupts")
        hrtimer_interrupts_saved_addrs = percpu.get_cpu_var("hrtimer_interrupts_saved")

        hrtimer_interrupts = [readULong(addr) for addr in hrtimer_interrupts_addrs]
        hrtimer_interrupts_saved = [readULong(addr) for addr in hrtimer_interrupts_saved_addrs]

        return hrtimer_interrupts, hrtimer_interrupts_saved

    except Exception as e:
        print(f"❌ Error: Failed to read hrtimer values: {e}")
        return None, None

def detect_hard_lockup():
    """Detects hard lockups in a vmcore by analyzing per-CPU hrtimer values."""
    print("🔍 Checking for hard lockups in vmcore...\n")

    interrupts, saved = get_hrtimer_values()
    if interrupts is None or saved is None:
        print("❌ Failed to read hrtimer values. Exiting.")
        return

    print(f"{'CPU':<5} {'hrtimer_interrupts':<20} {'hrtimer_interrupts_saved':<25} {'Status'}")
    print("=" * 65)

    locked_cpus = []
    for cpu in range(len(interrupts)):
        status = "✅ Normal" if interrupts[cpu] != saved[cpu] else "⚠️ Hard Lockup"
        print(f"{cpu:<5} {interrupts[cpu]:<20} {saved[cpu]:<25} {status}")

        if interrupts[cpu] == saved[cpu]:  # Hard lockup condition
            locked_cpus.append(cpu)

    print("\n🔍 Analysis Complete.")
    if locked_cpus:
        print(f"⚠️ Hard lockup detected on CPUs: {', '.join(map(str, locked_cpus))}")
    else:
        print("✅ No hard lockup detected in vmcore.")


# --- Main ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect soft and hard lockups")
    parser.add_argument("-s", "--soft-lockup", action="store_true", help="Detect soft lockup")
    parser.add_argument("-H", "--hard-lockup", action="store_true", help="Detect hard lockup")

    args = parser.parse_args()

    if args.soft_lockup:
        detect_soft_lockup()

    if args.hard_lockup:
        detect_hard_lockup()


