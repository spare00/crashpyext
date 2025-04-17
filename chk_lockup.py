import argparse
import re
from pykdump.API import *
from LinuxDump import percpu

# Soft lockup detector starts 
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
    """Detects soft lockups in a vmcore."""
    rhel_version = get_rhel_version()

    print(f"\n🔍 Checking for soft lockups in vmcore (RHEL {rhel_version})...")

    rq_time, touch_ts, period_ts, softlockup_thresh, is_watchdog_enabled = get_softlockup_values(rhel_version)
    if None in (rq_time, touch_ts, softlockup_thresh):
        print("❌ Failed to read required values. Exiting.")
        return

    if not is_watchdog_enabled:
        print("⚠️ Soft watchdog is disabled.")
        return

    print(f"Soft Lockup Threshold: {softlockup_thresh} seconds\n")

    max_now = max(rq_time)
    print(f"⏱️  Max rq->clock across CPUs: {max_now:.2f} sec\n")

    if rhel_version >= 9:
        print(f"{'CPU':<5} {'now (sec)':<12} {'behind by (s)':>12} {'touch_ts':>15} {'period_ts + ' + str(softlockup_thresh):>15} {'Diff':>15}  {'Status'}")
    else:
        print(f"{'CPU':<5} {'now (sec)':<12} {'behind by (s)':>12} {'touch+%d' % softlockup_thresh:>15} {'Diff':>15}  {'Status'}")
    print("=" * 100)

    locked_cpus = []
    ULONG_MAX = 18446744073709551615

    for cpu in range(len(rq_time)):
        delta = max_now - rq_time[cpu]
        plain_delta = f"{delta:>10.2f}"
        #behind_by_str = f"\033[91m{plain_delta}\033[0m" if int(delta) > 0 else plain_delta
        if int(delta) > 0:
            # Dynamically pad based on uncolored string width
            width = 12
            pad = width - len(plain_delta)
            behind_by_str = " " * pad + f"\033[91m{plain_delta}\033[0m"
        else:
            behind_by_str = f"{plain_delta:>10}"

        if rhel_version >= 9:
            if period_ts[cpu] == ULONG_MAX:
                status = "Ignored"
                diff_str = "-"
                threshold_ts = "N/A"
            else:
                threshold_ts = period_ts[cpu] + softlockup_thresh
                diff = rq_time[cpu] - threshold_ts
                diff_str = f"{diff:.2f}"
                status = "✅ Normal" if diff <= 0 else "⚠️ Soft Lockup"
                if status == "⚠️ Soft Lockup":
                    locked_cpus.append(cpu)
            print(f"{cpu:<5} {rq_time[cpu]:<12.2f} {behind_by_str:>12} {str(touch_ts[cpu]):>15} {str(threshold_ts):>15} {diff_str:>15}  {status}")
        else:
            if touch_ts[cpu] == 0:
                status = "Ignored"
                diff_str = "-"
                threshold_ts = "N/A"
            else:
                threshold_ts = touch_ts[cpu] + softlockup_thresh
                diff = rq_time[cpu] - threshold_ts
                diff_str = f"{diff:.2f}"
                status = "✅ Normal" if diff <= 0 else "⚠️ Soft Lockup"
                if status == "⚠️ Soft Lockup":
                    locked_cpus.append(cpu)
            print(f"{cpu:<5} {rq_time[cpu]:<12.2f} {behind_by_str:>12} {str(threshold_ts):>15} {diff_str:>15}  {status}")

    print("\n🔍 Analysis Complete.")
    if locked_cpus:
        print(f"⚠️ Soft lockup detected on CPUs: {', '.join(map(str, locked_cpus))}")
    else:
        print("✅ No soft lockup detected.")

# Hard lockup detector starts
def get_hrtimer_values():
    """Fetches hrtimer_interrupts and hrtimer_interrupts_saved for each CPU correctly."""
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

def get_cpu_rflags_cs_via_bt():
    """Parses 'bt -a' to extract CPU, RFLAGS, and CS."""
    try:
        output = exec_crash_command("bt -a")
        lines = output.splitlines()

        # Extract lines of interest
        filtered = [line for line in lines if re.search(r"CPU:\s*\d+|RFLAGS|CS\s*:\s*[0-9a-fA-F]{4}", line)]

        # Group every 3 lines: CPU + RFLAGS + CS
        cpu_info = []
        i = 0
        while i < len(filtered):
            if "CPU:" in filtered[i]:
                cpu_line = filtered[i]
                rflags_line = filtered[i + 1] if (i + 1) < len(filtered) else ""
                cs_line = filtered[i + 2] if (i + 2) < len(filtered) else ""

                cpu_match = re.search(r"CPU:\s*(\d+)", cpu_line)
                rflags_match = re.search(r"RFLAGS:\s*([0-9a-fA-F]+)", rflags_line)
                cs_match = re.search(r"CS:\s*([0-9a-fA-F]+)", cs_line)

                cpu = int(cpu_match.group(1)) if cpu_match else -1
                rflags = rflags_match.group(1) if rflags_match else "N/A"
                cs = cs_match.group(1) if cs_match else "N/A"

                cpu_info.append((cpu, rflags, cs))
                i += 3
            else:
                i += 1

        return cpu_info

    except Exception as e:
        print(f"❌ Failed to parse bt -a output: {e}")
        return []

def get_rflags_and_cs_per_cpu():
    """Returns RFLAGS and CS for each CPU using task_regs()."""
    rflags_list = []
    cs_list = []

    for cpu in range(getCpuCount()):
        task = getTaskByCpu(cpu)
        if not task:
            rflags_list.append("N/A")
            cs_list.append("N/A")
            continue
        regs = task_regs(task)
        rflags = regs.get("rflags", "N/A")
        cs = regs.get("cs", "N/A")
        rflags_list.append(f"{rflags:016x}" if isinstance(rflags, int) else "N/A")
        cs_list.append(f"{cs:04x}" if isinstance(cs, int) else "N/A")

    return rflags_list, cs_list

def detect_hard_lockup():
    """Detects hard lockups in a vmcore by analyzing per-CPU hrtimer values."""
    print("🔍 Checking for hard lockups in vmcore...\n")

    interrupts, saved = get_hrtimer_values()
    cpu_info = get_cpu_rflags_cs_via_bt()

    if interrupts is None or saved is None:
        print("❌ Failed to read hrtimer values. Exiting.")
        return

    print(f"{'CPU':<5} {'hrtimer_interrupts':<20} {'hrtimer_saved':<20} {'RFLAGS':<18} {'CS':<6} {'Status'}")
    print("=" * 90)

    locked_cpus = []
    print(f"{'CPU':<5} {'hrtimer_interrupts':<20} {'hrtimer_saved':<20} {'RFLAGS':<18} {'CS':<6} {'Status'}")
    print("=" * 90)

    locked_cpus = []
    for cpu in range(len(interrupts)):
        rflags = cs = "N/A"
        for info in cpu_info:
            if info[0] == cpu:
                rflags, cs = info[1], info[2]
                break

        is_locked = interrupts[cpu] == saved[cpu]

        # Check: bit 9 of RFLAGS (Interrupt Flag) is not set (6th hex digit is not 2/X2)
        rflags_suspicious = False
        if rflags != "N/A" and len(rflags) >= 6:
            rflags_suspicious = rflags[-6] != '2'

        cs_suspicious = (cs == "0010")

        # Decide color
        should_highlight = is_locked and rflags_suspicious and cs_suspicious
        status = "⚠️ Hard Lockup" if is_locked else "✅ Normal"

        line = f"{cpu:<5} {interrupts[cpu]:<20} {saved[cpu]:<20} {rflags:<18} {cs:<6} {status}"
        if should_highlight:
            line = f"\033[91m{line}\033[0m"  # wrap in red

        print(line)

        if is_locked:
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

