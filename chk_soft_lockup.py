import argparse
from pykdump.API import *
from LinuxDump import percpu
import re

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

def get_rflags_and_cs_from_bt():
    """Parses 'bt -a' to extract CPU, RFLAGS, and CS."""
    output = exec_crash_command("bt -a")
    lines = output.splitlines()

    filtered = [line for line in lines if re.search(r"CPU:\s*\d+|RFLAGS|CS\s*:\s*[0-9a-fA-F]{4}", line)]
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

def get_softlockup_values(rhel_version):
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
    rhel_version = get_rhel_version()
    print(f"\n🔍 Checking for soft lockups in vmcore (RHEL {rhel_version})...")

    rq_time, touch_ts, period_ts, softlockup_thresh, is_watchdog_enabled = get_softlockup_values(rhel_version)
    cpu_info = get_rflags_and_cs_from_bt()

    if None in (rq_time, touch_ts, softlockup_thresh):
        print("❌ Failed to read required values. Exiting.")
        return

    if not is_watchdog_enabled:
        print("⚠️ Soft watchdog is disabled.")
        return

    print(f"Soft Lockup Threshold: {softlockup_thresh} seconds\n")

    max_now = max(rq_time)
    print(f"⏱️  Max rq->clock across CPUs: {max_now:.2f} sec\n")

    print(f"{'CPU':<5} {'now (sec)':<12} {'behind(s)':>10} {'touch+%d' % softlockup_thresh:>15} {'Diff':>10} {'RFLAGS':>18} {'CS':>6} {'Status'}")
    print("=" * 100)

    locked_cpus = []
    ULONG_MAX = 18446744073709551615

    for cpu in range(len(rq_time)):
        delta = max_now - rq_time[cpu]
        plain_delta = f"{delta:.2f}"
        behind_by_str = plain_delta.rjust(10)

        rflags = cs = "N/A"
        for entry in cpu_info:
            if entry[0] == cpu:
                rflags, cs = entry[1], entry[2]
                break

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

        # Check RFLAGS bit 9 missing (interrupts disabled) and CS == 0010
        rflags_suspicious = rflags != "N/A" and len(rflags) >= 6 and rflags[-6] != '2'
        cs_suspicious = cs == "0010"
        highlight = status == "⚠️ Soft Lockup" and rflags_suspicious and cs_suspicious

        line = f"{cpu:<5} {rq_time[cpu]:<12.2f} {behind_by_str} {str(threshold_ts):>15} {diff_str:>10} {rflags:>18} {cs:>6} {status}"
        if highlight:
            line = f"\033[91m{line}\033[0m"

        print(line)

    print("\n🔍 Analysis Complete.")
    if locked_cpus:
        print(f"⚠️ Soft lockup detected on CPUs: {', '.join(map(str, locked_cpus))}")
    else:
        print("✅ No soft lockup detected.")

if __name__ == "__main__":
    detect_soft_lockup()
