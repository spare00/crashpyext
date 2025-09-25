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

            # Extract PID and COMMAND (task name)
            pid_match = re.search(r"PID:\s*\d+", cpu_line)
            comm_match = re.search(r'COMMAND:\s*"([^"]+)"', cpu_line)
            task_comm = comm_match.group(1) if comm_match else "Unknown"

            cpu_info.append((cpu, rflags, cs, task_comm))
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

        rflags = cs = task_comm = "N/A"
        for entry in cpu_info:
            if entry[0] == cpu:
                rflags, cs, task_comm = entry[1], entry[2], entry[3]
                break

        # Skip if it's swapper
        if task_comm.startswith("swapper"):
            status = "Idle - Ignored"
            diff_str = "-"
            threshold_ts = "N/A"
            line = f"{cpu:<5} {rq_time[cpu]:<12.2f} {'-':>10} {threshold_ts:>15} {diff_str:>10} {rflags:>18} {cs:>6} {status}"
            print(line)
            continue

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
        rflags_suspicious = if_bit_clear(rflags)
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

def if_bit_clear(rflags_str: str) -> bool:
    """True if IF (bit 9) is clear; returns False if parsing fails."""
    try:
        return (int(rflags_str, 16) & 0x200) == 0
    except Exception:
        return False

def is_hard_watchdog_enabled_default_true() -> bool:
    """Best-effort read of watchdog_enabled hard-bit (0x01). Defaults to True if unknown."""
    try:
        if not symbol_exists("watchdog_enabled"):
            return True
        val = readSymbol("watchdog_enabled")
        return (val & 0x01) != 0
    except Exception:
        return True

def get_cpu_rflags_cs_via_bt_robust():
    """
    Robustly parse 'bt -a': for each 'CPU: N' block, search lines until the next 'CPU:' for RFLAGS and CS.
    Returns list of tuples: (cpu, rflags_hex or 'N/A', cs_hex or 'N/A')
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
        # scan until next CPU or EOF
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

def is_hard_watchdog_enabled():
    try:
        if not symbol_exists("watchdog_enabled"):
            return True  # be permissive if symbol absent
        val = readSymbol("watchdog_enabled")
        return (val & 0x01) != 0  # hard watchdog bit
    except:
        return True

def if_bit_clear(rflags_str: str) -> bool:
    try:
        return (int(rflags_str, 16) & 0x200) == 0
    except:
        return False

def is_hard_watchdog_enabled():
    try:
        if not symbol_exists("watchdog_enabled"):
            return True  # be permissive if symbol absent
        val = readSymbol("watchdog_enabled")
        return (val & 0x01) != 0  # hard watchdog bit
    except:
        return True

def if_bit_clear(rflags_str: str) -> bool:
    try:
        return (int(rflags_str, 16) & 0x200) == 0
    except:
        return False

def detect_hard_lockup():
    """Detects hard lockups and classifies them as CONFIRMED / SUSPECT / NORMAL."""
    print("\n🔍 Checking for hard lockups in vmcore...\n")

    hard_wd_on = is_hard_watchdog_enabled_default_true()
    if not hard_wd_on:
        print("⚠️ Hard watchdog appears disabled; equality may be inconclusive.\n")

    interrupts, saved = get_hrtimer_values()
    cpu_info = get_cpu_rflags_cs_via_bt_robust()
    if interrupts is None or saved is None:
        print("❌ Failed to read hrtimer values. Exiting.")
        return

    # Map for quick lookup
    info_map = {c: (rf, cs) for c, rf, cs in cpu_info}

    print(f"{'CPU':<5} {'hrtimer_interrupts':<20} {'hrtimer_saved':<20} {'RFLAGS':<18} {'CS':<6} {'Verdict'}")
    print("=" * 98)

    suspects, confirmed = [], []
    for cpu in range(len(interrupts)):
        rflags, cs = info_map.get(cpu, ("N/A", "N/A"))
        equal = interrupts[cpu] == saved[cpu]
        kernel_cs = (cs == "0010")
        irqs_off = if_bit_clear(rflags)  # True means IF=0

        if equal:
            if kernel_cs:
                # In kernel: equality is meaningful. IF=0 strengthens but IF=1 does not clear it.
                verdict = "⚠️ CONFIRMED hard lockup"
                if not irqs_off:
                    verdict += " (IF=1)"
                confirmed.append(cpu)
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
        print(f"❓ Hard lockup (SUSPECT) on CPUs: {', '.join(map(str, suspects))}")
    if not confirmed and not suspects:
        print("✅ No hard lockup indicated.")

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

