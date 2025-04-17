from pykdump.API import *
from LinuxDump import percpu
import re

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

# Run the detection
detect_hard_lockup()

