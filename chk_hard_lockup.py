from pykdump.API import *
from LinuxDump import percpu

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

# Run the detection function inside crash
detect_hard_lockup()

