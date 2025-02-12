from pykdump.API import *
from LinuxDump import percpu

def get_softlockup_values():
    """Fetches per-CPU rq->clock and watchdog_touch_ts to check for soft lockups."""
    
    if not symbol_exists("runqueues") or not symbol_exists("watchdog_touch_ts") or not symbol_exists("watchdog_thresh") or not symbol_exists("watchdog_enabled"):
        print("⚠️ Warning: Required symbols 'runqueues', 'watchdog_touch_ts', 'watchdog_thresh', or 'watchdog_enabled' are missing.")
        return None, None, None, None

    try:
        # Fetch all CPU runqueues
        runqueue_addrs = percpu.get_cpu_var("runqueues")
        rq_clock = []
        
        for addr in runqueue_addrs:
            rq = readSU("struct rq", addr)  # Read the entire struct rq
            rq_clock.append(rq.clock)  # Access the 'clock' field
        
        # Fetch watchdog_touch_ts values for all CPUs
        watchdog_touch_ts_addrs = percpu.get_cpu_var("watchdog_touch_ts")
        watchdog_touch_ts = [readULong(addr) for addr in watchdog_touch_ts_addrs]

        # Convert rq_clock from nanoseconds to seconds (rq_clock >> 30)
        rq_time_sec = [clock_value >> 30 for clock_value in rq_clock]

        # Get soft lockup threshold (watchdog_thresh * 2)
        watchdog_thresh = readSymbol("watchdog_thresh")
        softlockup_thresh = watchdog_thresh * 2  # Correct soft lockup threshold

        # Check if the soft watchdog is enabled
        watchdog_enabled = readSymbol("watchdog_enabled")
        soft_watchdog_enabled = 0x02  # SOFT_WATCHDOG_ENABLED flag

        return rq_time_sec, watchdog_touch_ts, softlockup_thresh, watchdog_enabled & soft_watchdog_enabled

    except Exception as e:
        print(f"❌ Error: Failed to read soft lockup values: {e}")
        return None, None, None, None

def detect_soft_lockup():
    """Detects soft lockups in a vmcore by comparing rq->clock and watchdog_touch_ts."""
    print("🔍 Checking for soft lockups in vmcore...\n")

    rq_time, touch_ts, softlockup_thresh, is_watchdog_enabled = get_softlockup_values()
    if rq_time is None or touch_ts is None or softlockup_thresh is None:
        print("❌ Failed to read required values. Exiting.")
        return

    if not is_watchdog_enabled:
        print("⚠️ Soft watchdog is disabled. No soft lockup detection will be performed.")
        return

    print(f"Soft Lockup Threshold: {softlockup_thresh} seconds\n")
    print(f"{'CPU':<5} {'rq->clock (sec)':<20} {'watchdog_touch_ts':<20} {'Difference':<15} {'Status'}")
    print("=" * 90)

    locked_cpus = []
    for cpu in range(len(rq_time)):
        diff = rq_time[cpu] - touch_ts[cpu]

        if touch_ts[cpu] == 0:
            status = "Ignore"
        else:
            is_locked = rq_time[cpu] > (touch_ts[cpu] + softlockup_thresh)
            status = "✅ Normal" if not is_locked else "⚠️ Soft Lockup"
            if is_locked:
                locked_cpus.append(cpu)

        print(f"{cpu:<5} {rq_time[cpu]:<20} {touch_ts[cpu]:<20} {diff:<15} {status}")

    print("\n🔍 Analysis Complete.")
    if locked_cpus:
        print(f"⚠️ Soft lockup detected on CPUs: {', '.join(map(str, locked_cpus))}")
    else:
        print("✅ No soft lockup detected in vmcore.")

# Run the detection function inside crash
detect_soft_lockup()
