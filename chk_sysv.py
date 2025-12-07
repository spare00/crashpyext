"""
chk_sysv.py - System V Shared Memory Usage Analyzer for Crash (ePython)

Usage:
  epython chk_sysv.py -t [-K | -M | -G]
    -t : Show total allocated/resident/swapped memory
    -K : Output in kilobytes (default)
    -M : Output in megabytes
    -G : Output in gigabytes
"""

from pykdump.API import *
import argparse

def parse_ipcs_output():
    """
    Parses 'ipcs -M' output and returns totals of Allocated, Resident, and Swapped pages.
    Returns:
        (allocated_kb, resident_kb, swapped_kb): tuple of totals in kilobytes
    """
    output = exec_crash_command("ipcs -M")
    allocated = 0
    resident = 0
    swapped = 0

    for line in output.splitlines():
        if "PAGES ALLOCATED" in line:
            try:
                parts = line.split(":")[1].strip().split("/")
                allocated += int(parts[0])
                resident += int(parts[1])
                swapped += int(parts[2])
            except (IndexError, ValueError):
                continue

    allocated_kb = allocated * 4
    resident_kb = resident * 4
    swapped_kb = swapped * 4

    return allocated_kb, resident_kb, swapped_kb

def convert_units(kb_value, unit):
    if unit == "KB":
        return kb_value
    elif unit == "MB":
        return kb_value / 1024
    elif unit == "GB":
        return kb_value / (1024 ** 2)

def show_totals(unit):
    allocated_kb, resident_kb, swapped_kb = parse_ipcs_output()

    allocated = convert_units(allocated_kb, unit)
    resident = convert_units(resident_kb, unit)
    swapped = convert_units(swapped_kb, unit)

    print("\n%-20s %-20s %-20s %-20s" % ("", "Allocated", "Resident", "Swapped"))
    print("%-20s %-20.2f %-20.2f %-20.2f\n" % (
        f"Total ({unit})", allocated, resident, swapped
    ))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check System V Shared Memory (ipcs -M)")
    parser.add_argument("-t", "--total", action="store_true", help="Show total allocated/resident/swapped memory")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-K", "--kilobytes", action="store_true", help="Show size in kilobytes (KB)")
    group.add_argument("-M", "--megabytes", action="store_true", help="Show size in megabytes (MB)")
    group.add_argument("-G", "--gigabytes", action="store_true", help="Show size in gigabytes (GB)")

    args = parser.parse_args()

    # Default to KB
    unit = "GB"
    if args.megabytes:
        unit = "MB"
    elif args.kilobytes:
        unit = "KB"

    if args.total:
        show_totals(unit)
    else:
        print("Usage: chk_sysv.py -t [-K | -M | -G]")

