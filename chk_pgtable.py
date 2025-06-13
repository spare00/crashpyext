import argparse
import re
from pykdump.API import *
import struct

def parse_args():
    usage_desc = """
Scan a PTE or PMD page table for corruption, or validate a single PTE entry or faulting virtual address.

Examples:
  --fault-va 0x561a84a202f8
    → Full analysis of a faulting virtual address:
      validate PTE, scan its PTE page, and scan its PMD page
      (e.g. from logs: 'Corrupted page table at address 561a84a202f8')

  --validate-pte 0xef980207ffffff8b
    → Directly validate a single raw PTE entry
      (e.g. extracted from crash or memory dumps)

  --pte-phys 0x926f87000
    → Physical address of a PTE page
      (from 'vtop' → 'PTE: 0x926f87100 => ...', masked with 0xfff)

  --pmd-phys 0x61b267000
    → Physical address of a PMD page
      (from 'vtop' → PMD address, masked with 0xfff)
"""
    parser = argparse.ArgumentParser(
        description=usage_desc,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fault-va", type=lambda x: int(x, 16),
        help="Analyze faulting VA: validate PTE, scan PTE page, scan PMD page")
    group.add_argument("--validate-pte", type=lambda x: int(x, 16),
        help="Validate a raw PTE entry (e.g. 0xef980207ffffff8b)")
    group.add_argument("--pte-phys", type=lambda x: int(x, 16),
        help="Scan all 512 entries in a PTE page using its physical base address")
    group.add_argument("--pmd-phys", type=lambda x: int(x, 16),
        help="Scan all 512 entries in a PMD page using its physical base address")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    return parser.parse_args()

def red(text):
    return f"\033[91m{text}\033[0m"

def read_pte_page_via_rd(phys_addr, debug=False):
    output = exec_crash_command(f"rd -p 0x{phys_addr:x} -64 512")
    if debug:
        print(f"→ Raw rd -p output:\n{output}")

    entries = []
    for line in output.strip().splitlines():
        parts = re.findall(r'([0-9a-fA-F]{16})', line)
        for val in parts:
            entries.append(int(val, 16))

    if len(entries) != 512:
        raise RuntimeError(f"Expected 512 entries, got {len(entries)}")

    return entries

def is_hugepage_mapping(vaddr, debug=False):
    """
    Checks if the given virtual address is backed by a PMD-level huge page.

    Returns:
        True if hugepage is used, False otherwise
    """
    output = exec_crash_command(f"vtop 0x{vaddr:x}")
    if debug:
        print("→ Raw vtop output for hugepage check:")
        print(output)

    match = re.search(r"PMD:\s+[0-9a-fx]+\s+=>\s+([0-9a-fA-Fx]+)", output)
    if not match:
        return False

    pmd_entry = int(match.group(1), 16)
    return (pmd_entry & (1 << 7)) != 0  # bit 7 = huge page

def format_pte_binary(pte_val):
    """Format a 64-bit PTE entry for annotated binary display"""
    binstr = f"{pte_val:064b}"
    grouped = (
        f"{binstr[0]} "             # NX (bit 63)
        f"{binstr[1:12]} "          # Reserved (52–62)
        f"{binstr[12:52]} "         # Physical Addr (12–51)
        f"{binstr[52:]}"            # Flags (0–11)
    )
    return grouped


def is_pte_valid(pte_addr, pte_val, verbose=False, debug=False):
    flags = pte_val & 0xfff
    nx_bit = (pte_val >> 63) & 0x1
    pfn = (pte_val >> 12) & 0xffffffffff
    reserved = (pte_val >> 52) & 0x7ff
    phys_addr = pfn << 12

    boot_cpu_data = readSymbol("boot_cpu_data")
    cpuinfo = readSU("struct cpuinfo_x86", boot_cpu_data)
    x86_phys_bits = cpuinfo.x86_phys_bits
    max_phys_addr = (1 << x86_phys_bits) - 1

    if pte_addr:
        print(f"PTE Address   : 0x{pte_addr:x}")
    print(f"PTE Value     : 0x{pte_val:016x}")

    print(f"  → PFN            : 0x{pfn:x}")
    print(f"  → Flags          : 0x{flags:x}")
    print(f"  → NX             : {nx_bit}")
    print(f"  → Reserved[52–62]: 0x{reserved:x}")
    print(f"  → Physical Addr  : 0x{phys_addr:x}")
    print(f"  → Max Phys Addr  : 0x{max_phys_addr:x} ({x86_phys_bits} bits)")

    if verbose:
        binary_output = format_pte_binary(pte_val)

        print("\n=== Breakdown of PTE binary bits ===")
        print(f"  Binary:           {binary_output}")
        print("                    ^           ^                           ^                   ^")
        print("  NX Bit (Bit 63): ─┘           |                           |                   |")
        print("  Reserved Bits (Bits 52-62): ──┘                           |                   |")
        print("  Physical Address Bits (Bits 12-51):  ─────────────────────┘                   |")
        print("  Flags Bits (Bits 0-11):       ────────────────────────────────────────────────┘")

    if reserved != 0:
        print(red("\n❌ Invalid: Reserved bits 52–62 are set."))
    elif phys_addr > max_phys_addr:
        print(red("\n❌ Invalid: Physical address exceeds CPU-supported limit."))
    elif not (flags & 0x1):
        print(red("\n❌ Invalid: Not present (P bit not set)."))
    else:
        print("\n✅ PTE is valid.")

    return reserved == 0 and phys_addr <= max_phys_addr and (flags & 0x1)

def resolve_kernel_virt_to_phys(vaddr, debug=False):
    output = exec_crash_command(f"vtop 0x{vaddr:x}")
    if "not accessible" in output:
        raise RuntimeError(f"vtop failed: address 0x{vaddr:x} is not mapped")

    # Prefer PAGE: line
    for line in output.splitlines():
        if line.strip().startswith("PAGE:"):
            phys_str = line.split("PAGE:")[-1].strip()
            phys_addr = int(phys_str, 16)
            if debug:
                print(f"→ vtop: vaddr 0x{vaddr:x} → physical 0x{phys_addr:x} (from PAGE:)")
            return phys_addr

    # Fallback: PHYSICAL column
    match = re.search(r"PHYSICAL\s+([0-9a-fA-Fx]+)", output)
    if match:
        phys_addr = int(match.group(1), 16)
        if debug:
            print(f"→ vtop: vaddr 0x{vaddr:x} → physical 0x{phys_addr:x} (from PHYSICAL)")
        return phys_addr

    raise RuntimeError(f"Failed to extract physical address from vtop output for 0x{vaddr:x}")

def scan_pte_page(phys_addr, verbose=False, debug=False):
    phys_addr &= ~0xfff  # align to 4KB page
    try:
        if debug:
            print(f"→ Using physical address: 0x{phys_addr:x}")

        # Resolve virtual address for hugepage check (optional)
        try:
            output = exec_crash_command(f"ptov 0x{phys_addr:x}")
            match = re.search(r"([0-9a-f]+)\s+%x" % phys_addr, output)
            if match:
                vaddr = int(match.group(1), 16)
                if is_hugepage_mapping(vaddr, debug=debug):
                    print(f"⚠️  Skipping scan: Physical page 0x{phys_addr:x} is mapped via a 2MB huge page (PMD-level).")
                    print(f"   PTE entries are unused in this mapping.")
                    return
        except:
            print(f"⚠️  Warning: Could not resolve virtual address for phys 0x{phys_addr:x} — skipping hugepage check.")

        entries = read_pte_page_via_rd(phys_addr, debug)
    except Exception as e:
        print(f"❌ Failed to resolve or read physical page: {e}")
        return

    cpuinfo = readSU("struct cpuinfo_x86", readSymbol("boot_cpu_data"))
    max_phys_addr = (1 << cpuinfo.x86_phys_bits) - 1

    print(f"\n🔍 Scanning PTE page at physical 0x{phys_addr:x}")
    print(f"   CPU max physical address: 0x{max_phys_addr:x} ({cpuinfo.x86_phys_bits} bits)\n")

    total = 512
    valid = 0
    not_present = 0
    invalid_reserved = 0
    invalid_phys = 0

    for i, entry in enumerate(entries):
        flags = entry & 0xfff
        reserved = (entry >> 52) & 0x7ff
        pfn = (entry >> 12) & 0xffffffffff
        phys = pfn << 12

        entry_info = f"PTE[{i:3}] = 0x{entry:016x}"

        if reserved != 0:
            invalid_reserved += 1
            print(f"{entry_info} ❌ Reserved bits set [52–62]: 0x{reserved:x}")
        elif phys > max_phys_addr:
            invalid_phys += 1
            print(f"{entry_info} ❌ Physical address 0x{phys:x} exceeds CPU max")
        elif not (flags & 0x1):
            not_present += 1
            if verbose or debug:
                print(f"{entry_info} ⚠️  Not present (P bit not set)")
        else:
            valid += 1
            if debug:
                print(f"{entry_info} ✅ Valid")

    print("\n📊 Summary:")
    print(f"  Total Entries       : {total}")
    print(f"  Valid               : {valid}")
    print(f"  Not Present         : {not_present}")

    reserved_line = f"  Reserved Bit Errors : {invalid_reserved}"
    reserved_line = red(reserved_line) if invalid_reserved > 0 else reserved_line
    print(reserved_line)

    invalid_phys_line = f"  Physical Addr Errors: {invalid_phys}"
    invalid_phys_line = red(invalid_phys_line) if invalid_phys > 0 else invalid_phys_line
    print(invalid_phys_line)

def read_pmd_page_via_rd(phys_addr, debug=False):
    output = exec_crash_command(f"rd -p 0x{phys_addr:x} -64 512")
    if debug:
        print(f"→ Raw rd -p output (PMD):\n{output}")
    entries = []
    for line in output.strip().splitlines():
        parts = re.findall(r'([0-9a-fA-F]{16})', line)
        for val in parts:
            entries.append(int(val, 16))
    if len(entries) != 512:
        raise RuntimeError(f"Expected 512 PMD entries, got {len(entries)}")
    return entries

def scan_pmd_page(phys_addr, verbose=False, debug=False):
    phys_addr &= ~0xfff  # align to 4KB page
    try:
        if debug:
            print(f"→ Using PMD physical address: 0x{phys_addr:x}")

        entries = read_pte_page_via_rd(phys_addr, debug)  # reuse same reader
    except Exception as e:
        print(f"❌ Failed to read PMD page: {e}")
        return

    cpuinfo = readSU("struct cpuinfo_x86", readSymbol("boot_cpu_data"))
    max_phys_addr = (1 << cpuinfo.x86_phys_bits) - 1

    print(f"\n🔍 Scanning PMD page at physical 0x{phys_addr:x}")
    print(f"   CPU max physical address: 0x{max_phys_addr:x} ({cpuinfo.x86_phys_bits} bits)\n")

    total = 512
    valid = 0
    reserved_err = 0
    phys_err = 0
    not_present = 0

    for i, entry in enumerate(entries):
        flags = entry & 0xfff
        reserved = (entry >> 52) & 0x7ff
        pfn = (entry >> 12) & 0xffffffffff
        phys = pfn << 12

        entry_info = f"PMD[{i:3}] = 0x{entry:016x}"

        if reserved != 0:
            reserved_err += 1
            print(f"{entry_info} ❌ Reserved bits set [52–62]: 0x{reserved:x}")
        elif phys > max_phys_addr:
            phys_err += 1
            print(f"{entry_info} ❌ Physical address 0x{phys:x} exceeds CPU max")
        elif not (flags & 0x1):
            not_present += 1
            if verbose or debug:
                print(f"{entry_info} ⚠️  Not present")
        else:
            valid += 1
            if debug:
                print(f"{entry_info} ✅ Valid")

    print("\n📊 PMD Summary:")
    print(f"  Total Entries       : {total}")
    print(f"  Valid               : {valid}")
    print(f"  Not Present         : {not_present}")

    reserved_line = f"  Reserved Bit Errors : {reserved_err}"
    reserved_line = red(reserved_line) if reserved_err > 0 else reserved_line
    print(reserved_line)

    phys_err_line = f"  Physical Addr Errors: {phys_err}"
    phys_err_line = red(phys_err_line) if phys_err > 0 else phys_err_line
    print(phys_err_line)

def analyze_faulting_va(fault_va, verbose=False, debug=False):
    print(f"🔎 Resolving faulting virtual address: 0x{fault_va:x}\n")

    try:
        output = exec_crash_command(f"vtop 0x{fault_va:x}")
        if verbose or debug:
            print("→ Raw output from crash vtop:\n" + output)

        # Extract PTE entry
        pte_match = re.search(r"PTE:\s+([0-9a-f]+)\s+=>\s+([0-9a-f]+)", output)
        if not pte_match:
            raise RuntimeError("Failed to parse PTE entry")
        pte_addr = int(pte_match.group(1), 16)
        pte_val = int(pte_match.group(2), 16)

        # Validate the single PTE entry
        reserved = (pte_val >> 52) & 0x7ff
        print("✅ Validating PTE entry:")
        print(f"  PTE: {pte_val:016x}")
        pte_line = f"  → Reserved bits set: 0x{reserved:x} {'✅' if reserved == 0 else '❌'}\n"
        pte_line = red(pte_line) if reserved > 0 else pte_line
        print(pte_line)

        # Scan PTE page
        pte_phys_base = pte_addr & ~0xfff
        pte_entries = read_pte_page_via_rd(pte_phys_base, debug=debug)
        bad_pte = sum(1 for val in pte_entries if ((val >> 52) & 0x7ff) != 0)

        print("🧩 PTE page scan:")
        print(f"  Physical: 0x{pte_phys_base:x}")

        pte_page_line = f"  → {bad_pte} reserved-bit errors {'✅' if bad_pte == 0 else '❌'}\n"
        pte_page_line = red(pte_page_line) if bad_pte > 0 else pte_page_line
        print(pte_page_line)

        # Scan PMD page
        pmd_match = re.search(r"PMD:\s+([0-9a-fx]+)\s+=>\s+([0-9a-fx]+)", output)
        if not pmd_match:
            raise RuntimeError("Could not extract PMD address from vtop")
        pmd_val = int(pmd_match.group(1), 16)
        pmd_phys_base = pmd_val & ~0xfff

        pmd_entries = read_pte_page_via_rd(pmd_phys_base, debug=debug)
        bad_pmd = sum(1 for val in pmd_entries if ((val >> 52) & 0x7ff) != 0)

        print("🧩 PMD page scan:")
        print(f"  Physical: 0x{pmd_phys_base:x}")
        if bad_pmd == 0:
            print(f"  → All 512 entries valid ✅")
        else:
            print(red(f"  → {bad_pmd} reserved-bit errors ❌"))

    except Exception as e:
        print(f"❌ Error processing faulting VA: {e}")

def main():
    args = parse_args()

    if args.fault_va:
        try:
            if args.debug:
                print(f"🔎 Resolving faulting virtual address: 0x{args.fault_va:x}")
            analyze_faulting_va(args.fault_va, verbose=args.verbose, debug=args.debug)
        except Exception as e:
            print(f"❌ Error processing faulting VA: {e}")
    elif args.validate_pte:
        is_pte_valid(pte_addr=0, pte_val=args.validate_pte, verbose=args.verbose, debug=args.debug)
    elif args.pte_phys:
        scan_pte_page(args.pte_phys, verbose=args.verbose, debug=args.debug)
    elif args.pmd_phys:
        scan_pmd_page(args.pmd_phys, verbose=args.verbose, debug=args.debug)

if __name__ == "__main__":
    main()

