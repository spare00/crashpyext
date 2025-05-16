# -----------------------------------------------------------------------------
# Examples for how to find values to use with --phys, --kvaddr, or --validity
#
# --phys 0x926f87000
#   → From vtop or page table walk output. This is the *physical address* of
#     a PTE page containing 512 64-bit entries (typically 4KB aligned).
#
#     crash> vtop 0x561a84a202f8
#     ...
#     PTE: 0x926f87100 => 0xef980207ffffff8b
#     → page-aligned base = 0x926f87000
#
# --kvaddr ffff8a26a6f87000
#   → Kernel virtual address of the same PTE page (via direct map)
#
#     crash> ptov 0x926f87000
#     VIRTUAL           PHYSICAL
#     ffff8a26a6f87000  926f87000
#
# --validity 0x561a84a202f8
#   → The *virtual address* that caused a page fault or crash
#     (e.g. from logs or RIP context).
#
#     [1517658.618535] aide: Corrupted page table at address 561a84a202f8
#     → Use: --validity 0x561a84a202f8
#
# -----------------------------------------------------------------------------
import argparse
import re
from pykdump.API import *
import struct

def parse_args():
    usage_desc = """
Scan a PTE page for corruption or validate a single virtual address.

Examples:
  --phys 0x926f87000
      → From 'vtop' output: PTE entry page (aligned 4KB physical address)

  --kvaddr ffff8a26a6f87000
      → From 'ptov 0x926f87000': kernel virtual address of PTE page

  --validity 0x561a84a202f8
      → From crash log: virtual address that triggered a page fault
"""

    parser = argparse.ArgumentParser(
        description=usage_desc,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--phys", type=lambda x: int(x, 16),
            help="Physical base address of the PTE page (512 entries)")
    group.add_argument("--kvaddr", type=lambda x: int(x, 16),
            help="Kernel virtual address (e.g. direct-mapped) of the PTE page")
    group.add_argument("--validity", type=lambda x: int(x, 16),
            help="Validate PTE entry for a virtual address")

    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug output")
    return parser.parse_args()

def resolve_vtop(vaddr, debug=False):
    output = exec_crash_command(f"vtop 0x{vaddr:x}")
    if debug:
        print("→ Raw output from crash vtop:")
        print(output)

    if "PTE:" not in output:
        raise RuntimeError("vtop output does not contain a PTE entry")

    match = re.search(r"PTE:\s+([0-9a-fx]+)\s+=>\s+([0-9a-fx]+)", output)
    if not match:
        raise RuntimeError("Failed to parse PTE line from vtop output")

    pte_addr = int(match.group(1), 16)
    pte_val = int(match.group(2), 16)

    return pte_addr, pte_val

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

    print(f"PTE Address   : 0x{pte_addr:x}")
    print(f"PTE Value     : 0x{pte_val:016x}")

    if verbose or debug:
        print(f"  → PFN            : 0x{pfn:x}")
        print(f"  → Flags          : 0x{flags:x}")
        print(f"  → NX             : {nx_bit}")
        print(f"  → Reserved[52–62]: 0x{reserved:x}")
        print(f"  → Physical Addr  : 0x{phys_addr:x}")
        print(f"  → Max Phys Addr  : 0x{max_phys_addr:x} ({x86_phys_bits} bits)")

    if reserved != 0:
        print("❌ Invalid: Reserved bits 52–62 are set.")
    elif phys_addr > max_phys_addr:
        print("❌ Invalid: Physical address exceeds CPU-supported limit.")
    elif not (flags & 0x1):
        print("❌ Invalid: Not present (P bit not set).")
    else:
        print("✅ PTE is valid.")

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

def scan_pte_page(addr, is_phys=False, verbose=False, debug=False):
    try:
        if is_phys:
            phys_addr = addr
            if debug:
                print(f"→ Using physical address: 0x{phys_addr:x}")
        else:
            phys_addr = resolve_kernel_virt_to_phys(addr, debug)

        entries = read_pte_page_via_rd(phys_addr, debug)
    except Exception as e:
        print(f"❌ Failed to resolve or read physical page: {e}")
        return

    cpuinfo = readSU("struct cpuinfo_x86", readSymbol("boot_cpu_data"))
    max_phys_addr = (1 << cpuinfo.x86_phys_bits) - 1

    print(f"\n🔍 Scanning PTE page at {'physical' if is_phys else 'virtual'} 0x{addr:x}")
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
    print(f"  Reserved Bit Errors : {invalid_reserved}")
    print(f"  Physical Addr Errors: {invalid_phys}")

def main():
    args = parse_args()
    if args.validity:
        try:
            pte_addr, pte_val = resolve_vtop(args.validity, debug=args.debug)
            ok = is_pte_valid(pte_addr, pte_val, verbose=args.verbose, debug=args.debug)
            if not ok:
                sys.exit(1)
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
    if args.phys:
        scan_pte_page(args.phys, is_phys=True, verbose=args.verbose, debug=args.debug)
    elif args.kvaddr:
        scan_pte_page(args.kvaddr, is_phys=False, verbose=args.verbose, debug=args.debug)

if __name__ == "__main__":
    main()

