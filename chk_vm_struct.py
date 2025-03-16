from pykdump import *
import argparse
import re

def get_vm_start_from_vm_struct(vm_struct_addr):
    """Get vm_struct->addr (start address) from a given vm_struct."""
    vm_struct = readSU("struct vm_struct", vm_struct_addr)
    if not vm_struct:
        print(f"❌ Error: `vm_struct` not found at {hex(vm_struct_addr)}")
        return None
    return unsigned64(vm_struct.addr)

def find_vmap_area_from_vmstruct(vm_struct_addr):
    """Find vmap_area using vm_struct->addr via `kmem` command."""
    vm_start = get_vm_start_from_vm_struct(vm_struct_addr)
    if not vm_start:
        return None

    # Use `kmem <addr>` to find vmap_area
    kmem_output = exec_crash_command(f"kmem {hex(vm_start)}")

    match = re.search(r"([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-fx]+) - ([0-9a-fx]+)", kmem_output)
    if match:
        vmap_area_addr = int(match.group(1), 16)
        va_start = int(match.group(3), 16)
        va_end = int(match.group(4), 16)
        print(f"✅ Found `vmap_area` at {hex(vmap_area_addr)} for `vm_struct` {hex(vm_struct_addr)}")
        print(f"   🔹 Start: {hex(va_start)}, End: {hex(va_end)}")
        return vmap_area_addr

    print(f"❌ No matching `vmap_area` found for `vm_struct` at {hex(vm_struct_addr)}.")
    return None

def main():
    parser = argparse.ArgumentParser(description="Find vmap_area using vm_struct address")
    parser.add_argument("vm_struct_addr", type=lambda x: int(x, 16), help="Address of vm_struct (hex)")

    args = parser.parse_args()
    find_vmap_area_from_vmstruct(args.vm_struct_addr)

if __name__ == "__main__":
    main()
