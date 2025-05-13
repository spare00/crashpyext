import re
import argparse
from pykdump.API import *

# Currently only support bnxt and tg3 drivers.


BUFFER_SIZE = 2048
RX_BUF_RING_SIZE = 1024
MAX_ERRORS_TO_PRINT = 10
MAX_WARNINGS = 10

def log_warning(msg):
    print(f"⚠️  {msg}")

def log_error(msg):
    print(f"❌ {msg}")

def align_up(size, align):
    return ((size + align - 1) // align) * align

def get_buffer_size_from_mtu(mtu):
    if mtu <= 1500:
        return 2048
    elif mtu <= 9000:
        return 16384
    else:
        return align_up(mtu + 128, 2048)

def get_struct_size(struct_name):
    output = exec_crash_command(f"struct {struct_name}")
    for line in output.splitlines():
        if "SIZE:" in line:
            return int(line.split("SIZE:")[1].strip())
    raise RuntimeError(f"Could not get size of {struct_name}")

def get_field_offset(struct_name, field_name):
    output = exec_crash_command(f"struct {struct_name} -o")
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith('['):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        # Clean trailing semicolon and pointer/reference symbols
        raw_field = parts[-1].rstrip(';')  # Remove semicolon
        raw_field = raw_field.lstrip('*')  # Remove pointer mark
        raw_field = raw_field.split('[')[0]  # Strip array index, e.g., napi[5] → napi

        if raw_field == field_name:
            try:
                offset = int(parts[0][1:-1])
                return offset
            except ValueError:
                continue

    raise RuntimeError(f"Field {field_name} not found in struct {struct_name}")

def parse_net_devices(debug=False):
    net_output = exec_crash_command("net")
    netdev_addrs = []
    for line in net_output.splitlines():
        if debug:
            print(f"DEBUG: [NET DEVICE]: {line}")
        if re.match(r"^[0-9a-fA-F]+", line.strip()):
            addr = int(line.split()[0], 16)
            netdev_addrs.append(addr)
    return netdev_addrs

def read_driver_symbol(netdev):
    try:
        print(f"netdev.netdev_ops: {hex(int(netdev.netdev_ops))}")
        rtn = readSymbol(hex(int(netdev.netdev_ops)))
        print(f"netdev.netdev_ops: {hex(int(netdev.netdev_ops))}, {rtn}")
        return rtn
    except:
        print(f"netdev.netdev_ops: {hex(int(netdev.netdev_ops))}")
        return ""

def analyze_bnxt(netdev_addr, buffer_size, verbose=False, debug=False):
    try:
        netdev_size = get_struct_size("net_device")
        aligned_size = align_up(netdev_size, 32)
        bnxt_addr = netdev_addr + aligned_size
        if debug:
            print(f"DEBUG: bnxt {hex(bnxt_addr)}")

        # Offset helpers
        rx_ring_off = get_field_offset("bnxt", "rx_ring")
        cp_off = get_field_offset("bnxt", "cp_nr_rings")
        tx_ring_off = get_field_offset("bnxt", "tx_ring")
        tx_nr_rings_off = get_field_offset("bnxt", "tx_nr_rings")

        rx_ring_struct_off = get_field_offset("bnxt_rx_ring_info", "rx_ring_struct")
        tx_ring_info_struct_off = get_field_offset("bnxt_tx_ring_info", "tx_ring_struct")
        ring_mem_off = get_field_offset("bnxt_ring_struct", "ring_mem")
        depth_off = get_field_offset("bnxt_ring_mem_info", "depth")
        vmem_size_off = get_field_offset("bnxt_ring_mem_info", "vmem_size")

        # RX setup
        rx_ring_ptr = readPtr(bnxt_addr + rx_ring_off)
        num_rx_rings = readU16(bnxt_addr + cp_off)
        rx_bd_size = get_struct_size("bnxt_sw_rx_bd")
        rx_data_off = get_field_offset("bnxt_sw_rx_bd", "data")
        rx_ring_info_size = get_struct_size("bnxt_rx_ring_info")

        total_rx_buffers = 0

        for i in range(num_rx_rings):
            ring_info_ptr = rx_ring_ptr + i * rx_ring_info_size
            if debug:
                print(f"DEBUG: [RX Ring {i}] bnxt_rx_ring_info {hex(ring_info_ptr)}")
            try:
                ring_info = readSU("struct bnxt_rx_ring_info", ring_info_ptr)
                rx_buf_ring_ptr = ring_info.rx_buf_ring
                if rx_buf_ring_ptr in [0, 0xffffffffffffffff]:
                    if debug:
                        print(f"DEBUG: [RX Ring {i}] Invalid rx_buf_ring_ptr: {hex(rx_buf_ring_ptr)} — skipping")
                    continue
            except Exception as e:
                if debug:
                    print(f"DEBUG: [RX Ring {i}] Failed to read ring_info: {e}")
                continue

            ring_buf_count = 0
            ring_struct_addr = ring_info_ptr + rx_ring_struct_off
            ring_mem_addr = ring_struct_addr + ring_mem_off
            if debug:
                print(f"DEBUG: [RX Ring {i}] bnxt_ring_struct {hex(ring_struct_addr)}")

            try:
                ring_depth = readU16(ring_mem_addr + depth_off)
                if ring_depth == 0:
                    vmem_size = readInt(ring_mem_addr + vmem_size_off)
                    ring_depth = vmem_size // rx_bd_size
                    if debug:
                        print(f"DEBUG: [RX Ring {i}] ring depth inferred from vmem_size = {ring_depth}")
                else:
                    if debug:
                        print(f"DEBUG: [RX Ring {i}] ring depth = {ring_depth}")
            except Exception as e:
                ring_depth = 1024
                if debug:
                    print(f"DEBUG: [RX Ring {i}] Failed to determine ring depth: {e} — fallback to 1024")

            for j in range(ring_depth):
                entry_addr = rx_buf_ring_ptr + j * rx_bd_size
                try:
                    data_ptr = readPtr(entry_addr + rx_data_off)
                    if data_ptr:
                        ring_buf_count += 1
                        if verbose:
                            print(f"[RX {i}:{j:04d}] data = {hex(data_ptr)}")
                except:
                    continue

            if debug:
                print(f"DEBUG: [RX Ring {i}] Allocated buffers: {ring_buf_count} / {ring_depth}")
            total_rx_buffers += ring_buf_count

        # TX setup
        tx_ring_ptr = readPtr(bnxt_addr + tx_ring_off)
        num_tx_rings = readU16(bnxt_addr + tx_nr_rings_off)
        tx_ring_info_size = get_struct_size("bnxt_tx_ring_info")
        tx_bd_size = get_struct_size("tx_bd")
        tx_data_off = get_field_offset("tx_bd", "tx_bd_haddr")

        total_tx_buffers = 0

        for i in range(num_tx_rings):
            ring_info_ptr = tx_ring_ptr + i * tx_ring_info_size
            if debug:
                print(f"DEBUG: [TX Ring {i}] bnxt_tx_ring_info {hex(ring_info_ptr)}")
            try:
                ring_info = readSU("struct bnxt_tx_ring_info", ring_info_ptr)
                tx_buf_ring_ptr = ring_info.tx_buf_ring
                if tx_buf_ring_ptr in [0, 0xffffffffffffffff]:
                    if debug:
                        print(f"DEBUG: [TX Ring {i}] Invalid tx_buf_ring_ptr: {hex(tx_buf_ring_ptr)} — skipping")
                    continue
            except Exception as e:
                if debug:
                    print(f"DEBUG: [TX Ring {i}] Failed to read ring_info: {e}")
                continue

            ring_struct_addr = ring_info_ptr + tx_ring_info_struct_off
            ring_mem_addr = ring_struct_addr + ring_mem_off
            if debug:
                print(f"DEBUG: [TX Ring {i}] bnxt_ring_struct {hex(ring_struct_addr)}")

            try:
                ring_depth = readU16(ring_mem_addr + depth_off)
                if ring_depth == 0:
                    vmem_size = readInt(ring_mem_addr + vmem_size_off)
                    ring_depth = vmem_size // tx_bd_size
                    if debug:
                        print(f"DEBUG: [TX Ring {i}] ring depth inferred from vmem_size = {ring_depth}")
                else:
                    if debug:
                        print(f"DEBUG: [TX Ring {i}] ring depth = {ring_depth}")
            except Exception as e:
                ring_depth = 1024
                if debug:
                    print(f"DEBUG: [TX Ring {i}] Failed to determine ring depth: {e} — fallback to 1024")

            buf_count = 0
            for j in range(ring_depth):
                entry_addr = tx_buf_ring_ptr + j * tx_bd_size
                try:
                    addr_val = int.from_bytes(readmem(entry_addr + tx_data_off, 8), "little")
                    if addr_val:
                        buf_count += 1
                        if verbose:
                            print(f"[TX {i}:{j:04d}] addr = {hex(addr_val)}")
                except:
                    continue

            if debug:
                print(f"DEBUG: [TX Ring {i}] Allocated buffers: {buf_count} / {ring_depth}")
            total_tx_buffers += buf_count

        return {
            "driver": "bnxt",
            "rx_buffers": total_rx_buffers,
            "tx_buffers": total_tx_buffers,
            "rx_bytes": total_rx_buffers * buffer_size,
            "tx_bytes": total_tx_buffers * buffer_size
        }

    except Exception as e:
        print(f"❌ Error analyzing bnxt: {e}")
        return None

def analyze_tg3(dev_addr, buffer_size, verbose=False, debug=False):
    try:
        netdev_size = get_struct_size("net_device")
        aligned_size = align_up(netdev_size, 32)
        tg3_addr = dev_addr + aligned_size
        if debug:
            print(f"DEBUG: tg3 {hex(tg3_addr)}")

        tg3 = readSU("struct tg3", tg3_addr)

        napi_off = get_field_offset("tg3", "napi")
        napi_size = get_struct_size("tg3_napi")
        rx_rcb_off = get_field_offset("tg3_napi", "rx_rcb")
        tx_ring_off = get_field_offset("tg3_napi", "tx_ring")
        tx_pending_off = get_field_offset("tg3_napi", "tx_pending")

        rx_desc_size = get_struct_size("tg3_rx_buffer_desc")
        tx_desc_size = get_struct_size("tg3_tx_buffer_desc")

        total_rx_buffers = 0
        total_tx_buffers = 0

        for i in range(5):  # tg3 has napi[5]
            napi_addr = tg3_addr + napi_off + i * napi_size
            napi = readSU("struct tg3_napi", napi_addr)
            if debug:
                print(f"DEBUG: [NAPI {i}] tg3_napi {hex(napi_addr)}")

            # RX analysis
            rx_rcb_ptr = int(napi.rx_rcb)
            rx_ring_size = 1024  # conservative fallback

            if rx_rcb_ptr != 0 and rx_rcb_ptr != 0xffffffffffffffff:
                rx_count = 0
                error_count = 0
                for j in range(rx_ring_size):
                    desc_addr = rx_rcb_ptr + j * rx_desc_size
                    try:
                        val = int.from_bytes(readmem(desc_addr, 4), 'little')  # addr_lo
                        if val != 0:
                            rx_count += 1
                            if verbose:
                                print(f"[RX {i}:{j:04d}] addr_lo = {hex(val)}")
                    except:
                        if error_count < 10:
                            print(f"⚠️  tg3: unreadable RX descriptor at {hex(desc_addr)}")
                        elif error_count == 10:
                            print("⚠️  tg3: Further unreadable RX descriptors suppressed...")
                        error_count += 1
                        continue

                total_rx_buffers += rx_count
                if debug:
                    print(f"DEBUG: [NAPI {i}] Allocated buffer: {rx_count} / {rx_ring_size}")
            else:
                if debug:
                    print(f"DEBUG: [NAPI {i}] rx_rcb_ptr = {hex(rx_rcb_ptr)} skipping")

            # TX analysis
            tx_ring_ptr = int(napi.tx_ring)
            try:
                tx_ring_size = readInt(napi_addr + tx_pending_off)
                if tx_ring_size == 0 or tx_ring_size > 8192:
                    tx_ring_size = 1024
                    if debug:
                        print(f"DEBUG: [NAPI {i}] TX ring depth fallback to 1024")
                else:
                    if debug:
                        print(f"DEBUG: [NAPI {i}] TX ring depth = {tx_ring_size}")
            except:
                tx_ring_size = 1024
                if debug:
                    print(f"DEBUG: [NAPI {i}] Failed to read tx_pending — fallback to 1024")

            if tx_ring_ptr != 0 and tx_ring_ptr != 0xffffffffffffffff:
                tx_count = 0
                error_count = 0
                for j in range(tx_ring_size):
                    desc_addr = tx_ring_ptr + j * tx_desc_size
                    try:
                        val = int.from_bytes(readmem(desc_addr, 8), 'little')  # addr
                        if val != 0:
                            tx_count += 1
                            if verbose:
                                print(f"[TX {i}:{j:04d}] addr = {hex(val)}")
                    except:
                        if error_count < 10:
                            print(f"⚠️  tg3: unreadable TX descriptor at {hex(desc_addr)}")
                        elif error_count == 10:
                            print("⚠️  tg3: Further unreadable TX descriptors suppressed...")
                        error_count += 1
                        continue

                total_tx_buffers += tx_count
                if debug:
                    print(f"DEBUG: [NAPI {i}] Allocated buffer: {tx_count} / {tx_ring_size}")
            else:
                if debug:
                    print(f"DEBUG: [NAPI {i}] tx_ring_ptr = {hex(tx_ring_ptr)} — skipping")

        return {
            "driver": "tg3",
            "rx_buffers": total_rx_buffers,
            "tx_buffers": total_tx_buffers,
            "rx_bytes": total_rx_buffers * buffer_size,
            "tx_bytes": total_tx_buffers * buffer_size
        }

    except Exception as e:
        print(f"❌ Error analyzing tg3: {e}")
        return None

def analyze_ice(dev_addr, buffer_size, verbose=False, debug=False):
    try:
        netdev_size = get_struct_size("net_device")
        aligned_size = align_up(netdev_size, 32)
        priv_addr = dev_addr + aligned_size

        # Read struct ice_netdev_priv
        priv = readSU("struct ice_netdev_priv", priv_addr)
        vsi_addr = int(priv.vsi)
        if vsi_addr == 0 or vsi_addr == 0xffffffffffffffff:
            if debug:
                print("DEBUG: Invalid VSI pointer")
            return None

        vsi = readSU("struct ice_vsi", vsi_addr)
        num_rxq = int(vsi.num_rxq)
        num_txq = int(vsi.num_txq)
        rx_rings_ptr = int(vsi.rx_rings)
        tx_rings_ptr = int(vsi.tx_rings)

        if debug:
            print(f"DEBUG: VSI @ {hex(vsi_addr)} has {num_rxq} RX and {num_txq} TX queues")

        rx_ring_size = get_struct_size("ice_rx_ring")
        tx_ring_size = get_struct_size("ice_tx_ring")
        rx_buf_size = get_struct_size("ice_rx_buf")
        tx_buf_size = get_struct_size("ice_tx_buf")
        dma_off = get_field_offset("ice_rx_buf", "dma")
        tx_dma_off = get_field_offset("ice_tx_buf", "dma")

        total_rx_buffers = 0
        total_tx_buffers = 0

        # RX processing
        for i in range(num_rxq):
            ring_ptr = readPtr(rx_rings_ptr + i * 8)
            if ring_ptr in [0, 0xffffffffffffffff]:
                if debug:
                    print(f"DEBUG: RX Ring {i} pointer invalid: {hex(ring_ptr)}")
                continue

            rx_ring = readSU("struct ice_rx_ring", ring_ptr)
            rx_buf_ptr = int(rx_ring.rx_buf)
            depth = int(rx_ring.count)
            if depth == 0 or depth > 8192:
                depth = 1024

            count = 0
            for j in range(depth):
                buf_addr = rx_buf_ptr + j * rx_buf_size
                try:
                    dma_val = readULong(buf_addr + dma_off)
                    if dma_val:
                        count += 1
                        if verbose:
                            print(f"[RX {i}:{j:04d}] dma = {hex(dma_val)}")
                except:
                    continue

            total_rx_buffers += count
            if debug:
                print(f"DEBUG: RX Ring {i}: active buffers = {count}/{depth}")

        # TX processing
        for i in range(num_txq):
            ring_ptr = readPtr(tx_rings_ptr + i * 8)
            if ring_ptr in [0, 0xffffffffffffffff]:
                if debug:
                    print(f"DEBUG: TX Ring {i} pointer invalid: {hex(ring_ptr)}")
                continue

            tx_ring = readSU("struct ice_tx_ring", ring_ptr)
            tx_buf_ptr = int(tx_ring.tx_buf)
            depth = int(tx_ring.count)
            if depth == 0 or depth > 8192:
                depth = 1024

            count = 0
            for j in range(depth):
                buf_addr = tx_buf_ptr + j * tx_buf_size
                try:
                    dma_val = readULong(buf_addr + tx_dma_off)
                    if dma_val:
                        count += 1
                        if verbose:
                            print(f"[TX {i}:{j:04d}] dma = {hex(dma_val)}")
                except:
                    continue

            total_tx_buffers += count
            if debug:
                print(f"DEBUG: TX Ring {i}: active buffers = {count}/{depth}")

        return {
            "driver": "ice",
            "rx_buffers": total_rx_buffers,
            "tx_buffers": total_tx_buffers,
            "rx_bytes": total_rx_buffers * buffer_size,
            "tx_bytes": total_tx_buffers * buffer_size
        }

    except Exception as e:
        print(f"❌ Error analyzing ice: {e}")
        return None

def analyze_virtio_net(netdev_addr, buffer_size, verbose=False, debug=False):
    try:
        netdev = readSU("struct net_device", netdev_addr)
        ml_priv_offset = get_field_offset("net_device", "ml_priv")
        priv_ptr = readPtr(netdev_addr + ml_priv_offset)
        if priv_ptr == 0:
            if debug:
                print("DEBUG: ml_priv is NULL — skipping")
            return {
                "driver": "virtio_net",
                "rx_buffers": 0,
                "tx_buffers": 0,
                "rx_bytes": 0,
                "tx_bytes": 0
            }

        if debug:
            print(f"DEBUG: netdev_addr {hex(netdev_addr)}")
            print(f"DEBUG: ml_priv_offset {ml_priv_offset}")
            print(f"DEBUG: virtnet_info {priv_ptr}")
            print(f"DEBUG: netdev {netdev}")
        priv = readSU("struct virtnet_info", priv_ptr)

        curr_qpairs = int(priv.curr_queue_pairs)
        if curr_qpairs == 0:
            if debug:
                print("DEBUG: curr_queue_pairs is 0 — skipping")
            return {
                "driver": "virtio_net",
                "rx_buffers": 0,
                "tx_buffers": 0,
                "rx_bytes": 0,
                "tx_bytes": 0
            }

        rx_total = 0
        tx_total = 0

        rxq_size = get_struct_size("receive_queue")
        txq_size = get_struct_size("send_queue")

        for i in range(curr_qpairs):
            # RX ring analysis
            rq_ptr = readPtr(priv_ptr + get_field_offset("virtnet_info", "rq") + i * 8)
            if rq_ptr:
                try:
                    rq = readSU("struct receive_queue", rq_ptr)
                    vq_ptr = int(rq.vq)
                    if vq_ptr:
                        vq = readSU("struct virtqueue", vq_ptr)
                        used = 256 - int(vq.num_free)  # Assume 256 ring size unless known
                        rx_total += used
                        if debug:
                            print(f"DEBUG: [RX {i}] used = {used}")
                except Exception as e:
                    if debug:
                        print(f"DEBUG: [RX {i}] error: {e}")

            # TX ring analysis
            sq_ptr = readPtr(priv_ptr + get_field_offset("virtnet_info", "sq") + i * 8)
            if sq_ptr:
                try:
                    sq = readSU("struct send_queue", sq_ptr)
                    vq_ptr = int(sq.vq)
                    if vq_ptr:
                        vq = readSU("struct virtqueue", vq_ptr)
                        used = 256 - int(vq.num_free)  # Again, assume default ring size
                        tx_total += used
                        if debug:
                            print(f"DEBUG: [TX {i}] used = {used}")
                except Exception as e:
                    if debug:
                        print(f"DEBUG: [TX {i}] error: {e}")

        return {
            "driver": "virtio_net",
            "rx_buffers": rx_total,
            "tx_buffers": tx_total,
            "rx_bytes": rx_total * buffer_size,
            "tx_bytes": tx_total * buffer_size
        }

    except Exception as e:
        print(f"❌ Error analyzing virtio_net: {e}")
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose RX/TX entry info")
    args = parser.parse_args()

    print(f"{'Device':<12} {'Driver':<10} {'MTU':>6} {'RX Buffers':>12} {'TX Buffers':>12} "
          f"{'RX Usage (KB)':>15} {'TX Usage (KB)':>15}")
    print("=" * 88)

    total_rx_buffers = 0
    total_tx_buffers = 0
    total_rx_bytes = 0
    total_tx_bytes = 0

    known_builtin_drivers = {
        "loopback_ops": "loopback device",
        "team_netdev_ops": "virtual device",
        "internal_dev_netdev_ops": "virtual device",
        "ipgre_netdev_ops": "tunnel device",
        "gre_tap_netdev_ops": "tunnel device",
        "erspan_netdev_ops": "tunnel device",
        "vxlan_netdev_ether_ops": "tunnel device",
    }

    for addr in parse_net_devices(args.debug):
        try:
            netdev = readSU("struct net_device", addr)
            name = str(netdev.name).strip("\x00")
            mtu = int(netdev.mtu)
            max_mtu = int(netdev.max_mtu)
            buffer_size = get_buffer_size_from_mtu(mtu)

            if args.debug:
                print(f"DEBUG: Got net_device at {hex(addr)}, name = '{name}'")
                print(f"DEBUG: MTU = {mtu}, max_mtu = {max_mtu}, buffer_size = {buffer_size}")

            netdev_ops = int(netdev.netdev_ops)
            sym_output = exec_crash_command(f"sym {hex(netdev_ops)}").strip()
            if args.debug:
                print(f"DEBUG: sym_output = {sym_output}")

            match = re.search(r'(\S+)\s+\[\s*(\w+)\s*\]', sym_output)
            if match:
                func_name, module_name = match.groups()
            else:
                # Try extracting just the symbol name manually
                parts = sym_output.strip().split()
                if len(parts) >= 3:
                    func_name = parts[2]
                    module_name = "<builtin>"
                else:
                    func_name = parts[0]  # fallback to raw address
                    module_name = "<unknown>"
                if args.debug:
                    print(f"DEBUG: Could not parse full symbol format for {name}")

                if args.debug:
                    print(f"DEBUG: Could not parse symbol for {name}")
            if args.debug:
                print(f"DEBUG: Found netdev_ops: {func_name} in module {module_name}")

            # Check for known skip reasons
            if func_name in known_builtin_drivers:
                note = known_builtin_drivers[func_name]
                if args.debug:
                    print(f"DEBUG: ⚠️  Skipping {name}: {note}")
                print(f"{name:<12} {'-':<10} {'-':>6} {'-':>12} {'-':>12} {'-':>15} {'-':>15}  # skipped: {note}")
                continue

            # Process supported drivers
            if func_name == "bnxt_netdev_ops":
                result = analyze_bnxt(addr, buffer_size, args.verbose, args.debug)
            elif func_name == "tg3_netdev_ops":
                result = analyze_tg3(addr, buffer_size, args.verbose, args.debug)
            elif func_name == "ice_netdev_ops":
                result = analyze_ice(addr, buffer_size, args.verbose, args.debug)
            elif func_name == "virtnet_netdev":
                result = analyze_virtio_net(addr, buffer_size, args.verbose, args.debug)
            else:
                note = f"unsupported driver ({func_name})"
                if args.debug:
                    print(f"DEBUG: ⚠️  Skipping {name}: {note}")
                print(f"{name:<12} {'-':<10} {'-':>6} {'-':>12} {'-':>12} {'-':>15} {'-':>15}  # skipped: {note}")
                continue

            if result:
                print(f"{name:<12} {result['driver']:<10} {mtu:>6} {result['rx_buffers']:>12} {result['tx_buffers']:>12} "
                      f"{result['rx_bytes'] // 1024:>15,.2f} {result['tx_bytes'] // 1024:>15,.2f}")
                total_rx_buffers += result["rx_buffers"]
                total_tx_buffers += result["tx_buffers"]
                total_rx_bytes += result["rx_bytes"]
                total_tx_bytes += result["tx_bytes"]

        except Exception as e:
            print(f"⚠️  Failed to analyze device at {hex(addr)}: {e}")

    print("=" * 88)
    print(f"{'':<12} {'':<10} {'':>6} {total_rx_buffers:>12} {total_tx_buffers:>12} "
          f"{total_rx_bytes // 1024:>15,.2f} {total_tx_bytes // 1024:>15,.2f}")
    print("=" * 88)
    print(f"{'TOTAL':<12} {'':<10} {'':>6} {'':>12} {'':>12} "
          f"{'':>15} {(total_rx_bytes + total_tx_bytes) // 1024:>15,.2f}")


if __name__ == "__main__":
    main()

