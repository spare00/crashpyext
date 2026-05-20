import re
import argparse
import crash
from pykdump.API import *

# Supports bnxt, tg3, ice, virtio_net, igb, vmxnet3, sfc (Solarflare), and bridge masters.


BUFFER_SIZE = 2048
IFF_BRIDGE_PORT = 1 << 9
SCTP_IFACE_RE = re.compile(r'^p?sctp\d+$', re.I)
RX_BUF_RING_SIZE = 1024
MAX_ERRORS_TO_PRINT = 10
MAX_WARNINGS = 10

def log_warning(msg):
    print(f"⚠️  {msg}")

def log_error(msg):
    print(f"❌ {msg}")

def align_up(size, align):
    return ((size + align - 1) // align) * align

def format_value(kb, unit):
    if unit == 'KB':
        return kb
    elif unit == 'MB':
        return kb / 1024
    elif unit == 'GB':
        return kb / 1024 / 1024
    return kb

def get_buffer_size_from_mtu(mtu):
    if mtu <= 1500:
        return 2048
    elif mtu <= 9000:
        return 16384
    else:
        return align_up(mtu + 128, 2048)

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

def is_bridge_port(netdev):
    return bool(int(netdev.priv_flags) & IFF_BRIDGE_PORT)

def parse_netdev_ops(netdev_ops, debug=False):
    sym_output = exec_crash_command(f"sym {hex(netdev_ops)}").strip()
    if debug:
        print(f"DEBUG: sym_output = {sym_output}")

    match = re.search(r'(\S+)\s+\[\s*(\w+)\s*\]', sym_output)
    if match:
        return match.groups()

    parts = sym_output.strip().split()
    if len(parts) >= 3:
        return parts[2], "<builtin>"
    if parts:
        return parts[0], "<unknown>"
    return None, "<unknown>"

def analyze_by_ops(dev_addr, func_name, buffer_size, verbose=False, debug=False):
    if func_name == "bnxt_netdev_ops":
        return analyze_bnxt(dev_addr, buffer_size, verbose, debug)
    if func_name == "tg3_netdev_ops":
        return analyze_tg3(dev_addr, buffer_size, verbose, debug)
    if func_name == "ice_netdev_ops":
        return analyze_ice(dev_addr, buffer_size, verbose, debug)
    if func_name == "virtnet_netdev":
        return analyze_virtio_net(dev_addr, buffer_size, verbose, debug)
    if func_name == "igb_netdev_ops":
        return analyze_igb(dev_addr, buffer_size, verbose, debug)
    if func_name.startswith("vmxnet3_netdev_ops"):
        return analyze_vmxnet3(dev_addr, buffer_size, verbose, debug)
    if func_name in ("efx_netdev_ops", "ef100_netdev_ops"):
        return analyze_sfc(dev_addr, buffer_size, verbose, debug)
    return None

def analyze_bridge(br_addr, buffer_size, verbose=False, debug=False, analyzed_ports=None):
    """
    Linux bridge master (br_netdev_ops): aggregate RX/TX ring buffers from enslaved ports.
    sctp*/psctp* interfaces in VMware setups are often bridge masters, not hardware NICs.
    """
    MAX_PORTS = 64
    analyzed_ports = analyzed_ports if analyzed_ports is not None else set()

    try:
        netdev_size = crash.struct_size("struct net_device")
        port_list_off = crash.member_offset("struct net_bridge", "port_list")
        port_list_ent_off = crash.member_offset("struct net_bridge_port", "list")
        port_dev_off = crash.member_offset("struct net_bridge_port", "dev")

        head = br_addr + port_list_off
        cur = readPtr(head)

        total_rx_buffers = 0
        total_tx_buffers = 0
        port_names = []

        iterations = 0
        while cur != head and iterations < MAX_PORTS:
            if cur in (0, 0xffffffffffffffff):
                break

            port_addr = cur - port_list_ent_off
            port_dev = readPtr(port_addr + port_dev_off)
            if port_dev not in (0, 0xffffffffffffffff):
                analyzed_ports.add(port_dev)
                try:
                    port_netdev = readSU("struct net_device", port_dev)
                    port_name = str(port_netdev.name).strip("\x00")
                    port_mtu = int(port_netdev.mtu)
                    port_buffer_size = get_buffer_size_from_mtu(port_mtu)
                    port_ops = int(port_netdev.netdev_ops)
                    port_func, _ = parse_netdev_ops(port_ops, debug)
                    if debug:
                        print(f"DEBUG: bridge port '{port_name}' @ {hex(port_dev)} ops={port_func}")

                    sub = analyze_by_ops(port_dev, port_func, port_buffer_size, verbose, debug)
                    if sub:
                        total_rx_buffers += sub["rx_buffers"]
                        total_tx_buffers += sub["tx_buffers"]
                        port_names.append(port_name)
                except Exception as e:
                    if debug:
                        print(f"DEBUG: failed to analyze bridge port @ {hex(port_dev)}: {e}")

            cur = readPtr(cur)
            iterations += 1

        if debug:
            print(f"DEBUG: bridge @ {hex(br_addr)} ports analyzed: {port_names}")

        return {
            "driver": "bridge",
            "rx_buffers": total_rx_buffers,
            "tx_buffers": total_tx_buffers,
            "rx_bytes": total_rx_buffers * buffer_size,
            "tx_bytes": total_tx_buffers * buffer_size,
        }

    except Exception as e:
        print(f"❌ Error analyzing bridge: {e}")
        return None

def analyze_bnxt(netdev_addr, buffer_size, verbose=False, debug=False):
    try:
        netdev_size = crash.struct_size("net_device")
        aligned_size = align_up(netdev_size, 32)
        bnxt_addr = netdev_addr + aligned_size
        if debug:
            print(f"DEBUG: bnxt {hex(bnxt_addr)}")

        # Offset helpers
        rx_ring_off = crash.member_offset("bnxt", "rx_ring")
        cp_off = crash.member_offset("bnxt", "cp_nr_rings")
        tx_ring_off = crash.member_offset("bnxt", "tx_ring")
        tx_nr_rings_off = crash.member_offset("bnxt", "tx_nr_rings")

        rx_ring_struct_off = crash.member_offset("bnxt_rx_ring_info", "rx_ring_struct")
        tx_ring_info_struct_off = crash.member_offset("bnxt_tx_ring_info", "tx_ring_struct")
        ring_mem_off = crash.member_offset("bnxt_ring_struct", "ring_mem")
        depth_off = crash.member_offset("bnxt_ring_mem_info", "depth")
        vmem_size_off = crash.member_offset("bnxt_ring_mem_info", "vmem_size")

        # RX setup
        rx_ring_ptr = readPtr(bnxt_addr + rx_ring_off)
        num_rx_rings = readU16(bnxt_addr + cp_off)
        rx_bd_size = crash.struct_size("bnxt_sw_rx_bd")
        rx_data_off = crash.member_offset("bnxt_sw_rx_bd", "data")
        rx_ring_info_size = crash.struct_size("bnxt_rx_ring_info")

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
        tx_ring_info_size = crash.struct_size("bnxt_tx_ring_info")
        tx_bd_size = crash.struct_size("tx_bd")
        tx_data_off = crash.member_offset("tx_bd", "tx_bd_haddr")

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
    DEFAULT_RING_SIZE = 1024
    MAX_RING_SIZE = 8192
    ERROR_LOG_LIMIT = 10

    def log_read_error(addr, error_count, label="descriptor", limit=ERROR_LOG_LIMIT):
        if error_count < limit:
            print(f"⚠️  tg3: unreadable {label} at {hex(addr)}")
        elif error_count == limit:
            print(f"⚠️  tg3: Further unreadable {label}s suppressed...")

    try:
        netdev_size = crash.struct_size("net_device")
        aligned_size = align_up(netdev_size, 32)
        tg3_addr = dev_addr + aligned_size
        if debug:
            print(f"DEBUG: tg3 struct at {hex(tg3_addr)}")

        tg3 = readSU("struct tg3", tg3_addr)

        napi_off = crash.member_offset("tg3", "napi")
        napi_size = crash.struct_size("tg3_napi")
        rx_rcb_off = crash.member_offset("tg3_napi", "rx_rcb")
        tx_ring_off = crash.member_offset("tg3_napi", "tx_ring")
        tx_pending_off = crash.member_offset("tg3_napi", "tx_pending")

        rx_desc_size = crash.struct_size("tg3_rx_buffer_desc")
        tx_desc_size = crash.struct_size("tg3_tx_buffer_desc")

        total_rx_buffers = 0
        total_tx_buffers = 0

        for i in range(5):  # tg3 has napi[5]
            napi_addr = tg3_addr + napi_off + i * napi_size
            napi = readSU("struct tg3_napi", napi_addr)
            if debug:
                print(f"DEBUG: [NAPI {i}] struct tg3_napi at {hex(napi_addr)}")

            # RX analysis
            rx_rcb_ptr = int(napi.rx_rcb)
            rx_ring_size = DEFAULT_RING_SIZE

            if rx_rcb_ptr not in (0, 0xffffffffffffffff):
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
                        if verbose or debug:
                            log_read_error(desc_addr, error_count, label="RX descriptor")
                        error_count += 1
                        continue

                total_rx_buffers += rx_count
                if debug:
                    print(f"DEBUG: [NAPI {i}] RX buffers allocated: {rx_count} / {rx_ring_size}")
            else:
                if debug:
                    print(f"DEBUG: [NAPI {i}] rx_rcb_ptr = {hex(rx_rcb_ptr)} — skipping")

            # TX analysis
            tx_ring_ptr = int(napi.tx_ring)
            try:
                tx_ring_size = readInt(napi_addr + tx_pending_off)
                if tx_ring_size == 0 or tx_ring_size > MAX_RING_SIZE:
                    tx_ring_size = DEFAULT_RING_SIZE
                    if debug:
                        print(f"DEBUG: [NAPI {i}] TX ring depth fallback to {DEFAULT_RING_SIZE}")
                else:
                    if debug:
                        print(f"DEBUG: [NAPI {i}] TX ring depth = {tx_ring_size}")
            except:
                tx_ring_size = DEFAULT_RING_SIZE
                if debug:
                    print(f"DEBUG: [NAPI {i}] Failed to read tx_pending — fallback to {DEFAULT_RING_SIZE}")

            if tx_ring_ptr not in (0, 0xffffffffffffffff):
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
                        log_read_error(desc_addr, error_count, label="TX descriptor")
                        error_count += 1
                        continue

                total_tx_buffers += tx_count
                if debug:
                    print(f"DEBUG: [NAPI {i}] TX buffers allocated: {tx_count} / {tx_ring_size}")
            else:
                if debug:
                    print(f"DEBUG: [NAPI {i}] tx_ring_ptr = {hex(tx_ring_ptr)} — skipping")

        if total_rx_buffers == 0 and total_tx_buffers == 0:
            print("ℹ️  No RX/TX buffers found — descriptor memory may be unavailable in the dump.")

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
        netdev_size = crash.struct_size("net_device")
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

        rx_ring_size = crash.struct_size("ice_rx_ring")
        tx_ring_size = crash.struct_size("ice_tx_ring")
        rx_buf_size = crash.struct_size("ice_rx_buf")
        tx_buf_size = crash.struct_size("ice_tx_buf")
        dma_off = crash.member_offset("ice_rx_buf", "dma")
        tx_dma_off = crash.member_offset("ice_tx_buf", "dma")

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
        ml_priv_offset = crash.member_offset("net_device", "ml_priv")
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

        rxq_size = crash.struct_size("receive_queue")
        txq_size = crash.struct_size("send_queue")

        for i in range(curr_qpairs):
            # RX ring analysis
            rq_ptr = readPtr(priv_ptr + crash.member_offset("virtnet_info", "rq") + i * 8)
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
            sq_ptr = readPtr(priv_ptr + crash.member_offset("virtnet_info", "sq") + i * 8)
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

def analyze_igb(dev_addr, buffer_size, verbose=False, debug=False):
    DEFAULT_RING_SIZE = 1024
    MAX_RING_SIZE = 8192
    PTR_SIZE = 8  # 64-bit systems
    ERROR_LOG_LIMIT = 10

    def log_read_error(addr, error_count, label="descriptor", limit=ERROR_LOG_LIMIT):
        if error_count < limit:
            print(f"⚠️  igb: unreadable {label} at {hex(addr)}")
        elif error_count == limit:
            print(f"⚠️  igb: Further unreadable {label}s suppressed...")

    try:
        netdev_size = crash.struct_size("struct net_device")
        aligned_size = ((netdev_size + 31) // 32) * 32
        adapter_addr = dev_addr + aligned_size
        if debug:
            print(f"DEBUG: igb_adapter struct at {hex(adapter_addr)}")

        adapter = readSU("struct igb_adapter", adapter_addr)

        num_rx_queues = int(adapter.num_rx_queues)
        num_tx_queues = int(adapter.num_tx_queues)

        rx_ring_off = crash.member_offset("igb_adapter", "rx_ring")
        tx_ring_off = crash.member_offset("igb_adapter", "tx_ring")

        rx_desc_size = crash.struct_size("union e1000_rx_desc")
        tx_desc_size = crash.struct_size("union e1000_tx_desc")
        ring_struct_size = crash.struct_size("struct igb_ring")

        desc_field_off = crash.member_offset("igb_ring", "desc")
        count_field_off = crash.member_offset("igb_ring", "count")

        total_rx_buffers = 0
        total_tx_buffers = 0

        # RX Rings
        for i in range(num_rx_queues):
            ring_ptr_addr = adapter_addr + rx_ring_off + i * PTR_SIZE
            ring_ptr = readPtr(ring_ptr_addr)
            if ring_ptr in (0, 0xffffffffffffffff):
                if debug:
                    print(f"DEBUG: RX ring {i} pointer is invalid ({hex(ring_ptr)})")
                continue

            ring_count = int.from_bytes(readmem(ring_ptr + count_field_off, 4), 'little')
            ring_count = ring_count if 0 < ring_count <= MAX_RING_SIZE else DEFAULT_RING_SIZE

            desc_ptr = readPtr(ring_ptr + desc_field_off)
            rx_count = 0
            error_count = 0

            for j in range(ring_count):
                desc_addr = desc_ptr + j * rx_desc_size
                try:
                    val = int.from_bytes(readmem(desc_addr, 8), 'little')  # addr in desc
                    if val != 0:
                        rx_count += 1
                        if verbose:
                            print(f"[RX {i}:{j:04d}] addr = {hex(val)}")
                except:
                    log_read_error(desc_addr, error_count, label="RX descriptor")
                    error_count += 1
                    continue

            total_rx_buffers += rx_count
            if debug:
                print(f"DEBUG: [RX {i}] Buffers allocated: {rx_count} / {ring_count}")

        # TX Rings
        for i in range(num_tx_queues):
            ring_ptr_addr = adapter_addr + tx_ring_off + i * PTR_SIZE
            ring_ptr = readPtr(ring_ptr_addr)
            if ring_ptr in (0, 0xffffffffffffffff):
                if debug:
                    print(f"DEBUG: TX ring {i} pointer is invalid ({hex(ring_ptr)})")
                continue

            ring_count = int.from_bytes(readmem(ring_ptr + count_field_off, 4), 'little')
            ring_count = ring_count if 0 < ring_count <= MAX_RING_SIZE else DEFAULT_RING_SIZE

            desc_ptr = readPtr(ring_ptr + desc_field_off)
            tx_count = 0
            error_count = 0

            for j in range(ring_count):
                desc_addr = desc_ptr + j * tx_desc_size
                try:
                    val = int.from_bytes(readmem(desc_addr, 8), 'little')  # addr in desc
                    if val != 0:
                        tx_count += 1
                        if verbose:
                            print(f"[TX {i}:{j:04d}] addr = {hex(val)}")
                except:
                    log_read_error(desc_addr, error_count, label="TX descriptor")
                    error_count += 1
                    continue

            total_tx_buffers += tx_count
            if debug:
                print(f"DEBUG: [TX {i}] Buffers allocated: {tx_count} / {ring_count}")

        if total_rx_buffers == 0 and total_tx_buffers == 0:
            print("ℹ️  No RX/TX buffers found — descriptor memory may be unavailable in the dump.")

        return {
            "driver": "igb",
            "rx_buffers": total_rx_buffers,
            "tx_buffers": total_tx_buffers,
            "rx_bytes": total_rx_buffers * buffer_size,
            "tx_bytes": total_tx_buffers * buffer_size
        }

    except Exception as e:
        print(f"❌ Error analyzing igb: {e}")
        return None

def analyze_vmxnet3(dev_addr, buffer_size, verbose=False, debug=False):
    DEFAULT_RING_SIZE = 512
    MAX_QUEUES = 32
    PTR_SIZE = 8

    def log_read_error(addr, error_count, label="descriptor", limit=10):
        if error_count < limit:
            print(f"⚠️  vmxnet3: unreadable {label} at {hex(addr)}")
        elif error_count == limit:
            print(f"⚠️  vmxnet3: Further unreadable {label}s suppressed...")

    try:
        # Step 1: locate struct vmxnet3_adapter
        netdev_size = crash.struct_size("struct net_device")
        aligned_size = ((netdev_size + 31) // 32) * 32
        adapter_addr = dev_addr + aligned_size
        adapter = readSU("struct vmxnet3_adapter", adapter_addr)

        num_rx_queues = int(adapter.num_rx_queues)
        num_tx_queues = int(adapter.num_tx_queues)

        if debug:
            print(f"DEBUG: vmxnet3_adapter @ {hex(adapter_addr)}")
            print(f"DEBUG: RX queues = {num_rx_queues}, TX queues = {num_tx_queues}")

        rx_queue_base = adapter_addr + crash.member_offset("struct vmxnet3_adapter", "rx_queue")
        tx_queue_base = adapter_addr + crash.member_offset("struct vmxnet3_adapter", "tx_queue")
        rxq_size = crash.struct_size("struct vmxnet3_rx_queue")
        txq_size = crash.struct_size("struct vmxnet3_tx_queue")
        bufinfo_ptr_off_rx = crash.member_offset("struct vmxnet3_rx_queue", "buf_info")
        bufinfo_ptr_off_tx = crash.member_offset("struct vmxnet3_tx_queue", "buf_info")

        total_rx_buffers = 0
        total_tx_buffers = 0

        # RX ring analysis
        for i in range(min(num_rx_queues, MAX_QUEUES)):
            rxq_addr = rx_queue_base + i * rxq_size
            buf_info_ptr0_addr = rxq_addr + bufinfo_ptr_off_rx

            buf0_ptr = readPtr(buf_info_ptr0_addr)  # buf_info[0]
            if buf0_ptr in (0, 0xffffffffffffffff):
                if debug:
                    print(f"DEBUG: RX queue {i} buf_info[0] is invalid")
                continue

            error_count = 0
            rx_count = 0
            for j in range(DEFAULT_RING_SIZE):
                entry_addr = buf0_ptr + j * PTR_SIZE
                try:
                    val = readPtr(entry_addr)
                    if val != 0:
                        rx_count += 1
                        if verbose:
                            print(f"[RX {i}:{j:04d}] buf DMA = {hex(val)}")
                except:
                    log_read_error(entry_addr, error_count, label="RX buffer")
                    error_count += 1
                    continue

            total_rx_buffers += rx_count
            if debug:
                print(f"DEBUG: RX queue {i} buffers allocated: {rx_count}")

        # TX ring analysis
        for i in range(min(num_tx_queues, MAX_QUEUES)):
            txq_addr = tx_queue_base + i * txq_size
            buf_info_ptr_addr = txq_addr + bufinfo_ptr_off_tx
            buf_info_ptr = readPtr(buf_info_ptr_addr)

            if buf_info_ptr in (0, 0xffffffffffffffff):
                if debug:
                    print(f"DEBUG: TX queue {i} buf_info is invalid")
                continue

            error_count = 0
            tx_count = 0
            for j in range(DEFAULT_RING_SIZE):
                entry_addr = buf_info_ptr + j * PTR_SIZE
                try:
                    val = readPtr(entry_addr)
                    if val != 0:
                        tx_count += 1
                        if verbose:
                            print(f"[TX {i}:{j:04d}] buf DMA = {hex(val)}")
                except:
                    log_read_error(entry_addr, error_count, label="TX buffer")
                    error_count += 1
                    continue

            total_tx_buffers += tx_count
            if debug:
                print(f"DEBUG: TX queue {i} buffers allocated: {tx_count}")

        if total_rx_buffers == 0 and total_tx_buffers == 0:
            print("ℹ️  No RX/TX buffers found — descriptor memory may be unavailable in the dump.")

        return {
            "driver": "vmxnet3",
            "rx_buffers": total_rx_buffers,
            "tx_buffers": total_tx_buffers,
            "rx_bytes": total_rx_buffers * buffer_size,
            "tx_bytes": total_tx_buffers * buffer_size
        }

    except Exception as e:
        print(f"❌ Error analyzing vmxnet3: {e}")
        return None

def analyze_sfc(dev_addr, buffer_size, verbose=False, debug=False):
    """
    Solarflare / Xilinx sfc driver (efx_netdev_ops, ef100_netdev_ops).
    net_device private area holds a pointer to struct efx_probe_data; efx_nic is embedded there.
    """
    MAX_CHANNELS = 32
    MAX_TXQ_PER_CHANNEL = 4
    MAX_RING_SIZE = 8192
    DEFAULT_RING_SIZE = 1024
    PTR_SIZE = 8
    ERROR_LOG_LIMIT = 10

    def log_read_error(addr, error_count, label="buffer", limit=ERROR_LOG_LIMIT):
        if error_count < limit:
            print(f"⚠️  sfc: unreadable {label} at {hex(addr)}")
        elif error_count == limit:
            print(f"⚠️  sfc: Further unreadable {label}s suppressed...")

    try:
        netdev_size = crash.struct_size("struct net_device")
        probe_ptr = readPtr(dev_addr + netdev_size)
        if probe_ptr in (0, 0xffffffffffffffff):
            if debug:
                print(f"DEBUG: sfc probe_data pointer invalid: {hex(probe_ptr)}")
            return None

        efx_addr = probe_ptr + crash.member_offset("struct efx_probe_data", "efx")
        if debug:
            print(f"DEBUG: efx_probe_data @ {hex(probe_ptr)}, efx_nic @ {hex(efx_addr)}")

        efx = readSU("struct efx_nic", efx_addr)
        n_channels = min(int(efx.n_channels), MAX_CHANNELS)
        rxq_entries = int(efx.rxq_entries)
        txq_entries = int(efx.txq_entries)
        tx_queues_per_channel = int(efx.tx_queues_per_channel) or 1
        tx_queues_per_channel = min(tx_queues_per_channel, MAX_TXQ_PER_CHANNEL)

        channel_off = crash.member_offset("struct efx_nic", "channel")
        rx_queue_off = crash.member_offset("struct efx_channel", "rx_queue")
        tx_queue_off = crash.member_offset("struct efx_channel", "tx_queue")
        txq_size = crash.struct_size("struct efx_tx_queue")

        rx_buf_size = crash.struct_size("struct efx_rx_buffer")
        tx_buf_size = crash.struct_size("struct efx_tx_buffer")
        rx_dma_off = crash.member_offset("struct efx_rx_buffer", "dma_addr")
        tx_dma_off = crash.member_offset("struct efx_tx_buffer", "dma_addr")
        rx_buffer_off = crash.member_offset("struct efx_rx_queue", "buffer")
        rx_ptr_mask_off = crash.member_offset("struct efx_rx_queue", "ptr_mask")
        tx_buffer_off = crash.member_offset("struct efx_tx_queue", "buffer")
        tx_ptr_mask_off = crash.member_offset("struct efx_tx_queue", "ptr_mask")
        tx_init_off = crash.member_offset("struct efx_tx_queue", "initialised")

        total_rx_buffers = 0
        total_tx_buffers = 0

        for i in range(n_channels):
            channel_ptr = readPtr(efx_addr + channel_off + i * PTR_SIZE)
            if channel_ptr in (0, 0xffffffffffffffff):
                if debug:
                    print(f"DEBUG: channel {i} pointer invalid: {hex(channel_ptr)}")
                continue

            if debug:
                print(f"DEBUG: efx_channel {i} @ {hex(channel_ptr)}")

            # RX: embedded efx_rx_queue in each channel
            rxq_addr = channel_ptr + rx_queue_off
            rx_buf_ring = readPtr(rxq_addr + rx_buffer_off)
            if rx_buf_ring not in (0, 0xffffffffffffffff):
                ptr_mask = int.from_bytes(readmem(rxq_addr + rx_ptr_mask_off, 4), "little")
                ring_size = (ptr_mask + 1) if ptr_mask else rxq_entries
                if ring_size == 0 or ring_size > MAX_RING_SIZE:
                    ring_size = DEFAULT_RING_SIZE

                rx_count = 0
                error_count = 0
                for j in range(ring_size):
                    entry_addr = rx_buf_ring + j * rx_buf_size
                    try:
                        dma_val = readULong(entry_addr + rx_dma_off)
                        if dma_val:
                            rx_count += 1
                            if verbose:
                                print(f"[RX {i}:{j:04d}] dma = {hex(dma_val)}")
                    except Exception:
                        log_read_error(entry_addr, error_count, label="RX buffer")
                        error_count += 1

                total_rx_buffers += rx_count
                if debug:
                    print(f"DEBUG: RX channel {i}: active buffers = {rx_count}/{ring_size}")
            elif debug:
                print(f"DEBUG: RX channel {i}: buffer ring unavailable")

            # TX: up to tx_queues_per_channel queues per channel
            for t in range(tx_queues_per_channel):
                txq_addr = channel_ptr + tx_queue_off + t * txq_size
                try:
                    initialised = int.from_bytes(readmem(txq_addr + tx_init_off, 1), "little")
                except Exception:
                    initialised = 0
                if not initialised:
                    if debug:
                        print(f"DEBUG: TX channel {i} queue {t} not initialised — skipping")
                    continue

                tx_buf_ring = readPtr(txq_addr + tx_buffer_off)
                if tx_buf_ring in (0, 0xffffffffffffffff):
                    if debug:
                        print(f"DEBUG: TX channel {i} queue {t} buffer ring invalid")
                    continue

                ptr_mask = int.from_bytes(readmem(txq_addr + tx_ptr_mask_off, 4), "little")
                ring_size = (ptr_mask + 1) if ptr_mask else txq_entries
                if ring_size == 0 or ring_size > MAX_RING_SIZE:
                    ring_size = DEFAULT_RING_SIZE

                tx_count = 0
                error_count = 0
                for j in range(ring_size):
                    entry_addr = tx_buf_ring + j * tx_buf_size
                    try:
                        dma_val = readULong(entry_addr + tx_dma_off)
                        if dma_val:
                            tx_count += 1
                            if verbose:
                                print(f"[TX {i}:{t}:{j:04d}] dma = {hex(dma_val)}")
                    except Exception:
                        log_read_error(entry_addr, error_count, label="TX buffer")
                        error_count += 1

                total_tx_buffers += tx_count
                if debug:
                    print(f"DEBUG: TX channel {i} queue {t}: active buffers = {tx_count}/{ring_size}")

        if total_rx_buffers == 0 and total_tx_buffers == 0:
            print("ℹ️  No RX/TX buffers found — descriptor memory may be unavailable in the dump.")

        return {
            "driver": "sfc",
            "rx_buffers": total_rx_buffers,
            "tx_buffers": total_tx_buffers,
            "rx_bytes": total_rx_buffers * buffer_size,
            "tx_bytes": total_tx_buffers * buffer_size,
        }

    except Exception as e:
        print(f"❌ Error analyzing sfc: {e}")
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose RX/TX entry info")

    unit_group = parser.add_mutually_exclusive_group()
    unit_group.add_argument('-K', '--kilobytes', action='store_const', const='KB', dest='unit', help="Display values in kilobytes")
    unit_group.add_argument('-M', '--megabytes', action='store_const', const='MB', dest='unit', help="Display values in megabytes")
    unit_group.add_argument('-G', '--gigabytes', action='store_const', const='GB', dest='unit', help="Display values in gigabytes")
    parser.set_defaults(unit='KB')

    args = parser.parse_args()

    print(f"{'Device':<12} {'Driver':<10} {'MTU':>6} {'RX Buffers':>12} {'TX Buffers':>12} "
          f"{f'RX Usage ({args.unit})':>15} {f'TX Usage ({args.unit})':>15}")

    print("=" * 88)

    total_rx_buffers = 0
    total_tx_buffers = 0
    total_rx_bytes = 0
    total_tx_bytes = 0
    analyzed_bridge_ports = set()
    netdev_size = crash.struct_size("struct net_device")

    known_builtin_drivers = {
        "loopback_ops": "loopback device",
        "team_netdev_ops": "virtual device",
        "internal_dev_netdev_ops": "virtual device",
        "ipgre_netdev_ops": "tunnel device",
        "gre_tap_netdev_ops": "tunnel device",
        "erspan_netdev_ops": "tunnel device",
        "vxlan_netdev_ether_ops": "tunnel device",
    }

    devices = []
    for addr in parse_net_devices(args.debug):
        try:
            netdev = readSU("struct net_device", addr)
            name = str(netdev.name).strip("\x00")
            mtu = int(netdev.mtu)
            max_mtu = int(netdev.max_mtu)
            buffer_size = get_buffer_size_from_mtu(mtu)
            netdev_ops = int(netdev.netdev_ops)
            func_name, module_name = parse_netdev_ops(netdev_ops, args.debug)

            if args.debug:
                print(f"DEBUG: Got net_device at {hex(addr)}, name = '{name}'")
                print(f"DEBUG: MTU = {mtu}, max_mtu = {max_mtu}, buffer_size = {buffer_size}")
                print(f"DEBUG: Found netdev_ops: {func_name} in module {module_name}")

            devices.append((addr, netdev, name, mtu, buffer_size, func_name))
        except Exception as e:
            print(f"⚠️  Failed to read device at {hex(addr)}: {e}")

    # Bridge masters first so enslaved port addrs are marked before hardware pass.
    devices.sort(key=lambda d: (0 if d[5] == "br_netdev_ops" else 1, d[2]))

    for addr, netdev, name, mtu, buffer_size, func_name in devices:
        try:
            # Check for known skip reasons
            if func_name in known_builtin_drivers:
                note = known_builtin_drivers[func_name]
                if args.debug:
                    print(f"DEBUG: ⚠️  Skipping {name}: {note}")
                print(f"{name:<12} {'-':<10} {'-':>6} {'-':>12} {'-':>12} {'-':>15} {'-':>15}  # skipped: {note}")
                continue

            if is_bridge_port(netdev) and not SCTP_IFACE_RE.match(name):
                note = "bridge port (counted under bridge master)"
                if args.debug:
                    print(f"DEBUG: ⚠️  Skipping {name}: {note}")
                print(f"{name:<12} {'-':<10} {'-':>6} {'-':>12} {'-':>12} {'-':>15} {'-':>15}  # skipped: {note}")
                continue

            if addr in analyzed_bridge_ports:
                note = "bridge port (already counted)"
                if args.debug:
                    print(f"DEBUG: ⚠️  Skipping {name}: {note}")
                print(f"{name:<12} {'-':<10} {'-':>6} {'-':>12} {'-':>12} {'-':>15} {'-':>15}  # skipped: {note}")
                continue

            # Process supported drivers
            if func_name == "br_netdev_ops":
                result = analyze_bridge(
                    addr + netdev_size, buffer_size, args.verbose, args.debug, analyzed_bridge_ports
                )
            else:
                result = analyze_by_ops(addr, func_name, buffer_size, args.verbose, args.debug)
                if result is None:
                    note = f"unsupported driver ({func_name})"
                    if args.debug:
                        print(f"DEBUG: ⚠️  Skipping {name}: {note}")
                    print(f"{name:<12} {'-':<10} {'-':>6} {'-':>12} {'-':>12} {'-':>15} {'-':>15}  # skipped: {note}")
                    continue

            if result:
                rx_usage = format_value(result['rx_bytes'] / 1024, args.unit)
                tx_usage = format_value(result['tx_bytes'] / 1024, args.unit)
                print(f"{name:<12} {result['driver']:<10} {mtu:>6} {result['rx_buffers']:>12} {result['tx_buffers']:>12} "
                      f"{rx_usage:>15,.2f} {tx_usage:>15,.2f}")
                total_rx_buffers += result["rx_buffers"]
                total_tx_buffers += result["tx_buffers"]
                total_rx_bytes += result["rx_bytes"]
                total_tx_bytes += result["tx_bytes"]

        except Exception as e:
            print(f"⚠️  Failed to analyze device at {hex(addr)} ({name}): {e}")

    total_rx = format_value(total_rx_bytes / 1024, args.unit)
    total_tx = format_value(total_tx_bytes / 1024, args.unit)
    total_rx_tx = format_value((total_rx_bytes + total_tx_bytes) / 1024, args.unit)

    print("=" * 88)
    print(f"{'':<12} {'':<10} {'':>6} {total_rx_buffers:>12} {total_tx_buffers:>12} "
          f"{total_rx:>15,.2f} {total_tx:>15,.2f}")
    print("=" * 88)
    print(f"{'TOTAL':<12} {'':<10} {'':>6} {'':>12} {'':>12} "
          f"{'':>15} {total_rx_tx:>15,.2f}")


if __name__ == "__main__":
    main()

