#!/usr/bin/env python3
import argparse
import sys

import qspinlock
import mutex
import rwsem

def main():
    parser = argparse.ArgumentParser(description="Unified Lock Analyzer for VMcore")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # qspinlock
    p_qs = subparsers.add_parser("qspinlock", help="Analyze qspinlock state")
    p_qs.add_argument("addr", help="Address or symbol")
    p_qs.add_argument("-f", "--flowchart", action="store_true")
    p_qs.add_argument("-v", "--verbose", action="store_true")
    p_qs.add_argument("-d", "--debug", action="store_true")

    # spinlock (wrapper around qspinlock)
    p_sl = subparsers.add_parser("spinlock", help="Analyze spinlock_t")
    p_sl.add_argument("addr", help="Address or symbol")
    p_sl.add_argument("-v", "--verbose", action="store_true")
    p_sl.add_argument("-d", "--debug", action="store_true")

    # mutex
    p_mx = subparsers.add_parser("mutex", help="Analyze mutex")
    p_mx.add_argument("addr", help="Address or symbol")
    p_mx.add_argument("-l", "--list", action="store_true")

    # rwsem
    p_rw = subparsers.add_parser("rwsem", help="Analyze rw_semaphore")
    p_rw.add_argument("addr", help="Address (hex)")
    p_rw.add_argument("-l", "--list", action="store_true")
    p_rw.add_argument("-v", "--verbose", action="store_true")
    p_rw.add_argument("-d", "--debug", action="store_true")

    args = parser.parse_args()

    if args.command == "qspinlock":
        qspinlock.RHEL_VERSION = qspinlock.get_rhel_version()
        if args.flowchart:
            qspinlock.show_qspinlock_flowchart()
        qspinlock.analyze_qspinlock(
            qspinlock.resolve_address(args.addr),
            args.verbose,
            args.debug
        )

    elif args.command == "spinlock":
        qspinlock.RHEL_VERSION = qspinlock.get_rhel_version()
        qspinlock.analyze_spinlock(
            qspinlock.resolve_address(args.addr),
            args.verbose,
            args.debug
        )

    elif args.command == "mutex":
        mutex.rhel_version = mutex.get_rhel_version()
        addr = mutex.resolve_address(args.addr)
        info = mutex.get_mutex_info(addr, args.list)
        mutex.analyze_mutex(info)

    elif args.command == "rwsem":
        rwsem.RHEL_VERSION = rwsem.get_rhel_version()
        rwsem.DEBUG = args.debug
        rwsem.analyze_rw_semaphore_from_vmcore(
            int(args.addr, 16),
            args.list,
            args.verbose,
            args.debug
        )

if __name__ == "__main__":
    main()

