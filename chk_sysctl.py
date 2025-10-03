from LinuxDump import sysctl
import fnmatch
import sys
import argparse

def chk_sysctl(patterns, verbose=0, substring=False):
    """
    Print sysctl tunables matching given pattern(s).
    By default, fnmatch globbing is used.
    If substring=True, patterns are treated as simple substrings.
    """
    ctbl = sysctl.getCtlTables()   # dict: name -> ctl_table
    names = sorted(ctbl.keys())

    found = False
    for pat in patterns:
        if substring:
            matches = [n for n in names if pat in n]
        else:
            # if user didn’t give wildcards, auto-wrap with *
            if "*" not in pat and "?" not in pat:
                pat = f"*{pat}*"
            matches = [n for n in names if fnmatch.fnmatch(n, pat)]

        if not matches:
            print(f"No sysctl entries matched: {pat}")
            continue

        found = True
        for n in matches:
            ct = ctbl[n]
            try:
                val = sysctl.getCtlData(ct)
            except Exception:
                val = "(?)"

            if verbose > 1:
                from pykdump.API import addr2sym
                phandler = addr2sym(ct.proc_handler)
                print(f"----- {ct} ------ handler={phandler}")

            print(f"{n.ljust(30)} {val}")

    if not found:
        print("No matching sysctl tunables.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Search sysctl tunables in vmcore via PyKdump"
    )
    parser.add_argument(
        "patterns", nargs="+",
        help="Patterns to search (globs by default, substring if --substr)"
    )
    parser.add_argument(
        "-s", "--substr", action="store_true",
        help="Enable substring search mode instead of globbing"
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity (-v, -vv for more)"
    )

    args = parser.parse_args()

    chk_sysctl(args.patterns, verbose=args.verbose, substring=args.substr)
