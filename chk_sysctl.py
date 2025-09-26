from LinuxDump import sysctl
import fnmatch
import sys

def chk_sysctl(patterns, verbose=0):
    """
    Print sysctl tunables matching wildcard pattern(s).
    """
    ctbl = sysctl.getCtlTables()   # dict: name -> ctl_table
    names = sorted(ctbl.keys())

    found = False
    for pat in patterns:
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
    if len(sys.argv) < 2:
        print("Usage: chk_sym <pattern1> [pattern2] ...")
    else:
        chk_sysctl(sys.argv[1:], verbose=1)
