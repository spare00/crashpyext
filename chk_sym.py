from pykdump.API import *
import fnmatch
import sys

def chk_sym(patterns):
    """
    Print kernel symbols matching wildcard pattern(s).
    Usage:
        chk_sym <pattern1> [pattern2] ...
    Example:
        chk_sym vm_dirty* vm_swappiness
    """
    # Step 1: Get the entire symbol table
    all_syms = exec_crash_command("sym -l").splitlines()

    # Step 2: Extract the last field (the symbol name)
    sym_names = []
    for line in all_syms:
        parts = line.split()
        if parts:
            sym_names.append(parts[-1])

    # Step 3: Match each pattern against the list
    found = False
    for pat in patterns:
        matches = [s for s in sym_names if fnmatch.fnmatch(s, pat)]
        if not matches:
            print(f"No symbols matched: {pat}")
            continue

        found = True
        for sym in matches:
            try:
                val = readSymbol(sym)
                print(f"{sym} = {val}")
            except Exception as e:
                print(f"{sym}: <error reading> ({e})")

    if not found:
        print("No matching symbols found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: chk_sym <pattern1> [pattern2] ...")
    else:
        chk_sym(sys.argv[1:])
