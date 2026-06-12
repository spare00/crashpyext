# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a collection of Python scripts for automated Linux kernel vmcore analysis inside the crash utility. The tools run via `epython` (crash's embedded Python interpreter) and leverage `pykdump.API` to analyze kernel data structures from crash dumps.

**Key characteristics:**
- Target environment: crash utility with epython support (mpykdumpx86_64.so extension)
- Primary API: `pykdump.API` for kernel structure access
- Deployment: scripts are registered as crash aliases via `setup_chk_tools.py`
- Supports RHEL 7/8/9 with architecture-specific logic (x86_64, aarch64)

## Architecture

### Module Categories

**Lock analyzers** (unified under `chk_lock.py`):
- `chk_lock.py` — unified entry point with shared infrastructure (version detection, architecture, task state, address resolution)
- `mutex.py`, `rwsem.py`, `qspinlock.py`, `semaphore.py` — lock-specific analysis modules
- Each lock module imports from `chk_lock.py` and expects globals to be injected via `_push_globals()`

**Standalone analysis tools** (`chk_*.py`):
- Each `chk_*.py` script is a self-contained analysis tool for specific kernel subsystems
- Examples: `chk_rcu.py` (RCU state), `chk_mem.py` (memory), `chk_nic.py` (network), `chk_lockup.py` (hard/soft lockups)
- Scripts use `#!/usr/bin/env epython` or `#!/usr/bin/env python3` depending on whether they require crash context

**Page owner analysis** (two-phase workflow):
- `chk_po_export.py` — exports page_owner data from vmcore to NDJSON format
- `chk_po_analyze.py` — analyzes the exported NDJSON outside crash (faster, supports progress bars)
- Can also analyze kernel text format from `/sys/kernel/debug/page_owner`

**Disassemblers**:
- `chk_dis.py` — x86_64 instruction disassembly from vmcore
- `chk_dis_aarch64.py` — aarch64 instruction disassembly

**Setup/registration**:
- `setup_chk_tools.py` — auto-registers all scripts as crash aliases (run from ~/.crashrc)

### Common Patterns

**Version detection:**
- RHEL version extracted from kernel release string (e.g., `.el8` → RHEL 8)
- Different RHEL versions have different struct layouts (e.g., mutex changed from count-based in RHEL7 to owner-based in RHEL8+)
- RT kernel detection via `CONFIG_PREEMPT_RT` changes lock implementations

**Address resolution:**
- Scripts accept either numeric addresses or symbol names
- Use `readSymbol()` for symbols, fall back to numeric parsing
- Handle both decimal and hex (0x-prefixed) formats

**Task state decoding:**
- `get_task_state_map()` adapts to kernel version (TASK_RUNNING, TASK_INTERRUPTIBLE, etc.)
- Bit positions vary between kernel versions

**Crash command execution:**
- Use `exec_crash_command()` from `pykdump.API` to run crash commands
- Parse output with regex when structured data is needed

## Development Commands

**Testing within crash:**
```bash
# Load crash with vmcore
crash /usr/lib/debug/lib/modules/$(uname -r)/vmlinux /path/to/vmcore

# Load epython extension
extend /usr/lib64/crash/extensions/mpykdumpx86_64.so

# Test a script directly
epython /path/to/crashpyext/chk_lock.py mutex 0xffffa0b8412e4000 -v

# Or use setup script to register aliases
epython /path/to/crashpyext/setup_chk_tools.py -d
```

**Standalone analysis (for chk_po_analyze.py):**
```bash
# After exporting data from crash
python3 chk_po_analyze.py /path/to/page_owner.ndjson -v -p -M
```

**Debugging:**
- Most scripts accept `-d` or `--debug` for verbose output
- `-v` typically enables verbose mode without full debug
- Lock analyzers use `dbg()` function that checks DEBUG global

**Version checking:**
```python
# Common pattern across modules
def detect_rhel_version():
    out = exec_crash_command("sys")
    match = re.search(r'\.el(\d+)', out)
    return int(match.group(1)) if match else 8  # default RHEL 8
```

## Key Implementation Details

**Lock module integration:**
- `chk_lock.py` calls `_push_globals()` before invoking lock-specific analyze functions
- Lock modules (mutex.py, etc.) declare globals at module level that get overwritten by `_push_globals()`
- This avoids duplicate version detection logic across modules

**Page owner two-phase design:**
- Export from crash is slow; NDJSON format allows fast standalone analysis
- NDJSON format: `{"k":"r8","pfn":..., "o":order, "g":gfp, "h":handle}`
- Symbolization happens in analyze phase via `sym -l` calls back into crash

**Architecture-specific code:**
- `ARCH` global set to "64-bit" or "32-bit"
- Separate disassemblers for x86_64 vs aarch64
- qspinlock layout differs by architecture (pending byte position)

**PREEMPT_RT handling:**
- RT kernels embed `rt_mutex_base` inside `struct mutex`
- Detection via struct field presence: `hasattr(struct, 'rtmutex')`
- RT mutexes use different flag bits (only bit 0 for waiters)

## Adding New Analysis Tools

1. Create `chk_newfeature.py` with appropriate shebang (`#!/usr/bin/env epython` for crash context)
2. Import `pykdump.API` for crash functionality
3. Implement RHEL version detection if struct layouts vary
4. Add argparse for CLI options (follow existing patterns: `-v`, `-d`, `-l`)
5. Script will auto-register as alias when `setup_chk_tools.py` runs
6. For lock analyzers: integrate into `chk_lock.py` and create separate module like `mutex.py`

## Testing Notes

- Real vmcore files required for testing
- No unit test framework; manual testing in crash environment
- Version-specific behavior should be tested against RHEL 7/8/9 vmcores
- RT kernel behavior needs separate testing with PREEMPT_RT vmcores
