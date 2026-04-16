#!/usr/bin/env python
"""
Print the kernel boot command line from a crash session.

Usage inside crash:
    crash> epython chk_cmd
"""

import re
import sys


def _get_exec_crash_command():
    try:
        from pykdump.API import exec_crash_command  # type: ignore

        return exec_crash_command
    except ImportError:
        pass

    try:
        import crash  # type: ignore

        return crash.exec_crash_command
    except (ImportError, AttributeError):
        pass

    raise RuntimeError("Could not import exec_crash_command from crash Python environment")


def _first_hex_token(text):
    match = re.search(r"\b[0-9a-fA-F]{8,16}\b", text)
    if not match:
        raise RuntimeError("Failed to find an address in crash output:\n%s" % text)
    return match.group(0)


def _extract_ascii_dump(text):
    chunks = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        _, payload = line.split(":", 1)
        # `rd -a` prefixes each ASCII chunk with formatting spaces after the colon.
        # Remove only that prefix and preserve the chunk's original whitespace.
        if payload.startswith("  "):
            payload = payload[2:]
        if payload:
            chunks.append(payload)
    if not chunks:
        raise RuntimeError("Failed to extract command line text from crash output:\n%s" % text)
    return "".join(chunks)


def main():
    exec_crash_command = _get_exec_crash_command()

    sym_output = exec_crash_command("sym saved_command_line")
    sym_addr = _first_hex_token(sym_output)

    ptr_output = exec_crash_command("rd %s" % sym_addr)
    cmd_addr = _first_hex_token(ptr_output.split(":", 1)[1] if ":" in ptr_output else ptr_output)

    cmd_output = exec_crash_command("rd -a %s" % cmd_addr)
    print(_extract_ascii_dump(cmd_output))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("chk_cmd: %s" % exc, file=sys.stderr)
        sys.exit(1)
