#!/usr/bin/env epython

import os
import sys
from crash import exec_crash_command  # Import crash's function to run commands

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))

def get_existing_aliases():
    """Fetch the list of existing aliases from crash."""
    alias_output = exec_crash_command("alias").strip().split("\n")
    existing_aliases = set()

    for line in alias_output[1:]:  # Skip header row
        parts = line.split()
        if len(parts) >= 2:
            existing_aliases.add(parts[1])  # Alias name is in the second column
    return existing_aliases

def register_alias(command, fpath):
    """Registers an alias in crash, avoiding conflicts dynamically."""
    existing_aliases = get_existing_aliases()

    # Find the next available alias name
    if command not in existing_aliases:
        alias_name = command
    else:
        counter = 1
        while f"{command}{counter}" in existing_aliases:
            counter += 1
        alias_name = f"{command}{counter}"

    # Register the alias
    alias_cmd = f'alias {alias_name} "epython {fpath}"'
    exec_crash_command(alias_cmd)

    print(f"Registered: {alias_name} -> {fpath}")

# Register aliases for all Python scripts in the same directory
for script in os.listdir(SCRIPT_DIR):
    if script.endswith(".py") and script != os.path.basename(sys.argv[0]):  # Exclude this script
        script_name = os.path.splitext(script)[0]  # Remove .py extension
        script_path = os.path.join(SCRIPT_DIR, script)
        register_alias(script_name, script_path)

print("All aliases registered successfully.")
