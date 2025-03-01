#!/usr/bin/env epython

import os
import sys
from crash import exec_crash_command  # Import crash's function to run commands

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))

# Check for debug mode (-d option)
DEBUG = "-d" in sys.argv

def debug_print(message):
    """Prints debug messages only if debug mode is enabled."""
    if DEBUG:
        print("[DEBUG]", message)

def get_existing_aliases():
    """Fetch the current alias list from crash."""
    alias_output = exec_crash_command("alias").strip().split("\n")
    existing_aliases = set()

    for line in alias_output[1:]:  # Skip header row
        parts = line.split()
        if len(parts) >= 2:
            existing_aliases.add(parts[1])  # Alias name is in the second column

    debug_print(f"Existing aliases: {existing_aliases}")
    return existing_aliases

def register_alias(command, fpath, existing_aliases):
    """Registers an alias inside crash, ensuring no duplicates."""
    alias_name = command
    counter = 1

    # Ensure unique alias name by checking existing aliases
    while alias_name in existing_aliases:
        alias_name = f"{command}{counter}"
        counter += 1

    # Register the alias
    alias_cmd = f'alias {alias_name} "epython {fpath}"'
    debug_print(f"Registering: {alias_cmd}")
    exec_crash_command(alias_cmd)

    # Update alias list dynamically
    existing_aliases.add(alias_name)
    print(f"Registered: {alias_name} -> {fpath}")

# Fetch existing aliases once before processing
existing_aliases = get_existing_aliases()

# Debug: Show script directory
debug_print(f"Script directory: {SCRIPT_DIR}")

# Register aliases for all Python scripts in the same directory
for script in os.listdir(SCRIPT_DIR):
    if script.endswith(".py") and script != os.path.basename(sys.argv[0]):  # Exclude this script
        script_name = os.path.splitext(script)[0]  # Remove .py extension
        script_path = os.path.join(SCRIPT_DIR, script)

        # Debug: Show found script
        debug_print(f"Found script: {script_name} -> {script_path}")

        # Register alias
        register_alias(script_name, script_path, existing_aliases)

print("All aliases registered successfully.")
