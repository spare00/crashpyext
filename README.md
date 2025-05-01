Crash Python Extensions for VMCore Analysis
===========================================

This repository contains a collection of chk_*.py Python scripts to assist in
automated VMCore diagnostics inside the crash utility, powered by epython.

Features
--------

- Provides targeted analysis tools: RCU, spinlocks, lockups, vm_structs, and more.
- Automatically registers scripts as crash aliases on startup.
- Uses epython to enable Python execution inside crash.
- No need to manually type epython for each tool — just run chk_<tool>!


Prerequisites
-------------

1. epython support must be loaded into crash via mpykdumpx86_64.so:

   Within your crash session:
     extend /usr/lib64/crash/extensions/mpykdumpx86_64.so

2. Python 3 must be available.


Setup Instructions
------------------

Step 1: Clone the Repository

  git clone https://github.com/spare00/crashpyext.git

Step 2: Auto-register Aliases via ~/.crashrc

Append the following line to your ~/.crashrc file to register the Python tools
automatically each time crash starts:

  echo 'epython /home/YOUR_USERNAME/path/to/crashpyext/setup_chk_tools.py' >> ~/.crashrc

Replace the path above with the actual full path to setup_chk_tools.py.


Enable Debug Mode (Optional)
----------------------------

To enable verbose debug output during alias setup, use this instead:

  echo 'epython /home/YOUR_USERNAME/path/to/crashpyext/setup_chk_tools.py -d' >> ~/.crashrc

This will print:
- Found Python scripts
- Detected existing aliases
- Alias registration steps


Usage
-----

After setup, launch crash as usual with your vmlinux and vmcore:

  crash /usr/lib/debug/lib/modules/$(uname -r)/vmlinux /path/to/vmcore

Then you can run any registered script by its alias:

  crash> chk_rcu
  crash> chk_mutex
  crash> chk_soft_lockup


Removing or Resetting Aliases
-----------------------------

To remove an alias manually within crash:

  crash> unalias chk_rcu

To stop auto-registration, remove the epython line from your ~/.crashrc.


File Structure
--------------

  crashpyext/
  ├── chk_dis.py
  ├── chk_hard_lockup.py
  ├── chk_lockup.py
  ├── chk_mutex.py
  ├── chk_qspinlock.py
  ├── chk_rcu.py
  ├── chk_rw_semaphore.py
  ├── chk_soft_lockup.py
  ├── chk_vm_struct.py
  └── setup_chk_tools.py   (Registers the above scripts as crash aliases)


Notes
-----

- This toolkit is ideal for automation, internal post-mortem debugging,
  or SOPs for RHEL-based crash dump analysis.

- setup_chk_tools.py ensures no duplicate aliases are registered.

- To debug or reconfigure, modify the line in ~/.crashrc accordingly.

Maintained by: spare00
