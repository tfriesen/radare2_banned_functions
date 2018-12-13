# radare2_banned_functions

A python script for radare2 for discovering banned and dangerous functions. When run during debugging, will automatically set breakpoints every time a detected dangerous function is called. To call from within radare, ". /path/to/banned_functions.py"

When called from the command line, takes a single parameter, a path to a binary for analysis.

Compatible with both python 2 and 3. Tested on Linux and Windows.

Inspired by Stephen Sims' banned functions script for IDA: https://github.com/steph3nsims/banned_functions/blob/master/banned_functions.py

## Requirements

* Radare2 (obviously)
* python
* r2pipe - "pip install r2pipe" or "pip3 install r2pipe" suffices

## Bugs and Limitations

Note that there is a bug in the most recent version of r2pipe for python, 1.1.0, which prevents use from within radare. Fixed upstream, awaiting on a new release. You can fix yourself by changing line 46 in open_sync.py from 'else:' to 'elif filename:'

Can be called from Cutter, but output is to terminal, not console. Will not add breakpoints to Cutter. These are due to limitations with how Cutter has implemented console commands. Could potentially be fixed by converting the script to a plugin, but that is non-trivial.

