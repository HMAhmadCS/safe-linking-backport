#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF("./vuln.o")


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        context.terminal = ["gnome-terminal", "--"]
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

# -- Exploit goes here --

io = start()

io.interactive()
