from pwn import *

def get_block(_id, order):
	p = remote('pwnable.kr', 9006)
	p.sendlineafter('ID', _id)
	p.sendlineafter('PW', "")
	p.recvuntil('data (')
	encrypted = p.recvuntil(')')[:-1]
	p.close()
	start = 32*order
	end = 32*order+32 if 32*order+32 < 128 else 128
	return encrypted[start:end]

def find_char(user_data, hex_data, order):
	import hashlib
	for ch in "1234567890abcdefghijklmnopqrstuvwxyz-_":
		compared = get_block(user_data+ch, order)
		if compared == hex_data:
			print "Found: ", ch
			return ch
	return -1

range_set = [(13, -1, -1), (15, -1, -1)]
cookie = ''
tmp = ''
order = 0
isRunning = True
while isRunning:
	start, end, gap = range_set[order if order < 2 else 1]
	for i in range(start, end, gap):
		_id = "-"*i
		block = get_block(_id, order)
		print "Block: ", block
		_id = "--" + _id + cookie + tmp
		print "ID: ", _id, "len: ", len(_id)
		ch = find_char(_id, block, order)
		if ch == -1:
			isRunning = False
			break
		tmp += ch
	order += 1
	cookie += tmp
	tmp = ''
	print "Cookie: ", cookie
