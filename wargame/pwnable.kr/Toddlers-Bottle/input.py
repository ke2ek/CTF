from pwn import *

port = 12345
argvs = [str(i) for i in range(100)]
argvs[65] = "\x00"
argvs[66] = "\x20\x0a\x0d"

with open("/tmp/eK/stderr_file", 'a') as f:
	f.write("\x00\x0a\x02\xff")

envVal = {"\xde\xad\xbe\xef": "\xca\xfe\xba\xbe"}

with open("/tmp/eK/\x0a", 'a') as f:
	f.write("\x00\x00\x00\x00")

argvs[67] = '99999'

target = process(executable='/home/input2/input', argv=argvs, stderr=open("/tmp/eK/stderr_file"), env=envVal)
target.sendline('\x00\x0a\x00\xff') # Standard Input

conn = remote("localhost", 99999)
conn.send("\xde\xad\xbe\xef")
target.interactive()

# mkdir /tmp/myDir
# ln -s /home/input2/flag /tmp/myDir/flag
