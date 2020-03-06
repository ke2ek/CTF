from pwn import *

HOST = "pwnable.kr"
PORT = 9007
p = remote(HOST, PORT)

p.recvuntil("sec... -")

for i in range(100):
        p.recvuntil("N=")
        data = p.recvuntil("\n")[:-1].split()
        N = int(data[0])
        C = int(data[1].split("=")[1])

        coin_list = [str(i) for i in range(N)]
        start = 0
        end = N
        mid = N >> 1

        for i in range(C):
                msg = ' '.join(coin_list[start:mid])
                p.sendline(msg)
                weight = p.recvuntil('\n')[:-1]
                if weight[-1] != '0': end = mid
                else: start = mid
                mid = (start + end) >> 1
                if start == mid: start -= 1

        p.sendline(coin_list[mid])
        print p.recvuntil('Correct')
p.interactive()
