from pwn import *

HOST = 'pwnable.kr'
PORT = 9006
BLOCK_SIZE = 16

def get_encrypted_block(param_id, start, end):
        p = remote(HOST, PORT)
        p.sendlineafter('ID', param_id)
        p.sendlineafter('PW', '')
        p.recvuntil('data (')
        data = p.recvuntil(')')
        data = data[:-1]
        p.close()
        if end > len(data):
                return data[start:]
        return data[start:end]

def get_one_character(encrypted, part_of_id, start, end):
        charset = '1234567890abcdefghijklmnopqrstuvwxyz-_'
        for ch in charset:
                compared = get_encrypted_block(part_of_id+ch, start, end)
                print "user_id: {}, len: {}".format(part_of_id+ch, len(part_of_id+ch))
                print "ch: {}, compared: {}".format(ch, compared)
                if compared == encrypted:
                        return ch
        return ''

def get_part_of_cookie(start, end, user_id, checked_length):
        part = ''
        for i in range(checked_length, -1, -1):
                block = get_encrypted_block(user_id[0], start, end)
                print "block: ", block
                ch = get_one_character(block, user_id[1], start, end)
                part += ch
                user_id[1] = user_id[1][1:] + ch
                print "Found ! part_of_cookie: ", part
                if i == 1:
                        user_id[0] = ''
                else:
                        user_id[0] = user_id[0][:-1]
        return part

if __name__ == '__main__':
        cookie = ''
        start = 0
        end = 32
        user_id = ['-'*13, '-'*15]
        cookie += get_part_of_cookie(start, end, user_id, 13)

        while True:
                start += BLOCK_SIZE*2
                end += BLOCK_SIZE*2
                user_id = ['-'*BLOCK_SIZE, '-'*(BLOCK_SIZE+2)+cookie]
                cookie += get_part_of_cookie(start, end, user_id, BLOCK_SIZE)
        print "cookie: ", cookie
        
        # It's took a very long time :(...
