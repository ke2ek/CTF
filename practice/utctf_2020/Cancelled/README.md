# [Cancelled]

## Summary

* Poison NULL Byte + Overlapping Chunks


## Background Knowledges

* Merged if two unsorted-bins were adjacent.
    * Just checked `PREV_IN_USE == 0` in heap meta data.

* Tcache-bin in glibc 2.27 doesn't checked
    * double free bug
    * the size of the next chunk

* [Investigation of x64 glibc heap exploitation techniques on Linux](https://www.duo.uio.no/bitstream/handle/10852/69062/7/mymaster.pdf)

* [HITCON 2018 - baby_tcache](https://vigneshsrao.github.io/babytcache/)


## Tools

* pwndbg
* ghidra
* [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
* [one gadget](https://github.com/david942j/one_gadget)


## Description

* Vulnerability
    * Allocated and freed heap chunks as desired.
    * ![1](./img/1.png?raw=true)
        * It's possible to exploit with `"\x00"` byte at `PREV_IN_USE` bit of the next chunk.
    * ![2](./img/2.png?raw=true)

* Exploit
    * Not provided a function to print heap data or libc address.
        * Using `_IO_2_1_stdout` for memory leak.
    * Guess &_IO_2_1_stdout with main_arena address of unsorted-bin.
        * The least significant 12-bit of libc address isn't changed.
            * ![3](./img/3.png?raw=true)
        * So, we could find next 4-bit with simply `brute-forcing`.
        * The rest bytes will be taken from main_arena address.
    * Allocate a heap chunk at stdout.
        * ![4](./img/4.png?raw=true)
        * ![5](./img/5.png?raw=true)
        * `_IO_CURRENTLY_PUTTING` (=0x800) and `_IO_IS_APPENDING` (=0x1000) are appended at _flags.
            * _flags: 0xfbad2887 --> 0xfbad3887
    * This binary is Full RELRO, so need to overwrite at __free_hook/__malloc_hook.
    * Get Shell after overwriting fd, bk with hook address.
        * allocate, and write sth like below at __free_hook/__malloc_hook.
            1. one_gadget at __free_hook/__malloc_hook.
            2. system() at __malloc_hook: in this case, enter the address of "/bin/sh" as the size of heap chunk. (the length of description is long type)
        * Then, call free() or malloc().

    * Change of heap
        * ![6](./img/6.png?raw=true)
        * ![7](./img/7.png?raw=true)
        * ![8](./img/8.png?raw=true)
        * ![9](./img/9.png?raw=true)
    
    * ![10](./img/10.png?raw=true)
    * [`ex.py`](./ex.py)

* `utflag{j1tt3rbUg_iS_Canc3l1ed_:(}`