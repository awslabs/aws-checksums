XXHash implementation is imported from https://github.com/Cyan4973/xxHash. 
The 2 files of interest from that repository are xxhash.h and xxhash.c. 
xxhash.c has no modifications and can be imported directly (although in practice its minimal and has not changed in a long time).
xxhash.h has minor modifications for memory allocation. to update copy the new file over and replace the memory allocations with the crt changes,
which are indicated in current version with "/************** CRT modifications start */"
