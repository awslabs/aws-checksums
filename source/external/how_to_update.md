XXHash implementation is imported from https://github.com/Cyan4973/xxHash. 
The file of interest from that repository are xxhash.h.
xxhash.h has minor modifications for memory allocation. to update copy the new file over and replace the memory allocations with the crt changes,
which are indicated in current version with "/************** CRT modifications start */"
