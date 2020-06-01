#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
host = '127.0.0.1' 
port = 10000
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './zerostorage'
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



#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# FORTIFY:  Enabled

def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    ga()
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

