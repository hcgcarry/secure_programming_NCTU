
from pwn import *
def login(r,token):
    r.sendlineafter("> ",str(1))
    r.sendlineafter("token: \n> ",token)
    line = r.recvline()
    print("login message",line)

def signup(r,name,desc="dummy",job='dummy',keep='y'):
    r.sendlineafter("> ",str(2))
    r.sendafter("name ?\n> ",name)
    r.sendlineafter("desc ?\n> ",desc)
    r.sendlineafter("job ?\n> ",job)
    r.sendlineafter("have ?\n> ",str(3))
    userInfo= r.recvuntil("(y/n) > ")
    print("userInfo",userInfo)
    r.sendline(keep)
    line = r.recvline()
    token = line.split()[-1]
    print("token",token)
    return token,userInfo
def delete_account(r,token):
    print("delete_token",token)
    r.sendlineafter("> ",str(1))
    r.sendlineafter("token: \n> ",token)
    r.sendlineafter("> ",str(3))
    r.sendlineafter("> ",b'y')

def update_user(r,token,Name = "dummy",Desc = "dummy",Job = "dummy"):
    print("update_token",token)
    r.sendlineafter("> ",str(1))
    r.sendlineafter("token: \n> ",token)

    r.sendlineafter("> ",str(1))
    r.sendlineafter("Name: \n> ",Name)
    r.sendlineafter("Desc: \n> ",Desc)
    r.sendlineafter("Job: \n> ",Job)
    r.sendlineafter("Money: \n> ",str(777))
    r.sendlineafter("> ",str(4))

def chat_server(r,token):
    print("chat_server_token",token)
    r.sendlineafter("> ",str(1))
    r.sendlineafter("token: \n> ",token)

    r.sendlineafter("> ",str(2))
    # gdb.attach(r)
    r.sendlineafter("(y/n) > ","n")
    r.recvuntil("-------** Room **--------*\n")

    message= r.recv()
    print("client message",message)
    # r.sendlineafter("> ","i am server, I need to go :(")
    r.sendline("I need to go :(, client_message: ".encode()+ message)
    print("---message send")

def chat_client(r,token,sendStr):
    print("sendstr",sendStr)
    print("chat_client_token",token)
    r.sendlineafter("> ",str(1))
    r.sendlineafter("token: \n> ",token)

    r.sendlineafter("> ",str(2))
    r.sendlineafter("(y/n) > ","y")
    server_token = input("input server_token:") # 這邊注意 \n好像會被append到後面,所以下一行不用使用sendline
    r.sendafter("token: \n> ",server_token)
    r.sendafter("> ",sendStr)
    server_message = r.recv()
    print("server_messag",server_message)
    r.sendlineafter("> ",str(4))


def login_doNothing(r,token):
    r.sendlineafter("> ",str(1))
    r.sendlineafter("token: \n> ",token)
    text = r.recvuntil("> ")
    print("text",text)
    r.sendline(str(4))
    return text

