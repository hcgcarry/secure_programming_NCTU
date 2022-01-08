
from pwn import *

r = remote("edu-ctf.csie.org","42070")
q = r.recvline()
print("q",q)
cipher = bytes.fromhex(q.split(b" ")[-1][:-1].decode())
print("cipher",cipher)

finalResult = []

for block_index in  range(2):
    ok = b''
    for i in range(16):
        for j in range(256):
            iv = b'\x00' * (15-i) + bytes([j^0x80])
            iv += ok
            mess = iv+cipher[block_index * 16 + 16:block_index*16+32]
            mess = mess.hex().encode()
            print("mess",mess)
            r.sendlineafter(b'cipher = ',mess)
            result = r.recvline()
            if result != b'NOOOOOOOOO\n':
                ok = bytes([j]) + ok
                curRealIV = cipher[:block_index*16+16][-i-1:]
                plain = bytes( a^b for a,b in zip(ok,curRealIV))
                print("plain:",plain)
                finalResult.append(plain)
                break

            
for item in finalResult:
    print("item:",item)

r.interactive()