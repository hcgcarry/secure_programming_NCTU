# from server import verify
from pwn import *
from math import sin
from pwnlib.rop.rop import Padding

from six import b



def MyHash(s):
    A = 0x464c4147
    B = 0x7b754669
    C = 0x6e645468
    D = 0x65456173
    E = 0x74657245
    F = 0x6767217D

    def G(X, Y, Z):
        return (X ^ (~Z | ~Y) ^ Z) & 0xFFFFFFFF

    def H(X, Y):
        return (X << Y | X >> (32 - Y)) & 0xFFFFFFFF
    X = [int((0xFFFFFFFE) * sin(i)) & 0xFFFFFFFF for i in range(256)]
    s_size = len(s)
    s += bytes([0x80])
    if len(s) % 128 > 120:
        while len(s) % 128 != 0:
            s += bytes(1)
    while len(s) % 128 < 120: s += bytes(1)
    s += bytes.fromhex(hex(s_size * 8)[2:].rjust(16, '0'))
    for i, b in enumerate(s):
        k, l = int(b), i & 0x1f
        A = (B + H(A + G(B, C, D) + X[k], l)) & 0xFFFFFFFF
        B = (C + H(B + G(C, D, E) + X[k], l)) & 0xFFFFFFFF
        C = (D + H(C + G(D, E, F) + X[k], l)) & 0xFFFFFFFF
        D = (E + H(D + G(E, F, A) + X[k], l)) & 0xFFFFFFFF
        E = (F + H(E + G(F, A, B) + X[k], l)) & 0xFFFFFFFF
        F = (A + H(F + G(A, B, C) + X[k], l)) & 0xFFFFFFFF
    return ''.join(map(lambda x: hex(x)[2:].rjust(8, '0'), [A, F, C, B, D, E]))




def verify(*stuff):
    return MyHash(b'&&'.join(stuff)).encode()

class createMac:
    def server_mac2ABCDEF(self,server_mac):
        result= []
        for i in range(6):
            result.append(int(server_mac[i*8:i*8+8],16))
        # for i in range(6):
        #     print(i,hex(result[i]))
        # print('server_mac',server_mac)
        A, F, C, B, D, E = result
        return A,B,C,D,E,F

    def verify(self,old_content_with_padding_len,addContent,server_mac):
        salt = bytes(old_content_with_padding_len)
        return self.MyHash(salt+addContent,old_content_with_padding_len,*self.server_mac2ABCDEF(server_mac)).encode()

    def padding(self,s,saltLen):
        salt = bytes(saltLen)
        s =  salt +s
        s_size = len(s)
        s += bytes([0x80])
        if len(s) % 128 > 120:
            while len(s) % 128 != 0:
                s += bytes(1)
        while len(s) % 128 < 120: s += bytes(1)
        s += bytes.fromhex(hex(s_size * 8)[2:].rjust(16, '0'))
        s = s[saltLen:]
        return s
    def MyHash(self,s,saltLen,A,B,C,D,E,F):

        def G(X, Y, Z):
            return (X ^ (~Z | ~Y) ^ Z) & 0xFFFFFFFF

        def H(X, Y):
            return (X << Y | X >> (32 - Y)) & 0xFFFFFFFF
        X = [int((0xFFFFFFFE) * sin(i)) & 0xFFFFFFFF for i in range(256)]
        s_size = len(s)
        s += bytes([0x80])
        if len(s) % 128 > 120:
            while len(s) % 128 != 0:
                s += bytes(1)
        while len(s) % 128 < 120: s += bytes(1)
        s += bytes.fromhex(hex(s_size * 8)[2:].rjust(16, '0'))
        print("----0  A",hex(A),"B",hex(B),"C",hex(C),"D",hex(D),"E",hex(E),"F",hex(F))

        for i, b in enumerate(s):
            if i < saltLen:
                continue
            k, l = int(b), i & 0x1f
            A = (B + H(A + G(B, C, D) + X[k], l)) & 0xFFFFFFFF
            B = (C + H(B + G(C, D, E) + X[k], l)) & 0xFFFFFFFF
            C = (D + H(C + G(D, E, F) + X[k], l)) & 0xFFFFFFFF
            D = (E + H(D + G(E, F, A) + X[k], l)) & 0xFFFFFFFF
            E = (F + H(E + G(F, A, B) + X[k], l)) & 0xFFFFFFFF
            F = (A + H(F + G(A, B, C) + X[k], l)) & 0xFFFFFFFF
            print("----i",i," b",chr(b)," A",hex(A),"B",hex(B),"C",hex(C),"D",hex(D),"E",hex(E),"F",hex(F))
        return ''.join(map(lambda x: hex(x)[2:].rjust(8, '0'), [A, F, C, B, D, E]))






def loginGuest():
    username = b'Guest'
    password = b'No FLAG'
    cmd = b"flag"
    # r = remote("edu-ctf.csie.org","42073")
    # r = process("python3")
    r = process(['python3', 'server.py'])
    r.sendlineafter("username: ", username)
    r.recvuntil("ID: ")
    session = r.recvline()[:-1]
    # session = r.recvline()[:-2]
    print("session", session)


    print("my:username", username,"password",password,"session",session,"cmd",cmd)
    mac = verify(username, password,session,cmd)

    print("mac", mac)
    cmd = b'flag'
    line =  mac + b'&&' + session + b'&&' + cmd
    line = line.decode()
    line = ''.join([hex(ord(x))[2:] for x in line])
    print("line", line)
    r.sendlineafter('do? ', line)
    r.interactive()



def loginAdmin():
    username = b'Admin'
    # password = b'No FLAG'
    cmd = b"flag"
    r = remote("edu-ctf.csie.org","42073")
    # r = process(['python3', 'server.py'])
    r.sendlineafter(b"username: ", username)
    r.recvuntil(b"ID: ")
    session = r.recvline()[:-1]
    r.recvuntil(b"MAC(username&&password&&sessionID): ")
    server_mac = r.recvline()[:-1]
    
    print("server_mac",server_mac)
    print("local:username", username,"session",session,"cmd",cmd)

    ##注意hash多出來要算的部分是 &&flag"
    passwordLen=0
    while 1:
        passwordLen+=1
        # saltLen = 14
        saltLen = len(b"Admin&&&&")+passwordLen
        createMacObj = createMac()
        new_session = createMacObj.padding(session,saltLen)
        old_content_with_padding_len = len(new_session) + saltLen
        mac = createMacObj.verify(old_content_with_padding_len,b'&&'+cmd,server_mac)
        print("new_session",new_session)
        print("old_content_with_padding",old_content_with_padding_len)

        print("saltLen",saltLen)
        print("mac", mac)
        cmd = b'flag'
        line =  mac + b'&&' + new_session+ b'&&' + cmd
        line = line.hex().encode()
        print("line",line)
        # line = ''.join([hex(ord(x))[2:] for x in line])
        # print("send line:", line)
        r.sendlineafter(b'do? ', line)
        try:
            line = r.recvuntil(b'to')
            print("server response:",line)
        except:
            break
            
        # if line.find(b"Refused") == -1:
        #     print('refused not find')
        #     break
        # else:
        #     print("not found")
        

    r.interactive()

if __name__ == "__main__":
    loginAdmin()
    # loginGuest()

# b8c058ae16056c57fb1d66f5f28e8151a1c1b6124d59600b&&b8c058ae16056c57fb1d66f5f28e8151a1c1b6124d59600b&&flag
