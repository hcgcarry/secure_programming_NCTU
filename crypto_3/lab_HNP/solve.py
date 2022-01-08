#!/usr/bin/env python3
from random import randint
from Crypto.Util import number
from Crypto.Util.number import *
from hashlib import sha256
from collections import namedtuple
from ecdsa.ecdsa import *
from ecdsa import SECP256k1
from ecdsa import util, numbertheory
from ecdsa.ecdsa import Public_key, Private_key, Signature
from pwn import *
from sage.all import*



# r = remote("edu-ctf.csie.org" ,"42072")

def getPrivateKeyD(h1,h2,s1,s2,r1,r2,n):
    h1 = bytes_to_long(sha256(h1).digest())
    h2 = bytes_to_long(sha256(h2).digest())
    print("after hash","h1",h1,"h2",h2)
    print("s1",s1,"s2",s2)
    print("r1",r1,"r2",r2)
    d = (s1*h2 - 1337*s2*h1 )*inverse_mod(1337*s2*r1-s1*r2,n) %n
    print("private key d:",d)
    return d


def sign(h,privatekey,k):
    h = bytes_to_long(sha256(h.encode()).digest())
    sig = privatekey.sign(h, k)
    print('sig = sig.r:',sig.r, 'sig.s:',sig.s)
    return sig.r,sig.s

## 我們要做的事:nc 之後連續兩次填1 分別輸入f , u 把噴出來的r,s填到下面r1 s1 ,r2 s2
if __name__ == "__main__":
    E = SECP256k1
    G,n = E.generator, E.order
    # r = process(["python3","origin/server.py"])
    r = remote("edu-ctf.csie.org",42072)
    h1 = b'f'
    line=   r.recvuntil(b"1)")
    print("server response:",line)
    r.sendlineafter(b"exit",b'1')
    r.sendlineafter(b"you?",h1)
    line =r.recvuntil(b"sig = (")
    print("server response:",line)
    line = r.recvuntil(b")")[:-1]
    r1 ,s1 = line.split(b',')
    r1 = int(r1.decode())
    s1 = int(s1.decode())

    h2 = b'u'
    r.sendlineafter(b"exit",b'1')
    r.sendlineafter(b"you?",h2)
    line = r.recvuntil(b"sig = (")
    print("server response:",line)
    line = r.recvuntil(b")")[:-1]
    r2 ,s2 = line.split(b',')
    r2 = int(r2.decode())
    s2 = int(s2.decode())

    d= getPrivateKeyD(h1,h2,s1,s2,r1,r2,n)

    # r = remote("edu-ctf.csie.org" ,"42072")

    # P = (30814259162987987234834371454017490289079464080574564582799044411457272522284, 84500362529970880925940908440476548246122252581621949634689617577723696708429)
    #sig = (98692730171815017269387756770454741133970313522144599511390031250797160585572, 77451422445763974214852828301290578298252921869374080575019568440697481596844)
    #sig = (105621523302179919875279923870260302789714961830957056300606905379059512668007, 99071019152333485351056549269838476000743332525887224678791369294284632212611)
    pubkey = Public_key(G, d*G)
    prikey = Private_key(pubkey, d) 
    ## 注意下面是P: 就是 d*G 後的point 先比對我們算到的d正不正卻(看有沒跟server 噴出來的P 依樣))
    print('P = (',pubkey.point.x(),', ',pubkey.point.y(),')')

    k=2
    h= "Kuruwa"
    r_sig,s_sig = sign(h,prikey,k)
    r.sendlineafter(b'exit',b'2')
    r.sendlineafter(b'username: ',h.encode())
    r.sendlineafter(b'r: ',str(r_sig).encode())
    r.sendlineafter(b's: ',str(s_sig).encode())
    r.interactive()
    



