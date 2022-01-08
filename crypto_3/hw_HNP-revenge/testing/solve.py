#!/usr/bin/env python3
from random import randint
from Crypto.Util import number
import re
from Crypto.Util.number import *
from hashlib import sha256
from collections import namedtuple
from sage.all import *
from ecdsa.ecdsa import *
from ecdsa import SECP256k1
from ecdsa import util, numbertheory
from ecdsa.ecdsa import Public_key, Private_key, Signature
from pwn import *
from hashlib import sha256, md5


# r = remote("edu-ctf.csie.org" ,"42072")

# def getPrivateKeyD(h1,h2,s1,s2,r1,r2,n):
#     h1 = bytes_to_long(sha256(h1).digest())
#     h2 = bytes_to_long(sha256(h2).digest())
#     print("after hash","h1",h1,"h2",h2)
#     print("s1",s1,"s2",s2)
#     print("r1",r1,"r2",r2)
#     d = (s1*h2 - s2*h1 )*inverse_mod(s2*r1-s1*r2,n) %n
#     print("private key d:",d)
#     return d


def sign(h,privatekey,k):
    h = bytes_to_long(sha256(h.encode()).digest())
    sig = privatekey.sign(h, k)
    print('sig = sig.r:',sig.r, 'sig.s:',sig.s)
    return sig.r,sig.s


def getShortestVCandidate(n,s1,s2,r1,r2,h1,h2,a,K):
    # from gmpy2 import mpz
    # a = mpz(a)
    h1 = bytes_to_long(sha256(h1).digest())
    h2 = bytes_to_long(sha256(h2).digest())
    print("-------getShortestV args start")
    print("s1",s1,"s2",s2)
    print("r1",r1,"r2",r2)
    print("h1",h1,"h2",h2)
    print("a",a,"k",K)
    print("-------getShortestV args end")
    # s1 = (h1+d*r1)/(k1+a)
    # s2 = (h2+d*r2)/(k2+a)
    # s1*(k1+a) = (h1+d*r1)
    # s2*(k2+a) = (h2+d*r2)
    # (s1*(k1+a) -h1)/r1 = d
    # (s2*(k2+a) -h2)/r2 = d
    # (s1*(kl+a) -h1)/r1 - (s2*(k2+a) -h2)/r2= 0
    # k1+a-h1/s1 - r1*(s2*k2+s2*a - h2)/(r2*s1) = 0
    # k1+a-h1/s1 - r1*s2*k2/(r2*s1) - r1*(s2*a -h2)/(r2*s1) =0
    # k1- r1*s2*k2/(r2*s1) - r1*(s2*a -h2)/(r2*s1) +a - h1/s1=0
    # k1- r1*s2*k2/(r2*s1) + r1*h2/(r2*s1) -h1/s1 - r1*s2*a/(r2*s1) +a =0
    t = -1*inverse(s1,n) * s2 * r1 * inverse(r2,n) %n
    # u = inverse(s1,n) * r1 * ((s1 * a -h1)* inverse(r1,n)  + (s2*a+h2)*inverse(r2,n))  %n
    # u = (-1*r1*(s2*a-h2) * inverse(r2* s1,n) + a -h1* inverse(s1,n)) %n
    u = (inverse(s1,n)*r1*h2* inverse(r2,n) - h1* inverse(s1,n)  - inverse(s1,n)*inverse(r2,n)*r1*s2*a + a )%n
    print("t",t)
    print("u",u)
    # u = inverse(s1,n) * r1 * ((s1 * a -h1)* inverse(r1,n)  + (s2*a+h2)*inverse(r2,n))  %n
    L = matrix(ZZ,[[n,0,0],[t,1,0],[u,0,K]])
    v = L.LLL()
    print("v",v)
    # result = [ x for x in v if x[2] == K]
    # result = [ x for x in v if x[2] == K]
    # print("result",result)
    # return result
    return v
    

# t = 44673707238721626228839065798304219729978670538278261028337056421915843082485
# u = 50045504276568212787404613155792043629827984561635553972662017281769852254590


def getK1K2(v,a,n):
    # return abs(v[0])+a,abs(v[1])+a
    return (-v[0]+a) %n,(v[1]+a) %n
def caculateKey_d_byk1k2(h1,h2,k1,k2,s1,s2,r1,r2,n):
    h1 = bytes_to_long(sha256(h1).digest())
    h2 = bytes_to_long(sha256(h2).digest())
    print("-------caculatekey_d start")
    print("s1",s1,"s2",s2)
    print("r1",r1,"r2",r2)
    print("h1",h1,"h2",h2)
    print("k1",k1,"k2",k2)
    print("-------caculatekey_d end")
    # print("after hash","h1",h1,"h2",h2)
    # s1*k1 = h1 + d*r1
    # s2*k2 = h2 + d*r2
    # (s1*k1  - s2 * k2 - h1 + h2) /(r1-r2)=  d
    # d = ((k1-k2 -inverse(s1,n)*h1 - inverse(s2,n)*h2)*inverse(inverse(s1,n)*r1-inverse(s2,n)*r2,n)) %n
    d = ((s1* k1 - s2 * k2 - h1+h2)* inverse((r1-r2),n)) %n
    return d

def main():
    E = SECP256k1
    G,n = E.generator, E.order
    print('P = (',G.x(),', ',G.y(),')')
    r = process(["python3","server.py"])
    h1 = b'a'
    line=   r.recvuntil(b"1)")
    print("server response:",line.decode())
    regex_dG = re.search("\((\d*),\s(\d*)\)",line.decode())
    server_dG_x = int(regex_dG[1])
    server_dG_y = int(regex_dG[2])
    print("dG.x",regex_dG[1])
    print("dG.y",regex_dG[2])
    r.sendlineafter(b"exit",b'1')
    r.sendlineafter(b"you?",h1)
    line =r.recvuntil(b"(")
    print("server response:",line)
    line = r.recvuntil(b")")[:-1]
    r1 ,s1 = line.split(b',')
    r1 = int(r1.decode())
    s1 = int(s1.decode())
    print("r1",r1,"s1",s1)
    line = r.recvline()
    line = r.recvline()
    print('line',line)
    line = line.decode().split()
    server_k1 = line[1]
    server_h1=  line[3]
    server_e1 = line[5]
    print("******server response k1:",server_k1 ,"h",server_h1 ,"e",server_e1 )

    h2 = b'b'
    r.sendlineafter(b"exit",b'1')
    r.sendlineafter(b"you?",h2)
    line = r.recvuntil(b"(")
    print("server response:",line)
    line = r.recvuntil(b")")[:-1]
    r2 ,s2 = line.split(b',')
    r2 = int(r2.decode())
    s2 = int(s2.decode())
    print("r2",r2,"s2",s2)

    line = r.recvline()
    line = r.recvline()
    print('line',line)
    line = line.decode().split()
    server_k2 = line[1]
    server_h2=  line[3]
    server_e2 = line[5]
    print("******server response k2:",server_k2 ,"h",server_h2 ,"e",server_e2 )
    # d= getPrivateKeyD(h1,h2,s1,s2,r1,r2,n)

    # r = remote("edu-ctf.csie.org" ,"42072")
    K = 2**128
    a = int(md5(b'secret').hexdigest(),16) << 128

    v = getShortestVCandidate(n,s1,s2,r1,r2,h1,h2,a,K)

    for candidate_v in v:
        print("-----candidate_v",candidate_v)
        k1,k2 = getK1K2(candidate_v,a,n)
        print("######## candidate recover :k1",k1,"k2",k2)
        print("######## server :k1",server_k1,"k2",server_k2)
        if k1 == server_k1 and k2 == server_k2:
            print("key is same")
            exit()


        d = caculateKey_d_byk1k2(h1,h2,k1,k2,s1,s2,r1,r2,n)

        print("##########candidate recover d:",d)

        pubkey = Public_key(G, d*G)
        prikey = Private_key(pubkey, d) 
        ## 注意下面是P: 就是 d*G 後的point 先比對我們算到的d正不正卻(看有沒跟server 噴出來的P 依樣))
        print('P = (',pubkey.point.x(),', ',pubkey.point.y(),')')
        if pubkey.point.x() == server_dG_x and pubkey.point.y() == server_dG_y:
            k=2
            h= "Kuruwa"
            r_sig,s_sig = sign(h,prikey,k)
            r.sendlineafter(b'exit',b'2')
            r.sendlineafter(b'username: ',h.encode())
            r.sendlineafter(b'r: ',str(r_sig).encode())
            r.sendlineafter(b's: ',str(s_sig).encode())
            r.interactive()
            exit()
        else:
            print("----current candidate not match")
            print("pubkey.x",pubkey.point.x(),"server_dG_x",server_dG_x ,"pubkey.y",pubkey.point.y() ,"server_dG_y",server_dG_y)
            print('guess P = (',type(pubkey.point.x()),', ',type(pubkey.point.y()),')')
            print('server : P = (',type(server_dG_x) ,',', type(server_dG_y),')')
    print("------not match")
    print('guess P = (',pubkey.point.x(),', ',pubkey.point.y(),')')
    print('server : P = (',server_dG_x ,',', server_dG_y,')')
    r.close()


    # k=2
    # h= "Kuruwa"
    # r_sig,s_sig = sign(h,prikey,k)
    # r.sendlineafter(b'exit',b'2')
    # r.sendlineafter(b'username: ',h.encode())
    # r.sendlineafter(b'r: ',str(r_sig).encode())
    # r.sendlineafter(b's: ',str(s_sig).encode())
    # r.interactive()
        


## 我們要做的事:nc 之後連續兩次填1 分別輸入f , u 把噴出來的r,s填到下面r1 s1 ,r2 s2
if __name__ == "__main__":
    while 1:
        print("============================new while")
        main()