#!/usr/bin/env python3
from random import randint
from Crypto.Util.number import *
from hashlib import sha256
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key, Private_key, Signature
from sage.all import *

# FLAG = open("flag", 'r').read()
FLAG = b'FLAG{1232313}'

E = SECP256k1
G, n = E.generator, E.order

d = randint(1, n)
k = randint(1, n)
print("d:",d)
print("k:",k)
pubkey = Public_key(G, d*G)
prikey = Private_key(pubkey, d)
print(f'P = ({pubkey.point.x()}, {pubkey.point.y()})')

def modDivide(a,b,m):
    a = a % m
    inv = modInverse(b,m)
    if (inv == -1):
        print("Division not defined")
    else:
        return (inv*a) % m
def modInverse(b, m):
    g = math.gcd(b, m)
    if (g != 1):
        return -1
    else:
        return pow(b, m-2, m)

def getPrivateKeyD(h1,h2,s1,s2,r1,r2,n):
    h1 = bytes_to_long(sha256(h1).digest()) 
    h2 = bytes_to_long(sha256(h2).digest()) 
    print("---after hash","h1",h1,"h2",h2)
    print("s1",s1,"s2",s2)
    print("r1",r1,"r2",r2)
    # d = (s1*h2 - s2*h1 )*inverse_mod(s2*r1-s1*r2,n) %n
    # d = (inverse(s1,n)*h1 %n- inverse(s2,n)*h2 %n)*inverse(inverse(s2,n)*r2%n-inverse(s1,n)*r1%n,n) %n
    k = modDivide((h1 - h2), (s1 - s2),n)
    print("k",k)
    d = modDivide(((s1 * k) - h1), r1,n)
    print("private key d:",d)
    return d

count=0
h1=0;h2=0;s1=0;s2=0;r1=0;r2=0
for _ in range(3):
    print('''
1) talk to Kuruwa
2) login
3) exit''')
    option = input()
    if option == '1':
        count+=1
        msg = input('Who are you?\n')
        if msg == 'Kuruwa':
                print('No you are not...')
        else:
            h = bytes_to_long(sha256(msg.encode()).digest())
            k = k * 1337 % n
            print("server:","h",h,"k",k)
            sig = prikey.sign(h, k)
            if count == 1:
                h1 = msg.encode();s1 = sig.s;r1 = sig.r
            if count == 2:
                h2 = msg.encode();s2 = sig.s;r2 = sig.r
                getPrivateKeyD(h1,h2,s1,s2,r1,r2,n)
            print(f'sig = ({sig.r}, {sig.s})')

    elif option == '2':
        msg = input('username: ')
        r = input('r: ')
        s = input('s: ')
        h = bytes_to_long(sha256(msg.encode()).digest())
        verified = pubkey.verifies(h, Signature(int(r), int(s)))
        if verified:
            if msg == 'Kuruwa':
                print(FLAG)
            else:
                print('Bad username')
        else:
            print('Bad signature')
    else:
        break

