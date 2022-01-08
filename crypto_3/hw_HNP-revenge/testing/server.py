#!/usr/bin/env python3
from random import randint
from Crypto.Util.number import *
from hashlib import sha256, md5
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key, Private_key, Signature

FLAG = b'flag{jfsdkfs}'

E = SECP256k1
G, n = E.generator, E.order

# d = randint(1, n)
d = 113834649906244088505984786565637172817234606687321950610865910955219565050699
# d = 98043621399455152437478889217211723621516362684302566864639761075350546963998
# print("d",d)

pubkey = Public_key(G, d*G)
prikey = Private_key(pubkey, d)
print(f'P = ({pubkey.point.x()}, {pubkey.point.y()})')

f = open("test.txt","w") 
for _ in range(3):
    print('''
1) talk to Kuruwa
2) login
3) exit''')
    option = input()
    if option == '1':
        msg = input('Who are you?\n')
        if msg == 'Kuruwa':
                print('No you are not...')
        else:
            h = sha256(msg.encode()).digest()
            k = int(md5(b'secret').hexdigest() + md5(long_to_bytes(prikey.secret_multiplier) + h).hexdigest(), 16)
            sig = prikey.sign(bytes_to_long(h), k)
            print(f'({sig.r}, {sig.s})')
            print("k",k ,"h",bytes_to_long(h),"e",k & (2**128-1))

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
