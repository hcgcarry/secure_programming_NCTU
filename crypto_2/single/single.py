#!/bin/env python3
# from secrets import a, b, FLAG
from collections import namedtuple
from Crypto.Util.number import inverse, bytes_to_long
import hashlib
import random

Point = namedtuple("Point", "x y")
O = 'INFINITY'

def is_on_curve(P):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p

def point_inverse(P):
    if P == O:
        return P
    return Point(P.x, -P.y % p)

def point_addition(P, Q):
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P):
        return O
    else:
        if P == Q:
            s = (3*P.x**2 + a)*inverse(2*P.y, p) % p
        else:
            s = (Q.y - P.y) * inverse((Q.x - P.x), p) % p
    Rx = (s**2 - P.x - Q.x) % p
    Ry = (s*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert is_on_curve(R)
    return R

def point_multiply(P, d):
    bits = bin(d)[2:]
    Q = O
    for bit in bits:
        Q = point_addition(Q, Q)
        if bit == '1':
            Q = point_addition(Q, P)
    assert is_on_curve(Q)
    return Q

def get_curveParam_a_b(G,A):
    # y**2 =x**3 +ax +b (mod p)
    x1 =G.x; y1 = G.y
    x2 = A.x;y2= A.y
    a = (y1**2-y2**2 - x1**3 +x2**3 )* inverse(x1-x2,p) %p
    b = (y1**2 - x1**3 - a*x1) %p
    print("a",a,"b",b)
    return a,b
if __name__ == "__main__":
    p = 9631668579539701602760432524602953084395033948174466686285759025897298205383
    gx = 5664314881801362353989790109530444623032842167510027140490832957430741393367
    gy = 3735011281298930501441332016708219762942193860515094934964869027614672869355
    G = Point(gx, gy)
    a,b = (9605275265879631008726467740646537125692167794341640822702313056611938432994 ,7839838607707494463758049830515369383778931948114955676985180993569200375480)
    
    assert is_on_curve(G)

    #Alice
    # dA = random.randint(1, p-2)
    dA = 4770074603092273060710741004977720995010845762448275347366454290851081410074
    print("dA",dA)
    A = point_multiply(G, dA)
    print('A =', A)

    #Bob
    dB = random.randint(1, p-2)
    B = point_multiply(G, dB)
    print('B =', B)

    assert is_on_curve(G)
    assert is_on_curve(A)
    assert is_on_curve(B)
    #Encryption
    k = point_multiply(B, dA).x
    k = hashlib.sha512(str(k).encode('ascii')).digest()
    enc = bytes(ci ^ ki for ci, ki in zip(FLAG.ljust(len(k), b'\0'), k))
    print('enc =', enc.hex())
