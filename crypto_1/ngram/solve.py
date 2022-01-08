import random
import json
import functools as fn
import numpy as np
import string
import hashlib

charset = string.ascii_lowercase+string.digits+',. '
charset_idmap = {e: i for i, e in enumerate(charset)}

ksz = 80

def decrypt(ctx, key):
    N, ksz = len(charset), len(key)
    return ''.join(charset[(c-key[i % ksz]) % N] for i, c in enumerate(ctx))

def toPrintable(data):
    ul = ord('_')
    data = bytes(c if 32 <= c < 127 else ul for c in data)
    return data.decode('ascii')

with open('./output.txt') as f:
    ctx = f.readline().strip()[4:]
    enc = bytes.fromhex(f.readline().strip()[6:])
ctx = [charset_idmap[c] for c in ctx]

with open('./ngrams.json') as f:
    ngrams = json.load(f)

@fn.lru_cache(10000)
def get_trigram(x):
    x = ''.join(x)
    # 三個字有出現
    y = ngrams.get(x)
    if y is not None:
        return y
    ys = []
    # 前兩個字 加上 後一個字
    a, b = ngrams.get(x[:2]), ngrams.get(x[2:])
    if a is not None and b is not None:
        ys.append(a+b)
    # 前一個字 加上 後2個字
    a, b = ngrams.get(x[:1]), ngrams.get(x[1:])
    if a is not None and b is not None:
        ys.append(a+b)
    if len(ys):
        return max(ys)
    if any(c not in ngrams for c in x):
        return -25
    # 所有字相加
    return sum(map(ngrams.get, x))

@fn.lru_cache(10000)
def fitness(a):
    plain = decrypt(ctx, a)
    tgs = zip(plain, plain[1:], plain[2:])
    score = sum(get_trigram(tg) for tg in tgs)
    return score

# 生出一堆key
def initialize(size):
    population = []
    for i in range(size):
        key = tuple(random.randrange(len(charset)) for _ in range(ksz))
        population.append(key)
    return population

# 想要用一些高分的key生出下一個世代的key
def crossover(a, b, prob):
    r = list(a)
    for i in range(len(r)):
        if random.random() < prob:
            r[i] = b[i]
    return tuple(r)

def mutate(a):
    r = list(a)
    i = random.randrange(len(a))
    r[i] = random.randrange(len(charset))
    return tuple(r)

def guessKey():
    keys = np.array(initialize(7000))
    scores = np.array([])
    for i in keys:
        scores = np.append(scores,(fitness(tuple(i))))

    keys = keys[scores.argsort()[::-1]][:600]

    for m in range(4000):
        np.random.shuffle(keys)
        for i in range(len(keys)//2):
            child = np.array(crossover(keys[i*2],keys[i*2+1],0.7))
            keys = np.concatenate((keys,[child]))
        np.random.shuffle(keys)
        for i in range(len(keys)//2):
            keys[i] = mutate(keys[i])
        scores = np.array([])
        for i in keys:
            scores = np.append(scores,fitness(tuple(i)))
        keys = keys[scores.argsort()[::-1]][:600]
        scores = scores[scores.argsort()[::-1]][:600]
        print(m,int(scores[0]),decrypt(ctx,keys[0]))
        # print("key",keys[0])
        
    with open("key","a") as f :
        key = keys[0]
        print("key",key,file = f)
        print("crypt:", decrypt(ctx,key),file = f)

def testKey():
    key=[24,23,23,21,12,11,12,33,9,15,37,25,20,17,36,1,26,33,36,12,22,11,2,22
    ,15,28,25,8,4,31,29,21,25,24,19,14,32,19,16,34,27,0,28,8,21,24,21,10
    ,21,28,4,2,6,32,20,33,11,10,36,34,31,30,28,12,10,2,19,27,38,7,0,20
    ,29,38,27,2,21,17,1,28]
    key[2] = key[2] + (ord('t') - ord('m'))
    key[17] = key[17] - (ord('t') - ord('r'))
    key[18] = key[18] + (ord('r') - ord('s'))
    key[19] = key[19] - (charset_idmap[' ']- charset_idmap['e'])
    key[20] = key[20] - (charset_idmap['p']- charset_idmap['n'])
    key[21] = key[21] - (charset_idmap['e']- charset_idmap['a'])
    # key[19] = key[19] - (ord(' ') - ord('e'))
    print("key",key)
    print(len(key))
    print("test:", decrypt(ctx,key))
    return key
def testKey2():
    key=[24,23,23,21,12,10,17,3,10,15,37,25,20,17,36,1,26,31,35,17,22,11,2,22
    ,15,28,25,8,4,31,29,21,25,24,19,14,32,19,16,34,27,0,28,8,21,24,21,10
    ,21,28,4,2,6,32,20,33,11,10,36,34,31,30,28,12,10,2,19,27,38,7,0,20
    ,29,38,27,2,21,17,1,28]
    # key[2] = key[2] + (ord('t') - ord('m'))
    key[2] = key[2] + (ord('t') - ord('m'))
    print("key",key)
    print(len(key))
    print("test:", decrypt(ctx,key))
    return key


def getSol(key,enc):


    k = hashlib.sha512(''.join(charset[k] for k in key).encode('ascii')).digest()
    enc = bytes(ci ^ ki for ci, ki in zip(enc.ljust(len(k), b'\0'), k))
    print('hex(enc) =', enc.hex())
    print('enc =', enc)


if __name__ =="__main__":           
    # guessKey()
    key=testKey()
    getSol(key,enc)