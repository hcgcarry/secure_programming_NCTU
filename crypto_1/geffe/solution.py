
from correlation import *
import itertools
stream = [0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1]

def decode_flag(key):
    sha1 = hashlib.sha1()
    sha1.update(str(key).encode('ascii'))
    key = sha1.digest()[:16]
    iv = bytes.fromhex("cd2832f408d1d973be28b66b133a0b5f")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encode_flag = bytes.fromhex("1e3c272c4d9693580659218739e9adace2c5daf98062cf892cf6a9d0fc465671f8cd70a139b384836637c131217643c1")
    flag = cipher.decrypt(encode_flag)
    print("flag",flag)


def findKey(key_len,tupleArray):
    result=[]
    for pickNum in range(key_len):
        print("pickNum",pickNum)
        for pick_set in itertools.combinations(range(key_len),pickNum):
            # 直接取 stream 的來用是因為相似度很高
            key_candidates = [ 1-stream[i] if i in pick_set else stream[i] for i in range(key_len)]
            cyper = LFSR(key_candidates,tupleArray)
            newStream = [cyper.getbit() for _ in range(256)]
            matchs = sum(a==b for a,b in zip(newStream ,stream))
            if matchs >=180:
                print("find key_candidates:",key_candidates)
                # result.append(key_candidates)
                return key_candidates
                # break;
    return result
        

def bitlist2number(bitlist):
    out = 0
    for bit in bitlist:
        out = (out << 1) | bit
    return out
            
def getKey_19(key_27,key_23):
    lsfr_27 =LFSR(key_27, [27, 26, 25, 22])
    lsfr_23 = LFSR(key_23, [23, 22, 20, 18])
    key_19 = [-1] * 19
    lsfr_19 = LFSR(key_19, [19, 18, 17, 14])
    for i in range(256):
        a=  lsfr_23.getbit()
        b=  lsfr_27.getbit()
        if a!=b:
            if a == stream[i]:
                key_19[i%19] = a
            else:
                key_19[i%19] = b
            
    return key_19
    
def findKey19(key_len,tupleArray,key_27,key_23):
    for pickNum in range(key_len):
        print("pickNum",pickNum)
        for pick_set in itertools.combinations(range(key_len),pickNum):
            # 直接取 stream 的來用是因為相似度很高
            key_candidates = [ 1-stream[i] if i in pick_set else stream[i] for i in range(key_len)]
            lsfr_19 = LFSR(key_candidates,tupleArray)
            lsfr_27 =LFSR(key_27, [27, 26, 25, 22])
            lsfr_23 = LFSR(key_23, [23, 22, 20, 18])

            newStream=[]
            for _ in range(256):
                a = lsfr_19.getbit();b = lsfr_27.getbit();c= lsfr_23.getbit()
                k  = b if a else c
                newStream.append(k)

            matchs = sum(a==b for a,b in zip(newStream ,stream))
            if matchs ==256:
                print("find key_candidates:",key_candidates)
                # result.append(key_candidates)
                return key_candidates
                # break;

if __name__ == "__main__":
    print("key_27")
    # key_candidates_27 = findKey(27,[27,26,25,22])
    key_candidates_27 = [0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1]
    print("key_23")
    # key_candidates_23 = findKey(23,[23,22,20,18])
    key_candidates_23 = [0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1]
    # for key_27 in key_candidates_27:
    #     for key_23 in key_candidates_23:
    # key_candidates_19 = getKey_19(key_candidates_27,key_candidates_23)
    key_candidates_19 = findKey19(19,[19, 18, 17, 14],key_candidates_27,key_candidates_23)
    print('key_19',key_candidates_19)
    key = key_candidates_19 + key_candidates_27 + key_candidates_23
    key = bitlist2number(key)
    print("key",key)
    # key = 203423563983610905229
    decode_flag(key)

            