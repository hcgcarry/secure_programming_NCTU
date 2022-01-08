
import random
import string
import hashlib

with open("output", 'rb') as f:
    flag = f.read()
k = hashlib.sha512(''.join(charset[k] for k in key).encode('ascii')).digest()
enc = bytes(ci ^ ki for ci, ki in zip(flag.ljust(len(k), b'\0'), k))
print('enc =', enc.hex())