
from pwn import *
from Crypto.Util.number import *



r = remote("edu-ctf.csie.org",42071)


q = r.recvline()
n = int(q[4:])
q = r.recvline()
c = int(q[4:])

e = 65537

inver= inverse(3,n)
i=0
b=0
m=0
exitCount=0

while 1:
    r.sendline(str(pow(inver,i*e,n)*c%n).encode())
    q = r.recvline()
    mm = (int(q.split()[-1]) - (inver*b)%n)%3
    if mm == 0:
        exitCount+=1
        if exitCount == 10:
            break;
    else:
        exitCount = 0
    b = (inver*b + mm) %n
    m = 3**i*mm+m
    print(m)
    i+=1
        
print(m)
print(long_to_bytes(m))




