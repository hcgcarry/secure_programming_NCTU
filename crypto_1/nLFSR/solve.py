
from pwn import *
from sage.all import  *
import random
from Crypto.Util.number import *


# state = 1

    
def getPoly(poly):
    result = []
    result = [ -1*int(x) for x in bin(poly)[2:]]
    result.append(1)
    return result


def getCompanion_matrix(poly):
    cp_matrix = companion_matrix(poly, format='right')
    M_space = MatrixSpace(GF(2),64,64)
    # print("M_space",M_space)
    M = M_space.matrix(cp_matrix)
    # print("origin_Matrix",M)
    return M

def getState(r):
    prevMoney = 1.2
    state = []
    r.sendafter(b'> ',b'1\n'*64)
    for i in range(64):
        print("i",i)
        # r.sendlineafter(b'> ',b'1')
        # line = r.recvline()[:-1]
        if i ==0:
            line = r.recvline()[:-1]
        else:
            line = r.recvline()[2:-1]
        print("line",line)
        curMoney = float(line.decode())
        if curMoney == prevMoney - 0.04:
            state.append(0)
        else:
            state.append(1)
        prevMoney = curMoney
        
    
    return vector(state[::-1])

        

       


        
    
def getMatrix(origin_companion_matrix):
    # matrix_multi = copy(origin_companion_matrix**43)
    # acc_matrix = copy(origin_companion_matrix ** 42)
    cur_matrix = Matrix(GF(2),64,64)
    for i in range(64):
        cur_matrix.set_row(63-i,(origin_companion_matrix**(42+43*i)).row(63))
        # cur_matrix[63-i] = (origin_companion_matrix**(42+ 43*i))[63-i]
        # acc_matrix = copy(acc_matrix*  matrix_multi)
        
    # print("final matrix",cur_matrix)
    # print("final matrix.rank",cur_matrix.rank())
    return cur_matrix



# def printInfo(transfer_matrix,origin_companion_matrix):
#     start_state = [ int(x) for x in '1101110001011101001110100100110010010001000111010000100100001101']
#     print("-------------------info")
#     print("start_state",start_state)
#     vec = vector(start_state)
#     print("recover",transfer_matrix*vec)
#     print("-------------------info end")
#     for i in range(64):
#         print("i",i,"value",(origin_companion_matrix**(42+43*i)*vec)[-1])
#         print("i",i,"row",origin_companion_matrix**(42+43*i)[i])
    

    


if __name__ == "__main__":
    origin_state = []
    poly = 0xaa0d3a677e1be0bf
    poly = getPoly(poly)
    print("poly",poly)
    # r = process(["python3","origin/server.py"])
    r = remote("edu-ctf.csie.org","42069")
    server_response_state = getState(r)
    print("server_response_state",server_response_state)

    Companion_matrix = getCompanion_matrix(poly)

    # print("companion_matrix",Companion_matrix)
    final_transfer_matrix = getMatrix(Companion_matrix)
    # printInfo(final_transfer_matrix,Companion_matrix)
    # print("I 42",(Companion_matrix ** 42)[63])
    # print("finaltransfer",final_transfer_matrix)
    # print("companion_matrix",Companion_matrix)
    start_state = (final_transfer_matrix ** -1) * server_response_state
    print("start_state:",start_state)

    count = 0
    curState = Companion_matrix**(64* 43)*start_state
    result =""
    while count <200:
        curState = Companion_matrix**(42)*curState
        count +=1
        print("count",count)
        try:
            r.sendlineafter(b'> ',str(curState[-1]))
        # result+=str(curState[-1]) + "\n"
        except:
            break
        curState = Companion_matrix*curState
        
    print("result",result)
    # r.send(result.encode())



    r.interactive()