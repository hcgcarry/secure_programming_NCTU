#!/bin/env python3 -u
import os

# tmp = 1101110001011101001110100100110010010001000111010000100100001101
state = 15878911961704761613

# state = int.from_bytes(os.urandom(8), 'little')
# state = int.from_bytes(tmp, 'little')

print("server: start state = ",bin(state)[2:].rjust(64,'0'),"state",state)
poly = 0xaa0d3a677e1be0bf
count = 0
def step():
    global state
    global count 
    count +=1
    # if p:
    #     print("server: state = ",bin(state)[2:],"count",count)
    out = state & 1
    state >>= 1
    if out:
        state ^= poly
    return out
    

def random():
    for _ in range(42):
        step()
    return step()



money = 1.2
y_list = []
while money > 0:
    x = int(input('> '))
    print("state",bin(state))
    y = random()
    y_list.append(y)
    # print("y_list:",y_list)
    if x == y:
        money += 0.02
    else:
        money -= 0.04
    print(money)
    if money > 2.4:
        print("Here's your flag:")
        with open('./flag.txt') as f:
            print(f.read())
        exit(0)
print('E( G_G)')
