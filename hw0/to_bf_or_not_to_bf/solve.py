import cv2      #https://pypi.org/project/opencv-python/
import random
import string

charset = string.ascii_letters + string.digits + '+='
fire, water, earth, air = [random.choice(charset) for _ in range(4)]
print("fire",fire,"earth",earth,"air",air)

def combine(a, b):
    return ''.join([a,b])

def encrypt(arr):
    swamp  = combine(water, earth)
    energy = combine(fire, air)
    lava   = combine(fire, earth)
    life   = combine(swamp, energy)
    stone  = combine(lava, air)
    sand   = combine(stone, water)
    seed   = combine(sand, life)
    print("seed",seed)
    random.seed(seed)
    
    h, w = arr.shape
    for i in range(h):
        for j in range(w):
            arr[i][j] ^= random.randint(0,255)


msg1 = cv2.imread('flag_enc.png', cv2.IMREAD_GRAYSCALE)
msg2 = cv2.imread('golem_enc.png', cv2.IMREAD_GRAYSCALE)
msg =  msg1 ^ msg2
cv2.imwrite("result.png",msg)
