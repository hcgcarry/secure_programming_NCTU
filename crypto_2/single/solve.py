import hashlib
from collections import namedtuple
from Crypto.Util.number import inverse, bytes_to_long
from sage.all import *

O = 'INFINITY'
Point = namedtuple("Point", "x y")

# A = Point(x=3559969491150955424711514609117704515190987918382939076960524487427954179375, y=158589341254460011923837341338366567711140291929530351314919359064555626824)
# B = Point(x=7696467322202079656180364093044174206538519128695735917063341680544217683954, y=4942606694584754914290820206006881586434095915953644948597848045853102493056)
A = Point(x=3829488417236560785272607696709023677752676859512573328792921651640651429215, y=7947434117984861166834877190207950006170738405923358235762824894524937052000)
B = Point(x=9587224500151531060103223864145463144550060225196219072827570145340119297428, y=2527809441042103520997737454058469252175392602635610992457770946515371529908)
enc = "1536c5b019bd24ddf9fc50de28828f727190ff121b709a6c63c4f823ec31780ad30d219f07a8c419c7afcdce900b6e89b37b18b6daede22e5445eb98f3ca2e40"
# enc = "5c16e6498ae7b11c04f552a3132e7f42c62b2d39c57d8c21f705705c1124ac0e033ed96139055129c4c2c5c5c17e3833387686e55d2740a8d6480a0d77e7bfb5"

p = 9631668579539701602760432524602953084395033948174466686285759025897298205383

gx = 5664314881801362353989790109530444623032842167510027140490832957430741393367
gy = 3735011281298930501441332016708219762942193860515094934964869027614672869355
G = Point(gx, gy)
def get_curveParam_a_b(G,A):
    # y**2 =x**3 +ax +b (mod p)
    x1 =G.x; y1 = G.y
    x2 = A.x;y2= A.y
    a = (y1**2-y2**2 - x1**3 +x2**3 )* inverse(x1-x2,p) %p
    b = (y1**2 - x1**3 - a*x1) %p
    print("a",a,"b",b)
    return a,b
a,b = get_curveParam_a_b(G,A)

def checkSingular(a,b):
    if (4*a**3 +27*b**2) %p == 0:
        print("check Singular")
    else:
        print("not singular")

checkSingular(a,b)


def point_inverse(P):
    if P == O:
        return P
    return Point(P.x, -P.y % p)
def point_multiply(P, d):
    bits = bin(d)[2:]
    Q = O
    for bit in bits:
        Q = point_addition(Q, Q)
        if bit == '1':
            Q = point_addition(Q, P)
    assert is_on_curve(Q)
    return Q
def fi_transfer(Point,p):
    return Point.x * inverse(Point.y,p) %p
def checkNode():
    x = var('x')
    solve()
def fi_transfer_2(Point,p):
    x = Point.x
    y = Point.y
    return y+sqrt(a-b)

def is_on_curve(P):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p
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

# def checkAnomalous_curve(p,a,b,G):
#     E=EllipticCurve(GF(p),[a,b])
#     G_tmp = E(G.x,G.y)
#     singular_point = E.singular_points()[0]
#     F = GF(23981)
#     A.<x,y>=F[]
#     C=Curve(y^2-(x^3+17230*x+22699))
#     print("singular_point",singular_point)
#     print("p",p,"order",G_tmp.order())

def getdA(p,a,b,G,A,B):
    x,y = GF(p)['x,y'].gens()
    f = x**3 +  a*x + b
    C = Curve(-y**2 + f)
    singular_point = C.singular_points()[0][0]
    print("singular_point",singular_point)

    f_ = f.subs(x=x+singular_point)
    # G_ = (GF(p)(G.x-singular_point), GF(p)(G.y))
    # A_ = (GF(p)(A.x-singular_point), GF(p)(A.y))
    # B_t = (GF(p)(B.x-singular_point), GF(p)(B.y))
    G_ = ((G.x-singular_point), (G.y))
    A_ = ((A.x-singular_point), (A.y))
    
    # run 依次這個檔案就知道這個值是怎麼來的,他是Node 的beta
    beta_square_root = GF(p)(2559728733519623462165709156994202738915871345165545624745656061903971797242).square_root()
    print("factor",f_.factor())
    u = (G_[1] + beta_square_root*G_[0])/(G_[1] - beta_square_root*G_[0]) % p
    v = (A_[1] + beta_square_root*A_[0])/(A_[1] - beta_square_root*A_[0]) % p
    dA = discrete_log(v, u)
    return dA



dA  =getdA(p,a,b,G,A,B)
    

# checkAnomalous_curve(p,a,b,G)

assert is_on_curve(G)
assert is_on_curve(A)
assert is_on_curve(B)

print("A",fi_transfer(A,p))
print("G",fi_transfer(G,p))
# dA = fi_transfer(A,p)*inverse(fi_transfer(G,p),p) %p

print("dA",dA)


k = point_multiply(B, dA).x
k = hashlib.sha512(str(k).encode('ascii')).digest()
FLAG= bytes.fromhex(enc)
flag = bytes(ci ^ ki for ci, ki in zip(FLAG.ljust(len(k), b'\0'), k))
print("flag",flag)