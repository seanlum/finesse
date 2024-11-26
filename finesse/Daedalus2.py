import random

def toS(b):
    return ''.join([chr(c) for c in b])

def gKB(start, end):
    s = list(range(start, end))
    random.shuffle(s)
    return s

def Encrypt(plaintext, key, debug=False):
    k = key.encode() if isinstance(key, str) else bytes(key)
    p = bytearray(plaintext)
    e = p.copy()
    bs = 16384
    for j in range(0, len(p), bs):
        random.seed(k + j.to_bytes(4, byteorder='big'))
        k2 = random.getrandbits(bs * 8).to_bytes(bs, byteorder='big')
        p2 = p[j:j + bs]
        for n in range(4):
            random.seed(k2 + n.to_bytes(4, byteorder='big'))
            s = gKB(0, len(p2))
            kb = gKB(0, len(p2))
            if debug:
                print(f"Encrypt Block {j}, Round {n}, s={s}, kb={kb}")
            for idx in s:
                i = idx
                m = e[j + i]
                K = kb[i]
                e[j + i] = (m ^ i ^ K) % 256
    return bytes(e)

def Decrypt(ciphertext, key, debug=False):
    k = key.encode() if isinstance(key, str) else bytes(key)
    c = bytearray(ciphertext)
    p = c.copy()
    bs = 16384
    for j in range(len(p) - bs, -1, -bs):
        random.seed(k + j.to_bytes(4, byteorder='big'))
        k2 = random.getrandbits(bs * 8).to_bytes(bs, byteorder='big')
        c2 = c[j:j + bs]
        for n in range(3, -1, -1):
            random.seed(k2 + n.to_bytes(4, byteorder='big'))
            s = gKB(0, len(c2))
            kb = gKB(0, len(c2))
            if debug:
                print(f"Decrypt Block {j}, Round {n}, s={s}, kb={kb}")
            for idx in reversed(s):
                i = idx
                r = p[j + i]
                K = kb[i]
                p[j + i] = (r ^ i ^ K) % 256
    return bytes(p)
