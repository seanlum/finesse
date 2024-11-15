# Author: Sean Lum
# GitHub: https://www.github.com/seanlum
# Date:   November, 12th, 2024
# Title:  DRGB-rando PoC
# Description: 
# Following the algorithm:
#   E(K, R, P) = (DRBG(K R) ^ P, R)
# But instead doing the following:
#   E(K, R, P) = ((K ^ R) ^ (P ^ R))
# len(R) and len(K) is always equal to len(P)
#   - which makes the XOR key strong
#   - K and R are both random, making P hard to calculate
#======================================================================
# Modular bit XOR Encryption 
#======================================================================

import os
import base64

def i2b(i):
  return b''.join((n).to_bytes(1, byteorder='big') for n in i)

def b2i(b):
  return [int(f'{byte:08b}', 2) for byte in b]

def xorb(g, r):
  return b''.join([ (g[i] ^ r[i]).to_bytes(1, byteorder='big') for i in range(0, len(g)) ]) 

def Encrypt(key, plaintext):
  k = b2i(key)
  r = b2i(os.urandom(len(key)))
  p = b2i(plaintext)
  dbrg = xorb(key, r)
  pr = xorb(plaintext, r)
  e = xorb(b2i(dbrg), b2i(pr))
  eb = base64.b64encode(i2b(e))
  rb = base64.b64encode(i2b(r))
  return (eb, rb)

def Decrypt(k, r, e):
  kb = b2i(base64.b64decode(k))
  rb = b2i(base64.b64decode(r))
  eb = b2i(base64.b64decode(e))
  dbrg = xorb(kb, rb)
  pr  = xorb(eb, dbrg)
  p = xorb(pr, rb)
  r = i2b(p)
  return r

__all__ = ['Encrypt', 'Decrypt']