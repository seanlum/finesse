# Author: Sean Lum
# GitHub: https://www.github.com/seanlum
# Date:   November, 12th, 2024
# Title:  QROTP 2048-byte PoC
# Description: As according to "Perfect Encryption: The One-Time Pad"
#     on page 31 of 314 on Serious Cryptography, Chapter 1
# C = P ^ K = 01101101 ^ 10110100 = 11011001
# P = C ^ K = 11011001 ^ 10110100 = 01101101
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

def Encrypt(b):
  g = b2i(b)
  r = b2i(os.urandom(len(g)))
  c = xorb(g, r)
  kb = base64.b64encode(i2b(r))
  cb = base64.b64encode(c)
  return (cb, kb)

def Decrypt(b, key):
  c = b2i(base64.b64decode(b))
  k = b2i(base64.b64decode(key))
  p = xorb(c, k)
  b = i2b(p)
  return b

__all__ = ['Decrypt', 'Encrypt']