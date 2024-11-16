
# Author: Sean Lum
# GitHub: https://www.github.com/seanlum
# Date:   November, 14th, 2024
# Title:  RectaFast - The Recta algorithm, but using a lookup table and a vector buffer
# Test Key Size: 512-bytes
# Test File Size: 667648 bytes
# Original Encrypt Time: 2.8813841342926025
# Optimized Encrypt Time: 0.5142736434936523
# Optimized Decrypt Time: 0.4942922592163086
#======================================================================
# Begin RectaFast encryption
#======================================================================

import numpy 

def fg():
    T = numpy.zeros((256, 256), dtype=numpy.uint8)
    for n in range(256):
        for k in range(256):
            T[n, k] = (n ^ k) % 256
    return T

g = fg()

"""Binary to integers"""
def b2i(b):
    return [int(f'{byte:08b}', 2) for byte in b]

"""Integers to binary"""
def i2b(i):
    return bytes(i)

"""Handles per character change for Vigenere"""
def M(n, k):
  return g[n, k]

"""Encrypts or decrypts Vigenere"""
def F(x, k):
  x = b2i(x)
  y = b2i(k)
  x = numpy.array(x, dtype=numpy.uint8)
  y = numpy.array([y[e % len(y)] for e in range(len(x))], dtype=numpy.uint8)
  z = numpy.vectorize(M)(x, y)
  return i2b(z.tolist())
  
"""Encrypts p with k in Vigenere"""
def Encrypt(plaintext, key):
  return F(plaintext, key)

"""Decrypts c with k in Vigenere"""
def Decrypt(ciphertext, key):
  return F(ciphertext, key)

__all__ = ['Encrypt', 'Decrypt']