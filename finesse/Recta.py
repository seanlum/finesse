
# Author: Sean Lum
# GitHub: https://www.github.com/seanlum
# Date:   November, 14th, 2024
# Title:  Recta - The VIG8 algorithm, but with a slight twist
#======================================================================
# Begin Recta encryption
#======================================================================

g = [
    [i for i in range(256)],  # All possible byte values (0-255)
    [j for j in range(256)]
]

"""Binary to integers"""
def b2i(b):
    return [int(f'{byte:08b}', 2) for byte in b]

"""Integers to binary"""
def i2b(i):
    return bytes(i)

"""Handles per character change for Vigenere"""
def M(n,i,k,c):
  o = n.index(c)^i.index(k)
  return n[o % len(n)]

"""Encrypts or decrypts Vigenere"""
def F(x, k):
  x = b2i(x)
  y = b2i(k)
  for e in range(0, len(x)):
      for i in g:
          if y[e % len(y)] in i:
              for h in g:
                  if x[e] in h:
                      x[e] = M(h, i, y[e % len(y)], x[e])
                      break
              break
  return i2b(x)
  
"""Encrypts p with k in Vigenere"""
def Encrypt(plaintext, key):
  return F(plaintext, key)

"""Decrypts c with k in Vigenere"""
def Decrypt(ciphertext, key):
  return F(ciphertext, key)

__all__ = ['Encrypt', 'Decrypt']