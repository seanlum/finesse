
# Author: Sean Lum
# GitHub: https://www.github.com/seanlum
# Date:   November, 12th, 2024
# Title:  Vigenere PoC
# Algebraic description
# https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher
# Adapted from my Caesar PoC
#======================================================================
# Begin Vigenere encryption
#======================================================================

g = [
  'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  'abcdefghijklmnopqrstuvwxyz'
]

"""Handles per character change for Vigenere"""
def M(n,i,k,c,m):
  o = n.index(c)-i.index(k) if m == '-' else n.index(c)+i.index(k)
  return n[o % len(n)]

"""Encrypts or decrypts Vigenere"""
def Process(x, k, m):
  x = list(x)
  y = list(k)
  for e in range(0,len(x)):
    for i in g:
      if y[e % len(y)] in i:
        for h in g:
          if x[e] in h:
            x[e] = M(h, i,y[e % len(y)],x[e],m)
            break
        break
  return ''.join(x)
  
"""Encrypts p with k in Vigenere"""
def Encrypt(plaintext, key):
  return Process(plaintext, key, '+')

"""Decrypts c with k in Vigenere"""
def Decrypt(ciphertext, key):
  return Process(ciphertext, key, '-')

__all__ = ['Encrypt', 'Decrypt']