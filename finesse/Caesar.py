# Author: Sean Lum
# GitHub: https://www.github.com/seanlum
# Date:   November, 12th, 2024
# Title:  Caesar PoC
#======================================================================
# Begin Caesar Cipher
#======================================================================

g = [
  'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  'abcdefghijklmnopqrstuvwxyz'
]

"""Handles the index for C in X in Caesar"""
def M(n,k,c,m):
  o = n.index(c)-k if m == '-' else n.index(c)+k 
  return n[o % (len(n)-1)]

"""Enciphers or deciphers X in Caesar"""
def Process(x, k, m):
  x = list(x)
  for e in range(0,len(x)):
    for h in g:
      if x[e] in h:
        x[e] = M(h,k,x[e],m)
        break
  return ''.join(x)
  
"""Enciphers X in Caesar"""
def Encipher(plaintext, shift):
  return Process(plaintext, shift, '+')

"""Deciphers X in Caesar"""
def Decipher(ciphertext, shift):
  return Process(ciphertext, shift, '-')

__all__ = ['Encipher', 'Decipher']