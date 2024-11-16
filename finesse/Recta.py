
# Author: Sean Lum
# GitHub: https://www.github.com/seanlum
# Date:   November, 14th, 2024
# Title:  Recta - The VIG8 algorithm, but with a slight twist
#======================================================================
# Begin Recta encryption
#======================================================================

g = [ 
     [ i for i in range(0x00000000, 0x0010FFFF, 1) ],
     [ j for j in range(0x00000000, 0x0010FFFF, 1) ] 
]

"""Integers to characters"""
def i2c(i):
  return ''.join(chr(j) for j in i)

"""Characters to Integers"""
def c2i(s):
  return [ ord(c) for c in list(s) ]

"""Handles per character change for Vigenere"""
def M(n,i,k,c,m):
  o = n.index(c)^i.index(k)
  return n[o % len(n)]

"""Encrypts or decrypts Vigenere"""
def F(x, k, m):
  x = c2i(x)
  y = c2i(k)
  for e in range(0,len(x)):
    for i in g:
      if y[e % len(y)] in i:
        for h in g:
          if x[e] in h:
            x[e] = M(h, i,y[e % len(y)],x[e],m)
            break
        break
  return i2c(x)
  
"""Encrypts p with k in Vigenere"""
def Encrypt(plaintext, key):
  return F(plaintext, key, '+')

"""Decrypts c with k in Vigenere"""
def Decrypt(ciphertext, key):
  return F(ciphertext, key, '-')

__all__ = ['Encrypt', 'Decrypt']