

# Author: Sean Lum
# GitHub: https://www.github.com/seanlum
# Date:   November, 18th, 2024
# Title:  Daedalus Two
# Description: Named after a man who made a Labyrinth, this algorithm 
# makes a labyrinth of paths to take for the entire length of a file
# this algorithm is not meant to be fast or secure; but it does do 
# RNG fairly well.
# https://en.wikipedia.org/wiki/Daedalus
# Test Key Size: 2048 chars
# Test File Size: 512 KB
# Encrypt time: 2.9751834869384766s
# Decrypt time: 5.890410423278809s
# Decrypt matches plaintext
#======================================================================
# Begin RectaFast encryption
#======================================================================

import random

def toS(b):
  return ''.join([ chr(c) for c in b])

def gKB(start, end):
  s = [ i for i in range(start, end)]
  random.shuffle(s)
  return s

def Encrypt(plaintext, key, debug=False):
  k = bytes(key)
  p = bytes(plaintext)
  e = list(plaintext)
  for n in  range(0, 4):
    random.seed(k + bytes(n))
    s = gKB(0,len(p))
    kb = gKB(0,len(p))
    if debug:
      print(f'{n} {s} {kb}')
    for idx in s:
      i = s[idx]
      m = e[i]
      K = kb[i]
      r = (m ^ i ^ K) % 256
      e[i] = r
      if debug:
        print(f'Encrypt: len e ({len(e)}) r={m ^ i ^ K} idx={idx}: r={r} m={m} i={i} K {K}')
  return bytes(e)

def Decrypt(ciphertext, key, debug=False):
  k = bytes(key)
  c = list(ciphertext)  # Decrypt starts with the encrypted text
  p = c.copy()
  
  for n in range(3, -1, -1):
    random.seed(k + bytes(n))
    s = gKB(0, len(c))
    kb = gKB(0, len(c))
    for idx in reversed(s):
      i = s[idx]
      m = p[i]
      K = kb[i]
      r = (m ^ i ^ K) % 256
      if debug:
        print(f'Decrypt: {idx}: r={r} m={m} i={i} K={K}')
      p[i] = r  # Update the plaintext
  return bytes(p)