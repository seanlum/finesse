
# Author: Sean Lum
# GitHub: https://www.github.com/seanlum
# Date:   November, 14th, 2024
# Title:  RectaFast - The Recta algorithm, but using a lookup table and a vector buffer
# Test Key Size: 512-bytes
# Test File Size: 667648 bytes
# Encrypt Time: 0.36080217361450195
# Decrypt Time: 14.674391508102417
#======================================================================
# Begin RectaFast encryption
#======================================================================
import numpy
import hashlib

"""Seed with the key"""
def sg(k):
    if not isinstance(k, (bytes, bytearray)):
        k = bytes(k)
    h = hashlib.sha256(k).hexdigest()
    s = int(h, 16)
    numpy.random.seed(s % (2**32))  # Use consistent 32-bit seeding

"""Create the 256x256 lookup table"""
def fg(k):
  sg(k)  # Seed RNG with the key
  R = numpy.zeros((256, 256), dtype=numpy.uint8)
  for k in range(256):
      R[:, k] = numpy.random.permutation(256)  # Unique permutation for each column
  return R

"""Binary to integers"""
def b2i(b):
    return list(b)

"""Integers to binary"""
def i2b(i):
    return bytes(i)

"""Handles per character change for Vigenere"""
def M(g, n, k, reverse=False):
    if reverse:
        # Reverse lookup: Find the plaintext corresponding to g[n, k]
        for i in range(256):
            if g[i, k] == n:
                return i
        raise ValueError(f"Invalid ciphertext byte {n} for key {k}")
    else:
        # Forward lookup: Encryption
        return g[n, k]

"""Encrypts or decrypts Vigenere"""
def F(x, k, reverse=False):
    g = fg(k)  # Generate the lookup table based on the key
    x = b2i(x)  # Convert binary to integers
    y = b2i(k)  # Convert key to integers
    x = numpy.array(x, dtype=numpy.uint8)
    y = numpy.array([y[e % len(y)] for e in range(len(x))], dtype=numpy.uint8)
    
    # Apply the lookup table (reverse if decrypting)
    if reverse:
        z = [M(g, n, k, reverse=True) for n, k in zip(x, y)]
    else:
        z = [M(g, n, k) for n, k in zip(x, y)]
    
    return i2b(z)  # Convert back to binary

"""Encrypts plaintext with the key"""
def Encrypt(plaintext, key):
    return F(plaintext, key, reverse=False)

"""Decrypts ciphertext with the key"""
def Decrypt(ciphertext, key):
    return F(ciphertext, key, reverse=True)

__all__ = ['Encrypt', 'Decrypt']
