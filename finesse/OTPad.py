import os
import uuid
import base64

def i2b(i):
  return b''.join((n).to_bytes(1, byteorder='big') for n in i)

def b2i(b):
  return [int(f'{byte:08b}', 2) for byte in b]

def xorb(g, r):
  return b''.join([ (g[i] ^ r[i]).to_bytes(1, byteorder='big') for i in range(0, len(g)) ]) 

def Generate(guid):
  g = b2i(guid.bytes)
  r = b2i(os.urandom(len(g)))
  c = xorb(g, r)
  kb = base64.b64encode(i2b(r))
  cb = base64.b64encode(c)
  return (cb, kb)

def Decrypt(bytes, key):
  c = b2i(base64.b64decode(bytes))
  k = b2i(base64.b64decode(key))
  p = xorb(c, k)
  b = i2b(p)
  if len(b) != 16:
      ValueError("Decrypted bytes to not form a valid 16 byte UUID")
  g = uuid.UUID(bytes=b)
  return g

__all__ = ['Generate', 'Decrypt']