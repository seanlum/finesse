import unittest
import uuid
import hashlib
import base64
import os
import qrcode
import time
import sys

from PIL import Image
from pyzbar.pyzbar import decode


# This code is PoC for learning about encryption and ciphers 
# This code is not meant to be used on any production system 
# If it is used on a production system, I have not done adequate testing for it yet.
from finesse import Caesar, Vigenere, OTPad, QROTP, DRGBRando, VIG8

class Test(unittest.TestCase):
    barline = '===================================================================================='
    def __init__(self, *args, **kwargs):
        super(Test, self).__init__(*args, **kwargs)
        
    def test_Caesar(self):
      print(Test.barline)
      plaintext = 'One morning I shot an elephant in my pajamas. How he got stuck in my pajamas, I don\'t know.'
      ciphertext = Caesar.Encipher(plaintext, 13)
      deciphered = Caesar.Decipher(ciphertext, 13)
      print(f'Testing: {plaintext}')
      print(f'Enciphered: {ciphertext}')
      print(f'Deciphered: {deciphered}')
      self.assertEqual(plaintext, deciphered)
      print(Test.barline)

    def test_Vigenere(self):
      print(Test.barline)
      plaintext = 'Of all the gin joints in all the towns in all the world, she walks into mine.'
      key = 'whatadrink'
      encrypted = Vigenere.Encrypt(plaintext, key)
      decrypted = Vigenere.Decrypt(encrypted, key)
      print(f'Testing: {plaintext}')
      print(f'Encrypted: {encrypted}')
      print(f'Decrypted: {decrypted}')
      self.assertEqual(plaintext, decrypted)
      print(Test.barline)

    def test_otp(self):
      print(Test.barline)
      guid = uuid.uuid4()
      ciphertext, otpkey = OTPad.Generate(guid)
      returnGuid = OTPad.Decrypt(ciphertext, otpkey)
      print(f'Original GUID: {guid}')
      print(f'OTP Key: {otpkey}')
      print(f'Seed (secret): {ciphertext}')
      print(f'Return GUID: {returnGuid}')
      self.assertEqual(str(guid), str(returnGuid))
      print(Test.barline)

    def getQRData(self, filename):
      img = Image.open(filename)
      # Decode the QR code
      decoded_objects = decode(img)
      # Extract data from the QR code
      if decoded_objects:
          qr_data = decoded_objects[0].data.decode("utf-8")
          return qr_data
      else:
          return None

    def test_qrotp(self):
      sha256 = hashlib.sha256()
      iv = os.urandom(2048)
      ivb64 = base64.b64encode(iv)
      sha256.update(ivb64)
      # Create QR code for the SHA-256 hex string
      qrsha256instance = qrcode.QRCode(
          version=1,                        # Version 1 is enough for 64 characters
          error_correction=qrcode.constants.ERROR_CORRECT_L,  # Low error correction
          box_size=10,
          border=4,
      )
      qrIV = qrcode.QRCode(
          version=40,             # Use Version 40 for maximum data capacity
          error_correction=qrcode.constants.ERROR_CORRECT_L,  # Lowest error correction
          box_size=10,            # Box size of each module (pixel)
          border=4,               # Border size around the QR code
      )
      qrKey = qrcode.QRCode(
          version=40,             # Use Version 40 for maximum data capacity
          error_correction=qrcode.constants.ERROR_CORRECT_L,  # Lowest error correction
          box_size=10,            # Box size of each module (pixel)
          border=4,               # Border size around the QR code
      )
      qrCipher = qrcode.QRCode(
          version=40,             # Use Version 40 for maximum data capacity
          error_correction=qrcode.constants.ERROR_CORRECT_L,  # Lowest error correction
          box_size=10,            # Box size of each module (pixel)
          border=4,               # Border size around the QR code
      )
      ivhash = sha256.hexdigest()
      # Add the SHA-256 hash to the QR code
      qrsha256instance.add_data(ivhash)
      qrsha256instance.make(fit=True)
      # Add the IV 8192 bytes
      qrIV.add_data(ivb64)
      qrIV.make(fit=True)
      #
      # Encrypt the IV
      cipher, key = QROTP.Encrypt(iv)
      #
      # Add the Cipher 8192 bytes
      qrCipher.add_data(cipher)
      qrCipher.make(fit=True)
      # Add the Key 8192 bytes
      qrKey.make(fit=True)
      qrKey.add_data(key)
      #
      # Decrypt the ciphertext
      check2 = QROTP.Decrypt(cipher, key)
      #
      check2b64 = base64.b64encode(check2)
      # Generate and save the QR code image
      shapath = "sha256_qr_code.png"
      qrkeypath = "key_qr_code.png"
      ciphertextpath = "ciphertext_qr_code.png"
      ivtokenpath = "iv_token_qr_code.png"
      if (ivb64 == check2b64):
        print('Base64 sha256 encrypt and decrypt bytes by xor successfully')
        print(f'Plain Value: {len(ivb64)} bytes')
        print(f'Hash: {ivhash}')
        print(f'Key: {len(key)} bytes')
        print(f'Cipher Text: {len(cipher)} bytes')
        print(f'Decryption: {len(check2b64)} bytes')
        print('One Time Key:')
        print(key)
        qrIVImg = qrIV.make_image(fill='black', back_color='white')
        qrCipherImg = qrCipher.make_image(fill='black', back_color='white')
        qrKeyImg = qrKey.make_image(fill='black', back_color='white')
        qrsha256Img = qrsha256instance.make_image(fill='black', back_color='white')
        qrIVImg.save(ivtokenpath)
        qrCipherImg.save(ciphertextpath)
        qrKeyImg.save(qrkeypath)
        qrsha256Img.save(shapath)
      loadCipher = self.getQRData(ciphertextpath)
      loadKey = self.getQRData(qrkeypath)
      loadIV = self.getQRData(ivtokenpath)
      check3 = QROTP.Decrypt(loadCipher, loadKey)
      check3b64 = base64.b64encode(check3)
      print(f'Initialization Bytes: {ivb64}')
      print(f'Ciphertext: {cipher}')
      print(f'Key: {key}')
      print(f'Immediate Decrypt: {check2b64}')
      print(f'Decrypted from QR Code: {check3b64}')
      self.assertEqual(ivb64, check2b64)
      self.assertEqual(ivb64, check3b64)
      self.assertEqual(ivb64, loadIV.encode('utf8'))

    def test_drgbrando(self):
      plaintext = 'Testing plaintext to be encrypted with random data, the more I type, the more data will be encrypted.'
      key = os.urandom(len(plaintext))
      kb64 = base64.b64encode(key)
      e, r = DRGBRando.Encrypt(key, plaintext.encode('utf-8'))
      plain = DRGBRando.Decrypt(kb64, r, e)
      self.assertEqual(plaintext.encode('utf-8'), plain)
      
    def test_vig8(self):
      input_file = open('media\\lorem-ipsum.txt', 'r', encoding='utf-8')
      op = input_file.read()
      input_file.close()
      ok = "氷ゆをい監見ー著営ひあざ愛役リオネ約葉ス前43就ルキ証性破ぐよでー査刊ぜど徳四レ氷立モ応成第ア日紙ねごせ吏別どらでて得経カレコ絵庭づけつぞ。険ラアツ囲閉ク継35続ナエヌ熊外をょス際車兆悩メヤオラ静細ヌラヘミ宿辛男再難チコ課登ク験厳サリク千化じイ。手をむ族13宏し会致あ全航チソロ総10騰ね置2験うよっぼ毎性に訓情ウヲヘテ域筑今汚レイツ土族みうだて必白ルが。"

      print(f'Key: {ok}')
      print(f'Input Text: {len(op)} chars')
      # This is a test of a fancy text generator
      p = op
      k = ok

      print('Encrypt') # Should be a string
      timea = time.time()
      c = VIG8.Encrypt(p, k)
      print(f'Ciphertext: {len(c)} chars')
      timeb = time.time()

      encrypt_time = timeb - timea
      # Encode the encrypted text in base64 and write it as a UTF-8 string
      c_write = base64.b64encode(c.encode('utf-8')).decode('utf-8')
      k_write = str(k)

      # Check if decryption is correct before storing
      timec = time.time()
      d = VIG8.Decrypt(c, k)
      timed = time.time()
      decrypt_time = timed - timec
      self.assertEqual(p, d)
      if p == d:
          print('Decryption matches plaintext, paragraphs decrypted')
          
          # Write to log file
          with open('VIG8.log', 'w', encoding='utf-8') as log_output:
              log_output.write(f'Original Plaintext: {op}\n\n')
              log_output.write(f'Original Key: {ok}\n\n')
              log_output.write(f'Plaintext: {p}\n\n')
              log_output.write(f'Key: {k_write}\n\n')
              log_output.write(f'Decrypted: {d}\n\n')
              log_output.write(f'Encrypted: {c_write}\n\n')
          
          # Save the key and ciphertext
          with open('VIG8-key.log', 'w', encoding='utf-8') as key_file:
              key_file.write(k_write)
              
          with open('VIG8-ciphertext.log', 'w', encoding='utf-8') as cipher_text:
              cipher_text.write(c_write)
      else:
          print(f'Does not match')

      # Load the key
      keyfile = open('VIG8-key.log', 'r', encoding='utf-8')
      key = keyfile.read()
      keyfile.close()
      # Load and decode the base64-encoded ciphertext
      cipher_encodedfile = open('VIG8-ciphertext.log', 'r', encoding='utf-8')
      cipher = base64.b64decode(cipher_encodedfile.read()).decode('utf-8')  # Decode to UTF-8 string only here
      cipher_encodedfile.close()
      # Load the plaintext
      plaintextfile = open('media\\lorem-ipsum.txt', 'r', encoding='utf-8')
      plaintext = plaintextfile.read()
      plaintextfile.close()

      # Decrypt
      decrypted = VIG8.Decrypt(cipher, key)
      self.assertEqual(plaintext, decrypted)
      if decrypted == plaintext:
          print('Decryption matches plaintext')
      else:
          print('Decryption does not match')

      

if __name__ == '__main__':
    unittest.main()