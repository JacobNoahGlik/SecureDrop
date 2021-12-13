# used regex documentation and https://medium.com/@almirx101/pgp-key-pair-generation-and-encryption
# -and-decryption-examples-in-python-3-a72f56477c22
# wow that guy is good
import base64
import os
import random
import string
import FileCredibility
import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from string import ascii_uppercase as uppercase
from string import ascii_lowercase as lowercase
from string import digits
import secureDrop


def gen_public_key(pri_key):
    pem_public_key = pri_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_public_key



def encrypt_private_key(pri_key):
    return pri_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def get_private_key(file):
    FileCredibility.fullStop(file)
    with open(file, "rb") as key_file:
        pr_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    return pr_key


def get_public_key(file):
    FileCredibility.fullStop(file)
    with open(file, "rb") as key_file:
        pub_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return pub_key



def save_sym_key(sym_key, pub_key_location):
  with open("sym_file.encoded", 'wb') as write:
    pubKey = get_public_key(pub_key_location)
    pad = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    encrypted_bytes = pubKey.encrypt(sym_key, pad)
    write.write(encrypted_bytes)

  FileCredibility.updateFiles(["sym_file.encoded"])



def get_sym_key(pri_key_location):
    priKey = get_private_key(pri_key_location)
    FileCredibility.fullStop("sym_file.encoded")
    with open("sym_file.encoded", "rb") as sf:
      line = sf.read()
    if not line:
        return
    pad = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    org_bytes = priKey.decrypt(line, pad)
    return org_bytes

def execute(command, key_location, extraction_file, insertion_file):
    if command == '--encrypt':
        symmetric_key = ((''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))).encode())

        encrypt_symmetric(symmetric_key, extraction_file, insertion_file)
        save_sym_key(calculateKey(symmetric_key)[0], key_location)

    elif command == '--decrypt':
        decrypt_symmetric(key_location, extraction_file)


def calculateKey(password):
    if password.decode().lower() == 'q' or password.decode().lower() == 'quit':
      ch = input(f'You enterd {password.decode()}, would you like to quit?(y/n): ')
      while ch.lower() != 'y' and 'n' != ch.lower():
        ch = input(f'You enterd {password.decode()}, would you like to quit?(y/n): ')
      if ch.lower() == 'y':
        secureDrop.leave(False)

    # salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\\x8e\\xfe&\\x92,M38?\\x10\\xa0\\x80\\x98\\xda\\x9cR',
        iterations=100000,
        backend=default_backend()
    )
    pasReq = passRequirements(password.decode())
    return base64.urlsafe_b64encode(kdf.derive(password)), pasReq



def passRequirements(password):
  upperLetterPass = any(upperLetter in password for upperLetter in uppercase)
  lowerLetterPass = any(lowerLetter in password for lowerLetter in lowercase)
  numberPass = any(number in password for number in digits)
  sizePass = len(password) > 7

  return upperLetterPass and lowerLetterPass and numberPass and sizePass


def encrypt_symmetric(encoder, input_file_location, output_file_location):
    FileCredibility.fullStop(input_file_location)
    
    with open(input_file_location, 'rb') as fout:
      byte_file = fout.read()

    enc_bytes = encrypt_bytes(byte_file, encoder)
    with open(output_file_location, "wb") as fin:
      fin.write(enc_bytes)
    FileCredibility.updateFiles([output_file_location])
    return True



def encrypt_file_symmetric(encoder, file_name) -> bool:
  FileCredibility.fullStop(file_name)
  success = True
  encrypt_symmetric(encoder, file_name, 'tmp.txt')
  try:
    os.remove(file_name)
  except:
    success = False
  shutil.copyfile('tmp.txt', file_name)
  os.remove('tmp.txt')
  return success

def decrypt_file_symmetric(decoder, file_name, encoding) -> bool:
  success = True
  masterString = b''
  fernet_obj = Fernet(calculateKey(decoder)[0])

  try:
    lines = b''
    FileCredibility.fullStop(file_name + encoding)
    with open(file_name + encoding, 'rb') as zok:
      lines = zok.readlines()
    for line in lines:
      masterString += fernet_obj.decrypt(line[:-1])
  except:
    success = False
  
  with open(file_name + encoding, 'wb') as inpf:
    inpf.write(masterString)
  FileCredibility.updateFiles([file_name + encoding])
  return success


def decrypt_symmetric(key_location, input_file_location):
    masterString = ""
    fernet_obj = Fernet(get_sym_key(key_location))
    FileCredibility.fullStop(input_file_location)
    for line in open(input_file_location, 'r').readlines():
        plaintextLine = fernet_obj.decrypt(line[:-1].encode()).decode()
        masterString += (str(plaintextLine))
    return masterString


def makeClean(output):
    try:
        os.remove(output)
    except:
        pass


def dec_file(org_file, key_file) -> str:
  FileCredibility.fullStop(key_file)
  return decrypt_symmetric(key_file, org_file)


def enc_file(org_file, key_file, end_location):
  execute('--encrypt', key_file, org_file, end_location)

    
"""CHANGE"""

def encrypt_bytes(orgBytes, encryption_key):
  key = base64.urlsafe_b64encode(encryption_key)
  fer = Fernet(key)
  return fer.encrypt(orgBytes)

def decrypt_bytes(encBytes, encryption_key):
  fer = Fernet(base64.urlsafe_b64encode(encryption_key))
  return fer.decrypt(encBytes)
