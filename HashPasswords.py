from os import urandom, path as file_path
from hashlib import pbkdf2_hmac as hash_algo
from random import choices
from string import ascii_uppercase as uppercase
from string import ascii_lowercase as lowercase
from string import digits
from random import randrange
import FileCredibility
import encryption
import HashPasswords
import time


PICKLE_FILE = 'pickle.encrypted'


def writePsw(obj, unencoded_file):
  with open(unencoded_file + '.psw', 'wb') as f:
    f.write(obj)
  FileCredibility.updateFiles([unencoded_file + '.psw'])


def readPsw(unencoded_file):
  FileCredibility.fullStop(unencoded_file + '.psw')
  with open(unencoded_file + '.psw', 'rb') as f:
    obj = f.read()
  return obj


def newStore(password, pepper, unencoded_file):
  generate_pickle_list()
  password = password + pepper + randPickle()
  salt = urandom(32)
  key = hash_algo('sha256', password.encode('utf-8'), salt, 100000)
  writePsw(salt+key, unencoded_file)


def buildNew(password, salt):
  key = hash_algo('sha256', password.encode('utf-8'), salt, 100000)
  return key


def retrieve(unencoded_file):
  storage = readPsw(unencoded_file)
  return storage[:32], storage[32:]


def pass_compare_with_pickle(password, sal, pep, unencoded_file, email, return_dict) -> bool:
  FileCredibility.fullStop('userData.encrypted')
  with open('userData.encrypted', 'rb') as ud:
    enc_bytes_file = ud.read()
  for pickle in get_pickle_list():
    try:
      dec = HashPasswords.calcMaster(password, sal, pep, pickle)
      bytes_object = encryption.decrypt_bytes(enc_bytes_file, dec)
      fname, femail = bytes_object.decode().split('\n')
      if email == femail:
        return_dict[0] = (True, fname, femail)
        return
    except:
      pass
  
  return_dict[0] = (False, '', '')
  


def pass_compare(password, pepper, pickle, unencoded_file) -> bool:
  password = password + pepper + pickle
  storage = retrieve(unencoded_file)
  salt_from_storage = storage[0]
  org_key = storage[1]
  key_check = hash_algo(
    'sha256',
    password.encode('utf-8'), # Convert the password to bytes
    salt_from_storage, 
    100000
  )

  return org_key == key_check


def generatePepper(str_len): # rand str of len @param::str_len, [ABCD...]+[abcd...]
  return ''.join(choices(uppercase + lowercase + digits, k=str_len))


def randPickle():
  pl = get_pickle_list()
  return pl[randrange(0,9)]


def get_pickle_list():
  pickle_list = []
  FileCredibility.fullStop(PICKLE_FILE)
  with open(PICKLE_FILE, 'r') as pickle:
    pickle_list = pickle.readline()
    chunks, chunk_size = len(pickle_list), 6
    
  return [ pickle_list[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]


def generate_pickle_list():
  if file_path.exists(PICKLE_FILE):
    return
  
  with open(PICKLE_FILE, 'w') as f_pickle:
    for i in range(10):
      f_pickle.write(''.join(choices(uppercase + lowercase + digits, k=6)))
  FileCredibility.updateFiles([PICKLE_FILE])
  time.sleep(0.1)
  

def condiments():
  generate_pickle_list()
  salt = urandom(32)
  pepper = generatePepper(8).encode()
  pickle = randPickle()

  saveCondiments(salt, pepper)

  return salt, pepper, pickle



def saveCondiments(s, p):
  with open('salt.encrypted', 'wb') as sout:
    sout.write(s)
  with open('pepper.encrypted', 'wb') as pout:
    pout.write(p)
  FileCredibility.updateFiles(['salt.encrypted', 'pepper.encrypted'])



def calcMaster(ipas, isal, ipep, ipic):
  password = ipas + ipep + ipic.encode()
  out = hash_algo(
    'sha256',
    password, # Convert the password to bytes
    isal, 
    100000
  )
  return out



def calcPeperHash(password, s, p):
  return password + p



def getCondiments():
  FileCredibility.fullStop('salt.encrypted')
  FileCredibility.fullStop('pepper.encrypted')
  with open('salt.encrypted', 'rb') as out:
    sal = out.read()
  with open('pepper.encrypted', 'rb') as out:
    pep = out.read()
  return sal, pep