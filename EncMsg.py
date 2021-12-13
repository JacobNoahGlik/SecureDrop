import ECDH
import encryption
from tinyec import registry, ec
from random import randrange
import FileCredibility
import HashPasswords
import certificate_authority
import cryptography
# from shutil import copyfile


def decrypt_incoming_file(file_name, encoding, one_time_private_key, sal = b'\xdd:\x12\xb3b\xab&\xa6\xaat\xbfM\xc2G\xc7@P\xd3\xba,>\xd5\x91\x06N\xf4\xfe\x0c\xccf\\\xbb') -> bool:
  ca_responce, file = certificate_authority.Authenticate('s.pub')
  if not ca_responce:
    raise cryptography.exceptions.InvalidSignature()

  status = True
  sym_key = ECDH.compress(
    ECDH.getShairKey(
      one_time_private_key, 
      readPublicKey(file)
    )
  )
  #sym_key = one_time_private_key
  url_safe_sym_key = HashPasswords.calcMaster(sym_key, sal, b'', 'sym')
  FileCredibility.fullStop(file_name + encoding)
  with open(file_name + encoding, 'rb') as fout:
    enc_byte_file = fout.read()
  byte_file = encryption.decrypt_bytes(enc_byte_file, url_safe_sym_key)#base64.decodebytes
  try:
    with open(file_name + encoding, 'wb') as fin:
      fin.write(byte_file)
  except:
    status = False
  FileCredibility.updateFiles([file_name + encoding])
  return status

  

def new_Pri_Pub(seed):
  CurrentCurve = ECDH.getCurve(randrange(seed))  # generate random int 0 to 99999999
  pri_key = ECDH.getPri(CurrentCurve)
  pub_key = ECDH.getPub(pri_key, CurrentCurve)

  return pri_key, pub_key


def formatKey(pub_key):
  return "[" + pub_key.curve.name + ',' + str(pub_key.x) + ',' + str(pub_key.y) + "]"


# @return private key
def gen_receiver_key_file(): 
  PriPubPair = new_Pri_Pub(99999999)
  pri_key = PriPubPair[0]
  pub_key = PriPubPair[1]
  with open('r.pub', 'w') as write:
    write.write(formatKey(pub_key))
  FileCredibility.updateFiles(['r.pub'])
  responce, _ = certificate_authority.requestSignature('r.pub')
  if not responce:
    return -1
  return pri_key



def readPublicKey(init_file):
  FileCredibility.fullStop(init_file)
  with open(init_file, 'r') as out:
    content = out.readline().replace('[', '').replace(']', '').split(',')
    
  return ec.Point(registry.get_curve(content[0]), int(content[1]), int(content[2]))



# @return (bool, symmetric key)
def gen_sender_key_file():
  ca_responce, file = certificate_authority.requestSignature('r.pub')
  if not ca_responce:
    raise cryptography.exceptions.InvalidSignature()

  external_public_key = readPublicKey(file)
  pri_key = ECDH.getPri(external_public_key.curve)
  pub_key = ECDH.getPub(pri_key, external_public_key.curve)

  with open('s.pub', 'w') as write:
    write.write(formatKey(pub_key))
  FileCredibility.updateFiles(['s.pub'])
  
  responce, _ = certificate_authority.requestSignature('s.pub')
  if not responce:
    return -1

  return ECDH.compress(pri_key * external_public_key)


def gen_send_file(b64_sym_key, file_name, encoding, sal = b'\xdd:\x12\xb3b\xab&\xa6\xaat\xbfM\xc2G\xc7@P\xd3\xba,>\xd5\x91\x06N\xf4\xfe\x0c\xccf\\\xbb'):
  url_safe_key = HashPasswords.calcMaster(b64_sym_key, sal, b'', 'sym')
  return encryption.encrypt_symmetric(url_safe_key, file_name + encoding, file_name + '.zok')


def getSymKey(pub_file, pri):
  pub = readPublicKey(pub_file)
  return ECDH.compress(ECDH.getShairKey(pub, pri))


""" OUTDATED
def addEncoding(file_name):
  if not '.' in file_name:
    return None

  file_name = file_name.replace('.', '_') + '.zok'
  return file_name


  # try .rrreplace it might start from the back
def removeEncoding(file_name): 
  if not '.zok' in file_name:
    return None
  num_underscores = file_name.count('_')
  file_name = file_name.replace('.zok', '').replace('_', ".").replace(".", "_", num_underscores - 1)
  return file_name
"""