# Elliptic-curve Diffie–Hellman
# info: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman

# examples from https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange-examples

from tinyec import registry, ec
import secrets
import string
import random


def genRandStrLen(length) -> str:
  letters = string.ascii_uppercase + string.ascii_lowercase
  return ''.join(random.choice(letters) for i in range(length))


def compress(pubKey):
  return (hex(pubKey.x) + hex(pubKey.y % 2)[2:]).encode()


def test():
  curve = registry.get_curve("secp521r1") # get rand curve

  alicePrivKey = secrets.randbelow(curve.field.n)
  alicePubKey = alicePrivKey * curve.g
  print("Alice public key:", compress(alicePubKey))

  bobPrivKey = secrets.randbelow(curve.field.n)
  bobPubKey = bobPrivKey * curve.g
  print("Bob public key:", compress(bobPubKey))

  print("Now exchange the public keys (e.g. through Internet)")

  aliceSharedKey = alicePrivKey * bobPubKey
  print("Alice shared key:", compress(aliceSharedKey))

  bobSharedKey = bobPrivKey * alicePubKey
  print("Bob shared key:", compress(bobSharedKey))

  print("Equal shared keys:", aliceSharedKey == bobSharedKey)


def getExactCurveName(num) -> str:
  list_o_curves = "secp192r1", 'secp224r1', 'secp256r1', 'secp384r1', 'secp521r1', 'brainpoolP256r1', 'brainpoolP160r1', 'brainpoolP192r1', 'brainpoolP224r1', 'brainpoolP320r1', 'brainpoolP384r1', 'brainpoolP512r1'
  return list_o_curves[num]
  

def getCurve(i_rand):
  return registry.get_curve(getExactCurveName(int( (i_rand) % 12 )))


def getPri(curve):
  return secrets.randbelow(curve.field.n)


def getPub(pri_key, curve):
  return pri_key * curve.g


def getShairKey(self_pri_key, external_pub_key):
  return self_pri_key * external_pub_key


def test_scrypt():
  A_curve = getCurve(5)
  A_pri = getPri(A_curve)
  A_pub = getPub(A_pri, A_curve)

  B_curve = getCurve(5)
  B_pri = getPri(B_curve)
  B_pub = getPub(B_pri, B_curve)

  A_sym = getShairKey(A_pri, B_pub)
  B_sym = getShairKey(B_pri, A_pub)

  A_Parts = ( A_pub.curve.name, A_pub.x, A_pub.y )

  print(A_Parts)
  p1 = ec.Point( registry.get_curve(A_Parts[0]), A_Parts[1], A_Parts[2] )

  P_sym = getShairKey(B_pri, p1)



  #print(f'P is {p1}')

  #print(f'A_sym:', compress(A_sym))
  #print(f'B_sym:', compress(B_sym))
  #print(f'P_sym:', compress(P_sym))

  print("Are eq:", A_sym == B_sym)

  print(f'p1 is a sutable replacement:{A_sym == P_sym}')