from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.schemes.pkenc.pkenc_elgamal85 import ElGamal
from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.eccurve import prime192v2
from charm.core.math.integer import integer
from charm.toolbox.integergroup import IntegerGroupQ

# Generate key pair
p = integer(148829018183496626261556856344710600327516732500226144177322012998064772051982752493460332138204351040296264880017943408846937646702376203733370973197019636813306480144595809796154634625021213611577190781215296823124523899584781302512549499802030946698512327294159881907114777803654670044046376468983244647367)
q = integer(74414509091748313130778428172355300163758366250113072088661006499032386025991376246730166069102175520148132440008971704423468823351188101866685486598509818406653240072297904898077317312510606805788595390607648411562261949792390651256274749901015473349256163647079940953557388901827335022023188234491622323683)

groupObj = IntegerGroupQ()
elgamal = ElGamal(groupObj, p, q) 

# >>> This group is more consistent but the msg must be 20 bytes 
# >>> message len should be group.bitsize() len for prime192v1 (or 20 bytes)
# groupObj = ECGroup(prime192v2)
# el = ElGamal(groupObj)   

# Generate key pair
(pk, sk) = elgamal.keygen()

# Encrypt a message
plaintext = b"This is a secasdfsafsafdsfasdfret message."
ciphertext = elgamal.encrypt(pk, plaintext)

# Decrypt the message
decrypted_message = elgamal.decrypt(pk, sk, ciphertext)

# Print the decrypted message
print(decrypted_message.decode())
