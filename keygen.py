from Crypto.PublicKey import RSA
import Crypto.Random

key = RSA.generate(1024, Crypto.Random.get_random_bytes, e=65537)
publicKey = key.publickey()
f = open('privateKey.pem', 'wb')
f.write(key.export_key('PEM'))
f.close()

f = open('publicKey.pem', 'wb')
f.write(publicKey.export_key('PEM'))
f.close()

print('All done!')