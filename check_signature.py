import base64
import sys

from Cryptodome.Hash import SHA1, SHA224, SHA256, SHA384, SHA512, SHA3_224, \
    SHA3_512, SHA3_256, SHA3_384
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5

hashing = {
    'SHA1': SHA1,
    'SHA-224': SHA224,
    'SHA-256': SHA256,
    'SHA-384': SHA384,
    'SHA-512': SHA512,
    'SHA3-224': SHA3_224,
    'SHA3-256': SHA3_256,
    'SHA3-384': SHA3_384,
    'SHA3-512': SHA3_512,
}


public_key_file = sys.argv[1]
signed_file = sys.argv[2]

key_file = open(public_key_file)
public_key = RSA.import_key(key_file.read())
key_file.close()

file = open(signed_file, 'r')
value = ''

dict = {}
data_key = ''
for line in file.readlines():
    if ':' in line:
        data_key = line.split(':')[0].strip()
        if data_key != 'Method':
            value = ''
        else:
            value = []

    elif line.rstrip() == '':
        dict[data_key] = value
    else:
        if data_key != 'Method':
            value += line.strip()
        else:
            value.append(line.strip())

hash_algorithm = hashing[dict['Method'][1]].new()
value = base64.b64decode(dict['Signature'])


def verify(message, signature, pub_key):
    signer = PKCS1_v1_5.new(pub_key)
    hash_algorithm.update(message)
    return signer.verify(hash_algorithm, signature)


f = open(dict['File'], 'rb')
print(verify(f.read(), value, public_key))
f.close()

