import base64
import sys

from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA

private_key_file = sys.argv[1]
envelope_file = sys.argv[2]

key_file = open(private_key_file)
private_key = RSA.import_key(key_file.read())
key_file.close()

file = open(envelope_file, 'r')
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

file.close()

enc_session_key = base64.b64decode(dict['Session Key'])
tag = base64.b64decode(dict['AES Tag'])
nonce = base64.b64decode(dict['NONCE'])
content = base64.b64decode(dict['Encrypted content'])
original = base64.b64decode(dict['Original File'])

cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(content, tag)

print(data.decode("ascii"))
