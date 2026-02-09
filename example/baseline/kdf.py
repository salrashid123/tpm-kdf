from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import SP800_108_Counter

# pip3 install pycryptodome

secret = b'my_api_key'
label = b'foo'
context = b'context'
key_len = 32 # 256 bits


def prf(s, x):
    return HMAC.new(s, x, SHA256).digest()

derived_key = SP800_108_Counter(secret, key_len, prf, label=label, context=context)

print(derived_key.hex())

