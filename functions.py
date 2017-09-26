import binascii
import sys
import operator
import os
from Crypto.Cipher import AES



# Credit to Chris Coe for this code
# Requires pycrypto, which does indeed work for python3
blocksize = 128
keysize = 256


def encrypt(key, raw):
    '''
    Takes in a string of clear text and encrypts it.

    @param raw: a string of clear text
    @return: a string of encrypted ciphertext
    '''
    if (raw is None) or (len(raw) == 0):
        raise ValueError('input text cannot be null or empty set')
    cipher = AES.new(key[:32], AES.MODE_ECB)
    ciphertext = cipher.encrypt(raw)
    return binascii.hexlify(bytearray(ciphertext)).decode('utf-8')


def decrypt(key, enc):
    if (enc is None) or (len(enc) == 0):
        raise ValueError('input text cannot be null or empty set')
    enc = binascii.unhexlify(enc)
    cipher = AES.new(key[:32], AES.MODE_ECB)
    enc = cipher.decrypt(enc)
    return enc.decode('utf-8')

def padding(raw):
    lraw = len(raw[-1])*8
    modraw = lraw % 128
    remainder = blocksize - modraw
    # print("modraw:",modraw)
    if modraw == 0:
        raw.append(bytes("\0", encoding='utf-8') * int(((remainder)/(len(bytes("\0", encoding='utf-8')) * 8))))
    else:
        paddingstr = bytes(str(remainder),encoding='utf-8') * int(((remainder)/(len(bytes(str(remainder), encoding='utf-8')) * 8)))
        zerosreq = int((remainder %(len(bytes(str(remainder), encoding='utf-8')) * 8))/8)
        # print("Zeros needed:",zerosreq)
        zeros = bytes("\0", encoding='utf-8') * zerosreq
        raw[-1] = raw[-1] + zeros + paddingstr
    return raw

def remove_padding(raw):
    #needs some love
    love = 1
    return love

def XOR(a, b):# https://stackoverflow.com/questions/29408173/byte-operations-xor-in-python
    return bytes(map(operator.xor, a, b))

# Create a function called "chunks" with two arguments, l and n:
def chunks(l, n): # https://chrisalbon.com/python/break_list_into_chunks_of_e
    # For item i in a range that is a length of l,
    for i in range(0, len(l), n):
        # Create an index range for l of n items:
        yield l[i:i+n]

def IV_Gen():
    return os.urandom(int(keysize/8))

def cbc_enc(key,raw):
    ct_split = []
    iv = IV_Gen()
    ct_split.append(iv)
    split_raw = list(chunks(raw,int(blocksize/8)))
    print(split_raw)
    padded_split_raw = padding(split_raw)

    for item in padded_split_raw:

        block = XOR(iv,item)
        iv = encrypt(key,block)
        iv = bytes(iv, encoding='utf-8')
        ct_split.append(iv)
    ct = b''.join(ct_split)
    return ct

def cbc_dec(key,ct):
    IV = ct[:32]
    dt_split = []
    ct = ct[32:]
    split_raw = list(chunks(ct[32:],int(blocksize/8)))
    print(split_raw)
    for item in reversed(split_raw):
        print(len(item))
        block = decrypt(key,item)
        dt_split.append(block)

    for i in range(len(dt_split),0,-1):
        print(i)


if __name__ == "__main__":# Need some shit about the special way we are going to have him run our code
    key = bytes("1234567890abcdef1234567890abcdef", encoding='utf-8')
    raw = bytes("1234567890abcdefabcdefghijklm", encoding='utf-8')
    print("raw: ",raw)
    # ct = encrypt(key, padding(raw))
    # dt = decrypt(key, ct)
    ct = cbc_enc(key,raw)
    dt = cbc_dec(key,ct)
    print(ct)
    print(dt)