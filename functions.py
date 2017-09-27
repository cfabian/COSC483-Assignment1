import binascii
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
    return ciphertext


def decrypt(key, enc):
    if (enc is None) or (len(enc) == 0):
        raise ValueError('input text cannot be null or empty set')
    cipher = AES.new(key, AES.MODE_ECB)
    enc = cipher.decrypt(enc)
    return enc

def padding(raw):

    lraw = len(raw[-1])*8
    modraw = lraw % blocksize
    remainder = blocksize - modraw
    # print("modraw:",modraw)
    if modraw == 0:
        remainder = 128
        paddingstr = (int(remainder/8)).to_bytes(int(remainder/8),byteorder="big",signed=False)* int(remainder/8)
        # print("Padding str",paddingstr)
        # raw.append(bytes("\0", encoding='utf-8') * int(((remainder)/(len(bytes("\0", encoding='utf-8')) * 8))))
        raw.append(paddingstr)
    else:
        # paddingstr = bytes(str(remainder),encoding='utf-8') * int(((remainder)/(len(bytes(str(remainder), encoding='utf-8')) * 8)))
        paddingstr = (int(remainder / 8)).to_bytes(1, byteorder="big", signed=False) * int(remainder/8)
        # print(paddingstr)
        # print("Padding str", int(remainder / 8))
        raw[-1] = raw[-1] + paddingstr

    return raw

def remove_padding(raw):
    #needs some love
    # print("raw",raw[-1][-1:])
    i = int.from_bytes(raw[-1][-1:],byteorder="big",signed=False)
    print(i)
    raw[-1] = raw[-1][:16 - i]
    return raw

def XOR(a, b):# https://stackoverflow.com/questions/29408173/byte-operations-xor-in-python
    return bytes(map(operator.xor, a, b))

# Create a function called "chunks" with two arguments, l and n:
def chunks(l, n): # https://chrisalbon.com/python/break_list_into_chunks_of_e
    # For item i in a range that is a length of l,
    for i in range(0, len(l), n):
        # Create an index range for l of n items:
        yield l[i:i+n]

def IV_Gen():
    return os.urandom(int(blocksize/8))

def cbc_enc(key,raw):
    ct_split = []
    iv = IV_Gen()
    ct_split.append(iv)
    split_raw = list(chunks(raw,int(blocksize/8)))
    # print("split raw", split_raw)
    padded_split_raw = padding(split_raw)
    # print("padded_split_raw",padded_split_raw)
    for item in padded_split_raw:
        block = XOR(iv,item)
        iv = encrypt(key,block)
        ct_split.append(iv)

    print("Enc:", ct_split)
    ct = b''.join(ct_split)
    return ct

def cbc_dec(key,ct):
    IV = ct[:16]
    # print("IV:", IV)
    dt_split = []
    split_raw = list(chunks(ct[16:],int(blocksize/8)))
    # print("Dec:",split_raw)
    for i in range(0,len(split_raw)):
        block = decrypt(key,split_raw[i])
        if (i == 0):
            dt_split.append(XOR(block,IV))
        else:
            dt_split.append(XOR(block, split_raw[i - 1]))
    print(dt_split)
    dt_split = remove_padding(dt_split)
    return b''.join(dt_split)

if __name__ == "__main__":# Need some shit about the special way we are going to have him run our code
    key = bytes("1234567890abcdef1234567890abcdef", encoding='utf-8')
    raw = bytes("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefads", encoding='utf-8')
    print("raw: ",raw)
    # ct = encrypt(key, padding(raw))
    # dt = decrypt(key, ct)
    ct = cbc_enc(key,raw)
    dt = cbc_dec(key,ct)
    print("CipherText:",ct)
    print("PlainText: ",dt)