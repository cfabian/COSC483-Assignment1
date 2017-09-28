import binascii
import operator
import os
from Crypto.Cipher import AES
import sys


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
    i = int.from_bytes(raw[-1][-1:],byteorder="big",signed=False)
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

    # print("Enc:", ct_split)
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
    dt_split = remove_padding(dt_split)
    return b''.join(dt_split)

def ctr_enc(key,raw):
    ct_split = []
    iv = IV_Gen()
    ct_split.append(iv)
    temp = int.from_bytes(iv,byteorder="big",signed=False) + 1
    iv = (temp).to_bytes(16, byteorder="big", signed=False)


    split_raw = list(chunks(raw,int(blocksize/8)))
    for item in split_raw:
        block = encrypt(key, iv)
        temp = int.from_bytes(iv, byteorder="big", signed=False) + 1
        iv = (temp).to_bytes(16, byteorder="big", signed=False)
        ct_split.append(XOR(block, item))
    return b''.join(ct_split)

def ctr_dec(key, ct):
    IV = ct[:16]
    dt_split = []
    split_raw = list(chunks(ct[16:], int(blocksize/8)))

    temp = int.from_bytes(IV,byteorder="big",signed=False) + 1
    IV = (temp).to_bytes(16, byteorder="big", signed=False)
    print(len(IV))
    print(type(IV))
    print(type(ct))
    for i in range(0, len(split_raw)):
        block = XOR(split_raw[i], encrypt(key, IV))
        temp = int.from_bytes(IV, byteorder="big", signed=False) + 1
        IV = (temp).to_bytes(16, byteorder="big", signed=False)
        dt_split.append(block)
    return b''.join(dt_split)

if __name__ == "__main__":# Need some shit about the special way we are going to have him run our code
    mode = ''
    keyFile = None
    inputFile = None
    outputFile = None
    ivFile = None
    if len(sys.argv) == 2:
        print(sys.argv)
        print("Usage: ./[cbc-enc/cbc-dec/ctr-enc/ctr-dec] -k keyFile -i inputFile -o outputFile (-v ivFile)")
        exit()
    else:
        mode = sys.argv[1]
        for i in range(2, len(sys.argv)):
            if sys.argv[i] == '-k':
                keyFile = sys.argv[i+1]
            elif sys.argv[i] == '-i':
                inputFile = sys.argv[i+1]
            elif sys.argv[i] == '-o':
                outputFile = sys.argv[i+1]
            elif sys.argv[i] == '-v':
                ivFile = sys.argv[i+1]
    if keyFile == None or inputFile == None or outputFile == None:
        print(sys.argv)
        print("Usage: ./[cbc-enc/cbc-dec/ctr-enc/ctr-dec] -k keyFile -i inputFile -o outputFile (-v ivFile)")
        exit()
    #TODO: get key and raw from files, the files are hex encoded
    key = ''
    raw = ''
#    key = bytes("1234567890abcdef1234567890abcdef", encoding='utf-8')
#    raw = bytes("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefads", encoding='utf-8')
#    print("raw: ",raw)
    # ct = encrypt(key, padding(raw))
    # dt = decrypt(key, ct)
    ct = cbc_enc(key,raw)
    dt = cbc_dec(key,ct)
    ct2 = ctr_enc(key,raw)
    dt2 = ctr_dec(key,ct2)
    print("CipherText(CBC): ",ct)
    print("PlainText(CBC): ",dt)
    print("CipherText(CTR): ",ct2)
    print("PlainText(CTR): ", dt2)