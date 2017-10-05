from multiprocessing import Process
import operator
import os
from Crypto.Cipher import AES
import sys
from multiprocessing import Process,Manager
import binascii

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


def cbc_enc(key,raw,iv):
    ct_split = []
    ct_split.append(iv)
    split_raw = list(chunks(raw,int(blocksize/8)))
    # print("split raw", split_raw)
    padded_split_raw = padding(split_raw)
    print(padded_split_raw)
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


# parallel_encrypt: This function does the encryption for a block at index (iv-starting_point) in parallel_list.
def parallel_encrypt(key, raw, iv, starting_point, parallel_list):
    block = encrypt(key, iv)
    iv_int = int.from_bytes(iv,byteorder="big",signed=False)
    starting_int = int.from_bytes(starting_point, byteorder="big", signed=False)
    parallel_list[iv_int-starting_int] = XOR(block, raw)


def ctr_enc(key,raw,iv):
    # Initialize IV and split raw into blocks.
    #iv = IV_Gen()
    starting_point = iv
    split_raw = list(chunks(raw,int(blocksize/8)))

    # Create a synchronized list using a Manager
    manager = Manager()
    ct_split = manager.list([0] * (len(split_raw)+1))
    ct_split[0] = iv

    # Increment IV by 1 for first encryption
    temp = int.from_bytes(iv,byteorder="big",signed=False) + 1
    iv = (temp).to_bytes(16, byteorder="big", signed=False)

    # Start a process for each block
    process_list = []
    for item in split_raw:
        p = Process(target=parallel_encrypt, args=(key,item,iv,starting_point,ct_split,))
        p.start()
        process_list.append(p)
        temp = int.from_bytes(iv,byteorder="big",signed=False) + 1
        iv = (temp).to_bytes(16, byteorder="big", signed=False)

    # Block until all processes are complete
    while True:
        done = True
        for process in process_list:
            if process.is_alive():
                done = False
        if done == True:
            break
    return b''.join(ct_split)


def parallel_decrypt(key, ct, iv, index, parallel_list):
    block = XOR(ct, encrypt(key, iv))
    parallel_list[index] = block


def ctr_dec(key, ct):
    # Initialize IV and split ciphertext into blocks, create synced list
    IV = ct[:16]
    manager = Manager()
    split_raw = list(chunks(ct[16:], int(blocksize/8)))
    dt_split = manager.list([0] * len(split_raw))
    temp = int.from_bytes(IV,byteorder="big",signed=False) + 1
    IV = (temp).to_bytes(16, byteorder="big", signed=False)

    # Start up a new process for each IV+1
    process_list = []
    for i in range(0, len(split_raw)):
        p = Process(target=parallel_decrypt, args=(key,split_raw[i],IV,i,dt_split,))
        p.start()
        process_list.append(p)
        temp = int.from_bytes(IV, byteorder="big", signed=False) + 1 # Increment IV for next block
        IV = (temp).to_bytes(16, byteorder="big", signed=False)
    # Block until all processes are complete
    while True:
        done = True
        for process in process_list:
            if process.is_alive():
                done = False
        if done == True:
            break
    return b''.join(dt_split)


if __name__ == "__main__":# Need some shit about the special way we are going to have him run our code
    mode = ''
    raw = bytes('', encoding='utf-8')
    key = bytes('', encoding='utf-8')
    iv = None
    keyFile = None
    inputFile = None
    outputFile = None
    ivFile = None
    if len(sys.argv) <= 6:
        print("Usage: ./[cbc-enc/cbc-dec/ctr-enc/ctr-dec] -k keyFile -i inputFile -o outputFile (-v ivFile)")
        exit()
    else:
        mode = sys.argv[1]
        print(mode)
        for i in range(2, len(sys.argv)):
            if sys.argv[i] == '-k':
                keyFile = sys.argv[i+1]
                file = open(keyFile, 'rb')
                for line in file:
                    key += line
                key = binascii.unhexlify(key)
            elif sys.argv[i] == '-i':
                inputFile = sys.argv[i+1]
            elif sys.argv[i] == '-o':
                outputFile = sys.argv[i+1]
            elif sys.argv[i] == '-v':
                ivFile = sys.argv[i+1]
                file = open(ivFile, 'rb')
                iv = bytes('', encoding='utf-8')
                for line in file:
                    iv += line
                print(len(iv))
    if keyFile == None or inputFile == None or outputFile == None:
        print(sys.argv)
        print("Usage: ./[cbc-enc/cbc-dec/ctr-enc/ctr-dec] -k keyFile -i inputFile -o outputFile (-v ivFile)")
        exit()
    if iv == None:
        iv = IV_Gen()
    #TODO: get key and raw from files, the files are hex encoded
    #key = bytes("1234567890abcdef1234567890abcdef", encoding='utf-8')
    #raw = bytes("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefads", encoding='utf-8')
    output = open(outputFile, 'wb')
    input = open(inputFile, 'rb')

    for line in input:
        raw += line
    if mode == 'cbc-enc':
        print(iv,key)
        ct = cbc_enc(key,raw,iv)
        print('CipherText (CBC): ', ct)
        output.write(ct)
    elif mode == 'cbc-dec':
        dt = cbc_dec(key, raw)
        print('PlainText (CBC): ', dt)
        output.write(dt)
    elif mode == 'ctr-enc':
        ct = ctr_enc(key, raw, iv)
        print('CipherText (CTR): ', ct)
        output.write(ct)
    elif mode == 'ctr-dec':
        dt = ctr_dec(key, raw)
        print('PlainText (CTR): ', dt)
        output.write(dt)
    else:
        print("Invalid Mode")
        exit()

    output.close()
    input.close()