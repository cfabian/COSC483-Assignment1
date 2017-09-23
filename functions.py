import binascii
from Crypto.Cipher import AES



# Credit to Chris Coe for this code
# Requires pycrypto, which does indeed work for python3
blocksize = 128


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
    lraw = len(raw)*8
    modraw = lraw % 128
    remainder = blocksize - modraw
    print("modraw:",modraw)
    if modraw == 0:
        raw += bytes("\0", encoding='utf-8') * int(((remainder)/(len(bytes("\0", encoding='utf-8')) * 8)))
    else:
        paddingstr = bytes(str(remainder),encoding='utf-8') * int(((remainder)/(len(bytes(str(remainder), encoding='utf-8')) * 8)))
        zerosreq = int((remainder %(len(bytes(str(remainder), encoding='utf-8')) * 8))/8)
        print("Zeros needed:",zerosreq)
        zeros = bytes("\0", encoding='utf-8') * zerosreq
        raw = raw + zeros + paddingstr
    return raw


if __name__ == "__main__":
    key = bytes("1234567890abcdef1234567890abcdef", encoding='utf-8')
    raw = bytes("1234567890abcdefabcdefghijklm", encoding='utf-8')
    ct = encrypt(key, padding(raw))
    dt = decrypt(key, ct)
    print(ct)
    print(dt)