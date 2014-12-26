# Implement the cipher_block_chaining method below
#
DEBUG = 1

from Crypto.Cipher import AES

# Remember, this is NOT secure cryptology code
# This is for fun and education.  Unless you're planning
# on taking over the GoldenEye satellites, then we recommend
# using this code to protect your plans
############
# CBC uses a 'black box encoder' as discussed in the lecture
#
# AES is a very common example of this, which is available
# in the Crypto library
#
# For testing purposes, here is AES and some other, silly, encoders
# 
# These, or others might be used to grade your code
# so your implementation should be independent of the encoder used
def non_encoder(block, key):
    """A basic encoder that doesn't actually do anything"""
    # if DEBUG: print "non_encoder:", len(key), "key:", key, "len(bk):", len(block), "**:", block
    return pad_bits_append(block, len(key))

def xor_encoder(block, key):
    # if DEBUG: print "xor_encoder:", len(key), "key:", display_bits(key), "len(bk):", len(block)
    block = pad_bits_append(block, len(key))
    # if DEBUG: print "      padded block = ", display_bits(block)
    cipher = [b ^ k for b, k in zip(block, key)]
    # if DEBUG: print "      cipher       = ", display_bits(cipher)
    return cipher

def aes_encoder(block, key):
    block = pad_bits_append(block, len(key))
    # the pycrypto library expects the key and block in 8 bit ascii 
    # encoded strings so we have to convert from the bit string
    block = bits_to_string(block)
    key = bits_to_string(key)
    ecb = AES.new(key, AES.MODE_ECB)
    return string_to_bits(ecb.encrypt(block))
###### END of example encoders ########

# this is an example implementation of 
# the electronic cookbook cipher
# illustrating manipulating the plaintext,
# key, and init_vec 
def electronic_cookbook(plaintext, key, block_size, block_enc):
    """Return the ecb encoding of `plaintext"""
    cipher = []
    # break the plaintext into blocks
    # and encode each one
    for i in range(len(plaintext) / block_size + 1):
        start = i * block_size
        if start >= len(plaintext):
            break
        end = min(len(plaintext), (i+1) * block_size)
        block = plaintext[start:end]
        if DEBUG: print "block loop: ", "i:", i, "start:",start, "end:", end, "block_size:", block_size
        if DEBUG: print "  block to encode: ", display_bits(block)
        cipher.extend(block_enc(block, key))
    return cipher


def cipher_block_chaining(plaintext, key, init_vec, block_size, block_enc):
    """Return the cbc encoding of `plaintext`
    
    Args:
        plaintext: bits to be encoded
        key: bits used as key for the block encoder
        init_vec: bits used as the initalization vector for 
                  the block encoder
        block_size: size of the block used by `block_enc`
        block_enc: function that encodes a block using `key`
    """
    # Assume `block_enc` takes care of the necessary padding
    # if `plaintext` is not a full block
    # break the plaintext into blocks
    # and encode each one
    
    cipher = []
    cipher_block = []

    # break text into block_size blocks
    for i in range(len(plaintext) / block_size + 1):
        start = i * block_size
        if start >= len(plaintext):
            break
        end = min(len(plaintext), (i+1) * block_size)
        block = plaintext[start:end]
        if DEBUG: print "block loop: ", "i:", i, "start:",start, "end:", end, "block_size:", block_size
        if DEBUG: print "  block to encode: ", display_bits(block)
        
        # if i = 0, then first block - use IV - else use last cipher block
        if not i:
            cipher_block = block_enc(block, init_vec)
        else:
            cipher_block = block_enc(block, cipher_block)
        if DEBUG: print "    encoded block: ", display_bits(cipher_block)
        
        # next encode w/ key
        cipher_block = block_enc(cipher_block, key)
        if DEBUG: print "    *encode block: ", display_bits(cipher_block)
        
        cipher.extend(cipher_block)
    print "CBC:", bits_to_string(cipher)
    return cipher

    
    # return a bit array, something of the form: [0, 1, 1, 1, 0]

    ###############
    # START YOUR CODE HERE

    # END OF YOUR CODE
    ####################
    
def test():
    key = string_to_bits('4h8f.093mJo:*9#$')
    iv = string_to_bits('89JIlkj3$%0lkjdg')
    plaintext = string_to_bits("One if by land; two if by sea")

    cipher = cipher_block_chaining(plaintext, key, iv, 128, non_encoder)
    # assert bits_to_string(cipher) == 'wW/i\x05\rJQ]\x05\\\r\x05\x0e_G\x03 @Ilkj3$%/hd\x00\x00\x00'
    print "       assert bits:", display_bits(string_to_bits('wW/i\x05\rJQ]\x05\\\r\x05\x0e_G\x03 @Ilkj3$%/hd\x00\x00\x00'))
    print "=================================================="
    
    cipher = cipher_block_chaining(plaintext, key, iv, 128, xor_encoder)
    # assert bits_to_string(cipher) == 'C?\x17\x0f+=sb0O37/7|c\x03 @Ilkj3$%/hd9#$'
    cipher = cipher_block_chaining(cipher, key, iv, 128, xor_encoder)
    
    cipher = cipher_block_chaining(plaintext, key, iv, 128, aes_encoder)
    assert bits_to_string(cipher) == '\xeaJ\x13t\x00\x1f\xcb\xf8\xd2\x032b\xd0\xb6T\xb2\xb1\x81\xd5h\x97\xa0\xaeogtNi\xfa\x08\xca\x1e'

###################
# Here are some utility functions
# that you might find useful

BITS = ('0', '1')
ASCII_BITS = 8

def display_bits(b):
    """converts list of {0, 1}* to string"""
    return ''.join([BITS[e] for e in b])

def seq_to_bits(seq):
    return [0 if b == '0' else 1 for b in seq]

def pad_bits(bits, pad):
    """pads seq with leading 0s up to length pad"""
    assert len(bits) <= pad
    return [0] * (pad - len(bits)) + bits
        
def convert_to_bits(n):
    """converts an integer `n` to bit array"""
    result = []
    if n == 0:
        return [0]
    while n > 0:
        result = [(n % 2)] + result
        n = n / 2
    return result

def string_to_bits(s):
    def chr_to_bit(c):
        return pad_bits(convert_to_bits(ord(c)), ASCII_BITS)
    return [b for group in 
            map(chr_to_bit, s)
            for b in group]

def bits_to_char(b):
    assert len(b) == ASCII_BITS
    value = 0
    for e in b:
        value = (value * 2) + e
    return chr(value)

def list_to_string(p):
    return ''.join(p)

def bits_to_string(b):
    return ''.join([bits_to_char(b[i:i + ASCII_BITS]) 
                    for i in range(0, len(b), ASCII_BITS)])

def pad_bits_append(small, size):
    # as mentioned in lecture, simply padding with
    # zeros is not a robust way way of padding
    # as there is no way of knowing the actual length
    # of the file, but this is good enough
    # for the purpose of this exercise
    diff = max(0, size - len(small))
    return small + [0] * diff


if __name__ == '__main__':
    print "hello crypto"
    
    test()
    
    key = string_to_bits('4h8f.093mJo:*9#$')
    iv = string_to_bits('89JIlkj3$%0lkjdg')
    plaintext = string_to_bits("One if by land; two if by sea")
    
    block_size = len(key)
    cipher = electronic_cookbook(plaintext, key, block_size, xor_encoder)
    print "cipher = ", display_bits(cipher)
    print "  ", bits_to_string(cipher)
    decrypt = electronic_cookbook(cipher, key, block_size, xor_encoder)
    print "decrypt = ", display_bits(decrypt)
    print "  ", bits_to_string(decrypt)