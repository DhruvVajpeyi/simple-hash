import math
from ctypes import *
CHUNK_SIZE = 128//8                             # 128 bit chunk = 8 bytes
IV1 = c_uint32(int('12345678', 16))             # 32 bit initialization vector
IV2 = c_uint32(int('ABCDEF12', 16))             # 32 bit initialization vector

# Pad the message by adding '1' and then '0's until message size is divisible by 64 bits
def pad(bit_msg: bytes):
    bit_msg += b'\x80'
    msg_len = len(bit_msg)
    chunk_ct = math.ceil(msg_len/CHUNK_SIZE)
    pad_len = chunk_ct * CHUNK_SIZE - msg_len
    bit_msg += b'\0' * pad_len
    return bit_msg, chunk_ct

# TEA: Tiny Encryption Algorithm: 
# https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
def block_cipher(v0: c_uint32, v1: c_uint32, key: c_uint32):
    sum = c_uint32(0)
    delta = 0x9E3779B9
    k0 = int.from_bytes(key[0:4], "big")
    k1 = int.from_bytes(key[4:8], "big")
    k2 = int.from_bytes(key[8:12], "big")
    k3 = int.from_bytes(key[12:16], "big")
    out0 = c_uint32(v0.value)
    out1 = c_uint32(v1.value)
    for i in range(0, 32):
        sum.value += delta
        out0.value += (out1.value<<4) + k0 ^ out1.value + sum.value ^ (out1.value>>5) + k1
        out1.value += (out0.value<<4) + k2 ^ out0.value + sum.value ^ (out0.value>>5) + k3
    return out0, out1

# Davies-Meyer compression function: 
# https://en.wikipedia.org/wiki/One-way_compression_function#Davies%E2%80%93Meyer
def compress(msg: bytes, state1: c_uint32, state2: c_uint32):
    cipher1, cipher2 = block_cipher(state1, state2, msg)
    state1.value ^= cipher1.value
    state2.value ^= cipher2.value
    return state1, state2

# Merkle–Damgård construction: 
# https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction
def hash(message: str):
    msg_bytes = message.encode('utf-8')
    msg_padded, chunk_ct = pad(msg_bytes)

    state1 = IV1
    state2 = IV2
    for i in range(0, chunk_ct):
        state1, state2 = compress(msg_padded[i*CHUNK_SIZE:(i+1)*CHUNK_SIZE], state1, state2)

    hex1 = hex(state1.value)[2:]
    hex2 = hex(state2.value)[2:]
    hex1 = '0'*(8-len(hex1)) + hex1
    hex2 = '0'*(8-len(hex2)) + hex2
    return hex1+hex2

if __name__ == "__main__":
    hashes = set()
    print(hash(""))
    print(hash(" "))
    print(hash("hello"))
    print(hash("hallo"))
    print(hash("hlleo"))
    print(hash("The quick brown fox jumps over the lazy dog"))
    print(hash("The quick baown fox jumps over the lazy dog"))
    print(hash("The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog"))
