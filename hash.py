import math
from ctypes import *
CHUNK_SIZE = 128//8                   # 128 bit chunk = 8 bytes
IV1 = int('12345678', 16)             # 32 bit initialization vector
IV2 = int('ABCDEF12', 16)             # 32 bit initialization vector

# Pad the message by adding '1' and then '0's until message size is divisible by 128 bits
def pad(bit_msg: bytes):
    # Add 1 to prevent collision through adding 0 to message
    bit_msg += b'\x80'

    # Append '0's such that the length is divisible by the CHUNK_SIZE
    msg_len = len(bit_msg)
    chunk_ct = math.ceil(msg_len/CHUNK_SIZE)
    pad_len = chunk_ct * CHUNK_SIZE - msg_len
    bit_msg += b'\0' * pad_len
    return bit_msg, chunk_ct

# TEA: Tiny Encryption Algorithm: 
# https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
# Using the previous hash/state as the message to be encrypted and the current chunk as the key
# All the operations being used (+, <<, ^) are deterministic, so the hash output for a fixed input is always the same.
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
def simple_hash(message: str):
    # Encode the string into bytes
    msg_bytes = message.encode('utf-8')
    msg_padded, chunk_ct = pad(msg_bytes)

    # Make copies of the initialization vectors
    state1 = c_uint32(IV1)
    state2 = c_uint32(IV2)

    # Use a compression function for each chunk dependant on the previous hash
    # Using the previous hash value in the compression will ensure an avalanche effect when any chunk is changed.
    for i in range(0, chunk_ct):
        state1, state2 = compress(msg_padded[i*CHUNK_SIZE:(i+1)*CHUNK_SIZE], state1, state2)

    # Convert final state values from uint32 to hex strings
    hex1 = hex(state1.value)[2:]
    hex2 = hex(state2.value)[2:]

    # Append 0 at start of hexstring if they are smaller than 32 bits
    hex1 = '0'*(8-len(hex1)) + hex1
    hex2 = '0'*(8-len(hex2)) + hex2

    # Append state vectors to get 64-bit hash value
    return hex1+hex2