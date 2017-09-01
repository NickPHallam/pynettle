from os import urandom
from ctypes import *

try:
    nettle = CDLL('libnettle.so')
except Exception as e:
    print('[-] Error: Cannot open libnettle - {}'.format(e))
    raise


_CHACHA_STATE_LENGTH=16*8
class chacha_ctx(Structure):
    _fields_ = [("state", c_uint32 * _CHACHA_STATE_LENGTH)]


# Hooks to nettle library
def chacha_set_key(ctx, key):
    assert isinstance(ctx, chacha_ctx)
    assert len(key.raw) in (32,)  # 256 bits
    assert isinstance(key.raw, bytes)
    nettle.nettle_chacha_set_key(
        byref(ctx),
        byref(key))


def chacha_set_nonce(ctx, nonce):
    assert isinstance(ctx, chacha_ctx)
    assert len(nonce.raw) in (8,)  # 64 bits
    assert isinstance(nonce.raw, bytes)
    nettle.nettle_chacha_set_nonce(
        byref(ctx),
        byref(nonce))


def chacha_crypt(ctx, length, dst, src):
    assert isinstance(ctx, chacha_ctx)
    assert isinstance(length, c_size_t)
    assert isinstance(dst.raw, bytes)
    assert isinstance(src.raw, bytes)
    nettle.nettle_chacha_crypt(
        byref(ctx),
        length,
        byref(dst),
        byref(src))


# Python api for buffer handling
def chacha20_encrypt(ctx, buff_i):
    """
    encrypt a bytestream using chacha20 stream cipher
    :param ctx: a chacha20_ctx instance
    :param buff_i: plaintext buffer
    :return: cyphertext buffer
    """
    buff_o = create_string_buffer(len(buff_i))
    chacha_crypt(
        ctx,
        c_size_t(
            len(buff_i)),
        buff_o,
        buff_i)
    return buff_o

# Python api for buffer handling
def chacha20_decrypt(ctx, buff_i):
    """
    decrypt a bytestream using chacha20 stream cipher
    :param ctx: a chacha20_ctx instance
    :param buff_i: cyphertext buffer
    :return: plaintext buffer
    """
    buff_o = create_string_buffer(len(buff_i))
    chacha_crypt(
        ctx,
        c_size_t(
            len(buff_i)),
        buff_o,
        buff_i)
    return buff_o
