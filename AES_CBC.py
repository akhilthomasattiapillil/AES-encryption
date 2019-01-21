#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode
from base64 import b64decode
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad


def cbc_enc(sk, iv):
    with open('/AES/data/plaintxt.txt', 'rb') as read_txt:
        txt = read_txt.read()
    data = pad(txt, AES.block_size)
    _cbc = AES.new(sk, AES.MODE_CBC, iv)
    ct_bytes = _cbc.encrypt(data)
    return ct_bytes


def ecb_enc(sk):
    with open('/AES/data/plaintxt.txt', 'rb') as read_txt:
        txt = read_txt.read()
    data = pad(txt, AES.block_size)
    _ecb = AES.new(sk, AES.MODE_ECB)
    ct_bytes = _ecb.encrypt(data)
    return ct_bytes


def cbc_dec(sk, iv, ciphertxt):
    _cbc = AES.new(sk, AES.MODE_CBC, iv)
    decd = unpad(_cbc.decrypt(ciphertxt), AES.block_size)
    with open('/AES/data/result.txt', 'w') as write_decd:
        write_decd.write(decd.decode('utf8'))


if __name__ == "__main__":
    _sk = get_random_bytes(32)
    _iv = get_random_bytes(16)

    cbc = cbc_enc(_sk, _iv)
    ecb = ecb_enc(_sk)
    cbc_dec(_sk, _iv, cbc)

    cbc_hex = ''.join([str(hex(ord(i)) + " ") for i in (b64encode(cbc).decode('utf-8'))])
    with open('/AES/data/ciphertxt_cbc.txt', 'w') as write_encd:
        write_encd.write(cbc_hex)

    ecb_hex = ''.join([str(hex(ord(i)) + " ") for i in (b64encode(ecb).decode('utf-8'))])
    with open('/AES/data/ciphertxt_ecb.txt', 'w') as write_encd:
        write_encd.write(ecb_hex)

    _iv2 = get_random_bytes(16)
    cbc2 = cbc_enc(_sk, _iv2)
    ecb2 = ecb_enc(_sk)
    cbc_hex2 = ''.join([str(hex(ord(i)) + " ") for i in (b64encode(cbc2).decode('utf-8'))])
    with open('/AES/data/ciphertxt_cbc.txt', 'a') as write_encd:
        write_encd.write('\n' + cbc_hex2)

    ecb_hex2 = ''.join([str(hex(ord(i)) + " ") for i in (b64encode(ecb2).decode('utf-8'))])
    with open('/AES/data/ciphertxt_ecb.txt', 'a') as write_encd:
        write_encd.write('\n'+ ecb_hex2)

    _iv_str = b64encode(_iv).decode('utf-8')
    _sk_str = b64encode(_sk).decode('utf-8')
    _iv_hex = ''.join([str(hex(ord(i)) + " ") for i in _iv_str])
    _sk_hex = ''.join([str(hex(ord(i)) + " ") for i in _sk_str])
    print('sk: '+ _sk_hex)
    with open('/UAES/data/iv.txt', 'w') as _iv_in:
        _iv_in.write(_iv_hex)
    with open('/AES/data/key.txt', 'w') as _key_in:
        _key_in.write(_sk_hex)
    # print(" ")
