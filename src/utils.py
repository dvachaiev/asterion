#!/usr/bin/python
# -*- coding: utf-8 -*-

try:
    from hashlib import sha1 as sha
except ImportError:
    from sha import new as sha
import random


def genbignum(length):
    res = ''
    for i in xrange(length):
        res += chr(random.randint(0, 255))
    return res  # or return "".join([chr(i) for i in random.sample(range(0,0xff), length)])


def bin2hex(seq):
    return ' '.join([hex(ord(i))[2:].zfill(2).upper() for i in seq])
b2hex = b2h = bin2hex


def bin2int(seq, bigendian=True):
    res = 0L
    if not bigendian:
        seq = seq[::-1]
    for i in seq:
        res = (res << 8) + ord(i)
    return res
b2i = bin2int


def int2bin(num, bigendian=True):
    res = ''
    while num:
        res += chr(num & 0xff)
        num >>= 8
    if bigendian:
        res = res[::-1]
    return res
i2b = int2bin


if __name__ == "__main__":
    print bin2hex(genbignum(16))
