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


if __name__ == "__main__":
    print bin2hex(genbignum(16))
