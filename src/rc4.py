#!/usr/bin/python
# -*- coding: utf-8 -*-


def rc4(key):
    numofel = 2 ** 8
    # init cipher
    s = [i for i in xrange(numofel)]
    j = 0
    keylen = len(key)
    for i, val in enumerate(s):
        j = (j + val + ord(key[i % keylen])) & 0xff
        s[i], s[j] = s[j], s[i]

    # generator
    i = j = 0
    while 1:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        yield s[(s[i] + s[j]) & 0xff]


def crypt(msg, key):
    gen = key
    if type(key) is str:
        gen = rc4(key)
    res = ''
    for m, c in zip(msg, gen):
        res += chr(ord(m) ^ c)
    return res


def check():
    import binascii
    assert binascii.b2a_hex(crypt("Plaintext", "Key")).upper() == "BBF316E8D940AF0AD3"
    assert binascii.b2a_hex(crypt("pedia", "Wiki")).upper() == "1021BF0420"
    assert binascii.b2a_hex(crypt("Attack at dawn", "Secret")).upper() == "45A01F645FC35B383552544B9BF5"

    assert crypt(binascii.a2b_hex("BBF316E8D940AF0AD3"), "Key") == "Plaintext"
    assert crypt(binascii.a2b_hex("1021BF0420"), "Wiki") == "pedia"
    assert crypt(binascii.a2b_hex("45A01F645FC35B383552544B9BF5"), "Secret") == "Attack at dawn"

    assert crypt(binascii.a2b_hex("BBF316E8D940AF0AD3"), rc4("Key")) == "Plaintext"

    print "Looks cipher works fine :)"


if __name__ == "__main__":
    check()
