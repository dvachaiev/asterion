#!/usr/bin/python
#-*- coding: utf-8 -*-

import sys
import md5
import hmac
import socket

from twisted.internet import reactor
from twisted.internet import protocol
from twisted.python import log

import rc4
import mppc
import utils


server = '195.211.129.79'
port = 29000


class ProxyProtocol(protocol.Protocol):

    def __init__(self, out=None):
        self._out = out
        self.is_in = False
        if out:
            out._out = self
            self.is_in = True

    def connectionMade(self):
        if not self._out:   #we are just listen, so we should create another protocol
            self.factory.connectToServer()

    def dataReceived(self, data):
        log.msg("Received data: %s" % utils.b2h(data))
        try:
            self.factory.handler.handle(data, self.is_in)
        except:
            log.err()
        self._out.transport.write(data)

    def connectionLost(self, why):
        log.msg("Connection closed: %s" % why)
        if self._out:
            self._out.closeConnection()
            self._out = None

    def closeConnection(self):
        self._out = None
        self.transport.loseConnection()


class ProxyFactory(protocol.ClientFactory):

    protocol = ProxyProtocol

    def __init__(self, remote_addr, handler):
        self._in = None
        self.remote_addr = remote_addr
        self.handler = handler

    def connectToServer(self):
        reactor.connectTCP(*self.remote_addr, factory=self)

    def buildProtocol(self, addr):
        p = self.protocol(self._in)
        p.factory = self
        self._in = self._in or p
        return p


class Handler(object):

    def __init__(self):
        self._in_cipher = None
        self._in_decomp = None
        self._out_cipher = None
        self.out_stream = sys.stdout

    def handle(self, data, is_in):
        if is_in:
            args = ('in ', self._in_cipher, self._in_decomp)
            handler = self._handle_in
        else:
            args = ('out', self._out_cipher, None)
            handler = self._handle_out
        packet = self._parse(data, *args)
        handler(packet)

    def _handle_in(self, packet):
        if packet['opcode'] == 2:
            self._out_key = packet['key']
            self._out_cipher = rc4.rc4(hmac.new(self._login, self._hash + self._out_key).digest())

    def _handle_out(self, packet):
        if packet['opcode'] == 2:
            self._in_key = packet['key']
            self._in_cipher = rc4.rc4(hmac.new(self._login, self._hash + self._in_key).digest())
            self._in_decomp = mppc.MPPCDecoder()
        elif packet['opcode'] == 3:
            self._login = packet['login']
            self._hash = packet['hash']

    def _parse(self, data, direction, cipher, decomp):
        self.log_packet(direction, 'raw   ', data)
        if cipher:
            data = rc4.crypt(data, cipher)
            self.log_packet(direction, 'decr  ', data)
        if decomp:
            data = decomp.decompress(data)
            self.log_packet(direction, 'decomp', data)
        # Parse packet
        opcode, data = parse_cui(data)
        length, data = parse_cui(data)
        assert len(data) == length, "Real length - %s, expected - %s" % (len(data), length)
        if opcode in PARSE_TABLE:
            packet = PARSE_TABLE[opcode](data)
        else:
            packet = dict(opcode=opcode, unknown=data)
        return packet

    def log_packet(self, direction, state, data):
        print >> self.out_stream, ' | '.join((direction, state, utils.b2h(data)))


def parse_cui(data):
    """
    assert parse_cui('\x00zcbag')[0] == 0
    assert parse_cui('\x7fzcbag')[0] == 0x7f
    assert parse_cui('\x80\x80zcbag')[0] == 0x80
    assert parse_cui('\xbf\xffzcbag')[0] == 0x3fff
    assert parse_cui('\xc0\x00\x40\x00zcbag')[0] == 0x4000
    assert parse_cui('\xdf\xff\xff\xffzcbag')[0] == 0x1fffffff
    assert parse_cui('\xe0\x20\x00\x00\x00zcbag')[0] == 0x20000000
    assert parse_cui('\xe0\xff\xff\xff\xffzcbag')[0] == 0xffffffff
    assert parse_cui('\xe0\xff\xff\xff\xffzcbag')[1] == 'zcbag'
    """
    _id = ord(data[0]) & 0xf0
    if _id < 0x80:
        length = 1
        diff = 0
    elif _id < 0xc0: #0x80 <= _id < 0xc0:
        length = 2
        diff = 0x8000
    elif _id < 0xe0: #0xc0 <= _id < 0xe0:
        length = 4
        diff = 0xc0000000
    elif _id == 0xe0:
        length = 5
        diff = 0xe000000000
    else:
        raise RuntimeError("Could parse cui: 0x%X" % data[0])
    res = utils.bin2int(data[:length]) - diff
    return res, data[length:]


def parse_01(data):
    names = ('opcode', 'key', 'version', 'auth_type', 'crc', 'msg_code')
    opcode = 1
    key_len, data = parse_cui(data)
    key, data = data[:key_len], data[key_len:]
    version, data = tuple(ord(i) for i in data[:4]), data[4:]
    auth_type, data = parse_cui(data)
    crc_len, data = parse_cui(data)
    crc, data = data[:crc_len], data[crc_len:]
    msg_code, data = parse_cui(data)
    assert not data, utils.bin2hex(data)
    loc = locals()
    return dict((name, loc[name]) for name in names)

def parse_02(data):
    names = ('opcode', 'key')
    opcode = 2
    key_len, data = parse_cui(data)
    key, data = data[:key_len], data[key_len:]
    unk, data = ord(data[0]), data[1:]
    assert not data
    assert not unk
    loc = locals()
    return dict((name, loc[name]) for name in names)

def parse_03(data):
    names = ('opcode', 'login', 'hash')
    opcode = 3
    login_len, data = parse_cui(data)
    login, data = data[:login_len], data[login_len:]
    hash_len, data = parse_cui(data)
    hash, data = data[:hash_len], data[hash_len:]
    unk, data = ord(data[0]), data[1:]
    assert not data
    assert not unk
    loc = locals()
    return dict((name, loc[name]) for name in names)


PARSE_TABLE = {
        0x01: parse_01,
        0x02: parse_02,
        0x03: parse_03,
}

if __name__ == "__main__":
    log.startLogging(sys.stdout)
    reactor.listenTCP(port, ProxyFactory((server, port), Handler()), interface="0.0.0.0")
    reactor.run()
