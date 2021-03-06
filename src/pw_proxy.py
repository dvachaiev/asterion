#!/usr/bin/python
#-*- coding: utf-8 -*-

import os
import sys
import md5
import hmac
import time
import shutil
import socket

from twisted.internet import reactor
from twisted.internet import protocol
from twisted.python import log
from twisted.python import usage

import rc4
import mppc
import utils


server = '195.211.129.81'
port = 29000
logs_dir = '.'


class ProxyProtocol(protocol.Protocol):

    def connectionMade(self):
        self._out = getattr(self.factory, 'l_prot', None)
        if self._out: # if this connection from proxy to server
            del self.factory.l_prot # we don't need it anymore
            self.is_in = True
            self.handler = self._out.handler
            self._out._out = self
        else: #connection from client to proxy
            self.is_in = False
            self.handler = self.factory.handler()
            # Create connection from proxy to server
            factory = protocol.ClientFactory()
            factory.protocol = ProxyProtocol
            factory.l_prot = self
            reactor.connectTCP(*self.factory.remote_addr, factory=factory)

    def dataReceived(self, data):
        log.msg("Received data: %s" % utils.b2h(data))
        try:
            self.handler.handle(data, self.is_in)
        except:
            log.err()
            self.closeConnection()
            return
        self._out.transport.write(data)

    def connectionLost(self, why):
        log.msg("Connection closed: %s" % why)
        if self._out:
            self._out.closeConnection()
            self._out = None
        del self.handler

    def closeConnection(self):
        self._out = None
        self.transport.loseConnection()


class Handler(object):

    def __init__(self, output=None, log_opcodes=None, skip_opcodes=None):
        self._in_buf = ''
        self._in_cipher = None
        self._in_decomp = None
        self._out_buf = ''
        self._out_cipher = None
        self._do_close = False
        if output is None:
            self.out_stream = sys.stdout
        elif isinstance(output, str):
            self.out_stream = open(output, 'w')
            self._do_close = True
        else:
            self.out_stream = output
        self.log_opcodes = log_opcodes
        self.skip_opcodes = skip_opcodes

    def __del__(self):
        if self._do_close:
            self.out_stream.close()
            if hasattr(self, '_login'):
                path, fname = os.path.split(self.out_stream.name)
                fname = fname.replace('packets', self._login, 1)
                shutil.move(self.out_stream.name, os.path.join(path, fname))

    def handle(self, data, is_in):
        if is_in:
            args = ('s', self._in_cipher, self._in_decomp, self._in_buf)
            handler = self._handle_in
        else:
            args = ('c', self._out_cipher, None, self._out_buf)
            handler = self._handle_out
        packets, buf = self._parse(data, *args)
        if is_in:
            self._in_buf = buf
        else:
            self._out_buf = buf
        for packet in packets:
            handler(packet)

    def _handle_in(self, packet):
        if packet['opcode'] == 2:
            self._out_key = packet['key']
            self._out_cipher = rc4.rc4(hmac.new(self._login, self._hash + self._out_key).digest())
        elif packet['opcode'] == 0:
            for opcode, data in packet['packets']:
                self.log_packet('s', opcode, data)

    def _handle_out(self, packet):
        if packet['opcode'] == 2:
            self._in_key = packet['key']
            self._in_cipher = rc4.rc4(hmac.new(self._login, self._hash + self._in_key).digest())
            self._in_decomp = mppc.MPPCDecoder()
        elif packet['opcode'] == 3:
            self._login = packet['login']
            self._hash = packet['hash']

    def _parse(self, data, direction, cipher, decomp, buf):
        if cipher:
            data = rc4.crypt(data, cipher)
        if decomp:
            data = decomp.decompress(data)
        # Parse packet
        buf += data
        packets = []
        while buf:
            data = buf
            opcode, data = parse_cui(data)
            length, data = parse_cui(data)
            if len(data) < length and decomp:
                log.msg("Not enough data...")
                break
            else:
                data, buf = data[:length], data[length:]
                assert len(data) == length, "Real length - %s, expected - %s, data - %s" % (len(data), length, utils.b2h(data))
                self.log_packet(direction, opcode, data)
                if opcode in PARSE_TABLE:
                    packet = PARSE_TABLE[opcode](data)
                else:
                    packet = dict(unknown=data)
                packet['opcode'] = opcode
                packets.append(packet)
        return packets, buf

    def log_packet(self, direction, opcode, data):
        if not ((self.log_opcodes and opcode not in self.log_opcodes) or (self.skip_opcodes and opcode in self.skip_opcodes)):
            # Packet will be logged:
            # if log_opcodes is not set
            # if log_opcodes is set and opcode present in log_opcodes
            # if skip_opcodes is not set
            # if skip_opcodes is set and opcode is not present into skip_opcodes
            l_time = time.ctime().split()[3]
            print >> self.out_stream, ' | '.join((l_time, 'h', direction, '0x%X' % opcode, str(len(data)), utils.b2h(data)))
            print >> self.out_stream, ' | '.join((l_time, 'a', direction, '0x%X' % opcode, str(len(data)), data))


def get_filename(directory):
    pattern = 'packets_%s%%s.log' % ("_".join(str(i) for i in time.localtime()[:6]))
    pattern = os.path.join(directory, pattern)
    suffix = ''
    i = 0
    while os.path.exists(pattern % suffix):
        suffix = '_%s' % i
        i += 1
    return pattern % suffix


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
        raise RuntimeError("Could parse cui: 0x%X" % ord(data[0]))
    res = utils.bin2int(data[:length]) - diff
    return res, data[length:]


def parse_00(data):
    names = ('packets', )
    packets = []
    while data:
        opcode, data = parse_cui(data)
        length, data = parse_cui(data)
        assert len(data) >= length, 'Error while parsing subpackets from packet 0x00'
        packets.append((opcode, data[:length]))
        data = data[length:]
    loc = locals()
    return dict((name, loc[name]) for name in names)

def parse_01(data):
    names = ('key', 'version', 'auth_type', 'crc', 'msg_code')
    key_len, data = parse_cui(data)
    key, data = data[:key_len], data[key_len:]
    version, data = tuple(ord(i) for i in data[:4]), data[4:]
    auth_type, data = parse_cui(data)
    assert auth_type is 0, "Unsupported auth_type %s" % auth_type
    crc_len, data = parse_cui(data)
    crc, data = data[:crc_len], data[crc_len:]
    msg_code, data = parse_cui(data)
    assert not data, utils.bin2hex(data)
    loc = locals()
    return dict((name, loc[name]) for name in names)

def parse_02(data):
    names = ('key', )
    key_len, data = parse_cui(data)
    key, data = data[:key_len], data[key_len:]
    unk, data = ord(data[0]), data[1:]
    assert not unk
    assert not data, utils.bin2hex(data)
    loc = locals()
    return dict((name, loc[name]) for name in names)

def parse_03(data):
    names = ('login', 'hash')
    login_len, data = parse_cui(data)
    login, data = data[:login_len], data[login_len:]
    hash_len, data = parse_cui(data)
    hash, data = data[:hash_len], data[hash_len:]
    unk, data = ord(data[0]), data[1:]
    assert not unk
    len_added, data = parse_cui(data)
    added, data = data[:len_added], data[len_added:]
    assert added == '\xff' * 4, utils.bin2hex(added)
    assert not data, utils.bin2hex(data)
    loc = locals()
    return dict((name, loc[name]) for name in names)


PARSE_TABLE = {
        0x00: parse_00,
        0x01: parse_01,
        0x02: parse_02,
        0x03: parse_03,
}


class Options(usage.Options):

    optParameters = [
            ['remote-host', 'r', server],
            ['logs-dir', 'l', logs_dir],
            ['filter', 'f', None, 'List of opcodes that should be logged, all other packets will be skipped. Format: 123,0x7c,0x7d:128'],
            ['exclude', 'e', None, "List of opcodes which wouldn't be logged, it has highest priority than 'filter' option"],
    ]


def parse_opcodes_list(value):
    """Parses list of opcodes separated by comma, supported range separated by ':' both ends are included.
    Returns set of opcodes
    """
    res = set()
    for opcode in value.split(','):
        if ':' in opcode:
            range_ = [int(val, 0) for val in opcode.split(':', 1)]
            res.update(xrange(*range_))
            opcode = range_[1]
        else:
            opcode = int(opcode, 0)
        res.add(opcode)
    return res


if __name__ == "__main__":
    # Parse command-line options
    config = Options()
    try:
        config.parseOptions() # When given no argument, parses sys.argv[1:]
    except usage.UsageError, errortext:
        print '%s: %s' % (sys.argv[0], errortext)
        print '%s: Try --help for usage details.' % (sys.argv[0])
        sys.exit(1)
    server = config['remote-host']
    logs_dir = config['logs-dir']
    filter_ = parse_opcodes_list(config['filter']) if config['filter'] else config['filter']
    exclude = parse_opcodes_list(config['exclude']) if config['exclude'] else config['exclude']

    # Start proxy
    log.startLogging(sys.stdout)
    factory = protocol.ServerFactory()
    factory.protocol = ProxyProtocol
    factory.remote_addr = (server, port)
    factory.handler = lambda: Handler(get_filename(logs_dir, filter_, exclude))
    reactor.listenTCP(port, factory, interface="0.0.0.0")
    reactor.run()
