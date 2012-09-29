#!/usr/bin/env python


from bitstring import BitStream


class NotEnoughtBits(IndexError):
    pass


class MPPCDecoder(object):

    max_history = 8191

    def __init__(self):
        self.history = ""
        self.in_buf = ""
        self.out_buf = ""
        self._shift = 0
        self._backup_shift = 0

    def _get_bits(self, number, with_shift=True):
        if number > len(self.in_buf) * 8 - self._shift:
            raise NotEnoughtBits("Available %s bits only" % (len(self.in_buf) * 8 - self._shift))
        res = 0
        processed = 0
        s_num, bit_num = divmod(self._shift, 8)
        while True:
            bit_num = 7 - bit_num
            c = ord(self.in_buf[s_num]) & int('1' * (bit_num + 1), 2)
            while bit_num + 1:
                a, c = divmod(c, 1 << bit_num)
                res = (res << 1) + (a and 1)
                bit_num -= 1
                processed += 1
                if processed == number:
                    break
            else:
                s_num += 1
                bit_num = 0
                continue
            break

        if with_shift:
            self._shift += number
        return res

    def _remove_processed(self, number=0):
        to_remove, self._shift = divmod(self._shift + number, 8)
        self.in_buf = self.in_buf[to_remove:]
        self._backup_shift = self._shift

    def add_to_history(self, v):
        self.history = self.history[-self.max_history + len(v):] + v
        self.out_buf += v
        self._remove_processed()

    def process_tuple(self, offset, length):
        if length >= offset:
            v = self.history[-offset:] * (length // offset) + self.history[-offset:-offset + length % offset]
        else:
            v = self.history[-offset:-offset + length]
        self.add_to_history(v)

    def decompress(self, data):
        self.in_buf += data
        self.out_buf = ''
        try:
            while self.in_buf:
                offset = None
                marker = self._get_bits(1)
                if marker is 0:                 # 0     # literal encoding < 80
                    self.add_to_history(chr(self._get_bits(7)))
                else:
                    marker = self._get_bits(1)
                    if marker is 0:             # 10    # literal encoding >= 80
                        self.add_to_history(chr(128 + self._get_bits(7)))
                    else:
                        marker = self._get_bits(1)
                        if marker is 0:         # 110   # 320 <= offset < 8191
                            offset = 320 + self._get_bits(13)
                        else:
                            marker = self._get_bits(1)
                            if marker is 0:     # 1110  # 64 <= offset < 320
                                offset = 64 + self._get_bits(8)
                            else:               # 1111  # 0 <= offset < 64
                                offset = self._get_bits(6)
                                # Guess!! Drop to end of the byte
                                if not offset:
                                    bits = self._shift % 8
                                    if bits:
                                        bits = 8 - bits
                                    self._remove_processed(bits)
                                    pass
                if offset:
                    len_chunk = 1
                    while self._get_bits(1):
                        len_chunk += 1
                    assert len_chunk < 13
                    if len_chunk == 1:
                        length = 3
                    else:
                        length = (1 << len_chunk) + self._get_bits(len_chunk)

                    assert offset <= len(self.history), "Offset - %s, len(history) - %s" % (offset, len(history))
                    assert length <= len(self.history), "Length - %s, len(history) - %s" % (length, len(history))
                    self.process_tuple(offset, length)
        except NotEnoughtBits:
            self._shift = self._backup_shift
        return self.out_buf


def _mppc():

    max_history = 8191
    history = ""
    out_buf = ""
    stream = BitStream()

    while True:
        data = yield ''
        stream += BitStream(bytes=data)
        while len(stream.bin) >= 8:
            offset = None
            v = ''
            r = 0
            if stream.bin.startswith("0"):          # literal encoding < 80
                r = 8
                v = chr(stream[0:8].uint)
            elif stream.bin.startswith("10"):         # literal encoding >= 80
                r = 9
                v = chr(('0b1' + stream[2:9]).uint)
            elif stream.bin.startswith("1111"):       # 0 <= offset < 64
                r = 10
                offset = stream[4:10].uint
                # Guess!! End on packet
                if not offset:
                    r += (len(stream) - r) % 8
                    data = yield out_buf
                    out_buf = ''
                    if data:
                        stream += BitStream(bytes=data)
            elif stream.bin.startswith("1110"):       # 64 <= offset < 320
                r = 12
                offset = stream[4:12].uint + 64
            elif stream.bin.startswith("110"):        # 320 <= offset < 8191
                r = 16
                offset = stream[3:16].uint + 320
            else:
                raise RuntimeError("MPPC decode failed: stream len - %s, offset - %s" % (len(stream), stream[:8].bin))
            if offset:
                for i in xrange(0, 12):
                    start = "1" * i + "0"
                    if stream.bin[r:].startswith(start):
                        len_chunk = len(start)
                        r += len_chunk
                        if len_chunk == 1:
                            length = 3
                        else:
                            length = ("0b1" + stream[r:r + len_chunk]).uint
                            r += len_chunk
                        break
                else:
                    #raise RuntimeError("MPPC decode failed: stream len - %s, offset - %s - %s, length - %s" % (len(stream), offset, stream[:r].bin, stream[r:r + 16].bin))
                    break
                #Process tuple
                assert offset <= len(history), "Offset - %s, len(history) - %s" % (offset, len(history))
                assert length <= len(history), "Length - %s, len(history) - %s" % (length, len(history))
                if length >= offset:
                    v = history[-offset:] * (length // offset) + history[-offset:-offset + length % offset]
                else:
                    v = history[-offset:-offset + length]
            #add_to_history(v)
            if v:
                history = history[-max_history + len(v):] + v
                out_buf += v
            #Remove processed bites
            stream = stream[r:]


def mppc():
    gen = _mppc()
    assert gen.next() is ''
    return gen


def test_bitstring(p):
    bs = BitStream(bytes=p)
    for exp in (7, 0, 5, 2, 0):
        real = bs[:3].uint
        bs = bs[3:]
        assert real == exp, "%s != %s" % (real, exp)

def test_get_bits(p):
    decomp = MPPCDecoder()
    decomp.in_buf = p
    for exp in (7, 0, 5, 2, 0):
        real = decomp._get_bits(3)
        assert real == exp, "%s != %s" % (real, exp)
        #print "%s - OK" % exp
    #print decomp._get_bits(1)
    #print decomp._get_bits(1)

if __name__ == "__main__":
    import cProfile
    import utils
    s = '04 1C 00 95 0D C8 00 01 5B 6F 00 1E 08 2F C4 00 5F FC 17 91 1E 23 C0'
    #s = 'E2 A0'
    p = ''.join(chr(int(i, 16)) for i in s.split())

    #cProfile.run('for i in xrange(10000): test_bitstring(p)')
    #cProfile.run('for i in xrange(10000): test_get_bits(p)')

    decomp_gb = MPPCDecoder()
    d = decomp_gb.decompress(p)
    print utils.b2h(d)
    print len(d) == int('1c', 16) + 2
    decomp_gen = mppc()
    d = decomp_gen.send(p)
    print utils.b2h(d)
    print len(d) == int('1c', 16) + 2

    cProfile.run('for i in xrange(10000): decomp_gen.send(p)')
    cProfile.run('for i in xrange(10000): decomp_gb.decompress(p)')

