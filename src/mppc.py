#!/usr/bin/env python


from bitstring import BitStream


class MPPCDecoder(object):

    max_history = 8191

    def __init__(self):
        self.history = ""
        self.in_buf = BitStream()
        self.out_buf = ""

    def flush_history(self):
        self.history = ""

    def add_to_history(self, v):
        self.history = self.history[-self.max_history + len(v):] + v
        self.out_buf += v

    def process_tuple(self, offset, length):
        if length > offset:
            v = self.history[-offset:] * length + self.history[-offset:-offset + length % offset]
        else:
            v = self.history[-offset:-offset + length]
        self.add_to_history(v)

    def decompress(self, data):
        stream = BitStream(bytes=data)

        self.out_buf = ''
        while len(stream.bin) >= 8:
            offset = None
            if stream.bin.startswith("0"):          # literal encoding < 80
                v = stream[0:8].uint
                self.add_to_history(chr(v))
                r = 8
            elif stream.bin.startswith("10"):         # literal encoding >= 80
                v = ('0b1' + stream[2:9]).uint
                self.add_to_history(chr(v))
                r = 9
            elif stream.bin.startswith("1111"):       # 0 <= offset < 64
                offset = stream[4:10].uint
                # Guess!! End on packet
                if not offset:
                    print stream[10:].bin
                    break
                r = 10
            elif stream.bin.startswith("1110"):       # 64 <= offset < 320
                offset = stream[4:12].uint + 64
                r = 12
            elif stream.bin.startswith("110"):        # 320 <= offset < 8191
                offset = stream[3:16].uint + 320
                r = 16
            else:
                raise RuntimeError("MPPC decode failed: %s\n%s" % (stream.bin[:8], stream.hex))
            if offset:
                for i in xrange(0, 12):
                    start = "1" * i + "0"
                    len_chunk = len(start)
                    if stream.bin.startswith(start):
                        if len_chunk == 1:
                            length = 3
                            r += 1
                        else:
                            length = ("0b1" + stream[len_chunk:len_chunk * 2]).uint
                            r += len_chunk * 2

                assert offset <= len(self.history)
                assert length <= len(self.history)

                self.process_tuple(offset, length)

            stream = stream[r:]
        return self.out_buf


def _mppc():

    max_history = 8191
    history = ""
    out_buf = ""
    stream = BitStream()

    while True:
        data = yield None
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
    assert gen.next() is None
    return gen


if __name__ == "__main__":
    import utils
    s = '04 1C 00 95 0D C8 00 01 5B 6F 00 1E 08 2F C4 00 5F FC 17 91 1E 23 C0'
    p = ''.join(chr(int(i, 16)) for i in s.split())
    #decomp = MPPCDecoder()
    #d = decomp.decompress(p)
    decomp = mppc()
    d = decomp.send(p)
    print utils.b2h(d)
    print len(d) == int('1c', 16) + 2
