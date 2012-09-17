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
        offset = None
        marker_off = False
        while len(stream.bin):
            if marker_off is False:
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
                    # Guess!!
                    if not offset:
                        print stream[10:].bin
                        break
                    marker_off = True
                    r = 10
                elif stream.bin.startswith("1110"):       # 64 <= offset < 320
                    offset = stream[4:12].uint
                    offset += 64
                    #print "<[0b1110]>"
                    marker_off = True
                    r = 12
                elif stream.bin.startswith("110"):        # 320 <= offset < 8191
                    offset = stream[3:16].uint
                    offset += 320
                    #print "<[0b110]>"
                    marker_off = True
                    r = 16
                else:
                    assert not len(stream.bin), 'Not processed: "%s"' % stream.hex
                    break
            else:
                assert offset
                marker_off = False
                for i in xrange(0, 12):
                    start = "1" * i + "0"
                    len_chunk = len(start)
                    if stream.bin.startswith(start):
                        if len_chunk == 1:
                            length = 3
                            r = 1
                        else:
                            length = ("0b1" + stream[len_chunk:len_chunk * 2]).uint
                            r = len_chunk * 2

                assert offset <= len(self.history)
                assert length <= len(self.history)

                self.process_tuple(offset, length)

            stream = stream[r:]
        return self.out_buf


if __name__ == "__main__":
    import utils
    s = '04 1C 00 95 0D C8 00 01 5B 6F 00 1E 08 2F C4 00 5F FC 17 91 1E 23 C0'
    p = ''.join(chr(int(i, 16)) for i in s.split())
    decomp = MPPCDecoder()
    d = decomp.decompress(p)
    print utils.b2h(d)
    print len(d) == int('1c', 16) + 2
