import socket
import struct
import time

from constans import (
    FILTER_IP,
    FILTER_PORTS,
    HTTP_METHODS,
    HTTP_PORTS,
    MAX_STREAM,
    VERBOSE,
)


# --------------------------- payload inspection ----------------------------
def hexdump(data: bytes, limit: int = 768) -> str:
    """Hex + ASCII dump, really truncated at `limit` bytes."""
    view = data[:limit]
    out = []
    for offset in range(0, len(view), 16):
        chunk = view[offset:offset + 16]
        hx = " ".join("%02x" % b for b in chunk).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("    %04x  %s  %s" % (offset, hx, asc))
    if len(data) > limit:
        out.append("    ... (%d bytes total, showing first %d)"
                   % (len(data), limit))
    return "\n".join(out)


def is_http_start(data: bytes) -> bool:
    if not data:
        return False
    if data.startswith(b"HTTP/"):
        return True
    return data.split(b" ", 1)[0] in HTTP_METHODS


def http_ports():
    """Ports we treat as HTTP candidates: the built-ins plus your filter."""
    if FILTER_PORTS is None:
        return HTTP_PORTS
    return HTTP_PORTS | set(FILTER_PORTS)


class HttpReassembler:
    """
    Glue TCP segments back together so a split HTTP message prints once.

    One buffer per 4-tuple (src, sport, dst, dport).  Sequence numbers are
    used to ignore retransmissions and to recover from small gaps.
    """

    def __init__(self):
        self.streams = {}          # key -> [next_seq, bytearray]

    def has(self, key) -> bool:
        return key in self.streams

    def feed(self, key, seq: int, data: bytes):
        """
        Add a TCP segment.  Returns:
            None        -> pure retransmission, nothing new to show
            []          -> new bytes buffered but no complete message yet
            [messages]  -> one or more complete HTTP messages
        """
        state = self.streams.get(key)
        if state is None:
            state = [seq, bytearray()]
            self.streams[key] = state

        next_seq, buf = state
        if seq == next_seq:
            buf.extend(data)
            state[0] = next_seq + len(data)
        elif seq < next_seq:
            overlap = next_seq - seq
            if overlap >= len(data):
                return None                     # pure retransmission
            buf.extend(data[overlap:])
            state[0] = next_seq + len(data) - overlap
        else:
            # We missed a segment.  Start this stream over from here rather
            # than concatenating garbage.
            del buf[:]
            buf.extend(data)
            state[0] = seq + len(data)

        if len(buf) > MAX_STREAM:
            del buf[:len(buf) - MAX_STREAM]

        messages = []
        while True:
            message = self._take_one(buf)
            if message is None:
                break
            if message == "garbage":
                continue
            messages.append(message)
        return messages

    @staticmethod
    def _take_one(buf):
        sep = buf.find(b"\r\n\r\n")
        if sep < 0:
            return None

        head = bytes(buf[:sep])
        first = head.split(b"\r\n", 1)[0]
        is_request = first.split(b" ", 1)[0] in HTTP_METHODS
        is_response = first.startswith(b"HTTP/")
        if not (is_request or is_response):
            del buf[:sep + 4]                   # not HTTP: drop the block
            return "garbage"

        content_length = None
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    content_length = None
                break

        if content_length is None:
            # Requests have no body without Content-Length.  For responses
            # (chunked / close-delimited) we cannot find the end, so show
            # the headers and move on.
            content_length = 0
            if is_response:
                del buf[:sep + 4]
                return ("response", head, b"", None)

        total = sep + 4 + content_length
        if len(buf) < total:
            return None                          # wait for more segments

        body = bytes(buf[sep + 4:total])
        del buf[:total]
        return ("request" if is_request else "response",
                head, body, content_length)


def print_http(kind: str, head: bytes, body: bytes, content_length) -> None:
    side = "REQUEST" if kind == "request" else "RESPONSE"
    print("    ===== HTTP %s HEADERS =====" % side)
    for line in head.split(b"\r\n"):
        print("    " + line.decode("latin-1", "replace"))
    print("    ===== HTTP %s BODY (%d bytes%s) ====="
          % (side, len(body),
             "" if content_length is None
             else ", Content-Length=%d" % content_length))
    if body:
        print(hexdump(body))
    else:
        print("    (no body)")


def handle_ipv4(frame: bytes, direction: str,
                assembler: HttpReassembler) -> bool:
    """Display one IPv4 packet if it passes the display filter.

    Returns True when something was printed, False when the packet was hidden
    (so the relay loop can report that it is still alive).
    """
    ip = frame[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return False
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return False
    frag = struct.unpack("!H", ip[6:8])[0]
    if frag & 0x1FFF:                     # non-first fragment: no L4 header
        return False

    total = min(struct.unpack("!H", ip[2:4])[0], len(ip))
    proto = ip[9]
    src = socket.inet_ntoa(ip[12:16])
    dst = socket.inet_ntoa(ip[16:20])

    if FILTER_IP is not None and FILTER_IP not in (src, dst):
        return False

    seg = ip[ihl:total]
    key = seq = None
    sport = dport = None

    if proto == 6:                                    # TCP
        if len(seg) < 20:
            return False
        sport, dport = struct.unpack("!HH", seg[0:4])
        data_offset = (seg[12] >> 4) * 4
        if data_offset < 20 or len(seg) < data_offset:
            return False
        data = seg[data_offset:]
        seq = struct.unpack("!I", seg[4:8])[0]
        key = (src, sport, dst, dport)
        label = "TCP  %s:%d -> %s:%d" % (src, sport, dst, dport)
    elif proto == 17:                                 # UDP
        if len(seg) < 8:
            return False
        sport, dport = struct.unpack("!HH", seg[0:4])
        data = seg[8:]
        label = "UDP  %s:%d -> %s:%d" % (src, sport, dst, dport)
    elif proto == 1:                                  # ICMP
        if len(seg) < 4:
            return False
        data = seg[4:]
        label = "ICMP %s -> %s" % (src, dst)
    else:
        return False

    if not data:
        return False                                  # pure ACK / keep-alive

    if FILTER_PORTS is not None:
        if sport is None or not ({sport, dport} & FILTER_PORTS):
            return False

    candidates = http_ports()
    http_flow = (proto == 6 and
                 (assembler.has(key) or sport in candidates
                  or dport in candidates or is_http_start(data)))

    messages = None
    if http_flow:
        messages = assembler.feed(key, seq, data)
        if messages is None:
            return False                              # pure retransmission

    print("\n[%s] %-22s %s  (%d bytes)"
          % (time.strftime("%H:%M:%S"), direction, label, len(data)))

    if http_flow:
        if messages:
            for kind, head, body, content_length in messages:
                print_http(kind, head, body, content_length)
        else:
            print("    (partial HTTP segment buffered, waiting for more)")
        return True

    if VERBOSE:
        print(hexdump(data))
    else:
        preview = data[:60].decode("latin-1", "replace")
        preview = "".join(c if 32 <= ord(c) < 127 else "." for c in preview)
        print("    %s%s" % (preview, " ..." if len(data) > 60 else ""))
    return True
