#!/usr/bin/env python3
"""Local UDP+TCP fake DNS server with switchable faults, for testing dnscheck.

Binds 127.0.0.1 only. Never point it at, or run it against, a real network.

Faults:
  correct          well-formed answer
  wrong_txid       reply id is the query id XOR 0xFFFF
  case_not_echoed  question name has its letter case inverted
  oversize_no_tc   >512 byte reply (non-EDNS too) without TC
  loop_pointer     answer name is a compression pointer to itself
  drop_nth         every Nth query gets no reply
  duplicate        every UDP reply is sent twice (TCP: written twice)
  wrong_source     UDP reply leaves from a different socket/port
"""

import socket
import struct
import threading

FAULTS = ("correct", "wrong_txid", "case_not_echoed", "oversize_no_tc",
          "loop_pointer", "drop_nth", "duplicate", "wrong_source")


def _qend(data):
    off = 12
    while data[off]:
        off += 1 + data[off]
    return off + 1  # offset just past the root label


def build_reply(query, fault):
    qid, _flags, _qd, _an, _ns, arcount = struct.unpack("!6H", query[:12])
    end = _qend(query) + 4
    question = query[12:end]
    qtype = struct.unpack("!H", question[-4:-2])[0]
    edns = arcount > 0
    if fault == "wrong_txid":
        qid ^= 0xFFFF
    if fault == "case_not_echoed":
        question = question[:-4].swapcase() + question[-4:]
    if qtype == 1:
        rdata = bytes([192, 0, 2, 1])
    elif qtype == 28:
        rdata = bytes(15) + b"\x01"
    else:
        rdata = None
    answers = b""
    n = 0
    if rdata is not None:
        name = b"\xc0\x0c"
        if fault == "loop_pointer":
            off = 12 + len(question)
            name = bytes([0xC0 | (off >> 8), off & 0xFF])
        rr = name + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
        n = 40 if fault == "oversize_no_tc" else 1
        answers = rr * n
    additional = b""
    if edns:
        additional = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    hdr = struct.pack("!6H", qid, 0x8180, 1, n, 0, 1 if edns else 0)
    return hdr + question + answers + additional


class FakeDns:
    def __init__(self, fault="correct", drop_every=3, host="127.0.0.1"):
        if fault not in FAULTS:
            raise ValueError("unknown fault " + fault)
        self.fault = fault
        self.drop_every = drop_every
        self.host = host
        self.port = 0
        self._n = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads = []
        self._socks = []

    def _dropped(self):
        if self.fault != "drop_nth":
            return False
        with self._lock:
            self._n += 1
            return self._n % self.drop_every == 0

    def start(self):
        for _ in range(50):
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.bind((self.host, 0))
            t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                t.bind((self.host, u.getsockname()[1]))
            except OSError:
                u.close()
                t.close()
                continue
            break
        else:
            raise RuntimeError("no port free for both UDP and TCP")
        self.port = u.getsockname()[1]
        t.listen(16)
        u.settimeout(0.1)
        t.settimeout(0.1)
        self._socks = [u, t]
        for fn, s in ((self._udp_loop, u), (self._tcp_loop, t)):
            th = threading.Thread(target=fn, args=(s,), daemon=True)
            th.start()
            self._threads.append(th)

    def stop(self):
        self._stop.set()
        for th in self._threads:
            th.join(2)
        for s in self._socks:
            s.close()

    def _udp_loop(self, sock):
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(data) < 12 or self._dropped():
                continue
            reply = build_reply(data, self.fault)
            out = sock
            if self.fault == "wrong_source":
                out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                out.bind((self.host, 0))
            out.sendto(reply, addr)
            if self.fault == "duplicate":
                out.sendto(reply, addr)
            if out is not sock:
                out.close()

    def _tcp_loop(self, sock):
        while not self._stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            th = threading.Thread(target=self._tcp_conn, args=(conn,), daemon=True)
            th.start()

    def _recv_exact(self, conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise EOFError
            buf += chunk
        return buf

    def _tcp_conn(self, conn):
        conn.settimeout(0.2)
        with conn:
            while not self._stop.is_set():
                try:
                    ln = struct.unpack("!H", self._recv_exact(conn, 2))[0]
                    data = self._recv_exact(conn, ln)
                except socket.timeout:
                    continue
                except (EOFError, OSError):
                    return
                if len(data) < 12 or self._dropped():
                    continue
                reply = build_reply(data, self.fault)
                msg = struct.pack("!H", len(reply)) + reply
                try:
                    conn.sendall(msg)
                    if self.fault == "duplicate":
                        conn.sendall(msg)
                except OSError:
                    return


if __name__ == "__main__":
    import argparse
    import time
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fault", default="correct", choices=FAULTS)
    ap.add_argument("--drop-every", type=int, default=3)
    a = ap.parse_args()
    s = FakeDns(a.fault, a.drop_every)
    s.start()
    print("fake dns on 127.0.0.1:%d fault=%s" % (s.port, a.fault), flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        s.stop()
