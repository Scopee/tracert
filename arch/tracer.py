import socket
import struct
import time
from arch.whois_info import WhoisInfo


def get_checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i + 1]
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s


def packet():
    head = struct.pack("bbHHh", 8, 0, 0, 0, 1)
    data = struct.pack("d", time.time())
    checksum = socket.htons(get_checksum(head + data))

    head = struct.pack("bbHHh", 8, 0, checksum, 0, 1)
    return head + data


def format_line(ttl, address):
    return f"{ttl}. {address}\r\n{WhoisInfo(address).get_res()}\r\n"


class Tracer:
    def __init__(self, ip, max_ttl):
        self.dest = ip
        self.ip = ip
        self.max_ttl = max_ttl
        self.count = 0
        self.socket = None
        self.res = []
        self.is_finish = False

    def ping(self):
        for ttl in range(1, self.max_ttl + 1):
            for i in range(3):
                self.send_packet(ttl)
                finish = self.recv_packet(ttl)
                if finish:
                    break
            if self.is_finish:
                break

    def send_packet(self, ttl):
        dest = socket.gethostbyname(self.ip)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                    socket.IPPROTO_ICMP)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL,
                               struct.pack('I', ttl))
        self.socket.settimeout(3)
        self.socket.sendto(packet(), (dest, 0))

    def recv_packet(self, ttl):
        try:
            pack, addr = self.socket.recvfrom(1024)
            if addr[0] == self.dest:
                self.is_finish = True
        except socket.timeout:
            print(f"{ttl}. *\r\n")
            self.count += 1
            return True
        else:
            t = pack[20]
            if t == 11 or t == 0:
                if self.count == ttl - 1:
                    print(format_line(ttl, addr[0]))
                    self.count += 1
                return True
        finally:
            self.socket.close()
