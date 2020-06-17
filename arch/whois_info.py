import socket
import re

PORT = 43


# According to RFC1918 these addresses are allocated for private use:
# 10.0.0.0        -   10.255.255.255  (10/8 prefix)
# 172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
# 192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
# https://tools.ietf.org/html/rfc1918
def is_local(ip):
    o = list(map(int, ip.split('.')))
    if o[0] == 127 and 16 <= o[1] <= 31:
        return True
    if o[0] == 10:
        return True
    if o[0] == 192 and o[1] == 168:
        return True

    return False


class WhoisInfo:
    def __init__(self, ip, host="whois.iana.org"):
        self.name = ""
        self._as = ""
        self.country = ""
        self.is_local = False
        self.parse_error = False
        if is_local(ip):
            self.is_local = True
        else:
            self.parse_info(ip, host)

    def parse_info(self, ip, host="whois.iana.org"):
        data = self.get_data(ip, host)
        t = re.search(r"[nN]et[nN]ame:\s+\S+", data)
        if t:
            self.name = data[t.start() + 8:t.end()].strip()
        t = re.search(r"[Oo]riginA?S?:\s+A?S?\d*", data)
        if t:
            self._as = data[t.start():t.end()][10:].strip()[2:]
        t = re.search(r"[cC]ountry:\s+\S+", data)
        if t and data[t.start() + 8:t.end()].strip() != "EU":
            self.country = data[t.start() + 8:t.end()].strip()
        if self.name == "" and self._as == "" and self.country == "":
            try:
                t = re.search(r"whois.\S+.net", data)
                h = data[t.start():t.end()]
                self.parse_info(ip, h)
            except Exception:
                self.parse_error = True

    def get_data(self, ip, host):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, PORT))
            sock.settimeout(10)
            sock.sendall(socket.gethostbyname(ip).encode() + b'\n')
            res = b""
            while True:
                try:
                    data = sock.recv(1024)
                except socket.timeout:
                    self.is_local = True
                    return
                res += data
                if not data:
                    break
            try:
                res1 = res.decode()
            except Exception:
                res1 = res.decode(encoding='ISO-8859-1')
        return res1

    def get_res(self):
        if self.is_local:
            return "local"
        if self.parse_error:
            return "Error during parse whois answer"
        if self._as == "":
            return f"{self.name}, {self.country}"
        if self.country == "":
            return f"{self.name}, {self._as}"
        return f"{self.name}, {self._as}, {self.country}"
