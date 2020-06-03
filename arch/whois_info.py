import socket
import re

PORT = 43


class WhoisInfo:
    def __init__(self, ip, host="whois.iana.org"):
        self.name = ""
        self._as = ""
        self.country = ""
        self.is_local = False
        self.parse_info(ip, host)

    def parse_info(self, ip, host="whois.iana.org"):
        data = self.get_data(ip, host)
        try:
            t = re.search(r"[Nn]et[Nn]ame:\s+\S+", data)
            self.name = data[t.start() + 8:t.end()].strip()
            t = re.search(r"[Oo]riginA?S?:\s+A?S?\d*", data)
            self._as = data[t.start():t.end()][10:].strip()
            t = re.search(r"[cC]ountry:\s+\S+", data)
            if data[t.start() + 8:t.end()].strip() != "EU":
                self.country = data[t.start() + 8:t.end()].strip()
        except Exception:
            try:
                t = re.search(r"whois.\S+.net", data)
                h = data[t.start():t.end()]
                self.parse_info(ip, h)
            except Exception:
                self.is_local = True

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
            res = res.decode()
        return res

    def get_res(self):
        if self.is_local:
            return "local"
        if self._as == "":
            return f"{self.name}, {self.country}"
        return f"{self.name}, {self._as}, {self.country}"
