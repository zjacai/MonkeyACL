import os
import re
import sys
import ssl
import time
import json
import base64
import hashlib
import shutil
import traceback
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer


OPTIONS = {
    "check_interval": 600,
    "grace_seconds": 180
}

RULE_TAG = "monkeyACL"
AUTO_CERT_NAME = "monkeyacl-auto.pem"
AUTO_KEY_NAME = "monkeyacl-auto.key"
RULE_GRACE = {}
RULE_GRACE_LOCK = threading.Lock()


class MonkeyACLServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, firewall):
        super().__init__(server_address, RequestHandlerClass)
        self.firewall = firewall


def normalize_ip(ip):
    if not ip:
        return ip
    if ip.startswith("::ffff:"):
        return ip[7:]
    return ip.strip("[]")


def is_valid_ipv4(ip):
    if not ip or not isinstance(ip, str):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if len(part) > 1 and part.startswith("0"):
            return False
        value = int(part)
        if value < 0 or value > 255:
            return False
    return True


def mark_rule_grace(ip):
    with RULE_GRACE_LOCK:
        RULE_GRACE[ip] = time.time() + OPTIONS["grace_seconds"]


def in_rule_grace(ip):
    now = time.time()
    with RULE_GRACE_LOCK:
        expire = RULE_GRACE.get(ip)
        if expire is None:
            return False
        if now < expire:
            return True
        RULE_GRACE.pop(ip, None)
        return False


RULE_TTL = {}


def mark_rule_ttl(ip, ttl_seconds):
    if not ttl_seconds:
        with RULE_GRACE_LOCK:
            RULE_TTL.pop(ip, None)
        return
    with RULE_GRACE_LOCK:
        RULE_TTL[ip] = time.time() + ttl_seconds


def rule_ttl_expired(ip):
    now = time.time()
    with RULE_GRACE_LOCK:
        expire = RULE_TTL.get(ip)
        if expire is None:
            return False
        if now < expire:
            return False
        RULE_TTL.pop(ip, None)
        RULE_GRACE.pop(ip, None)
        return True


def clear_rule_timers(ip):
    with RULE_GRACE_LOCK:
        RULE_GRACE.pop(ip, None)
        RULE_TTL.pop(ip, None)


def run_cmd(cmd, timeout=30, input_data=None):
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            input=input_data
        )
    except FileNotFoundError:
        return 127, "", "command not found"
    except Exception as e:
        return 1, "", str(e)
    stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
    stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
    return result.returncode, stdout, stderr


def which(name):
    return shutil.which(name)


def is_admin():
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _peer_from_endpoint(peer):
    if not peer or ":" not in peer:
        return None
    ip = peer.rsplit(":", 1)[0]
    ip = normalize_ip(ip)
    if ip and ip not in ("0.0.0.0", "*", "::"):
        return ip
    return None


def get_connected_ips():
    peer_ips = set()

    if os.name == "nt":
        code, out, _ = run_cmd(["netstat", "-ano", "-p", "TCP"])
        if code == 0:
            for line in out.splitlines():
                upper = line.upper()
                if "ESTABLISHED" not in upper and "已建立" not in line:
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    ip = _peer_from_endpoint(parts[2])
                    if ip:
                        peer_ips.add(ip)
        return peer_ips

    if which("ss"):
        code, out, _ = run_cmd(["ss", "-antp"])
        if code == 0:
            for line in out.splitlines():
                if "ESTAB" not in line.upper():
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    ip = _peer_from_endpoint(parts[4])
                    if ip:
                        peer_ips.add(ip)
            return peer_ips

    if which("netstat"):
        code, out, _ = run_cmd(["netstat", "-ant"])
        if code == 0:
            for line in out.splitlines():
                if "ESTABLISHED" not in line.upper():
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    ip = _peer_from_endpoint(parts[4])
                    if ip:
                        peer_ips.add(ip)
    return peer_ips


def _der_len(n):
    if n < 128:
        return bytes([n])
    raw = []
    while n:
        raw.append(n & 0xff)
        n >>= 8
    raw.reverse()
    return bytes([0x80 | len(raw)]) + bytes(raw)


def _der_tlv(tag, data):
    return bytes([tag]) + _der_len(len(data)) + data


def _der_int(x):
    if x == 0:
        body = b"\x00"
    else:
        length = (x.bit_length() + 7) // 8
        body = x.to_bytes(length, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return _der_tlv(0x02, body)


def _der_oid(parts):
    body = bytes([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        stack = [n & 0x7f]
        n >>= 7
        while n:
            stack.append(0x80 | (n & 0x7f))
            n >>= 7
        body += bytes(reversed(stack))
    return _der_tlv(0x06, body)


def _der_bitstring(data, unused=0):
    return _der_tlv(0x03, bytes([unused]) + data)


def _der_octet(data):
    return _der_tlv(0x04, data)


def _der_seq(*items):
    return _der_tlv(0x30, b"".join(items))


def _der_set(*items):
    return _der_tlv(0x31, b"".join(items))


def _der_ctx(n, data, constructed=True):
    tag = (0xa0 if constructed else 0x80) | n
    return _der_tlv(tag, data)


def _egcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def _modinv(a, m):
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("modular inverse failed")
    return x % m


def _is_prime(n, rounds=8):
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31)
    for p in small:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = int.from_bytes(os.urandom(2 + n.bit_length() // 8), "big") % (n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        n = int.from_bytes(os.urandom(bits // 8), "big")
        n |= (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n


def _rsa_keypair(bits=2048):
    e = 65537
    half = bits // 2
    while True:
        p = _gen_prime(half)
        q = _gen_prime(half)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = _modinv(e, phi)
        n = p * q
        if n.bit_length() != bits:
            continue
        d_p = d % (p - 1)
        d_q = d % (q - 1)
        q_inv = _modinv(q, p)
        return n, e, d, p, q, d_p, d_q, q_inv


def _pem(label, der):
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)


def _pkcs1_private_der(n, e, d, p, q, d_p, d_q, q_inv):
    return _der_seq(
        _der_int(0),
        _der_int(n),
        _der_int(e),
        _der_int(d),
        _der_int(p),
        _der_int(q),
        _der_int(d_p),
        _der_int(d_q),
        _der_int(q_inv),
    )


def _rsa_public_der(n, e):
    return _der_seq(_der_int(n), _der_int(e))


def _pkcs1_sign(tbs, d, n):
    digest = hashlib.sha256(tbs).digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    k = (n.bit_length() + 7) // 8
    pad_len = k - len(digest_info) - 3
    em = b"\x00\x01" + (b"\xff" * pad_len) + b"\x00" + digest_info
    sig = pow(int.from_bytes(em, "big"), d, n)
    return sig.to_bytes(k, "big")


def generate_self_signed_python(cert_path, key_path, days=365, cn="monkeyACL"):
    n, e, d, p, q, d_p, d_q, q_inv = _rsa_keypair(2048)
    key_der = _pkcs1_private_der(n, e, d, p, q, d_p, d_q, q_inv)
    pub_der = _rsa_public_der(n, e)

    now = int(time.time()) - 86400
    until = int(time.time()) + days * 86400

    def utc(ts):
        return time.strftime("%y%m%d%H%M%SZ", time.gmtime(ts)).encode("ascii")

    oid_cn = _der_oid((2, 5, 4, 3))
    oid_rsa = _der_oid((1, 2, 840, 113549, 1, 1, 1))
    oid_sha256_rsa = _der_oid((1, 2, 840, 113549, 1, 1, 11))
    alg_id = _der_seq(oid_sha256_rsa, _der_tlv(0x05, b""))
    rsa_alg = _der_seq(oid_rsa, _der_tlv(0x05, b""))
    name = _der_seq(_der_set(_der_seq(oid_cn, _der_tlv(0x0c, cn.encode("utf-8")))))
    spki = _der_seq(rsa_alg, _der_bitstring(pub_der))
    serial = int.from_bytes(os.urandom(8), "big") | 1
    validity = _der_seq(_der_tlv(0x17, utc(now)), _der_tlv(0x17, utc(until)))
    tbs = _der_seq(
        _der_ctx(0, _der_int(2)),
        _der_int(serial),
        alg_id,
        name,
        validity,
        name,
        spki,
    )
    sig = _pkcs1_sign(tbs, d, n)
    cert_der = _der_seq(tbs, alg_id, _der_bitstring(sig))

    with open(key_path, "w", encoding="ascii") as f:
        f.write(_pem("RSA PRIVATE KEY", key_der))
    with open(cert_path, "w", encoding="ascii") as f:
        f.write(_pem("CERTIFICATE", cert_der))
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass


def generate_self_signed_openssl(cert_path, key_path, days=365):
    openssl = which("openssl")
    if not openssl:
        return False
    code, _, err = run_cmd([
        openssl, "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", cert_path,
        "-days", str(days), "-nodes",
        "-subj", "/CN=monkeyACL"
    ], timeout=60)
    if code != 0:
        return False
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass
    return os.path.isfile(cert_path) and os.path.isfile(key_path)


def ensure_ssl_files(cert_path, key_path):
    if cert_path and key_path and os.path.isfile(cert_path) and os.path.isfile(key_path):
        return cert_path, key_path, False

    base_dir = os.path.dirname(os.path.abspath(__file__))
    auto_cert = os.path.join(base_dir, AUTO_CERT_NAME)
    auto_key = os.path.join(base_dir, AUTO_KEY_NAME)

    if os.path.isfile(auto_cert) and os.path.isfile(auto_key):
        print("[i] Using previously generated self-signed SSL certificate.")
        print("[i] Certificate: %s" % auto_cert)
        print("[i] Private key: %s" % auto_key)
        return auto_cert, auto_key, True

    print("[i] No SSL certificate specified, generating a self-signed certificate...")
    if generate_self_signed_openssl(auto_cert, auto_key):
        print("[i] Generated self-signed certificate with openssl.")
    else:
        generate_self_signed_python(auto_cert, auto_key)
        print("[i] Generated self-signed certificate with the built-in generator.")
    print("[i] Certificate: %s" % auto_cert)
    print("[i] Private key: %s" % auto_key)
    print("[!] Self-signed certificate. API clients should allow insecure TLS (curl -k).")
    return auto_cert, auto_key, True


class FirewalldBackend:
    name = "firewalld"

    def get_netstat(self):
        return get_connected_ips()

    def add_rule(self, ip, port, protocol="tcp"):
        zone = "public"
        try:
            rich_rule = (
                'rule family="ipv4" '
                'source address="%s" '
                'port port="%s" protocol="%s" '
                'log prefix="%s" level="info" '
                "accept" % (ip, port, protocol, RULE_TAG)
            )
            cmd = ["firewall-cmd", "--zone", zone, "--add-rich-rule", rich_rule]
            print("[%s] Create rule: %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), " ".join(cmd)))
            subprocess.check_call(cmd)
            cmd = ["firewall-cmd", "--permanent", "--zone", zone, "--add-rich-rule", rich_rule]
            print("[%s] Create rule: %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), " ".join(cmd)))
            subprocess.check_call(cmd)
            subprocess.check_call(["firewall-cmd", "--reload"])
            return {"success": True, "message": "Create firewall rule success: %s --[%s]--> %s" % (ip, protocol, port)}
        except Exception:
            return {"success": False, "exception": True, "message": "Create firewall rule failed: %s" % traceback.format_exc()}

    def remove_rule(self, target_ip, zone="public"):
        try:
            result = subprocess.check_output(
                ["firewall-cmd", "--zone", zone, "--list-rich-rules"],
                universal_newlines=True
            )
            rules = result.strip().splitlines()
            removed = False
            for rule in rules:
                if RULE_TAG in rule and 'source address="%s"' % target_ip in rule:
                    subprocess.call(["firewall-cmd", "--zone", zone, "--remove-rich-rule", rule])
                    subprocess.call(["firewall-cmd", "--permanent", "--zone", zone, "--remove-rich-rule", rule])
                    removed = True
            if removed:
                subprocess.check_call(["firewall-cmd", "--reload"])
                return {"success": True, "message": "Remove firewall rule success"}
            return {"success": False, "exception": False, "message": "Non-existent rules"}
        except Exception:
            return {"success": False, "exception": True, "message": traceback.format_exc()}

    def get_authorized_ips(self, zone="public"):
        try:
            result = subprocess.check_output(
                ["firewall-cmd", "--zone", zone, "--list-rich-rules"],
                universal_newlines=True
            )
            ip_list = []
            for rule in result.strip().splitlines():
                if RULE_TAG in rule:
                    match = re.search(r'source address="([^"]+)"', rule)
                    if match:
                        ip_list.append(match.group(1))
            return {"success": True, "data": ip_list}
        except Exception as e:
            return {"success": False, "exception": True, "message": str(e), "error": traceback.format_exc()}

    def rule_exists(self, ip, port, protocol="tcp", zone="public"):
        try:
            result = subprocess.check_output(
                ["firewall-cmd", "--zone", zone, "--list-rich-rules"],
                universal_newlines=True
            )
            ip_str = 'source address="%s"' % ip
            port_str = 'port port="%s" protocol="%s"' % (port, protocol)
            for rule in result.strip().splitlines():
                if RULE_TAG in rule and ip_str in rule and port_str in rule:
                    return True
            return False
        except subprocess.CalledProcessError:
            return False

    def hint_open_api_port(self, port):
        return [
            "sudo firewall-cmd --zone=public --add-port=%s/tcp --permanent" % port,
            "sudo firewall-cmd --reload",
        ]


class UfwBackend:
    name = "ufw"

    def get_netstat(self):
        return get_connected_ips()

    def _comment(self):
        return RULE_TAG

    def add_rule(self, ip, port, protocol="tcp"):
        try:
            cmd = [
                "ufw", "allow", "from", ip, "to", "any",
                "port", str(port), "proto", protocol,
                "comment", self._comment()
            ]
            print("[%s] Create rule: %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), " ".join(cmd)))
            code, out, err = run_cmd(cmd)
            if code != 0:
                return {"success": False, "exception": True, "message": "Create firewall rule failed: %s" % (err or out)}
            return {"success": True, "message": "Create firewall rule success: %s --[%s]--> %s" % (ip, protocol, port)}
        except Exception:
            return {"success": False, "exception": True, "message": "Create firewall rule failed: %s" % traceback.format_exc()}

    def remove_rule(self, target_ip):
        try:
            code, out, err = run_cmd(["ufw", "status", "numbered"])
            if code != 0:
                return {"success": False, "exception": True, "message": err or out}
            numbers = []
            for line in out.splitlines():
                if RULE_TAG not in line:
                    continue
                if target_ip not in line:
                    continue
                match = re.match(r"\[\s*(\d+)\]", line.strip())
                if match:
                    numbers.append(int(match.group(1)))
            if not numbers:
                return {"success": False, "exception": False, "message": "Non-existent rules"}
            for num in sorted(numbers, reverse=True):
                run_cmd(["ufw", "--force", "delete", str(num)])
            return {"success": True, "message": "Remove firewall rule success"}
        except Exception:
            return {"success": False, "exception": True, "message": traceback.format_exc()}

    def get_authorized_ips(self):
        try:
            code, out, err = run_cmd(["ufw", "status"])
            if code != 0:
                return {"success": False, "exception": True, "message": err or out}
            ip_list = []
            for line in out.splitlines():
                if RULE_TAG not in line:
                    continue
                parts = line.split()
                for token in parts:
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", token):
                        ip_list.append(token)
            return {"success": True, "data": ip_list}
        except Exception as e:
            return {"success": False, "exception": True, "message": str(e), "error": traceback.format_exc()}

    def rule_exists(self, ip, port, protocol="tcp"):
        code, out, _ = run_cmd(["ufw", "status"])
        if code != 0:
            return False
        compact = "%s/%s" % (port, protocol)
        for line in out.splitlines():
            if RULE_TAG not in line or ip not in line:
                continue
            lowered = line.lower().replace(" ", "")
            if compact in lowered or (str(port) in line and protocol in line.lower()):
                return True
        return False

    def hint_open_api_port(self, port):
        return ["sudo ufw allow %s/tcp" % port]


class IptablesBackend:
    name = "iptables"

    def get_netstat(self):
        return get_connected_ips()

    def _persist(self):
        code, out, _ = run_cmd(["iptables-save"])
        if code != 0:
            return
        for path in ("/etc/iptables/rules.v4", "/etc/sysconfig/iptables"):
            if os.path.isfile(path):
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(out)
                except Exception:
                    pass
                return

    def add_rule(self, ip, port, protocol="tcp"):
        try:
            cmd = [
                "iptables", "-I", "INPUT", "1",
                "-s", ip, "-p", protocol, "--dport", str(port),
                "-m", "comment", "--comment", RULE_TAG,
                "-j", "ACCEPT"
            ]
            print("[%s] Create rule: %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), " ".join(cmd)))
            code, out, err = run_cmd(cmd)
            if code != 0:
                return {"success": False, "exception": True, "message": "Create firewall rule failed: %s" % (err or out)}
            self._persist()
            return {"success": True, "message": "Create firewall rule success: %s --[%s]--> %s" % (ip, protocol, port)}
        except Exception:
            return {"success": False, "exception": True, "message": "Create firewall rule failed: %s" % traceback.format_exc()}

    def _list_rules(self):
        code, out, err = run_cmd(["iptables", "-S", "INPUT"])
        if code != 0:
            raise RuntimeError(err or out)
        return out.splitlines()

    def remove_rule(self, target_ip):
        try:
            removed = False
            for line in self._list_rules():
                if RULE_TAG not in line:
                    continue
                if "-s %s" % target_ip not in line and "-s %s/32" % target_ip not in line:
                    continue
                parts = line.split()
                if parts and parts[0] == "-A":
                    delete = ["iptables", "-D"] + parts[1:]
                    code, _, _ = run_cmd(delete)
                    if code == 0:
                        removed = True
            if removed:
                self._persist()
                return {"success": True, "message": "Remove firewall rule success"}
            return {"success": False, "exception": False, "message": "Non-existent rules"}
        except Exception:
            return {"success": False, "exception": True, "message": traceback.format_exc()}

    def get_authorized_ips(self):
        try:
            ip_list = []
            for line in self._list_rules():
                if RULE_TAG not in line:
                    continue
                match = re.search(r"-s\s+([0-9.]+)(?:/32)?", line)
                if match:
                    ip_list.append(match.group(1))
            return {"success": True, "data": ip_list}
        except Exception as e:
            return {"success": False, "exception": True, "message": str(e), "error": traceback.format_exc()}

    def rule_exists(self, ip, port, protocol="tcp"):
        try:
            for line in self._list_rules():
                if RULE_TAG not in line:
                    continue
                if ip not in line:
                    continue
                if "--dport %s" % port not in line and "--dport=%s" % port not in line:
                    continue
                if "-p %s" % protocol not in line and "-p%s" % protocol not in line:
                    continue
                return True
            return False
        except Exception:
            return False

    def hint_open_api_port(self, port):
        return ["sudo iptables -I INPUT -p tcp --dport %s -j ACCEPT" % port]


class NftablesBackend:
    name = "nftables"
    table = "monkeyacl"
    chain = "input"

    def get_netstat(self):
        return get_connected_ips()

    def _ensure_table(self):
        code, _, _ = run_cmd(["nft", "list", "table", "inet", self.table])
        if code == 0:
            return True
        script = (
            "add table inet %s\n"
            "add chain inet %s %s { type filter hook input priority -10 ; policy accept ; }\n"
            % (self.table, self.table, self.chain)
        )
        code, _, _ = run_cmd(["nft", "-f", "-"], input_data=script.encode("utf-8"))
        return code == 0

    def add_rule(self, ip, port, protocol="tcp"):
        try:
            if not self._ensure_table():
                return {"success": False, "exception": True, "message": "Create nftables table failed"}
            cmd = [
                "nft", "add", "rule", "inet", self.table, self.chain,
                "ip", "saddr", ip, protocol, "dport", str(port),
                "comment", '"%s"' % RULE_TAG, "accept"
            ]
            print("[%s] Create rule: %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), " ".join(cmd)))
            code, out, err = run_cmd(cmd)
            if code != 0:
                return {"success": False, "exception": True, "message": "Create firewall rule failed: %s" % (err or out)}
            return {"success": True, "message": "Create firewall rule success: %s --[%s]--> %s" % (ip, protocol, port)}
        except Exception:
            return {"success": False, "exception": True, "message": "Create firewall rule failed: %s" % traceback.format_exc()}

    def _list_json_or_text(self):
        code, out, err = run_cmd(["nft", "-a", "list", "chain", "inet", self.table, self.chain])
        if code != 0:
            return ""
        return out

    def remove_rule(self, target_ip):
        try:
            text = self._list_json_or_text()
            handles = []
            for line in text.splitlines():
                if RULE_TAG not in line:
                    continue
                if target_ip not in line:
                    continue
                match = re.search(r"handle\s+(\d+)", line)
                if match:
                    handles.append(match.group(1))
            if not handles:
                return {"success": False, "exception": False, "message": "Non-existent rules"}
            for handle in handles:
                run_cmd(["nft", "delete", "rule", "inet", self.table, self.chain, "handle", handle])
            return {"success": True, "message": "Remove firewall rule success"}
        except Exception:
            return {"success": False, "exception": True, "message": traceback.format_exc()}

    def get_authorized_ips(self):
        try:
            text = self._list_json_or_text()
            ip_list = []
            for line in text.splitlines():
                if RULE_TAG not in line:
                    continue
                match = re.search(r"saddr\s+([0-9.]+)", line)
                if match:
                    ip_list.append(match.group(1))
            return {"success": True, "data": ip_list}
        except Exception as e:
            return {"success": False, "exception": True, "message": str(e), "error": traceback.format_exc()}

    def rule_exists(self, ip, port, protocol="tcp"):
        text = self._list_json_or_text()
        for line in text.splitlines():
            if RULE_TAG in line and ip in line and str(port) in line and protocol in line:
                return True
        return False

    def hint_open_api_port(self, port):
        return [
            "sudo nft add rule inet filter input tcp dport %s accept" % port
        ]


class WindowsFirewallBackend:
    name = "windows"

    def get_netstat(self):
        return get_connected_ips()

    def _rule_name(self, ip, port, protocol):
        return "%s-%s-%s-%s" % (RULE_TAG, ip, port, protocol)

    def add_rule(self, ip, port, protocol="tcp"):
        try:
            name = self._rule_name(ip, port, protocol)
            proto = "TCP" if protocol.lower() == "tcp" else "UDP"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=%s" % name,
                "dir=in",
                "action=allow",
                "protocol=%s" % proto,
                "localport=%s" % port,
                "remoteip=%s" % ip,
                "enable=yes",
                "profile=any"
            ]
            print("[%s] Create rule: %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), " ".join(cmd)))
            code, out, err = run_cmd(cmd)
            if code != 0:
                return {"success": False, "exception": True, "message": "Create firewall rule failed: %s" % (err or out)}
            return {"success": True, "message": "Create firewall rule success: %s --[%s]--> %s" % (ip, protocol, port)}
        except Exception:
            return {"success": False, "exception": True, "message": "Create firewall rule failed: %s" % traceback.format_exc()}

    def _iter_rule_names(self):
        code, out, err = run_cmd(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
        if code != 0:
            raise RuntimeError(err or out)
        names = []
        for line in out.splitlines():
            stripped = line.strip()
            lower = stripped.lower()
            if lower.startswith("rule name:") or lower.startswith("规则名称:"):
                name = stripped.split(":", 1)[1].strip()
                if name.startswith(RULE_TAG):
                    names.append(name)
        return names

    def remove_rule(self, target_ip):
        try:
            removed = False
            prefix = "%s-%s-" % (RULE_TAG, target_ip)
            for name in self._iter_rule_names():
                if name.startswith(prefix):
                    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", "name=%s" % name]
                    code, _, _ = run_cmd(cmd)
                    if code == 0:
                        removed = True
            if removed:
                return {"success": True, "message": "Remove firewall rule success"}
            return {"success": False, "exception": False, "message": "Non-existent rules"}
        except Exception:
            return {"success": False, "exception": True, "message": traceback.format_exc()}

    def get_authorized_ips(self):
        try:
            ip_list = []
            for name in self._iter_rule_names():
                rest = name[len(RULE_TAG) + 1:]
                parts = rest.rsplit("-", 2)
                if len(parts) == 3:
                    ip_list.append(parts[0])
            return {"success": True, "data": ip_list}
        except Exception as e:
            return {"success": False, "exception": True, "message": str(e), "error": traceback.format_exc()}

    def rule_exists(self, ip, port, protocol="tcp"):
        try:
            name = self._rule_name(ip, port, protocol)
            for existing in self._iter_rule_names():
                if existing == name:
                    return True
            return False
        except Exception:
            return False

    def hint_open_api_port(self, port):
        return [
            'netsh advfirewall firewall add rule name="MonkeyACL-API" dir=in action=allow protocol=TCP localport=%s' % port
        ]


def firewalld_running():
    if not which("firewall-cmd"):
        return False
    code, out, _ = run_cmd(["firewall-cmd", "--state"])
    return code == 0 and "running" in (out or "").lower()


def ufw_active():
    if not which("ufw"):
        return False
    code, out, _ = run_cmd(["ufw", "status"])
    if code != 0:
        return False
    first = (out.splitlines() or [""])[0].lower()
    return "inactive" not in first and "active" in first


def detect_firewall():
    if os.name == "nt":
        return WindowsFirewallBackend()
    if firewalld_running():
        return FirewalldBackend()
    if ufw_active():
        return UfwBackend()
    if which("iptables"):
        code, _, _ = run_cmd(["iptables", "-L", "-n"])
        if code == 0:
            return IptablesBackend()
    if which("nft"):
        return NftablesBackend()
    if which("ufw"):
        return UfwBackend()
    if which("firewall-cmd"):
        return FirewalldBackend()
    return None


class MonkeyACLHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _write_json(self, payload):
        body = json.dumps(payload).encode("utf-8") + b"\n\n"
        self.send_response_only(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_text(self, text):
        body = text.encode("utf-8")
        self.send_response_only(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reject_empty(self):
        self.send_response_only(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.wfile.write(b"")

    def do_POST(self):
        request_path = request_api_path(self.path)
        expected_path = OPTIONS["url"]
        if request_path != expected_path and not request_path.startswith(expected_path + "/"):
            print("[%s] Rejected api Call: Illegal URI address： [%s], expected: [/%s]" % (
                time.strftime("%Y-%m-%d %H:%M:%S"), self.path, expected_path))
            self._reject_empty()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            json_data = json.loads(post_data)
        except Exception:
            self._write_json({"success": False, "message": "Invalid JSON body"})
            return

        if "auth" not in json_data:
            print("[%s] Rejected api Call: Illegal user auth: [%s], set auth: [%s]" % (
                time.strftime("%Y-%m-%d %H:%M:%S"), None, OPTIONS["auth"]))
            self._reject_empty()
            return
        auth = json_data["auth"]
        if auth != OPTIONS["auth"]:
            print("[%s] Rejected api Call: Illegal user auth: [%s], set auth: [%s]" % (
                time.strftime("%Y-%m-%d %H:%M:%S"), auth, OPTIONS["auth"]))
            self._write_text("auth failed\n\n")
            return

        action = str(json_data.get("action", "add")).lower()
        if action not in ("add", "delete"):
            self._write_json({"success": False, "message": "%s is not a valid action" % json_data.get("action")})
            return

        caller_ip = normalize_ip(self.client_address[0])
        if "ip" in json_data and json_data["ip"] not in (None, ""):
            ip = normalize_ip(str(json_data["ip"]).strip())
            if not is_valid_ipv4(ip):
                self._write_json({"success": False, "message": "%s is not a valid IPv4 address" % json_data["ip"]})
                return
        else:
            ip = caller_ip
            if not is_valid_ipv4(ip):
                self._write_json({"success": False, "message": "%s is not a valid IPv4 address" % ip})
                return

        if action == "delete":
            res = self.server.firewall.remove_rule(target_ip=ip)
            if res.get("success"):
                clear_rule_timers(ip)
                res["ip"] = ip
                res["action"] = "delete"
            self._write_json(res)
            return

        if "port" not in json_data:
            print("[%s] Rejected api Call: Invalid parameter of port" % time.strftime("%Y-%m-%d %H:%M:%S"))
            self._reject_empty()
            return
        p = json_data["port"]
        try:
            port = int(p)
        except Exception:
            self._write_json({"success": False, "message": "%s is not a valid port" % p})
            return
        if port < 0 or port > 65535:
            self._write_json({"success": False, "message": "%s is not a valid port" % p})
            return

        if "protocol" not in json_data:
            print("[%s] Rejected api Call: Invalid parameter of protocol" % time.strftime("%Y-%m-%d %H:%M:%S"))
            self._reject_empty()
            return

        protocol = str(json_data["protocol"]).lower()
        if protocol not in ("tcp", "udp"):
            self._write_json({"success": False, "message": "%s is not a valid protocol" % json_data["protocol"]})
            return

        ttl = 0
        if "ttl" in json_data and json_data["ttl"] not in (None, ""):
            try:
                ttl = int(json_data["ttl"])
            except Exception:
                self._write_json({"success": False, "message": "%s is not a valid ttl" % json_data["ttl"]})
                return
            if ttl < 1:
                self._write_json({"success": False, "message": "ttl must be greater than 0"})
                return

        if self.server.firewall.rule_exists(ip=ip, port=port, protocol=protocol):
            self._write_json({"success": False, "message": "The rule already exists, there is no need to create it again."})
            return
        res = self.server.firewall.add_rule(ip=ip, port=port, protocol=protocol)
        if res.get("success"):
            mark_rule_grace(ip)
            mark_rule_ttl(ip, ttl)
            res["ip"] = ip
            res["action"] = "add"
            if ttl:
                res["ttl"] = ttl
        self._write_json(res)


def strip_wrapping_quotes(value):
    if not isinstance(value, str):
        return value
    value = value.strip()
    while len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"', "`"):
        value = value[1:-1].strip()
    return value


def normalize_api_url(url):
    url = strip_wrapping_quotes(url).strip()
    url = url.lstrip("/")
    return url.strip("/")


def request_api_path(request_path):
    path = request_path.split("?", 1)[0]
    return path.strip("/")


class Tool:
    def parse_args(self, argv):
        options = {}
        positionals = []
        for arg in argv:
            if arg.startswith("--"):
                if "=" in arg:
                    key, value = arg[2:].split("=", 1)
                    options[key] = strip_wrapping_quotes(value)
                else:
                    options[arg[2:]] = True
            elif arg.startswith("-") and len(arg) > 1:
                for char in arg[1:]:
                    options[char] = True
            else:
                positionals.append(arg)
        return options, positionals

    def check_password(self, pwd):
        return (
            len(pwd) > 15 and
            any(c.islower() for c in pwd) and
            any(c.isupper() for c in pwd) and
            any(c.isdigit() for c in pwd)
        )


ascii_logo = """
                        _                       _____ _      
                       | |                /\\   / ____| |     
  _ __ ___   ___  _ __ | | _____ _   _   /  \\ | |    | |     
 | '_ ` _ \\ / _ \\| '_ \\| |/ / _ \\ | | | / /\\ \\| |    | |     
 | | | | | | (_) | | | |   <  __/ |_| |/ ____ \\ |____| |____ 
 |_| |_| |_|\\___/|_| |_|_|\\_\\___|\\___ /_/    \\_\\_____|______|
                                  __/ |                      
                                 |___/                       

A lightweight, secure tool for dynamic firewall authorization
Designed for temporary access control and on-demand port opening via API automation.
"""


def help_message():
    print("")
    print(ascii_logo)
    print("Github: https://github.com/Scorcsoft/monkeyACL")
    print("")
    print("Options:")
    print("    -h,--help: \t Show this help message and exit")
    print("\n")
    print("Required parameter:")
    print("    --auth=AUTH: \t\t API authentication")
    print("    --port=PORT: \t\t API HTTP port")
    print("    --url=URL: \t\t\t API URL")
    print("\n")
    print("Optional parameter:")
    print("    --cert=PATH_TO_CERT_FILE: \t Path of the SSL certificate file (pem)")
    print("    --key=PATH_TO_KEY_FILE: \t Path to the SSL private key file (pem)")
    print("    --interval=SECONDS: \t Idle-check interval in seconds, default 600")
    print("\n")
    print("Notes:")
    print("    For your server security, The length of the --auth parameter must be greater than 16, and it must contain uppercase letters, lowercase letters, numbers")
    print("    If --cert and --key are omitted, Monkey ACL generates a self-signed certificate automatically.")
    print("    Supported platforms: Linux (firewalld / ufw / iptables / nftables) and Windows (Windows Firewall).")
    print("\n")
    print("Example:")
    print("    python3 monkeyACL.py --auth='1*r^(5_N1rrbKo6e' --port=8080 --url='myapi'")
    print("    python3 monkeyACL.py --auth='1*r^(5_N1rrbKo6e' --port=8080 --url='myapi' --cert=cert.pem --key=key.pem")
    print("\n\n")


def acl_recycle(firewall):
    print("[i] Automatically detect network connections and clean up unused rules.")
    while 1:
        netstat = firewall.get_netstat()
        rules = firewall.get_authorized_ips()
        if rules["success"]:
            for ip in rules["data"]:
                if rule_ttl_expired(ip):
                    print("[%s] The authorized IP: [%s] reached ttl, its permission will be removed." % (
                        time.strftime("%Y-%m-%d %H:%M:%S"), ip))
                    r = firewall.remove_rule(target_ip=ip)
                    if r["success"]:
                        clear_rule_timers(ip)
                        print("[%s] Successfully removed access permission for [%s]" % (
                            time.strftime("%Y-%m-%d %H:%M:%S"), ip))
                    else:
                        print("[%s] Failed to remove access permission for [%s], Reason: %s" % (
                            time.strftime("%Y-%m-%d %H:%M:%S"), ip, r["message"]))
                    continue
                if ip not in netstat:
                    if in_rule_grace(ip):
                        print("[%s] The authorized IP: [%s] is in grace period, its permission will be hold." % (
                            time.strftime("%Y-%m-%d %H:%M:%S"), ip))
                        continue
                    print("[%s] The authorized IP: [%s] is not connected to this server, its permission will be removed." % (
                        time.strftime("%Y-%m-%d %H:%M:%S"), ip))
                    r = firewall.remove_rule(target_ip=ip)
                    if r["success"]:
                        clear_rule_timers(ip)
                        print("[%s] Successfully removed access permission for [%s]" % (
                            time.strftime("%Y-%m-%d %H:%M:%S"), ip))
                    else:
                        print("[%s] Failed to remove access permission for [%s], Reason: %s" % (
                            time.strftime("%Y-%m-%d %H:%M:%S"), ip, r["message"]))
                else:
                    print("[%s] The authorized IP: [%s] is connected to this server, its permission will be hold." % (
                        time.strftime("%Y-%m-%d %H:%M:%S"), ip))
        else:
            print("[%s] Unable to retrieve rule list： %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), rules["message"]))
        time.sleep(OPTIONS["check_interval"])


def build_ssl_context(certfile, keyfile):
    proto = getattr(ssl, "PROTOCOL_TLS_SERVER", None) or getattr(ssl, "PROTOCOL_TLS", ssl.PROTOCOL_SSLv23)
    context = ssl.SSLContext(proto)
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def main():
    if not is_admin():
        print(ascii_logo)
        print("Github: https://github.com/Scorcsoft/monkeyACL")
        if os.name == "nt":
            print("[!] Administrator privileges are required to manage Windows Firewall.")
        else:
            print("[!] Root privileges are required to manage the firewall.")
        return
    args = sys.argv[1:]
    if len(args) == 0:
        help_message()
        return
    tool = Tool()
    opts, pos = tool.parse_args(args)
    if "h" in opts and opts["h"]:
        help_message()
        return
    if "help" in opts:
        help_message()
        return

    if "auth" not in opts:
        print("[!] You must to specify the --auth parameter for API authentication.")
        print('[i] Example: python3 monkeyACL.py --auth="fr#yrQ(7rsM8v)ra"')
        return

    if "port" not in opts:
        print("[!] You must to specify the --port parameter for API HTTP port.")
        print("[i] Example: python3 monkeyACL.py --port=8080")
        return

    if "url" not in opts:
        print("[!] You must to specify the --url parameter for API url.")
        print("[i] Example: python3 monkeyACL.py --url=myapi")
        return

    cert_opt = opts.get("cert")
    key_opt = opts.get("key")
    if bool(cert_opt) != bool(key_opt):
        print("[!] --cert and --key must be provided together.")
        print("[i] Omit both to auto-generate a self-signed certificate.")
        return
    if cert_opt and (not os.path.isfile(cert_opt) or not os.path.isfile(key_opt)):
        print("[!] SSL certificate or private key file does not exist.")
        return

    auth = strip_wrapping_quotes(opts["auth"])
    if not tool.check_password(auth):
        print("[!] %s is not a valid auth key" % auth)
        print("[!] For your server security, The length of the --auth parameter must be greater than 16, and it must contain uppercase letters, lowercase letters and numbers")
        print('[i] Example: python3 monkeyACL.py --auth="fr#yrQ(7rsM8v)ra"')
        print("more information: https://github.com/Scorcsoft/monkeyACL")
        return

    OPTIONS["auth"] = auth
    p = opts["port"]
    try:
        port = int(p)
    except Exception:
        print("[!] --port parameter must be an integer, which serves as the API HTTP port.")
        print("[i] Example: python3 monkeyACL.py --port=8080")
        print("more information: https://github.com/Scorcsoft/monkeyACL")
        return
    if port < 0 or port > 65535:
        print("[!] %s is not a valid port" % p)
        print("[!] You must to specify the --port parameter for API HTTP Port.")
        print("[i] Example: python3 monkeyACL.py --port=8080")
        print("more information: https://github.com/Scorcsoft/monkeyACL")
        return

    OPTIONS["url"] = normalize_api_url(opts["url"])
    if not OPTIONS["url"]:
        print("[!] --url cannot be empty.")
        print("[i] Example: python3 monkeyACL.py --url=myapi")
        return

    if "interval" in opts:
        try:
            interval = int(opts["interval"])
        except Exception:
            print("[!] --interval must be an integer in seconds.")
            print("[i] Example: python3 monkeyACL.py --interval=600")
            return
        if interval < 30:
            print("[!] --interval must be at least 30 seconds.")
            return
        OPTIONS["check_interval"] = interval

    firewall = detect_firewall()
    if firewall is None:
        print("[!] No supported firewall backend was detected.")
        print("[i] Linux: firewalld, ufw, iptables or nftables. Windows: Windows Firewall.")
        return

    try:
        certfile, keyfile, auto_ssl = ensure_ssl_files(cert_opt, key_opt)
        recycle = threading.Thread(target=acl_recycle, args=(firewall,), daemon=True)
        server = MonkeyACLServer(("", port), MonkeyACLHandler, firewall)
        context = build_ssl_context(certfile, keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)

        print(ascii_logo)
        print("Github: https://github.com/Scorcsoft/monkeyACL")
        print("")
        recycle.start()
        print("[i] Firewall backend: %s" % firewall.name)
        print("[i] MonkeyACL is running at: https://0.0.0.0:%s/%s" % (port, opts["url"]))
        print("[i] Idle whitelist recycle interval: %s seconds" % OPTIONS["check_interval"])
        if auto_ssl:
            print("[i] Using a self-signed SSL certificate. Call the API with curl -k.")
        print("[i] If you cannot access the Monkey ACL API service, open the API port:")
        for line in firewall.hint_open_api_port(opts["port"]):
            print(line)

        server.serve_forever()
    except KeyboardInterrupt:
        print("[i] User quit.")
        sys.exit(1)
    except OSError as e:
        in_use = e.errno in (98, 48, 10048) or getattr(e, "winerror", None) == 10048
        if in_use:
            print("[!] 0.0.0.0:%s already in use, please specify other port." % port)
        else:
            print("[!] MonkeyACL startup failed, %s" % e)
        sys.exit(1)
    except Exception as e:
        print("[!] MonkeyACL startup failed, %s" % e)


if __name__ == "__main__":
    main()
