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


__version__ = "1.1.0"

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
    ip = ip.strip("[]")
    if ip.startswith("::ffff:"):
        return ip[7:]
    return ip


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


def _timer_key(ip, port=None, protocol=None):
    if port is None or protocol is None:
        return ip
    return "%s:%s:%s" % (ip, port, str(protocol).lower())


def _clear_timer_stores(ip, port=None, protocol=None):
    if port is None or protocol is None:
        prefix = ip + ":"
        for store in (RULE_GRACE, RULE_TTL):
            for key in list(store.keys()):
                if key == ip or key.startswith(prefix):
                    store.pop(key, None)
        return
    key = _timer_key(ip, port, protocol)
    RULE_GRACE.pop(key, None)
    RULE_TTL.pop(key, None)
    RULE_GRACE.pop(ip, None)
    RULE_TTL.pop(ip, None)


def mark_rule_grace(ip, port=None, protocol=None):
    with RULE_GRACE_LOCK:
        RULE_GRACE[_timer_key(ip, port, protocol)] = time.time() + OPTIONS["grace_seconds"]


def in_rule_grace(ip, port=None, protocol=None):
    now = time.time()
    key = _timer_key(ip, port, protocol)
    with RULE_GRACE_LOCK:
        expire = RULE_GRACE.get(key)
        if expire is None and key != ip:
            expire = RULE_GRACE.get(ip)
        if expire is None:
            return False
        if now < expire:
            return True
        RULE_GRACE.pop(key, None)
        if key != ip:
            RULE_GRACE.pop(ip, None)
        return False


RULE_TTL = {}
CREATED_RULES = {}


def mark_rule_ttl(ip, ttl_seconds, port=None, protocol=None):
    key = _timer_key(ip, port, protocol)
    if not ttl_seconds:
        with RULE_GRACE_LOCK:
            RULE_TTL.pop(key, None)
            if key != ip:
                RULE_TTL.pop(ip, None)
        return
    with RULE_GRACE_LOCK:
        RULE_TTL[key] = time.time() + ttl_seconds


def rule_ttl_expired(ip, port=None, protocol=None):
    now = time.time()
    key = _timer_key(ip, port, protocol)
    with RULE_GRACE_LOCK:
        expire = RULE_TTL.get(key)
        if expire is None and key != ip:
            expire = RULE_TTL.get(ip)
        if expire is None:
            return False
        if now < expire:
            return False
        _clear_timer_stores(ip, port, protocol)
        return True


def clear_rule_timers(ip, port=None, protocol=None):
    with RULE_GRACE_LOCK:
        _clear_timer_stores(ip, port, protocol)


def _looks_like_utf16_le(data):
    if not data or len(data) < 8 or len(data) % 2:
        return False
    sample = data[:400]
    return sample.count(0) >= max(8, len(sample) // 4)


def _decode_output(data):
    if not data:
        return ""
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    if _looks_like_utf16_le(data):
        try:
            return data.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    encodings = []
    if os.name == "nt":
        encodings.extend(["mbcs", "oem", "gbk", "cp936", "utf-8"])
    else:
        encodings.extend(["utf-8"])
    encodings.append("latin-1")
    seen = set()
    for enc in encodings:
        if not enc or enc in seen:
            continue
        seen.add(enc)
        try:
            return data.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


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
    stdout = _decode_output(result.stdout)
    stderr = _decode_output(result.stderr)
    return result.returncode, stdout, stderr


def which(name):
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt" and not str(name).lower().endswith(".exe"):
        return shutil.which(name + ".exe")
    return None


def _powershell_exe():
    return which("powershell") or which("powershell.exe") or which("pwsh")


def _run_powershell(script, timeout=60):
    ps = _powershell_exe()
    if not ps:
        return 127, "", "powershell not found"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return run_cmd([ps, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], timeout=timeout)


def _windows_cmd_ok(code, out, err):
    text = "%s\n%s" % (out or "", err or "")
    compact = text.replace("\x00", "")
    lower = compact.lower()
    if "no rules match" in lower or "没有与指定" in compact or "找不到指定" in compact:
        return False
    if "ok." in lower or "ok" == lower.strip() or "确定" in compact or "已删除" in compact or "deleted" in lower:
        return True
    return code == 0


def remember_created_rule(ip, port, protocol):
    entry = _authorized_entry(ip, port, protocol)
    if not entry:
        return
    key = (entry["ip"], entry["port"], entry["protocol"])
    with RULE_GRACE_LOCK:
        CREATED_RULES[key] = entry


def forget_created_rule(ip, port=None, protocol=None):
    with RULE_GRACE_LOCK:
        if port is None or protocol is None:
            for key in list(CREATED_RULES.keys()):
                if key[0] == ip:
                    CREATED_RULES.pop(key, None)
            return
        try:
            port_val = int(port)
        except (TypeError, ValueError):
            return
        CREATED_RULES.pop((ip, port_val, str(protocol).lower()), None)


def created_rule_entries(ip=None):
    with RULE_GRACE_LOCK:
        entries = list(CREATED_RULES.values())
    if ip is None:
        return entries
    return [entry for entry in entries if entry["ip"] == ip]


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


def _parse_endpoint(endpoint):
    if not endpoint:
        return None, None
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        if "]:" in endpoint:
            ip, port = endpoint.rsplit("]:", 1)
            ip = normalize_ip(ip + "]")
            return ip, port
        return normalize_ip(endpoint), None
    if endpoint.count(":") == 1:
        ip, port = endpoint.rsplit(":", 1)
        return normalize_ip(ip), port
    if endpoint.count(":") > 1:
        ip = normalize_ip(endpoint.rsplit(":", 1)[0])
        port = endpoint.rsplit(":", 1)[1]
        return ip, port
    return normalize_ip(endpoint), None


def _peer_from_endpoint(peer):
    ip, _ = _parse_endpoint(peer)
    if ip and ip not in ("0.0.0.0", "*", "::", "127.0.0.1", "::1"):
        return ip
    return None


def _local_port_from_endpoint(endpoint):
    _, port = _parse_endpoint(endpoint)
    if not port:
        return None
    port = port.split("%", 1)[0]
    if port.isdigit():
        return int(port)
    return None


def _netstat_line_established(line):
    upper = line.upper()
    return "ESTABLISHED" in upper or "ESTAB" in upper or "已建立" in line


def _endpoint_tokens(parts):
    tokens = []
    for token in parts:
        if ":" not in token:
            continue
        ip, port = _parse_endpoint(token)
        if ip and port is not None:
            tokens.append(token)
    return tokens


def _collect_netstat_connections(out, proto, local_idx=None, remote_idx=None):
    connections = set()
    for line in out.splitlines():
        if not _netstat_line_established(line):
            continue
        parts = line.split()
        local_token = None
        remote_token = None
        if local_idx is not None and remote_idx is not None and len(parts) > max(local_idx, remote_idx):
            local_token = parts[local_idx]
            remote_token = parts[remote_idx]
        else:
            endpoints = _endpoint_tokens(parts)
            if len(endpoints) >= 2:
                local_token, remote_token = endpoints[0], endpoints[1]
        if not local_token or not remote_token:
            continue
        remote_ip = _peer_from_endpoint(remote_token)
        local_port = _local_port_from_endpoint(local_token)
        if remote_ip and local_port is not None:
            connections.add((remote_ip, local_port, proto))
            connections.add(remote_ip)
    return connections


def get_connected_ips():
    connections = set()

    if os.name == "nt":
        for proto, flag in (("tcp", "TCP"), ("udp", "UDP")):
            code, out, _ = run_cmd(["netstat", "-ano", "-p", flag])
            if code != 0:
                continue
            connections.update(_collect_netstat_connections(out, proto))
        return connections

    if which("ss"):
        code, out, _ = run_cmd(["ss", "-antupH"])
        if code != 0:
            code, out, _ = run_cmd(["ss", "-antup"])
        if code == 0:
            for line in out.splitlines():
                if not _netstat_line_established(line):
                    continue
                parts = line.split()
                if not parts:
                    continue
                proto = None
                first = parts[0].lower()
                if first.startswith("tcp"):
                    proto = "tcp"
                elif first.startswith("udp"):
                    proto = "udp"
                addrs = []
                for token in parts:
                    if token.lower().startswith("users:"):
                        continue
                    if ":" not in token:
                        continue
                    addrs.append(token)
                if len(addrs) < 2:
                    continue
                if proto is None:
                    proto = "tcp"
                remote_ip = _peer_from_endpoint(addrs[1])
                local_port = _local_port_from_endpoint(addrs[0])
                if remote_ip and local_port is not None:
                    connections.add((remote_ip, local_port, proto))
                    connections.add(remote_ip)
            if connections:
                return connections

    if which("netstat"):
        code, out, _ = run_cmd(["netstat", "-anu"])
        tcp_code, tcp_out, _ = run_cmd(["netstat", "-ant"])
        if tcp_code == 0:
            connections.update(_collect_netstat_connections(tcp_out, "tcp", 3, 4))
        if code == 0:
            connections.update(_collect_netstat_connections(out, "udp", 3, 4))
    return connections


def connection_active(netstat, ip, port=None, protocol=None):
    if port is None or protocol is None:
        if ip in netstat:
            return True
        for item in netstat:
            if isinstance(item, tuple) and item and item[0] == ip:
                return True
        return False
    proto = str(protocol).lower()
    try:
        port = int(port)
    except (TypeError, ValueError):
        return ip in netstat
    return (ip, port, proto) in netstat


def _authorized_entry(ip, port, protocol):
    if not ip or port is None or protocol is None:
        return None
    try:
        port_val = int(port)
    except (TypeError, ValueError):
        return None
    proto = str(protocol).lower()
    if proto not in ("tcp", "udp"):
        return None
    return {"ip": ip, "port": port_val, "protocol": proto}


def _rule_matches_target(entry_ip, entry_port, entry_protocol, target_ip, port=None, protocol=None):
    if entry_ip != target_ip:
        return False
    if port is None:
        return True
    if entry_port is None or int(entry_port) != int(port):
        return False
    if protocol is None:
        return True
    return str(entry_protocol or "").lower() == str(protocol).lower()


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


def _app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def ensure_ssl_files(cert_path, key_path):
    if cert_path and key_path and os.path.isfile(cert_path) and os.path.isfile(key_path):
        return cert_path, key_path, False

    base_dir = _app_dir()
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

    def _list_rich_rules(self, zone="public"):
        code, out, err = run_cmd(["firewall-cmd", "--zone", zone, "--list-rich-rules"])
        if code != 0:
            raise RuntimeError(err or out)
        return out.strip().splitlines()

    def _parse_rich_rule(self, rule):
        ip_match = re.search(r'source address="([^"]+)"', rule)
        port_match = re.search(r'port port="([^"]+)" protocol="([^"]+)"', rule)
        if not ip_match or not port_match:
            return None
        return _authorized_entry(ip_match.group(1), port_match.group(1), port_match.group(2))

    def remove_rule(self, target_ip, zone="public", port=None, protocol=None):
        try:
            rules = self._list_rich_rules(zone)
            removed = False
            for rule in rules:
                if RULE_TAG not in rule:
                    continue
                parsed = self._parse_rich_rule(rule)
                if not parsed:
                    continue
                if not _rule_matches_target(parsed["ip"], parsed["port"], parsed["protocol"], target_ip, port, protocol):
                    continue
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
            data = []
            for rule in self._list_rich_rules(zone):
                if RULE_TAG not in rule:
                    continue
                parsed = self._parse_rich_rule(rule)
                if parsed:
                    data.append(parsed)
            return {"success": True, "data": data}
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

    def _parse_ufw_line(self, line):
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        if not ip_match:
            return None
        port_match = re.search(r"(\d+)\s*/\s*(tcp|udp)", line, re.IGNORECASE)
        if not port_match:
            port_match = re.search(r"(tcp|udp)\s+(\d+)", line, re.IGNORECASE)
            if port_match:
                return _authorized_entry(ip_match.group(1), port_match.group(2), port_match.group(1))
            return None
        return _authorized_entry(ip_match.group(1), port_match.group(1), port_match.group(2))

    def remove_rule(self, target_ip, port=None, protocol=None):
        try:
            code, out, err = run_cmd(["ufw", "status", "numbered"])
            if code != 0:
                return {"success": False, "exception": True, "message": err or out}
            numbers = []
            for line in out.splitlines():
                if RULE_TAG not in line:
                    continue
                parsed = self._parse_ufw_line(line)
                if not parsed:
                    continue
                if not _rule_matches_target(parsed["ip"], parsed["port"], parsed["protocol"], target_ip, port, protocol):
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
            data = []
            for line in out.splitlines():
                if RULE_TAG not in line:
                    continue
                parsed = self._parse_ufw_line(line)
                if parsed:
                    data.append(parsed)
            return {"success": True, "data": data}
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

    def _parse_iptables_line(self, line):
        ip_match = re.search(r"-s\s+([0-9.]+)(?:/32)?", line)
        port_match = re.search(r"--dport(?:\s+|=)(\d+)", line)
        proto_match = re.search(r"-p\s*([a-zA-Z0-9]+)", line)
        if not ip_match or not port_match or not proto_match:
            return None
        return _authorized_entry(ip_match.group(1), port_match.group(1), proto_match.group(1))

    def remove_rule(self, target_ip, port=None, protocol=None):
        try:
            removed = False
            for line in self._list_rules():
                if RULE_TAG not in line:
                    continue
                parsed = self._parse_iptables_line(line)
                if not parsed:
                    continue
                if not _rule_matches_target(parsed["ip"], parsed["port"], parsed["protocol"], target_ip, port, protocol):
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
            data = []
            for line in self._list_rules():
                if RULE_TAG not in line:
                    continue
                parsed = self._parse_iptables_line(line)
                if parsed:
                    data.append(parsed)
            return {"success": True, "data": data}
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

    def _parse_nft_line(self, line):
        ip_match = re.search(r"saddr\s+([0-9.]+)", line)
        port_match = re.search(r"(tcp|udp)\s+dport\s+(\d+)", line, re.IGNORECASE)
        if not ip_match or not port_match:
            return None
        return _authorized_entry(ip_match.group(1), port_match.group(2), port_match.group(1))

    def remove_rule(self, target_ip, port=None, protocol=None):
        try:
            text = self._list_json_or_text()
            handles = []
            for line in text.splitlines():
                if RULE_TAG not in line:
                    continue
                parsed = self._parse_nft_line(line)
                if not parsed:
                    continue
                if not _rule_matches_target(parsed["ip"], parsed["port"], parsed["protocol"], target_ip, port, protocol):
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
            data = []
            for line in text.splitlines():
                if RULE_TAG not in line:
                    continue
                parsed = self._parse_nft_line(line)
                if parsed:
                    data.append(parsed)
            return {"success": True, "data": data}
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
            self._delete_rule_name(name)
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
            if not _windows_cmd_ok(code, out, err):
                if not self._add_rule_powershell(name, ip, port, proto):
                    return {"success": False, "exception": True, "message": "Create firewall rule failed: %s" % (err or out)}
            remember_created_rule(ip, port, protocol)
            return {"success": True, "message": "Create firewall rule success: %s --[%s]--> %s" % (ip, protocol, port)}
        except Exception:
            return {"success": False, "exception": True, "message": "Create firewall rule failed: %s" % traceback.format_exc()}

    def _add_rule_powershell(self, name, ip, port, proto):
        script = (
            "$params = @{"
            "DisplayName='%s'; Direction='Inbound'; Action='Allow'; "
            "Protocol='%s'; LocalPort=%s; RemoteAddress='%s'; Profile='Any'; Enabled='True'"
            "}; New-NetFirewallRule @params -ErrorAction Stop | Out-Null; 'OK'"
            % (name.replace("'", "''"), proto, int(port), ip)
        )
        code, out, err = _run_powershell(script)
        return _windows_cmd_ok(code, out, err) or "OK" in (out or "")

    def _parse_rule_name(self, name):
        prefix = RULE_TAG + "-"
        if not name.startswith(prefix):
            return None
        rest = name[len(prefix):]
        parts = rest.rsplit("-", 2)
        if len(parts) != 3:
            return None
        return _authorized_entry(parts[0], parts[1], parts[2])

    def _is_rule_name_line(self, line):
        compact = line.lower().replace("：", ":").replace(" ", "")
        return compact.startswith("rulename:") or compact.startswith("规则名称:")

    def _iter_rule_names_powershell(self):
        script = (
            "Get-NetFirewallRule -DisplayName '%s-*' -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.DisplayName }"
            % RULE_TAG
        )
        code, out, _ = _run_powershell(script)
        if code != 0:
            return []
        names = []
        for line in out.splitlines():
            name = line.strip().lstrip("\ufeff")
            if name.startswith(RULE_TAG + "-"):
                names.append(name)
        return names

    def _iter_rule_names_netsh(self):
        code, out, err = run_cmd(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in"],
            timeout=120
        )
        if code != 0:
            code, out, err = run_cmd(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                timeout=120
            )
            if code != 0:
                raise RuntimeError(err or out)
        names = []
        seen = set()
        pattern = re.compile(r"(%s-\d+\.\d+\.\d+\.\d+-\d+-(?:tcp|udp))" % re.escape(RULE_TAG), re.IGNORECASE)
        for raw in out.splitlines():
            stripped = raw.strip().lstrip("\ufeff")
            if not stripped:
                continue
            name = None
            match = pattern.search(stripped)
            if match:
                name = match.group(1)
            elif self._is_rule_name_line(stripped):
                name = stripped.replace("：", ":").split(":", 1)[1].strip()
            elif stripped.startswith(RULE_TAG + "-"):
                name = stripped
            if name and name.startswith(RULE_TAG) and name not in seen:
                seen.add(name)
                names.append(name)
        return names

    def _iter_rule_names(self):
        names = self._iter_rule_names_powershell()
        if names:
            return names
        return self._iter_rule_names_netsh()

    def _delete_rule_name(self, name):
        if not name:
            return False
        quoted = "name=%s" % name
        quoted_wrap = 'name="%s"' % name
        attempts = [
            ["netsh", "advfirewall", "firewall", "delete", "rule", quoted_wrap, "dir=in"],
            ["netsh", "advfirewall", "firewall", "delete", "rule", quoted, "dir=in"],
            ["netsh", "advfirewall", "firewall", "delete", "rule", quoted_wrap],
            ["netsh", "advfirewall", "firewall", "delete", "rule", quoted],
        ]
        for cmd in attempts:
            code, out, err = run_cmd(cmd)
            if _windows_cmd_ok(code, out, err):
                return True
        escaped = name.replace("'", "''")
        script = (
            "$n = '%s'; "
            "try { Remove-NetFirewallRule -DisplayName $n -ErrorAction Stop; 'OK'; return } catch {}; "
            "try { Remove-NetFirewallRule -Name $n -ErrorAction Stop; 'OK'; return } catch {}; "
            "'FAIL'"
            % escaped
        )
        ps_code, ps_out, ps_err = _run_powershell(script)
        return _windows_cmd_ok(ps_code, ps_out, ps_err) or "OK" in (ps_out or "")

    def _candidate_rule_names(self, target_ip, port=None, protocol=None):
        names = []
        seen = set()

        def add_name(name):
            if name and name not in seen:
                seen.add(name)
                names.append(name)

        if port is not None and protocol is not None:
            add_name(self._rule_name(target_ip, port, protocol))
        for entry in created_rule_entries(target_ip):
            if _rule_matches_target(entry["ip"], entry["port"], entry["protocol"], target_ip, port, protocol):
                add_name(self._rule_name(entry["ip"], entry["port"], entry["protocol"]))
        try:
            listed = self._iter_rule_names()
        except Exception:
            listed = []
        for name in listed:
            parsed = self._parse_rule_name(name)
            if not parsed:
                continue
            if _rule_matches_target(parsed["ip"], parsed["port"], parsed["protocol"], target_ip, port, protocol):
                add_name(name)
        return names

    def remove_rule(self, target_ip, port=None, protocol=None):
        try:
            removed = False
            names = self._candidate_rule_names(target_ip, port, protocol)
            for name in names:
                if self._delete_rule_name(name):
                    removed = True
                    parsed = self._parse_rule_name(name)
                    if parsed:
                        forget_created_rule(parsed["ip"], parsed["port"], parsed["protocol"])
            if not removed and port is None:
                forget_created_rule(target_ip)
            elif removed:
                if port is None:
                    forget_created_rule(target_ip)
                else:
                    forget_created_rule(target_ip, port, protocol)
            if removed:
                return {"success": True, "message": "Remove firewall rule success"}
            if names:
                return {"success": False, "exception": True, "message": "Delete firewall rule failed"}
            return {"success": False, "exception": False, "message": "Non-existent rules"}
        except Exception:
            return {"success": False, "exception": True, "message": traceback.format_exc()}

    def get_authorized_ips(self):
        data = []
        seen = set()
        try:
            names = self._iter_rule_names()
        except Exception:
            names = []
        for name in names:
            parsed = self._parse_rule_name(name)
            if not parsed:
                continue
            key = (parsed["ip"], parsed["port"], parsed["protocol"])
            if key in seen:
                continue
            seen.add(key)
            data.append(parsed)
        for entry in created_rule_entries():
            key = (entry["ip"], entry["port"], entry["protocol"])
            if key in seen:
                continue
            seen.add(key)
            data.append(entry)
        if data:
            return {"success": True, "data": data}
        fallback = _entries_from_timers()
        if fallback:
            return {"success": True, "data": fallback}
        if names == []:
            return {"success": True, "data": []}
        return {"success": True, "data": data}

    def rule_exists(self, ip, port, protocol="tcp"):
        name = self._rule_name(ip, port, protocol)
        for entry in created_rule_entries(ip):
            if entry["port"] == int(port) and entry["protocol"] == str(protocol).lower():
                return True
        try:
            for existing in self._iter_rule_names():
                if existing == name:
                    return True
        except Exception:
            return False
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
            del_port = None
            del_proto = None
            if "port" in json_data and json_data["port"] not in (None, ""):
                try:
                    del_port = int(json_data["port"])
                except Exception:
                    self._write_json({"success": False, "message": "%s is not a valid port" % json_data["port"]})
                    return
                if del_port < 0 or del_port > 65535:
                    self._write_json({"success": False, "message": "%s is not a valid port" % json_data["port"]})
                    return
            if "protocol" in json_data and json_data["protocol"] not in (None, ""):
                del_proto = str(json_data["protocol"]).lower()
                if del_proto not in ("tcp", "udp"):
                    self._write_json({"success": False, "message": "%s is not a valid protocol" % json_data["protocol"]})
                    return
            res = self.server.firewall.remove_rule(target_ip=ip, port=del_port, protocol=del_proto)
            if res.get("success"):
                clear_rule_timers(ip, del_port, del_proto)
                forget_created_rule(ip, del_port, del_proto)
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
            remember_created_rule(ip, port, protocol)
            mark_rule_grace(ip, port, protocol)
            mark_rule_ttl(ip, ttl, port, protocol)
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
    print("Version: %s" % __version__)
    print("")
    print("Options:")
    print("    -h,--help: \t Show this help message and exit")
    print("    --version: \t Show version and exit")
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


def _rule_log_target(entry):
    return "%s --[%s]--> %s" % (entry["ip"], entry["protocol"], entry["port"])


def _entries_from_timers():
    entries = []
    with RULE_GRACE_LOCK:
        keys = list(RULE_GRACE.keys()) + list(RULE_TTL.keys())
    for key in keys:
        parts = str(key).split(":")
        if len(parts) != 3:
            continue
        entry = _authorized_entry(parts[0], parts[1], parts[2])
        if entry:
            entries.append(entry)
    return entries


def acl_recycle(firewall):
    print("[i] Automatically detect network connections and clean up unused rules.")
    while 1:
        netstat = firewall.get_netstat()
        rules = firewall.get_authorized_ips()
        if rules["success"]:
            seen = set()
            for entry in list(rules["data"]) + _entries_from_timers():
                ip = entry["ip"]
                port = entry["port"]
                protocol = entry["protocol"]
                key = (ip, port, protocol)
                if key in seen:
                    continue
                seen.add(key)
                target = _rule_log_target(entry)
                if rule_ttl_expired(ip, port, protocol):
                    print("[%s] The authorized rule: [%s] reached ttl, its permission will be removed." % (
                        time.strftime("%Y-%m-%d %H:%M:%S"), target))
                    r = firewall.remove_rule(target_ip=ip, port=port, protocol=protocol)
                    if r["success"]:
                        clear_rule_timers(ip, port, protocol)
                        forget_created_rule(ip, port, protocol)
                        print("[%s] Successfully removed access permission for [%s]" % (
                            time.strftime("%Y-%m-%d %H:%M:%S"), target))
                    else:
                        print("[%s] Failed to remove access permission for [%s], Reason: %s" % (
                            time.strftime("%Y-%m-%d %H:%M:%S"), target, r["message"]))
                    continue
                if not connection_active(netstat, ip, port, protocol):
                    if in_rule_grace(ip, port, protocol):
                        print("[%s] The authorized rule: [%s] is in grace period, its permission will be hold." % (
                            time.strftime("%Y-%m-%d %H:%M:%S"), target))
                        continue
                    print("[%s] The authorized rule: [%s] is not connected to this server, its permission will be removed." % (
                        time.strftime("%Y-%m-%d %H:%M:%S"), target))
                    r = firewall.remove_rule(target_ip=ip, port=port, protocol=protocol)
                    if r["success"]:
                        clear_rule_timers(ip, port, protocol)
                        forget_created_rule(ip, port, protocol)
                        print("[%s] Successfully removed access permission for [%s]" % (
                            time.strftime("%Y-%m-%d %H:%M:%S"), target))
                    else:
                        print("[%s] Failed to remove access permission for [%s], Reason: %s" % (
                            time.strftime("%Y-%m-%d %H:%M:%S"), target, r["message"]))
                else:
                    print("[%s] The authorized rule: [%s] is connected to this server, its permission will be hold." % (
                        time.strftime("%Y-%m-%d %H:%M:%S"), target))
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
    args = sys.argv[1:]
    tool = Tool()
    opts, pos = tool.parse_args(args)
    if len(args) == 0 or opts.get("h") or opts.get("help"):
        help_message()
        return
    if opts.get("version"):
        print("MonkeyACL %s" % __version__)
        return
    if not is_admin():
        print(ascii_logo)
        print("Github: https://github.com/Scorcsoft/monkeyACL")
        print("Version: %s" % __version__)
        if os.name == "nt":
            print("[!] Administrator privileges are required to manage Windows Firewall.")
        else:
            print("[!] Root privileges are required to manage the firewall.")
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
        print("Version: %s" % __version__)
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
