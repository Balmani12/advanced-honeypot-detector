#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ad_honeypot_dtect_complete.py (UPDATED)
Full Advanced Honeypot Detector with extended signatures and full pipeline.

Changes in this update:
 - Malformed/extra SSH identification handling and heuristic for it
 - Host-key check via ssh-keyscan (with ssh-keygen parsing) and fallback to paramiko
 - Loopback RTT heuristic (flags abnormally high RTT on 127.0.0.1/::1)
 - Banner vs behavior mismatch heuristic scaffold (hostkey vs banner)
 - Human-readable reasons appended to heuristic_scores
 - Minimal, conservative changes only; rest of file left intact
"""
from __future__ import annotations
import argparse
import os
import sys
import socket
import ssl
import json
import time
import datetime
import tempfile
import hashlib
import threading
import random
import re
import subprocess
import logging
import uuid
from typing import List, Dict, Any, Optional, Tuple

# Optional libs
try:
    import requests
except Exception:
    requests = None

try:
    from scapy.all import sniff, wrpcap
except Exception:
    sniff = None
    wrpcap = None

try:
    import paramiko
except Exception:
    paramiko = None

# ---------------- Directories & Constants ----------------
LOG_DIR = "logs"
REPORTS_DIR = "reports"
EVIDENCE_DIR = "evidence"
CACHE_DIR = "cache"
DEFAULT_RULES = "rules.json"
DEFAULT_SIGS = "signatures.json"
CONFIG_FILE = "config.json"
DEFAULT_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,3389]

for d in (LOG_DIR, REPORTS_DIR, EVIDENCE_DIR, CACHE_DIR):
    os.makedirs(d, exist_ok=True)

# ---------------- Logging ----------------
logger = logging.getLogger("honeypotdtect")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(os.path.join(LOG_DIR, "scan.log"))
fh.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
fh.setFormatter(fmt)
ch.setFormatter(fmt)
logger.addHandler(fh)
logger.addHandler(ch)

def set_verbosity(level_str: str, quiet: bool=False):
    level = getattr(logging, level_str.upper(), logging.INFO)
    if quiet:
        ch.setLevel(logging.ERROR)
    else:
        ch.setLevel(level)
    fh.setLevel(level)
    logger.setLevel(level)

# ---------------- Utilities ----------------
def now_iso():
    # timezone-aware recommended but simple UTC ISO for compatibility
    return datetime.datetime.utcnow().isoformat() + 'Z'

def save_json_atomic(path: str, data: Any):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception as e:
        logger.exception("Failed atomic save: %s", e)
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass
        raise

def load_json(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        logger.exception("Failed to load JSON: %s", path)
        return None

def env_bool(name: str, default: bool=False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).lower() in ('1','true','yes','y','on')

def file_cache_get(key: str) -> Optional[Any]:
    fn = os.path.join(CACHE_DIR, hashlib.sha1(key.encode()).hexdigest() + ".json")
    return load_json(fn)

def file_cache_set(key: str, obj: Any):
    fn = os.path.join(CACHE_DIR, hashlib.sha1(key.encode()).hexdigest() + ".json")
    try:
        save_json_atomic(fn, obj)
    except Exception:
        logger.exception("Failed to set cache for %s", key)

# ---------------- Signature DB (defaults) ----------------
SIG_DB_DEFAULT = {
    # SSH Honeypots
    "cowrie": ["Cowrie SSH Honeypot", "cowrie"],
    "kippo": ["Kippo", "SSH-2.0-Kippo", "Kippo"],
    "heralding": ["Heralding", "SSH-2.0-Heralding"],

    # HTTP/Web Honeypots
    "glastopf": ["Glastopf", "glastopf"],
    "wordpot": ["Wordpot", "wp-content/plugins/fakeplugin", "WordPress honeypot"],
    "elastichoney": ["Elastichoney", "X-elastichoney"],

    # FTP Honeypots
    "amun": ["Amun FTP Honeypot", "220 Amun FTP", "Amun"],
    "honeypot-ftp": ["FTP Honeypot", "FakeFTP"],

    # SMB Honeypots
    "smbtrap": ["SMBTrap", "SMB honeypot", "SMBTrap"],
    "smb-honey": ["SMB Honeypot", "Windows for Workgroups 3.1a"],

    # SMTP Honeypots
    "mailoney": ["Mailoney", "220 mailoney", "MAILONEY"],
    "fake-smtp": ["FakeSMTP", "ESMTP Postfix Honeypot"],

    # ICS/SCADA Honeypots
    "conpot": ["Conpot", "conpot", "Server: Conpot"],
    "gridpot": ["Gridpot", "gridpot"],

    # Database Honeypots
    "mysql-honey": ["MySQL Honeypot", "mysql_native_password", "MySQL Proxy"],
    "mssql-honey": ["MSSQL Honeypot", "MSSQLServerFake", "MSSQL"],
    "redis-honey": ["Redis Honeypot", "redis_version:999.fake"],

    # RDP Honeypots
    "rdp-honey": ["RDP Honeypot", "MS_T120", "RDP-FAKE"],

    # Generic low interaction
    "honeyd": ["Honeyd", "honeyd"],
    "dionaea": ["dionaea", "Dionaea"],
    "snare": ["Snare", "Snare honeypot"],
}

def load_signatures(sig_file: str = DEFAULT_SIGS) -> Dict[str, List[str]]:
    cfg = load_json(sig_file)
    if cfg and isinstance(cfg, dict):
        logger.info("Loaded signatures from %s (%d families)", sig_file, len(cfg))
        return cfg
    logger.debug("Using built-in signature DB")
    return SIG_DB_DEFAULT.copy()

# ---------------- Input Handler ----------------
class InputHandler:
    def __init__(self, raw_target: Optional[str]):
        self.raw = raw_target
        self.target = None
        self.resolved_ips: List[str] = []
        self.type = None
        if raw_target:
            self.normalize()

    def normalize(self):
        t = self.raw.strip()
        if t.startswith('http://') or t.startswith('https://'):
            t = t.split('://', 1)[1].split('/',1)[0]
        if ':' in t and not t.count(':') > 1:
            host, port = t.split(':', 1)
            t = host
        self.target = t
        try:
            socket.inet_aton(t)
            self.type = 'ip'
            self.resolved_ips = [t]
        except Exception:
            self.type = 'domain'
            try:
                ips = socket.getaddrinfo(t, None)
                self.resolved_ips = list({i[4][0] for i in ips})
            except Exception:
                self.resolved_ips = []

    def get_ips(self) -> List[str]:
        return self.resolved_ips

# ---------------- Scanner ----------------
class Scanner:
    def __init__(self, targets: List[str], ports: List[int]=None, workers: int=100, timeout: float=1.0, stealth: bool=False):
        self.targets = targets
        self.ports = ports or DEFAULT_PORTS
        self.timeout = timeout
        self.workers = workers if not stealth else max(2, min(workers, 8))
        self.stealth = stealth
        self.results: Dict[str, Dict[int, Dict[str, Any]]] = {}

    def scan_port(self, ip: str, port: int) -> Tuple[int, Dict[str, Any]]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        to = self.timeout + (random.uniform(0, 1.5) if self.stealth else 0)
        sock.settimeout(to)
        start = time.time()
        try:
            if self.stealth:
                time.sleep(random.uniform(0.2, 0.8))
            r = sock.connect_ex((ip, port))
            duration = time.time() - start
            if r == 0:
                banner = None
                try:
                    sock.send(b"\r\n")
                except Exception:
                    pass
                try:
                    sock.settimeout(0.5 + (0.5 if self.stealth else 0))
                    banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
                return port, {"open": True, "banner": banner, "rtt": duration}
            else:
                return port, {"open": False, "rtt": duration}
        except Exception as e:
            return port, {"open": False, "error": str(e)}
        finally:
            sock.close()

    def run(self):
        import concurrent.futures
        for ip in self.targets:
            self.results[ip] = {}
        targets_ports = []
        for ip in self.targets:
            plist = list(self.ports)
            if self.stealth:
                random.shuffle(plist)
            for p in plist:
                targets_ports.append((ip, p))
        if self.stealth:
            random.shuffle(targets_ports)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as exe:
            futures = {exe.submit(self.scan_port, ip, p): (ip, p) for ip,p in targets_ports}
            for fut in concurrent.futures.as_completed(futures):
                ip, p = futures[fut]
                try:
                    port, res = fut.result()
                except Exception as e:
                    port, res = p, {"open": False, "error": str(e)}
                self.results.setdefault(ip, {})[port] = res
                if self.stealth:
                    time.sleep(random.uniform(0.01, 0.12))
        return self.results

# ---------------- Fingerprinter ----------------
class Fingerprinter:
    def __init__(self, sig_file: str = DEFAULT_SIGS):
        self.sig_db = load_signatures(sig_file)

    def match_signatures(self, text: Optional[str]) -> List[str]:
        found = []
        if not text:
            return found
        b = text.lower()
        for name, sigs in self.sig_db.items():
            if not isinstance(sigs, list):
                continue
            for sg in sigs:
                try:
                    if sg and sg.lower() in b:
                        found.append(name)
                        break
                except Exception:
                    continue
        return found

    def http_fingerprint(self, host: str, port: int = 80, stealth: bool=False) -> Dict[str, Any]:
        r = {"server": None, "status": None, "body_preview": None, "matches": []}
        try:
            if stealth:
                req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (compatible; Bot/0.1)\r\nConnection: close\r\n\r\n"
            else:
                req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            conn = socket.create_connection((host, port), timeout=5 + (2 if stealth else 0))
            conn.send(req.encode())
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            s = data.decode('utf-8', errors='ignore')
            headers, _, body = s.partition('\r\n\r\n')
            for line in headers.split('\r\n'):
                if line.lower().startswith('server:'):
                    r['server'] = line.split(':',1)[1].strip()
            r['status'] = headers.split('\r\n')[0] if headers else None
            r['body_preview'] = body[:512]
            r['matches'] = self.match_signatures(s + (r['server'] or "") + (r['body_preview'] or ""))
        except Exception as e:
            r['error'] = str(e)
        return r

    def cert_fingerprint(self, host: str, port: int = 443) -> Optional[str]:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(3)
                s.connect((host, port))
                der = s.getpeercert(True)
                h = hashlib.sha256(der).hexdigest()
                return h
        except Exception:
            return None

    def tls_fingerprint(self, host: str, port: int = 443) -> Dict[str, Any]:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(3)
                s.connect((host, port))
                cert = s.getpeercert()
                der = s.getpeercert(True)
                pem = ssl.DER_cert_to_PEM_cert(der)
                search_text = json.dumps(cert) + pem
                return {
                    "subject": cert.get('subject'),
                    "issuer": cert.get('issuer'),
                    "notBefore": cert.get('notBefore'),
                    "notAfter": cert.get('notAfter'),
                    "cert_fingerprint_sha256": hashlib.sha256(der).hexdigest(),
                    "matches": self.match_signatures(search_text),
                }
        except Exception as e:
            return {"error": str(e)}

    def hostkey_info(self, host: str, port: int = 22, timeout: int = 4) -> Dict[str, Any]:
        """
        Try to fetch host key using ssh-keyscan + ssh-keygen -lf for bit size.
        Fallback to paramiko if available. Return dict:
          {"ok": True/False, "raw": "<keyline>", "algo": "ssh-rsa", "bits": 2048, "error": "..."}
        """
        out = {"ok": False, "raw": None, "algo": None, "bits": None, "error": None}
        # Try cached result
        cachek = f"hostkey:{host}:{port}"
        cached = file_cache_get(cachek)
        if cached:
            return cached

        # Attempt ssh-keyscan
        try:
            # ssh-keyscan may not exist; call with timeout
            p = subprocess.run(["ssh-keyscan", "-p", str(port), "-T", str(timeout), host],
                               capture_output=True, text=True, timeout=timeout+1)
            ks = p.stdout.strip()
            if ks:
                # ks may contain multiple lines; pick first non-empty
                for line in ks.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # line like: "hostname algo base64..."
                    parts = line.split()
                    if len(parts) >= 3:
                        algo = parts[1]
                        rawfn = None
                        try:
                            fd, rawfn = tempfile.mkstemp(prefix="hk_", suffix=".pub", text=True)
                            os.write(fd, (line + "\n").encode())
                            os.close(fd)
                            # try ssh-keygen to get bit-length/ fingerprint
                            q = subprocess.run(["ssh-keygen", "-lf", rawfn], capture_output=True, text=True, timeout=3)
                            outline = q.stdout.strip()
                            # typical output: "2048 SHA256:... hostname (RSA)"
                            m = re.search(r'(\d+)\s+([A-Za-z0-9+/=:.]+)\s+.*\((\w+)\)', outline)
                            bits = None
                            if m:
                                try:
                                    bits = int(m.group(1))
                                except Exception:
                                    bits = None
                            if bits is None:
                                # fallback parse leading number
                                mm = re.search(r'^(\d+)\s', outline)
                                if mm:
                                    try:
                                        bits = int(mm.group(1))
                                    except Exception:
                                        bits = None
                            out.update({"ok": True, "raw": line, "algo": algo, "bits": bits})
                            break
                        except Exception as e:
                            # if ssh-keygen missing or error, still return algo
                            out.update({"ok": True, "raw": line, "algo": algo, "bits": None})
                            break
                        finally:
                            try:
                                if rawfn and os.path.exists(rawfn):
                                    os.remove(rawfn)
                            except Exception:
                                pass
            # if we filled out, cache and return
            if out.get("ok"):
                file_cache_set(cachek, out)
                return out
        except Exception as e:
            logger.debug("ssh-keyscan attempt failed: %s", e)

        # Fallback to paramiko if installed
        if paramiko:
            try:
                t = paramiko.Transport((host, port))
                t.start_client(timeout=timeout)
                key = t.get_remote_server_key()
                bits = None
                try:
                    if hasattr(key, 'get_bits'):
                        bits = key.get_bits()
                except Exception:
                    pass
                algo = key.get_name() if hasattr(key, 'get_name') else None
                raw = None
                out.update({"ok": True, "raw": str(key), "algo": algo, "bits": bits})
                try:
                    t.close()
                except Exception:
                    pass
                file_cache_set(cachek, out)
                return out
            except Exception as e:
                out['error'] = f"paramiko-fallback-error: {e}"
        # nothing worked
        file_cache_set(cachek, out)
        return out

# ---------------- Behavior Analyzer ----------------
class BehaviorAnalyzer:
    def __init__(self):
        self.baseline_rtts: Dict[str, List[float]] = {}

    def check_response_patterns(self, scan_results: Dict[str, Dict[int, Any]]) -> Dict[str, Any]:
        findings = {}
        for ip, ports in scan_results.items():
            rtts = [p.get('rtt', 0.0) for p in ports.values() if p.get('open')]
            avg = sum(rtts)/len(rtts) if rtts else 0
            findings[ip] = {"avg_rtt": avg, "open_ports": [p for p,v in ports.items() if v.get('open')], "count_open": sum(1 for v in ports.values() if v.get('open'))}
        return findings

# ---------------- Heuristic Engine ----------------
class HeuristicEngine:
    def __init__(self, rules_path: str = DEFAULT_RULES):
        self.rules = []
        self.rules_path = rules_path
        self.load_default_rules()

    def load_default_rules(self):
        # fallback defaults if rules.json missing
        defaults = [
            {"name": "very-fast-rtt", "weight": 10, "cond": {"type": "rtt_lt", "value": 0.01}},
            {"name": "no-banner-short", "weight": 5, "cond": {"type": "banner_len_lt", "value": 5}},
            # new defaults:
            {"name": "high-loopback-rtt", "weight": 3, "cond": {"type": "rtt_loopback_gt", "value": 0.05}},
            {"name": "invalid-ssh-id", "weight": 4, "cond": {"type": "banner_contains", "value": "invalid ssh identification string"}},
            {"name": "hostkey_bits_too_small", "weight": 6, "cond": {"type": "hostkey_bits_lt", "value": 2048}},
        ]
        cfg = load_json(self.rules_path)
        if cfg and isinstance(cfg, dict) and cfg.get("rules"):
            logger.info("Loading heuristics from %s", self.rules_path)
            rules = cfg.get("rules")
        else:
            logger.info("Using default heuristics")
            rules = defaults
        self.rules = []
        for r in rules:
            cond = r.get("cond", {})
            name = r.get("name", "unnamed")
            weight = r.get("weight", 1)
            ctype = cond.get("type")
            val = cond.get("value")

            # Define functions that accept (ip, port_info)
            if ctype == "rtt_lt":
                fn = lambda ip, p, v=val: p.get('open') and (p.get('rtt', 9999) < v)
            elif ctype == "banner_len_lt":
                fn = lambda ip, p, v=val: p.get('open') and ((p.get('banner') or "") == "" or len((p.get('banner') or "")) < v)
            elif ctype == "rtt_loopback_gt":
                # checks if ip is loopback and rtt greater than threshold
                def _fn(ip, p, v=val):
                    try:
                        if not p.get('open'):
                            return False
                        if ip in ('127.0.0.1', '::1'):
                            return (p.get('rtt', 0.0) > v)
                        # also check localhost names?
                        return False
                    except Exception:
                        return False
                fn = _fn
            elif ctype == "banner_contains":
                def _fn(ip, p, v=val):
                    try:
                        if not p.get('open') or not p.get('banner'):
                            return False
                        return v.lower() in (p.get('banner') or "").lower()
                    except Exception:
                        return False
                fn = _fn
            elif ctype == "hostkey_bits_lt":
                def _fn(ip, p, v=val):
                    try:
                        if not p.get('open'):
                            return False
                        bits = p.get('hostkey_bits')
                        if bits is None:
                            return False
                        return bits < v
                    except Exception:
                        return False
                fn = _fn
            else:
                logger.warning("Unknown rule cond type: %s", ctype)
                continue
            self.rules.append((fn, weight, name))

    def score(self, results: Dict[str, Dict[int, Any]]) -> Dict[str, Any]:
        out = {}
        for ip, ports in results.items():
            score = 0
            reasons = []
            for port, p in ports.items():
                for rule, weight, name in self.rules:
                    try:
                        if rule(ip, p):
                            score += weight
                            # append human friendly reason
                            reasons.append(f"{port}:{name}")
                    except Exception:
                        pass
            out[ip] = {"score": score, "reasons": reasons}
        return out

# ---------------- Anomaly Detector ----------------
class AnomalyDetector:
    def __init__(self):
        self.windows: Dict[str, List[float]] = {}

    def update_and_detect(self, ip: str, value: float, window_size:int=10, threshold: float = 3.0) -> Dict[str, Any]:
        w = self.windows.setdefault(ip, [])
        w.append(value)
        if len(w) > window_size:
            w.pop(0)
        mean = sum(w)/len(w) if w else 0
        var = sum((x-mean)**2 for x in w)/len(w) if len(w) else 0
        sd = var**0.5
        score = 0
        if sd > 0 and abs(value-mean)/sd > threshold:
            score = (abs(value-mean)/sd)
        return {"mean": mean, "sd": sd, "zscore": score}

# ---------------- Protocol Fuzzer ----------------
class ProtocolFuzzer:
    def __init__(self, stealth: bool=False):
        # Keep payloads conservative to avoid breaking targets unintentionally
        self.payloads = [b"\x00\x00\x00", b"GET /\xff HTTP/1.1\r\nHost: x\r\n\r\n", b"\xff\xff\xff\xff\xff"]
        self.stealth = stealth

    def fuzz_tcp(self, ip: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
        results = []
        for pld in self.payloads:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout + (1 if self.stealth else 0))
            try:
                sock.connect((ip, port))
                if self.stealth:
                    time.sleep(random.uniform(0.5, 1.0))
                sock.send(pld)
                try:
                    resp = sock.recv(4096)
                    results.append({"payload": pld.hex(), "resp_len": len(resp)})
                except Exception:
                    results.append({"payload": pld.hex(), "resp_len": 0})
            except Exception as e:
                results.append({"payload": pld.hex(), "error": str(e)})
            finally:
                sock.close()
        return {"ip": ip, "port": port, "fuzz_results": results}

# ---------------- Honeytoken Manager ----------------
class HoneytokenManager:
    def __init__(self, listen_host: str = '0.0.0.0', listen_port: int = 8085):
        self.tokens: Dict[str, Dict[str, Any]] = {}
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.server_thread: Optional[threading.Thread] = None
        self._stop = False

    def gen_token(self, label: str = 'tk') -> str:
        tok = str(uuid.uuid4())
        url = f"http://{self.listen_host}:{self.listen_port}/{tok}"
        self.tokens[tok] = {"label": label, "created": now_iso(), "hits": []}
        return url

    def start_listener(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        mgr = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                key = self.path.strip('/').split('?')[0]
                if key in mgr.tokens:
                    mgr.tokens[key]['hits'].append({"time": now_iso(), "from": self.client_address[0], "path": self.path, "headers": dict(self.headers)})
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"OK")
            def log_message(self, format, *args):
                return
        def run_server():
            try:
                httpd = HTTPServer((self.listen_host, self.listen_port), Handler)
                httpd.timeout = 1
                while not self._stop:
                    httpd.handle_request()
            except Exception as e:
                logger.exception("Honeytoken listener failed: %s", e)
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

    def stop_listener(self):
        self._stop = True
        if self.server_thread:
            self.server_thread.join(timeout=2)

    def get_status(self):
        return self.tokens

# ---------------- TLS Analyzer ----------------
class TLSAnalyzer:
    def __init__(self):
        pass

    def get_cert_info(self, host: str, port: int = 443) -> Dict[str, Any]:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(3)
                s.connect((host, port))
                cert = s.getpeercert()
                return {"subject": cert.get('subject'), "issuer": cert.get('issuer'), "notBefore": cert.get('notBefore'), "notAfter": cert.get('notAfter')}
        except Exception as e:
            return {"error": str(e)}

# ---------------- Env Artifact Detector ----------------
class EnvArtifactDetector:
    def __init__(self):
        pass

    def try_ssh_probe(self, ip: str, port: int = 22, username: str = 'nobody') -> Dict[str, Any]:
        if not paramiko:
            return {"error": "paramiko not installed"}
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(ip, port=port, username=username, password='', timeout=3)
            return {"connected": True}
        except Exception as e:
            return {"connected": False, "error": str(e)}

# ---------------- TI Integrator (cached) ----------------
class TIIntegrator:
    def __init__(self, shodan_key: Optional[str] = None, vt_key: Optional[str] = None):
        self.shodan_key = shodan_key
        self.vt_key = vt_key

    def shodan_lookup(self, ip: str) -> Dict[str, Any]:
        cachek = f"shodan:{ip}"
        cached = file_cache_get(cachek)
        if cached:
            return {"cached": True, "result": cached}
        if not requests or not self.shodan_key:
            return {"error": "shodan or key missing"}
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
        try:
            r = requests.get(url, timeout=6)
            obj = r.json()
            file_cache_set(cachek, obj)
            return obj
        except Exception as e:
            return {"error": str(e)}

    def vt_lookup(self, ip_or_url: str) -> Dict[str, Any]:
        cachek = f"vt:{ip_or_url}"
        cached = file_cache_get(cachek)
        if cached:
            return {"cached": True, "result": cached}
        if not requests or not self.vt_key:
            return {"error": "vt or key missing"}
        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip_or_url
        headers = {"x-apikey": self.vt_key}
        try:
            r = requests.get(url, headers=headers, timeout=6)
            obj = r.json()
            file_cache_set(cachek, obj)
            return obj
        except Exception as e:
            return {"error": str(e)}

# ---------------- Forensics Collector ----------------
class ForensicsCollector:
    def __init__(self, outdir: str = EVIDENCE_DIR):
        self.outdir = outdir
        os.makedirs(self.outdir, exist_ok=True)
        self.captures: List[str] = []

    def capture_pcap(self, iface: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:
        if not sniff or not wrpcap:
            return {"error": "scapy not installed"}
        fname = os.path.join(self.outdir, f"capture_{int(time.time())}.pcap")
        pkts = sniff(timeout=timeout, iface=iface) if iface else sniff(timeout=timeout)
        wrpcap(fname, pkts)
        self.captures.append(fname)
        return {"pcap": fname, "count": len(pkts)}

    def save_session(self, host: str, data: Any, suffix: str = 'session.txt'):
        fn = os.path.join(self.outdir, f"{host}_{int(time.time())}_{suffix}")
        with open(fn, 'wb') as f:
            if isinstance(data, str):
                f.write(data.encode())
            else:
                f.write(data)
        return fn

# ---------------- Sandbox Manager (stub) ----------------
class SandboxManager:
    def __init__(self, endpoint: Optional[str] = None, api_key: Optional[str] = None):
        self.endpoint = endpoint
        self.api_key = api_key

    def submit_file(self, path: str) -> Dict[str, Any]:
        return {"error": "sandbox not configured", "path": path}

# ---------------- Reporter ----------------
class Reporter:
    def __init__(self, outdir: str = REPORTS_DIR):
        self.outdir = outdir
        os.makedirs(self.outdir, exist_ok=True)
        self.reports = []

    def generate_report(self, summary: Dict[str, Any], filename: str = None, fmt: str = "json") -> str:
        fn_base = filename or os.path.join(self.outdir, f"report_{int(time.time())}")
        json_path = fn_base + ".json"
        save_json_atomic(json_path, summary)
        self.reports.append(json_path)
        if fmt == "html":
            html_path = fn_base + ".html"
            self._generate_html(summary, html_path)
            return html_path
        return json_path

    def _generate_html(self, summary: Dict[str, Any], path: str):
        html = ["<html><head><meta charset='utf-8'><title>Honeypot Report</title></head><body>"]
        meta = summary.get('meta', {})
        html.append(f"<h1>Scan Report: {meta.get('target')}</h1>")
        html.append(f"<p>Time: {meta.get('time')} | Resolved IPs: {meta.get('resolved_ips')} | Stealth: {meta.get('stealth')}</p>")
        results = summary.get('results', {})
        html.append("<h2>Per-IP Summary</h2><ul>")
        scan = results.get('scan', {})
        heur = results.get('heuristic_scores', {})
        for ip, ports in scan.items():
            openp = [p for p,v in ports.items() if v.get('open')]
            html.append(f"<li><strong>{ip}</strong> - Open: {openp} <br/> Heuristic: {heur.get(ip,{})}</li>")
        html.append("</ul>")
        html.append("<h2>Full JSON</h2>")
        html.append(f"<pre>{json.dumps(summary, indent=2)}</pre>")
        html.append("</body></html>")
        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(html))

# ---------------- Network Intelligence ----------------
try:
    import dns.resolver as _dnsresolver
except Exception:
    _dnsresolver = None

class NetworkIntel:
    def __init__(self):
        self._dns_resolver = _dnsresolver

    def dns_basic(self, host: str) -> Dict[str, Any]:
        out = {"A": [], "AAAA": []}
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                fam = info[0]
                addr = info[4][0]
                if fam == socket.AF_INET:
                    if addr not in out["A"]:
                        out["A"].append(addr)
                elif fam == socket.AF_INET6:
                    if addr not in out["AAAA"]:
                        out["AAAA"].append(addr)
        except Exception:
            pass
        return out

    def dns_records(self, host: str) -> Dict[str, Any]:
        out = {"MX": [], "NS": [], "TXT": []}
        if self._dns_resolver:
            try:
                resolver = self._dns_resolver.Resolver()
                try:
                    ans = resolver.resolve(host, 'MX', lifetime=5)
                    out['MX'] = [str(r.exchange).rstrip('.') for r in ans]
                except Exception:
                    pass
                try:
                    ans = resolver.resolve(host, 'NS', lifetime=5)
                    out['NS'] = [str(r.target).rstrip('.') for r in ans]
                except Exception:
                    pass
                try:
                    ans = resolver.resolve(host, 'TXT', lifetime=5)
                    txts = []
                    for r in ans:
                        try:
                            if hasattr(r, 'strings'):
                                txts.append(''.join([t.decode() if isinstance(t, bytes) else t for t in r.strings]))
                            else:
                                txts.append(str(r))
                        except Exception:
                            pass
                    out['TXT'] = txts
                except Exception:
                    pass
                return out
            except Exception:
                pass

        def _nslookup(qtype):
            try:
                p = subprocess.run(["nslookup", "-type="+qtype, host], capture_output=True, text=True, timeout=6)
                return p.stdout
            except Exception:
                return ""

        try:
            s = _nslookup("mx")
            for line in s.splitlines():
                line = line.strip()
                m = re.search(r'mail exchanger = \d+\s+(\S+)', line)
                if m:
                    out['MX'].append(m.group(1).rstrip('.'))
                else:
                    m2 = re.search(r'mail exchanger =\s*(\S+)', line)
                    if m2:
                        out['MX'].append(m2.group(1).rstrip('.'))
        except Exception:
            pass

        try:
            s = _nslookup("ns")
            for line in s.splitlines():
                line = line.strip()
                m = re.search(r'nameserver =\s*(\S+)', line)
                if m:
                    out['NS'].append(m.group(1).rstrip('.'))
                else:
                    m2 = re.search(r'Name:\s*(\S+)', line)
                    if m2 and '.' in m2.group(1):
                        out['NS'].append(m2.group(1).rstrip('.'))
        except Exception:
            pass

        try:
            s = _nslookup("txt")
            for line in s.splitlines():
                line = line.strip()
                m = re.findall(r'\"([^\"]+)\"', line)
                for t in m:
                    out['TXT'].append(t)
        except Exception:
            pass

        for k in out:
            out[k] = sorted(set(out[k]))
        return out

    def whois_query(self, query: str, timeout: int = 6) -> str:
        cachek = f"whois:{query}"
        cached = file_cache_get(cachek)
        if cached:
            return cached.get('whois', '')
        def _whois_server(q, server, timeout=6):
            resp = ""
            try:
                s = socket.create_connection((server, 43), timeout=timeout)
                s.send((q + "\r\n").encode('utf-8', errors='ignore'))
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    resp += data.decode('utf-8', errors='ignore')
                s.close()
            except Exception as e:
                resp += f"\n\n# WHOIS error contacting {server}: {e}"
            return resp

        base = _whois_server(query, "whois.iana.org", timeout=timeout)
        ref = None
        for line in base.splitlines():
            if ':' in line:
                k,v = line.split(':',1)
                if k.strip().lower() in ('refer', 'whois', 'refer:'):
                    ref = v.strip().split()[0]
                    break
        if not ref:
            if re.match(r'^\d+\.', query):
                ref = "whois.arin.net"
            else:
                ref = None
        full = base
        if ref:
            full += "\n\n-- Referral WHOIS (" + ref + "):\n\n"
            full += _whois_server(query, ref, timeout=timeout)
        try:
            file_cache_set(cachek, {"whois": full})
        except Exception:
            pass
        return full

    def extract_asn_from_whois(self, whois_text: str) -> List[str]:
        asns = set()
        for m in re.finditer(r'\bAS(\d{1,10})\b', whois_text, flags=re.IGNORECASE):
            asns.add("AS" + m.group(1))
        for line in whois_text.splitlines():
            if ':' in line:
                k,v = line.split(':',1)
                k = k.strip().lower()
                v = v.strip()
                if k in ('origin', 'originas', 'origin-as', 'aut-num'):
                    m = re.search(r'AS?(\d+)', v, flags=re.IGNORECASE)
                    if m:
                        asns.add("AS" + m.group(1))
        return sorted(asns)

    def asn_lookup(self, ip: str) -> Dict[str, Any]:
        out = {"ip": ip, "whois": None, "asns": []}
        try:
            who = self.whois_query(ip)
            out['whois'] = who
            out['asns'] = self.extract_asn_from_whois(who)
        except Exception as e:
            out['whois'] = f"error: {e}"
        return out

    def collect(self, host_or_ip: str, ips: List[str]) -> Dict[str, Any]:
        res = {"dns_basic": {}, "dns_records": {}, "whois": {}, "asn": {}}
        try:
            res['dns_basic'] = self.dns_basic(host_or_ip)
        except Exception:
            res['dns_basic'] = {}
        try:
            res['dns_records'] = self.dns_records(host_or_ip)
        except Exception:
            res['dns_records'] = {}
        for ip in ips or []:
            try:
                w = self.whois_query(ip)
                res['whois'][ip] = w
                res['asn'][ip] = self.extract_asn_from_whois(w)
            except Exception as e:
                res['whois'][ip] = f"error: {e}"
                res['asn'][ip] = []
        return res

# ---------------- Main Orchestrator ----------------
class HoneypotDetector:
    def __init__(self, target: Optional[str], ports: Optional[List[int]] = None,
                 shodan_key: Optional[str]=None, vt_key: Optional[str]=None,
                 stealth: bool=False, workers: int = 100,
                 enable_fuzz: bool=False, enable_honey: bool=False, capture_pcap: bool=False,
                 enabled_steps: Optional[List[str]] = None, sig_file: str = DEFAULT_SIGS, rules_file: str = DEFAULT_RULES):
        self.input = InputHandler(target)
        self.ips = self.input.get_ips() or []
        if not self.ips and self.input.type == 'domain' and self.input.target:
            try:
                self.ips = [socket.gethostbyname(self.input.target)]
            except Exception:
                pass
        if not self.ips and self.input.type == 'ip' and self.input.target:
            self.ips = [self.input.target]
        self.stealth = stealth
        self.scanner = Scanner(self.ips, ports, workers=workers, stealth=stealth)
        self.fingerprint = Fingerprinter(sig_file=sig_file)
        self.behavior = BehaviorAnalyzer()
        self.heuristic = HeuristicEngine(rules_path=rules_file)
        self.anomaly = AnomalyDetector()
        self.fuzzer = ProtocolFuzzer(stealth=stealth)
        self.honey = HoneytokenManager()
        self.tls = TLSAnalyzer()
        self.env = EnvArtifactDetector()
        self.ti = TIIntegrator(shodan_key=shodan_key, vt_key=vt_key)
        self.forensics = ForensicsCollector()
        self.sandbox = SandboxManager()
        self.reporter = Reporter()
        self.netintel = NetworkIntel()

        self.enable_fuzz = enable_fuzz
        self.enable_honey = enable_honey
        self.capture_pcap = capture_pcap
        self.enabled_steps = set(enabled_steps or ["scan","fingerprint","behavior","heuristic","netinfo"])

    def run_scan(self):
        out = {"meta": {"target": self.input.target, "resolved_ips": self.ips, "time": now_iso(), "stealth": self.stealth}, "results": {}}

        # SCAN1.
        if "scan" in self.enabled_steps:
            scan_res = self.scanner.run()
            out['results']['scan'] = scan_res
        else:
            out['results']['scan'] = {}

        # FINGERPRINT
        if "fingerprint" in self.enabled_steps:
            fp = {}
            # We'll also attach hostkey info (if any) into the scan results for heuristic usage
            for ip, ports in out['results'].get('scan', {}).items():
                fp[ip] = {}
                for p, info in ports.items():
                    if info.get('open'):
                        try:
                            fp[ip].setdefault(p, {})
                            fp[ip][p]['banner'] = info.get('banner')
                            fp[ip][p].setdefault('sig_match', []).extend(self.fingerprint.match_signatures(info.get('banner')))
                            # For HTTP ports
                            if p in (80, 8080, 8000):
                                fp[ip][p]['http'] = self.fingerprint.http_fingerprint(ip, p, stealth=self.stealth)
                                fp[ip][p]['sig_from_http'] = fp[ip][p]['http'].get('matches', [])
                            # For TLS port
                            if p == 443:
                                fp[ip][p]['cert_fingerprint'] = self.fingerprint.cert_fingerprint(ip, 443)
                                fp[ip][p]['tls'] = self.fingerprint.tls_fingerprint(ip, 443)
                                fp[ip][p]['sig_from_tls'] = fp[ip][p]['tls'].get('matches', [])
                            # For SSH-ish ports (including custom SSH on other ports), attempt hostkey check
                            if p == 22 or (info.get('banner') and 'ssh-' in (info.get('banner') or "").lower()):
                                try:
                                    hk = self.fingerprint.hostkey_info(ip, port=p)
                                    if hk:
                                        fp[ip][p]['hostkey'] = hk
                                        # attach hostkey bits into the original scan data for heuristics
                                        try:
                                            out['results']['scan'][ip][p]['hostkey_bits'] = hk.get('bits')
                                            out['results']['scan'][ip][p]['hostkey_algo'] = hk.get('algo')
                                        except Exception:
                                            pass
                                        # also add reason if small
                                        if hk.get('bits') and isinstance(hk.get('bits'), int) and hk.get('bits') < 2048:
                                            fp[ip][p].setdefault('sig_match', []).append('small-hostkey')
                                except Exception:
                                    logger.debug("hostkey_info failure for %s:%s", ip, p)
                        except Exception:
                            logger.exception("fingerprint failure for %s:%s", ip, p)
            out['results']['fingerprint'] = fp

        # BEHAVIOR
        if "behavior" in self.enabled_steps:
            out['results']['behavior'] = self.behavior.check_response_patterns(out['results'].get('scan', {}))

        # HEURISTICS
        if "heuristic" in self.enabled_steps:
            # use heuristics against the scan results (which may now include hostkey_bits etc)
            heur = self.heuristic.score(out['results'].get('scan', {}))
            # Additional banner-vs-behavior mismatch: check banner claims vs hostkey/algo inconsistencies
            # Minimal check: if banner contains OpenSSH_X.Y but hostkey_algo is something unexpected add a reason
            for ip, ports in out['results'].get('scan', {}).items():
                for p, info in ports.items():
                    if not info.get('open'):
                        continue
                    b = (info.get('banner') or "").lower()
                    hk_algo = info.get('hostkey_algo')
                    # if banner claims OpenSSH but hostkey algo missing or inconsistent, flag
                    if 'openssh' in b:
                        if not hk_algo:
                            # minor suspicion: OpenSSH banner but no hostkey info retrievable
                            heur.setdefault(ip, {"score": heur.get(ip, {}).get('score', 0), "reasons": heur.get(ip, {}).get('reasons', [])})
                            heur[ip]['score'] = heur[ip].get('score', 0) + 2
                            heur[ip].setdefault('reasons', []).append(f"{p}:banner-openssh-but-no-hostkey")
                        else:
                            # if algorithm looks odd (very small bits were already flagged by rule)
                            pass
                    # detection for malformed identification strings: many honeypots respond oddly
                    if info.get('banner') and 'invalid ssh identification string' in info.get('banner').lower():
                        heur.setdefault(ip, {"score": heur.get(ip, {}).get('score', 0), "reasons": heur.get(ip, {}).get('reasons', [])})
                        heur[ip]['score'] = heur[ip].get('score', 0) + 4
                        heur[ip].setdefault('reasons', []).append(f"{p}:invalid-ssh-identification")
            out['results']['heuristic_scores'] = heur

        # ANOMALIES
        anomalies = {}
        for ip, ports in out['results'].get('scan', {}).items():
            vals = [p.get('rtt',0.0) for p in ports.values() if p.get('rtt')]
            if vals:
                last = vals[-1]
                anomalies[ip] = self.anomaly.update_and_detect(ip, last)
        out['results']['anomalies'] = anomalies

        # FUZZING (backend-only)
        if self.enable_fuzz:
            fuzz_out = {}
            for ip, ports in out['results'].get('scan', {}).items():
                for p, info in ports.items():
                    if info.get('open'):
                        fuzz_out.setdefault(ip, {})[p] = self.fuzzer.fuzz_tcp(ip, p)
            out['results']['fuzzing'] = fuzz_out

        # HONEYTOKEN (backend-only)
        if self.enable_honey:
            try:
                self.honey.start_listener()
                token_url = self.honey.gen_token('scan-'+str(uuid.uuid4())[:6])
                out['results']['honeytoken'] = {"url": token_url}
            except Exception as e:
                out['results']['honeytoken'] = {"error": str(e)}

        # ENV ARTIFACTS (SSH probe)
        env_out = {}
        for ip, ports in out['results'].get('scan', {}).items():
            if 22 in ports and ports[22].get('open'):
                env_out[ip] = self.env.try_ssh_probe(ip, 22)
        out['results']['env_artifact'] = env_out

        # TI (shodan/vt)
        ti_out = {}
        if requests and (self.ti.shodan_key or self.ti.vt_key):
            for ip in self.ips:
                ti_out[ip] = {}
                if self.ti.shodan_key:
                    ti_out[ip]['shodan'] = self.ti.shodan_lookup(ip)
                if self.ti.vt_key:
                    ti_out[ip]['vt'] = self.ti.vt_lookup(ip)
        out['results']['ti'] = ti_out

        # FORENSICS PCAP
        if self.capture_pcap:
            try:
                fc = self.forensics.capture_pcap(timeout=10)
                out['results']['forensics'] = fc
            except Exception as e:
                out['results']['forensics'] = {"error": str(e)}

        # NETWORK INTEL
        try:
            net = self.netintel.collect(self.input.target, self.ips)
            out['results']['netinfo'] = net
        except Exception as e:
            out['results']['netinfo'] = {"error": str(e)}

        report_path = self.reporter.generate_report(out)
        out['report'] = report_path
        return out

# ---------------- CLI / Helpers ----------------
def parse_ports(s: str) -> List[int]:
    ps = []
    for part in s.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a,b = part.split('-',1)
            try:
                ps.extend(list(range(int(a), int(b)+1)))
            except Exception:
                pass
        else:
            try:
                ps.append(int(part))
            except Exception:
                pass
    return sorted(set(ps))

def interactive_prompt():
    print("--- Interactive mode: answer the prompts ---")
    target = input("Target (IP or domain): ").strip()
    ports_in = input(f"Ports (comma or ranges) [default: {','.join(map(str, DEFAULT_PORTS))}]: ").strip()
    ports = parse_ports(ports_in) if ports_in else DEFAULT_PORTS
    stealth_in = input("Enable stealth mode? (y/N): ").strip().lower()
    stealth = stealth_in == 'y'
    workers_in = input("Workers (threads) [default: 100]: ").strip()
    try:
        workers = int(workers_in) if workers_in else 100
    except Exception:
        workers = 100
    return {"target": target, "ports": ports, "stealth": stealth, "workers": workers}

def gather_backend_flags():
    cfg = load_json(CONFIG_FILE) or {}
    enable_fuzz = bool(cfg.get('enable_fuzz')) or env_bool('HONEYPOT_ENABLE_FUZZ', False)
    enable_honey = bool(cfg.get('enable_honey')) or env_bool('HONEYPOT_ENABLE_HONEY', False)
    capture_pcap = bool(cfg.get('capture_pcap')) or env_bool('HONEYPOT_CAPTURE_PCAP', False)
    shodan_key = cfg.get('shodan_key') or os.getenv('SHODAN_API_KEY') or os.getenv('SHODAN_KEY')
    vt_key = cfg.get('vt_key') or os.getenv('VT_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
    enabled_steps = cfg.get('enabled_steps') or ["scan","fingerprint","behavior","heuristic","netinfo"]
    return {"enable_fuzz": enable_fuzz, "enable_honey": enable_honey, "capture_pcap": capture_pcap, "shodan_key": shodan_key, "vt_key": vt_key, "enabled_steps": enabled_steps}

def summarize_and_print(out: Dict[str, Any]):
    meta = out.get('meta', {})
    results = out.get('results', {})
    print("\n=== Scan Summary ===")
    print(f"Target: {meta.get('target')} | Resolved IPs: {meta.get('resolved_ips')} | Time: {meta.get('time')}")
    print(f"Stealth: {meta.get('stealth')}")
    scan = results.get('scan', {})
    for ip, ports in scan.items():
        open_ports = [p for p,v in ports.items() if v.get('open')]
        print(f"\nIP: {ip}")
        print(f" Open ports: {open_ports if open_ports else 'None'}")
        if open_ports:
            for p in open_ports:
                b = ports[p].get('banner')
                rtt = ports[p].get('rtt')
                hk_bits = ports[p].get('hostkey_bits')
                hk_algo = ports[p].get('hostkey_algo')
                extra = ""
                if hk_bits:
                    extra = f" hostkey_bits={hk_bits} algo={hk_algo}"
                print(f"  - Port {p}: rtt={rtt} banner_preview={str(b)[:120]}{(' | ' + extra) if extra else ''}")
        heur = results.get('heuristic_scores', {}).get(ip, {})
        print(f" Heuristic score: {heur.get('score',0)} Reasons: {heur.get('reasons',[])}")
        beh = results.get('behavior', {}).get(ip, {})
        if beh:
            print(f" Behavior: avg_rtt={beh.get('avg_rtt')} open_ports={beh.get('open_ports')}")
        anom = results.get('anomalies', {}).get(ip, {})
        if anom:
            print(f" Anomaly: mean={anom.get('mean')} sd={anom.get('sd')} zscore={anom.get('zscore')}")
        net = results.get('netinfo', {})
        if net:
            dns_basic = net.get('dns_basic', {})
            dns_records = net.get('dns_records', {})
            asn = net.get('asn', {}).get(ip, [])
            print(f" DNS A: {dns_basic.get('A',[])} AAAA: {dns_basic.get('AAAA',[])}")
            if dns_records:
                print(f" DNS MX: {dns_records.get('MX',[])} NS: {dns_records.get('NS',[])} TXT (len): {len(dns_records.get('TXT',[]))}")
            if asn:
                print(f" ASN(s): {asn}")
    print(f"\nFull report saved: {out.get('report')}")
    print("====================\n")

def main():
    parser = argparse.ArgumentParser(description='Advanced Honeypot Detector (complete)')
    parser.add_argument('--target', required=False, help='target domain or IP')
    parser.add_argument('--ports', default=','.join(map(str, DEFAULT_PORTS)), help='comma list or ranges of ports')
    parser.add_argument('--interactive', action='store_true', help='prompt user for input interactively')
    parser.add_argument('--stealth', action='store_true', help='enable stealth mode')
    parser.add_argument('--workers', type=int, default=100, help='number of worker threads for scanning (default: 100)')
    parser.add_argument('--quiet', action='store_true', help='minimize console output')
    parser.add_argument('--log-level', default='INFO', help='logging level (DEBUG/INFO/WARNING/ERROR)')
    parser.add_argument('--no-json-dump', action='store_true', help="don't print full JSON to console")
    parser.add_argument('--report-format', choices=['json','html'], default='json', help='report output format')
    parser.add_argument('--enable-fuzz', action='store_true', help='enable protocol fuzzing (be careful)')
    parser.add_argument('--enable-honey', action='store_true', help='enable honeytoken listener')
    parser.add_argument('--capture-pcap', action='store_true', help='capture pcap using scapy (requires scapy and privileges)')
    parser.add_argument('--sig-file', default=DEFAULT_SIGS, help='path to signatures.json to load (optional)')
    parser.add_argument('--rules-file', default=DEFAULT_RULES, help='path to rules.json to load (optional)')
    args = parser.parse_args()

    set_verbosity(args.log_level, quiet=args.quiet)
    backend = gather_backend_flags()
    # override backend flags with CLI switches
    enable_fuzz = args.enable_fuzz or backend.get('enable_fuzz', False)
    enable_honey = args.enable_honey or backend.get('enable_honey', False)
    capture_pcap = args.capture_pcap or backend.get('capture_pcap', False)

    if args.interactive or not args.target:
        cfg = interactive_prompt()
        target = cfg['target']
        ports = cfg['ports']
        stealth = cfg['stealth']
        workers = cfg['workers']
    else:
        target = args.target
        ports = parse_ports(args.ports)
        stealth = args.stealth
        workers = args.workers

    detector = HoneypotDetector(
        target,
        ports=ports,
        shodan_key=backend.get('shodan_key'),
        vt_key=backend.get('vt_key'),
        stealth=stealth,
        workers=workers,
        enable_fuzz=enable_fuzz,
        enable_honey=enable_honey,
        capture_pcap=capture_pcap,
        enabled_steps=backend.get('enabled_steps', None),
        sig_file=args.sig_file,
        rules_file=args.rules_file
    )

    logger.info("Starting scan against %s (resolved ips: %s) | stealth=%s | workers=%s", target, detector.ips, stealth, workers)
    res = detector.run_scan()
    # Save report according to requested format (overrides reporter default)
    report_path = detector.reporter.generate_report(res, fmt=args.report_format)
    res['report'] = report_path

    if not args.no_json_dump:
        try:
            print(json.dumps(res, indent=2))
        except Exception:
            logger.exception("Failed to print JSON dump")

    summarize_and_print(res)

if __name__ == '__main__':
    main()
