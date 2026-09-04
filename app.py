import os
import sys
import csv
import io
import json
import re
import socket
import logging
import sqlite3
import ipaddress
import hashlib
import hmac
import secrets
import urllib.request
import urllib.parse
import urllib.error
import subprocess
import platform
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, abort, g, jsonify)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB max upload

# Bu worker/process ne zaman baslatildi (servis yeniden baslarsa sifirlanir - uptime'i gosterir)
APP_START_TIME = datetime.now()

# ── Config ────────────────────────────────────────────────────────────────────
_default_feed_dir = r"C:\ThreatFeed\public" if platform.system() == "Windows" else "/opt/threatfeed/public"
BASE_DIR   = os.environ.get("IOCMANAGER_FEED_DIR", _default_feed_dir)
FEED_FILES = {
    "allowlist-ip":     os.path.join(BASE_DIR, "allowlist-ip.txt"),
    "blacklist-ip":     os.path.join(BASE_DIR, "blacklist-ip.txt"),
    "blacklist-hash":   os.path.join(BASE_DIR, "blacklist-hash.txt"),
    "allowlist-domain": os.path.join(BASE_DIR, "allowlist-domain.txt"),
    "blacklist-domain": os.path.join(BASE_DIR, "blacklist-domain.txt"),
    "allowlist-url":    os.path.join(BASE_DIR, "allowlist-url.txt"),
    "blacklist-url":    os.path.join(BASE_DIR, "blacklist-url.txt"),
}
IP_FEEDS     = {"allowlist-ip", "blacklist-ip"}
HASH_FEEDS   = {"blacklist-hash"}
DOMAIN_FEEDS = {"allowlist-domain", "blacklist-domain"}
URL_FEEDS    = {"allowlist-url", "blacklist-url"}
HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}

# Private / ozel IP araliklari - bunlar allow VEYA block listeye EKLENEMEZ
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]
DB_PATH  = os.environ.get("IOCMANAGER_DB",
           os.path.join(os.path.dirname(__file__), "data", "iocmanager.db"))
LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "iocmanager-cef.log")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES     = 15

# ── CEF File Logger ───────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
cef_file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
cef_file_handler.setLevel(logging.INFO)
cef_logger = logging.getLogger("cef")
cef_logger.setLevel(logging.INFO)
cef_logger.addHandler(cef_file_handler)

# ── Security headers ──────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    # Dinamik sayfalar cache'lenmesin (eski sorgu sonucu gorunmesin)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"]        = "no-cache"
    response.headers.pop("Server", None)
    return response

# ── DB ────────────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        username        TEXT UNIQUE NOT NULL,
        password        TEXT NOT NULL,
        role            TEXT NOT NULL DEFAULT 'operator',
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until    TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT NOT NULL,
        username   TEXT NOT NULL,
        action     TEXT NOT NULL,
        feed       TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        note       TEXT,
        client_ip  TEXT
    );
    CREATE TABLE IF NOT EXISTS csrf_tokens (
        token      TEXT PRIMARY KEY,
        username   TEXT NOT NULL,
        expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT
    );
    """)
    # Varsayilan SIEM ayarlari
    defaults = {
        "siem_enabled":  "0",
        "siem_host":     "",
        "siem_port":     "514",
        "siem_protocol": "UDP",
        "siem_cef_file": "1",
        # Cisco Umbrella Management API
        "umbrella_enabled":   "0",
        "umbrella_key":       "",
        "umbrella_secret":    "",
        "umbrella_list_id":   "",
        "umbrella_auto_sync": "0",
        # Trend Micro TippingPoint SMS Reputation Database
        "tippingpoint_enabled":          "0",
        "tippingpoint_server":           "",
        "tippingpoint_api_key":          "",
        "tippingpoint_tag_category":     "",
        "tippingpoint_tag_value":        "",
        "tippingpoint_skip_ssl_verify":  "0",
        "tippingpoint_auto_sync":        "0",
        # Threat Intel API anahtarlari (bos = devre disi)
        "api_virustotal": "",
        "api_abuseipdb":  "",
        "api_urlscan":    "",
        "api_shodan":     "",
        "api_mxtoolbox":  "",
        "urlscan_live":   "0",
    }
    for k, v in defaults.items():
        try:
            conn.execute("INSERT INTO settings (key, value) VALUES (?,?)", (k, v))
        except sqlite3.IntegrityError:
            pass
    conn.commit()

    pw = hash_password("IoCManager2026!")
    try:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                     ("admin", pw, "admin"))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()

# ── Password ──────────────────────────────────────────────────────────────────
def hash_password(password):
    salt = secrets.token_hex(32)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return "pbkdf2:sha256:260000:{}:{}".format(salt, dk.hex())

def verify_password(stored, provided):
    try:
        parts     = stored.split(":")
        salt      = parts[3]
        stored_dk = bytes.fromhex(parts[4])
        dk = hashlib.pbkdf2_hmac("sha256", provided.encode(), salt.encode(), 260000)
        return hmac.compare_digest(dk, stored_dk)
    except Exception:
        return False

# ── CSRF ──────────────────────────────────────────────────────────────────────
def generate_csrf_token():
    token   = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    db.execute("DELETE FROM csrf_tokens WHERE expires_at < ?",
               (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))
    db.execute("INSERT INTO csrf_tokens (token, username, expires_at) VALUES (?,?,?)",
               (token, session.get("username", ""), expires))
    db.commit()
    session["csrf_token"] = token
    return token

def validate_csrf():
    token = request.form.get("csrf_token")
    if not token:
        abort(403)
    db  = get_db()
    row = db.execute(
        "SELECT * FROM csrf_tokens WHERE token=? AND expires_at > ?",
        (token, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    ).fetchone()
    if not row:
        abort(403)

@app.context_processor
def inject_csrf():
    if "username" in session:
        return {"csrf_token": generate_csrf_token()}
    return {"csrf_token": ""}

# ── Lockout ───────────────────────────────────────────────────────────────────
def is_locked(username):
    db  = get_db()
    row = db.execute("SELECT locked_until FROM users WHERE username=?", (username,)).fetchone()
    if not row or not row["locked_until"]:
        return False
    if datetime.now() < datetime.strptime(row["locked_until"], "%Y-%m-%d %H:%M:%S"):
        return True
    db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
    db.commit()
    return False

def record_failed(username):
    db = get_db()
    db.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username=?", (username,))
    row = db.execute("SELECT failed_attempts FROM users WHERE username=?", (username,)).fetchone()
    if row and row["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
        until = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
        db.execute("UPDATE users SET locked_until=? WHERE username=?", (until, username))
    db.commit()

def reset_failed(username):
    db = get_db()
    db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
    db.commit()

# ── Settings ──────────────────────────────────────────────────────────────────
def get_setting(key, default=""):
    db  = get_db()
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

def set_setting(key, value):
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, value))
    db.commit()

def get_all_settings():
    db   = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}

# ── SIEM / CEF ────────────────────────────────────────────────────────────────
CEF_SEVERITY = {"ADD": 5, "REMOVE": 3, "LOGIN": 2, "LOGIN_FAIL": 7, "LOCKOUT": 8}

def build_cef(action, username, feed, ip_address, note, client_ip):
    severity = CEF_SEVERITY.get(action, 5)
    ts       = datetime.now().strftime("%b %d %Y %H:%M:%S")
    ext = (
        "act={action} src={client_ip} duser={username} "
        "cs1={feed} cs1Label=FeedName cs2={ip} cs2Label=IPAddress "
        "msg={note} rt={ts}"
    ).format(
        action=action, client_ip=client_ip, username=username,
        feed=feed, ip=ip_address, note=note or "-", ts=ts
    )
    return "CEF:0|IoCManager|IoCManager|1.2|{}|IoCManager {}|{}|{}".format(
        action, action, severity, ext
    )

def send_siem(cef_msg):
    if get_setting("siem_cef_file") == "1":
        cef_logger.info(cef_msg)

    if get_setting("siem_enabled") != "1":
        return True, "SIEM devre disi"

    host     = get_setting("siem_host")
    port     = int(get_setting("siem_port", "514"))
    protocol = get_setting("siem_protocol", "UDP")

    if not host:
        return False, "SIEM host ayarlanmamis"

    try:
        msg = (cef_msg + "\n").encode("utf-8")
        if protocol == "TCP":
            with socket.create_connection((host, port), timeout=5) as s:
                s.sendall(msg)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(msg, (host, port))
        return True, "OK"
    except Exception as e:
        return False, str(e)

def log_action(username, action, feed, ip_address, note, client_ip):
    import re
    note = re.sub(r"[<>\"'%;()&+]", "", str(note))[:200]
    db   = get_db()
    db.execute(
        "INSERT INTO audit_log (timestamp,username,action,feed,ip_address,note,client_ip) VALUES (?,?,?,?,?,?,?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, action, feed, ip_address, note, client_ip)
    )
    db.commit()
    cef = build_cef(action, username, feed, ip_address, note, client_ip)
    send_siem(cef)

# ── Sistem Izleme ──────────────────────────────────────────────────────────────
def get_service_status():
    """Isletim sistemine gore servis durumunu sorgular. Basarisiz olursa 'unknown' doner."""
    try:
        if platform.system() == "Windows":
            out = subprocess.run(["sc", "query", "IoCManager"],
                                 capture_output=True, text=True, timeout=5)
            text = out.stdout.upper()
            if "RUNNING" in text:
                return "running"
            if "STOPPED" in text:
                return "stopped"
            if "START_PENDING" in text or "STOP_PENDING" in text:
                return "pending"
            return "unknown"
        else:
            out = subprocess.run(["systemctl", "is-active", "iocmanager"],
                                 capture_output=True, text=True, timeout=5)
            state = out.stdout.strip()
            return state if state else "unknown"
    except Exception:
        return "unknown"

def format_uptime(td):
    total = int(td.total_seconds())
    days, rem  = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    parts = []
    if days:  parts.append("{}g".format(days))
    if hours: parts.append("{}sa".format(hours))
    if mins:  parts.append("{}dk".format(mins))
    if not parts:
        parts.append("{}sn".format(secs))
    return " ".join(parts)

def tail_file(path, n=200, max_bytes=500_000):
    """Dosyanin son n satirini, en fazla max_bytes okuyarak dondurur."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            read_size = min(size, max_bytes)
            f.seek(size - read_size)
            data = f.read().decode("utf-8", errors="replace")
        lines = data.splitlines()
        return "\n".join(lines[-n:])
    except FileNotFoundError:
        return None
    except Exception as e:
        return "(log okunamadi: {})".format(e)

# ── Gosterge Tipi Algilama ──────────────────────────────────────────────────
def detect_indicator_type(indicator):
    indicator = indicator.strip()
    if validate_hash(indicator):
        return "hash"
    if validate_ip(indicator):
        return "ip"
    if re.match(r'^https?://', indicator, re.IGNORECASE) or "/" in indicator:
        return "url"
    if validate_domain(indicator):
        return "domain"
    return "unknown"

# ── Threat Intelligence API (Sorgu / Enrichment) ──────────────────────────────
def _http_get(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout, context=_get_ssl_context()) as resp:
        return json.loads(resp.read().decode("utf-8"))

def query_virustotal(indicator, itype):
    key = get_setting("api_virustotal")
    if not key:
        return None
    try:
        if itype == "ip":
            url = "https://www.virustotal.com/api/v3/ip_addresses/" + urllib.parse.quote(indicator)
        elif itype == "domain":
            url = "https://www.virustotal.com/api/v3/domains/" + urllib.parse.quote(indicator)
        elif itype == "url":
            import base64
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            url = "https://www.virustotal.com/api/v3/urls/" + url_id
        elif itype == "hash":
            url = "https://www.virustotal.com/api/v3/files/" + urllib.parse.quote(indicator)
        else:
            return None

        data  = _http_get(url, headers={"x-apikey": key})
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values()) if stats else 0

        result = {
            "source": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total": total,
            "verdict": "malicious" if stats.get("malicious", 0) > 0 else ("suspicious" if stats.get("suspicious", 0) > 0 else "clean"),
        }
        result["reputation"] = attrs.get("reputation", None)

        cats = attrs.get("categories", {})
        if cats:
            result["categories"] = list(set(cats.values()))[:6]

        if itype == "domain":
            result["registrar"] = attrs.get("registrar", None)
            cd = attrs.get("creation_date", None)
            if cd:
                try:
                    result["created"] = datetime.utcfromtimestamp(cd).strftime("%Y-%m-%d")
                except Exception:
                    pass

        if itype == "url":
            result["final_url"] = attrs.get("last_final_url", None)
            result["title"] = attrs.get("title", None)

        return result
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"source": "VirusTotal", "verdict": "no_data",
                    "note": "VT veritabaninda kayit yok (henuz taranmamis)"}
        return {"source": "VirusTotal", "error": "HTTP {}".format(e.code)}
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)[:100]}

def query_abuseipdb(indicator, itype):
    key = get_setting("api_abuseipdb")
    if not key or itype != "ip":
        return None
    try:
        url = "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90".format(
            urllib.parse.quote(indicator))
        data = _http_get(url, headers={"Key": key, "Accept": "application/json"})
        d = data.get("data", {})
        return {
            "source": "AbuseIPDB",
            "score": d.get("abuseConfidenceScore", 0),
            "reports": d.get("totalReports", 0),
            "country": d.get("countryCode", "-"),
            "isp": d.get("isp", "-"),
            "usage": d.get("usageType", "-"),
            "verdict": "malicious" if d.get("abuseConfidenceScore", 0) >= 50 else "clean",
        }
    except urllib.error.HTTPError as e:
        return {"source": "AbuseIPDB", "error": "HTTP {}".format(e.code)}
    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)[:100]}

def _urlscan_detail(result_url, key):
    """URLScan result API'sinden zengin detay ceker (screenshot haric)."""
    try:
        data = _http_get(result_url, headers={"API-Key": key})
        verdicts  = data.get("verdicts", {})
        overall   = verdicts.get("overall", {})
        lists     = data.get("lists", {})
        page      = data.get("page", {})

        cats   = overall.get("categories", [])
        brands = [b.get("name", "") for b in overall.get("brands", [])] if overall.get("brands") else []
        tags   = data.get("tags", [])

        return {
            "score": overall.get("score", 0),
            "verdict": "malicious" if overall.get("malicious") else "found",
            "categories": cats[:6],
            "brands": brands[:4],
            "tags": tags[:6],
            "related_ips": lists.get("ips", [])[:10],
            "related_domains": lists.get("domains", [])[:10],
            "tls_issuer": page.get("tlsIssuer", "-"),
        }
    except Exception:
        return {}

def query_urlscan(indicator, itype):
    key = get_setting("api_urlscan")
    if not key or itype not in ("url", "domain"):
        return None
    try:
        q = urllib.parse.quote('page.domain:"{}"'.format(indicator) if itype == "domain" else 'page.url:"{}"'.format(indicator))
        url = "https://urlscan.io/api/v1/search/?q={}&size=1".format(q)
        data = _http_get(url, headers={"API-Key": key})
        results = data.get("results", [])
        if results:
            r = results[0]
            result_url = r.get("result", "")
            detail = _urlscan_detail(result_url, key) if result_url else {}
            page = r.get("page", {})
            base = {
                "source": "URLScan",
                "verdict": "found",
                "url": page.get("url", "-"),
                "ip": page.get("ip", "-"),
                "country": page.get("country", "-"),
                "server": page.get("server", "-"),
                "asnname": page.get("asnname", "-"),
            }
            base.update(detail)
            return base
        if itype == "url" and get_setting("urlscan_live") == "1":
            return urlscan_live_scan(indicator, key)
        return {"source": "URLScan", "verdict": "no_data",
                "note": "Kayit yok" + (" (canli tarama kapali)" if itype == "url" else "")}
    except urllib.error.HTTPError as e:
        return {"source": "URLScan", "error": "HTTP {}".format(e.code)}
    except Exception as e:
        return {"source": "URLScan", "error": str(e)[:100]}

def urlscan_live_scan(target_url, key):
    """URLScan'e yeni tarama gonderir, sonucu bekler (max ~30sn). Screenshot alinmaz."""
    import time
    try:
        payload = json.dumps({"url": target_url, "visibility": "unlisted"}).encode("utf-8")
        req = urllib.request.Request(
            "https://urlscan.io/api/v1/scan/",
            data=payload,
            headers={"API-Key": key, "Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15, context=_get_ssl_context()) as resp:
            submit = json.loads(resp.read().decode("utf-8"))
        result_api = submit.get("api")
        if not result_api:
            return {"source": "URLScan", "verdict": "no_data", "note": "Tarama baslatilamadi"}

        for _ in range(10):
            time.sleep(3)
            try:
                data = _http_get(result_api, headers={"API-Key": key})
                page = data.get("page", {})
                verdicts = data.get("verdicts", {})
                overall  = verdicts.get("overall", {})
                lists    = data.get("lists", {})
                return {
                    "source": "URLScan",
                    "verdict": "malicious" if overall.get("malicious") else "found",
                    "url": page.get("url", target_url),
                    "ip": page.get("ip", "-"),
                    "country": page.get("country", "-"),
                    "server": page.get("server", "-"),
                    "score": overall.get("score", 0),
                    "categories": overall.get("categories", [])[:6],
                    "brands": [b.get("name", "") for b in overall.get("brands", [])][:4],
                    "tags": data.get("tags", [])[:6],
                    "related_ips": lists.get("ips", [])[:10],
                    "related_domains": lists.get("domains", [])[:10],
                    "tls_issuer": page.get("tlsIssuer", "-"),
                    "note": "Canli tarama sonucu",
                }
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    continue
                raise
        return {"source": "URLScan", "verdict": "no_data", "note": "Tarama zaman asimi"}
    except Exception as e:
        return {"source": "URLScan", "error": "Canli tarama: " + str(e)[:80]}

def query_shodan(indicator, itype):
    key = get_setting("api_shodan")
    if not key or itype != "ip":
        return None
    try:
        url = "https://api.shodan.io/shodan/host/{}?key={}".format(
            urllib.parse.quote(indicator), urllib.parse.quote(key))
        data = _http_get(url)
        return {
            "source": "Shodan",
            "ports": data.get("ports", []),
            "org": data.get("org", "-"),
            "os": data.get("os", "-") or "-",
            "country": data.get("country_name", "-"),
            "hostnames": data.get("hostnames", []),
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"source": "Shodan", "verdict": "no_data", "note": "Host bulunamadi"}
        return {"source": "Shodan", "error": "HTTP {}".format(e.code)}
    except Exception as e:
        return {"source": "Shodan", "error": str(e)[:100]}

def query_mxtoolbox(indicator, itype):
    key = get_setting("api_mxtoolbox")
    if not key or itype != "domain":
        return None
    try:
        url = "https://api.mxtoolbox.com/api/v1/Lookup/blacklist/?argument={}".format(
            urllib.parse.quote(indicator))
        data = _http_get(url, headers={"Authorization": key})
        failed = data.get("Failed", [])
        return {
            "source": "MXToolbox",
            "blacklists": len(failed),
            "verdict": "listed" if failed else "clean",
            "details": [f.get("Name", "-") for f in failed[:5]],
        }
    except urllib.error.HTTPError as e:
        return {"source": "MXToolbox", "error": "HTTP {}".format(e.code)}
    except Exception as e:
        return {"source": "MXToolbox", "error": str(e)[:100]}

def enrich_indicator(indicator, itype=None):
    """Tum aktif kaynaklara sorgu atar, sonuclari toplar."""
    if itype is None:
        itype = detect_indicator_type(indicator)
    results = []
    for fn in (query_virustotal, query_abuseipdb, query_urlscan, query_shodan, query_mxtoolbox):
        try:
            r = fn(indicator, itype)
            if r is not None:
                results.append(r)
        except Exception as e:
            results.append({"source": fn.__name__, "error": str(e)[:100]})
    return itype, results


UMBRELLA_AUTH  = "https://api.umbrella.com/auth/v2/token"
UMBRELLA_API   = "https://api.umbrella.com"
UMBRELLA_LIST_NAME = "IoCManager Blacklist"

def _get_ssl_context():
    """
    Sistem varsayilan sertifika deposunu (Windows/Linux root CA'lari) yukler.
    IOCMANAGER_CA_BUNDLE tanimliysa, o sertifikalari EK olarak yukler -
    sistem deposunun yerine gecmez. Boylece hem genel HTTPS servisleri
    (VirusTotal, AbuseIPDB, URLScan vb.) hem de ozel/kurumsal sertifika
    gerektiren servisler (Umbrella, TippingPoint) ayni anda calisir.
    """
    import ssl
    ctx = ssl.create_default_context()  # sistem varsayilan deposu (her zaman yuklu)
    ca_bundle = os.environ.get("IOCMANAGER_CA_BUNDLE")
    if ca_bundle and os.path.exists(ca_bundle):
        try:
            ctx.load_verify_locations(cafile=ca_bundle)  # ek sertifikalari EKLER
        except Exception:
            pass
    return ctx

def umbrella_enabled():
    return (get_setting("umbrella_enabled") == "1"
            and bool(get_setting("umbrella_key"))
            and bool(get_setting("umbrella_secret")))

def umbrella_get_token():
    """API Key+Secret ile OAuth2 client_credentials token alir."""
    import base64
    key    = get_setting("umbrella_key")
    secret = get_setting("umbrella_secret")
    if not key or not secret:
        return None
    creds = base64.b64encode("{}:{}".format(key, secret).encode()).decode()
    data  = urllib.parse.urlencode({"grant_type": "client_credentials"}).encode()
    req = urllib.request.Request(UMBRELLA_AUTH, data=data, headers={
        "Authorization": "Basic " + creds,
        "Content-Type": "application/x-www-form-urlencoded",
    }, method="POST")
    with urllib.request.urlopen(req, timeout=10, context=_get_ssl_context()) as resp:
        return json.loads(resp.read().decode()).get("access_token")

def _umbrella_req(method, path, token, body=None):
    url = UMBRELLA_API + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15, context=_get_ssl_context()) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        # Hata govdesini oku ve mesaja ekle
        try:
            err_body = e.read().decode()
        except Exception:
            err_body = ""
        raise urllib.error.HTTPError(e.url, e.code,
            "{} - {}".format(e.reason, err_body[:200]), e.headers, None)

def umbrella_get_or_create_list(token):
    """IoCManager listesini bulur, yoksa olusturur. List ID doner."""
    # Kayitli ID varsa once onu dogrula
    saved_id = get_setting("umbrella_list_id")
    # Tum listeleri cek
    data = _umbrella_req("GET", "/policies/v2/destinationlists", token)
    for lst in data.get("data", []):
        if str(lst.get("id")) == str(saved_id):
            return saved_id
        if lst.get("name") == UMBRELLA_LIST_NAME:
            set_setting("umbrella_list_id", str(lst.get("id")))
            return str(lst.get("id"))
    # Yoksa olustur (block tipi)
    created = _umbrella_req("POST", "/policies/v2/destinationlists", token, {
        "name": UMBRELLA_LIST_NAME,
        "access": "block",
        "isGlobal": False,
        "bundleTypeId": 1,
    })
    new_id = str(created.get("data", {}).get("id", ""))
    if new_id:
        set_setting("umbrella_list_id", new_id)
    return new_id

def umbrella_add_domain(domain):
    """Domaini IoCManager Destination List'ine ekler."""
    try:
        token = umbrella_get_token()
        if not token:
            return False, "Token alinamadi"
        list_id = umbrella_get_or_create_list(token)
        if not list_id:
            return False, "Liste olusturulamadi"
        _umbrella_req("POST", "/policies/v2/destinationlists/{}/destinations".format(list_id),
                      token, [{"destination": domain, "type": "domain"}])
        return True, "OK"
    except urllib.error.HTTPError as e:
        return False, "HTTP {} - {}".format(e.code, e.reason)[:180]
    except Exception as e:
        return False, str(e)[:150]

def umbrella_remove_domain(domain):
    """Domaini Destination List'ten siler."""
    try:
        token = umbrella_get_token()
        if not token:
            return False, "Token alinamadi"
        list_id = get_setting("umbrella_list_id")
        if not list_id:
            return False, "Liste ID yok"
        # Once domain'in destination ID'sini bul
        data = _umbrella_req("GET",
            "/policies/v2/destinationlists/{}/destinations?limit=100".format(list_id), token)
        dest_id = None
        for d in data.get("data", []):
            if d.get("destination", "").lower() == domain.lower():
                dest_id = d.get("id")
                break
        if dest_id is None:
            return True, "Zaten yok"
        _umbrella_req("DELETE",
            "/policies/v2/destinationlists/{}/destinations/remove".format(list_id),
            token, [int(dest_id)])
        return True, "OK"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True, "Zaten yok"
        return False, "HTTP {}".format(e.code)
    except Exception as e:
        return False, str(e)[:100]

def umbrella_sync_all():
    """Mevcut blacklist-domain'i komple Umbrella listesine iter (tek token ile)."""
    try:
        token = umbrella_get_token()
        if not token:
            return 0, ["Token alinamadi"]
        list_id = umbrella_get_or_create_list(token)
        if not list_id:
            return 0, ["Liste olusturulamadi"]
        domains = read_feed("blacklist-domain")
        # wildcard temizle, batch halinde ekle (Umbrella tek istekte coklu kabul eder)
        batch = [{"destination": (d[2:] if d.startswith("*.") else d), "type": "domain"} for d in domains]
        if not batch:
            return 0, []
        # 500'luk gruplar halinde gonder
        ok_count = 0
        fail = []
        for i in range(0, len(batch), 500):
            chunk = batch[i:i+500]
            try:
                _umbrella_req("POST",
                    "/policies/v2/destinationlists/{}/destinations".format(list_id), token, chunk)
                ok_count += len(chunk)
            except Exception as e:
                fail.append(str(e)[:80])
        return ok_count, fail
    except Exception as e:
        return 0, [str(e)[:100]]

# ── Trend Micro TippingPoint SMS Reputation Database ──────────────────────────
def _tippingpoint_ssl_context():
    if get_setting("tippingpoint_skip_ssl_verify") == "1":
        import ssl
        return ssl._create_unverified_context()
    return _get_ssl_context()

def tippingpoint_enabled():
    return (get_setting("tippingpoint_enabled") == "1"
            and bool(get_setting("tippingpoint_server"))
            and bool(get_setting("tippingpoint_api_key")))

def _tippingpoint_request(path, params=None, method="GET"):
    server  = get_setting("tippingpoint_server").rstrip("/")
    api_key = get_setting("tippingpoint_api_key")
    if not server or not api_key:
        raise RuntimeError("SMS sunucu adresi veya API Key eksik")
    query = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = "https://{}/{}{}".format(server, path.lstrip("/"), query)
    req = urllib.request.Request(url, method=method, headers={"X-SMS-API-KEY": api_key})
    with urllib.request.urlopen(req, timeout=15, context=_tippingpoint_ssl_context()) as resp:
        return resp.read().decode("utf-8", errors="replace")

# Reputation DB API sadece ip/dns/url destekler - hash icin parametre yok
_TPT_TYPE_PARAM = {"ip": "ip", "domain": "dns", "url": "url"}

def tippingpoint_add_entry(entry, itype):
    param = _TPT_TYPE_PARAM.get(itype)
    if not param:
        return False, "Desteklenmeyen tip (sadece ip/domain/url)"
    params = {param: entry}
    tag_cat = get_setting("tippingpoint_tag_category").strip()
    tag_val = get_setting("tippingpoint_tag_value").strip()
    # TagData opsiyonel - ikisi de doluysa gonder, degilse sade IP/domain/url eklenir
    if tag_cat and tag_val:
        params["TagData"] = "{},{}".format(tag_cat, tag_val)
    try:
        raw = _tippingpoint_request("/repEntries/add", params)
        return True, raw.strip()[:150] if raw else "OK"
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return False, "HTTP {} - {}".format(e.code, body[:150])
    except Exception as e:
        return False, str(e)[:150]

def tippingpoint_remove_entry(entry, itype):
    param = _TPT_TYPE_PARAM.get(itype)
    if not param:
        return False, "Desteklenmeyen tip"
    params = {param: entry, "criteria": "entry"}
    try:
        _tippingpoint_request("/repEntries/delete", params)
        return True, "OK"
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return False, "HTTP {} - {}".format(e.code, body[:150])
    except Exception as e:
        return False, str(e)[:150]

def tippingpoint_sync_all():
    """Mevcut blacklist-ip'yi SMS Reputation DB'ye iter (sadece IP - domain/URL desteklenmiyor)."""
    ok_count = 0
    fail = []
    for entry in read_feed("blacklist-ip"):
        success, msg = tippingpoint_add_entry(entry, "ip")
        if success:
            ok_count += 1
        else:
            fail.append("{} ({})".format(entry, msg))
    return ok_count, fail

def tippingpoint_feed_itype(feed):
    """TippingPoint entegrasyonu sadece blacklist-ip'yi destekler."""
    return {"blacklist-ip": "ip"}.get(feed)


def validate_ip(ip_str):
    try:
        ipaddress.ip_network(ip_str.strip(), strict=False)
        return True
    except ValueError:
        return False

def is_private_ip(ip_str):
    """Private/ozel IP mi? allow ve block listeye eklenmesi engellenir."""
    try:
        net = ipaddress.ip_network(ip_str.strip(), strict=False)
        for private in PRIVATE_NETWORKS:
            if net.version == private.version and net.subnet_of(private):
                return True
        return False
    except ValueError:
        return False

def validate_hash(hash_str):
    h = hash_str.strip().lower()
    return bool(re.match(r'^[0-9a-f]+$', h)) and len(h) in HASH_LENGTHS

def detect_hash_type(hash_str):
    return HASH_LENGTHS.get(len(hash_str.strip().lower()), "UNKNOWN")

def normalize_hash(hash_str):
    return hash_str.strip().lower()

def normalize_domain(domain_str):
    d = domain_str.strip().lower()
    # protokol varsa kaldir
    d = re.sub(r'^https?://', '', d)
    d = d.rstrip('/')
    return d

def validate_domain(domain_str):
    """Domain veya wildcard (*.example.com) dogrula."""
    d = normalize_domain(domain_str)
    if not d or len(d) > 253:
        return False
    # wildcard destegi: *.example.com
    if d.startswith("*."):
        d = d[2:]
    # temel domain regex
    pattern = r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    return bool(re.match(pattern, d))

def normalize_url(url_str):
    u = url_str.strip()
    # protokol yoksa http ekle
    if not re.match(r'^https?://', u, re.IGNORECASE):
        u = "http://" + u
    return u

def validate_url(url_str):
    u = normalize_url(url_str)
    try:
        parsed = urllib.parse.urlparse(u)
        return bool(parsed.netloc) and bool(re.match(r'^[a-z0-9.\-:]+$', parsed.netloc, re.IGNORECASE))
    except Exception:
        return False

def process_entry(feed, entry):
    """
    Feed turune gore entry'yi normalize ve validate eder.
    Donus: (ok, normalized_entry, reason)
    reason: 'ok' | 'invalid' | 'private'
    """
    entry = entry.strip()
    if not entry:
        return False, entry, "invalid"

    if feed in HASH_FEEDS:
        entry = normalize_hash(entry)
        return (validate_hash(entry), entry, "ok" if validate_hash(entry) else "invalid")

    if feed in DOMAIN_FEEDS:
        entry = normalize_domain(entry)
        return (validate_domain(entry), entry, "ok" if validate_domain(entry) else "invalid")

    if feed in URL_FEEDS:
        entry = normalize_url(entry)
        return (validate_url(entry), entry, "ok" if validate_url(entry) else "invalid")

    # IP feed
    if not validate_ip(entry):
        return False, entry, "invalid"
    if is_private_ip(entry):
        return False, entry, "private"
    return True, entry, "ok"

def sanitize_text(text, max_len=200):
    import re
    return re.sub(r"[<>\"'%;()&+]", "", str(text))[:max_len]

def read_feed(feed_name):
    path = FEED_FILES.get(feed_name)
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def write_feed(feed_name, entries):
    path = FEED_FILES.get(feed_name)
    if not path:
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# IoCManager - Auto-generated\n")
        f.write("# Last updated: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        f.write("# Total entries: {}\n\n".format(len(entries)))
        for entry in sorted(entries):
            f.write(entry + "\n")
    return True

def parse_csv_ips(text):
    ips = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        for cell in row:
            cell = cell.strip().strip('"').strip("'")
            if cell and not cell.lower().startswith(("ip", "#", "address")):
                ips.append(cell)
    if not ips:
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.append(line)
    return ips

# ── Auth decorators ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Bu sayfaya erisim yetkiniz yok.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

# ── Routes: Auth ──────────────────────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = sanitize_text(request.form.get("username", "").strip(), 64)
        password = request.form.get("password", "")
        if is_locked(username):
            error = "Hesap gecici olarak kilitlendi. {} dk sonra tekrar deneyin.".format(LOCKOUT_MINUTES)
        else:
            db   = get_db()
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and verify_password(user["password"], password):
                reset_failed(username)
                session.clear()
                session["username"] = user["username"]
                session["role"]     = user["role"]
                session.permanent   = False
                log_action(username, "LOGIN", "-", "-", "Basarili giris", request.remote_addr)
                return redirect(url_for("dashboard"))
            else:
                if user:
                    record_failed(username)
                log_action(username, "LOGIN_FAIL", "-", "-", "Basarisiz giris", request.remote_addr)
                error = "Kullanici adi veya sifre hatali."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── Routes: Dashboard ─────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    feeds = {name: read_feed(name) for name in FEED_FILES}
    return render_template("dashboard.html", feeds=feeds,
                           username=session["username"], role=session["role"])

# ── Routes: Add / Remove ──────────────────────────────────────────────────────
@app.route("/add", methods=["POST"])
@login_required
def add_ip():
    validate_csrf()
    feed      = request.form.get("feed", "")
    ip_raw    = request.form.get("ip", "").strip()
    note      = sanitize_text(request.form.get("note", "").strip())
    client_ip = request.remote_addr

    if feed not in FEED_FILES:
        flash("Gecersiz feed.", "error")
        return redirect(url_for("dashboard"))

    entries_to_add = [x.strip() for x in ip_raw.splitlines() if x.strip()]
    if not entries_to_add:
        flash("Deger bos birakilamaz.", "error")
        return redirect(url_for("dashboard"))

    current = set(read_feed(feed))
    added, skipped_invalid, skipped_dup, skipped_private = [], [], [], []

    for raw in entries_to_add:
        ok, entry, reason = process_entry(feed, raw)
        if not ok:
            if reason == "private":
                skipped_private.append(entry)
            else:
                skipped_invalid.append(entry)
            continue
        if entry in current:
            skipped_dup.append(entry)
            continue
        current.add(entry)
        added.append(entry)

    if added:
        write_feed(feed, list(current))
        for entry in added:
            log_action(session["username"], "ADD", feed, entry, note, client_ip)
        flash("{} kayit eklendi.".format(len(added)), "success")
        # Umbrella otomatik sync (sadece blacklist-domain)
        if feed == "blacklist-domain" and umbrella_enabled() and get_setting("umbrella_auto_sync") == "1":
            u_ok, u_msg = 0, ""
            for entry in added:
                clean = entry[2:] if entry.startswith("*.") else entry
                success, msg = umbrella_add_domain(clean)
                if success: u_ok += 1
                else: u_msg = msg
            if u_ok:
                flash("{} domain Umbrella'ya gonderildi.".format(u_ok), "success")
            if u_msg:
                flash("Umbrella hatasi: {}".format(u_msg), "warning")
        # TippingPoint SMS otomatik sync (blacklist-ip, blacklist-domain, blacklist-url)
        tpt_itype = tippingpoint_feed_itype(feed)
        if tpt_itype and tippingpoint_enabled() and get_setting("tippingpoint_auto_sync") == "1":
            t_ok, t_msg = 0, ""
            for entry in added:
                clean = entry[2:] if (tpt_itype == "domain" and entry.startswith("*.")) else entry
                success, msg = tippingpoint_add_entry(clean, tpt_itype)
                if success: t_ok += 1
                else: t_msg = msg
            if t_ok:
                flash("{} kayit TippingPoint SMS'e gonderildi.".format(t_ok), "success")
            if t_msg:
                flash("TippingPoint hatasi: {}".format(t_msg), "warning")
    if skipped_private:
        flash("{} private/ozel IP engellendi (eklenemez): {}".format(
            len(skipped_private), ", ".join(skipped_private[:5])), "error")
    if skipped_invalid:
        flash("{} gecersiz format atlandi.".format(len(skipped_invalid)), "warning")
    if skipped_dup:
        flash("{} duplicate atlandi.".format(len(skipped_dup)), "warning")

    return redirect(url_for("dashboard"))

# ── Smart Add: otomatik tip algila + dogru feed'e dagit ───────────────────────
@app.route("/smart-add", methods=["POST"])
@login_required
def smart_add():
    validate_csrf()
    raw_text  = request.form.get("indicators", "").strip()
    direction = request.form.get("direction", "blacklist")  # allowlist | blacklist
    note      = sanitize_text(request.form.get("note", "").strip())
    client_ip = request.remote_addr

    if direction not in ("allowlist", "blacklist"):
        direction = "blacklist"

    lines = [x.strip() for x in raw_text.splitlines() if x.strip()]
    if not lines:
        flash("Deger bos birakilamaz.", "error")
        return redirect(url_for("dashboard"))

    # tip -> feed eslesmesi
    def resolve_feed(itype):
        if itype == "hash":
            return "blacklist-hash"  # hash sadece blacklist
        if itype == "ip":
            return "{}-ip".format(direction)
        if itype == "domain":
            return "{}-domain".format(direction)
        if itype == "url":
            return "{}-url".format(direction)
        return None

    # her satiri tipine gore grupla
    buckets = {}          # feed -> set(entries)
    unknown = []
    private_blocked = []
    invalid = []

    for line in lines:
        itype = detect_indicator_type(line)
        feed  = resolve_feed(itype)
        if not feed:
            unknown.append(line)
            continue
        ok, entry, reason = process_entry(feed, line)
        if not ok:
            if reason == "private":
                private_blocked.append(entry)
            else:
                invalid.append(entry)
            continue
        buckets.setdefault(feed, set()).add(entry)

    # her feed'e yaz
    total_added = 0
    per_feed_summary = []
    dup_total = 0
    umbrella_domains = []
    tpt_new_by_feed = {}  # feed -> [entries] (blacklist-ip/domain/url icin)
    for feed, entries in buckets.items():
        current = set(read_feed(feed))
        new_entries = [e for e in entries if e not in current]
        dup_total += len(entries) - len(new_entries)
        if new_entries:
            current.update(new_entries)
            write_feed(feed, list(current))
            for e in new_entries:
                log_action(session["username"], "ADD", feed, e, note, client_ip)
            total_added += len(new_entries)
            per_feed_summary.append("{}: {}".format(feed, len(new_entries)))
            if feed == "blacklist-domain":
                umbrella_domains.extend(new_entries)
            if tippingpoint_feed_itype(feed):
                tpt_new_by_feed[feed] = new_entries

    # Umbrella otomatik sync
    if umbrella_domains and umbrella_enabled() and get_setting("umbrella_auto_sync") == "1":
        u_ok = 0
        for entry in umbrella_domains:
            clean = entry[2:] if entry.startswith("*.") else entry
            success, _ = umbrella_add_domain(clean)
            if success: u_ok += 1
        if u_ok:
            flash("{} domain Umbrella'ya gonderildi.".format(u_ok), "success")

    # TippingPoint SMS otomatik sync
    if tpt_new_by_feed and tippingpoint_enabled() and get_setting("tippingpoint_auto_sync") == "1":
        t_ok = 0
        for feed, entries in tpt_new_by_feed.items():
            itype = tippingpoint_feed_itype(feed)
            for entry in entries:
                clean = entry[2:] if (itype == "domain" and entry.startswith("*.")) else entry
                success, _ = tippingpoint_add_entry(clean, itype)
                if success: t_ok += 1
        if t_ok:
            flash("{} kayit TippingPoint SMS'e gonderildi.".format(t_ok), "success")

    if total_added:
        flash("{} kayit eklendi ({})".format(total_added, ", ".join(per_feed_summary)), "success")
    if dup_total:
        flash("{} duplicate atlandi.".format(dup_total), "warning")
    if private_blocked:
        flash("{} private/ozel IP engellendi: {}".format(
            len(private_blocked), ", ".join(private_blocked[:5])), "error")
    if invalid:
        flash("{} gecersiz format atlandi.".format(len(invalid)), "warning")
    if unknown:
        flash("{} satir taninmadi (IP/domain/URL/hash degil): {}".format(
            len(unknown), ", ".join(unknown[:5])), "warning")

    return redirect(url_for("dashboard"))

# ── Canli tip algilama (JS icin JSON) ─────────────────────────────────────────
@app.route("/detect", methods=["POST"])
@login_required
def detect_types():
    raw_text = request.form.get("indicators", "")
    lines = [x.strip() for x in raw_text.splitlines() if x.strip()]
    counts = {"ip": 0, "domain": 0, "url": 0, "hash": 0, "unknown": 0}
    for line in lines:
        counts[detect_indicator_type(line)] = counts.get(detect_indicator_type(line), 0) + 1
    return jsonify(counts)

@app.route("/remove", methods=["POST"])
@login_required
def remove_ip():
    validate_csrf()
    feed      = request.form.get("feed", "")
    entry     = request.form.get("ip", "").strip()
    note      = sanitize_text(request.form.get("note", "").strip())
    client_ip = request.remote_addr

    if feed not in FEED_FILES:
        flash("Gecersiz istek.", "error")
        return redirect(url_for("dashboard"))

    # feed turune gore normalize et (silmede private kontrolu yok, zaten listede)
    if feed in HASH_FEEDS:
        entry = normalize_hash(entry)
    elif feed in DOMAIN_FEEDS:
        entry = normalize_domain(entry)
    elif feed in URL_FEEDS:
        entry = normalize_url(entry)

    current = set(read_feed(feed))
    if entry not in current:
        flash("{} listede bulunamadi.".format(entry), "warning")
        return redirect(url_for("dashboard"))

    current.discard(entry)
    write_feed(feed, list(current))
    log_action(session["username"], "REMOVE", feed, entry, note, client_ip)
    flash("{} listeden cikarildi.".format(entry), "success")

    # Umbrella'dan da sil (blacklist-domain)
    if feed == "blacklist-domain" and umbrella_enabled() and get_setting("umbrella_auto_sync") == "1":
        clean = entry[2:] if entry.startswith("*.") else entry
        success, msg = umbrella_remove_domain(clean)
        if success:
            flash("Domain Umbrella'dan da silindi.", "success")
        else:
            flash("Umbrella'dan silinemedi: {}".format(msg), "warning")

    # TippingPoint SMS'ten de sil
    tpt_itype = tippingpoint_feed_itype(feed)
    if tpt_itype and tippingpoint_enabled() and get_setting("tippingpoint_auto_sync") == "1":
        clean = entry[2:] if (tpt_itype == "domain" and entry.startswith("*.")) else entry
        success, msg = tippingpoint_remove_entry(clean, tpt_itype)
        if success:
            flash("Kayit TippingPoint SMS'ten de silindi.", "success")
        else:
            flash("TippingPoint'ten silinemedi: {}".format(msg), "warning")

    return redirect(url_for("dashboard"))

# ── Routes: CSV Import ────────────────────────────────────────────────────────
@app.route("/import", methods=["GET", "POST"])
@login_required
def csv_import():
    if request.method == "POST":
        validate_csrf()
        feed      = request.form.get("feed", "")
        note      = sanitize_text(request.form.get("note", "CSV import").strip())
        client_ip = request.remote_addr

        if feed not in FEED_FILES:
            flash("Gecersiz feed.", "error")
            return redirect(url_for("csv_import"))

        # Dosya yukleme veya metin
        raw_text = ""
        uploaded = request.files.get("csv_file")
        if uploaded and uploaded.filename:
            raw_text = uploaded.read().decode("utf-8", errors="ignore")
        else:
            raw_text = request.form.get("csv_text", "").strip()

        if not raw_text:
            flash("Dosya veya metin bos.", "error")
            return redirect(url_for("csv_import"))

        candidates = parse_csv_ips(raw_text)
        current    = set(read_feed(feed))
        added, skipped_invalid, skipped_dup, skipped_private = [], [], [], []

        for raw in candidates:
            ok, entry, reason = process_entry(feed, raw)
            if not ok:
                if reason == "private":
                    skipped_private.append(entry)
                else:
                    skipped_invalid.append(entry)
                continue
            if entry in current:
                skipped_dup.append(entry)
                continue
            current.add(entry)
            added.append(entry)

        if added:
            write_feed(feed, list(current))
            for entry in added:
                log_action(session["username"], "ADD", feed, entry, note, client_ip)
            flash("{} kayit eklendi.".format(len(added)), "success")
        if skipped_private:
            flash("{} private/ozel IP engellendi.".format(len(skipped_private)), "error")
        if skipped_invalid:
            flash("{} gecersiz satir atlandi.".format(len(skipped_invalid)), "warning")
        if skipped_dup:
            flash("{} duplicate atlandi.".format(len(skipped_dup)), "warning")

        return redirect(url_for("dashboard"))

    return render_template("import.html",
                           username=session["username"], role=session["role"])

# ── Routes: Audit ─────────────────────────────────────────────────────────────
@app.route("/audit")
@login_required
@admin_required
def audit():
    page          = max(1, int(request.args.get("page", 1)))
    per_page      = 50
    offset        = (page - 1) * per_page
    feed_filter   = request.args.get("feed", "")
    action_filter = request.args.get("action", "")

    query  = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    if feed_filter in FEED_FILES:
        query += " AND feed=?"; params.append(feed_filter)
    if action_filter in ("ADD", "REMOVE", "LOGIN", "LOGIN_FAIL", "LOCKOUT"):
        query += " AND action=?"; params.append(action_filter)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [per_page, offset]

    db    = get_db()
    logs  = db.execute(query, params).fetchall()
    total = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]

    return render_template("audit.html", logs=logs, page=page,
                           per_page=per_page, total=total,
                           feed_filter=feed_filter, action_filter=action_filter,
                           username=session["username"], role=session["role"],
                           feeds=list(FEED_FILES.keys()))

# ── Routes: Users ─────────────────────────────────────────────────────────────
@app.route("/users", methods=["GET", "POST"])
@login_required
@admin_required
def users():
    if request.method == "POST":
        validate_csrf()
        action   = request.form.get("action")
        username = sanitize_text(request.form.get("username", "").strip(), 64)

        if action == "add":
            password = request.form.get("password", "")
            role     = request.form.get("role", "operator")
            if role not in ("admin", "operator"):
                flash("Gecersiz rol.", "error")
            elif len(password) < 8:
                flash("Sifre en az 8 karakter olmali.", "error")
            else:
                try:
                    db = get_db()
                    db.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                               (username, hash_password(password), role))
                    db.commit()
                    flash("Kullanici '{}' olusturuldu.".format(username), "success")
                except sqlite3.IntegrityError:
                    flash("Bu kullanici adi zaten mevcut.", "error")
        elif action == "delete":
            if username == session["username"]:
                flash("Kendi hesabinizi silemezsiniz.", "error")
            else:
                db = get_db()
                db.execute("DELETE FROM users WHERE username=?", (username,))
                db.commit()
                flash("Kullanici '{}' silindi.".format(username), "success")

    db        = get_db()
    user_list = db.execute("SELECT id, username, role, failed_attempts, locked_until FROM users").fetchall()
    return render_template("users.html", users=user_list,
                           username=session["username"], role=session["role"])

@app.route("/unlock/<username>", methods=["POST"])
@login_required
@admin_required
def unlock_user(username):
    validate_csrf()
    db = get_db()
    db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
    db.commit()
    flash("'{}' hesabinin kilidi acildi.".format(username), "success")
    return redirect(url_for("users"))

# ── Routes: Change Password ───────────────────────────────────────────────────
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        validate_csrf()
        current = request.form.get("current_password", "")
        new_pw  = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        db      = get_db()
        user    = db.execute("SELECT * FROM users WHERE username=?", (session["username"],)).fetchone()
        if not verify_password(user["password"], current):
            flash("Mevcut sifre hatali.", "error")
        elif len(new_pw) < 8:
            flash("Yeni sifre en az 8 karakter olmali.", "error")
        elif new_pw != confirm:
            flash("Sifreler uyusmuyor.", "error")
        else:
            db.execute("UPDATE users SET password=? WHERE username=?",
                       (hash_password(new_pw), session["username"]))
            db.commit()
            flash("Sifre basariyla degistirildi.", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html",
                           username=session["username"], role=session["role"])

# ── Routes: Threat Intel Sorgu ────────────────────────────────────────────────
@app.route("/enrich", methods=["GET", "POST"])
@login_required
def enrich():
    result = None
    indicator = ""
    itype = ""
    if request.method == "POST":
        validate_csrf()
        indicator = request.form.get("indicator", "").strip()
        if indicator:
            itype, results = enrich_indicator(indicator)
            result = results
            log_action(session["username"], "ENRICH", "-", indicator,
                       "Threat intel sorgu ({})".format(itype), request.remote_addr)

    active_sources = []
    for name, key in [("VirusTotal", "api_virustotal"), ("AbuseIPDB", "api_abuseipdb"),
                      ("URLScan", "api_urlscan"), ("Shodan", "api_shodan"), ("MXToolbox", "api_mxtoolbox")]:
        active_sources.append({"name": name, "active": bool(get_setting(key))})

    return render_template("enrich.html", result=result, indicator=indicator,
                           itype=itype, active_sources=active_sources,
                           username=session["username"], role=session["role"])

# ── Routes: SIEM Settings ─────────────────────────────────────────────────────
@app.route("/settings", methods=["GET", "POST"])
@login_required
@admin_required
def settings():
    test_result = None
    if request.method == "POST":
        validate_csrf()
        action = request.form.get("action")

        if action == "save":
            set_setting("siem_enabled",  "1" if request.form.get("siem_enabled") else "0")
            set_setting("siem_host",     sanitize_text(request.form.get("siem_host", "").strip(), 255))
            set_setting("siem_port",     request.form.get("siem_port", "514").strip())
            set_setting("siem_protocol", request.form.get("siem_protocol", "UDP"))
            set_setting("siem_cef_file", "1" if request.form.get("siem_cef_file") else "0")
            flash("SIEM ayarlari kaydedildi.", "success")

        elif action == "test":
            host     = sanitize_text(request.form.get("siem_host", "").strip(), 255)
            port     = int(request.form.get("siem_port", "514").strip())
            protocol = request.form.get("siem_protocol", "UDP")
            test_cef = build_cef("TEST", session["username"], "-", "0.0.0.0",
                                 "IoCManager baglanti testi", request.remote_addr)
            try:
                msg = (test_cef + "\n").encode("utf-8")
                if protocol == "TCP":
                    with socket.create_connection((host, port), timeout=5) as s:
                        s.sendall(msg)
                else:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(msg, (host, port))
                test_result = ("success", "{}:{} ({}) adresine basariyla gonderildi.".format(host, port, protocol))
            except Exception as e:
                test_result = ("error", "Hata: {}".format(str(e)))

    cfg = get_all_settings()
    return render_template("settings.html", cfg=cfg, test_result=test_result,
                           username=session["username"], role=session["role"],
                           log_path=LOG_PATH)

# ── Routes: Entegrasyonlar (Umbrella, TippingPoint) ───────────────────────────
@app.route("/integrations", methods=["GET", "POST"])
@login_required
@admin_required
def integrations():
    if request.method == "POST":
        validate_csrf()
        action = request.form.get("action")

        if action == "save_api":
            for k in ("api_virustotal", "api_abuseipdb", "api_urlscan", "api_shodan", "api_mxtoolbox"):
                val = request.form.get(k, "").strip()
                set_setting(k, val)
            set_setting("urlscan_live", "1" if request.form.get("urlscan_live") else "0")
            flash("Threat Intel API ayarlari kaydedildi.", "success")

        elif action == "save_umbrella":
            set_setting("umbrella_enabled",   "1" if request.form.get("umbrella_enabled") else "0")
            set_setting("umbrella_key",       request.form.get("umbrella_key", "").strip())
            secret = request.form.get("umbrella_secret", "").strip()
            if secret:  # bos gelirse mevcut secret'i koru
                set_setting("umbrella_secret", secret)
            set_setting("umbrella_auto_sync", "1" if request.form.get("umbrella_auto_sync") else "0")
            flash("Umbrella ayarlari kaydedildi.", "success")

        elif action == "umbrella_test":
            try:
                token = umbrella_get_token()
                if token:
                    flash("Umbrella baglantisi basarili (token alindi).", "success")
                else:
                    flash("Token alinamadi - key/secret kontrol edin.", "error")
            except Exception as e:
                flash("Umbrella baglanti hatasi: {}".format(str(e)[:100]), "error")

        elif action == "umbrella_sync":
            if not umbrella_enabled():
                flash("Umbrella aktif degil veya API key yok.", "error")
            else:
                ok_count, fail = umbrella_sync_all()
                flash("{} domain Umbrella'ya senkronize edildi.".format(ok_count), "success")
                if fail:
                    flash("{} domain gonderilemedi: {}".format(len(fail), ", ".join(fail[:5])), "warning")

        elif action == "save_tippingpoint":
            set_setting("tippingpoint_enabled", "1" if request.form.get("tippingpoint_enabled") else "0")
            set_setting("tippingpoint_server", sanitize_text(request.form.get("tippingpoint_server", "").strip(), 255))
            api_key = request.form.get("tippingpoint_api_key", "").strip()
            if api_key:  # bos gelirse mevcut key korunur
                set_setting("tippingpoint_api_key", api_key)
            set_setting("tippingpoint_tag_category", sanitize_text(request.form.get("tippingpoint_tag_category", "").strip(), 100))
            set_setting("tippingpoint_tag_value", sanitize_text(request.form.get("tippingpoint_tag_value", "").strip(), 100))
            set_setting("tippingpoint_skip_ssl_verify", "1" if request.form.get("tippingpoint_skip_ssl_verify") else "0")
            set_setting("tippingpoint_auto_sync", "1" if request.form.get("tippingpoint_auto_sync") else "0")
            flash("TippingPoint SMS ayarlari kaydedildi.", "success")

        elif action == "tippingpoint_test":
            try:
                result_text = _tippingpoint_request("/dbAccess/tptDBServlet", {"method": "Status"})
                flash("TippingPoint baglantisi basarili: {}".format(result_text.strip()[:100]), "success")
            except Exception as e:
                flash("TippingPoint baglanti hatasi: {}".format(str(e)[:150]), "error")

        elif action == "tippingpoint_sync":
            if not tippingpoint_enabled():
                flash("TippingPoint aktif degil veya sunucu/API key eksik.", "error")
            else:
                ok_count, fail = tippingpoint_sync_all()
                flash("{} kayit TippingPoint SMS'e senkronize edildi.".format(ok_count), "success")
                if fail:
                    flash("{} kayit gonderilemedi: {}".format(len(fail), ", ".join(fail[:5])), "warning")

    cfg = get_all_settings()
    return render_template("integrations.html", cfg=cfg,
                           username=session["username"], role=session["role"])

# ── Routes: Sistem Izleme ──────────────────────────────────────────────────────
@app.route("/monitor")
@login_required
@admin_required
def monitor():
    log_dir = os.path.dirname(LOG_PATH)
    available_logs = []
    if os.path.isdir(log_dir):
        available_logs = sorted(f for f in os.listdir(log_dir) if f.endswith(".log"))

    selected_log = request.args.get("log", "")
    if selected_log not in available_logs:
        selected_log = available_logs[0] if available_logs else ""

    try:
        lines = int(request.args.get("lines", 200))
    except ValueError:
        lines = 200
    lines = max(50, min(lines, 1000))

    log_content = None
    log_mtime = None
    if selected_log:
        log_path = os.path.join(log_dir, selected_log)
        log_content = tail_file(log_path, n=lines)
        try:
            log_mtime = datetime.fromtimestamp(os.path.getmtime(log_path)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

    service_state = get_service_status()
    uptime_str     = format_uptime(datetime.now() - APP_START_TIME)

    # Feed dosyalarinin durumu
    feed_status = []
    for name, path in FEED_FILES.items():
        if os.path.exists(path):
            st = os.stat(path)
            feed_status.append({
                "name": name, "exists": True,
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "entries": len(read_feed(name)),
            })
        else:
            feed_status.append({"name": name, "exists": False})

    # Veritabani saglik kontrolu
    db_ok = True
    db_size = None
    try:
        get_db().execute("SELECT 1").fetchone()
        if os.path.exists(DB_PATH):
            db_size = os.path.getsize(DB_PATH)
    except Exception:
        db_ok = False

    # Son 24 saat aktivite ozeti
    db = get_db()
    since = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    rows = db.execute(
        "SELECT action, COUNT(*) as c FROM audit_log WHERE timestamp >= ? GROUP BY action",
        (since,)
    ).fetchall()
    activity_24h = {r["action"]: r["c"] for r in rows}

    return render_template("monitor.html",
        username=session["username"], role=session["role"],
        service_state=service_state, uptime_str=uptime_str,
        app_start_time=APP_START_TIME.strftime("%Y-%m-%d %H:%M:%S"),
        feed_status=feed_status, db_ok=db_ok, db_size=db_size, db_path=DB_PATH,
        available_logs=available_logs, selected_log=selected_log,
        log_content=log_content, log_mtime=log_mtime, lines=lines,
        activity_24h=activity_24h,
        siem_enabled=(get_setting("siem_enabled") == "1"),
        umbrella_active=umbrella_enabled(),
    )

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)

init_db()
