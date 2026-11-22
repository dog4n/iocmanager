import os
import sys
import csv
import io
import json
import re
import socket
import ssl
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
import time
import threading
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
BASE_DIR   = r"C:\ThreatFeed\public"
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
    CREATE TABLE IF NOT EXISTS fortigate_devices (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT NOT NULL,
        host       TEXT NOT NULL,
        port       INTEGER NOT NULL DEFAULT 443,
        method     TEXT NOT NULL DEFAULT 'api',
        username   TEXT,
        password   TEXT,
        token      TEXT,
        verify_ssl INTEGER NOT NULL DEFAULT 0,
        enabled    INTEGER NOT NULL DEFAULT 1,
        created_at TEXT
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
        # Cloudflare Rules Lists (IP list)
        "cloudflare_enabled":    "0",
        "cloudflare_token":      "",
        "cloudflare_account_id": "",
        "cloudflare_list_id":    "",
        "cloudflare_auto_sync":  "0",
        "cloudflare_allow_list_id": "",
        "cloudflare_allow_sync":    "0",
        # Trend Micro TippingPoint SMS Reputation Database
        "tippingpoint_enabled":          "0",
        "tippingpoint_server":           "",
        "tippingpoint_api_key":          "",
        "tippingpoint_tag_category":     "",
        "tippingpoint_tag_value":        "",
        "tippingpoint_skip_ssl_verify":  "0",
        "tippingpoint_auto_sync":        "0",
        "tippingpoint_allow_tag_category": "WhiteList",
        "tippingpoint_allow_sync":         "0",
        # Brandefense EASM - tarama (discovery) IP'leri -> allowlist hedefleri
        "brandefense_enabled":        "0",
        "brandefense_token":          "",
        "brandefense_targets":        "allowlist-ip",
        "brandefense_interval_hours": "24",
        "brandefense_managed":        "[]",
        "brandefense_feed_added":     "[]",
        "brandefense_last_sync":      "",
        "brandefense_last_sync_ts":   "",
        "brandefense_last_result":    "",
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
        # maxAgeInDays=365: AbuseIPDB web sitesi tum gecmisi gosterir; 90 gunluk
        # varsayilan pencere rapor sayisini dusuk gosteriyordu (ornek: 927 yerine 321).
        url = "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=365".format(
            urllib.parse.quote(indicator))
        data = _http_get(url, headers={"Key": key, "Accept": "application/json"})
        d = data.get("data", {})
        reports = d.get("totalReports", 0)
        # Verdict artik abuse confidence skoruna degil, RAPOR SAYISINA gore:
        #   raporlama < 3        -> temiz     (clean)
        #   raporlama 3 - 10     -> supheli   (suspicious)
        #   raporlama > 10       -> zararli   (malicious)
        if reports > 10:
            verdict = "malicious"
        elif reports >= 3:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {
            "source": "AbuseIPDB",
            "score": d.get("abuseConfidenceScore", 0),
            "reports": reports,
            "country": d.get("countryCode", "-"),
            "isp": d.get("isp", "-"),
            "usage": d.get("usageType", "-"),
            "domain": d.get("domain") or "-",
            "verdict": verdict,
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


# ============================================================================
# FortiGate Firewall Envanter Sorgusu (v1.7.0)
# ----------------------------------------------------------------------------
# - Adres objeleri + adres gruplari envanteri
# - IP arama: tekil obje eslesmesi + grup uyeligi (ic ice gruplar dahil)
# - Referans degeri (q_ref): sadece eslesen obje/gruplar icin okunur (hizli)
# - Blacklist ekleme korumasi: IP zaten bir FGT'de varsa ekleme engellenir
#
# SSH: Windows dahili ssh.exe / plink (paramiko YOK - GPO uyumlu)
# REST API: urllib ile /api/v2/cmdb/firewall/{address,addrgrp}
# ============================================================================
import subprocess, ipaddress

def get_fortigate_devices(enabled_only=True):
    db = get_db()
    q = "SELECT id, name, host, port, method, username, password, token, verify_ssl, enabled FROM fortigate_devices"
    if enabled_only:
        q += " WHERE enabled = 1"
    q += " ORDER BY name"
    rows = db.execute(q).fetchall()
    out = []
    for r in rows:
        out.append({"id": r[0], "name": r[1], "host": r[2], "port": r[3],
                    "method": r[4], "username": r[5], "password": r[6],
                    "token": r[7], "verify_ssl": bool(r[8]), "enabled": bool(r[9])})
    return out

def get_fortigate_device(dev_id):
    for d in get_fortigate_devices(enabled_only=False):
        if d["id"] == int(dev_id):
            return d
    return None

def _fgt_ssl_context(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _fgt_ip_in_subnet(ip, subnet_str):
    try:
        parts = subnet_str.split()
        if len(parts) == 2:
            net = ipaddress.ip_network("{}/{}".format(parts[0], parts[1]), strict=False)
        else:
            net = ipaddress.ip_network(subnet_str, strict=False)
        return ipaddress.ip_address(ip) in net
    except Exception:
        return False

# ── SSH calistirma ────────────────────────────────────────────────────────────
def _shell_quote(s):
    """Windows cmd icin komutu cift tirnak icine alir (bosluk/ozel karakter guvenligi)."""
    return '"{}"'.format(s.replace('"', '""'))


def _find_ssh_binary(name):
    """ssh.exe veya plink.exe'yi bilinen konumlarda arar. NSSM/SYSTEM hesabinin
    PATH'inde bulunmayabilecegi icin tam yollari da dener. Bulamazsa cikplak
    ismi doner (PATH'te varsa calisir)."""
    import shutil
    # once PATH'te var mi
    found = shutil.which(name)
    if found:
        return found
    # bilinen tam yollar
    candidates = []
    if name == "ssh":
        candidates = [
            r"C:\Windows\System32\OpenSSH\ssh.exe",
            r"C:\Windows\Sysnative\OpenSSH\ssh.exe",  # 32-bit process -> 64-bit System32
            r"C:\Program Files\OpenSSH\ssh.exe",
            r"C:\Program Files\OpenSSH-Win64\ssh.exe",
        ]
    elif name == "plink":
        candidates = [
            r"C:\IoCManager\plink.exe",              # uygulama klasorune konulmus olabilir
            r"C:\Program Files\PuTTY\plink.exe",
            r"C:\Program Files (x86)\PuTTY\plink.exe",
        ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return name  # son care: ciplak isim (FileNotFoundError verirse yakalanir)


def _fgt_ssh_run(device, remote_cmd):
    """FGT'ye SSH ile baglanip komut ciktisini doner. (output, error)"""
    host = device["host"]; port = str(device.get("port") or 22)
    user = device["username"]; password = device.get("password") or ""
    try:
        if password:
            plink = _find_ssh_binary("plink")
            # plink ilk baglantida host key'i tanimaz ve -batch modunda reddeder.
            # Ic agdaki kendi cihazimiz oldugundan, "y" ile host key'i otomatik
            # kabul ediyoruz: 'cmd /c echo y | plink ...' ile plink'in
            # "Store key in cache? (y/n)" sorusuna otomatik y yaniti veriyoruz.
            # (echo y, hem host key kabulu hem batch guvenligi icin -batch YOK)
            cmd_str = 'echo y | "{}" -ssh -P {} -l {} -pw {} {} {}'.format(
                plink, port, _shell_quote(user), _shell_quote(password),
                _shell_quote(host), _shell_quote(remote_cmd))
            proc = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=25)
        else:
            ssh = _find_ssh_binary("ssh")
            proc = subprocess.run(
                [ssh, "-p", port, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=10", "{}@{}".format(user, host), remote_cmd],
                capture_output=True, text=True, timeout=25)
        if proc.returncode != 0 and not proc.stdout:
            return None, (proc.stderr or "baglanti basarisiz")[:200]
        return proc.stdout, None
    except FileNotFoundError:
        if password:
            return None, "plink.exe bulunamadi. Parola ile SSH icin PuTTY plink.exe'yi C:\\IoCManager\\ klasorune koyun."
        return None, "ssh.exe bulunamadi (C:\\Windows\\System32\\OpenSSH\\ssh.exe kontrol edin)"
    except subprocess.TimeoutExpired:
        return None, "zaman asimi (25s) - cihaza erisilemiyor olabilir"
    except Exception as e:
        return None, str(e)[:200]

# ── REST API cagrisi ──────────────────────────────────────────────────────────
def _fgt_api_get(device, path):
    host = device["host"]; port = device.get("port") or 443
    token = device.get("token") or ""; verify = bool(device.get("verify_ssl"))
    ctx = _fgt_ssl_context(verify)

    # Yontem 1: Authorization: Bearer header (yeni FortiOS surumlerinin tercihi)
    url_plain = "https://{}:{}{}".format(host, port, path)
    req = urllib.request.Request(url_plain, method="GET")
    req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise
        # 401 - Bearer kabul edilmedi, URL access_token yontemini dene
    # Yontem 2: URL access_token parametresi (eski yontem / bazi surumler)
    sep = "&" if "?" in path else "?"
    url_token = "https://{}:{}{}{}access_token={}".format(host, port, path, sep, urllib.parse.quote(token))
    req2 = urllib.request.Request(url_token, method="GET")
    with urllib.request.urlopen(req2, timeout=15, context=ctx) as resp:
        return json.loads(resp.read().decode())

# ── Config parse (SSH ciktisi) ────────────────────────────────────────────────
def _parse_addresses_cli(config_text):
    """'show firewall address' -> {ad: {type, value, comment}}"""
    objs = {}
    cur = None
    for line in config_text.splitlines():
        s = line.strip()
        if s.startswith('edit "'):
            cur = {"name": s[6:].rstrip('"'), "type": "ipmask", "value": "", "comment": ""}
        elif s.startswith("set subnet ") and cur:
            cur["type"] = "ipmask"; cur["value"] = s[len("set subnet "):]
        elif s.startswith("set type ") and cur:
            cur["type"] = s[len("set type "):]
        elif s.startswith("set start-ip ") and cur:
            cur["value"] = s[len("set start-ip "):]
        elif s.startswith("set end-ip ") and cur:
            cur["value"] += " - " + s[len("set end-ip "):]
        elif s.startswith("set fqdn ") and cur:
            cur["value"] = s[len("set fqdn "):].strip('"')
        elif s.startswith("set comment ") and cur:
            cur["comment"] = s[len("set comment "):].strip('"')
        elif s == "next" and cur:
            objs[cur["name"]] = cur; cur = None
    return objs

def _parse_addrgrps_cli(config_text):
    """'show firewall addrgrp' -> {grup_ad: [uye_ad, ...]}"""
    grps = {}
    cur = None
    for line in config_text.splitlines():
        s = line.strip()
        if s.startswith('edit "'):
            cur = {"name": s[6:].rstrip('"'), "members": []}
        elif s.startswith("set member ") and cur:
            # set member "A" "B" "C"
            members = [m.strip('"') for m in s[len("set member "):].split('" "')]
            members = [m.strip('"') for m in members]
            cur["members"] = members
        elif s == "next" and cur:
            grps[cur["name"]] = cur["members"]; cur = None
    return grps

# ── Referans degeri (q_ref) - sadece eslesen obje/grup icin ───────────────────
def _fgt_get_refcount(device, obj_name, is_group=False):
    """Bir obje/grubun kac yerde (policy vb.) kullanildigini doner. Bulunamazsa None."""
    kind = "addrgrp" if is_group else "address"
    if device.get("method") == "api":
        try:
            data = _fgt_api_get(device, "/api/v2/cmdb/firewall/{}/{}".format(kind, urllib.parse.quote(obj_name)))
            res = data.get("results", [])
            if res and isinstance(res, list):
                return res[0].get("q_ref", None)
        except Exception:
            return None
        return None
    else:
        # SSH: get firewall address <ad> -> "q_ref: N"
        cmd = "get firewall {} {}".format(kind, obj_name)
        out, err = _fgt_ssh_run(device, cmd)
        if not out:
            return None
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("q_ref"):
                try:
                    return int(s.split(":")[1].strip())
                except Exception:
                    return None
        return None

# ── Envanter: cihazin tum obje + gruplarini getir ─────────────────────────────
def fortigate_inventory(device):
    """Bir cihazin adres objelerini ve gruplarini doner.
    q_ref (referans sayisi) ana envanter cagrisinda zaten geldigi icin burada
    saklanir - ayrica sorgu ATILMAZ (performans)."""
    if device.get("method") == "api":
        try:
            addr_data = _fgt_api_get(device, "/api/v2/cmdb/firewall/address")
            grp_data = _fgt_api_get(device, "/api/v2/cmdb/firewall/addrgrp")
        except urllib.error.HTTPError as e:
            return {"error": "HTTP {}".format(e.code)}
        except Exception as e:
            return {"error": str(e)[:150]}
        objects = {}
        for o in addr_data.get("results", []):
            t = o.get("type", "ipmask")
            if t == "ipmask":
                val = o.get("subnet", "")
            elif t == "iprange":
                val = "{} - {}".format(o.get("start-ip",""), o.get("end-ip",""))
            elif t == "fqdn":
                val = o.get("fqdn", "")
            else:
                val = o.get("subnet", "") or o.get("fqdn", "")
            objects[o.get("name","")] = {"name": o.get("name",""), "type": t,
                                          "value": val, "comment": o.get("comment",""),
                                          "q_ref": o.get("q_ref", None)}
        groups = {}
        group_refs = {}
        for g in grp_data.get("results", []):
            members = [m.get("name","") for m in g.get("member", [])]
            groups[g.get("name","")] = members
            group_refs[g.get("name","")] = g.get("q_ref", None)
        return {"objects": objects, "groups": groups, "group_refs": group_refs}
    else:
        addr_out, addr_err = _fgt_ssh_run(device, "show firewall address")
        if addr_err:
            return {"error": addr_err}
        grp_out, grp_err = _fgt_ssh_run(device, "show firewall addrgrp")
        if grp_err:
            return {"error": grp_err}
        return {"objects": _parse_addresses_cli(addr_out),
                "groups": _parse_addrgrps_cli(grp_out), "group_refs": {}}

# ── IP arama: tekil obje + grup uyeligi (ic ice dahil) + referans ─────────────
def _object_matches_ip(obj, ip):
    t = obj.get("type", "ipmask")
    val = obj.get("value", "")
    if t == "ipmask":
        return _fgt_ip_in_subnet(ip, val)
    if t == "iprange":
        try:
            parts = val.split(" - ")
            return len(parts) == 2 and ipaddress.ip_address(parts[0]) <= ipaddress.ip_address(ip) <= ipaddress.ip_address(parts[1])
        except Exception:
            return False
    return False  # fqdn/wildcard IP ile eslesmez

def _groups_containing(obj_name, groups):
    """obj_name'i (dogrudan veya ic ice) iceren tum gruplari doner."""
    result = set()
    # dogrudan uyelik
    changed = True
    members_map = {obj_name}
    while changed:
        changed = False
        for gname, members in groups.items():
            if gname in result:
                continue
            if any(m in members_map for m in members):
                result.add(gname)
                members_map.add(gname)  # bu grup baska grupta olabilir (ic ice)
                changed = True
    return result

def fortigate_search_ip(device, ip):
    """Bir cihazda IP arar: eslesen tekil objeler + o objelerin oldugu gruplar
    (ic ice gruplar dahil), her biri icin referans degeri (q_ref).
    CANLI sorgu - her aramada guncel envanter cekilir."""
    inv = fortigate_inventory(device)
    if inv.get("error"):
        return {"device": device["name"], "error": inv["error"]}

    objects = inv["objects"]; groups = inv["groups"]
    group_refs = inv.get("group_refs", {})
    matched_objects = []
    all_matched_names = set()

    for name, obj in objects.items():
        if _object_matches_ip(obj, ip):
            all_matched_names.add(name)
            matched_objects.append({"name": name, "type": obj["type"],
                                    "value": obj["value"], "comment": obj.get("comment", ""),
                                    "q_ref": obj.get("q_ref", None)})

    # eslesen objelerin uye oldugu gruplar
    matched_groups = []
    seen_groups = set()
    for oname in all_matched_names:
        for gname in _groups_containing(oname, groups):
            if gname in seen_groups:
                continue
            seen_groups.add(gname)
            matched_groups.append({"name": gname, "q_ref": group_refs.get(gname, None),
                                   "via_object": oname})

    return {"device": device["name"], "device_id": device["id"],
            "found": bool(matched_objects),
            "objects": matched_objects, "groups": matched_groups,
            "total_objects": len(objects), "total_groups": len(groups)}

def fortigate_search_ip_multi(ip, device_ids=None):
    """Secili (veya tum) cihazlarda paralel IP aramasi."""
    import concurrent.futures
    devices = get_fortigate_devices(enabled_only=True)
    if device_ids:
        device_ids = set(int(x) for x in device_ids)
        devices = [d for d in devices if d["id"] in device_ids]
    if not devices:
        return []
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(devices), 8)) as ex:
        futures = {ex.submit(fortigate_search_ip, d, ip): d for d in devices}
        for f in concurrent.futures.as_completed(futures, timeout=60):
            try:
                results.append(f.result())
            except Exception as e:
                d = futures[f]
                results.append({"device": d["name"], "error": str(e)[:150]})
    return results

def fortigate_check_before_blacklist(ip):
    """Blacklist'e eklemeden once: IP herhangi bir FGT'de var mi?
    Donen: (engellensin_mi, [eslesme_detaylari])"""
    results = fortigate_search_ip_multi(ip)
    hits = []
    for r in results:
        if r.get("error"):
            continue
        if r.get("found"):
            hits.append(r)
    return (len(hits) > 0, hits)


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

# ── Cloudflare Rules Lists (IP list) ──────────────────────────────────────────
# Hesap-bazli IP listeleri. Liste yoksa otomatik olusturulur.
#   blacklist-ip  -> iocmanager_blacklist  (WAF'ta Block)
#   allowlist-ip  -> iocmanager_allowlist  (WAF'ta Skip)   [v1.11.0]
# API: https://api.cloudflare.com/client/v4/accounts/{acct}/rules/lists
# Auth: Bearer API Token (izin: Account -> Account Filter Lists -> Edit)
CLOUDFLARE_API       = "https://api.cloudflare.com/client/v4"
CLOUDFLARE_LIST_NAME = "iocmanager_blacklist"   # sadece harf/rakam/alt cizgi, max 50
CLOUDFLARE_LISTS = {
    False: {"name": "iocmanager_blacklist", "setting": "cloudflare_list_id",
            "feed": "blacklist-ip", "desc": "IoCManager blacklist - otomatik senkronize edilir"},
    True:  {"name": "iocmanager_allowlist", "setting": "cloudflare_allow_list_id",
            "feed": "allowlist-ip", "desc": "IoCManager allowlist - otomatik senkronize edilir"},
}

def cloudflare_enabled():
    return (get_setting("cloudflare_enabled") == "1"
            and bool(get_setting("cloudflare_token"))
            and bool(get_setting("cloudflare_account_id")))

def _cloudflare_req(method, path, token, body=None):
    """Cloudflare API cagrisi. success=false ise Exception firlatir."""
    url = CLOUDFLARE_API + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=20, context=_get_ssl_context()) as resp:
            raw = resp.read().decode()
            j = json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode()
        except Exception:
            err_body = ""
        msg = err_body[:250]
        try:
            ej = json.loads(err_body)
            errs = ej.get("errors", []) or []
            if errs:
                msg = "; ".join("{} {}".format(x.get("code", ""), x.get("message", "")) for x in errs)[:250]
        except Exception:
            pass
        raise urllib.error.HTTPError(e.url, e.code, "{} - {}".format(e.reason, msg), e.headers, None)
    if not j.get("success", False):
        errs = j.get("errors", []) or []
        emsg = "; ".join("{} {}".format(x.get("code", ""), x.get("message", "")) for x in errs) or "bilinmeyen hata"
        raise Exception("Cloudflare API: " + emsg[:250])
    return j

def cloudflare_get_or_create_list(token, account_id, allow=False):
    """IoCManager IP listesini (black/allow) bulur, yoksa olusturur. List ID doner."""
    cfg = CLOUDFLARE_LISTS[allow]
    saved_id = get_setting(cfg["setting"])
    j = _cloudflare_req("GET", "/accounts/{}/rules/lists".format(account_id), token)
    for lst in j.get("result", []) or []:
        if saved_id and str(lst.get("id")) == str(saved_id):
            return saved_id
        if lst.get("name") == cfg["name"]:
            set_setting(cfg["setting"], str(lst.get("id")))
            return str(lst.get("id"))
    created = _cloudflare_req("POST", "/accounts/{}/rules/lists".format(account_id), token, {
        "name": cfg["name"], "kind": "ip", "description": cfg["desc"],
    })
    new_id = str(created.get("result", {}).get("id", ""))
    if new_id:
        set_setting(cfg["setting"], new_id)
    return new_id

def cloudflare_add_ip(ip, allow=False):
    """IP'yi (veya CIDR) ilgili Cloudflare IP listesine ekler (async append)."""
    try:
        token      = get_setting("cloudflare_token")
        account_id = get_setting("cloudflare_account_id")
        if not token or not account_id:
            return False, "Token/Account ID yok"
        list_id = cloudflare_get_or_create_list(token, account_id, allow)
        if not list_id:
            return False, "Liste olusturulamadi"
        _cloudflare_req("POST",
            "/accounts/{}/rules/lists/{}/items".format(account_id, list_id),
            token, [{"ip": ip, "comment": "IoCManager"}])
        return True, "OK"
    except urllib.error.HTTPError as e:
        return False, "HTTP {} - {}".format(e.code, e.reason)[:180]
    except Exception as e:
        return False, str(e)[:150]

def cloudflare_remove_ip(ip, allow=False):
    """IP'yi listeden siler. Once item ID'sini bulur (sayfali), sonra DELETE."""
    try:
        token      = get_setting("cloudflare_token")
        account_id = get_setting("cloudflare_account_id")
        if not token or not account_id:
            return False, "Token/Account ID yok"
        list_id = get_setting(CLOUDFLARE_LISTS[allow]["setting"])
        if not list_id:
            return False, "Liste ID yok"
        target = ip.split("/")[0]
        item_id = None
        cursor = None
        for _ in range(100):  # guvenlik siniri (100 * 500 = 50k item)
            path = "/accounts/{}/rules/lists/{}/items?per_page=500".format(account_id, list_id)
            if cursor:
                path += "&cursor=" + urllib.parse.quote(cursor)
            j = _cloudflare_req("GET", path, token)
            for it in j.get("result", []) or []:
                if str(it.get("ip", "")).split("/")[0] == target:
                    item_id = it.get("id")
                    break
            if item_id:
                break
            cursor = ((j.get("result_info", {}) or {}).get("cursors", {}) or {}).get("after")
            if not cursor:
                break
        if not item_id:
            return True, "Zaten yok"
        # Listede bekleyen bir bulk islem varsa Cloudflare 400 donebilir -> kisa bekleyip tekrar dene
        for attempt in range(4):
            try:
                _cloudflare_req("DELETE",
                    "/accounts/{}/rules/lists/{}/items".format(account_id, list_id),
                    token, {"items": [{"id": item_id}]})
                return True, "OK"
            except urllib.error.HTTPError as e:
                if e.code in (400, 409, 429) and attempt < 3:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True, "Zaten yok"
        return False, "HTTP {} - {}".format(e.code, e.reason)[:200]
    except Exception as e:
        return False, str(e)[:150]

def cloudflare_sync_all(allow=False):
    """Ilgili feed'i (blacklist-ip / allowlist-ip) komple Cloudflare listesine iter (PUT)."""
    try:
        token      = get_setting("cloudflare_token")
        account_id = get_setting("cloudflare_account_id")
        if not token or not account_id:
            return 0, ["Token/Account ID yok"]
        list_id = cloudflare_get_or_create_list(token, account_id, allow)
        if not list_id:
            return 0, ["Liste olusturulamadi"]
        ips   = read_feed(CLOUDFLARE_LISTS[allow]["feed"])
        items = [{"ip": ip, "comment": "IoCManager"} for ip in ips if ip]
        _cloudflare_req("PUT",
            "/accounts/{}/rules/lists/{}/items".format(account_id, list_id), token, items)
        return len(items), []
    except urllib.error.HTTPError as e:
        return 0, ["HTTP {} - {}".format(e.code, e.reason)[:120]]
    except Exception as e:
        return 0, [str(e)[:120]]

# ── Brandefense EASM: tarama IP'leri -> allowlist hedefleri ───────────────────
# Brandefense'in EASM taramasi yaptigi kaynak IP'ler cekilir ve secilen
# allowlist hedeflerine basilir (taramalar engellenmesin diye).
# Hedefler: allowlist-ip feed'i (FortiGate external feed), Cloudflare allowlist,
# TippingPoint WhiteList. Brandefense listesinden cikan IP'ler hedeflerden de
# silinir; elle eklenmis kayitlara dokunulmaz.
BRANDEFENSE_URL = "https://api.brandefense.io/api/v2/easm/discovery/discovery-ips"
BRANDEFENSE_TARGETS = [
    ("allowlist-ip", "IoCManager allowlist-ip (FortiGate feed)"),
    ("cloudflare",   "Cloudflare allowlist"),
    ("tippingpoint", "TippingPoint WhiteList"),
]

def brandefense_enabled():
    return get_setting("brandefense_enabled") == "1" and bool(get_setting("brandefense_token"))

def brandefense_fetch_ips():
    """Brandefense discovery IP'lerini ceker. Doner: ({ip: type}, [gecersiz])."""
    token = get_setting("brandefense_token")
    if not token:
        raise RuntimeError("Brandefense API token tanimli degil")
    req = urllib.request.Request(BRANDEFENSE_URL + "?format=json", headers={
        "Authorization": "Bearer " + token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20, context=_get_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace") or "{}")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise RuntimeError("401 - Token gecersiz veya yetkilendirme hatali")
        if e.code == 403:
            raise RuntimeError("403 - Token'da 'EASM Read' yetkisi yok")
        raise RuntimeError("HTTP {}".format(e.code))
    items = data.get("data", []) if isinstance(data, dict) else (data or [])
    ips, invalid = {}, []
    for it in items:
        raw = (it.get("ip") if isinstance(it, dict) else str(it)) or ""
        ok, entry, _reason = process_entry("allowlist-ip", str(raw).strip())
        if ok:
            ips[entry] = (it.get("type") if isinstance(it, dict) else "") or "-"
        elif raw:
            invalid.append(str(raw))
    return ips, invalid

def brandefense_sync(full=False, actor="brandefense"):
    """Brandefense IP'lerini secili hedeflere senkronize eder.
    full=True: tum guncel IP'ler tekrar gonderilir (hedef yeni secildiyse).
    full=False: sadece yeni eklenen/cikan IP'ler islenir (zamanlanmis calisma)."""
    fetched, invalid = brandefense_fetch_ips()
    targets = {t for t in get_setting("brandefense_targets").split(",") if t}
    managed = set(json.loads(get_setting("brandefense_managed") or "[]"))
    current = set(fetched)
    black = set(read_feed("blacklist-ip"))
    conflicts = sorted(x for x in current if x in black)
    current -= set(conflicts)
    new  = current if full else (current - managed)
    gone = managed - current
    res = {"fetched": len(fetched), "new": len(current - managed), "removed": len(gone),
           "conflicts": conflicts, "invalid": invalid, "errors": [], "targets": sorted(targets)}

    if "allowlist-ip" in targets:
        feed  = set(read_feed("allowlist-ip"))
        added_by_bd = set(json.loads(get_setting("brandefense_feed_added") or "[]"))
        add = sorted(x for x in new if x not in feed)
        rem = sorted(x for x in gone if x in feed and x in added_by_bd)
        if add or rem:
            feed.update(add); feed.difference_update(rem)
            write_feed("allowlist-ip", list(feed))
        for x in add:
            log_action(actor, "ADD", "allowlist-ip", x, "Brandefense EASM tarama IP'si", "-")
        for x in rem:
            log_action(actor, "REMOVE", "allowlist-ip", x, "Brandefense listesinden cikti", "-")
        added_by_bd = (added_by_bd | set(add)) - set(rem)
        set_setting("brandefense_feed_added", json.dumps(sorted(added_by_bd)))

    if "cloudflare" in targets:
        if not cloudflare_enabled():
            res["errors"].append("Cloudflare entegrasyonu aktif degil")
        else:
            for x in sorted(new):
                ok, m = cloudflare_add_ip(x, allow=True)
                if not ok: res["errors"].append("Cloudflare {}: {}".format(x, m))
            for x in sorted(gone):
                ok, m = cloudflare_remove_ip(x, allow=True)
                if not ok: res["errors"].append("Cloudflare sil {}: {}".format(x, m))

    if "tippingpoint" in targets:
        if not tippingpoint_enabled():
            res["errors"].append("TippingPoint entegrasyonu aktif degil")
        else:
            for x in sorted(new):
                ok, m = tippingpoint_add_entry(x, "ip", allow=True)
                if not ok: res["errors"].append("TippingPoint {}: {}".format(x, m))
            for x in sorted(gone):
                ok, m = tippingpoint_remove_entry(x, "ip")
                if not ok: res["errors"].append("TippingPoint sil {}: {}".format(x, m))

    set_setting("brandefense_managed", json.dumps(sorted(current)))
    now = datetime.now()
    set_setting("brandefense_last_sync", now.strftime("%Y-%m-%d %H:%M:%S"))
    set_setting("brandefense_last_sync_ts", str(int(now.timestamp())))
    summary = "{} IP cekildi, {} yeni, {} cikan, {} cakisma, {} hata".format(
        res["fetched"], res["new"], res["removed"], len(conflicts), len(res["errors"]))
    set_setting("brandefense_last_result", summary)
    log_action(actor, "SYNC", "brandefense", "-", summary, "-")
    return res

def _brandefense_scheduler():
    """Arka plan: 5 dakikada bir kontrol, aralik dolduysa senkron."""
    while True:
        try:
            with app.app_context():
                if brandefense_enabled():
                    hrs = float(get_setting("brandefense_interval_hours") or 0)
                    last = get_setting("brandefense_last_sync_ts")
                    if hrs > 0 and (not last or time.time() - float(last) >= hrs * 3600):
                        brandefense_sync(full=False, actor="brandefense-auto")
        except Exception as e:
            try:
                with app.app_context():
                    set_setting("brandefense_last_result", "Otomatik senkron hatasi: {}".format(str(e)[:150]))
                    set_setting("brandefense_last_sync_ts", str(int(time.time())))
            except Exception:
                pass
        time.sleep(300)

_BG_STARTED = False
def start_background_jobs():
    global _BG_STARTED
    if _BG_STARTED or os.environ.get("IOCMANAGER_NO_SCHEDULER") == "1":
        return
    _BG_STARTED = True
    threading.Thread(target=_brandefense_scheduler, name="brandefense-sync", daemon=True).start()

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

# WhiteList/BlackList tag kategorisi (List tipi) degerleri: IP / DNS / URL
_TPT_TAG_VALUE = {"ip": "IP", "domain": "DNS", "url": "URL"}

def tippingpoint_add_entry(entry, itype, allow=False):
    param = _TPT_TYPE_PARAM.get(itype)
    if not param:
        return False, "Desteklenmeyen tip (sadece ip/domain/url)"
    params = {param: entry}
    if allow:
        # Allowlist: SMS'teki WhiteList tag kategorisi, deger tipe gore (IP/DNS/URL)
        tag_cat = get_setting("tippingpoint_allow_tag_category").strip() or "WhiteList"
        params["TagData"] = "{},{}".format(tag_cat, _TPT_TAG_VALUE[itype])
    else:
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

def tippingpoint_allow_feed_itype(feed):
    """Allowlist (WhiteList tag) senkronu: allowlist-ip."""
    return {"allowlist-ip": "ip"}.get(feed)

def tippingpoint_allow_sync_all():
    """allowlist-ip'yi SMS Reputation DB'ye WhiteList tag'i ile iter."""
    ok_count, fail = 0, []
    for entry in read_feed("allowlist-ip"):
        success, msg = tippingpoint_add_entry(entry, "ip", allow=True)
        if success:
            ok_count += 1
        else:
            fail.append("{} ({})".format(entry, msg))
    return ok_count, fail

def opposite_feed(feed):
    """blacklist-X <-> allowlist-X karsiligi (yoksa None). Cakisma kontrolu icin."""
    if feed.startswith("blacklist-"):
        o = "allowlist-" + feed[len("blacklist-"):]
    elif feed.startswith("allowlist-"):
        o = "blacklist-" + feed[len("allowlist-"):]
    else:
        return None
    return o if o in FEED_FILES else None

def sync_allowlist_add(feed, entries):
    """allowlist-ip eklemelerini Cloudflare ve TippingPoint'e yansitir. (ok_mesajlari, hata_mesajlari)"""
    oks, errs = [], []
    if feed != "allowlist-ip" or not entries:
        return oks, errs
    if cloudflare_enabled() and get_setting("cloudflare_allow_sync") == "1":
        c_ok, c_msg = 0, ""
        for e in entries:
            ok, m = cloudflare_add_ip(e, allow=True)
            if ok: c_ok += 1
            else: c_msg = m
        if c_ok: oks.append("{} IP Cloudflare allowlist'e gonderildi.".format(c_ok))
        if c_msg: errs.append("Cloudflare allowlist hatasi: {}".format(c_msg))
    if tippingpoint_enabled() and get_setting("tippingpoint_allow_sync") == "1":
        t_ok, t_msg = 0, ""
        for e in entries:
            ok, m = tippingpoint_add_entry(e, "ip", allow=True)
            if ok: t_ok += 1
            else: t_msg = m
        if t_ok: oks.append("{} IP TippingPoint WhiteList'e gonderildi.".format(t_ok))
        if t_msg: errs.append("TippingPoint WhiteList hatasi: {}".format(t_msg))
    return oks, errs

def sync_allowlist_remove(feed, entry):
    oks, errs = [], []
    if feed != "allowlist-ip":
        return oks, errs
    if cloudflare_enabled() and get_setting("cloudflare_allow_sync") == "1":
        ok, m = cloudflare_remove_ip(entry, allow=True)
        (oks if ok else errs).append("Cloudflare allowlist'ten silindi." if ok else "Cloudflare allowlist'ten silinemedi: {}".format(m))
    if tippingpoint_enabled() and get_setting("tippingpoint_allow_sync") == "1":
        ok, m = tippingpoint_remove_entry(entry, "ip")
        (oks if ok else errs).append("TippingPoint WhiteList'ten silindi." if ok else "TippingPoint'ten silinemedi: {}".format(m))
    return oks, errs


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


# ── Rol tabanli liste yazma yetkisi ───────────────────────────────────────────
# Roller:
#   admin        - her sey (kullanici yonetimi, entegrasyonlar dahil)
#   operator     - tum listelere yaz (eski davranis, geriye uyumluluk)
#   read-write   - tum listelere yaz (blacklist + allowlist)
#   blacklist-only - sadece blacklist-* listelerine yaz
#   allowlist-only - sadece allowlist-* listelerine yaz
#   read-only    - hicbir listeye yazamaz, sadece goruntuler
VALID_ROLES = ("admin", "operator", "read-write", "blacklist-only", "allowlist-only", "read-only")

def can_write_feed(role, feed):
    """Verilen rolun, verilen feed'e (blacklist-ip, allowlist-domain vb.)
    yazma yetkisi var mi?"""
    if role in ("admin", "operator", "read-write"):
        return True
    if role == "blacklist-only":
        return feed.startswith("blacklist")
    if role == "allowlist-only":
        return feed.startswith("allowlist")
    # read-only ve bilinmeyen roller: yazamaz
    return False

def require_feed_write(feed):
    """Yetki yoksa flash + False doner; route icinde kullanilir."""
    role = session.get("role", "")
    if not can_write_feed(role, feed):
        flash("'{}' listesine yazma yetkiniz yok (rol: {}).".format(feed, role), "error")
        return False
    return True

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

    if not require_feed_write(feed):
        return redirect(url_for("dashboard"))

    entries_to_add = [x.strip() for x in ip_raw.splitlines() if x.strip()]
    if not entries_to_add:
        flash("Deger bos birakilamaz.", "error")
        return redirect(url_for("dashboard"))

    current = set(read_feed(feed))
    added, skipped_invalid, skipped_dup, skipped_private = [], [], [], []
    skipped_fortigate = []  # zaten bir FortiGate'te tanimli oldugu icin engellenenler
    skipped_conflict = []   # karsi listede (black <-> allow) zaten var
    opp = opposite_feed(feed)
    opp_set = set(read_feed(opp)) if opp else set()

    # FortiGate on-kontrolu: blacklist-ip'ye eklenmek istenen IP, tanimli
    # FortiGate cihazlarindan HERHANGI birinde adres objesi/grubu olarak zaten
    # varsa, HICBIR yere eklenmez (mukerrer/cakisan kayit onlenir).
    fgt_devices_exist = feed == "blacklist-ip" and len(get_fortigate_devices(enabled_only=True)) > 0

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
        if entry in opp_set:
            skipped_conflict.append(entry)
            continue
        if fgt_devices_exist:
            try:
                blocked, hits = fortigate_check_before_blacklist(entry)
            except Exception:
                blocked, hits = False, []
            if blocked:
                detay = []
                for h in hits:
                    obj_names = ", ".join(o["name"] for o in h.get("objects", []))
                    grp_names = ", ".join("{}(ref:{})".format(g["name"], g.get("q_ref", "?")) for g in h.get("groups", []))
                    parca = "{}: obje [{}]".format(h["device"], obj_names)
                    if grp_names:
                        parca += ", grup [{}]".format(grp_names)
                    detay.append(parca)
                skipped_fortigate.append({"ip": entry, "detay": " | ".join(detay)})
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
        # Cloudflare otomatik sync (sadece blacklist-ip)
        if feed == "blacklist-ip" and cloudflare_enabled() and get_setting("cloudflare_auto_sync") == "1":
            c_ok, c_msg = 0, ""
            for entry in added:
                success, msg = cloudflare_add_ip(entry)
                if success: c_ok += 1
                else: c_msg = msg
            if c_ok:
                flash("{} IP Cloudflare listesine gonderildi.".format(c_ok), "success")
            if c_msg:
                flash("Cloudflare hatasi: {}".format(c_msg), "warning")
        # Allowlist senkronu (Cloudflare allowlist + TippingPoint WhiteList)
        a_oks, a_errs = sync_allowlist_add(feed, added)
        for m in a_oks: flash(m, "success")
        for m in a_errs: flash(m, "warning")
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
    if skipped_fortigate:
        for item in skipped_fortigate:
            flash("'{}' eklenemedi — zaten FortiGate'te tanimli: {}".format(
                item["ip"], item["detay"]), "error")
    if skipped_invalid:
        flash("{} gecersiz format atlandi.".format(len(skipped_invalid)), "warning")
    if skipped_dup:
        flash("{} duplicate atlandi.".format(len(skipped_dup)), "warning")
    if skipped_conflict:
        flash("{} kayit eklenemedi — {} listesinde zaten var (cakisma): {}".format(
            len(skipped_conflict), opp, ", ".join(skipped_conflict[:5])), "error")

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
    cloudflare_ips = []
    tpt_new_by_feed = {}  # feed -> [entries] (blacklist-ip/domain/url icin)
    conflict_entries = []
    allow_new_by_feed = {}
    for feed, entries in buckets.items():
        current = set(read_feed(feed))
        opp = opposite_feed(feed)
        opp_set = set(read_feed(opp)) if opp else set()
        conflicts = [e for e in entries if e in opp_set and e not in current]
        conflict_entries.extend(conflicts)
        entries = [e for e in entries if e not in opp_set]
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
            if feed == "blacklist-ip":
                cloudflare_ips.extend(new_entries)
            if feed == "allowlist-ip":
                allow_new_by_feed[feed] = new_entries
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

    # Cloudflare otomatik sync
    if cloudflare_ips and cloudflare_enabled() and get_setting("cloudflare_auto_sync") == "1":
        c_ok = 0
        for entry in cloudflare_ips:
            success, _ = cloudflare_add_ip(entry)
            if success: c_ok += 1
        if c_ok:
            flash("{} IP Cloudflare listesine gonderildi.".format(c_ok), "success")

    # Allowlist senkronu
    for f, ents in allow_new_by_feed.items():
        a_oks, a_errs = sync_allowlist_add(f, ents)
        for m in a_oks: flash(m, "success")
        for m in a_errs: flash(m, "warning")
    if conflict_entries:
        flash("{} kayit karsi listede (kara/beyaz) zaten oldugu icin eklenmedi: {}".format(
            len(conflict_entries), ", ".join(conflict_entries[:5])), "error")

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

    if not require_feed_write(feed):
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

    # Cloudflare'dan da sil (blacklist-ip)
    if feed == "blacklist-ip" and cloudflare_enabled() and get_setting("cloudflare_auto_sync") == "1":
        success, msg = cloudflare_remove_ip(entry)
        if success:
            flash("IP Cloudflare listesinden de silindi.", "success")
        else:
            flash("Cloudflare'dan silinemedi: {}".format(msg), "warning")

    # Allowlist: Cloudflare allowlist + TippingPoint WhiteList'ten de sil
    a_oks, a_errs = sync_allowlist_remove(feed, entry)
    for m in a_oks: flash(m, "success")
    for m in a_errs: flash(m, "warning")

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

        if not require_feed_write(feed):
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
        skipped_conflict = []
        opp = opposite_feed(feed)
        opp_set = set(read_feed(opp)) if opp else set()

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
            if entry in opp_set:
                skipped_conflict.append(entry)
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
        if skipped_conflict:
            flash("{} kayit {} listesinde zaten oldugu icin eklenmedi (cakisma).".format(
                len(skipped_conflict), opp), "error")

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
            if role not in VALID_ROLES:
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

# ── Routes: FortiGate Envanter & Sorgu ────────────────────────────────────────
@app.route("/fortigate", methods=["GET"])
@login_required
def fortigate():
    devices = get_fortigate_devices(enabled_only=False)
    return render_template("fortigate.html", devices=devices,
                           username=session["username"], role=session["role"])

@app.route("/fortigate/search", methods=["POST"])
@login_required
def fortigate_search():
    """AJAX: IP'yi TUM aktif cihazlarda arar, JSON doner."""
    validate_csrf()
    ip = request.form.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP bos"})
    try:
        import ipaddress as _ip
        _ip.ip_address(ip)
    except ValueError:
        return jsonify({"error": "gecersiz IP formati"})

    results = fortigate_search_ip_multi(ip)  # tum aktif cihazlar
    log_action(session["username"], "FGT_SEARCH", "-", ip,
               "FortiGate IP arama ({} cihaz)".format(len(results)), request.remote_addr)
    return jsonify({"ip": ip, "results": results})


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

# ── Routes: Roller & Yetkiler ────────────────────────────────────────────────
ROLE_INFO = [
    ("admin",          "Yonetici",          True,  True,  True),
    ("operator",       "Operator (klasik)", True,  True,  False),
    ("read-write",     "Okuma-Yazma",       True,  True,  False),
    ("blacklist-only", "Sadece Blacklist",  True,  False, False),
    ("allowlist-only", "Sadece Allowlist",  False, True,  False),
    ("read-only",      "Salt Okuma",        False, False, False),
]

@app.route("/roles")
@login_required
@admin_required
def roles():
    db = get_db()
    counts = {r["role"]: r["c"] for r in db.execute("SELECT role, COUNT(*) AS c FROM users GROUP BY role").fetchall()}
    rows = [{"key": k, "name": n, "black": b, "allow": a, "admin": adm, "count": counts.get(k, 0)}
            for k, n, b, a, adm in ROLE_INFO]
    return render_template("roles.html", rows=rows, username=session["username"], role=session["role"])

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

        elif action == "fortigate_add":
            name = sanitize_text(request.form.get("name", "").strip())
            host = request.form.get("host", "").strip()
            port = request.form.get("port", "").strip()
            token = request.form.get("token", "").strip()
            verify_ssl = 1 if request.form.get("verify_ssl") else 0
            if not name or not host or not token:
                flash("FortiGate cihaz adi, host ve token zorunlu.", "error")
            else:
                try:
                    port = int(port) if port else 443
                except ValueError:
                    port = 443
                db = get_db()
                db.execute("""INSERT INTO fortigate_devices
                              (name, host, port, method, username, password, token, verify_ssl, enabled, created_at)
                              VALUES (?,?,?,?,?,?,?,?,1,?)""",
                           (name, host, port, "api", "", "", token, verify_ssl,
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                db.commit()
                log_action(session["username"], "FGT_ADD", "-", host, "FortiGate eklendi: " + name, request.remote_addr)
                flash("FortiGate cihazi eklendi: {}".format(name), "success")

        elif action == "fortigate_delete":
            dev_id = request.form.get("device_id", "")
            db = get_db()
            db.execute("DELETE FROM fortigate_devices WHERE id = ?", (dev_id,))
            db.commit()
            log_action(session["username"], "FGT_DEL", "-", str(dev_id), "FortiGate silindi", request.remote_addr)
            flash("FortiGate cihazi silindi.", "success")

        elif action == "fortigate_test":
            dev_id = request.form.get("device_id", "")
            device = get_fortigate_device(dev_id)
            if not device:
                flash("Cihaz bulunamadi.", "error")
            else:
                inv = fortigate_inventory(device)
                if inv.get("error"):
                    flash("FortiGate baglanti hatasi ({}): {}".format(device["name"], inv["error"]), "error")
                else:
                    flash("FortiGate baglantisi basarili ({}): {} obje, {} grup okundu.".format(
                        device["name"], len(inv["objects"]), len(inv["groups"])), "success")

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

        elif action == "save_cloudflare":
            set_setting("cloudflare_enabled",    "1" if request.form.get("cloudflare_enabled") else "0")
            set_setting("cloudflare_account_id", request.form.get("cloudflare_account_id", "").strip())
            token = request.form.get("cloudflare_token", "").strip()
            if token:  # bos gelirse mevcut token korunur
                set_setting("cloudflare_token", token)
            set_setting("cloudflare_auto_sync",  "1" if request.form.get("cloudflare_auto_sync") else "0")
            set_setting("cloudflare_allow_sync", "1" if request.form.get("cloudflare_allow_sync") else "0")
            flash("Cloudflare ayarlari kaydedildi.", "success")

        elif action == "cloudflare_test":
            token      = get_setting("cloudflare_token")
            account_id = get_setting("cloudflare_account_id")
            if not token or not account_id:
                flash("Cloudflare token veya Account ID eksik.", "error")
            else:
                try:
                    list_id = cloudflare_get_or_create_list(token, account_id)
                    if list_id:
                        flash("Cloudflare baglantisi basarili. Liste hazir (ID: {}).".format(list_id), "success")
                    else:
                        flash("Baglanti kuruldu ama liste olusturulamadi.", "warning")
                except Exception as e:
                    flash("Cloudflare baglanti hatasi: {}".format(str(e)[:150]), "error")

        elif action == "cloudflare_sync":
            if not cloudflare_enabled():
                flash("Cloudflare aktif degil veya token/Account ID yok.", "error")
            else:
                ok_count, fail = cloudflare_sync_all()
                flash("{} IP Cloudflare listesine senkronize edildi.".format(ok_count), "success")
                if fail:
                    flash("Cloudflare sync hatasi: {}".format(", ".join(fail[:5])), "warning")

        elif action == "cloudflare_allow_sync_now":
            if not cloudflare_enabled():
                flash("Cloudflare aktif degil veya token/Account ID yok.", "error")
            else:
                ok_count, fail = cloudflare_sync_all(allow=True)
                flash("{} IP Cloudflare allowlist'e senkronize edildi.".format(ok_count), "success")
                if fail:
                    flash("Cloudflare allowlist sync hatasi: {}".format(", ".join(fail[:5])), "warning")

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
            set_setting("tippingpoint_allow_tag_category", sanitize_text(request.form.get("tippingpoint_allow_tag_category", "WhiteList").strip() or "WhiteList", 100))
            set_setting("tippingpoint_allow_sync", "1" if request.form.get("tippingpoint_allow_sync") else "0")
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

        elif action == "save_brandefense":
            set_setting("brandefense_enabled", "1" if request.form.get("brandefense_enabled") else "0")
            tok = request.form.get("brandefense_token", "").strip()
            if tok:  # bos gelirse mevcut token korunur
                set_setting("brandefense_token", tok)
            valid_t = {k for k, _ in BRANDEFENSE_TARGETS}
            set_setting("brandefense_targets", ",".join(t for t in request.form.getlist("brandefense_targets") if t in valid_t))
            try:
                hrs = max(0, min(168, int(request.form.get("brandefense_interval_hours", "24") or 0)))
            except ValueError:
                hrs = 24
            set_setting("brandefense_interval_hours", str(hrs))
            log_action(session["username"], "SETTINGS", "brandefense", "-", "Brandefense ayarlari guncellendi", request.remote_addr)
            flash("Brandefense ayarlari kaydedildi.", "success")

        elif action == "brandefense_test":
            try:
                ips, invalid = brandefense_fetch_ips()
                sample = ", ".join("{} ({})".format(k, v) for k, v in list(ips.items())[:5])
                flash("Brandefense baglantisi basarili: {} IP alindi. Ornek: {}".format(len(ips), sample or "-"), "success")
                if invalid:
                    flash("{} gecersiz kayit atlandi.".format(len(invalid)), "warning")
            except Exception as e:
                flash("Brandefense baglanti hatasi: {}".format(str(e)[:150]), "error")

        elif action == "brandefense_sync_now":
            if not brandefense_enabled():
                flash("Brandefense aktif degil veya token yok.", "error")
            elif not get_setting("brandefense_targets"):
                flash("En az bir hedef liste secin.", "error")
            else:
                try:
                    r = brandefense_sync(full=True, actor=session["username"])
                    flash("Brandefense senkronu: {} IP cekildi, {} yeni, {} cikan -> {}".format(
                        r["fetched"], r["new"], r["removed"], ", ".join(r["targets"])), "success")
                    if r["conflicts"]:
                        flash("{} IP blacklist-ip'de oldugu icin allowlist'e basilmadi: {}".format(
                            len(r["conflicts"]), ", ".join(r["conflicts"][:5])), "error")
                    for m in r["errors"][:5]:
                        flash(m, "warning")
                except Exception as e:
                    flash("Brandefense senkron hatasi: {}".format(str(e)[:150]), "error")

        elif action == "tippingpoint_allow_sync_now":
            if not tippingpoint_enabled():
                flash("TippingPoint aktif degil veya sunucu/API key eksik.", "error")
            else:
                ok_count, fail = tippingpoint_allow_sync_all()
                flash("{} IP TippingPoint WhiteList'e senkronize edildi.".format(ok_count), "success")
                if fail:
                    flash("{} kayit gonderilemedi: {}".format(len(fail), ", ".join(fail[:5])), "warning")

    cfg = get_all_settings()
    return render_template("integrations.html", cfg=cfg,
                           bd_targets=BRANDEFENSE_TARGETS,
                           bd_selected=[t for t in cfg.get("brandefense_targets", "").split(",") if t],
                           bd_managed_count=len(json.loads(cfg.get("brandefense_managed") or "[]")),
                           fortigate_devices=get_fortigate_devices(enabled_only=False),
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
    start_background_jobs()
    app.run(host="0.0.0.0", port=5000, debug=False)

init_db()
start_background_jobs()
