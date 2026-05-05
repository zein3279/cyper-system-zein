#!/usr/bin/env python3
# ================================================================
#   ZEIN Cyber Defense Agent v2.0 — Enterprise Grade
#   تم تطويره بواسطة: ZEIN Security Systems
#   الإصدار: 2.0.0 Enterprise
# ================================================================

import os
import sys
import time
import json
import socket
import logging
import threading
import subprocess
import platform
import datetime
import collections
import hashlib
import hmac
import base64
import sqlite3
import ipaddress
import re
import signal
from pathlib import Path
from typing import Optional

# ── تثبيت المكتبات تلقائياً ──
REQUIRED = ["psutil", "requests", "cryptography"]
for pkg in REQUIRED:
    try:
        __import__(pkg)
    except ImportError:
        print(f"[ZEIN] تثبيت {pkg}...")
        subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"], check=False)

import psutil
import requests
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ================================================================
#   المسارات والإعدادات الأساسية
# ================================================================
BASE_DIR    = Path(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = BASE_DIR / "zein_config.enc"
DB_FILE     = BASE_DIR / "zein_defense.db"
KEY_FILE    = BASE_DIR / ".zein_key"
LOG_FILE    = BASE_DIR / "zein_log.txt"

# إعدادات افتراضية
DEFAULT_CONFIG = {
    "TG_TOKEN":           "",
    "TG_CHAT_ID":         "",
    "COMPANY":            "شركتي",
    "COMPANY_ID":         "",
    "API_ENDPOINT":       "https://zein3279.github.io/cyber-security/api",
    "CPU_THRESHOLD":      85,
    "RAM_THRESHOLD":      90,
    "DISK_THRESHOLD":     90,
    "MAX_CONNECTIONS":    200,
    "BRUTE_FORCE_LIMIT":  10,
    "PORT_SCAN_LIMIT":    15,
    "BANDWIDTH_MB":       100,
    "SENSITIVE_PORTS":    [21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 27017],
    "WHITELIST":          ["127.0.0.1", "::1"],
    "AUTO_BLOCK":         False,
    "SCAN_INTERVAL":      10,
    "REPORT_INTERVAL":    3600,
    "MAX_BLOCK_DURATION": 86400,
    "ALERT_COOLDOWN":     300,
    "LOG_LEVEL":          "INFO",
    "ENABLE_HONEYPOT":    False,
    "HONEYPOT_PORTS":     [2222, 8888, 9999],
}

CONFIG = dict(DEFAULT_CONFIG)

# ================================================================
#   تشفير الإعدادات
# ================================================================
def _get_or_create_key() -> bytes:
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key() if CRYPTO_AVAILABLE else base64.urlsafe_b64encode(os.urandom(32))
    KEY_FILE.write_bytes(key)
    KEY_FILE.chmod(0o600)
    return key

def save_config_encrypted(cfg: dict):
    data = json.dumps(cfg, ensure_ascii=False).encode()
    if CRYPTO_AVAILABLE:
        fernet = Fernet(_get_or_create_key())
        encrypted = fernet.encrypt(data)
    else:
        encrypted = base64.b64encode(data)
    CONFIG_FILE.write_bytes(encrypted)
    CONFIG_FILE.chmod(0o600)

def load_config_encrypted() -> Optional[dict]:
    if not CONFIG_FILE.exists():
        return None
    try:
        raw = CONFIG_FILE.read_bytes()
        if CRYPTO_AVAILABLE:
            fernet = Fernet(_get_or_create_key())
            data = fernet.decrypt(raw)
        else:
            data = base64.b64decode(raw)
        return json.loads(data)
    except Exception as e:
        print(f"[ZEIN] تحذير: فشل قراءة الإعداد المشفر: {e}")
        return None

# ================================================================
#   قاعدة البيانات SQLite
# ================================================================
def init_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip          TEXT PRIMARY KEY,
            reason      TEXT,
            blocked_at  REAL,
            expires_at  REAL,
            threat_level INTEGER DEFAULT 1,
            attack_count INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL,
            event_type  TEXT,
            ip          TEXT,
            details     TEXT,
            severity    TEXT
        );

        CREATE TABLE IF NOT EXISTS stats_daily (
            date        TEXT PRIMARY KEY,
            threats     INTEGER DEFAULT 0,
            alerts      INTEGER DEFAULT 0,
            blocks      INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()

def db_block_ip(ip: str, reason: str, threat_level: int = 1):
    now = time.time()
    expires = now + CONFIG["MAX_BLOCK_DURATION"]
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO blocked_ips (ip, reason, blocked_at, expires_at, threat_level, attack_count)
        VALUES (?, ?, ?, ?, ?, 1)
        ON CONFLICT(ip) DO UPDATE SET
            attack_count = attack_count + 1,
            expires_at   = ?,
            reason       = ?,
            threat_level = MAX(threat_level, ?)
    """, (ip, reason, now, expires, threat_level, expires, reason, threat_level))
    conn.commit()
    conn.close()

def db_is_blocked(ip: str) -> bool:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT expires_at FROM blocked_ips WHERE ip = ?", (ip,))
    row = c.fetchone()
    conn.close()
    if row and row[0] > time.time():
        return True
    return False

def db_get_blocked_ips() -> list:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT ip, reason, blocked_at, threat_level, attack_count FROM blocked_ips WHERE expires_at > ?", (time.time(),))
    rows = c.fetchall()
    conn.close()
    return rows

def db_log_event(event_type: str, ip: str, details: str, severity: str = "MEDIUM"):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO events (timestamp, event_type, ip, details, severity)
        VALUES (?, ?, ?, ?, ?)
    """, (time.time(), event_type, ip, details, severity))
    today = datetime.date.today().isoformat()
    c.execute("""
        INSERT INTO stats_daily (date, threats) VALUES (?, 1)
        ON CONFLICT(date) DO UPDATE SET threats = threats + 1
    """, (today,))
    conn.commit()
    conn.close()

def db_cleanup_expired():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM blocked_ips WHERE expires_at < ?", (time.time(),))
    c.execute("DELETE FROM events WHERE timestamp < ?", (time.time() - 30 * 86400,))
    conn.commit()
    conn.close()

def db_get_stats() -> dict:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM blocked_ips WHERE expires_at > ?", (time.time(),))
    active_blocks = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM events WHERE timestamp > ?", (time.time() - 86400,))
    events_24h = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM events WHERE severity = 'HIGH' AND timestamp > ?", (time.time() - 86400,))
    high_severity = c.fetchone()[0]
    conn.close()
    return {
        "active_blocks": active_blocks,
        "events_24h":    events_24h,
        "high_severity": high_severity,
    }

# ================================================================
#   إعداد السجل
# ================================================================
def setup_logging():
    level = getattr(logging, CONFIG.get("LOG_LEVEL", "INFO"), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [ZEIN] %(levelname)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
        ]
    )

log = logging.getLogger("ZEIN")

# ================================================================
#   ذاكرة التتبع (في الذاكرة + قاعدة البيانات)
# ================================================================
alert_cooldown   = {}
failed_attempts  = collections.defaultdict(list)
port_scan_track  = collections.defaultdict(set)
port_scan_time   = collections.defaultdict(float)
connection_history = collections.defaultdict(list)
runtime_stats = {
    "threats_blocked": 0,
    "alerts_sent":     0,
    "start_time":      time.time(),
}

# ================================================================
#   التحقق من صحة IP (أمان ضد حقن الأوامر)
# ================================================================
def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ================================================================
#   تيليجرام — مع Queue لتجنب الإرسال المتزامن
# ================================================================
_tg_queue = collections.deque(maxlen=100)
_tg_lock  = threading.Lock()

def send_telegram(message: str, level: str = "⚠️", priority: bool = False):
    token   = CONFIG.get("TG_TOKEN", "")
    chat_id = CONFIG.get("TG_CHAT_ID", "")
    if not token or not chat_id:
        return False

    now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    text = (
        f"🛡 *ZEIN Cyber Defense*\n"
        f"🏢 *{CONFIG['COMPANY']}*\n\n"
        f"{level} {message}\n\n"
        f"⏱ {now}"
    )

    def _send():
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=15,
            )
            if r.ok:
                runtime_stats["alerts_sent"] += 1
                today = datetime.date.today().isoformat()
                conn = sqlite3.connect(DB_FILE)
                conn.execute("""
                    INSERT INTO stats_daily (date, alerts) VALUES (?, 1)
                    ON CONFLICT(date) DO UPDATE SET alerts = alerts + 1
                """, (today,))
                conn.commit()
                conn.close()
        except Exception:
            pass

    if priority:
        threading.Thread(target=_send, daemon=True).start()
    else:
        _tg_queue.append(_send)

def _tg_worker():
    while True:
        if _tg_queue:
            fn = _tg_queue.popleft()
            fn()
            time.sleep(1)  # rate limiting
        else:
            time.sleep(0.5)

def alert(ip: str, message: str, level: str = "⚠️", force: bool = False, severity: str = "MEDIUM"):
    now = time.time()
    last = alert_cooldown.get(ip, 0)
    if not force and (now - last) < CONFIG["ALERT_COOLDOWN"]:
        return
    alert_cooldown[ip] = now
    log.warning(f"🚨 {message}")
    db_log_event(level, ip, message, severity)
    send_telegram(message, level, priority=force)

# ================================================================
#   حجب IP — آمن ضد حقن الأوامر
# ================================================================
def block_ip(ip: str, reason: str, threat_level: int = 1):
    if not is_valid_ip(ip):
        log.warning(f"IP غير صالح تم تجاهله: {ip}")
        return

    if ip in CONFIG["WHITELIST"] or db_is_blocked(ip):
        return

    db_block_ip(ip, reason, threat_level)
    runtime_stats["threats_blocked"] += 1
    log.warning(f"🚫 حجب IP: {ip} — {reason}")

    if not CONFIG["AUTO_BLOCK"]:
        alert(ip, f"يُنصح بحجب IP: `{ip}`\nالسبب: {reason}\nمستوى التهديد: {'🔴 عالٍ' if threat_level >= 3 else '🟡 متوسط'}", "🚫")
        return

    system = platform.system()
    try:
        if system == "Linux":
            # استخدام subprocess بدلاً من os.system — آمن من حقن الأوامر
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=10
            )
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=10
            )
            log.info(f"  ✅ iptables: حُجب {ip}")

        elif system == "Windows":
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=ZEIN_BLOCK_{ip}",
                "dir=in", "action=block", f"remoteip={ip}",
                "enable=yes", "profile=any"
            ], check=True, capture_output=True, timeout=10)
            log.info(f"  ✅ Windows Firewall: حُجب {ip}")

        elif system == "Darwin":
            subprocess.run(
                ["pfctl", "-ef", "-"],
                input=f"block in from {ip} to any\n".encode(),
                capture_output=True, timeout=10
            )
            log.info(f"  ✅ pfctl: حُجب {ip}")

    except subprocess.CalledProcessError as e:
        log.error(f"  ❌ فشل الحجب (تحتاج صلاحيات مشرف): {e}")
    except FileNotFoundError:
        log.error(f"  ❌ أداة الحجب غير موجودة على هذا النظام")
    except Exception as e:
        log.error(f"  ❌ خطأ غير متوقع: {e}")

    alert(ip, f"🔴 تم حجب IP تلقائياً: `{ip}`\nالسبب: {reason}", "🚫", force=True, severity="HIGH")

def unblock_expired_ips():
    system = platform.system()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT ip FROM blocked_ips WHERE expires_at < ?", (time.time(),))
    expired = [row[0] for row in c.fetchall()]
    conn.close()

    for ip in expired:
        if not is_valid_ip(ip):
            continue
        try:
            if system == "Linux":
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                                capture_output=True, timeout=5)
            elif system == "Windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                                 f"name=ZEIN_BLOCK_{ip}"], capture_output=True, timeout=5)
        except Exception:
            pass
        log.info(f"🔓 انتهت مدة حجب {ip}")

    db_cleanup_expired()

# ================================================================
#   فحص موارد النظام
# ================================================================
def check_system_resources():
    try:
        cpu  = psutil.cpu_percent(interval=2)
        ram  = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        swap = psutil.swap_memory().percent

        log.info(f"📊 CPU={cpu:.1f}% RAM={ram:.1f}% Disk={disk:.1f}% Swap={swap:.1f}%")

        if cpu > CONFIG["CPU_THRESHOLD"]:
            # تحليل أي عملية تستهلك CPU
            top_procs = sorted(psutil.process_iter(["pid", "name", "cpu_percent"]),
                               key=lambda p: p.info["cpu_percent"] or 0, reverse=True)[:3]
            procs_str = "\n".join([f"  • {p.info['name']} (PID:{p.info['pid']}) — {p.info['cpu_percent']:.1f}%"
                                   for p in top_procs])
            alert("system_cpu",
                  f"⚡ *CPU مرتفع جداً: {cpu:.1f}%*\n"
                  f"أعلى العمليات:\n{procs_str}\n"
                  f"محتمل: DDoS أو Crypto Mining",
                  "🔥", severity="HIGH")

        if ram > CONFIG["RAM_THRESHOLD"]:
            alert("system_ram", f"💾 *RAM مرتفعة: {ram:.1f}%*\nSwap: {swap:.1f}%", "🔥")

        if disk > CONFIG["DISK_THRESHOLD"]:
            alert("system_disk",
                  f"💿 *القرص ممتلئ: {disk:.1f}%*\nخطر توقف الخدمات والسجلات",
                  "💿", force=True, severity="HIGH")

    except Exception as e:
        log.error(f"فحص الموارد: {e}")

# ================================================================
#   فحص الاتصالات الشبكية
# ================================================================
def check_network_connections():
    try:
        connections = psutil.net_connections(kind="inet")
        ip_counter  = collections.Counter()
        now         = time.time()

        for conn in connections:
            if not conn.raddr:
                continue

            remote_ip   = conn.raddr.ip
            remote_port = conn.laddr.port if conn.laddr else 0

            if remote_ip in CONFIG["WHITELIST"] or db_is_blocked(remote_ip):
                continue

            if conn.status == "ESTABLISHED":
                ip_counter[remote_ip] += 1
                connection_history[remote_ip].append(now)
                # احتفظ فقط بآخر 60 ثانية
                connection_history[remote_ip] = [t for t in connection_history[remote_ip] if now - t < 60]

            # ── كشف Port Scan ──
            if remote_port in CONFIG["SENSITIVE_PORTS"]:
                port_scan_track[remote_ip].add(remote_port)
                if remote_ip not in port_scan_time:
                    port_scan_time[remote_ip] = now

                elapsed   = now - port_scan_time[remote_ip]
                ports_hit = len(port_scan_track[remote_ip])

                if elapsed < 60 and ports_hit >= CONFIG["PORT_SCAN_LIMIT"]:
                    ports_str = ", ".join(str(p) for p in sorted(port_scan_track[remote_ip]))
                    block_ip(remote_ip, f"Port Scan — {ports_hit} منفذ خلال {elapsed:.0f}s", threat_level=2)
                    alert(remote_ip,
                          f"🔍 *مسح منافذ (Port Scan)*\n"
                          f"IP: `{remote_ip}`\n"
                          f"المنافذ: `{ports_str}`\n"
                          f"خلال: {elapsed:.0f} ثانية",
                          "🔍", force=True, severity="HIGH")
                    port_scan_track[remote_ip].clear()
                    port_scan_time.pop(remote_ip, None)

                elif elapsed > 120:
                    port_scan_track[remote_ip].clear()
                    port_scan_time.pop(remote_ip, None)

        # ── كشف DDoS (اتصالات كثيرة من نفس IP) ──
        for ip, count in ip_counter.items():
            if count > CONFIG["MAX_CONNECTIONS"]:
                block_ip(ip, f"DDoS محتمل — {count} اتصال متزامن", threat_level=3)
                alert(ip,
                      f"🌊 *هجوم DDoS محتمل*\n"
                      f"IP: `{ip}`\n"
                      f"الاتصالات المتزامنة: *{count}*",
                      "🌊", force=True, severity="HIGH")

        log.info(f"📡 اتصالات نشطة: {len(connections)} | IPs فريدة: {len(ip_counter)}")

    except Exception as e:
        log.error(f"فحص الشبكة: {e}")

# ================================================================
#   كشف Brute Force
# ================================================================
def check_auth_logs():
    system = platform.system()
    if system == "Linux":
        _check_linux_auth()
    elif system == "Windows":
        _check_windows_events()

def _check_linux_auth():
    auth_files = ["/var/log/auth.log", "/var/log/secure", "/var/log/faillog"]
    patterns = [
        r"Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)",
        r"Invalid user.*from\s+(\d+\.\d+\.\d+\.\d+)",
        r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)",
        r"FAILED LOGIN.*FROM\s+(\d+\.\d+\.\d+\.\d+)",
    ]

    for path in auth_files:
        try:
            if not os.path.exists(path):
                continue
            now = time.time()
            with open(path, "r", errors="ignore") as f:
                lines = f.readlines()[-500:]

            for line in lines:
                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        ip = match.group(1)
                        if not is_valid_ip(ip) or ip in CONFIG["WHITELIST"]:
                            continue
                        failed_attempts[ip].append(now)
                        failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < 60]
                        count = len(failed_attempts[ip])
                        if count >= CONFIG["BRUTE_FORCE_LIMIT"]:
                            block_ip(ip, f"Brute Force — {count} محاولة/دقيقة", threat_level=2)
                            alert(ip,
                                  f"🔐 *هجوم Brute Force*\n"
                                  f"IP: `{ip}`\n"
                                  f"المحاولات: *{count}* في الدقيقة",
                                  "🔐", force=True, severity="HIGH")
                            failed_attempts[ip].clear()
        except PermissionError:
            log.debug(f"لا توجد صلاحية لقراءة: {path}")
        except Exception as e:
            log.debug(f"خطأ في قراءة {path}: {e}")

def _check_windows_events():
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} "
             "-MaxEvents 100 | Select-Object -ExpandProperty Message"],
            capture_output=True, text=True, timeout=15
        )
        now = time.time()
        ip_pattern = re.compile(r"Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)")
        for match in ip_pattern.finditer(result.stdout):
            ip = match.group(1)
            if not is_valid_ip(ip) or ip in CONFIG["WHITELIST"] or ip == "-":
                continue
            failed_attempts[ip].append(now)
            failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < 60]
            count = len(failed_attempts[ip])
            if count >= CONFIG["BRUTE_FORCE_LIMIT"]:
                block_ip(ip, f"Brute Force Windows — {count} محاولة", threat_level=2)
                alert(ip,
                      f"🔐 *Brute Force على Windows*\n"
                      f"IP: `{ip}`\n"
                      f"المحاولات: *{count}*",
                      "🔐", force=True, severity="HIGH")
                failed_attempts[ip].clear()
    except Exception as e:
        log.debug(f"أحداث Windows: {e}")

# ================================================================
#   فحص النطاق الترددي
# ================================================================
_prev_net      = None
_prev_net_time = None

def check_bandwidth():
    global _prev_net, _prev_net_time
    try:
        now     = time.time()
        current = psutil.net_io_counters()

        if _prev_net is not None:
            elapsed  = max(now - _prev_net_time, 0.1)
            sent_mb  = (current.bytes_sent - _prev_net.bytes_sent) / (1024 * 1024 * elapsed)
            recv_mb  = (current.bytes_recv - _prev_net.bytes_recv) / (1024 * 1024 * elapsed)

            log.info(f"📡 الشبكة: ↑{sent_mb:.2f} MB/s ↓{recv_mb:.2f} MB/s")

            if recv_mb > CONFIG["BANDWIDTH_MB"]:
                alert("bandwidth",
                      f"🌊 *استنزاف النطاق الترددي*\n"
                      f"استقبال: *{recv_mb:.1f} MB/s* (الحد: {CONFIG['BANDWIDTH_MB']} MB/s)\n"
                      f"إرسال: *{sent_mb:.1f} MB/s*\n"
                      f"محتمل: DDoS أو تسريب بيانات",
                      "🌊", severity="HIGH")

            if sent_mb > CONFIG["BANDWIDTH_MB"] * 2:
                alert("exfil",
                      f"📤 *تسريب بيانات محتمل*\n"
                      f"إرسال غير طبيعي: *{sent_mb:.1f} MB/s*",
                      "🔴", force=True, severity="HIGH")

        _prev_net      = current
        _prev_net_time = now

    except Exception as e:
        log.error(f"فحص النطاق: {e}")

# ================================================================
#   فحص المنافذ المفتوحة
# ================================================================
_known_ports = None

def check_open_ports():
    global _known_ports
    try:
        current_ports = {}
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                port = conn.laddr.port
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    pname = proc.name() if proc else "unknown"
                except Exception:
                    pname = "unknown"
                current_ports[port] = pname

        if _known_ports is not None:
            new_ports = set(current_ports.keys()) - set(_known_ports.keys())
            closed_ports = set(_known_ports.keys()) - set(current_ports.keys())

            for port in new_ports:
                pname = current_ports[port]
                if port in CONFIG["SENSITIVE_PORTS"]:
                    alert("open_port",
                          f"🔓 *منفذ خطير فُتح فجأة*\n"
                          f"المنفذ: *{port}*\n"
                          f"العملية: `{pname}`\n"
                          f"⚠️ قد يكون Backdoor أو برنامج ضار",
                          "🔓", force=True, severity="HIGH")
                else:
                    log.info(f"📌 منفذ جديد مفتوح: {port} ({pname})")

            if closed_ports:
                log.info(f"🔒 منافذ أُغلقت: {closed_ports}")

        _known_ports = current_ports
        log.info(f"🔌 منافذ مفتوحة: {len(current_ports)}")

    except Exception as e:
        log.error(f"فحص المنافذ: {e}")

# ================================================================
#   فحص العمليات المشبوهة
# ================================================================
SUSPICIOUS_NAMES = {
    "mimikatz", "meterpreter", "nc.exe", "ncat", "netcat",
    "psexec", "wce", "fgdump", "pwdump", "procdump",
    "cobaltstrike", "beacon", "empire",
}

def check_suspicious_processes():
    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            try:
                name = (proc.info["name"] or "").lower()
                if any(s in name for s in SUSPICIOUS_NAMES):
                    alert("suspicious_proc",
                          f"☠️ *عملية مشبوهة اكتُشفت*\n"
                          f"الاسم: `{proc.info['name']}`\n"
                          f"PID: `{proc.info['pid']}`\n"
                          f"المستخدم: `{proc.info['username']}`",
                          "☠️", force=True, severity="HIGH")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        log.error(f"فحص العمليات: {e}")

# ================================================================
#   تقرير الحالة
# ================================================================
def send_status_report():
    uptime  = time.time() - runtime_stats["start_time"]
    hours   = int(uptime // 3600)
    minutes = int((uptime % 3600) // 60)
    db_stats = db_get_stats()

    cpu  = psutil.cpu_percent()
    ram  = psutil.virtual_memory().percent

    blocked = db_get_blocked_ips()
    blocked_str = "\n".join([f"  • `{b[0]}` — {b[1][:30]}" for b in blocked[:5]])
    if len(blocked) > 5:
        blocked_str += f"\n  ... و{len(blocked) - 5} آخرين"

    msg = (
        f"📊 *تقرير ZEIN الدوري*\n\n"
        f"🏢 {CONFIG['COMPANY']}\n"
        f"⏱ وقت التشغيل: {hours}h {minutes}m\n\n"
        f"📈 *إحصائيات 24 ساعة:*\n"
        f"  🚨 أحداث: *{db_stats['events_24h']}*\n"
        f"  🔴 تهديدات حرجة: *{db_stats['high_severity']}*\n"
        f"  🚫 IPs محجوبة: *{db_stats['active_blocks']}*\n\n"
        f"💻 CPU: {cpu:.1f}% | RAM: {ram:.1f}%\n\n"
        f"🔴 *IPs المحجوبة الآن:*\n"
        f"{blocked_str if blocked_str else '  لا يوجد حظر نشط'}\n\n"
        f"✅ المنظومة تعمل بشكل طبيعي"
    )
    send_telegram(msg, "📊", priority=True)

# ================================================================
#   الحلقة الرئيسية
# ================================================================
def main_loop():
    setup_logging()
    init_database()

    log.info("=" * 60)
    log.info("  ZEIN Cyber Defense Agent v2.0 — Enterprise Edition")
    log.info(f"  الشركة: {CONFIG['COMPANY']}")
    log.info(f"  النظام: {platform.system()} {platform.release()}")
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = "غير معروف"
    log.info(f"  IP المحلي: {local_ip}")
    log.info(f"  قاعدة البيانات: {DB_FILE}")
    log.info(f"  الحجب التلقائي: {'✅ مفعّل' if CONFIG['AUTO_BLOCK'] else '⚠️ معطّل (توصيات فقط)'}")
    log.info("=" * 60)

    # تشغيل worker تيليجرام
    threading.Thread(target=_tg_worker, daemon=True).start()

    # إشعار البدء
    send_telegram(
        f"✅ *ZEIN v2.0 Enterprise تم تشغيله*\n\n"
        f"🖥 النظام: {platform.system()} {platform.release()}\n"
        f"🌐 IP: {local_ip}\n"
        f"🔄 فحص كل {CONFIG['SCAN_INTERVAL']} ثانية\n"
        f"🗄 قاعدة البيانات: نشطة",
        "🚀", priority=True
    )

    last_report   = time.time()
    last_cleanup  = time.time()
    scan_count    = 0

    while True:
        try:
            scan_count += 1
            log.info(f"── فحص #{scan_count} {'─'*40}")

            threads = [
                threading.Thread(target=check_system_resources,    daemon=True),
                threading.Thread(target=check_network_connections,  daemon=True),
                threading.Thread(target=check_bandwidth,            daemon=True),
                threading.Thread(target=check_open_ports,           daemon=True),
                threading.Thread(target=check_auth_logs,            daemon=True),
                threading.Thread(target=check_suspicious_processes, daemon=True),
            ]
            for t in threads: t.start()
            for t in threads: t.join(timeout=20)

            # تقرير دوري
            if time.time() - last_report > CONFIG["REPORT_INTERVAL"]:
                threading.Thread(target=send_status_report, daemon=True).start()
                last_report = time.time()

            # تنظيف دوري كل ساعة
            if time.time() - last_cleanup > 3600:
                unblock_expired_ips()
                last_cleanup = time.time()

            time.sleep(CONFIG["SCAN_INTERVAL"])

        except KeyboardInterrupt:
            log.info("⛔ إيقاف ZEIN من قِبل المستخدم")
            send_telegram("⛔ تم إيقاف ZEIN يدوياً", "⛔", priority=True)
            time.sleep(2)
            break
        except Exception as e:
            log.error(f"خطأ غير متوقع: {e}")
            time.sleep(5)

# ================================================================
#   الإعداد التفاعلي
# ================================================================
def first_run_setup():
    saved = load_config_encrypted()
    if saved:
        CONFIG.update(saved)
        log.info("✅ تم تحميل الإعداد المشفر")
        return

    print("\n" + "="*55)
    print("  ZEIN Cyber Defense v2.0 — الإعداد الأول")
    print("="*55)
    print("\n📱 تفعيل تنبيهات تيليجرام:")
    print("  1. افتح تيليجرام → @BotFather → /newbot")
    print("  2. احصل على Bot Token")
    print("  3. افتح @userinfobot → احصل على Chat ID\n")

    token   = input("🔑 Bot Token:    ").strip()
    chat    = input("💬 Chat ID:      ").strip()
    company = input("🏢 اسم الشركة:   ").strip()
    comp_id = input("🆔 Company ID (من الموقع): ").strip()
    auto    = input("🚫 تفعيل الحجب التلقائي؟ (y/n): ").strip().lower()

    if token and chat:
        CONFIG["TG_TOKEN"]   = token
        CONFIG["TG_CHAT_ID"] = chat
    if company:
        CONFIG["COMPANY"]    = company
    if comp_id:
        CONFIG["COMPANY_ID"] = comp_id
    CONFIG["AUTO_BLOCK"] = (auto == "y")

    save_config_encrypted(CONFIG)
    print(f"\n✅ تم حفظ الإعداد بشكل مشفر في: {CONFIG_FILE}")
    print(f"🔐 مفتاح التشفير: {KEY_FILE}")

# ================================================================
#   نقطة البداية
# ================================================================
if __name__ == "__main__":
    first_run_setup()
    main_loop()
