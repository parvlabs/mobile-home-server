"""
Samsung A23 Server — Flask API
--------------------------------------------------------------
Run with:
    python3 api.py

Listens on 0.0.0.0:5000 (LAN only — never expose this to the
public internet).

Requires:
    pip install flask flask-cors
    pkg install termux-api      (provides termux-battery-status)
    The separate "Termux:API" app must be installed on the device.

SECURITY MODEL
    - File-manager access is confined to ~/server/shared/ only —
      NOT the whole phone storage. safe_join() blocks any path
      that would escape it (../, absolute paths, symlink escapes).
    - .token and the logs/ directory live outside ~/server/shared/,
      so they are structurally unreachable through file endpoints.
    - File-management, server-control, and log-clear endpoints
      require `Authorization: Bearer <token>` (or ?token= for the
      two GET endpoints that need to be opened directly by the
      browser: download and stream).
    - Server controls only ever call one of a small, hardcoded set
      of actions (start/stop/restart web|api|ssh|all). There is no
      endpoint that runs an arbitrary command.
    - CORS is restricted to local-network origins on port 8080
      (10.x, 172.16-31.x, 192.168.x, localhost) rather than "*".
    - debug=False always; unhandled errors return a generic JSON
      message, never a Python traceback.
"""

import getpass
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from functools import wraps
from logging.handlers import RotatingFileHandler

import io
import platform

try:
    import psutil
except ImportError:
    psutil = None

try:
    from PIL import Image, ImageDraw
except ImportError:
    Image = None
    ImageDraw = None

try:
    import qrcode
except ImportError:
    qrcode = None

from flask import Flask, jsonify, request, send_file, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename

# ================================================================
# CONFIG
# ================================================================
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SERVER_DIR, "logs")
TOKEN_FILE = os.path.join(SERVER_DIR, ".token")
FILE_ROOT = os.path.join(SERVER_DIR, "shared")          # File Manager / media root
DASHBOARD_PID_FILE = os.path.join(LOG_DIR, "dashboard.pid")

API_PORT = 5000
DASHBOARD_PORT = 8080
SSH_DEFAULT_PORT = 8022

# State for Cloudflare Tunnel
_tunnel_proc = None
_tunnel_url = None

def get_device_info_meta():
    """Dynamically autodetects device model, brand, OS version, and CPU architecture."""
    env_name = os.environ.get("SERVER_DEVICE_NAME")
    brand = ""
    model = ""
    try:
        p_brand = subprocess.run(["getprop", "ro.product.brand"], capture_output=True, text=True, timeout=1)
        if p_brand.returncode == 0:
            brand = p_brand.stdout.strip().capitalize()
        p_model = subprocess.run(["getprop", "ro.product.model"], capture_output=True, text=True, timeout=1)
        if p_model.returncode == 0:
            model = p_model.stdout.strip()
    except Exception:
        pass

    if env_name:
        device_name = env_name
    elif model:
        device_name = f"{brand} {model}".strip()
    else:
        sys_name = platform.system()
        node_name = platform.node()
        if sys_name == "Windows":
            device_name = f"Windows Host ({node_name})"
        elif sys_name == "Darwin":
            device_name = f"macOS Host ({node_name})"
        elif sys_name == "Linux":
            if "com.termux" in os.environ.get("PREFIX", "") or os.path.exists("/data/data/com.termux"):
                device_name = "Android (Termux Host)"
            else:
                device_name = f"Linux Host ({node_name})"
        else:
            device_name = f"Host ({node_name})"

    os_ver = "Unknown"
    try:
        p_os = subprocess.run(["getprop", "ro.build.version.release"], capture_output=True, text=True, timeout=1)
        if p_os.returncode == 0 and p_os.stdout.strip():
            os_ver = f"Android {p_os.stdout.strip()}"
    except Exception:
        pass
    if os_ver == "Unknown":
        os_ver = f"{platform.system()} {platform.release()}"

    arch = platform.machine() or "unknown"
    return {"device_name": device_name, "os_version": os_ver, "arch": arch}

# Real internal storage (for the Storage Usage stat only — NOT the
# file manager root). Requires `termux-setup-storage` once.
STORAGE_STAT_PATH = "/storage/emulated/0"

MAX_UPLOAD_BYTES = 300 * 1024 * 1024  # 300 MB per upload

ALLOWED_LOG_FILES = {"server.log", "api-stdout.log", "dashboard-stdout.log"}
MEDIA_PREVIEW_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".mp4", ".webm", ".mov",
    ".mp3", ".wav", ".ogg", ".m4a",
}

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(FILE_ROOT, exist_ok=True)

START_TIME = time.time()

# ================================================================
# LOGGING (rotating, size-capped so it can't fill phone storage)
# ================================================================
logger = logging.getLogger("a23server")
logger.setLevel(logging.INFO)
_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, "server.log"), maxBytes=2 * 1024 * 1024, backupCount=3
)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_handler)


def log_event(message, level="info"):
    getattr(logger, level, logger.info)(message)


# ================================================================
# AUTH — per-install token, Authorization: Bearer header
# ================================================================
def load_or_create_token():
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE) as f:
                tok = f.read().strip()
                if tok:
                    return tok
        except Exception:
            pass
    tok = secrets.token_hex(16)
    try:
        with open(TOKEN_FILE, "w") as f:
            f.write(tok)
        os.chmod(TOKEN_FILE, 0o600)
    except Exception as err:
        print(f"[token] could not persist token file: {err}")
    return tok


API_TOKEN = load_or_create_token()

# ================================================================
# SECURITY: Brute-Force Rate Limiter & Constant-Time Auth
# ================================================================
_failed_auth_attempts = {}  # ip -> [timestamps]
_banned_ips = {}            # ip -> ban_until_timestamp
MAX_FAILED_ATTEMPTS = 10
BAN_DURATION_SECONDS = 300  # 5 minutes lockout

def is_ip_banned(ip):
    now = time.time()
    ban_until = _banned_ips.get(ip, 0)
    if now < ban_until:
        return True
    if ip in _banned_ips:
        del _banned_ips[ip]
    return False

def record_failed_attempt(ip):
    now = time.time()
    attempts = [t for t in _failed_auth_attempts.get(ip, []) if now - t < 60]
    attempts.append(now)
    _failed_auth_attempts[ip] = attempts
    if len(attempts) >= MAX_FAILED_ATTEMPTS:
        _banned_ips[ip] = now + BAN_DURATION_SECONDS
        log_event(f"SECURITY ALERT: IP {ip} temporarily locked out for {BAN_DURATION_SECONDS}s due to failed token attempts.", level="warning")

def extract_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.args.get("token")


def require_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr or "127.0.0.1"
        if is_ip_banned(client_ip):
            return jsonify({"error": "Too many failed attempts. Temporarily locked out for 5 minutes."}), 429

        token = extract_token()
        if not token or not API_TOKEN or not secrets.compare_digest(token, API_TOKEN):
            record_failed_attempt(client_ip)
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)

    return wrapper


# ================================================================
# APP SETUP & SECURITY HEADERS
# ================================================================
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

LOCAL_ORIGIN_RE = re.compile(
    r"^https?://(?:10(?:\.\d{1,3}){3}"
    r"|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r"|127\.0\.0\.1|localhost)(?::\d+)?$"
)
CORS(app, origins=LOCAL_ORIGIN_RE)


@app.after_request
def apply_security_headers_and_log(response):
    # Defense-in-depth security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Redact sensitive query parameters (e.g. ?token=) from logs
    try:
        clean_path = request.path
        logger.info(f"{request.remote_addr} {request.method} {clean_path} -> {response.status_code}")
    except Exception:
        pass
    return response


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "File too large"}), 413


@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    # Never leak a traceback or internal detail to the browser.
    logger.error(f"Unhandled error: {e}")
    return jsonify({"error": "Internal server error"}), 500


# ================================================================
# SECURITY: confine all file access to FILE_ROOT (~/server/shared)
# ================================================================
def safe_join(root, rel_path):
    root_real = os.path.realpath(root)
    rel_path = (rel_path or "").replace("\\", "/").lstrip("/")
    if "\x00" in rel_path:
        raise ValueError("Invalid path")
    candidate = os.path.realpath(os.path.join(root_real, rel_path))
    if candidate != root_real and not candidate.startswith(root_real + os.sep):
        raise ValueError("Path traversal attempt blocked")
    return candidate


def to_relative(abs_path):
    rel = os.path.relpath(abs_path, os.path.realpath(FILE_ROOT))
    return "" if rel == "." else rel.replace(os.sep, "/")


# ================================================================
# DEVICE / SYSTEM INFO
# ================================================================
def get_uptime_seconds():
    return int(time.time() - START_TIME)


def get_storage_info():
    """Real usage of actual phone storage, with fallback to local drive when previewing."""
    stat_path = STORAGE_STAT_PATH if os.path.isdir(STORAGE_STAT_PATH) else SERVER_DIR
    try:
        usage = shutil.disk_usage(stat_path)
        gb = 1024 ** 3
        return {
            "total_gb": round(usage.total / gb, 2),
            "used_gb": round(usage.used / gb, 2),
            "free_gb": round(usage.free / gb, 2),
        }
    except Exception as err:
        log_event(f"Storage read failed: {err}", level="error")
        return {"total_gb": None, "used_gb": None, "free_gb": None}


def get_battery_info():
    fields = {
        "percentage": None, "level": None, "health": None,
        "temperature": None, "voltage": None, "current": None,
        "current_average": None, "plugged": None, "status": None,
        "technology": None, "charge_counter": None, "cycle": None,
    }
    # 1. Termux API (Android)
    try:
        result = subprocess.run(
            ["termux-battery-status"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            raw = json.loads(result.stdout)
            for key in ("percentage", "health", "temperature", "voltage", "current",
                        "current_average", "plugged", "status", "technology",
                        "charge_counter", "cycle"):
                fields[key] = raw.get(key)
            if fields["percentage"] is not None:
                fields["level"] = round(fields["percentage"] / 100, 2)
            return fields
    except Exception:
        pass

    # 2. psutil fallback (Laptop / Desktop / Local Preview)
    if psutil and hasattr(psutil, "sensors_battery"):
        try:
            bat = psutil.sensors_battery()
            if bat:
                fields["percentage"] = round(bat.percent, 1)
                fields["level"] = round(bat.percent / 100, 2)
                fields["plugged"] = "PLUGGED_AC" if bat.power_plugged else "UNPLUGGED"
                fields["status"] = "CHARGING" if bat.power_plugged else "DISCHARGING"
                fields["health"] = "GOOD"
                return fields
        except Exception:
            pass

    return fields


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as err:
        log_event(f"Could not determine local IP: {err}", level="warning")
        return None


def get_network_interface():
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"], capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            parts = result.stdout.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return None


_net_sample_cache = {}


def read_net_bytes(interface):
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if ":" not in line:
                    continue
                name, data = line.split(":", 1)
                if name.strip() == interface:
                    fields = data.split()
                    return int(fields[0]), int(fields[8])  # rx_bytes, tx_bytes
    except Exception:
        pass
    return None, None


def get_network_traffic(interface):
    empty = {"rx_bytes": None, "tx_bytes": None, "rx_rate_bps": None, "tx_rate_bps": None}
    now = time.time()
    if interface:
        rx, tx = read_net_bytes(interface)
        if rx is not None:
            prev = _net_sample_cache.get(interface)
            rx_rate = tx_rate = None
            if prev:
                prev_rx, prev_tx, prev_time = prev
                dt = now - prev_time
                if 0 < dt < 30:
                    rx_rate = round(max(0, (rx - prev_rx) / dt), 1)
                    tx_rate = round(max(0, (tx - prev_tx) / dt), 1)
            _net_sample_cache[interface] = (rx, tx, now)
            return {"rx_bytes": rx, "tx_bytes": tx, "rx_rate_bps": rx_rate, "tx_rate_bps": tx_rate}

    # psutil fallback for Windows / local preview
    if psutil:
        try:
            net_io = psutil.net_io_counters()
            rx, tx = net_io.bytes_recv, net_io.bytes_sent
            prev = _net_sample_cache.get("__psutil__")
            rx_rate = tx_rate = None
            if prev:
                prev_rx, prev_tx, prev_time = prev
                dt = now - prev_time
                if 0 < dt < 30:
                    rx_rate = round(max(0, (rx - prev_rx) / dt), 1)
                    tx_rate = round(max(0, (tx - prev_tx) / dt), 1)
            _net_sample_cache["__psutil__"] = (rx, tx, now)
            return {"rx_bytes": rx, "tx_bytes": tx, "rx_rate_bps": rx_rate, "tx_rate_bps": tx_rate}
        except Exception:
            pass

    return empty


def check_port_open(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def find_pid(pattern):
    """Best-effort PID lookup by command-line pattern. Never raises."""
    try:
        result = subprocess.run(["pgrep", "-af", pattern], capture_output=True, text=True, timeout=3)
        if result.returncode == 0 and result.stdout.strip():
            first_line = result.stdout.strip().splitlines()[0]
            return int(first_line.split()[0])
    except Exception:
        pass

    # psutil fallback (cross-platform)
    if psutil:
        try:
            my_pid = os.getpid()
            for proc in psutil.process_iter(["pid", "cmdline"]):
                if proc.info["pid"] == my_pid:
                    continue
                cmd = " ".join(proc.info.get("cmdline") or [])
                if pattern in cmd:
                    return proc.info["pid"]
        except Exception:
            pass
    return None


def read_pid_file(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)  # raises if the process is gone
        return pid
    except Exception:
        return None


def get_ssh_status():
    """Tri-state: online / offline / unknown — never guessed."""
    for p in (SSH_DEFAULT_PORT, 22):
        if check_port_open("127.0.0.1", p):
            return {"status": "online", "port": p}
    try:
        result = subprocess.run(["pgrep", "-f", "sshd"], capture_output=True, text=True, timeout=3)
    except Exception:
        return {"status": "unknown", "port": None}
    if result.returncode == 0 and result.stdout.strip():
        return {"status": "online", "port": None}
    if result.returncode == 1:
        return {"status": "offline", "port": None}
    return {"status": "unknown", "port": None}


def get_termux_username():
    try:
        return getpass.getuser()
    except Exception:
        return None


# ---- CPU / RAM: Android/Termux-compatible, no psutil, no root ----
def _read_cpu_snapshot():
    with open("/proc/stat") as f:
        line = f.readline()
    nums = list(map(int, line.split()[1:8]))  # user nice system idle iowait irq softirq
    idle = nums[3] + nums[4]
    return idle, sum(nums)


def get_cpu_usage():
    try:
        idle1, total1 = _read_cpu_snapshot()
        time.sleep(0.15)
        idle2, total2 = _read_cpu_snapshot()
        dtotal = total2 - total1
        if dtotal <= 0:
            return None
        usage = (1 - (idle2 - idle1) / dtotal) * 100
        return round(max(0, min(100, usage)), 1)
    except Exception:
        pass

    # psutil fallback
    if psutil:
        try:
            return round(psutil.cpu_percent(interval=0.1), 1)
        except Exception:
            pass
    return None


def get_ram_usage():
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    info[parts[0].strip()] = int(parts[1].strip().split()[0])
        total = info.get("MemTotal")
        avail = info.get("MemAvailable")
        if not total or avail is None:
            return None
        return round(max(0, min(100, (total - avail) / total * 100)), 1)
    except Exception:
        pass

    # psutil fallback
    if psutil:
        try:
            return round(psutil.virtual_memory().percent, 1)
        except Exception:
            pass
    return None


# ================================================================
# ROUTES: dashboard / status / services / network / server-info
# ================================================================
@app.route("/", methods=["GET"])
@app.route("/dashboard", methods=["GET"])
def dashboard_home():
    index_path = os.path.join(SERVER_DIR, "index.html")
    if os.path.isfile(index_path):
        return send_file(index_path)
    return jsonify({"message": "Samsung A23 Server API is running"}), 200


@app.route("/api/status", methods=["GET"])
def status():
    dev_meta = get_device_info_meta()
    try:
        storage = get_storage_info()
    except Exception as err:
        log_event(f"Status: storage section failed: {err}", level="error")
        storage = {"total_gb": None, "used_gb": None, "free_gb": None}
    try:
        battery = get_battery_info()
    except Exception as err:
        log_event(f"Status: battery section failed: {err}", level="error")
        battery = {}
    try:
        network_ip = get_local_ip()
    except Exception:
        network_ip = None
    try:
        network_interface = get_network_interface()
    except Exception:
        network_interface = None
    try:
        ssh = get_ssh_status()
    except Exception:
        ssh = {"status": "unknown", "port": None}
    try:
        cpu = get_cpu_usage()
    except Exception:
        cpu = None
    try:
        ram = get_ram_usage()
    except Exception:
        ram = None

    # Battery Health Guard calculation
    swelling_risk = False
    guard_msg = "Battery state normal."
    bat_pct = battery.get("percentage")
    bat_plugged = battery.get("plugged")
    if bat_pct is not None and bat_pct >= 95 and bat_plugged in ("PLUGGED_AC", "PLUGGED_USB"):
        swelling_risk = True
        guard_msg = "Battery is at 100% and continuously charging. For 24/7 server longevity, consider unplugging or using a smart plug to avoid battery swelling."
    elif bat_pct is not None and bat_pct < 20 and bat_plugged == "UNPLUGGED":
        guard_msg = "Battery low (<20%). Connect charger to avoid unexpected server shutdown."

    battery_guard = {
        "swelling_risk": swelling_risk,
        "message": guard_msg,
    }

    tunnel_running = _tunnel_proc is not None and _tunnel_proc.poll() is None

    return jsonify({
        "device": dev_meta["device_name"],
        "os_version": dev_meta["os_version"],
        "arch": dev_meta["arch"],
        "status": "online",
        "uptime_seconds": get_uptime_seconds(),
        "storage": storage,
        "battery": battery,
        "battery_guard": battery_guard,
        "cpu": cpu,
        "ram": ram,
        "network": network_ip,
        "network_interface": network_interface,
        "ssh": ssh,
        "tunnel": {
            "running": tunnel_running,
            "url": _tunnel_url if tunnel_running else None,
        },
    })


@app.route("/api/services", methods=["GET"])
def services():
    dashboard_pid = read_pid_file(DASHBOARD_PID_FILE) or find_pid("http.server")
    dashboard_up = check_port_open("127.0.0.1", DASHBOARD_PORT)
    ssh_info = get_ssh_status()
    ssh_pid = find_pid("sshd") if ssh_info["status"] == "online" else None
    file_manager_ok = os.path.isdir(FILE_ROOT)
    tunnel_running = _tunnel_proc is not None and _tunnel_proc.poll() is None

    return jsonify([
        {
            "name": "Web Server", "process": "python http.server",
            "port": DASHBOARD_PORT, "pid": dashboard_pid if dashboard_up else None,
            "status": "online" if dashboard_up else "offline",
        },
        {
            "name": "Flask API", "process": "api.py",
            "port": API_PORT, "pid": os.getpid(),
            "status": "online",
        },
        {
            "name": "SSH", "process": "sshd",
            "port": ssh_info["port"], "pid": ssh_pid,
            "status": ssh_info["status"],
        },
        {
            "name": "File Manager", "process": "n/a",
            "port": None, "pid": None,
            "status": "online" if file_manager_ok else "unknown",
        },
        {
            "name": "Cloudflare Tunnel", "process": "cloudflared",
            "port": None, "pid": _tunnel_proc.pid if tunnel_running else None,
            "status": "online" if tunnel_running else "offline",
        },
    ])


@app.route("/api/network", methods=["GET"])
def network_info():
    interface = get_network_interface()
    ssh_info = get_ssh_status()
    return jsonify({
        "local_ip": get_local_ip(),
        "interface": interface,
        "dashboard_port": DASHBOARD_PORT,
        "api_port": API_PORT,
        "ssh_port": ssh_info["port"] or SSH_DEFAULT_PORT,
        "dashboard_reachable": check_port_open("127.0.0.1", DASHBOARD_PORT),
        "traffic": get_network_traffic(interface),
    })


@app.route("/api/server/info", methods=["GET"])
def server_info():
    dev_meta = get_device_info_meta()
    ip = get_local_ip()
    ssh_info = get_ssh_status()
    username = get_termux_username()
    connect_cmd = (
        f"ssh {username}@{ip} -p {ssh_info['port'] or SSH_DEFAULT_PORT}"
        if ip and username else None
    )
    return jsonify({
        "device": dev_meta["device_name"],
        "os_version": dev_meta["os_version"],
        "arch": dev_meta["arch"],
        "local_ip": ip,
        "dashboard_port": DASHBOARD_PORT,
        "api_port": API_PORT,
        "ssh": {**ssh_info, "connect_command": connect_cmd},
        "uptime_seconds": get_uptime_seconds(),
    })


# ================================================================
# ROUTES: CLOUDFLARE REMOTE TUNNEL
# ================================================================


@app.route("/api/tunnel/status", methods=["GET"])
def tunnel_status():
    global _tunnel_proc, _tunnel_url
    running = _tunnel_proc is not None and _tunnel_proc.poll() is None
    if not running:
        _tunnel_url = None
    installed = shutil.which("cloudflared") is not None
    return jsonify({
        "installed": installed,
        "running": running,
        "url": _tunnel_url,
    })


@app.route("/api/tunnel/start", methods=["POST"])
@require_token
def tunnel_start():
    global _tunnel_proc, _tunnel_url
    if not shutil.which("cloudflared"):
        return jsonify({
            "error": "cloudflared not found",
            "instructions": "Install via 'pkg install cloudflared' on Termux or 'winget install cloudflare.cloudflared' on Windows.",
        }), 400

    if _tunnel_proc is not None and _tunnel_proc.poll() is None:
        return jsonify({"status": "already_running", "url": _tunnel_url})

    _tunnel_url = None
    try:
        _tunnel_proc = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", f"http://127.0.0.1:{DASHBOARD_PORT}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        def monitor_tunnel(proc):
            global _tunnel_url
            for line in iter(proc.stdout.readline, ""):
                m = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", line)
                if m:
                    _tunnel_url = m.group(0)
                    log_event(f"Cloudflare Tunnel active at: {_tunnel_url}")
                    break
                if proc.poll() is not None:
                    break

        threading.Thread(target=monitor_tunnel, args=(_tunnel_proc,), daemon=True).start()
        time.sleep(1.5)
    except Exception as err:
        log_event(f"Failed to start tunnel: {err}", level="error")
        return jsonify({"error": f"Failed to start cloudflared: {err}"}), 500

    return jsonify({"status": "starting", "url": _tunnel_url})


@app.route("/api/tunnel/stop", methods=["POST"])
@require_token
def tunnel_stop():
    global _tunnel_proc, _tunnel_url
    if _tunnel_proc is not None:
        try:
            _tunnel_proc.terminate()
        except Exception:
            pass
        _tunnel_proc = None
    _tunnel_url = None
    log_event("Cloudflare Tunnel stopped")
    return jsonify({"status": "stopped"})


@app.route("/api/qrcode", methods=["GET"])
def qr_code_endpoint():
    """Generates a QR code PNG or SVG for easy mobile/Wi-Fi connection."""
    raw_data = request.args.get("data")
    if not raw_data:
        ip = get_local_ip() or "127.0.0.1"
        raw_data = f"http://{ip}:{DASHBOARD_PORT}"

    if qrcode:
        try:
            qr = qrcode.QRCode(box_size=8, border=2)
            qr.add_data(raw_data)
            qr.make(fit=True)
            img = qr.make_image(fill_color="#000000", back_color="#ffffff")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            buf.seek(0)
            return send_file(buf, mimetype="image/png")
        except Exception:
            pass

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="220" height="220" viewBox="0 0 220 220">
      <rect width="220" height="220" fill="#ffffff" rx="8"/>
      <text x="110" y="100" fill="#111" font-family="sans-serif" font-size="12" text-anchor="middle">Scan URL:</text>
      <text x="110" y="125" fill="#00dc82" font-family="sans-serif" font-size="11" font-weight="bold" text-anchor="middle">{raw_data[:30]}</text>
    </svg>"""
    return Response(svg, mimetype="image/svg+xml")


# ================================================================
# ROUTES: file manager (confined to FILE_ROOT = ~/server/shared)
# ================================================================
@app.route("/api/files", methods=["GET"])
@require_token
def list_files():
    rel_path = request.args.get("path", "")
    try:
        target = safe_join(FILE_ROOT, rel_path)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.isdir(target):
        return jsonify({"error": "Not a directory"}), 404

    entries = []
    try:
        with os.scandir(target) as it:
            for entry in it:
                try:
                    st = entry.stat()
                    ext = os.path.splitext(entry.name)[1].lower()
                    entries.append({
                        "name": entry.name,
                        "is_dir": entry.is_dir(),
                        "size_bytes": None if entry.is_dir() else st.st_size,
                        "modified": int(st.st_mtime),
                        "previewable": (not entry.is_dir()) and ext in MEDIA_PREVIEW_EXTS,
                    })
                except Exception:
                    continue
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as err:
        log_event(f"List files failed: {err}", level="error")
        return jsonify({"error": "Could not list directory"}), 500

    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    rel_display = to_relative(target)
    log_event(f"Listed directory: /{rel_display}")
    return jsonify({"path": rel_display, "entries": entries})


@app.route("/api/files/download", methods=["GET"])
@require_token
def download_file():
    rel_path = request.args.get("path", "")
    try:
        target = safe_join(FILE_ROOT, rel_path)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.isfile(target):
        return jsonify({"error": "File not found"}), 404
    log_event(f"Downloaded file: {rel_path}")
    try:
        return send_file(target, as_attachment=True)
    except Exception as err:
        log_event(f"Download failed: {err}", level="error")
        return jsonify({"error": "Download failed"}), 500


@app.route("/api/files/stream", methods=["GET"])
@require_token
def stream_file():
    """Inline view for images/video/audio (Media Sharing preview)."""
    rel_path = request.args.get("path", "")
    try:
        target = safe_join(FILE_ROOT, rel_path)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.isfile(target):
        return jsonify({"error": "File not found"}), 404
    log_event(f"Streamed file: {rel_path}")
    try:
        return send_file(target, as_attachment=False)
    except Exception as err:
        log_event(f"Stream failed: {err}", level="error")
        return jsonify({"error": "Could not stream file"}), 500


@app.route("/api/files/upload", methods=["POST"])
@require_token
def upload_file():
    """
    Handles both:
      - a single plain file upload (existing behavior, unchanged), and
      - one file of a folder upload, identified by an optional
        `relative_path` form field (e.g. "MyProject/css/style.css"),
        sent by the dashboard's Upload Folder feature — one request
        per file, so large folders never block the dashboard.

    Every path segment of `relative_path` is sanitized individually
    and the final destination is re-verified with safe_join(), so a
    crafted relative_path (e.g. "../../x") can never escape FILE_ROOT.
    """
    rel_path = request.form.get("path", "")
    try:
        target_dir = safe_join(FILE_ROOT, rel_path)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.isdir(target_dir):
        return jsonify({"error": "Target directory not found"}), 404
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    relative_path = (request.form.get("relative_path") or "").strip()

    if relative_path:
        # Folder upload: rebuild the sub-path under the current
        # directory, sanitizing every segment (drops any "..", ".",
        # empty segments, or unsafe characters).
        relative_path = relative_path.replace("\\", "/")
        segments = [s for s in relative_path.split("/") if s not in ("", ".", "..")]
        safe_segments = [secure_filename(s) for s in segments]
        safe_segments = [s for s in safe_segments if s]
        if not safe_segments:
            return jsonify({"error": "Invalid relative path"}), 400

        sub_rel = "/".join(safe_segments)
        try:
            dest = safe_join(FILE_ROOT, f"{rel_path}/{sub_rel}" if rel_path else sub_rel)
        except ValueError:
            return jsonify({"error": "Invalid path"}), 400

        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
        except Exception as err:
            log_event(f"Could not create folder for upload: {err}", level="error")
            return jsonify({"error": "Could not create destination folder"}), 500

        filename = safe_segments[-1]
    else:
        # Plain single-file upload
        filename = secure_filename(file.filename or "")
        if not filename:
            return jsonify({"error": "Invalid filename"}), 400
        dest = os.path.join(target_dir, filename)

    # Security: Prohibit uploading executable scripts and binaries
    ext = os.path.splitext(filename)[1].lower()
    DANGEROUS_EXTS = {".exe", ".bat", ".cmd", ".sh", ".bash", ".ps1", ".vbs", ".pif", ".scr", ".com", ".apk", ".php", ".py", ".pl"}
    if ext in DANGEROUS_EXTS:
        log_event(f"Blocked dangerous upload attempt: {filename}", level="warning")
        return jsonify({"error": f"Upload blocked: '{ext}' executable/script files are prohibited for security."}), 400

    try:
        file.save(dest)
        try:
            os.chmod(dest, 0o644)
        except Exception:
            pass
    except Exception as err:
        log_event(f"Upload failed: {err}", level="error")
        return jsonify({"error": "Upload failed"}), 500

    uploaded_rel = to_relative(dest)
    log_event(f"Uploaded file: {uploaded_rel}")
    return jsonify({"message": "uploaded", "name": filename, "path": uploaded_rel})


@app.route("/api/files/create-folder", methods=["POST"])
@require_token
def create_folder():
    data = request.get_json(silent=True) or {}
    rel_path = data.get("path", "")
    name = secure_filename(data.get("name", ""))
    if not name:
        return jsonify({"error": "Invalid folder name"}), 400
    try:
        new_dir = safe_join(FILE_ROOT, f"{rel_path}/{name}" if rel_path else name)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if os.path.exists(new_dir):
        return jsonify({"error": "Already exists"}), 409
    try:
        os.makedirs(new_dir)
    except Exception as err:
        log_event(f"Create-folder failed: {err}", level="error")
        return jsonify({"error": "Could not create folder"}), 500
    log_event(f"Created folder: {rel_path}/{name}")
    return jsonify({"message": "created"})


@app.route("/api/files/rename", methods=["POST"])
@require_token
def rename_item():
    data = request.get_json(silent=True) or {}
    rel_path = data.get("path", "")
    new_name = secure_filename(data.get("new_name", ""))
    if not new_name:
        return jsonify({"error": "Invalid new name"}), 400
    try:
        source = safe_join(FILE_ROOT, rel_path)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.exists(source):
        return jsonify({"error": "Not found"}), 404

    parent_rel = os.path.dirname(rel_path.rstrip("/"))
    try:
        dest = safe_join(FILE_ROOT, f"{parent_rel}/{new_name}" if parent_rel else new_name)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if os.path.exists(dest):
        return jsonify({"error": "Target already exists"}), 409
    try:
        os.rename(source, dest)
    except Exception as err:
        log_event(f"Rename failed: {err}", level="error")
        return jsonify({"error": "Rename failed"}), 500
    log_event(f"Renamed: {rel_path} -> {new_name}")
    return jsonify({"message": "renamed"})


@app.route("/api/files", methods=["DELETE"])
@require_token
def delete_item():
    data = request.get_json(silent=True) or {}
    rel_path = data.get("path", "")
    if not rel_path:
        return jsonify({"error": "Path required"}), 400
    try:
        target = safe_join(FILE_ROOT, rel_path)
    except ValueError:
        return jsonify({"error": "Invalid path"}), 400
    if target == os.path.realpath(FILE_ROOT):
        return jsonify({"error": "Cannot delete the shared root directory"}), 400
    if not os.path.exists(target):
        return jsonify({"error": "Not found"}), 404
    try:
        if os.path.isdir(target):
            shutil.rmtree(target)
        else:
            os.remove(target)
    except Exception as err:
        log_event(f"Delete failed: {err}", level="error")
        return jsonify({"error": "Delete failed"}), 500
    log_event(f"Deleted: {rel_path}")
    return jsonify({"message": "deleted"})


# ================================================================
# ROUTES: logs (whitelisted filenames only — .token is never reachable)
# ================================================================
@app.route("/api/logs", methods=["GET"])
def get_logs():
    filename = request.args.get("file", "server.log")
    if filename not in ALLOWED_LOG_FILES:
        return jsonify({"error": "Invalid log file"}), 400
    lines = request.args.get("lines", default=100, type=int) or 100
    lines = max(1, min(lines, 1000))
    path = os.path.join(LOG_DIR, filename)
    if not os.path.exists(path):
        return jsonify({"file": filename, "lines": []})
    try:
        with open(path, "r", errors="replace") as f:
            content = f.readlines()
    except Exception as err:
        log_event(f"Could not read log file {filename}: {err}", level="error")
        return jsonify({"error": "Could not read log file"}), 500
    return jsonify({"file": filename, "lines": [l.rstrip("\n") for l in content[-lines:]]})


@app.route("/api/logs/clear", methods=["POST"])
@require_token
def clear_logs():
    data = request.get_json(silent=True) or {}
    filename = data.get("file")
    if filename not in ALLOWED_LOG_FILES:
        return jsonify({"error": "Invalid log file"}), 400
    path = os.path.join(LOG_DIR, filename)
    try:
        open(path, "w").close()
    except Exception as err:
        log_event(f"Failed to clear log {filename}: {err}", level="error")
        return jsonify({"error": "Could not clear log"}), 500
    log_event(f"Cleared log file: {filename}")
    return jsonify({"message": "cleared", "file": filename})


# ================================================================
# ROUTES: server controls — predefined actions only, no shell exec
# ================================================================
def _start_web():
    if check_port_open("127.0.0.1", DASHBOARD_PORT):
        return {"service": "web", "action": "start", "status": "already_running"}
    try:
        log_file = open(os.path.join(LOG_DIR, "dashboard-stdout.log"), "a")
        proc = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(DASHBOARD_PORT)],
            cwd=SERVER_DIR, stdout=log_file, stderr=subprocess.STDOUT,
        )
        with open(DASHBOARD_PID_FILE, "w") as f:
            f.write(str(proc.pid))
    except Exception as err:
        log_event(f"Failed to start web server: {err}", level="error")
        return {"service": "web", "action": "start", "status": "error"}
    log_event("Web server started via control API")
    return {"service": "web", "action": "start", "status": "started", "pid": proc.pid}


def _stop_web():
    pid = read_pid_file(DASHBOARD_PID_FILE) or find_pid("http.server")
    if not pid:
        return {"service": "web", "action": "stop", "status": "not_running"}
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except Exception as err:
        log_event(f"Failed to stop web server: {err}", level="error")
        return {"service": "web", "action": "stop", "status": "error"}
    if os.path.exists(DASHBOARD_PID_FILE):
        os.remove(DASHBOARD_PID_FILE)
    log_event("Web server stopped via control API")
    return {"service": "web", "action": "stop", "status": "stopped"}


def _restart_web():
    _stop_web()
    time.sleep(0.5)
    return _start_web()


def _start_ssh():
    if get_ssh_status()["status"] == "online":
        return {"service": "ssh", "action": "start", "status": "already_running"}
    try:
        subprocess.run(["sshd"], timeout=5)
    except Exception as err:
        log_event(f"Failed to start sshd: {err}", level="error")
        return {"service": "ssh", "action": "start", "status": "error"}
    log_event("SSH started via control API")
    return {"service": "ssh", "action": "start", "status": "started"}


def _stop_ssh():
    try:
        subprocess.run(["pkill", "-f", "sshd"], timeout=5)
    except Exception as err:
        log_event(f"Failed to stop sshd: {err}", level="error")
        return {"service": "ssh", "action": "stop", "status": "error"}
    log_event("SSH stopped via control API")
    return {"service": "ssh", "action": "stop", "status": "stopped"}


def _restart_ssh():
    _stop_ssh()
    time.sleep(0.5)
    return _start_ssh()


def _start_api():
    return {
        "service": "api", "action": "start", "status": "already_running",
        "note": "This API is already running — it just answered this request.",
    }


def _stop_api():
    log_event("API stop requested via control API")

    def do_stop():
        time.sleep(1)
        os._exit(0)

    threading.Thread(target=do_stop, daemon=True).start()
    return {"service": "api", "action": "stop", "status": "stopping"}


def _restart_api():
    log_event("API restart requested via control API")

    def do_restart():
        time.sleep(1)
        os.execv(sys.executable, [sys.executable] + sys.argv)

    threading.Thread(target=do_restart, daemon=True).start()
    return {"service": "api", "action": "restart", "status": "restarting"}


ACTION_TABLE = {
    ("web", "start"): _start_web, ("web", "stop"): _stop_web, ("web", "restart"): _restart_web,
    ("ssh", "start"): _start_ssh, ("ssh", "stop"): _stop_ssh, ("ssh", "restart"): _restart_ssh,
    ("api", "start"): _start_api, ("api", "stop"): _stop_api, ("api", "restart"): _restart_api,
}


def dispatch_control(action, service):
    if service == "all":
        order = ["ssh", "web", "api"]  # api last since "stop" ends this process
        return [ACTION_TABLE[(svc, action)]() for svc in order if (svc, action) in ACTION_TABLE]
    fn = ACTION_TABLE.get((service, action))
    return fn() if fn else None


@app.route("/api/control/<action>", methods=["POST"])
@require_token
def control(action):
    if action not in ("start", "stop", "restart"):
        return jsonify({"error": "Unknown action"}), 400
    data = request.get_json(silent=True) or {}
    service = data.get("service")
    if service not in ("web", "api", "ssh", "all"):
        return jsonify({"error": "Unknown service. Use web, api, ssh, or all."}), 400
    try:
        result = dispatch_control(action, service)
    except Exception as err:
        log_event(f"Control action failed ({action}/{service}): {err}", level="error")
        return jsonify({"error": "Action failed"}), 500
    if result is None:
        return jsonify({"error": "Unsupported action for this service"}), 400
    return jsonify({"result": result})


# ================================================================
# MAIN
# ================================================================
if __name__ == "__main__":
    log_event("Server API starting up")
    print("=" * 64)
    print("Samsung A23 Server API")
    print(f"Listening on 0.0.0.0:{API_PORT}")
    print()
    print("API access token (needed for File Manager & Server Controls):")
    print(API_TOKEN)
    print("Enter this once in the dashboard's Settings action.")
    print("=" * 64)
    app.run(host="0.0.0.0", port=API_PORT, debug=False)
