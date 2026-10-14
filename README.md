# ⚡ Mobile Home Server

> **Ultra low-power personal home server & IoT hub for Android (Termux) and PC. Features built-in battery UPS guard, real-time hardware telemetry, CCTV security cam, local Wi-Fi radar, shared clipboard sync, and zero-config Cloudflare tunnels.**

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Termux](https://img.shields.io/badge/Termux-Supported-10b981?style=flat&logo=android&logoColor=white)](https://termux.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An ultra-lightweight, self-hosted server and dashboard designed to run seamlessly on Android devices (via [Termux](https://termux.dev)) or on any desktop/laptop (Windows, Linux, macOS).

---

## 🌟 Why an Android Phone as a Server?

* 🔋 **Built-in Battery UPS**: Immune to sudden power outages — built-in battery keeps the server online.
* ⚡ **Ultra Low Power**: Draws only ~2–4W compared to 60–100W+ for desktop servers.
* 📷 **Built-in Sensors & Hardware**: Camera, flashlight, battery sensors, Wi-Fi, and 4G/5G connectivity in one pocketable device.
* ♻️ **Upcycle Old Hardware**: Give old smartphones a productive second life instead of letting them sit in drawers.

---

## ✨ Features

### 🚀 Phone Superpowers (Hardware Integration)
* 📸 **CCTV / IP Webcam**: Live camera viewfinder with front/back camera switching and an auto-refreshing 5s CCTV surveillance mode.
* 🔦 **Remote Flashlight / Torch**: Remotely toggle the phone's physical flash LED with one click.
* 🗣️ **Text-to-Speech (TTS)**: Broadcast voice announcements through the phone's speaker directly from your browser.
* 📳 **Haptic / Alarm Alert**: Remotely vibrate the phone for alerts.
* 🔋 **Battery Health Guard**: Continuous monitoring of battery level and temperature with smart advisory alerts to prevent battery swelling when plugged in 24/7.
* 📋 **Universal Clipboard Sync**: Seamlessly read or push text between your computer and the phone's system clipboard with one click.

### 📡 Network Radar & Utilities
* 📡 **Network Device Radar (Wi-Fi Scanner)**: Discover active client devices, routers, and IoT hardware connected to your local Wi-Fi subnet with IP and MAC resolution.
* 📝 **Persistent Scratchpad**: Shared sticky notes for code snippets, to-dos, and quick notes auto-saved directly to your server.

### 📊 Real-Time Telemetry & Visuals
* 📈 **60-Second Real-Time Telemetry Graph**: Smooth canvas chart displaying real-time CPU %, RAM %, and network traffic over the last minute.
* 🌓 **Dark / Light Mode**: Modern interface with an obsidian dark theme, emerald accents, and theme persistence.
* 📱 **Instant Wi-Fi QR Connect**: Display an offline QR code to connect mobile phones or laptops on your local network instantly without typing IP addresses.
* 🌐 **Zero-Config Remote Access**: 1-click toggle for Cloudflare Tunnel (`cloudflared`) to access your server globally over HTTPS without port forwarding.

### 📁 Cloud Storage & Media Sharing
* 📁 **Web File Manager**: Browse, create folders, download, rename, and delete files.
* 📂 **Folder Upload**: Upload entire directories with nested hierarchies preserved.
* 🎬 **In-line Media Preview**: Stream videos, music, and images directly in the browser.
* 🔒 **Hardened Security**: Timing-safe token authentication (`secrets.compare_digest`), automated brute-force IP rate-limiting, and blocked executable uploads.

---

## 🚀 Quick Start

### 📱 Running on Android (Termux)

1. **Install Termux and Termux:API** from [F-Droid](https://f-droid.org/en/packages/com.termux/).
2. **Open Termux** and install required packages:
   ```bash
   pkg update -y
   pkg install -y python git termux-api
   ```
3. **Clone the repository**:
   ```bash
   git clone https://github.com/parvlabs/mobile-home-server.git ~/server
   cd ~/server
   ```
4. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
5. **Start all services**:
   ```bash
   bash start-all.sh
   ```
6. **Open the Dashboard**:
   The terminal will display your local IP. Open your browser on any device on the same Wi-Fi:
   ```text
   http://<PHONE_IP>:8080
   ```

---

### 💻 Running Locally on Windows / macOS / Linux

1. **Clone the repository**:
   ```bash
   git clone https://github.com/parvlabs/mobile-home-server.git
   cd mobile-home-server
   ```
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Launch the server**:
   * **Windows (One-Click)**: Double-click `start-local.bat`
   * **Any OS (Terminal)**:
     ```bash
     python run_local.py
     ```
   The script will launch both services, print your access token, and open the dashboard in your default browser automatically.

---

## 📂 Project Structure

```text
mobile-home-server/
├── api.py              # Flask backend REST API (telemetry, phone controls, files, logs)
├── index.html          # Frontend web dashboard (telemetry charts, camera, file manager)
├── run_local.py        # Cross-platform runner for Windows / macOS / Linux
├── start-local.bat     # One-click Windows batch launcher
├── start-all.sh        # Background launcher for Termux / Linux
├── start-api.sh        # Foreground API debug launcher
├── start-dashboard.sh  # Foreground HTTP server debug launcher
├── start-server.sh     # Boot script for Termux:Boot app
├── requirements.txt    # Python dependencies
├── .gitignore          # Security rules (ignores tokens, logs, uploaded files)
└── README.md           # Documentation
```

---

## 🔒 Security Model

* **Sandboxed Storage**: File Manager access is strictly confined to `~/server/shared/`. Path traversal (`../`, absolute paths, symlinks) is blocked via sanitized paths.
* **Token Authentication**: Modifying files, server controls, and phone hardware features require the `Authorization: Bearer <token>` header. Tokens are generated locally on first startup in `.token`.
* **Private Network First**: By default, CORS is constrained to local network and private IP subnets (10.x, 172.16-31.x, 192.168.x, localhost).
* **Safe Error Handling**: Unhandled errors return sanitized JSON responses without leaking Python tracebacks.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
