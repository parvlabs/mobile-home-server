#!/data/data/com.termux/files/usr/bin/bash
# Starts the Flask API in the foreground (use for debugging).
# For normal use, prefer start-all.sh (runs in background, checks
# for an already-running instance first).
cd ~/server || exit 1

port_open() {
  (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && exec 3<&- 3>&- && return 0 || return 1
}

if port_open 5000; then
  echo "Port 5000 is already in use — API may already be running. Not starting a duplicate."
  exit 1
fi

exec python3 api.py
