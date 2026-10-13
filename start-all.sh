#!/data/data/com.termux/files/usr/bin/bash
# Starts the API and dashboard as background processes.
# Safe to run multiple times — checks each port first and will
# NOT start a duplicate process if something is already listening.
cd ~/server || exit 1
mkdir -p logs shared

port_open() {
  (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && exec 3<&- 3>&- && return 0 || return 1
}

if port_open 5000; then
  echo "API: already running on port 5000 — skipping."
else
  nohup python3 api.py >> logs/api-stdout.log 2>&1 &
  echo $! > logs/api.pid
  echo "API: started (pid $(cat logs/api.pid))."
  sleep 1
fi

if port_open 8080; then
  echo "Dashboard: already running on port 8080 — skipping."
else
  nohup python3 -m http.server 8080 >> logs/dashboard-stdout.log 2>&1 &
  echo $! > logs/dashboard.pid
  echo "Dashboard: started (pid $(cat logs/dashboard.pid))."
fi

LOCAL_IP=$(python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    s.connect(('8.8.8.8', 80))
    print(s.getsockname()[0])
    s.close()
except Exception:
    print('unknown')
")

echo ""
echo "Dashboard: http://${LOCAL_IP}:8080"
echo "API:       http://${LOCAL_IP}:5000/api/status"
