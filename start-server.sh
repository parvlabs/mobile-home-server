#!/data/data/com.termux/files/usr/bin/bash
# Termux:Boot script. Copy to ~/.termux/boot/start-server.sh
# (requires the separate Termux:Boot app to be installed).
# start-all.sh is idempotent (checks ports first), so this is
# safe even if it somehow runs more than once.
termux-wake-lock
sleep 5
bash ~/server/start-all.sh
