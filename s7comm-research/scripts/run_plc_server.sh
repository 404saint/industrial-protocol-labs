#!/usr/bin/env bash
# S7comm Research Lab - Native C++ Server Launcher

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="$PROJECT_ROOT/snap7-code/snap7-full-1.4.2/build/bin/x86_64-linux"
SERVER_BIN="$PROJECT_ROOT/snap7-code/snap7-full-1.4.2/examples/cpp/x86_64-linux/server"

if [ ! -f "$SERVER_BIN" ]; then
    echo "[-] Server binary not found at $SERVER_BIN"
    exit 1
fi

export LD_LIBRARY_PATH="$BIN_PATH:$LD_LIBRARY_PATH"

echo "=========================================================="
echo "      S7comm Native C++ PLC Target Server                "
echo "=========================================================="
echo "[*] Library Path : $BIN_PATH"
echo "[*] Listener     : 0.0.0.0:102 (ISO-on-TCP / TPKT / COTP)"
echo "[*] PID          : $$"
echo "=========================================================="

exec "$SERVER_BIN"
