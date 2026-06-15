#!/bin/bash
# Optional runner: server + tcpdump + client for one option case, prints wire ToS.
# Usage: sudo bash run_case.sh <none|tclass|tos|both> [val]
#   e.g. sudo bash run_case.sh tclass 0xb8     (expect wire tos 0x0  -> bug)
#        sudo bash run_case.sh tos    0xb8     (expect wire tos 0xb8 -> works)
set -uo pipefail
OPT="${1:-tos}"
VAL="${2:-0xb8}"
DIR=./
PORT=5201

ip netns exec srv python3 "$DIR/tos.py" server --port "$PORT" >/dev/null 2>&1 &
SRV=$!
sleep 0.3

# Capture only client->server IPv4 TCP; -v prints the IP "tos 0x.." field.
ip netns exec srv timeout 6 tcpdump -ni veth-srv -c 6 -v \
	"ip and src 10.0.0.1 and dst 10.0.0.2 and tcp" >"$DIR/cap.$OPT.txt" 2>/dev/null &
CAP=$!
sleep 0.3

ip netns exec cli python3 "$DIR/tos.py" client \
	--dst 10.0.0.2 --port "$PORT" --opt "$OPT" --val "$VAL"

wait "$CAP" 2>/dev/null
kill "$SRV" 2>/dev/null

echo "===== wire ToS seen (opt=$OPT val=$VAL) ====="
grep -oE "tos 0x[0-9a-f]+" "$DIR/cap.$OPT.txt" | sort | uniq -c
