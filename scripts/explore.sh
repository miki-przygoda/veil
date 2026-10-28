#!/usr/bin/env bash
# Veil: bring the world up for hands-on exploration, with the dashboard.
# Run on the Linux host, from anywhere in the repo:
#   bash scripts/explore.sh            # world only; you drive the box yourself
#   bash scripts/explore.sh --scripted # also replays a short scripted subject
# The dashboard listens on the host's 127.0.0.1:8080. From another machine:
#   ssh -N -L 8080:127.0.0.1:8080 <host>    then open http://localhost:8080
# A shell in the box (the subject's view), on the host:
#   docker exec -it veil-world-01 /bin/sh
# Ctrl-C stops veild; it removes the box, residents, veil-net and its nat chain.
# Save the score before stopping: curl -s http://127.0.0.1:8080/report
set -u
cd "$(dirname "$(readlink -f "$0")")/.."
export PATH=/usr/local/go/bin:$PATH
# Each run logs to its own folder; VEIL_LOGS moves the root (default ./logs).
LOGS=${VEIL_LOGS:-$PWD/logs}/$(date +%Y%m%d-%H%M%S)
mkdir -p "$LOGS"

echo "== preflight (nothing started yet)"
uptime
echo "containers running: $(docker ps -q | wc -l)"
docker ps -a --format '{{.Names}}' | grep -E '^veil' && echo "WARNING: veil containers already exist"
docker network ls --format '{{.Name}}' | grep -qx veil-net && echo "WARNING: veil-net already exists"
ss -ltnu 2>/dev/null | grep -E ':(53|8080)\b' | grep -v 127.0.0.53 && echo "WARNING: something holds :53 or :8080"
df -h "$PWD" | tail -1
read -r -p "Start veild now? [y/N] " ok
[ "$ok" = y ] || { echo "not started"; exit 0; }

go build -o bin/veild ./cmd/veild || exit 1
sudo -v || exit 1
FLAGS=()
if [ "${1:-}" = --scripted ]; then
  printf '%s\n' 'uname -a' 'cat /etc/resolv.conf' 'nslookup web.veil.local' 'wget -T3 -qO- http://web.veil.local | head -5' > "$LOGS/subject.txt"
  FLAGS=(-subject="$LOGS/subject.txt")
fi
echo "== veild starting; logs in $LOGS"
echo "   dashboard: http://127.0.0.1:8080 (tunnel with ssh -N -L 8080:127.0.0.1:8080 <host>)"
echo "   box shell: docker exec -it veil-world-01 /bin/sh"
# A handler (not an ignore) so Ctrl-C reaches veild but this script carries on.
trap 'true' INT
sudo bin/veild "${FLAGS[@]}" 2>&1 | tee -i "$LOGS/veild.log"
trap - INT
echo "== stopped. leftovers (should be none):"
docker ps -a --format '{{.Names}}' | grep -E '^veil' || echo "  no veil containers"
docker network ls --format '{{.Name}}' | grep -x veil-net || echo "  no veil-net"
