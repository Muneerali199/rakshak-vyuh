#!/bin/bash
# Push the labelled traffic classes across an established tunnel.
#
# Separate from the entrypoint on purpose. The entrypoint brings the daemon up
# and supervises the association; re-running it to generate traffic would try to
# start charon a second time and stall. This script only sends, and only after
# the caller has confirmed the SA is up.
#
# The source and destination are the tunnel's own traffic selectors, not the
# lab bridge addresses. A ping to the peer's bridge address is directly
# connected and leaves the host unencrypted, so the dataset would label clear
# traffic as tunnel-protected. The source address has to be bound explicitly
# too: left to itself the kernel picks the bridge address, which the XFRM
# policy does not match, and the packet bypasses the tunnel the same way.

set -uo pipefail

: "${ROLE:?}"
: "${LOCAL_HOST:?}"
: "${REMOTE_HOST:?}"
: "${TUNNEL:?}"

# Keyed by tunnel as well as role. A single file per role is overwritten by the
# next tunnel in the run, which left the corpus with the class log of whichever
# tunnel happened to go last and no way to label the other five.
OUT=/capture/traffic
mkdir -p "$OUT"
LOG="$OUT/${TUNNEL}-${ROLE}.traffic.log"
: >"$LOG"
log() { echo "[$(date +%s)] $*" >>"$LOG"; }

log "selector-src=$LOCAL_HOST dst=$REMOTE_HOST"

# ICMP interactive: small packets, long gaps. What a person typing looks like.
log "icmp-interactive-start"
for _ in 1 2 3 4 5 6; do
    ping -c 2 -W 2 -I "$LOCAL_HOST" -i 0.4 -s 64 "$REMOTE_HOST" >/dev/null 2>&1 || true
done
log "icmp-interactive-done"

# ICMP bulk: one large fast stream. A file transfer, a backup, a segment burst.
log "icmp-bulk-start"
ping -c 40 -W 2 -I "$LOCAL_HOST" -i 0.05 -s 1400 "$REMOTE_HOST" >/dev/null 2>&1 || true
log "icmp-bulk-done"

# VoIP-like: small packets at a steady 20 ms cadence, which is what a voice
# codec sends. Distinguished from interactive ICMP by regularity, not size.
log "voip-start"
for _ in $(seq 1 25); do
    ping -c 1 -W 1 -I "$LOCAL_HOST" -i 0.02 -s 160 "$REMOTE_HOST" >/dev/null 2>&1 || true
done
log "voip-done"

# Video streaming: sustained large packets at a high rate.
log "video-start"
for _ in $(seq 1 10); do
    ping -c 6 -W 2 -I "$LOCAL_HOST" -i 0.01 -s 1300 "$REMOTE_HOST" >/dev/null 2>&1 || true
done
log "video-done"

# DNS. UDP to the resolver on the far side. Unique per run so the flow is
# unmistakable in the capture.
log "dns-start"
nslookup -type=A "vyuh-dns-$TUNNEL.test" "$REMOTE_HOST" >>"$LOG" 2>&1 || true
log "dns-done"

# SSH. TCP to port 22, bound to the selector source.
log "ssh-start"
printf 'vyuh-probe\n' | timeout 8 \
    socat -T 5 "TCP4:$REMOTE_HOST:22,bind=$LOCAL_HOST" \
    >>"$LOG" 2>&1 || true
log "ssh-done"

# Web browsing. An HTTP request the far side answers, so this is a completed
# request/response rather than a bare SYN.
log "http-start"
printf 'GET /vyuh-%s HTTP/1.0\r\nHost: %s\r\nUser-Agent: vyuh-lab\r\n\r\n' \
    "$TUNNEL" "$REMOTE_HOST" | timeout 12 \
    socat -T 5 "TCP4:$REMOTE_HOST:80,bind=$LOCAL_HOST" \
    >>"$LOG" 2>&1 || true
log "http-done"

log "traffic-complete"

# The harness reads the phase's progress from stdout, so echo the log rather
# than leaving the caller to scrape a file out of the container.
cat "$LOG"
