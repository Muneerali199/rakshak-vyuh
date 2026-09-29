#!/bin/bash
# The demo, end to end, in one run.
#
# Written as a script rather than improvised at the keyboard for two reasons.
# A recorded demo that is retyped live fails on the one run that matters, and a
# demo that has a fixed order can be rehearsed, timed and captioned. Every
# pause here is long enough to read the output before it scrolls, and short
# enough that the whole thing stays under two minutes.
#
#   ./scripts/demo.sh
#
# Nothing here is mocked. Every figure printed comes from a capture produced by
# two real strongSwan gateways, and the analyser that reads them is the same
# binary that ships.

set -uo pipefail
cd "$(dirname "$0")/.."

VYUH=./target/release/vyuh
[ -x "$VYUH" ] || { echo "build first: cargo build --release"; exit 1; }

# Long enough to read, short enough to keep moving.
say()  { printf '\n\033[1;37m%s\033[0m\n' "$*"; sleep "${1:-2}"; }
pause() { sleep "${1:-3}"; }

# A clean screen between sections, so a viewer knows the topic changed without a
# title card.
clear_section() { printf '\033[2J\033[H'; }

clear_section
say "RAKSHAK.VYUH  ·  Reads the handshake. Never the payload." 3
say "Passive IPsec analyzer. No keys, no decryption, no traffic injection." 2
say "Every figure below comes from a capture made by real gateways." 2
pause 1

# ---------------------------------------------------------------- 1. the fleet
clear_section
say "1 / 5   Eleven real tunnels, scored" 2
say "Two strongSwan 5.9.13 gateways each, Docker, real negotiation." 2
$VYUH --batch corpus
pause 6

# ------------------------------------------------------- 2. the headline find
clear_section
say "2 / 5   The IKEv1 tunnel that should have failed loudly" 2
$VYUH corpus/vyuh-ikev1-aggressive-3des.pcap
pause 8

# ------------------------------------------------- 3. the same, as machine data
clear_section
say "3 / 5   Every finding is machine readable, with its packet number" 2
$VYUH corpus/vyuh-ikev1-aggressive-3des.pcap --quiet --json /tmp/demo.json
printf '   '
head -c 620 /tmp/demo.json
printf '\n\n'
say "   Findings carry the packet they were read from. Not a score." 2
pause 6

# ---------------------------------------------------------------- 4. the fix
clear_section
say "4 / 5   It hands back the fix, not just the complaint" 2
$VYUH corpus/vyuh-ikev2-weak-dh.pcap --remediate /tmp/demo.fix.json --quiet
printf '\n   What it proposes instead, per gateway:\n'
head -20 /tmp/demo.fix.json
pause 7

# ------------------------------------------------------------------ 5. the CBOM
clear_section
say "5 / 5   The cryptographic bill, in an industry format" 2
$VYUH corpus/vyuh-ikev2-weak-dh.pcap --cbom /tmp/demo.cdx.json --quiet
printf '\n   CycloneDX 1.6, with NIST object identifiers:\n'
grep -E '"name"|"oid"' /tmp/demo.cdx.json | head -8 | sed 's/^/   /'
pause 6

clear_section
say "Dataset, packet table and 137 tests: github.com/team-venom/rakshak-vyuh" 3
say "Approved on AIKosh, IndiaAI Open Source Community, MeitY." 3
say "Reads the handshake. Never the payload." 3
