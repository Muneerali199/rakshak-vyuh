#!/bin/bash
# Gateway entrypoint.
#
# A swanctl connection is generated from the T-matrix variables the harness
# passes in, so every tunnel in the corpus is a real negotiated suite rather
# than a claimed one. The engine then has to read it off the wire like any
# other capture.

set -Eeuo pipefail

TUNNEL="${TUNNEL:-${1:-idle}}"
: "${ROLE:?ROLE must be gw-a or gw-b}"
: "${PEER_IP:?PEER_IP required}"
: "${LOCAL_IP:?LOCAL_IP required}"
: "${SUBNET_A:?SUBNET_A required}"
: "${SUBNET_B:?SUBNET_B required}"
: "${IKESUBNET:?IKESUBNET required}"

# The usable address inside a traffic selector: 10.61.0.0/24 -> 10.61.0.1.
#
# The gateways live on the lab bridge, but the tunnel's traffic selectors are
# the 10.61/10.62 blocks. A ping to the peer's bridge address never enters the
# tunnel, because that address is directly connected, so traffic has to be
# addressed into the selector pair for the SA to match.
#
# Note that swanctl installs a /32 policy for a /24 selector, which is why the
# selector address itself has to be used rather than some other host in the
# block: the policy is keyed on exactly this address.
selector_addr() {
    local base="${1%%/*}" o1 o2 o3
    IFS=. read -r o1 o2 o3 _ <<<"$base"
    echo "$o1.$o2.$o3.0"
}

dump_diagnostics() {
    echo "----- entrypoint failed at line $1: $2 -----" >&2
    for f in /var/log/swanctl-load.log /var/log/swanctl-up.log /var/log/ipsec-start.log; do
        [ -f "$f" ] && { echo "--- $f ---" >&2; tail -20 "$f" >&2; }
    done
    [ -f /etc/swanctl/swanctl.conf ] && { echo "--- swanctl.conf ---" >&2; cat /etc/swanctl/swanctl.conf >&2; }
    [ -f "$LOG" ] && { echo "--- strongswan.log ---" >&2; tail -25 "$LOG" >&2; }
}
trap 'dump_diagnostics "$LINENO" "$BASH_COMMAND"' ERR

mkdir -p /etc/strongswan /etc/swanctl /run/strongswan /var/log /capture
LOG=/var/log/strongswan.log
: >"$LOG"

# ------------------------------------------------------------------ charon
cat >/etc/strongswan/strongswan.conf <<EOF
charon {
    install_routes = no
    install_virtual_ip = no
    interfaces_use = $IKESUBNET
    filelog {
        vyuh {
            path = $LOG
            time_format = %s
            append = yes
            ike_name = yes
            default = 1
        }
    }
}
EOF

# ------------------------------------------------------------- certificates
#
# A single CA, generated once on the host and mounted read-only. Two containers
# that each mint their own CA cannot verify each other, and the resulting
# AUTHENTICATION_FAILED looks like a credential problem rather than the
# provisioning mistake it is.
PKI_DIR="${PKI_DIR:-/lab-pki}"
install_certs() {
    local d=/etc/swanctl
    rm -f "$d/swanctl.conf"
    mkdir -p "$d/x509" "$d/x509ca" "$d/private"

    # PKI_NAME selects this gateway's certificate from the shared CA, because
    # the file is named for the tunnel as well as the role.
    local n="${PKI_NAME:-$ROLE}"
    cp "$PKI_DIR/ca.pem"        "$d/x509ca/ca.pem"
    cp "$PKI_DIR/$n.pem"        "$d/x509/$ROLE.pem"
    cp "$PKI_DIR/$n-key.pem"    "$d/private/$ROLE-key.pem"
    chmod 600 "$d/private/$ROLE-key.pem"
}

[ -f "/etc/swanctl/x509ca/ca.pem" ] || install_certs

# ------------------------------------------------------------------ proposals
case "$TUNNEL" in
T1) # modern baseline: AES-256-GCM, SHA2-256 PRF, ECP-256, PFS, long rekey
    PROPOSALS="aes256gcm16-prfsha256-ecp256"; REKEY_TIME="8h" ;;
T2) # weak Diffie-Hellman group
    PROPOSALS="aes128-sha1-modp1024";         REKEY_TIME="8h" ;;
T3) # IKEv1 Aggressive Mode, 3DES, MODP-1024, no PFS
    #
    # SHA-1 rather than MD5: strongSwan 5.9 no longer ships the md5 plugin, so
    # an md5 proposal is silently undeliverable and the association never comes
    # up. 3DES is the finding under test, so keeping the suite to 3DES-SHA1
    # still shows a 64-bit block cipher and a demoted hash.
    PROPOSALS="3des-sha1-modp1024"; REKEY_TIME="8h"
    # No key exchange in the ESP proposal is what "no PFS" means on the wire.
    ESP_PROPOSALS="3des-sha1" ;;
T4) # NULL encryption: no confidentiality at all
    PROPOSALS="null-md5-modp1024";            REKEY_TIME="8h" ;;
T5) # X25519 with AEAD, short rekey
    PROPOSALS="aes256gcm16-prfsha256-x25519"; REKEY_TIME="4h" ;;
T6) # legacy integrity algorithm, acceptable DH group
    PROPOSALS="aes128-sha1-modp2048";         REKEY_TIME="8h" ;;
T7) # IKEv1 Main Mode, same ciphers as T3 with the exchange type changed
    PROPOSALS="3des-sha1-modp1024"; REKEY_TIME="8h"
    ESP_PROPOSALS="3des-sha1" ;;
T8) # AES-XCBC integrity: not a hash, which the others do not cover
    PROPOSALS="aes256gcm16-xcbc-prfsha256-ecp256"; REKEY_TIME="8h" ;;
T9) # modern IKE suite protecting data with 3DES
    PROPOSALS="${VYUH_IKE:-aes192-sha256-prfsha256-modp2048}"; REKEY_TIME="8h"
    ESP_PROPOSALS="${VYUH_ESP:-3des-sha256-modp2048}" ;;
T10) # Aggressive Mode with 3DES but a 2048-bit group
    PROPOSALS="${VYUH_IKE:-3des-sha1-modp2048}"; REKEY_TIME="8h"
    ESP_PROPOSALS="3des-sha1" ;;
T11) # AES-256-GCM, SHA2-256 integrity, 384-bit curve: a second clean baseline
    PROPOSALS="aes256gcm16-prfsha256-ecp384"; REKEY_TIME="8h" ;;
T12) # MODP-1536, which RFC 8247 lists as SHOULD NOT rather than MUST NOT
    PROPOSALS="aes128-sha256-prfsha256-modp1536"; REKEY_TIME="8h" ;;
T13) # single DES under IKEv1 Main Mode
    PROPOSALS="${VYUH_IKE:-des-sha1-modp1024}"; REKEY_TIME="8h"
    ESP_PROPOSALS="des-sha1" ;;
T14) # a perfect IKE suite protecting data with NULL
    PROPOSALS="aes256gcm16-prfsha256-ecp256"; REKEY_TIME="8h"
    ESP_PROPOSALS="${VYUH_ESP:-null-sha256-modp2048}" ;;
*)
    # Anything unlisted falls back to the reference posture rather than
    # refusing to boot. A matrix row that has not reached this script should
    # produce a capture of the default tunnel, which is obvious in the results,
    # instead of a container that dies before tcpdump starts.
    PROPOSALS="aes256gcm16-prfsha256-ecp256"; REKEY_TIME="8h" ;;
esac
# Every tunnel except the IKEv1 ones negotiates the same suite for IKE and ESP. The default
# has to be set here, before either connection body expands it: under `set -u`
# an unset ESP_PROPOSALS aborts the entrypoint, and a container that dies at
# that point looks exactly like a tunnel that refused to negotiate.
: "${ESP_PROPOSALS:=$PROPOSALS}"

# Role-dependent values first: the connection body below refers to them.
PEER_ROLE=gw-b; [ "$ROLE" = "gw-b" ] && PEER_ROLE=gw-a
# Every IKEv2 tunnel initiates from both ends; the IKEv1 tunnels initiate from
# one. Set in the IKEv1 branch below.
CHILD_START=start
if [ "$ROLE" = "gw-a" ]; then
    LOCAL_TS="$SUBNET_A"; REMOTE_TS="$SUBNET_B"
    LOCAL_HOST=$(selector_addr "$SUBNET_A"); REMOTE_HOST=$(selector_addr "$SUBNET_B")
else
    LOCAL_TS="$SUBNET_B"; REMOTE_TS="$SUBNET_A"
    LOCAL_HOST=$(selector_addr "$SUBNET_B"); REMOTE_HOST=$(selector_addr "$SUBNET_A")
fi

# IKEv1 tunnels are T3, T7, T10 and T13. Aggressive Mode is a swanctl option
# rather than a proposal, and it is the behaviour under test on T3 and T10 only.
#
# IKEv1 Aggressive Mode cannot be initiated from both ends at once. There is no
# session resumption for it, so two simultaneous initiations each answer the
# other's proposal with NO_PROPOSAL_CHOSEN and the association never settles.
# The responder therefore gets start_action = none, and the supervision loop
# below is told not to initiate either. IKEv2 has no such restriction, which is
# why every IKEv2 tunnel initiates from both ends.
if [ "$TUNNEL" = "T3" ] || [ "$TUNNEL" = "T7" ] \
   || [ "$TUNNEL" = "T10" ] || [ "$TUNNEL" = "T13" ]; then
    IKE_VERSION=1
    case "$TUNNEL" in
        T3|T10) AGGRESSIVE=yes ;;
        *)      AGGRESSIVE=no  ;;
    esac
    [ "$ROLE" = "gw-a" ] || CHILD_START=none
    cat >/etc/swanctl/swanctl.conf <<EOF
connections {
    vyuh {
        version = $IKE_VERSION
        aggressive = $AGGRESSIVE
        proposals = $PROPOSALS
        local_addrs  = $LOCAL_IP
        remote_addrs = $PEER_IP
        # Certificates rather than a PSK. Every finding this tunnel is meant to
        # show is a property of the exchange, not of the authentication
        # method: Aggressive Mode sends the peer's identity in the clear before
        # anything is authenticated, 3DES is a 64-bit block cipher, and an ESP
        # proposal with no key exchange means no perfect forward secrecy. A PSK
        # here would add an AUTHENTICATION_FAILED retry storm to the capture
        # without changing any of them.
        local {
            auth = pubkey
            certs = $ROLE.pem
            # The certificate's subject, not the bridge address. IKEv1 resolves
            # the signing key by identity before it has a peer to talk to, and
            # an identity of 10.x.y.z matches no key in the private directory,
            # so the initiator never signs and the peer answers
            # AUTHENTICATION_FAILED. The IKEv2 connections can use the address
            # because IKEv2 defers the choice until AUTH is exchanged.
            id = $ROLE
        }
        remote {
            auth = pubkey
            id = $PEER_ROLE
        }
        dpd_delay = 30s
        rekey_time = $REKEY_TIME
        reauth_time = 0s
        children {
            net {
                esp_proposals = $ESP_PROPOSALS
                local_ts = $LOCAL_TS
                remote_ts = $REMOTE_TS
                mode = tunnel
                # Aggressive Mode cannot be run from both ends at once. IKEv1
                # has no session resumption for it, so when the two gateways
                # initiate simultaneously each answers the other's proposal
                # with NO_PROPOSAL_CHOSEN and the association never settles.
                # IKEv2 tolerates simultaneous initiation; IKEv1 does not.
                start_action = $CHILD_START
            }
        }
    }
}

secrets {
    private {
        $ROLE {
            file = /etc/swanctl/private/$ROLE-key.pem
        }
    }
}

EOF
else
    cat >/etc/swanctl/swanctl.conf <<EOF
connections {
    vyuh {
        version = 2
        proposals = $PROPOSALS
        encap = yes
        mobike = no
        local_addrs  = $LOCAL_IP
        remote_addrs = $PEER_IP
        local {
            auth = pubkey
            id = $LOCAL_IP
            certs = $ROLE.pem
        }
        remote {
            auth = pubkey
            id = $PEER_IP
        }
        dpd_delay = 30s
        rekey_time = $REKEY_TIME
        reauth_time = 0s
        children {
            net {
                esp_proposals = $ESP_PROPOSALS
                local_ts = $LOCAL_TS
                remote_ts = $REMOTE_TS
                mode = tunnel
                start_action = start
            }
        }
    }
}
EOF
fi

# Capture before charon starts, so the first handshake is not missed.
# -U writes each packet as it is read, so a container stop cannot lose the
# buffer. No periodic signal is needed, and sending one would risk killing the
# capture.
# The BPF filter has to carry the port, not the protocol number.
#
# Once a peer is behind NAT, or immediately after negotiating, strongSwan moves
# ESP into UDP/4500. Those packets are protocol 17 (UDP), not 50 (ESP), so a
# filter of "ip proto 50" records zero data packets even though the tunnel is
# carrying traffic. "udp port 4500" catches both the IKE messages and the
# encapsulated ESP, and the analyser distinguishes them by looking inside.
#
# port 4501 is ESP-in-UDP for aggressive mode. proto 50 and 51 are the
# non-encapsulated forms, kept for peers that do not negotiate NAT-T.
tcpdump -i "$IKESUBNET" -s 0 -U -w "/capture/${ROLE}-${TUNNEL}.pcap" \
        'ip and (udp port 500 or udp port 4500 or udp port 4501 or ip proto 50 or ip proto 51)' \
        >/var/log/tcpdump.log 2>&1 &

ip link set lo up
ip link set "$IKESUBNET" up

# The traffic selectors are the 10.61/10.62 blocks, not the lab bridge. Put an
# address from the local selector on the interface and a route for the remote
# one, so application traffic is addressed into the SA policy and the kernel
# encapsulates it. Without these, everything routes out the bridge directly and
# the capture records zero ESP packets.
add_selector_addressing() {
    ip addr add "$LOCAL_HOST/24" dev "$IKESUBNET" 2>/dev/null || true
    # A host route via the interface, not via a gateway. The XFRM policy
    # selects on the selector pair and is installed by strongSwan when the SA
    # comes up, so the route only has to put the packet on the wire in the
    # right direction.
    ip route replace "$REMOTE_HOST/32" dev "$IKESUBNET" 2>/dev/null || true
    echo "selector addressing: src=$LOCAL_HOST dst=$REMOTE_HOST ts=$LOCAL_TS<->$REMOTE_TS" \
        >/var/log/selector.log
}

add_selector_addressing

# --nofork keeps the starter in the foreground. As PID 1 that blocks forever,
# so background it and poll for the daemon instead of guessing a sleep.
ipsec start --nofork >/var/log/ipsec-start.log 2>&1 &
STARTER_PID=$!

for _ in $(seq 1 30); do
    if swanctl --list-conns >/dev/null 2>&1; then break; fi
    if ! kill -0 "$STARTER_PID" 2>/dev/null; then
        echo "starter exited early" >&2
        cat /var/log/ipsec-start.log >&2
        exit 1
    fi
    sleep 1
done

swanctl --load-all >/var/log/swanctl-load.log 2>&1

# A first bring-up attempt, bounded. Failing here is not fatal: the peer may not
# be up yet and the supervision loop retries. What matters is that the container
# reaches READY so the harness can measure the real outcome.
timeout 30 ipsec up vyuh >/var/log/swanctl-up.log 2>&1 || true

# ------------------------------------------------------------- traffic
#
# The tunnels above negotiate but carry nothing, so the capture contains
# handshakes and no data traffic. PS SIH26160 asks for "ESP packets" and
# "normal communication", and an analyser that has only ever seen a handshake
# has never exercised its ESP path on a real packet.
#
# Only gw-a drives traffic, so the same application is not sent twice and the
# classes stay separable. Each class is chosen so the label is true by
# construction: we know what we sent, so the encrypted payload has a known
# ground truth without anyone decrypting it.
serve_once() {
    # A throwaway HTTP listener so the HTTP class is a completed exchange
    # rather than a bare SYN. socat is already in the image, so this needs no
    # extra package and no daemon to shut down cleanly.
    #
    # One request then exit: this has to be a listener, not a server, because a
    # long-lived one would keep answering after the traffic phase and pollute
    # the capture with traffic the dataset does not describe.
    # Bind on the selector host address, not the bridge one: a client aiming at
    # the remote selector has to reach a listener on this side's selector
    # address for the reply to be routed back into the tunnel.
    socat -T 90 "TCP4-LISTEN:80,bind=$LOCAL_HOST,reuseaddr,fork" \
        SYSTEM:'printf "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nvyuh-%s-ok\n" "$TUNNEL"' \
        >/var/log/socat-http.log 2>&1 &
    HTTPD_PID=$!
}

# The responder serves HTTP, then the initiator drives the labelled traffic
# once the association is up. This is polled rather than run inline: on a cold
# start the first READY is "pending", and generating traffic then would send
# everything out the bridge unencrypted and label it as though it had been
# protected.
if [ "$ROLE" = "gw-b" ]; then
    TRAFFIC_DONE=0
fi

wait_and_generate() {
    # Announce readiness as soon as the daemon answers, so the harness stops
    # waiting, and then keep retrying the association. The SA takes longer to
    # come up than a fixed loop allows, and the previous version gave up while
    # the peer was still configuring, which left the capture with handshakes
    # and no data.
    if sa_is_up; then
        echo "READY $ROLE $TUNNEL established"
    else
        echo "READY $ROLE $TUNNEL pending"
    fi
}

wait_and_generate

# Supervise. The traffic phase is gated on the association, and it runs once:
# after a rekey the selectors and the policy are unchanged, so re-sending would
# only add unlabelled duplicates to the capture.
# `grep -q` is not usable in this script under `set -o pipefail`: it
# exits the moment it has a match, swanctl then takes SIGPIPE on the still-open
# pipe, and pipefail turns that into a non-zero status that `set -e` treats as
# fatal. The supervise loop dies silently, the traffic phase never runs, and
# the capture records handshakes with no data in them. `grep -c` reads the whole
# stream and has no such problem, so a positive count is the test.
sa_is_up() {
    local n
    n=$(swanctl --list-sas 2>/dev/null | grep -c ESTABLISHED || true)
    [ "${n:-0}" -gt 0 ]
}

# The harness drives the traffic phase from outside with `docker exec`, once it
# has confirmed the SA is established. Doing it in here raced the association
# coming up: a phase that starts early sends every packet out the bridge
# unencrypted while the dataset still labels it as tunnel-protected, which is
# the one failure mode that must not ship.
#
# gw-b only needs to serve HTTP while the harness is sending to it.
if [ "$ROLE" = "gw-b" ]; then
    serve_once &
fi

# The responder must not initiate. On the IKEv1 tunnel the child is configured
# with start_action = none so that only gw-a starts the exchange, and this
# guard keeps the supervision loop from undoing that by calling `ipsec up` on
# the peer anyway. Two simultaneous Aggressive Mode initiations each reject the
# other's proposal and the association never settles.
INITIATE=1
[ "${IKE_VERSION:-2}" = "1" ] && [ "$ROLE" = "gw-b" ] && INITIATE=0

while true; do
    if [ "$INITIATE" = "1" ] && ! sa_is_up; then
        timeout 25 ipsec up vyuh >>/var/log/swanctl-up.log 2>&1 || true
    fi
    sleep 3
done
