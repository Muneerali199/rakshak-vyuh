# RAKSHAK.VYUH testbed
#
# One image, six configurations. strongSwan runs in a network namespace so the
# handshake really happens on the wire and tcpdump can see it. Nothing here is
# simulated: the captures this produces are genuine IKEv1 and IKEv2 exchanges,
# which is the point.
#
# alpine's strongswan package bundles swanctl and the pki tool, so no separate
# strongswan-pki or libcharon package is needed.

FROM alpine:3.20

RUN apk add --no-cache \
      strongswan \
      tcpdump \
      iproute2 \
      iputils \
      curl \
      iperf3 \
      openssl \
      bash \
      socat \
      jq \
 && update-ca-certificates

# Traffic tools for the labelled capture set. The entrypoint pushes five
# application classes through each tunnel so the capture contains ESP data
# packets and not just a handshake.
#
# bind-tools supplies nslookup for the DNS class. Everything else the generator
# needs, including nc and a one-shot HTTP server, comes from busybox or socat,
# both already in the base image, so this adds one package and not a resolver
# daemon that would need its own configuration and its own port to be free.
RUN apk add --no-cache bind-tools

# The image ships a config we never want; the harness writes its own. The
# directory itself is kept, because the entrypoint writes into it and a
# missing directory is not worth discovering at container start.
RUN mkdir -p /etc/strongswan /etc/swanctl /run/strongswan /var/log /capture \
 && rm -f /etc/strongswan/strongswan.conf /etc/strongswan/ipsec.conf

COPY entrypoint.sh traffic.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/traffic.sh

# Verify the pieces the entrypoint depends on are actually present, so a broken
# image fails at build time rather than mid-corpus-generation.
RUN set -e; \
    for b in ipsec swanctl pki tcpdump ping nslookup socat traffic.sh; do \
        command -v "$b" >/dev/null || { echo "missing $b"; exit 1; }; done; \
    ipsec --version

WORKDIR /tunnel
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["idle"]
