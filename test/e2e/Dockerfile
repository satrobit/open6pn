# A "host" for the end-to-end test: run privileged, one per mesh node.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping dnsutils wireguard-tools iperf3 socat jq procps ethtool udev iptables \
 && rm -rf /var/lib/apt/lists/*
COPY .build/open6pn .build/seed /usr/local/bin/
