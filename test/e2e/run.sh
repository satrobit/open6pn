#!/usr/bin/env bash
# End-to-end test: three mesh hosts as privileged containers, with network
# namespaces standing in for tenant containers. Real WireGuard, real eBPF.
#
#   KEEP=1 ./test/e2e/run.sh    leave everything running afterwards
#
# To run the three hosts inside a large mesh, register placeholder hosts first.
# Each real host then carries that many WireGuard peers and gets a node ID
# above them, and the whole suite runs under that load:
#
#   PLACEHOLDERS=16000 ./test/e2e/run.sh                  default layout, 16383 hosts
#   NODE_BITS=16 PLACEHOLDERS=65000 ./test/e2e/run.sh     65535 hosts
set -uo pipefail
cd "$(dirname "$0")/../.."

IMAGE=open6pn-e2e
NET=open6pn-e2e
ETCD_IMAGE=${ETCD_IMAGE:-gcr.io/etcd-development/etcd:v3.6.0}
NODE_BITS=${NODE_BITS:-}
PLACEHOLDERS=${PLACEHOLDERS:-0}
PASS=0
FAIL=0

say() { printf '\n== %s\n' "$*"; }
pass() { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; }
expect_ok() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
expect_fail() { local d=$1; shift; if "$@" >/dev/null 2>&1; then fail "$d"; else pass "$d"; fi; }
expect_eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (want '$2', got '$3')"; fi; }
expect_gt() { if [ "${3:-0}" -gt "$2" ] 2>/dev/null; then pass "$1 ($3)"; else fail "$1 (want > $2, got '${3:-}')"; fi; }

# h NODE CMD...       run on a host
# c NODE NS CMD...    run inside a "container" on that host
h() { local n=$1; shift; docker exec "open6pn-$n" "$@"; }
c() { local n=$1 ns=$2; shift 2; docker exec "open6pn-$n" ip netns exec "$ns" "$@"; }
bg() { local n=$1 ns=$2; shift 2; docker exec -d "open6pn-$n" ip netns exec "$ns" "$@"; }
stat() { h "$1" sh -c "open6pn status --json | jq -r .stats.$2"; }
count_eps() { h "$1" sh -c "open6pn endpoint ls --json | jq length"; }
sorted() { sort | tr '\n' ' ' | sed 's/ $//'; }
list() { printf '%s\n' "$@" | sorted; }
lines() { wc -l | tr -d ' '; }
name_count() { c "$1" "$2" dig +short +time=1 +tries=1 AAAA "$3.internal" @fdaa::53 | lines; }
peer_count() { h "$1" wg show open6pn-wg peers | lines; }
# Kernel threads serving WireGuard peers, on all three hosts together. They
# are only visible from the VM's own PID namespace.
peer_threads() { docker run --rm --pid=host "$IMAGE" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null | grep -c "^napi/open6pn-wg"'; }
# until_eq WANT N CMD...: until CMD prints WANT, at most N times, 0.3s apart
until_eq() { local want=$1 n=$2; shift 2; for _ in $(seq "$n"); do [ "$("$@")" = "$want" ] && return 0; sleep 0.3; done; return 1; }
# retry N CMD...: until CMD succeeds, at most N times, 0.3s apart
retry() { local n=$1; shift; for _ in $(seq "$n"); do "$@" && return 0; sleep 0.3; done; return 1; }

cleanup() {
	docker rm -f open6pn-etcd open6pn-n1 open6pn-n2 open6pn-n3 >/dev/null 2>&1
	docker network rm "$NET" >/dev/null 2>&1
}
[ -n "${KEEP:-}" ] || trap cleanup EXIT
cleanup

say "build"
ARCH=$(docker version --format '{{.Server.Arch}}')
mkdir -p test/e2e/.build
CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -o test/e2e/.build/open6pn ./cmd/open6pn || exit 1
CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -o test/e2e/.build/seed ./test/e2e/seed || exit 1
docker build -q -t "$IMAGE" test/e2e >/dev/null || exit 1
echo "  open6pn binary and host image built ($ARCH, kernel $(docker version --format '{{.Server.KernelVersion}}'))"

say "start etcd and three hosts"
docker network create "$NET" >/dev/null || exit 1
docker run -d --name open6pn-etcd --network "$NET" "$ETCD_IMAGE" etcd \
	--listen-client-urls http://0.0.0.0:2379 --advertise-client-urls http://open6pn-etcd:2379 >/dev/null || exit 1
ETCD_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' open6pn-etcd)

start_daemon() { # NODE [ENV=VALUE] [FLAGS]
	local ip
	ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "open6pn-$1")
	docker exec -d ${2:+-e "$2"} "open6pn-$1" sh -c "exec open6pn daemon --etcd http://open6pn-etcd:2379 --advertise $ip ${3:-} >>/var/log/open6pn.log 2>&1"
	if ! retry 100 docker exec "open6pn-$1" open6pn status >/dev/null 2>&1; then
		echo "daemon on $1 did not come up:"
		docker exec "open6pn-$1" cat /var/log/open6pn.log
		exit 1
	fi
}
stop_daemon() {
	h "$1" pkill -TERM -x open6pn
	retry 30 sh -c "! docker exec open6pn-$1 pgrep -x open6pn >/dev/null"
}

for n in n1 n2 n3; do
	docker run -d --privileged --name "open6pn-$n" --hostname "$n" --network "$NET" "$IMAGE" sleep infinity >/dev/null || exit 1
	h "$n" /usr/lib/systemd/systemd-udevd --daemon >/dev/null 2>&1 || exit 1
	h "$n" ip6tables -t mangle -A PREROUTING -m rpfilter --loose --validmark -j RETURN || exit 1
	h "$n" ip6tables -t mangle -A PREROUTING -j DROP || exit 1
done
if [ "$PLACEHOLDERS" -gt 0 ]; then
	t=$(h n1 date +%s%N)
	h n1 seed --etcd http://open6pn-etcd:2379 --count "$PLACEHOLDERS" || exit 1
	echo "  registered $PLACEHOLDERS placeholder hosts in $((($(h n1 date +%s%N) - t) / 1000000)) ms"
fi
# Only the first host says what layout the cluster has; the others adopt it.
start_daemon n1 "" "${NODE_BITS:+--node-bits $NODE_BITS}"
start_daemon n2
start_daemon n3
N1_ID=$((PLACEHOLDERS + 1)) N2_ID=$((PLACEHOLDERS + 2)) N3_ID=$((PLACEHOLDERS + 3))
PEERS=$((PLACEHOLDERS + 2))
node_id() { h "$1" sh -c 'open6pn status --json | jq .node.id'; }
expect_eq "the three hosts took the lowest free node IDs" "$N1_ID $N2_ID $N3_ID" "$(node_id n1) $(node_id n2) $(node_id n3)"
expect_ok "n1 has $PEERS WireGuard peers" until_eq "$PEERS" 100 peer_count n1
expect_ok "n3 has $PEERS WireGuard peers" until_eq "$PEERS" 100 peer_count n3
expect_eq "n3 adopted the layout n1 created the cluster with" "${NODE_BITS:-14}" "$(h n3 sh -c 'open6pn status --json | jq .layout.node_bits')"
MAX_EP=$(h n1 sh -c 'open6pn status --json | jq .layout.max_endpoints_per_network_per_node')
echo "  layout: $(h n1 sh -c 'open6pn status --json | jq -c .layout')"
out=$(h n3 timeout 20 open6pn daemon --etcd http://open6pn-etcd:2379 --node-bits $((${NODE_BITS:-14} == 9 ? 10 : 9)) \
	--state-dir /tmp/other --socket /tmp/other.sock 2>&1)
expect_ok "a daemon asking for a different layout is refused" grep -q 'cannot be changed' <<<"$out"
out=$(h n3 timeout 20 open6pn daemon --etcd http://open6pn-etcd:2379 --mtu 1400 \
	--state-dir /tmp/other --socket /tmp/other.sock 2>&1)
expect_ok "a daemon asking for a different MTU is refused" grep -q 'MTU of 1420; it cannot be changed' <<<"$out"

expect_eq "no kernel thread per WireGuard peer" "0" "$(peer_threads)"

if [ "$PLACEHOLDERS" -gt 0 ]; then
	say "cost of $PEERS WireGuard peers per host"
	for n in n1 n2 n3; do
		printf '  %s: first sync %s, daemon RSS %s MB\n' "$n" \
			"$(h "$n" sh -c "grep -m1 'synced peers' /var/log/open6pn.log | sed 's/.*took=//'")" \
			"$(h "$n" sh -c 'echo $(( $(ps -o rss= -C open6pn) / 1024 ))')"
	done
	h n1 sh -c 'awk "/^(wg_peer|allowedips_node) /{printf \"  kernel: %s x %s, %s bytes each = %.1f MB\n\", \$3, \$1, \$4, \$3*\$4/1048576}" /proc/slabinfo'
	h n1 sh -c 's=$(date +%s%N); wg show open6pn-wg dump | wc -l >/dev/null; echo "  wg show dump: $(( ($(date +%s%N) - s) / 1000000 )) ms"'
fi

say "create networks and attach containers"
expect_ok "create network blue" h n1 open6pn network create blue
expect_ok "create network red" h n2 open6pn network create red
expect_fail "duplicate network name is refused" h n3 open6pn network create blue
expect_fail "attach to a network that does not exist is refused" h n1 sh -c 'ip netns add x && open6pn attach --netns /var/run/netns/x nope'

attach() { # NODE NS NETWORK [NAME...]  ->  "ipv6 ipv4 id"
	local n=$1 ns=$2 net=$3 flags=""
	shift 3
	for name in "$@"; do flags="$flags --name $name"; done
	h "$n" ip netns add "$ns" && h "$n" ip netns exec "$ns" ip link set lo up
	h "$n" sh -c "open6pn attach --netns /var/run/netns/$ns $flags $net | jq -r '[.ipv6,.ipv4,.id]|join(\" \")'"
}
# blue: a1 and a1b on n1, a2 on n2, a3 on n3.   red: r1 on n1, r2 on n2.
# a1/r1 and a2/r2 are the first endpoint of their network on their host, so
# they get the SAME IPv4 address: the overlap the design allows.
read -r A1_6 A1_4 A1_ID <<<"$(attach n1 a1 blue web)"
read -r R1_6 R1_4 R1_ID <<<"$(attach n1 r1 red web)"
read -r A1B_6 A1B_4 A1B_ID <<<"$(attach n1 a1b blue web)"
read -r A2_6 A2_4 A2_ID <<<"$(attach n2 a2 blue web api)"
read -r R2_6 R2_4 R2_ID <<<"$(attach n2 r2 red db)"
read -r A3_6 A3_4 A3_ID <<<"$(attach n3 a3 blue db)"
printf '  blue  a1=%s %s  a1b=%s %s\n        a2=%s %s  a3=%s %s\n' "$A1_6" "$A1_4" "$A1B_6" "$A1B_4" "$A2_6" "$A2_4" "$A3_6" "$A3_4"
printf '  red   r1=%s %s  r2=%s %s\n' "$R1_6" "$R1_4" "$R2_6" "$R2_4"
expect_eq "blue and red reuse the same IPv4 on n1" "$A1_4" "$R1_4"
expect_eq "blue and red reuse the same IPv4 on n2" "$A2_4" "$R2_4"

say "connectivity inside a network"
expect_ok "IPv6 n1 -> n2" c n1 a1 ping -c2 -W2 "$A2_6"
expect_ok "IPv6 n1 -> n3" c n1 a1 ping -c2 -W2 "$A3_6"
expect_ok "IPv6 n3 -> n2" c n3 a3 ping -c2 -W2 "$A2_6"
expect_ok "IPv4 n1 -> n2" c n1 a1 ping -c2 -W2 "$A2_4"
expect_ok "IPv4 n2 -> n3" c n2 a2 ping -c2 -W2 "$A3_4"
expect_ok "IPv4 n3 -> n1" c n3 a3 ping -c2 -W2 "$A1_4"
expect_ok "IPv6 same host" c n1 a1 ping -c2 -W2 "$A1B_6"
expect_ok "IPv4 same host" c n1 a1b ping -c2 -W2 "$A1_4"
expect_ok "IPv6 red n1 -> n2" c n1 r1 ping -c2 -W2 "$R2_6"
expect_ok "IPv4 red n2 -> n1" c n2 r2 ping -c2 -W2 "$R1_4"

say "overlapping IPv4: the same address reaches a different container per network"
bg n2 a2 socat TCP4-LISTEN:7000,fork,reuseaddr SYSTEM:'echo blue-a2'
bg n2 r2 socat TCP4-LISTEN:7000,fork,reuseaddr SYSTEM:'echo red-r2'
bg n1 a1 socat TCP4-LISTEN:7000,fork,reuseaddr SYSTEM:'echo blue-a1'
bg n1 r1 socat TCP4-LISTEN:7000,fork,reuseaddr SYSTEM:'echo red-r1'
sleep 0.5
ask() { c "$1" "$2" socat -t2 - "TCP4:$3:7000,connect-timeout=3" 2>/dev/null; }
expect_eq "blue on n1 asks $A2_4, across hosts" "blue-a2" "$(ask n1 a1 "$A2_4")"
expect_eq "red on n1 asks the same $R2_4, across hosts" "red-r2" "$(ask n1 r1 "$R2_4")"
expect_eq "blue on n1 asks $A1_4, same host" "blue-a1" "$(ask n1 a1b "$A1_4")"
expect_eq "red on n2 asks the same $R1_4, across hosts" "red-r1" "$(ask n2 r2 "$R1_4")"

say "isolation between networks"
before=$(stat n1 drop_isolation)
expect_fail "blue cannot reach red over IPv6, across hosts" c n1 a1 ping -c1 -W1 "$R2_6"
expect_fail "blue cannot reach red over IPv6, same host" c n1 a1 ping -c1 -W1 "$R1_6"
expect_fail "red cannot reach blue over IPv6" c n2 r2 ping -c1 -W1 "$A1_6"
expect_gt "those packets were counted as isolation drops on n1" "$before" "$(stat n1 drop_isolation)"

before=$(stat n1 drop_spoof)
c n1 a1 ip addr add "$R1_6/128" dev o6pn0 nodad
expect_fail "blue cannot reach red by spoofing a red IPv6 source" c n1 a1 ping -c1 -W1 -I "$R1_6" "$R2_6"
c n1 a1 ip addr del "$R1_6/128" dev o6pn0
expect_eq "that packet left the container and was counted as a spoofing drop" "$((before + 1))" "$(stat n1 drop_spoof)"
c n1 a1 ip addr add "$A3_4/32" dev o6pn0
expect_fail "a spoofed IPv4 source is dropped" c n1 a1 ping -c1 -W1 -I "$A3_4" "$A2_4"
c n1 a1 ip addr del "$A3_4/32" dev o6pn0
expect_eq "that packet left the container and was counted as a spoofing drop" "$((before + 2))" "$(stat n1 drop_spoof)"

expect_fail "a container cannot ping the host through its gateway" c n1 a1 ping -c1 -W1 fe80::1%o6pn0
expect_fail "a container cannot reach other ports on the resolver address" c n1 a1 socat -t1 - 'TCP6:[fdaa::53]:22,connect-timeout=1'
# Misconfigure the hosts on purpose: the egress guards must hold anyway.
before=$(stat n1 drop_guard)
h n1 ip -6 route add "$A2_6/128" dev open6pn-wg
expect_fail "with a stray host route into the mesh, the host still cannot send into a network" h n1 ping -c1 -W1 "$A2_6"
h n1 ip -6 route del "$A2_6/128" dev open6pn-wg
expect_gt "that packet was dropped by the WireGuard egress guard" "$before" "$(stat n1 drop_guard)"

N1_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' open6pn-n1)
A1_IF=$(h n1 sh -c "open6pn endpoint ls --json | jq -r '.[] | select(.id == \"$A1_ID\") | .host_if'")
A1_MAC=$(c n1 a1 cat /sys/class/net/o6pn0/address)
before=$(stat n1 drop_guard)
h n1 sh -c "echo 1 >/proc/sys/net/ipv4/ip_forward && ip route add $A1_4/32 dev $A1_IF && ip neigh replace $A1_4 lladdr $A1_MAC dev $A1_IF"
h n3 ip route add "$A1_4/32" via "$N1_IP"
expect_fail "with a stray host route to a container, forwarded traffic still cannot enter it" h n3 ping -c2 -W1 "$A1_4"
h n3 ip route del "$A1_4/32" via "$N1_IP"
h n1 sh -c "ip neigh del $A1_4 dev $A1_IF; ip route del $A1_4/32 dev $A1_IF; echo 0 >/proc/sys/net/ipv4/ip_forward"
expect_gt "those packets were dropped by the container egress guard" "$before" "$(stat n1 drop_guard)"

say "what a container can make its host do"
# The node is part of every address, so a container can name any host. Its
# host must only send to hosts that have an endpoint in the container's network.
# Red is on n1 and n2 only.
RED_ON_N3=$(awk -F: -v n="$(printf %x "$N3_ID")" 'BEGIN { OFS = ":" } { $2 = n; print }' <<<"$R1_6")
before=$(stat n1 drop_no_peer)
expect_fail "red cannot send IPv6 to a host that has no red endpoint" c n1 r1 ping -c1 -W1 "$RED_ON_N3"
expect_fail "red cannot send IPv4 to a host that has no red endpoint" c n1 r1 ping -c1 -W1 "$A3_4"
expect_eq "both were dropped on the sending host" "$((before + 2))" "$(stat n1 drop_no_peer)"

# Neighbour discovery reaches the host's stack, which remembers every source
# it hears from. Only the endpoint's own addresses may be such a source.
before=$(stat n1 drop_spoof)
c n1 a1 sh -c 'ip -6 addr add fe80::bad/64 dev o6pn0 nodad; ip -6 neigh flush dev o6pn0; ping -c1 -W1 -I fe80::bad%o6pn0 fe80::1%o6pn0' >/dev/null 2>&1
c n1 a1 ip -6 addr del fe80::bad/64 dev o6pn0
expect_gt "neighbour discovery from an address that is not the endpoint's is dropped" "$before" "$(stat n1 drop_spoof)"
expect_eq "the host learned no neighbour from it" "0" "$(h n1 sh -c 'ip -6 neigh show | grep -c fe80::bad')"
expect_ok "neighbour discovery from the endpoint's own address still works" c n1 a1 sh -c 'ip -6 neigh flush dev o6pn0; ping -c2 -W2 '"$A1B_6"

# The resolver address must exist only for packets that came in through an
# attached veth. Any other interface of the host must not reach it, or the host
# would answer to whatever source address the packet claims: here, r1's.
snmp6() { c "$1" "$2" awk -v "k=$3" '$1 == k { print $2 }' /proc/net/snmp6; }
h n1 sh -c 'ip netns add other && ip link add otherh type veth peer name otherc netns other && ip link set otherh up \
	&& echo 0 >/proc/sys/net/ipv6/conf/otherh/disable_ipv6'
h n1 ip netns exec other sh -c "ip link set lo up && ip link set otherc up && ip -6 addr add $R1_6/128 dev otherc nodad"
retry 20 h n1 sh -c 'ip -6 -o addr show dev otherh scope link | grep -qv tentative'
h n1 sh -c 'ip netns exec other ip -6 route add fdaa::53/128 dev otherc via $(ip -6 -o addr show dev otherh scope link | awk "{print \$4}" | cut -d/ -f1)'
echoes=$(snmp6 n1 r1 Icmp6InEchoReplies) noports=$(snmp6 n1 r1 Udp6NoPorts) dgrams=$(snmp6 n1 r1 Udp6InDatagrams)
h n1 ip netns exec other ping -c2 -W1 -I "$R1_6" fdaa::53 >/dev/null 2>&1
h n1 ip netns exec other dig +time=1 +tries=2 -b "$R1_6" AAAA web.internal @fdaa::53 >/dev/null 2>&1
expect_eq "pinging the resolver address from another interface puts nothing into a network" "$echoes" "$(snmp6 n1 r1 Icmp6InEchoReplies)"
expect_eq "querying it from another interface puts nothing into a network" "$noports $dgrams" "$(snmp6 n1 r1 Udp6NoPorts) $(snmp6 n1 r1 Udp6InDatagrams)"
h n1 sh -c 'ip link del otherh; ip netns del other'
expect_eq "no interface of the host carries the resolver address" "0" "$(h n1 sh -c 'ip -6 addr show | grep -c "fdaa::53"')"

say "DNS"
dig6() { c "$1" "$2" dig +short +time=2 +tries=1 "$3" "$4" @fdaa::53 | sorted; }
rcode() { c "$1" "$2" dig +time=2 +tries=1 "$3" "$4" @fdaa::53 | sed -n 's/.*status: \([A-Z]*\).*/\1/p'; }
until_eq 3 10 name_count n1 a1 web
expect_eq "blue: web has AAAA records on both hosts" "$(list "$A1_6" "$A1B_6" "$A2_6")" "$(dig6 n1 a1 AAAA web.internal)"
expect_eq "blue: web has A records on both hosts" "$(list "$A1_4" "$A1B_4" "$A2_4")" "$(dig6 n3 a3 A web.internal)"
expect_eq "blue: api resolves from another host" "$A2_6" "$(dig6 n1 a1 AAAA api.internal)"
expect_eq "blue: db is blue's db, not red's" "$A3_6" "$(dig6 n2 a2 AAAA db.internal)"
expect_eq "red: web is red's web only" "$R1_6" "$(dig6 n2 r2 AAAA web.internal)"
expect_eq "red: db is red's db, not blue's" "$R2_6" "$(dig6 n1 r1 AAAA db.internal)"
expect_eq "red: blue-only name does not exist" "NXDOMAIN" "$(rcode n1 r1 AAAA api.internal)"
expect_eq "DNS over TCP" "$A2_6" "$(c n1 a1 dig +tcp +short +time=2 +tries=1 AAAA api.internal @fdaa::53)"
expect_eq "other names are forwarded upstream" "$ETCD_IP" "$(dig6 n1 a1 A open6pn-etcd)"
# The C library's resolver, with the resolv.conf the attach output describes.
h n1 sh -c 'mkdir -p /etc/netns/a1 && printf "nameserver fdaa::53\nsearch internal\n" >/etc/netns/a1/resolv.conf'
expect_eq "libc resolves a bare name to IPv6 through the search domain" "$A2_6" "$(c n1 a1 getent ahostsv6 api | awk '{print $1}' | sort -u | sorted)"
expect_eq "libc resolves a bare name to IPv4 through the search domain" "$A2_4" "$(c n1 a1 getent ahostsv4 api | awk '{print $1}' | sort -u | sorted)"

say "bulk TCP and small packets across hosts"
iperf() { # CLIENT-NODE CLIENT-NS SERVER-NODE SERVER-NS ADDR -> Mbit/s received
	bg "$3" "$4" iperf3 -s -1
	local out
	for _ in 1 2 3 4 5; do
		sleep 0.3
		out=$(c "$1" "$2" iperf3 -c "$5" -t 2 -J 2>/dev/null | jq -r '.end.sum_received.bits_per_second // 0 | . / 1e6 | floor' 2>/dev/null)
		[ "${out:-0}" -gt 0 ] 2>/dev/null && break
	done
	echo "${out:-0}"
}
expect_gt "iperf3 IPv6 n1 -> n2, Mbit/s" 50 "$(iperf n1 a1 n2 a2 "$A2_6")"
expect_gt "iperf3 IPv4 n1 -> n2, Mbit/s" 50 "$(iperf n1 a1 n2 a2 "$A2_4")"
expect_gt "iperf3 IPv4 same host, Mbit/s" 50 "$(iperf n1 a1b n1 a1 "$A1_4")"
udp1() { # one-byte IPv4 datagram: shorter than an IPv6 header once unwrapped
	h "$3" rm -f /tmp/udp.out
	bg "$3" "$4" socat -u UDP4-RECVFROM:9000 CREATE:/tmp/udp.out
	sleep 0.3
	c "$1" "$2" sh -c "printf x | socat -u - UDP4-SENDTO:$5:9000"
	retry 10 h "$3" test -s /tmp/udp.out && h "$3" cat /tmp/udp.out
}
expect_eq "1-byte IPv4 UDP datagram n1 -> n2" "x" "$(udp1 n1 a1 n2 a2 "$A2_4")"
expect_ok "IPv4 ping at the container MTU, don't-fragment" c n1 a1 ping -c1 -W2 -M do -s 1352 "$A2_4"
expect_ok "IPv6 ping at the container MTU" c n1 a1 ping -c1 -W2 -s 1332 "$A2_6"

say "attaching veth pairs that already exist"
h n3 sh -c 'ip netns add b1 && ip link add vhost1 type veth peer name eth1 netns b1'
read -r B1_6 B1_4 B1_ID <<<"$(h n3 sh -c "open6pn attach --veth vhost1 --netns /var/run/netns/b1 --name manual blue | jq -r '[.ipv6,.ipv4,.id]|join(\" \")'")"
expect_ok "daemon configures the container side: IPv6 in" c n1 a1 ping -c2 -W2 "$B1_6"
expect_ok "daemon configures the container side: IPv4 out" c n3 b1 ping -c2 -W2 "$A1_4"
expect_fail "the same veth cannot be attached twice" h n3 open6pn attach --veth vhost1 --netns /var/run/netns/b1 red

# Without the namespace, the daemon only needs the container MAC; the caller
# configures the container side from the attach output.
h n3 sh -c 'ip netns add b2 && ip link add vhost2 type veth peer name eth1 netns b2'
B2_MAC=$(c n3 b2 cat /sys/class/net/eth1/address)
read -r B2_6 B2_4 B2_MTU <<<"$(h n3 sh -c "open6pn attach --veth vhost2 --mac $B2_MAC blue | jq -r '[.ipv6,.ipv4,.mtu]|join(\" \")'")"
c n3 b2 sh -c "ip link set eth1 mtu $B2_MTU up && ip -6 addr add $B2_6/128 dev eth1 nodad && ip addr add $B2_4/32 dev eth1 \
	&& ip -6 route add fdaa::/16 via fe80::1 dev eth1 \
	&& ip route add 169.254.1.1 dev eth1 scope link && ip route add 10.0.0.0/8 via 169.254.1.1 dev eth1"
expect_ok "caller configures the container side: IPv6 out" c n3 b2 ping -c2 -W2 "$A2_6"
expect_ok "caller configures the container side: IPv4 in" c n1 a1 ping -c2 -W2 "$B2_4"
expect_ok "detach by host interface name" h n3 open6pn detach vhost2
expect_ok "a veth the daemon did not create is left in place" h n3 ip link show vhost2
expect_eq "it is left down, without the gateway address" "down 0" "$(h n3 sh -c 'echo $(cat /sys/class/net/vhost2/operstate) $(ip -6 addr show dev vhost2 | grep -c "fe80::1/")')"
expect_fail "its container cannot reach the host through it" c n3 b2 ping -c1 -W1 fe80::1%eth1
# The worst that can be done to it afterwards: up again, with an address.
before=$(stat n3 drop_unknown_if)
h n3 sh -c 'ip link set vhost2 up && ip addr add 192.0.2.1/24 dev vhost2'
c n3 b2 ip addr add 192.0.2.2/24 dev eth1
expect_fail "nor over IPv6 after someone brings it up again" c n3 b2 ping -c2 -W1 fe80::1%eth1
expect_fail "nor over IPv4" c n3 b2 ping -c2 -W1 192.0.2.1
expect_gt "the filters left on it dropped those packets" "$before" "$(stat n3 drop_unknown_if)"
expect_ok "detach by endpoint ID" h n3 open6pn detach "$B1_ID"
expect_fail "detached endpoints are unreachable" c n1 a1 ping -c1 -W1 "$B1_6"

say "daemon restart on n2"
out=$(h n2 timeout 20 open6pn daemon --etcd http://open6pn-etcd:2379 2>&1)
expect_ok "a second daemon on the same host is refused" grep -q 'already serving' <<<"$out"
expect_ok "and the first carries on, still a member" h n2 sh -c "open6pn node ls | grep -q '^$N2_ID .*this host'"
# An address n2 has just stopped using, and then the daemon is killed outright.
read -r OLD_6 OLD_4 OLD_ID <<<"$(attach n2 old blue)"
h n2 open6pn detach "$OLD_ID" >/dev/null
# etcd's network ID counter goes back, as it would if etcd were restored from
# a backup. n2 puts it right when it next comes up.
docker exec open6pn-etcd etcdctl put /open6pn/networks/next 1 >/dev/null
h n2 pkill -KILL -x open6pn
retry 30 sh -c "! docker exec open6pn-n2 pgrep -x open6pn >/dev/null"
expect_fail "n2's daemon is down" h n2 open6pn status
expect_ok "IPv6 to n2 still flows with its daemon down" c n1 a1 ping -c2 -W2 "$A2_6"
expect_ok "IPv4 to n2 still flows with its daemon down" c n1 a1 ping -c2 -W2 "$A2_4"
expect_fail "isolation holds with the daemon down" c n1 a1 ping -c1 -W1 "$R2_6"
start_daemon n2 OPEN6PN_LEGACY_DECAP=1
expect_eq "n2 restored both endpoints" "2" "$(count_eps n2)"
expect_eq "n2 kept its node ID" "$N2_ID" "$(node_id n2)"
read -r NEW_6 NEW_4 NEW_ID <<<"$(attach n2 new blue)"
expect_ok "after being killed, n2 does not hand out the address just freed ($OLD_6, now $NEW_6)" test -n "$NEW_6" -a "$NEW_6" != "$OLD_6"
h n2 open6pn detach "$NEW_ID" >/dev/null
expect_ok "n2 moved etcd's network ID counter back past the networks it serves" \
	retry 20 sh -c '[ "$(docker exec open6pn-etcd etcdctl get --print-value-only /open6pn/networks/next)" -gt 2 ]'
expect_ok "n2 still has $PEERS WireGuard peers" until_eq "$PEERS" 100 peer_count n2
[ "$PLACEHOLDERS" -gt 0 ] && echo "  resync after restart: $(h n2 sh -c "grep 'synced peers' /var/log/open6pn.log | tail -1 | sed 's/.*count=/count=/'")"
expect_ok "IPv6 to n2 after restart" c n1 a1 ping -c2 -W2 "$A2_6"
expect_eq "n2 resolves again after restart" "$A3_6" "$(retry 10 sh -c "[ -n \"\$(docker exec open6pn-n2 ip netns exec a2 dig +short +time=1 +tries=1 AAAA db.internal @fdaa::53)\" ]" && dig6 n2 a2 AAAA db.internal)"

say "IPv4 decapsulation path for kernels before 6.3 (forced on n2)"
expect_ok "IPv4 ping n1 -> n2" c n1 a1 ping -c2 -W2 "$A2_4"
expect_eq "1-byte IPv4 UDP datagram n1 -> n2" "x" "$(udp1 n1 a1 n2 a2 "$A2_4")"
expect_gt "iperf3 IPv4 n1 -> n2, Mbit/s" 50 "$(iperf n1 a1 n2 a2 "$A2_4")"
stop_daemon n2
start_daemon n2
expect_ok "IPv4 ping n1 -> n2 back on the normal path" c n1 a1 ping -c2 -W2 "$A2_4"

say "lifecycle"
before=$(count_eps n1)
h n1 ip netns del a1b
expect_ok "a vanished container is detached automatically" until_eq $((before - 1)) 20 count_eps n1
expect_ok "its DNS record disappears on other hosts" until_eq 2 20 name_count n2 a2 web
expect_fail "its address no longer answers" c n1 a1 ping -c1 -W1 "$A1B_6"

expect_fail "a network with endpoints cannot be removed" h n1 open6pn network rm blue
expect_ok "detach a3" h n3 open6pn detach "$A3_ID"
expect_fail "a detached endpoint is unreachable" c n1 a1 ping -c1 -W1 "$A3_6"
expect_ok "its name stops resolving on other hosts" retry 20 sh -c "docker exec open6pn-n1 ip netns exec a1 dig +time=1 +tries=1 AAAA db.internal @fdaa::53 | grep -q NXDOMAIN"
expect_eq "n3 has no endpoints left" "0" "$(count_eps n3)"

say "churn: 40 containers come and go on n1"
base=$(count_eps n1)
h n1 sh -c 's=$(date +%s%N); for i in $(seq 40); do ip netns add ch$i && open6pn attach --netns /var/run/netns/ch$i --name churn blue >/dev/null || exit 1; done; e=$(date +%s%N); echo "  $(( (e - s) / 40000000 )) ms per namespace + attach"'
expect_eq "40 more endpoints on n1" "$((base + 40))" "$(count_eps n1)"
expect_ok "another host resolves the name, capped at 24 answers" until_eq 24 20 name_count n2 a2 churn
expect_ok "the last one attached is reachable from another host" c n2 a2 ping -c2 -W2 "$(h n1 sh -c "open6pn endpoint ls --json | jq -r '[.[] | select(.names == [\"churn\"])] | last | .ipv6'")"
h n1 sh -c 'for i in $(seq 40); do ip netns del ch$i; done'
expect_ok "all 40 are detached once their namespaces are gone" until_eq "$base" 60 count_eps n1
expect_eq "no veth is left behind" "$base" "$(h n1 sh -c 'ip -o link | grep -c ": o6pn[0-9a-f]*@"')"
expect_ok "the name is gone on other hosts" retry 20 sh -c "docker exec open6pn-n2 ip netns exec a2 dig +time=1 +tries=1 AAAA churn.internal @fdaa::53 | grep -q NXDOMAIN"

if [ "$MAX_EP" -le 300 ]; then
	say "endpoint limit: $MAX_EP endpoints of one network on one host"
	expect_ok "create network full" h n3 open6pn network create full
	h n3 sh -c "for i in \$(seq $MAX_EP); do ip netns add f\$i && open6pn attach --netns /var/run/netns/f\$i full >/dev/null || exit 1; done"
	expect_eq "$MAX_EP endpoints attached" "$MAX_EP" "$(count_eps n3)"
	LAST_4=$(h n3 sh -c "open6pn endpoint ls --json | jq -r 'max_by(.endpoint_id) | .ipv4'")
	read -r F2_6 F2_4 F2_ID <<<"$(attach n2 f2 full)"
	expect_ok "the last one, $LAST_4, is reachable over IPv4 from another host" c n2 f2 ping -c2 -W2 "$LAST_4"
	h n3 ip netns add fmore
	expect_fail "one more is refused" h n3 open6pn attach --netns /var/run/netns/fmore full
	expect_ok "another network on the same host is unaffected" h n3 open6pn attach --netns /var/run/netns/fmore blue
	h n3 sh -c "for i in \$(seq $MAX_EP); do ip netns del f\$i; done; ip netns del fmore"
	expect_ok "all are detached once their namespaces are gone" until_eq 0 100 count_eps n3
fi

# Small meshes only: deleting a WireGuard device takes several milliseconds
# per peer.
if [ "$PLACEHOLDERS" -eq 0 ]; then
	say "--wg-peer-threads leaves the kernel's receive mode alone (n3, on a new WireGuard device)"
	stop_daemon n3
	h n3 ip link del open6pn-wg
	start_daemon n3 "" --wg-peer-threads
	expect_ok "n3 has $PEERS WireGuard peers again" until_eq "$PEERS" 100 peer_count n3
	if [ "$(h n3 cat /sys/class/net/open6pn-wg/threaded)" = 1 ]; then
		expect_ok "this kernel then runs one thread per peer" until_eq "$PEERS" 20 peer_threads
	else
		echo "  this kernel has no per-peer threads to keep"
	fi
	read -r T3_6 T3_4 T3_ID <<<"$(attach n3 t3 blue)"
	# n3 goes first: its new device has no sessions, and other hosts keep
	# using their old one until n3 starts a handshake or they time it out.
	expect_ok "IPv4 from n3 in that mode" c n3 t3 ping -c2 -W2 "$A1_4"
	expect_ok "IPv6 to n3 in that mode" c n1 a1 ping -c2 -W2 "$T3_6"
	expect_gt "iperf3 IPv6 n1 -> n3 in that mode, Mbit/s" 50 "$(iperf n1 a1 n3 t3 "$T3_6")"
fi

say "two networks under one ID, as after etcd lost its history"
# Take red out of etcd and turn the counter back to its ID. The next network
# created gets that ID, while red's containers are still running on n1 and n2.
RED_ID=$(h n1 sh -c "open6pn endpoint ls --json | jq '.[] | select(.network == \"red\") | .network_id' | head -n1")
docker exec open6pn-etcd etcdctl del /open6pn/networks/name/red >/dev/null
docker exec open6pn-etcd etcdctl del "/open6pn/networks/id/$RED_ID" >/dev/null
docker exec open6pn-etcd etcdctl put /open6pn/networks/next "$RED_ID" >/dev/null
expect_eq "a new network is given red's ID" "$RED_ID" "$(h n3 sh -c 'open6pn network create --json mallory | jq .id')"
expect_fail "a host with red containers refuses to attach it" h n1 sh -c 'ip netns add m1 && open6pn attach --netns /var/run/netns/m1 mallory'
read -r M3_6 M3_4 M3_ID <<<"$(attach n3 m3 mallory web)"
expect_ok "a host without any attaches it" test -n "$M3_6"
sleep 2 # for n3's record to reach n1 and n2
expect_fail "it cannot reach red's containers over IPv6" c n3 m3 ping -c2 -W1 "$R1_6"
expect_fail "it cannot reach red's containers over IPv4" c n3 m3 ping -c2 -W1 "$R2_4"
expect_fail "red's containers cannot reach it" c n1 r1 ping -c2 -W1 "$M3_6"
expect_eq "red does not resolve its names" "$R1_6" "$(dig6 n2 r2 AAAA web.internal)"
expect_eq "it does not resolve red's names" "$M3_6" "$(dig6 n3 m3 AAAA web.internal)"
expect_ok "red itself is unaffected" c n1 r1 ping -c2 -W2 "$R2_6"
expect_ok "the hosts with red containers say what they are ignoring" h n1 grep -q 'different network under this network' /var/log/open6pn.log
h n3 open6pn detach "$M3_ID" >/dev/null

say "removing a host"
expect_ok "remove node $N3_ID" h n1 open6pn node rm "$N3_ID"
expect_ok "n1 drops it as a WireGuard peer" until_eq "$((PEERS - 1))" 20 peer_count n1
expect_ok "n3's daemon, which was still running, stops" retry 30 sh -c "! docker exec open6pn-n3 pgrep -x open6pn >/dev/null"
expect_ok "and says why" h n3 grep -q 'was removed from the mesh while this daemon was running' /var/log/open6pn.log
expect_ok "the rest of the mesh is unaffected" c n1 a1 ping -c2 -W2 "$A2_4"

say "datapath counters"
for n in n1 n2; do
	printf '  %s: ' "$n"
	h "$n" sh -c "open6pn status --json | jq -c .stats"
done

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
	for n in n1 n2 n3; do
		printf '\n--- %s daemon log\n' "$n"
		h "$n" tail -n 40 /var/log/open6pn.log
	done
	exit 1
fi
