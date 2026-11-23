# open6pn

Private networks for containers across many hosts. One daemon per host, WireGuard between hosts, an eBPF datapath, and etcd for cluster state.

open6pn is an independent, open implementation of the idea behind [Fly.io's 6PN private networking](https://fly.io/docs/networking/private-networking/); see [Credits](#credits).

A container attached to a network gets an IPv6 address, an IPv4 address and a resolver. It can reach every other container on the same network, on any host, and nothing else.

## How it works

Every attached interface (an *endpoint*) is identified by three numbers, and both its addresses are derived from them:

| | Range |
|---|---|
| node (host) | 1–16,383 by default; up to 65,535 |
| network | 1–4,294,967,295 |
| endpoint, per node and network | 1–1,022 by default |

```
IPv6   fdaa:<node>:<network hi>:<network lo>::<endpoint>     fdaa:2a:0:beef::7
IPv4   10.<node><endpoint>, 24 bits between them             10.0.168.7
```

IPv6 has 16 bits for the node and 16 for the endpoint. IPv4 has 24 bits for both, so a cluster chooses how to split them when its first host starts (`--node-bits`), and keeps that split for good:

| `--node-bits` | Hosts | Endpoints of one network on one host |
|---|---|---|
| 12 | 4,095 | 4,094 |
| 14 (default) | 16,383 | 1,022 |
| 16 | 65,535 | 254 |

Running out of hosts cannot be fixed without re-addressing every container. Running out of endpoints only means that host refuses another container of that network, and it can go on another host. If in doubt, choose more hosts.

- **Between hosts** there is one WireGuard device per host and one peer per other host. A peer's only allowed range is its own `fdaa:<node>::/32`, which is also the route to it.
- **IPv6** is routed natively: container → veth → WireGuard → veth → container.
- **IPv4** carries no network ID, so every network has all of `10.0.0.0/8` to itself and addresses overlap between networks. Between hosts an IPv4 packet is wrapped in an IPv6 header whose network field the *sending host* fills in from the interface the packet arrived on. On the same host it is delivered directly.
- **DNS** is served by the daemon on `fdaa::53`. `<name>.internal` resolves to the endpoints with that name in the asker's network; everything else is forwarded to the resolvers given with `--dns-upstream` (by default, the host's own).
- **Cluster state** is in etcd: the node list, the networks, and each endpoint's names. Every host watches the node list. A host watches a network's endpoints only while it has an endpoint in that network.

The host's IP stack never forwards mesh traffic. Packets move between interfaces with `bpf_redirect`, so no forwarding sysctls, iptables rules or per-tenant routes are involved.

## Requirements

- Linux 5.6 or later, with WireGuard and tc eBPF. The IPv4 path uses a helper flag from Linux 6.3 and falls back to an older method below that; the fallback is exercised by the test suite, but only on a recent kernel.
- Root (or `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_SYS_ADMIN`).
- An etcd cluster every host can reach.
- UDP 51820 open between hosts.
- IPv6 not disabled on the host (`net.ipv6.conf.all.disable_ipv6=0`). No IPv6 connectivity is needed.

## Build

```bash
make build
```

This produces `bin/open6pn-linux-<arch>`. The compiled eBPF object is committed; `make bpf` rebuilds it from `internal/datapath/bpf/open6pn.c` using Docker.

With Nix, `nix build` produces `result/bin/open6pn` on Linux and runs the unit tests, and `nix develop` gives a shell with Go on Linux and macOS.

### NixOS

The flake has a NixOS module, `nixosModules.default`:

```nix
{
  imports = [ open6pn.nixosModules.default ];
  services.open6pn = {
    enable = true;
    etcd.endpoints = [ "https://etcd-1:2379" ];
    etcd.caFile = "/run/secrets/etcd-ca.pem";
    advertise = "203.0.113.10";
  };
}
```

It runs the daemon with its state in `/var/lib/open6pn`, loads WireGuard, opens the WireGuard port, lets the host's resolver answer containers through the NixOS firewall (iptables or nftables), and keeps dhcpcd off the interfaces open6pn creates. `nix build .#checks.x86_64-linux.nixos` runs it in three NixOS VMs: etcd and two hosts.

## Quick start

On every host:

```bash
open6pn daemon --etcd https://etcd-1:2379,https://etcd-2:2379 --advertise 203.0.113.10
```

Starting the daemon joins the host: it generates a WireGuard key, takes the lowest free node ID and registers itself. Both are kept in `/var/lib/open6pn/state.json`, so the host keeps its ID across restarts and reboots. That directory is the host's identity: never copy it to another host, or start a host from a snapshot of another. Two hosts with one identity are not detected; each takes the other's place, and traffic for their containers goes to whichever registered last.

The first host to start creates the cluster, with 16,383 hosts as the limit and a WireGuard MTU of 1420. For other values, give that first host `--node-bits` (see the table above) or `--mtu`; the others read them from etcd. Neither can be changed afterwards, and a daemon started with a different value refuses to run.

On any host:

```bash
open6pn network create acme
```

On the host running the container:

```bash
open6pn attach --netns /proc/$PID/ns/net --name web acme
```

```json
{
  "id": "805b4eb02325",
  "network": "acme",
  "ipv6": "fdaa:1:0:1::1",
  "ipv4": "10.0.4.1",
  "names": ["web"],
  "host_if": "o6pnf6f7e71b52",
  "mtu": 1380,
  "routes": [
    {"dst": "fdaa::/16", "via": "fe80::1"},
    {"dst": "10.0.0.0/8", "via": "169.254.1.1"}
  ],
  "dns": {"servers": ["fdaa::53"], "search": ["internal"]}
}
```

Put `nameserver fdaa::53` and `search internal` in the container's `resolv.conf`, and `web` resolves to every endpoint named `web` on the network.

## Try it locally

`compose.yaml` starts a small mesh on one machine with Docker: etcd, three hosts, and seven containers in two private networks. It builds the binary itself, so Go is not needed.

```bash
docker compose up -d --build --wait
```

| Container | Network | Host | Name | IPv4 | IPv6 |
|---|---|---|---|---|---|
| `blue-web` | blue | n1 | `web` | 10.0.4.1 | fdaa:1:0:1::1 |
| `blue-worker` | blue | n1 | `worker` | 10.0.4.2 | fdaa:1:0:1::2 |
| `blue-api` | blue | n2 | `api` | 10.0.8.1 | fdaa:2:0:1::1 |
| `blue-db` | blue | n3 | `db` | 10.0.12.1 | fdaa:3:0:1::1 |
| `red-web` | red | n1 | `web` | 10.0.4.1 | fdaa:1:0:2::1 |
| `red-api` | red | n2 | `api` | 10.0.8.1 | fdaa:2:0:2::1 |
| `red-db` | red | n3 | `db` | 10.0.12.1 | fdaa:3:0:2::1 |

`./dev/addrs` prints this table from the running containers. The two networks use the same names and the same IPv4 addresses on purpose.

Within a network, by address or by name:

```bash
docker compose exec blue-web ping -c2 10.0.12.1
```

```bash
docker compose exec blue-web ping -c2 db
```

Between networks nothing gets through. `blue-web` cannot reach `red-api`, on another host or its own:

```bash
docker compose exec blue-web ping -c2 -W1 fdaa:2:0:2::1
```

The same IPv4 address is a different container in each network. Start a listener in both `db` containers, then ask from each side:

```bash
docker compose exec -d blue-db socat TCP4-LISTEN:7000,fork,reuseaddr SYSTEM:'echo I am blue-db'
```

```bash
docker compose exec -d red-db socat TCP4-LISTEN:7000,fork,reuseaddr SYSTEM:'echo I am red-db'
```

```bash
docker compose exec red-web socat - TCP4:10.0.12.1:7000
```

The hosts are `n1`, `n2` and `n3`:

```bash
docker compose exec n1 open6pn status
```

```bash
docker compose exec n1 wg show
```

`open6pn status` shows the blocked packets under `drop_isolation`. `wg show` lists a peer for each other host from the start; a peer's handshake appears with the first packet sent to it.

Things to know:

- The containers have no other network: no internet, no Docker network. The mesh interface is all they have.
- After changing the code, run the `up` command again. The hosts keep their node IDs in volumes, so the addresses stay the same.
- `docker compose exec n1 pkill -x open6pn` restarts a host's daemon; traffic keeps flowing while it is down.
- `docker compose restart n2` is a host reboot. Its containers stop with it and come back on their own.
- `docker compose down -v` removes everything. Without `-v` the cluster's state is kept for the next `up`.
- To add a container, copy one of the services in `compose.yaml` and set `pid:` to its host and `OPEN6PN_NETWORK` to its network. A new network goes into `OPEN6PN_NETWORKS`.

## Attaching containers

| You have | Command | The daemon does |
|---|---|---|
| A network namespace | `open6pn attach --netns PATH NET` | Creates the veth pair, configures both ends, deletes the pair on detach |
| A veth pair and the namespace | `open6pn attach --veth HOSTIF --netns PATH NET` | Configures both ends of your pair |
| A veth pair only | `open6pn attach --veth HOSTIF --mac CONTAINER-MAC NET` | Configures the host end; you configure the container end from the output |

For the last case, inside the container:

```bash
ip link set eth1 mtu 1380 up
ip -6 addr add fdaa:1:0:1::1/128 dev eth1 nodad
ip addr add 10.0.4.1/32 dev eth1
ip -6 route add fdaa::/16 via fe80::1 dev eth1
ip route add 169.254.1.1 dev eth1 scope link
ip route add 10.0.0.0/8 via 169.254.1.1 dev eth1
```

`--name` may be repeated, and names may have several labels (`--name web --name web.ams`).

An endpoint is detached with `open6pn detach ID|HOSTIF`, or automatically when its veth disappears, which is what happens when the container exits. A veth the daemon created is deleted. A veth you created is handed back down, with the gateway address removed, IPv6 switched off on it, and the filters still in place, so that the container behind it is not connected to the host whatever happens to the interface next. Attaching it again works as before. To use it for something else, remove the filters with `tc qdisc del dev IF clsact`.

When a network is new to a host, the host has to read which other hosts serve it before the container can send to them, which is one request to etcd. `attach` waits for that, for up to two seconds. Other hosts learn of the new endpoint a moment after `attach` returns.

With gVisor, the sandbox reads its interfaces, addresses and routes from the network namespace when it starts, so attach before `runsc` boots the sandbox.

## Isolation

Three checks, all in `internal/datapath/bpf/open6pn.c`:

1. **Leaving a container**, the source address must be exactly the endpoint's own.
2. **Choosing a destination**, an IPv6 destination must be in the sender's network. An IPv4 destination has no network; the host supplies the sender's.
3. **Arriving from another host**, source and destination network must match, and the inner IPv4 addresses must agree with the outer IPv6 ones. WireGuard has already verified that the source lies in the sending host's range.

On top of that:

- **The host does not forward.** Egress programs on every veth and on the WireGuard device drop anything the host's IP stack is forwarding, so a stray route on the host, or forwarding being enabled, does not open a path into a network. Into a container they let through what the datapath put there and what the host itself originates, which is neighbour discovery and resolver answers.
- **What a container can reach on its host** is neighbour discovery on its own veth, from its own addresses only, and port 53 on `fdaa::53`.
- **The resolver address is not an address of the host.** `fdaa::53` exists only for packets that came in through an attached veth and passed check 1 there. Nothing arriving on any other interface can reach the resolver or make the host answer from that address. That is also what makes it safe for the resolver to choose answers by the asker's source address.
- **A container can only send to hosts that serve its network.** The host is part of every address, so a container can name any host in the mesh; its own host refuses to send to one that has no endpoint in the container's network.
- **A detached veth is not left connected.** See [Attaching containers](#attaching-containers).
- **Network IDs are not reused.** They come from a counter in etcd that only moves forward. If etcd loses its history (see [restoring etcd](#operations)), two networks can end up with one ID. Hosts guard against that themselves: every endpoint is published with the name and creation time of its network, a host ignores endpoints published under one of its IDs for a different network, and it refuses to attach a different network under an ID it already uses. Two such networks cannot reach each other or see each other's names.

What this does **not** protect against:

- **A compromised host.** Hosts are trusted. A host with root can attach anything to any network, and anything that can write to etcd can change the node list.
- **A noisy neighbour.** Networks cannot reach each other, but they share their hosts. Nothing limits how much traffic one network sends through a host's WireGuard device. The resolver does limit each network on a host: 32 forwarded queries in flight and 8 TCP connections, out of 512 and 256 for the whole host. The limits are per network, so a tenant with many networks gets that many shares.
- **What the upstream resolvers know.** A container can look up any name the resolvers behind `fdaa::53` answer. By default those are the host's own, which may know internal names; point `--dns-upstream` at resolvers that only know what tenants may see.

## Operations

- **Restarting or upgrading the daemon** does not interrupt traffic. The eBPF maps are pinned and the programs stay attached; a new daemon swaps its programs in and reconciles. Only DNS is unavailable while the daemon is down. The exception is an upgrade that changes the layout of a map: the maps are then rebuilt, and traffic stops for the moment that takes.
- **A dead daemon or host** keeps its DNS records for `--endpoint-ttl` (default 1m), then they expire.
- **A reboot** clears the kernel state. The host rejoins with the same ID; every endpoint it had is dropped, because none of their interfaces exist any more. Hosts that were talking to it keep their old WireGuard session until it sends them something or they time the session out (about 15 seconds).
- **etcd being unreachable from every host** stops changes from propagating. Existing traffic and DNS answers are unaffected, and attaching to a network the host already serves still works.
- **One host losing etcd** while the others keep it is different: after `--endpoint-ttl` its records expire, and the other hosts stop resolving its containers' names. Traffic to their addresses keeps flowing: other hosts go on sending to it for an hour after its records are gone, and for as long as its containers keep sending to theirs. When the host reaches etcd again it publishes everything afresh. If links to etcd are unreliable, raise `--endpoint-ttl`; the price is that a host that has really died keeps its names that much longer.
- **Removing a host**: stop its daemon, then `open6pn node rm ID` from any other host. Its ID becomes free. A daemon that is still running when its node is removed withdraws its DNS records and exits; if something restarts it, it joins again.
- **Restoring etcd from a backup** loses what happened after the backup. Hosts that joined since find themselves removed: their daemons exit and join again when restarted, with the same ID unless another host has taken it. Networks created since are gone from etcd while their containers run on; create them again under a new name, or leave them until their containers are gone. The network ID counter goes back too: each daemon moves it forward again past the networks it has containers in, when it starts and every ten minutes, and logs an error when it had to. Avoid creating networks in the first ten minutes after a restore. If one is created with an ID still in use, the two are kept apart as described under [Isolation](#isolation).
- **Monitoring**: `open6pn status` prints the datapath counters. `drop_spoof`, `drop_isolation`, `drop_guard` and `drop_no_peer` should stay at zero in normal operation.
- **Uninstalling**: `ip link del open6pn-wg; rm -rf /sys/fs/bpf/open6pn /var/lib/open6pn; ip -6 rule del pref 99; ip -6 rule del pref 100; ip -6 route flush table 5353; ip -6 route flush table 5354; ip -6 route del blackhole fdaa::/16`. In a large mesh the first command is slow; see below.

Secure etcd with TLS (`--etcd-ca`, `--etcd-cert`, `--etcd-key`) or a user (`--etcd-user`, `OPEN6PN_ETCD_PASSWORD`). `--etcd-prefix` separates several meshes on one etcd.

## Large meshes

Every host is a WireGuard peer of every other host. That is a lot of peers and very little work: a peer that carries no traffic sends nothing (no keepalives are configured), and a host only sends to, and so only exchanges handshakes with, the hosts it shares a network with.

Measured on Linux 7.0, three real hosts in a mesh padded out with placeholder hosts (`PLACEHOLDERS=N make e2e`):

| Peers per host | Kernel memory | Daemon memory | First sync | Resync after a daemon restart | Single-flow throughput vs. 2 peers |
|---|---|---|---|---|---|
| 16,002 | about 30 MB | 50 MB | 0.5 s | 25 ms | unchanged |
| 65,002 | about 110 MB | about 120 MB | 2.3 s | 0.1 s | unchanged |

Things to know at that size:

- **Kernel threads.** Recent kernels (7.0 here) start one kernel thread per WireGuard peer. Each costs about 24 KB and counts against the host's thread limit (`kernel.threads-max`, which is derived from RAM): 16,000 peers were 16,000 threads and about 380 MB, and 65,000 peers exhausted the limit of an 8 GB machine, after which nothing on it could start a process. The daemon therefore turns this mode off on its device, which is how older kernels behave. `--wg-peer-threads` keeps the kernel's default. Single-flow throughput was the same either way; many peers busy at once has not been compared.
- **A host joining or leaving** is one small update on every other host. Nothing is recomputed. Each daemon also compares the kernel's whole peer set with the node list it holds every five minutes and after any failed update; it reads the list from etcd again whenever its watch on it is interrupted.
- **Many hosts joining at once** first try the lowest free ID, and those that lose pick a random free one, so they do not queue up behind each other.
- **Deleting a host's whole WireGuard device** is the one slow operation: `ip link del` on a device with 65,000 peers took about ten minutes here.
- **etcd** has one watch on the node list per host, plus one per network a host serves. The node list is read in pages.
- **A host's own state** is one small file per endpoint, so attaching and detaching cost the same on a host with tens of thousands of endpoints as on an empty one.
- **Hosts per network.** Each host keeps a table of the other hosts its networks reach: one entry for every (network it serves, other host serving that network). It holds 1,048,576 entries by default, for 16 MB of kernel memory. A host whose networks together span more than that needs a larger `--max-network-hosts`; when the table is full the daemon logs an error and containers cannot reach the hosts that did not fit (`drop_no_peer`).
- **Many endpoints on one host.** The kernel keeps a neighbour entry for every container the host talks to, and its default limit is 1,024 (`net.ipv6.neigh.default.gc_thresh3`). On hosts with more than a few hundred endpoints, raise `gc_thresh1`, `gc_thresh2` and `gc_thresh3` to a few times the number of endpoints.

## Limits

- 16,383 hosts and 1,022 endpoints per network per host by default; see `--node-bits`. A host can serve 65,536 endpoints in total (the eBPF map size, a constant in `open6pn.c`).
- Container MTU is 1380 with the default WireGuard MTU of 1420. The MTU is the same on every host of a cluster.
- The resolver is reached over IPv6 only. It answers both `A` and `AAAA` queries.
- Containers route all of `10.0.0.0/8` into the mesh. If they also need to reach something else in that range, this layout does not fit as it is.
- A container's addresses change if it moves to another host. Use names. An address that becomes free on a host is the last one that host hands out again.
- A name resolves to at most 24 endpoints per answer, chosen at random.
- No customer-chosen subnets, no multicast or broadcast, no access from outside the mesh.

## Testing

```bash
make test
```

runs the unit tests (address layout, DNS, resolver limits).

```bash
make e2e
```

starts etcd and three hosts as privileged containers and checks, with real WireGuard and eBPF: IPv4 and IPv6 within a network across and within hosts; that the same IPv4 address reaches different containers in different networks; that networks cannot reach each other, including with spoofed sources and with a deliberately misconfigured host; that a container cannot reach its host after a detach, cannot send to hosts outside its network, and cannot be reached through the resolver address from another interface; DNS over UDP, TCP and through libc; bulk TCP and small packets; daemon restarts; and endpoint and host lifecycle.

To run the same checks inside a large mesh, register placeholder hosts first. The three real hosts then get node IDs above them and carry that many WireGuard peers each:

```bash
PLACEHOLDERS=16000 make e2e
```

```bash
NODE_BITS=16 PLACEHOLDERS=65000 make e2e
```

## Layout

```
cmd/open6pn               CLI and daemon entry point
internal/addr             address layout
internal/datapath         WireGuard, veth plumbing, eBPF loader
internal/datapath/bpf     the eBPF programs
internal/store            cluster state in etcd
internal/state            the host's local state file
internal/dns              resolver
internal/agent            the daemon
internal/api              local control API (Unix socket)
test/e2e                  multi-host test
test/e2e/seed             registers placeholder hosts for the large-mesh test
compose.yaml, dev         a local mesh to try things on (Docker Compose)
```

## Credits

open6pn is inspired by [Fly.io](https://fly.io) and its 6PN ("IPv6 private networking"), which the name refers to. The core of the design is theirs: a WireGuard mesh between hosts, IPv6 addresses under `fdaa::/16` that carry the host and the network, eBPF to keep networks apart, and `.internal` DNS. Fly.io described it in [Incoming! 6PN Private Networks](https://fly.io/blog/incoming-6pn-private-networks/) and documents it under [Private Networking](https://fly.io/docs/networking/private-networking/).

This project is not affiliated with or endorsed by Fly.io, and shares no code with it. The address layout, the IPv4 support and the implementation are its own, and so are its mistakes.

## License

MIT; see [LICENSE](LICENSE).

The eBPF programs in `internal/datapath/bpf` are the exception: they are licensed under GPL-2.0-only or BSD-2-Clause, at your option, as their header says. The kernel only lets a program use some of its helpers if it declares a GPL-compatible licence.
