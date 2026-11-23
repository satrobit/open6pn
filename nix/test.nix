{ module, package }:
{
  name = "open6pn";

  nodes =
    let
      host =
        { config, pkgs, ... }:
        {
          imports = [ module ];
          services.open6pn = {
            enable = true;
            inherit package;
            etcd.endpoints = [ "http://etcd:2379" ];
            advertise = config.networking.primaryIPAddress;
          };
          environment.systemPackages = [
            pkgs.dnsutils
            pkgs.curl
            pkgs.socat
            pkgs.jq
            pkgs.wireguard-tools
          ];
        };
    in
    {
      etcd = {
        services.etcd = {
          enable = true;
          listenClientUrls = [ "http://0.0.0.0:2379" ];
          advertiseClientUrls = [ "http://etcd:2379" ];
        };
        networking.firewall.allowedTCPPorts = [ 2379 ];
      };
      n1 = host;
      n2 = {
        imports = [ host ];
        networking.nftables.enable = true;
      };
    };

  testScript = ''
    def attach(node, ns, name):
        node.succeed(f"ip netns add {ns} && ip netns exec {ns} ip link set lo up")
        return node.succeed(f"open6pn attach --netns /var/run/netns/{ns} --name {name} blue | jq -r .ipv6,.ipv4").split()

    start_all()
    etcd.wait_for_unit("etcd.service")
    for n in (n1, n2):
        n.wait_for_unit("open6pn.service")
        n.wait_until_succeeds("open6pn status")

    with subtest("the hosts joined one mesh"):
        n1.wait_until_succeeds("[ $(open6pn node ls --json | jq length) = 2 ]")
        n1.succeed("open6pn network create blue")

    web6, web4 = attach(n1, "web", "web")
    api6, api4 = attach(n2, "api", "api")
    n2.succeed("printf 'HTTP/1.0 200 OK\\r\\nContent-Length: 6\\r\\n\\r\\nhello\\n' >/resp")
    n2.succeed("ip netns exec api socat TCP6-LISTEN:7000,ipv6only=0,fork,reuseaddr SYSTEM:'sleep 0.1; cat /resp' >/dev/null 2>&1 &")

    n1.execute(f"ip netns exec web ping -c3 -W2 {api6}")
    with subtest("containers on two hosts reach each other over IPv6 and IPv4"):
        n1.wait_until_succeeds(f"ip netns exec web ping -c1 -W2 {api6}", timeout=30)
        n1.succeed(f"ip netns exec web ping -c2 -W2 {api4}")
        n1.succeed(f"ip netns exec web curl -sf -m5 http://[{api6}]:7000/ | grep -q hello")
        n1.succeed(f"ip netns exec web curl -sf -m5 http://{api4}:7000/ | grep -q hello")

    with subtest("containers resolve names with the firewall on, iptables on n1 and nftables on n2"):
        n1.succeed("systemctl is-active firewall.service")
        n2.succeed("systemctl is-active nftables.service")
        got = n1.succeed("ip netns exec web dig +short +time=2 +tries=2 AAAA api.internal @fdaa::53").strip()
        assert got == api6, f"n1: api.internal resolved to {got!r}, want {api6}"
        got = n2.succeed("ip netns exec api dig +short +time=2 +tries=2 AAAA web.internal @fdaa::53").strip()
        assert got == web6, f"n2: web.internal resolved to {got!r}, want {web6}"

    with subtest("a daemon restart keeps the endpoints and their traffic"):
        n1.systemctl("restart open6pn.service")
        n1.wait_until_succeeds("open6pn status")
        n1.succeed("[ $(open6pn endpoint ls --json | jq length) = 1 ]")
        n1.succeed(f"ip netns exec web ping -c2 -W2 {api6}")

    with subtest("dhcpcd leaves the interfaces open6pn creates alone"):
        n1.sleep(40)
        for n in (n1, n2):
            n.fail("journalctl -u dhcpcd --no-pager | grep -E 'o6pn|open6pn-wg'")
            n.fail("ip -4 addr show | grep -B2 169.254 | grep -E 'o6pn|open6pn-wg'")
  '';
}
