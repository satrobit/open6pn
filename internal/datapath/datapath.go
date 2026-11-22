//go:build linux

// Package datapath owns everything the daemon puts in the kernel: the
// WireGuard device, the eBPF programs and maps, and the handful of routes the
// resolver needs.
package datapath

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"open6pn/internal/addr"
)

//go:embed bpf/open6pn.o
var bpfObject []byte

const (
	// WGDevice is the name of the WireGuard interface on every host.
	WGDevice = "open6pn-wg"

	// EncapOverhead is the IPv6 header added to IPv4 packets between hosts.
	EncapOverhead = 40

	bpfFS  = "/sys/fs/bpf"
	pinDir = bpfFS + "/open6pn"

	// The resolver answers from addr.DNS; its replies reach containers
	// through this table, which only locally generated packets from that
	// address may use.
	dnsTable        = 5353
	dnsRulePriority = 100

	// addr.DNS is not assigned to any interface. It is a local address only
	// in this table, and only packets the datapath marked on their way in
	// from a container look there: nothing arriving on any other interface
	// can reach the resolver, or make the host answer from its address.
	dnsLocalTable        = 5354
	dnsLocalRulePriority = 99
	markedRulePriority   = 101
	// hostMark mirrors O6PN_MARK_HOST in bpf/open6pn.c.
	hostMark = 0x6f36706f
)

// Config is what the datapath needs to know about this host.
type Config struct {
	Layout     addr.Layout
	NodeID     uint16
	PrivateKey wgtypes.Key
	ListenPort int
	MTU        int // of the WireGuard device

	// PeerThreads leaves WireGuard's receive mode as the kernel has it.
	// Kernels from 6.16 start one kernel thread per peer; in a full mesh
	// that is one thread and some 24 KB of memory for every other host,
	// nearly all of them idle, so by default the daemon turns it off and
	// peers are served from softirq context as on every older kernel.
	PeerThreads bool

	// MaxNetNodes is the size of the table of (network, host) pairs that
	// containers may send to: for every network this host serves, one
	// entry per other host serving it.
	MaxNetNodes int

	// LegacyDecap forces the IPv4 decapsulation path used on kernels
	// older than 6.3. It exists so that path can be tested on newer ones.
	LegacyDecap bool
}

// Peer is another host in the mesh.
type Peer struct {
	NodeID    uint16
	PublicKey wgtypes.Key
	Endpoint  *net.UDPAddr
}

// Endpoint is one attached container interface, as the kernel sees it.
type Endpoint struct {
	NetworkID    uint32
	EpID         uint16
	Ifindex      int // host side of the veth
	HostMAC      net.HardwareAddr
	ContainerMAC net.HardwareAddr
}

type objects struct {
	FromContainer *ebpf.Program `ebpf:"o6pn_from_container"`
	ToContainer   *ebpf.Program `ebpf:"o6pn_to_container"`
	FromWG        *ebpf.Program `ebpf:"o6pn_from_wg"`
	ToWG          *ebpf.Program `ebpf:"o6pn_to_wg"`
	EpByIf        *ebpf.Map     `ebpf:"o6pn_ep_by_if"`
	EpByAddr      *ebpf.Map     `ebpf:"o6pn_ep_by_addr"`
	NetNodes      *ebpf.Map     `ebpf:"o6pn_net_nodes"`
	Stats         *ebpf.Map     `ebpf:"o6pn_stats"`
}

// These mirror struct ep_if, ep_key, ep_val and net_node in bpf/open6pn.c.
type epIf struct {
	NetID uint32
	EpID  uint16
	HMAC  [6]byte
	CMAC  [6]byte
	_     [2]byte
}

// NetNode says that a node has an endpoint in a network.
type NetNode struct {
	NetID uint32
	Node  uint32
}

type epKey struct {
	NetID uint32
	EpID  uint32
}

type epVal struct {
	Ifindex uint32
	CMAC    [6]byte
	HMAC    [6]byte
}

// StatNames mirrors the STAT_* enum in bpf/open6pn.c.
var StatNames = []string{
	"tx_local", "tx_remote", "rx_remote", "to_host", "arp_reply",
	"drop_unknown_if", "drop_spoof", "drop_isolation", "drop_outside",
	"drop_no_endpoint", "drop_unsupported", "drop_encap", "drop_guard",
	"drop_no_peer",
}

// Datapath is the kernel state of one host.
type Datapath struct {
	cfg  Config
	wg   *wgctrl.Client
	link netlink.Link
	objs objects

	threadsOff bool // per-peer kernel threads are known to be off
}

// Open creates or adopts the kernel state. Maps are pinned, and tc filters
// hold the programs, so traffic keeps flowing while the daemon is down; Open
// swaps freshly loaded programs in over the old ones.
func Open(cfg Config) (*Datapath, error) {
	if err := cfg.Layout.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Layout.ValidNode(cfg.NodeID) {
		return nil, fmt.Errorf("invalid node ID %d", cfg.NodeID)
	}
	d := &Datapath{cfg: cfg}
	if err := d.setupWireGuard(); err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	if err := d.loadBPF(); err != nil {
		d.wg.Close()
		return nil, fmt.Errorf("ebpf: %w", err)
	}
	if err := attachTC(d.link, d.objs.FromWG, d.objs.ToWG); err != nil {
		d.Close()
		return nil, fmt.Errorf("attach to %s: %w", WGDevice, err)
	}
	if err := d.setupRouting(); err != nil {
		d.Close()
		return nil, fmt.Errorf("routing: %w", err)
	}
	return d, nil
}

// Close releases the daemon's handles. Kernel state stays in place.
func (d *Datapath) Close() {
	for _, p := range []*ebpf.Program{d.objs.FromContainer, d.objs.ToContainer, d.objs.FromWG, d.objs.ToWG} {
		if p != nil {
			p.Close()
		}
	}
	for _, m := range []*ebpf.Map{d.objs.EpByIf, d.objs.EpByAddr, d.objs.NetNodes, d.objs.Stats} {
		if m != nil {
			m.Close()
		}
	}
	if d.wg != nil {
		d.wg.Close()
	}
}

func (d *Datapath) setupWireGuard() error {
	link, err := netlink.LinkByName(WGDevice)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		wg := &netlink.Wireguard{LinkAttrs: netlink.NewLinkAttrs()}
		wg.Name = WGDevice
		wg.MTU = d.cfg.MTU
		if err := netlink.LinkAdd(wg); err != nil {
			return fmt.Errorf("create %s (is the wireguard module available?): %w", WGDevice, err)
		}
		link, err = netlink.LinkByName(WGDevice)
	}
	if err != nil {
		return err
	}
	if link.Type() != "wireguard" {
		return fmt.Errorf("%s exists but is a %s device", WGDevice, link.Type())
	}
	if link.Attrs().MTU != d.cfg.MTU {
		if err := netlink.LinkSetMTU(link, d.cfg.MTU); err != nil {
			return err
		}
	}

	d.wg, err = wgctrl.New()
	if err != nil {
		return err
	}
	port := d.cfg.ListenPort
	if err := d.wg.ConfigureDevice(WGDevice, wgtypes.Config{PrivateKey: &d.cfg.PrivateKey, ListenPort: &port}); err != nil {
		return err
	}

	if err := enableIPv6(WGDevice); err != nil {
		return err
	}
	// Earlier builds assigned the resolver address to this device, which
	// made it reachable from every interface of the host. See setupRouting.
	netlink.AddrDel(link, &netlink.Addr{IPNet: hostNet(addr.DNS)})
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	d.peerThreadsOff()
	d.link, err = netlink.LinkByName(WGDevice)
	return err
}

// peerThreadsOff stops WireGuard from running a kernel thread per peer, for
// peers added from now on and for those already there. The kernel only
// accepts the setting while the device has at least one peer, so this is
// called again after peers are added until it has taken.
func (d *Datapath) peerThreadsOff() {
	if d.cfg.PeerThreads || d.threadsOff {
		return
	}
	path := "/sys/class/net/" + WGDevice + "/threaded"
	cur, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(cur)) == "0" {
		d.threadsOff = true // a kernel without the mode, or already off
		return
	}
	if os.WriteFile(path, []byte("0"), 0o644) == nil {
		d.threadsOff = true
	}
}

func (d *Datapath) loadBPF() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	if err := ensureBPFFS(); err != nil {
		return err
	}
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		return err
	}

	load := func() error {
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
		if err != nil {
			return err
		}
		consts := map[string]uint32{
			"cfg_node_id":    uint32(d.cfg.NodeID),
			"cfg_ep_bits":    uint32(d.cfg.Layout.EndpointBits()),
			"cfg_wg_ifindex": uint32(d.link.Attrs().Index),
		}
		if d.cfg.LegacyDecap {
			consts["cfg_legacy_decap"] = 1
		}
		if d.cfg.MaxNetNodes > 0 {
			m, ok := spec.Maps["o6pn_net_nodes"]
			if !ok {
				return errors.New("datapath object has no o6pn_net_nodes")
			}
			m.MaxEntries = uint32(d.cfg.MaxNetNodes)
		}
		for name, v := range consts {
			vs, ok := spec.Variables[name]
			if !ok {
				return fmt.Errorf("datapath object has no %s", name)
			}
			if err := vs.Set(v); err != nil {
				return err
			}
		}
		return spec.LoadAndAssign(&d.objs, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}})
	}

	err := load()
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		// Pinned maps from a build with a different layout. Programs
		// still attached keep the old maps alive until they are replaced
		// below, so start over with new ones; the daemon repopulates them.
		entries, _ := os.ReadDir(pinDir)
		for _, e := range entries {
			os.Remove(filepath.Join(pinDir, e.Name()))
		}
		err = load()
	}
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("verifier rejected the datapath: %+v", ve)
		}
		return err
	}
	return nil
}

func (d *Datapath) setupRouting() error {
	// Mesh addresses are never routed by the host. Without this, a packet
	// the host generates for one (an ICMP error, say) would follow the
	// default route out of the uplink.
	blackhole := &netlink.Route{
		Family: netlink.FAMILY_V6,
		Dst:    prefixNet(addr.Cluster6),
		Type:   unix.RTN_BLACKHOLE,
	}
	if err := netlink.RouteReplace(blackhole); err != nil {
		return fmt.Errorf("blackhole %s: %w", addr.Cluster6, err)
	}

	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V6
	rule.IifName = "lo" // locally generated packets only
	rule.Src = hostNet(addr.DNS)
	rule.Table = dnsTable
	rule.Priority = dnsRulePriority
	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("resolver rule: %w", err)
	}

	// The resolver address, for marked packets only.
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	local := &netlink.Route{
		Family:    netlink.FAMILY_V6,
		Type:      unix.RTN_LOCAL,
		Dst:       hostNet(addr.DNS),
		LinkIndex: lo.Attrs().Index,
		Table:     dnsLocalTable,
	}
	if err := netlink.RouteReplace(local); err != nil {
		return fmt.Errorf("resolver address: %w", err)
	}
	mask := uint32(0xffffffff)
	marked := netlink.NewRule()
	marked.Family = netlink.FAMILY_V6
	marked.Mark = hostMark
	marked.Mask = &mask
	marked.Table = dnsLocalTable
	marked.Priority = dnsLocalRulePriority
	if err := netlink.RuleAdd(marked); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("resolver address rule: %w", err)
	}

	endpoints := netlink.NewRule()
	endpoints.Family = netlink.FAMILY_V6
	endpoints.Mark = hostMark
	endpoints.Mask = &mask
	endpoints.Table = dnsTable
	endpoints.Priority = markedRulePriority
	if err := netlink.RuleAdd(endpoints); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("endpoint route rule: %w", err)
	}
	return nil
}

// ---- which hosts a network may send to ----

// ErrNetNodesFull means the table of hosts that networks may send to has no
// room left.
var ErrNetNodesFull = errors.New("the table of hosts that networks may send to is full")

// AllowNode lets containers of a network send to a node.
func (d *Datapath) AllowNode(k NetNode) error {
	err := d.objs.NetNodes.Put(k, uint8(1))
	if errors.Is(err, unix.E2BIG) {
		return ErrNetNodesFull
	}
	return err
}

// DenyNode undoes AllowNode.
func (d *Datapath) DenyNode(k NetNode) error {
	if err := d.objs.NetNodes.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// AllowedNodes returns everything AllowNode has let through and DenyNode has
// not taken back, including what an earlier run of the daemon left.
func (d *Datapath) AllowedNodes() ([]NetNode, error) {
	var (
		k   NetNode
		v   uint8
		out []NetNode
	)
	it := d.objs.NetNodes.Iterate()
	for it.Next(&k, &v) {
		out = append(out, k)
	}
	return out, it.Err()
}

// SyncPeers makes the WireGuard peer set exactly peers and returns how many it
// had to change. Peers that are already configured correctly are left
// untouched: reconfiguring one discards its session, and traffic from the
// other side then stalls until it notices.
func (d *Datapath) SyncPeers(peers []Peer) (int, error) {
	dev, err := d.wg.Device(WGDevice)
	if err != nil {
		return 0, err
	}
	have := make(map[wgtypes.Key]wgtypes.Peer, len(dev.Peers))
	for _, p := range dev.Peers {
		have[p.PublicKey] = p
	}
	var cfg wgtypes.Config
	for _, p := range peers {
		cur, ok := have[p.PublicKey]
		delete(have, p.PublicKey)
		if !ok || !samePeer(cur, p) {
			cfg.Peers = append(cfg.Peers, peerConfig(p))
		}
	}
	for key := range have {
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: key, Remove: true})
	}
	if len(cfg.Peers) == 0 {
		return 0, nil
	}
	n := len(cfg.Peers)
	if !d.cfg.PeerThreads && !d.threadsOff {
		// Add one peer, turn the per-peer threads off, then add the rest:
		// otherwise a large mesh starts thousands of threads only to stop
		// them again.
		first := wgtypes.Config{Peers: cfg.Peers[:1]}
		if err := d.wg.ConfigureDevice(WGDevice, first); err != nil {
			return 0, err
		}
		d.peerThreadsOff()
		if cfg.Peers = cfg.Peers[1:]; len(cfg.Peers) == 0 {
			return n, nil
		}
	}
	return n, d.wg.ConfigureDevice(WGDevice, cfg)
}

func samePeer(cur wgtypes.Peer, want Peer) bool {
	if len(cur.AllowedIPs) != 1 || cur.Endpoint == nil || want.Endpoint == nil {
		return false
	}
	ip, ok := netip.AddrFromSlice(cur.AllowedIPs[0].IP)
	ones, _ := cur.AllowedIPs[0].Mask.Size()
	if !ok || netip.PrefixFrom(ip.Unmap(), ones) != addr.NodePrefix(want.NodeID) {
		return false
	}
	a, b := cur.Endpoint.AddrPort(), want.Endpoint.AddrPort()
	return a.Addr().Unmap() == b.Addr().Unmap() && a.Port() == b.Port()
}

// SetPeer adds or updates one peer.
func (d *Datapath) SetPeer(p Peer) error {
	err := d.wg.ConfigureDevice(WGDevice, wgtypes.Config{Peers: []wgtypes.PeerConfig{peerConfig(p)}})
	d.peerThreadsOff()
	return err
}

// RemovePeer removes one peer.
func (d *Datapath) RemovePeer(key wgtypes.Key) error {
	return d.wg.ConfigureDevice(WGDevice, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}}})
}

// A peer may send from, and is sent, exactly its own /32: WireGuard's
// AllowedIPs is both the routing table and the source check between hosts.
func peerConfig(p Peer) wgtypes.PeerConfig {
	return wgtypes.PeerConfig{
		PublicKey:         p.PublicKey,
		Endpoint:          p.Endpoint,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{*prefixNet(addr.NodePrefix(p.NodeID))},
	}
}

// AttachEndpoint programs the datapath for one veth and brings its host side
// up. It is idempotent. The link is brought up last: before the programs are
// attached, anything the container sent would land in the host stack.
func (d *Datapath) AttachEndpoint(ep Endpoint) error {
	link, err := netlink.LinkByIndex(ep.Ifindex)
	if err != nil {
		return err
	}
	if len(ep.HostMAC) != 6 || len(ep.ContainerMAC) != 6 {
		return fmt.Errorf("endpoint needs both MAC addresses")
	}
	byIf := epIf{NetID: ep.NetworkID, EpID: ep.EpID}
	copy(byIf.HMAC[:], ep.HostMAC)
	copy(byIf.CMAC[:], ep.ContainerMAC)
	byAddr := epVal{Ifindex: uint32(ep.Ifindex)}
	copy(byAddr.CMAC[:], ep.ContainerMAC)
	copy(byAddr.HMAC[:], ep.HostMAC)

	if err := d.objs.EpByIf.Put(uint32(ep.Ifindex), byIf); err != nil {
		return fmt.Errorf("endpoint map: %w", err)
	}
	if err := attachTC(link, d.objs.FromContainer, d.objs.ToContainer); err != nil {
		return fmt.Errorf("attach to %s: %w", link.Attrs().Name, err)
	}
	if err := d.objs.EpByAddr.Put(epKey{NetID: ep.NetworkID, EpID: uint32(ep.EpID)}, byAddr); err != nil {
		return fmt.Errorf("endpoint map: %w", err)
	}
	// The host side's own configuration: the IPv6 gateway address the
	// container routes through. It is (re)done here rather than when the
	// veth is prepared so that an endpoint restored after an interrupted
	// detach comes back whole.
	name := link.Attrs().Name
	if err := enableIPv6(name); err != nil {
		return err
	}
	os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/accept_ra", []byte("0"), 0o644)
	if err := netlink.AddrReplace(link, gatewayAddr()); err != nil {
		return fmt.Errorf("assign %s to %s: %w", addr.Gateway6, name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	route := &netlink.Route{
		Family:    netlink.FAMILY_V6,
		LinkIndex: ep.Ifindex,
		Dst:       hostNet(addr.V6(d.cfg.NodeID, ep.NetworkID, ep.EpID)),
		Table:     dnsTable,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("resolver route: %w", err)
	}
	return nil
}

// DetachEndpoint removes an endpoint from the datapath. The veth may already
// be gone. If it is not, it is left down, without the gateway address, with
// IPv6 off, and with the filters still on it.
//
// The filters stay on purpose. With the endpoint's map entries gone they drop
// everything the container sends, whatever is done to the interface later; a
// veth without them is a container on the host's own IP stack the moment it
// is brought up. Attaching the veth again replaces them; to use it for
// something else, remove them with "tc qdisc del dev IF clsact".
func (d *Datapath) DetachEndpoint(ep Endpoint) error {
	var errs []error
	key := epKey{NetID: ep.NetworkID, EpID: uint32(ep.EpID)}
	var cur epVal
	// Only remove the address entry if it still points at this veth.
	if err := d.objs.EpByAddr.Lookup(key, &cur); err == nil && cur.Ifindex == uint32(ep.Ifindex) {
		if err := d.objs.EpByAddr.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	if err := d.objs.EpByIf.Delete(uint32(ep.Ifindex)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, err)
	}
	if link, err := netlink.LinkByIndex(ep.Ifindex); err == nil {
		netlink.RouteDel(&netlink.Route{
			Family:    netlink.FAMILY_V6,
			LinkIndex: ep.Ifindex,
			Dst:       hostNet(addr.V6(d.cfg.NodeID, ep.NetworkID, ep.EpID)),
			Table:     dnsTable,
		})
		if err := netlink.LinkSetDown(link); err != nil {
			errs = append(errs, fmt.Errorf("set %s down: %w", link.Attrs().Name, err))
		}
		netlink.AddrDel(link, gatewayAddr())
		os.WriteFile("/proc/sys/net/ipv6/conf/"+link.Attrs().Name+"/disable_ipv6", []byte("1"), 0o644)
	}
	return errors.Join(errs...)
}

// Prune deletes every map entry that does not belong to one of keep. It
// clears out whatever a previous run left behind.
func (d *Datapath) Prune(keep []Endpoint) error {
	ifs := make(map[uint32]bool, len(keep))
	addrs := make(map[epKey]bool, len(keep))
	for _, ep := range keep {
		ifs[uint32(ep.Ifindex)] = true
		addrs[epKey{NetID: ep.NetworkID, EpID: uint32(ep.EpID)}] = true
	}

	var (
		ifKey    uint32
		ifVal    epIf
		staleIfs []uint32
	)
	it := d.objs.EpByIf.Iterate()
	for it.Next(&ifKey, &ifVal) {
		if !ifs[ifKey] {
			staleIfs = append(staleIfs, ifKey)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, k := range staleIfs {
		d.objs.EpByIf.Delete(k)
	}

	var (
		aKey       epKey
		aVal       epVal
		staleAddrs []epKey
	)
	it = d.objs.EpByAddr.Iterate()
	for it.Next(&aKey, &aVal) {
		if !addrs[aKey] {
			staleAddrs = append(staleAddrs, aKey)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, k := range staleAddrs {
		d.objs.EpByAddr.Delete(k)
	}
	return nil
}

// Stats returns the datapath counters, summed over CPUs.
func (d *Datapath) Stats() (map[string]uint64, error) {
	out := make(map[string]uint64, len(StatNames))
	for i, name := range StatNames {
		var perCPU []uint64
		if err := d.objs.Stats.Lookup(uint32(i), &perCPU); err != nil {
			return nil, err
		}
		for _, v := range perCPU {
			out[name] += v
		}
	}
	return out, nil
}

// LinkExists reports whether ifindex still refers to an interface called name.
func LinkExists(ifindex int, name string) bool {
	link, err := netlink.LinkByIndex(ifindex)
	return err == nil && link.Attrs().Name == name
}

// LinkIs reports whether ifindex is still the veth it was when an endpoint
// was attached: same name and same MAC address. An interface index or a name
// alone can come back as a different container's interface.
func LinkIs(ifindex int, name string, mac net.HardwareAddr) bool {
	link, err := netlink.LinkByIndex(ifindex)
	return err == nil && link.Type() == "veth" && link.Attrs().Name == name &&
		bytes.Equal(link.Attrs().HardwareAddr, mac)
}

// LinkNames returns the name of every interface, by index.
func LinkNames() (map[int]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	out := make(map[int]string, len(links))
	for _, l := range links {
		out[l.Attrs().Index] = l.Attrs().Name
	}
	return out, nil
}

func ensureBPFFS() error {
	var st unix.Statfs_t
	if err := unix.Statfs(bpfFS, &st); err == nil && st.Type == unix.BPF_FS_MAGIC {
		return nil
	}
	if err := os.MkdirAll(bpfFS, 0o755); err != nil {
		return err
	}
	if err := unix.Mount("bpf", bpfFS, "bpf", 0, ""); err != nil {
		return fmt.Errorf("mount bpffs on %s: %w", bpfFS, err)
	}
	return nil
}

func enableIPv6(ifname string) error {
	path := "/proc/sys/net/ipv6/conf/" + ifname + "/disable_ipv6"
	if err := os.WriteFile(path, []byte("0"), 0o644); err != nil {
		return fmt.Errorf("enable IPv6 on %s: %w", ifname, err)
	}
	return nil
}

func hostNet(a netip.Addr) *net.IPNet {
	return prefixNet(netip.PrefixFrom(a, a.BitLen()))
}

func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
