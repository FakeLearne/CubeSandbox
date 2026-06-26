// Copyright (c) 2024 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"github.com/tencentcloud/CubeSandbox/CubeNet/cubevs"
	CubeLog "github.com/tencentcloud/CubeSandbox/cubelog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var netlinkRouteReplace = netlink.RouteReplace
var netlinkRouteDel = netlink.RouteDel
var netlinkRouteListFiltered = netlink.RouteListFiltered
var netlinkRouteList = netlink.RouteList
var netlinkLinkByIndex = netlink.LinkByIndex
var netlinkLinkByName = netlink.LinkByName
var netlinkLinkList = netlink.LinkList
var netlinkLinkDel = netlink.LinkDel
var netlinkAddrList = netlink.AddrList
var netlinkNeighList = netlink.NeighList
var unixOpen = unix.Open
var unixClose = unix.Close
var unixIoctlIfreq = unix.IoctlIfreq
var unixIoctlSetInt = unix.IoctlSetInt
var unixIoctlSetPointerInt = unix.IoctlSetPointerInt
var execCommand = exec.Command

const (
	tapNamePrefix    = "z"
	cubeDevName      = "cube-dev"
	cubeRouterName   = "cube-router"
	cubeSNATPortMin  = 30000
	cubeSNATPortMax  = 65535
	virtioNetHdrSize = 12
	txQLen           = 1000
	tunDevicePath    = "/dev/net/tun"
)

type machineDevice struct {
	Index      int
	Name       string
	IP         net.IP
	Mac        net.HardwareAddr
	GatewayMac net.HardwareAddr
}

type cubeDev struct {
	Index int
	Name  string
	IP    net.IP
	Mac   net.HardwareAddr
}

type cubeRouter struct {
	Index        int
	Name         string
	IP           net.IP
	Mask         int
	Mac          net.HardwareAddr
	NATIP        net.IP
	RoutedPrefix bool
}

type cubeRouterSpec struct {
	IP           net.IP
	Mask         int
	Mac          string
	NATIP        net.IP
	RoutedPrefix bool
}

type tapDevice struct {
	Index        int
	Name         string
	IP           net.IP
	InUse        bool
	File         *os.File
	PortMappings []PortMapping
	FailureCount int
	LastError    string
	LastStage    string
}

func deriveCubeRouterCIDRSpec(cidr, macAddr string) (*cubeRouterSpec, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cube-router cidr %q: %w", cidr, err)
	}
	ip4 := ip.To4()
	if ip4 == nil || network.IP.To4() == nil {
		return nil, fmt.Errorf("cube-router cidr %q is not IPv4", cidr)
	}
	if !ip4.Equal(network.IP.To4()) {
		return nil, fmt.Errorf("cube-router cidr %q must be aligned to the network address", cidr)
	}
	mask, bits := network.Mask.Size()
	if bits != 32 || mask < 8 || mask > 30 {
		return nil, fmt.Errorf("cube-router cidr %q mask must be between /8 and /30", cidr)
	}
	if _, err := net.ParseMAC(macAddr); err != nil {
		return nil, fmt.Errorf("parse cube-router mac %q: %w", macAddr, err)
	}

	base := ipv4ToUint32(network.IP)
	return &cubeRouterSpec{
		IP:           uint32ToIPv4(base + 1),
		Mask:         mask,
		Mac:          macAddr,
		NATIP:        uint32ToIPv4(base + 2),
		RoutedPrefix: true,
	}, nil
}

func deriveCubeRouterSpecFromSandboxCIDR(cidr, macAddr string) (*cubeRouterSpec, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse sandbox cidr %q: %w", cidr, err)
	}
	if ip.To4() == nil || network.IP.To4() == nil {
		return nil, fmt.Errorf("sandbox cidr %q is not IPv4", cidr)
	}
	mask, bits := network.Mask.Size()
	if bits != 32 || mask < 8 || mask > 29 {
		return nil, fmt.Errorf("sandbox cidr %q must be between /8 and /29 when cube-router cidr is omitted", cidr)
	}
	if _, err := net.ParseMAC(macAddr); err != nil {
		return nil, fmt.Errorf("parse cube-router mac %q: %w", macAddr, err)
	}

	base := ipv4ToUint32(network.IP)
	size := uint32(1) << (32 - mask)
	return &cubeRouterSpec{
		IP:           uint32ToIPv4(base + size - 3),
		Mask:         32,
		Mac:          macAddr,
		NATIP:        uint32ToIPv4(base + size - 2),
		RoutedPrefix: false,
	}, nil
}

func cubeRouterSpecFromConfig(cfg Config) (*cubeRouterSpec, error) {
	if cfg.CubeRouterCIDR != "" {
		return deriveCubeRouterCIDRSpec(cfg.CubeRouterCIDR, cfg.CubeRouterMacAddr)
	}
	return deriveCubeRouterSpecFromSandboxCIDR(cfg.CIDR, cfg.CubeRouterMacAddr)
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func uint32ToIPv4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
}

func getGatewayMacAddr(ifName string) (string, error) {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return "", err
	}
	gatewayIP, err := defaultGatewayIP(link)
	if err != nil {
		return "", err
	}
	neighs, err := netlinkNeighList(link.Attrs().Index, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, neigh := range neighs {
		if isUsableGatewayNeighbor(neigh, gatewayIP) {
			return neigh.HardwareAddr.String(), nil
		}
	}
	return "", fmt.Errorf("gateway mac for %s via %s not found", ifName, gatewayIP.String())
}

func defaultGatewayIP(link netlink.Link) (net.IP, error) {
	routes, err := netlinkRouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	var gatewayIP net.IP
	var gatewayMetric int
	for _, route := range routes {
		if !isIPv4DefaultRoute(route.Dst) || route.Gw.To4() == nil {
			continue
		}
		if gatewayIP == nil || route.Priority < gatewayMetric {
			gatewayIP = route.Gw.To4()
			gatewayMetric = route.Priority
		}
	}
	if gatewayIP == nil {
		return nil, fmt.Errorf("default gateway not found on %s", link.Attrs().Name)
	}
	return gatewayIP, nil
}

func isIPv4DefaultRoute(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, bits := dst.Mask.Size()
	return bits == 32 && ones == 0
}

func isUsableGatewayNeighbor(neigh netlink.Neigh, gatewayIP net.IP) bool {
	if neigh.Family != netlink.FAMILY_V4 || !neigh.IP.Equal(gatewayIP) || len(neigh.HardwareAddr) == 0 {
		return false
	}
	switch neigh.State {
	case unix.NUD_REACHABLE, unix.NUD_STALE, unix.NUD_DELAY, unix.NUD_PROBE, unix.NUD_PERMANENT:
		return true
	default:
		return false
	}
}

func getMachineDevice(ifName string) (*machineDevice, error) {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return nil, err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	if len(addrs) != 1 {
		return nil, fmt.Errorf("ipv4 address on %s is not unique", ifName)
	}
	gwMac, err := getGatewayMacAddr(ifName)
	if err != nil {
		return nil, err
	}
	gatewayMac, err := net.ParseMAC(gwMac)
	if err != nil {
		return nil, err
	}
	return &machineDevice{
		Index:      link.Attrs().Index,
		Name:       link.Attrs().Name,
		IP:         addrs[0].IP,
		Mac:        link.Attrs().HardwareAddr,
		GatewayMac: gatewayMac,
	}, nil
}

func getOrCreateCubeDev(ip net.IP, mask, mtu int, macAddr string) (*cubeDev, error) {
	desiredAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(mask, 32),
		},
	}
	link, err := netlinkLinkByName(cubeDevName)
	if err == nil {
		dummy, ok := link.(*netlink.Dummy)
		if !ok {
			return nil, fmt.Errorf("%s is not dummy", cubeDevName)
		}
		addrs, err := netlink.AddrList(dummy, netlink.FAMILY_V4)
		if err != nil {
			return nil, err
		}
		hasDesiredAddr := false
		for _, addr := range addrs {
			if addr.IPNet != nil && addr.IPNet.IP.Equal(ip) {
				ones, _ := addr.IPNet.Mask.Size()
				if ones == mask {
					hasDesiredAddr = true
					continue
				}
			}
			if err := netlink.AddrDel(dummy, &addr); err != nil {
				return nil, err
			}
		}
		if !hasDesiredAddr {
			if err := netlink.AddrAdd(dummy, desiredAddr); err != nil && !errors.Is(err, syscall.EEXIST) {
				return nil, err
			}
		}
		if dummy.Attrs().Flags&net.FlagUp == 0 {
			if err := netlink.LinkSetUp(dummy); err != nil {
				return nil, err
			}
		}
		if dummy.Attrs().MTU != mtu {
			if err := netlink.LinkSetMTU(dummy, mtu); err != nil {
				return nil, err
			}
		}
		return &cubeDev{
			Index: dummy.Index,
			Name:  cubeDevName,
			IP:    ip,
			Mac:   dummy.HardwareAddr,
		}, nil
	}
	gwAddr, err := net.ParseMAC(macAddr)
	if err != nil {
		return nil, err
	}
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:         cubeDevName,
			HardwareAddr: gwAddr,
			TxQLen:       txQLen,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		return nil, err
	}
	if err := netlink.AddrAdd(dummy, desiredAddr); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetUp(dummy); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetMTU(dummy, mtu); err != nil {
		return nil, err
	}
	return &cubeDev{
		Index: dummy.Index,
		Name:  cubeDevName,
		IP:    ip,
		Mac:   dummy.HardwareAddr,
	}, nil
}

func getOrCreateCubeRouter(spec *cubeRouterSpec, mtu int) (*cubeRouter, error) {
	if spec == nil {
		return nil, fmt.Errorf("cube-router spec is nil")
	}
	ip := spec.IP
	mask := spec.Mask
	natIP := spec.NATIP
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("cube-router ip is not an IPv4 address")
	}
	if natIP == nil || natIP.To4() == nil {
		return nil, fmt.Errorf("cube-router nat ip is not an IPv4 address")
	}
	if ip.Equal(natIP) {
		return nil, fmt.Errorf("cube-router nat ip %s must differ from cube-router local ip", natIP.String())
	}
	if mask <= 0 || mask > 32 {
		return nil, fmt.Errorf("invalid cube-router mask %d", mask)
	}
	if spec.RoutedPrefix && !ipInSameIPv4Prefix(ip, natIP, mask) {
		return nil, fmt.Errorf("cube-router nat ip %s is not in %s/%d", natIP.String(), ip.String(), mask)
	}
	if err := ensureIPv4IsNotLocal(natIP); err != nil {
		return nil, err
	}

	desiredAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(mask, 32),
		},
	}
	link, err := netlinkLinkByName(cubeRouterName)
	if err == nil {
		dummy, ok := link.(*netlink.Dummy)
		if !ok {
			return nil, fmt.Errorf("%s is not dummy", cubeRouterName)
		}
		if spec.RoutedPrefix {
			if err := ensureCIDRDoesNotOverlapHostRoutes(desiredAddr.IPNet, dummy.Index); err != nil {
				return nil, err
			}
		}
		if err := ensureCubeRouterMAC(dummy, spec.Mac); err != nil {
			return nil, err
		}
		addrs, err := netlinkAddrList(dummy, netlink.FAMILY_V4)
		if err != nil {
			return nil, err
		}
		hasDesiredAddr := false
		for _, addr := range addrs {
			if addr.IPNet != nil && addr.IPNet.IP.Equal(ip) {
				ones, _ := addr.IPNet.Mask.Size()
				if ones == mask {
					hasDesiredAddr = true
					continue
				}
			}
			if err := netlink.AddrDel(dummy, &addr); err != nil {
				return nil, err
			}
		}
		if !hasDesiredAddr {
			if err := netlink.AddrAdd(dummy, desiredAddr); err != nil && !errors.Is(err, syscall.EEXIST) {
				return nil, err
			}
		}
		if dummy.Attrs().Flags&net.FlagUp == 0 {
			if err := netlink.LinkSetUp(dummy); err != nil {
				return nil, err
			}
		}
		if dummy.Attrs().MTU != mtu {
			if err := netlink.LinkSetMTU(dummy, mtu); err != nil {
				return nil, err
			}
		}
		return &cubeRouter{
			Index:        dummy.Index,
			Name:         cubeRouterName,
			IP:           ip,
			Mask:         mask,
			Mac:          dummy.HardwareAddr,
			NATIP:        natIP,
			RoutedPrefix: spec.RoutedPrefix,
		}, nil
	}
	gwAddr, err := net.ParseMAC(spec.Mac)
	if err != nil {
		return nil, err
	}
	if spec.RoutedPrefix {
		if err := ensureCIDRDoesNotOverlapHostRoutes(desiredAddr.IPNet, 0); err != nil {
			return nil, err
		}
	}
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:         cubeRouterName,
			HardwareAddr: gwAddr,
			TxQLen:       txQLen,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		return nil, err
	}
	if err := netlink.AddrAdd(dummy, desiredAddr); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetUp(dummy); err != nil {
		return nil, err
	}
	if err := netlink.LinkSetMTU(dummy, mtu); err != nil {
		return nil, err
	}
	return &cubeRouter{
		Index:        dummy.Index,
		Name:         cubeRouterName,
		IP:           ip,
		Mask:         mask,
		Mac:          dummy.HardwareAddr,
		NATIP:        natIP,
		RoutedPrefix: spec.RoutedPrefix,
	}, nil
}

func ensureCubeRouterMAC(dummy *netlink.Dummy, macAddr string) error {
	want, err := net.ParseMAC(macAddr)
	if err != nil {
		return err
	}
	if dummy.HardwareAddr.String() == want.String() {
		return nil
	}
	return fmt.Errorf("%s has MAC %s, want %s", cubeRouterName, dummy.HardwareAddr.String(), want.String())
}

func ensureCubeRouterMatches(spec *cubeRouterSpec) error {
	existing, err := currentCubeRouter()
	if err != nil || existing == nil {
		return err
	}
	wantMac, err := net.ParseMAC(spec.Mac)
	if err != nil {
		return err
	}
	if existing.IP.Equal(spec.IP) &&
		existing.Mask == spec.Mask &&
		existing.NATIP.Equal(spec.NATIP) &&
		existing.RoutedPrefix == spec.RoutedPrefix &&
		existing.Mac.String() == wantMac.String() {
		return nil
	}
	return cleanupCubeRouter()
}

func currentCubeRouter() (*cubeRouter, error) {
	link, err := netlinkLinkByName(cubeRouterName)
	if err != nil {
		if isLinkNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	dummy, ok := link.(*netlink.Dummy)
	if !ok {
		return nil, fmt.Errorf("%s is not dummy", cubeRouterName)
	}
	router := &cubeRouter{
		Index: dummy.Index,
		Name:  dummy.Name,
		Mac:   dummy.HardwareAddr,
	}
	addrs, err := netlinkAddrList(dummy, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if addr.IPNet == nil || addr.IP.To4() == nil {
			continue
		}
		mask, bits := addr.IPNet.Mask.Size()
		if bits != 32 || mask <= 0 || mask > 32 {
			continue
		}
		router.IP = addr.IP.To4()
		router.Mask = mask
		if mask <= 30 {
			router.NATIP = uint32ToIPv4(ipv4ToUint32(addr.IP.Mask(addr.IPNet.Mask)) + 2)
			router.RoutedPrefix = true
		} else if mask == 32 {
			router.NATIP = uint32ToIPv4(ipv4ToUint32(addr.IP) + 1)
		}
		return router, nil
	}
	return router, nil
}

func cleanupCubeRouter() error {
	link, err := netlinkLinkByName(cubeRouterName)
	if err != nil {
		if isLinkNotFound(err) {
			return nil
		}
		return err
	}
	router, err := currentCubeRouter()
	if err != nil {
		return err
	}
	if router != nil && router.IP != nil && router.NATIP != nil {
		if err := deleteCubeRouterHostNetworking(router); err != nil {
			return err
		}
	}
	return netlinkLinkDel(link)
}

func isLinkNotFound(err error) bool {
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound) || strings.Contains(strings.ToLower(err.Error()), "not found")
}

func ipInSameIPv4Prefix(base, ip net.IP, mask int) bool {
	base4 := base.To4()
	ip4 := ip.To4()
	if base4 == nil || ip4 == nil {
		return false
	}
	return (&net.IPNet{IP: base4, Mask: net.CIDRMask(mask, 32)}).Contains(ip4)
}

func ensureIPv4IsNotLocal(ip net.IP) error {
	links, err := netlinkLinkList()
	if err != nil {
		return err
	}
	for _, link := range links {
		addrs, err := netlinkAddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			if addr.IP.Equal(ip) {
				return fmt.Errorf("cube-router nat ip %s must not be configured as local address on %s", ip.String(), link.Attrs().Name)
			}
		}
	}
	return nil
}

func ensureCIDRDoesNotOverlapHostRoutes(cidr *net.IPNet, ignoreLinkIndex int) error {
	if cidr == nil || cidr.IP.To4() == nil {
		return fmt.Errorf("cube-router prefix is not an IPv4 CIDR")
	}
	links, err := netlinkLinkList()
	if err != nil {
		return err
	}
	for _, link := range links {
		routes, err := netlinkRouteList(link, netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		for _, route := range routes {
			if route.Dst == nil || route.Dst.IP.To4() == nil {
				continue
			}
			if ignoreLinkIndex != 0 && route.LinkIndex == ignoreLinkIndex {
				continue
			}
			ones, bits := route.Dst.Mask.Size()
			if bits != 32 || ones == 0 {
				continue
			}
			if cidrsOverlap(cidr, route.Dst) {
				return fmt.Errorf("cube-router prefix %s overlaps host route %s on %s", cidr.String(), route.Dst.String(), link.Attrs().Name)
			}
		}
	}
	return nil
}

func cidrsOverlap(a, b *net.IPNet) bool {
	if a == nil || b == nil || a.IP.To4() == nil || b.IP.To4() == nil {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func configureCubeRouterHostNetworking(router *cubeRouter) error {
	if router == nil {
		return fmt.Errorf("cube-router is not initialized")
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("enable ip_forward failed: %w", err)
	}
	if err := writeSysctlIfExists("/proc/sys/net/ipv4/conf/all/rp_filter", "0"); err != nil {
		return err
	}
	if err := writeSysctlIfExists(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", router.Name), "0"); err != nil {
		return err
	}
	if !router.RoutedPrefix {
		if err := ensureRouteToCubeRouterNAT(router); err != nil {
			return err
		}
	}
	if err := ensureCubeRouterIptables(router); err != nil {
		return err
	}
	if err := ensureCubeRouterNATNeighbor(router); err != nil {
		return err
	}
	return nil
}

func deleteCubeRouterHostNetworking(router *cubeRouter) error {
	if router == nil || router.IP == nil || router.NATIP == nil {
		return nil
	}
	if err := deleteCubeRouterIptables(router); err != nil {
		return err
	}
	if !router.RoutedPrefix {
		if err := deleteRouteToCubeRouterNAT(router); err != nil {
			return err
		}
	}
	_ = netlink.NeighDel(&netlink.Neigh{
		Family:    netlink.FAMILY_V4,
		IP:        router.NATIP,
		LinkIndex: router.Index,
	})
	return nil
}

func ensureCubeRouterNATNeighbor(router *cubeRouter) error {
	return netlink.NeighSet(&netlink.Neigh{
		Family:       netlink.FAMILY_V4,
		IP:           router.NATIP,
		HardwareAddr: router.Mac,
		LinkIndex:    router.Index,
		State:        netlink.NUD_PERMANENT,
	})
}

func ensureRouteToCubeRouterNAT(router *cubeRouter) error {
	if router == nil || router.Index == 0 || router.NATIP == nil {
		return fmt.Errorf("cube-router is not initialized")
	}
	dst := &net.IPNet{IP: router.NATIP, Mask: net.CIDRMask(32, 32)}
	route := &netlink.Route{
		LinkIndex: router.Index,
		Dst:       dst,
		Scope:     netlink.SCOPE_LINK,
		Protocol:  unix.RTPROT_STATIC,
	}
	routes, err := netlinkRouteListFiltered(netlink.FAMILY_V4, route, netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
	if err != nil {
		return fmt.Errorf("list route for %s via %s: %w", dst.String(), router.Name, err)
	}
	for _, existing := range routes {
		if existing.Dst != nil && existing.Dst.String() == dst.String() && existing.LinkIndex == router.Index {
			return nil
		}
	}
	return netlinkRouteReplace(route)
}

func deleteRouteToCubeRouterNAT(router *cubeRouter) error {
	if router == nil || router.Index == 0 || router.NATIP == nil {
		return nil
	}
	err := netlinkRouteDel(&netlink.Route{
		LinkIndex: router.Index,
		Dst:       &net.IPNet{IP: router.NATIP, Mask: net.CIDRMask(32, 32)},
		Scope:     netlink.SCOPE_LINK,
		Protocol:  unix.RTPROT_STATIC,
	})
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such") {
		return err
	}
	return nil
}

func writeSysctlIfExists(path, value string) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return os.WriteFile(path, []byte(value), 0644)
}

func ensureCubeRouterIptables(router *cubeRouter) error {
	if err := runIptablesEnsure("-t", "filter", "-A", "FORWARD",
		"-i", router.Name,
		"-s", router.NATIP.String()+"/32",
		"-j", "ACCEPT"); err != nil {
		return err
	}
	if err := runIptablesEnsure("-t", "filter", "-A", "FORWARD",
		"-o", router.Name,
		"-d", router.NATIP.String()+"/32",
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
		"-j", "ACCEPT"); err != nil {
		return err
	}

	for _, rule := range cubeRouterMasqueradeRules(router) {
		if err := runIptablesEnsure(rule...); err != nil {
			return err
		}
	}
	return nil
}

func deleteCubeRouterIptables(router *cubeRouter) error {
	rules := [][]string{
		{"-t", "filter", "-A", "FORWARD",
			"-i", router.Name,
			"-s", router.NATIP.String() + "/32",
			"-j", "ACCEPT"},
		{"-t", "filter", "-A", "FORWARD",
			"-o", router.Name,
			"-d", router.NATIP.String() + "/32",
			"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
			"-j", "ACCEPT"},
	}
	rules = append(rules, cubeRouterMasqueradeRules(router)...)
	for _, rule := range rules {
		if err := runIptablesDeleteIfExists(rule...); err != nil {
			return err
		}
	}
	return nil
}

func cubeRouterMasqueradeRules(router *cubeRouter) [][]string {
	base := []string{
		"-t", "nat", "-A", "POSTROUTING",
		"-s", router.NATIP.String() + "/32",
		"!", "-o", router.Name,
	}

	tcpRule := append(append([]string{}, base...), "-p", "tcp")
	tcpRule = append(tcpRule,
		"-j", "MASQUERADE",
		"--to-ports", fmt.Sprintf("%d-%d", cubeSNATPortMin, cubeSNATPortMax))

	udpRule := append(append([]string{}, base...), "-p", "udp")
	udpRule = append(udpRule, "-j", "MASQUERADE")

	icmpRule := append(append([]string{}, base...), "-p", "icmp")
	icmpRule = append(icmpRule, "-j", "MASQUERADE")

	return [][]string{tcpRule, udpRule, icmpRule}
}

func runIptablesEnsure(args ...string) error {
	checkArgs, err := iptablesArgsWithAction(args, "-C")
	if err != nil {
		return err
	}
	if err := execCommand("iptables", checkArgs...).Run(); err == nil {
		return nil
	}
	out, err := execCommand("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runIptablesDeleteIfExists(args ...string) error {
	checkArgs, err := iptablesArgsWithAction(args, "-C")
	if err != nil {
		return err
	}
	if err := execCommand("iptables", checkArgs...).Run(); err != nil {
		return nil
	}

	deleteArgs, err := iptablesArgsWithAction(args, "-D")
	if err != nil {
		return err
	}
	out, err := execCommand("iptables", deleteArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s failed: %w: %s",
			strings.Join(deleteArgs, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func iptablesArgsWithAction(args []string, action string) ([]string, error) {
	out := append([]string(nil), args...)
	for i, arg := range out {
		if arg == "-A" {
			out[i] = action
			return out, nil
		}
	}
	return nil, fmt.Errorf("iptables rule is missing -A action: %s", strings.Join(args, " "))
}

func addARPEntry(ip net.IP, mac string, cubeDevIndex int) error {
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		return err
	}
	return netlink.NeighSet(&netlink.Neigh{
		Family:       netlink.FAMILY_V4,
		IP:           ip,
		HardwareAddr: macAddr,
		LinkIndex:    cubeDevIndex,
		State:        unix.NUD_PERMANENT,
		Type:         unix.RTN_UNSPEC,
	})
}

func ensureRouteToCubeDev(cidr string, dev *cubeDev) error {
	if dev == nil || dev.Index == 0 {
		return fmt.Errorf("cube-dev is not initialized")
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse mvm cidr %q: %w", cidr, err)
	}
	filter := &netlink.Route{
		LinkIndex: dev.Index,
		Dst:       dst,
		Scope:     netlink.SCOPE_LINK,
		Protocol:  unix.RTPROT_STATIC,
	}
	routes, err := netlinkRouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
	if err != nil {
		return fmt.Errorf("list route for %s via %s: %w", dst.String(), dev.Name, err)
	}
	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == dst.String() && route.LinkIndex == dev.Index {
			return nil
		}
	}
	return netlinkRouteReplace(filter)
}

func newTap(ip net.IP, mvmMacAddr string, mtu, cubeDevIdx int) (_ *tapDevice, retErr error) {
	logger := CubeLog.WithContext(context.Background())
	name := tapName(ip.String())
	tapConfig := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name:  name,
			Flags: net.FlagUp,
		},
		Mode:   netlink.TUNTAP_MODE_TAP,
		Flags:  unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_ONE_QUEUE,
		Queues: 1,
	}
	logger.Infof("network-agent newTap begin: name=%s ip=%s mtu=%d cube_dev_idx=%d flags=0x%x queues=%d",
		name, ip.String(), mtu, cubeDevIdx, tapConfig.Flags, tapConfig.Queues)
	if err := netlink.LinkAdd(tapConfig); err != nil {
		logger.Warnf("network-agent newTap link add failed: name=%s err=%v", name, err)
		return nil, err
	}
	defer func() {
		if retErr != nil {
			logger.Warnf("network-agent newTap cleanup after failure: name=%s ifindex=%d err=%v", name, tapConfig.Index, retErr)
			_ = destroyTap(tapConfig.Index)
		}
	}()
	tap := &tapDevice{
		IP:    ip,
		Name:  name,
		Index: tapConfig.Index,
		InUse: true,
	}
	if len(tapConfig.Fds) == 0 {
		logger.Warnf("network-agent newTap missing fd: name=%s ifindex=%d", tap.Name, tap.Index)
		return nil, fmt.Errorf("tap(%s) fd is empty", tap.Name)
	}
	tap.File = tapConfig.Fds[0]
	logger.Infof("network-agent newTap link add done: name=%s ifindex=%d fd=%d", tap.Name, tap.Index, tap.File.Fd())
	size := virtioNetHdrSize
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, tap.File.Fd(), uintptr(unix.TUNSETVNETHDRSZ), uintptr(unsafe.Pointer(&size))); errno != 0 {
		logger.Warnf("network-agent newTap set vnet hdr failed: name=%s fd=%d size=%d errno=%v", tap.Name, tap.File.Fd(), size, errno)
		return nil, fmt.Errorf("set tap(%s) vnet hdr failed: %v", tap.Name, errno)
	}
	logger.Infof("network-agent newTap set vnet hdr done: name=%s fd=%d size=%d", tap.Name, tap.File.Fd(), size)
	if err := netlink.LinkSetUp(tapConfig); err != nil {
		logger.Warnf("network-agent newTap link set up failed: name=%s ifindex=%d err=%v", tap.Name, tap.Index, err)
		return nil, err
	}
	logger.Infof("network-agent newTap link set up done: name=%s ifindex=%d", tap.Name, tap.Index)
	if err := cubevs.AttachFilter(uint32(tap.Index)); err != nil {
		logger.Warnf("network-agent newTap attach filter failed: name=%s ifindex=%d err=%v", tap.Name, tap.Index, err)
		return nil, err
	}
	logger.Infof("network-agent newTap attach filter done: name=%s ifindex=%d", tap.Name, tap.Index)
	if err := netlink.LinkSetMTU(tapConfig, mtu); err != nil {
		logger.Warnf("network-agent newTap set mtu failed: name=%s ifindex=%d mtu=%d err=%v", tap.Name, tap.Index, mtu, err)
		return nil, err
	}
	logger.Infof("network-agent newTap set mtu done: name=%s ifindex=%d mtu=%d", tap.Name, tap.Index, mtu)
	if err := addARPEntry(ip, mvmMacAddr, cubeDevIdx); err != nil && err != syscall.EEXIST {
		logger.Warnf("network-agent newTap add arp failed: name=%s ifindex=%d ip=%s mac=%s cube_dev_idx=%d err=%v",
			tap.Name, tap.Index, ip.String(), mvmMacAddr, cubeDevIdx, err)
		return nil, err
	}
	logger.Infof("network-agent newTap ready: name=%s ifindex=%d ip=%s fd=%d arp_mac=%s",
		tap.Name, tap.Index, ip.String(), tap.File.Fd(), mvmMacAddr)
	return tap, nil
}

type ifReq struct {
	Name  [16]byte
	Flags uint16
}

func getTapFd(name string) (*os.File, error) {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return nil, err
	}
	tap, ok := link.(*netlink.Tuntap)
	if !ok {
		return nil, fmt.Errorf("%s is not tap", name)
	}

	fd, err := unixOpen(tunDevicePath, os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	var req ifReq
	copy(req.Name[:15], tap.Name)
	req.Flags = unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_ONE_QUEUE

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		unixClose(fd)
		return nil, fmt.Errorf("set tap(%s) TUNSETIFF failed, errno: %+v", tap.Name, errno)
	}

	size := virtioNetHdrSize
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETVNETHDRSZ), uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		unixClose(fd)
		return nil, fmt.Errorf("set tap(%s) vnet hdr failed, errno: %+v", tap.Name, errno)
	}

	offload := uintptr(unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6)
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETOFFLOAD), offload)
	if errno != 0 {
		unixClose(fd)
		return nil, fmt.Errorf("set tap(%s) TUNSETOFFLOAD failed, errno: %+v", tap.Name, errno)
	}
	// tx-tcp-mangleid-segmentation is optional, no need to bail out
	enableTXTCPMangleIDSegmentation(tap.Name)

	return os.NewFile(uintptr(fd), tunDevicePath), nil
}

// openTapFdByName opens a fresh fd for an already-existing, already-configured
// tap device identified by name, WITHOUT any netlink/rtnl lookup. It is the hot
// path used when the caller already knows the device exists and is fully set up
// (e.g. a pooled tap whose fd was closed while idle). Compared to restoreTap it
// avoids netlinkLinkByName (an rtnl read), LinkSetUp/SetMTU, the TC AttachFilter
// and the ARP entry, all of which were already applied when the tap was created.
// For recovering taps of unknown state (e.g. after a restart) use restoreTap.
func openTapFdByName(name string) (*os.File, error) {
	// Use unix.Ifreq (a properly-sized struct ifreq) rather than the local
	// 18-byte ifReq + raw unsafe.Pointer syscall: TUNSETIFF copies the full
	// sizeof(struct ifreq) (~40 bytes) from userspace, so a short struct makes
	// the kernel read past it. unix.NewIfreq also validates the name length.
	// This mirrors deletePersistentTapByName below.
	req, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	req.SetUint16(uint16(unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_ONE_QUEUE))

	fd, err := unixOpen(tunDevicePath, os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	if err := unixIoctlIfreq(fd, unix.TUNSETIFF, req); err != nil {
		unixClose(fd)
		return nil, fmt.Errorf("set tap(%s) TUNSETIFF failed: %w", name, err)
	}

	// TUNSETVNETHDRSZ takes a POINTER to an int (kernel does get_user on argp),
	// so it must use IoctlSetPointerInt, NOT IoctlSetInt (which passes the value
	// as argp directly and makes the kernel fault on a bogus address). This
	// matches newTap/restoreTap, which pass &size. Getting this wrong makes the
	// fast reopen fail and silently fall back to the slow restoreTap path.
	if err := unixIoctlSetPointerInt(fd, unix.TUNSETVNETHDRSZ, virtioNetHdrSize); err != nil {
		unixClose(fd)
		return nil, fmt.Errorf("set tap(%s) vnet hdr failed: %w", name, err)
	}

	return os.NewFile(uintptr(fd), tunDevicePath), nil
}

func restoreTap(tap *tapDevice, mtu int, mvmMacAddr string, cubeDevIdx int) (*tapDevice, error) {
	if tap == nil {
		return nil, fmt.Errorf("tap is nil")
	}
	if tap.IP == nil {
		return nil, fmt.Errorf("tap %q missing ip", tap.Name)
	}
	name := tap.Name
	if name == "" {
		name = tapName(tap.IP.String())
	}

	link, err := netlinkLinkByName(name)
	if err != nil {
		return nil, err
	}
	sysTap, ok := link.(*netlink.Tuntap)
	if !ok {
		return nil, fmt.Errorf("%s is not tap", name)
	}

	restored := &tapDevice{
		Name:         name,
		Index:        sysTap.Index,
		IP:           tap.IP.To4(),
		InUse:        link.Attrs().RawFlags&unix.IFF_LOWER_UP > 0,
		File:         tap.File,
		PortMappings: append([]PortMapping(nil), tap.PortMappings...),
	}

	// If the tap is currently in use (IFF_LOWER_UP set), another process
	// (typically sandbox spawned by cubelet) holds the original fd. Issuing
	// TUNSETIFF here would fail with EBUSY for IFF_ONE_QUEUE taps, so we skip
	// fd acquisition. Callers that actually need the fd later (e.g. fresh
	// allocation from the pool, or GetTapFile) will retry once the tap is
	// idle again.
	if restored.File == nil && !restored.InUse {
		restored.File, err = getTapFd(name)
		if err != nil {
			return nil, err
		}
	}

	if link.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(link); err != nil {
			return nil, err
		}
	}
	if sysTap.MTU != mtu {
		if err := netlink.LinkSetMTU(sysTap, mtu); err != nil {
			return nil, err
		}
	}
	if err := cubevs.AttachFilter(uint32(restored.Index)); err != nil {
		return nil, err
	}
	if err := addARPEntry(restored.IP, mvmMacAddr, cubeDevIdx); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, err
	}
	return restored, nil
}

func listCubeTaps() (map[string]*tapDevice, error) {
	links, err := netlinkLinkList()
	if err != nil {
		return nil, err
	}
	ipToTap := make(map[string]*tapDevice)
	for _, link := range links {
		tap, ok := link.(*netlink.Tuntap)
		if !ok || tap.Mode != netlink.TUNTAP_MODE_TAP {
			continue
		}
		ipStr, err := extractIP(tap.Name)
		if err != nil {
			continue
		}
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			continue
		}
		ipToTap[ip.String()] = &tapDevice{
			Name:  tap.Name,
			Index: tap.Index,
			IP:    ip,
			InUse: link.Attrs().RawFlags&unix.IFF_LOWER_UP > 0,
		}
	}
	return ipToTap, nil
}

func getTapByName(name string) (*tapDevice, error) {
	link, err := netlinkLinkByName(name)
	if err != nil {
		return nil, err
	}
	tap, ok := link.(*netlink.Tuntap)
	if !ok {
		return nil, fmt.Errorf("%s is not tap", name)
	}
	ipStr, err := extractIP(tap.Name)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid tap ip for %s", name)
	}
	return &tapDevice{
		Name:  tap.Name,
		Index: tap.Index,
		IP:    ip,
		InUse: link.Attrs().RawFlags&unix.IFF_LOWER_UP > 0,
	}, nil
}

func destroyTap(ifIdx int) error {
	link, err := netlinkLinkByIndex(ifIdx)
	if err != nil {
		return err
	}
	if tap, ok := link.(*netlink.Tuntap); ok {
		if err := deletePersistentTapByName(tap.Name); err == nil {
			return nil
		}
	}
	return netlinkLinkDel(link)
}

func isTapMissingError(err error) bool {
	if err == nil {
		return false
	}
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound)
}

func deletePersistentTapByName(name string) error {
	req, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	req.SetUint16(uint16(netlink.TUNTAP_MODE_TAP) | uint16(unix.IFF_TAP) | uint16(unix.IFF_NO_PI) | uint16(unix.IFF_VNET_HDR) | uint16(unix.IFF_ONE_QUEUE))
	fd, err := unixOpen(tunDevicePath, os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unixClose(fd)
	if err := unixIoctlIfreq(fd, unix.TUNSETIFF, req); err != nil {
		return err
	}
	if err := unixIoctlSetInt(fd, unix.TUNSETPERSIST, 0); err != nil {
		return err
	}
	return nil
}

func tapName(ip string) string {
	return tapNamePrefix + ip
}

func extractIP(name string) (string, error) {
	if len(name) <= len(tapNamePrefix) || name[:len(tapNamePrefix)] != tapNamePrefix {
		return "", fmt.Errorf("not cube tap: %s", name)
	}
	return name[len(tapNamePrefix):], nil
}
