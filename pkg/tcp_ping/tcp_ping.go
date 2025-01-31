package tcp_ping

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/syepes/network_exporter/pkg/common"
	"golang.org/x/net/ipv4"
)

// pkg/icmp/icmp.go
// https://hechao.li/2018/09/27/How-Is-Ping-Deduplexed/
const (
	protocolICMP     = 1  // Internet Control Message
	protocolIPv6ICMP = 58 // ICMP for IPv6
)

// tcpPing performs a TCP ping to the destination address with a specific TTL
func TCPPing(destAddr string, srcAddr string, port int, pid int, ttl int, timeout time.Duration, ipv6_proto bool) (common.IcmpReturn, error) {
	var hop common.IcmpReturn

	dstIp := net.ParseIP(destAddr)
	if dstIp == nil {
		return hop, fmt.Errorf("destination ip: %v is invalid", destAddr)
	}

	ipAddr := net.IPAddr{IP: dstIp}

	if srcAddr != "" {
		srcIp := net.ParseIP(srcAddr)
		if srcIp == nil {
			return hop, fmt.Errorf("source ip: %v is invalid, target: %v", srcAddr, destAddr)
		}

		if p4 := dstIp.To4(); len(p4) == net.IPv4len {
			return tcpPing4(srcAddr, &ipAddr, ttl, pid, timeout, seq)
		}
		if ipv6_proto {
			return tcpPing6(srcAddr, &ipAddr, ttl, pid, timeout, seq)
		} else {
			return hop, nil
		}
	}

	if p4 := dstIp.To4(); len(p4) == net.IPv4len {
		return tcpPingv4("0.0.0.0", &ipAddr, ttl, pid, timeout, seq)
	}
	if ipv6_proto {
		return tcpPingv6("::", &ipAddr, ttl, pid, timeout, seq)
	} else {
		return hop, nil
	}
}

func tcpPingv4(localAddr string, dst net.Addr, ttl int, pid int, timeout time.Duration, seq int) (hop common.IcmpReturn, err error) {
	hop.Success = false
	start := time.Now()
	// c, err := icmp.ListenPacket("ip4:icmp", localAddr)
	var raw_pacekt ipv4.RawConn
	c, err := ipv4.NewRawConn(raw_pacekt.IPConn)
	if err != nil {
		return hop, err
	}
	defer c.Close()

	err = c.SetControlMessage(ipv4.FlagTTL, true)
	if err != nil {
		return hop, err
	}

	// if err = c.IPv4PacketConn().SetTTL(ttl); err != nil {
	if err = c.SetTTL(ttl); err != nil {
		return hop, err
	}

	if err = c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return hop, err
	}

	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(seq))

}
