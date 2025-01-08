package tcp_ping

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/syepes/network_exporter/pkg/common"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// pkg/icmp/icmp.go
// https://hechao.li/2018/09/27/How-Is-Ping-Deduplexed/
const (
	protocolICMP     = 1  // Internet Control Message
	protocolIPv6ICMP = 58 // ICMP for IPv6
)

// tcpPing performs a TCP ping to the destination address with a specific TTL
func TCPPing(destAddr string, srcAddr string, port int, ttl int, timeout time.Duration, ipv6 bool) (common.IcmpReturn, error) {
	var hop common.IcmpReturn
	dstIp := net.ParseIP(destAddr)
	if dstIp == nil {
		return hop, fmt.Errorf("destination ip: %v is invalid", destAddr)
	}

	ipAddr := net.JoinHostPort(destAddr, fmt.Sprintf("%d", port))

	// Create a raw socket for TCP
	var ipver int
	if ipv6 {
		ipver = syscall.AF_INET6
	} else {
		ipver = syscall.AF_INET
	}

	fd, err := syscall.Socket(ipver, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return hop, fmt.Errorf("failed to create raw socket: %v", err)
	}
	defer syscall.Close(fd)

	// Set the TTL value for the socket
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl); err != nil {
		return hop, fmt.Errorf("failed to set TTL: %v", err)
	}

	// Enable receiving ICMP error messages
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_RECVERR, 1); err != nil {
		return hop, fmt.Errorf("failed to set IP_RECVERR: %v", err)
	}

	// Set the timeout for the socket
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return hop, fmt.Errorf("failed to set timeout: %v", err)
	}

	// Send a TCP SYN packet
	start := time.Now()
	conn, err := net.DialTimeout("tcp", ipAddr, timeout)
	elapsed := time.Since(start)

	if err != nil {
		hop.Success = false
		hop.Elapsed = elapsed
		return hop, err
	}
	defer conn.Close()

	// Listen for ICMP responses
	icmpResponse, err := listenForICMP(fd, timeout, ipv6)
	if err != nil {
		hop.Success = false
		hop.Elapsed = elapsed
		return hop, err
	}

	hop.Success = true
	hop.Elapsed = elapsed
	hop.Addr = icmpResponse
	return hop, nil
}

// listenForICMP listens for ICMP responses
func listenForICMP(fd int, timeout time.Duration, ipv6 bool) (string, error) {
	buf := make([]byte, 1500)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return "", err
		}

		var msg *icmp.Message
		if ipv6 {
			msg, err = icmp.ParseMessage(protocolIPv6ICMP, buf[:n])
		} else {
			msg, err = icmp.ParseMessage(protocolICMP, buf[:n])
		}
		if err != nil {
			return "", err
		}

		switch msg.Type {
		case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
			return "Time Exceeded", nil
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			return "Echo Reply", nil
		}
	}
}
