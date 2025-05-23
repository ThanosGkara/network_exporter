package tcp_ping

import (
	"fmt"
	"net"
	"time"

	"github.com/syepes/network_exporter/pkg/common"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type ICMPResult struct {
	Reachable bool
	Peer      net.Addr
}

func TCPPing(destAddr string, srcAddr string, port int, pid int, ttl int, timeout time.Duration, ipv6_proto bool) (common.IcmpReturn, error) {
	// Resolve the host to both IPv4 and IPv6 addresses
	ipAddrs, err := net.LookupIP(host)
	if err != nil {
		return false, nil, fmt.Errorf("resolve IP: %w", err)
	}

	var ipAddr net.IP
	for _, addr := range ipAddrs {
		if addr.To4() != nil || addr.To16() != nil {
			ipAddr = addr
			break
		}
	}
	if ipAddr == nil {
		return false, nil, fmt.Errorf("no valid IP address found for host: %s", host)
	}
	fmt.Printf("Resolved IP: %s\n", ipAddr)

	// Determine if the IP is IPv4 or IPv6
	var network, proto string
	if ipAddr.To4() != nil {
		network = "ip4:icmp"
		proto = "ipv4"
	} else {
		network = "ip6:ipv6-icmp"
		proto = "ipv6"
	}

	// Create an ICMP listener
	c, err := icmp.ListenPacket(network, "::")
	if err != nil {
		return false, nil, fmt.Errorf("icmp.ListenPacket: %w", err)
	}
	defer c.Close()

	// Attempt TCP connection
	target := fmt.Sprintf("[%s]:%d", ipAddr, port) // Use brackets for IPv6 addresses
	fmt.Printf("Attempting TCP connection to %s...\n", target)
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err == nil {
		// TCP connection succeeded
		fmt.Printf("TCP connection to %s succeeded\n", target)
		conn.Close()
		return true, nil, nil
	}

	// TCP connection failed
	fmt.Printf("TCP connection failed: %v\n", err)
	fmt.Println("Waiting for ICMP messages...")

	// Channel to communicate ICMP results
	icmpResult := make(chan ICMPResult, 1)
	errChan := make(chan error, 1)

	// Start a goroutine to listen for ICMP messages
	go func() {
		startTime := time.Now()
		for {
			// Check if the timeout has been reached
			if time.Since(startTime) > timeout {
				fmt.Println("ICMP listener stopped: timeout reached")
				return
			}

			// Set a read deadline to avoid blocking indefinitely
			if err := c.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
				errChan <- fmt.Errorf("SetReadDeadline error: %w", err)
				return
			}

			buf := make([]byte, 1500)
			n, peer, err := c.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout, continue the loop
					continue
				}
				if err.Error() == "use of closed network connection" {
					// Normal exit when the connection is closed
					fmt.Println("ICMP listener stopped: connection closed")
					return
				}
				errChan <- fmt.Errorf("ICMP read error: %w", err)
				return
			}

			// Log all ICMP messages for debugging
			fmt.Printf("Received ICMP message from %s\n", peer)

			// Only process ICMP messages from the target host
			if peer.String() != ipAddr.String() {
				fmt.Printf("Ignoring ICMP message from non-target peer: %s\n", peer)
				continue
			}

			var msg *icmp.Message
			if proto == "ipv4" {
				msg, err = icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), buf[:n])
			} else {
				msg, err = icmp.ParseMessage(ipv6.ICMPTypeEchoRequest.Protocol(), buf[:n])
			}
			if err != nil {
				fmt.Printf("Failed to parse ICMP message: %v\n", err)
				continue
			}

			// Check for ICMP messages indicating unreachability or other issues
			switch msg.Type {
			case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
				fmt.Printf("Received ICMP message: %v from %s\n", msg, peer)
				icmpResult <- ICMPResult{Reachable: false, Peer: peer}
				return
			default:
				fmt.Printf("Received ICMP message: %v from %s\n", msg, peer)
			}
		}
	}()

	// Wait for ICMP results or timeout
	select {
	case result := <-icmpResult:
		return result.Reachable, result.Peer, nil
	case icmpErr := <-errChan:
		return false, nil, icmpErr
	case <-time.After(timeout):
		// No ICMP message received, assume host is unreachable
		return false, nil, nil
	}
}
