package target

import (
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/syepes/network_exporter/pkg/tcp"
)

// TCPPort Object
type TCPPort struct {
	logger    *slog.Logger
	name      string
	host      string
	ip        string
	srcAddr   string
	port      string
	interval  time.Duration
	timeout   time.Duration
	labels    map[string]string
	result    *tcp.TCPPortReturn
	stop      chan struct{}
	wg        sync.WaitGroup
	sync.RWMutex
}

// NewTCPPort starts a new monitoring goroutine
func NewTCPPort(logger *slog.Logger, startupDelay time.Duration, name string, host string, ip string, srcAddr string, port string, interval time.Duration, timeout time.Duration, labels map[string]string) (*TCPPort, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	t := &TCPPort{
		logger:    logger,
		name:      name,
		host:      host,
		ip:        ip,
		srcAddr:   srcAddr,
		port:      port,
		interval:  interval,
		timeout:   timeout,
		labels:    labels,
		stop:      make(chan struct{}),
	}
	t.wg.Add(1)
	go t.run(startupDelay)
	return t, nil
}

func (t *TCPPort) run(startupDelay time.Duration) {
	if startupDelay > 0 {
		select {
		case <-time.After(startupDelay):
		case <-t.stop:
		}
	}

	waitChan := make(chan struct{}, MaxConcurrentJobs)
	tick := time.NewTicker(t.interval)
	for {
		select {
		case <-t.stop:
			tick.Stop()
			t.wg.Done()
			return
		case <-tick.C:
			waitChan <- struct{}{}
			go func() {
				t.portCheck()
				<-waitChan
			}()
		}
	}
}

// Stop gracefully stops the monitoring
func (t *TCPPort) Stop() {
	close(t.stop)
	t.wg.Wait()
}

func (t *TCPPort) portCheck() {
	data, err := tcp.Port(t.host, t.ip, t.srcAddr, t.port, t.timeout)
	if err != nil {
		t.logger.Error("TCP Port check failed", "type", "TCP", "func", "port", "err", err)
	}

	bytes, err2 := json.Marshal(data)
	if err2 != nil {
		t.logger.Error("Failed to marshal result", "type", "TCP", "func", "port", "err", err2)
	}
	t.logger.Debug("TCP Port result", "type", "TCP", "func", "port", "result", string(bytes))

	t.Lock()
	defer t.Unlock()
	t.result = data
}

// Compute returns the results of the TCP metrics
func (t *TCPPort) Compute() *tcp.TCPPortReturn {
	t.RLock()
	defer t.RUnlock()

	if t.result == nil {
		return nil
	}
	return t.result
}

// Name returns name
func (t *TCPPort) Name() string {
	t.RLock()
	defer t.RUnlock()
	return t.name
}

// Host returns host
func (t *TCPPort) Host() string {
	t.RLock()
	defer t.RUnlock()
	return t.host
}

// Ip returns ip
func (t *TCPPort) Ip() string {
	t.RLock()
	defer t.RUnlock()
	return t.ip
}

// Labels returns labels
func (t *TCPPort) Labels() map[string]string {
	t.RLock()
	defer t.RUnlock()
	return t.labels
}
