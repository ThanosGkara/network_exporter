package target

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/syepes/network_exporter/pkg/common"
	"github.com/syepes/network_exporter/pkg/mtr"
)

// MTR Object
type MTR struct {
	logger   log.Logger
	icmpID   *common.IcmpID
	name     string
	host     string
	srcAddr  string
	interval time.Duration
	timeout  time.Duration
	maxHops  int
	count    int
	mtrtype  common.MtrType
	ipv6     bool
	labels   map[string]string
	result   *mtr.MtrResult
	stop     chan struct{}
	wg       sync.WaitGroup
	sync.RWMutex
}

// NewMTR starts a new monitoring goroutine
func NewMTR(logger log.Logger, icmpID *common.IcmpID, startupDelay time.Duration, name string, host string, srcAddr string, interval time.Duration, timeout time.Duration, maxHops int, count int, mtrtype common.MtrType, labels map[string]string, ipv6 bool) (*MTR, error) {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	t := &MTR{
		logger:   logger,
		icmpID:   icmpID,
		name:     name,
		host:     host,
		srcAddr:  srcAddr,
		interval: interval,
		timeout:  timeout,
		maxHops:  maxHops,
		count:    count,
		mtrtype:  mtrtype, // initialize with MTR as default
		ipv6:     ipv6,
		labels:   labels,
		stop:     make(chan struct{}),
		result:   &mtr.MtrResult{HopSummaryMap: map[string]*common.IcmpSummary{}},
	}
	t.wg.Add(1)
	go t.run(startupDelay)
	return t, nil
}

func (t *MTR) run(startupDelay time.Duration) {
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
				t.mtr()
				<-waitChan
			}()
		}
	}
}

// Stop gracefully stops the monitoring
func (t *MTR) Stop() {
	close(t.stop)
	t.wg.Wait()
}

func (t *MTR) mtr() {
	icmpID := int(t.icmpID.Get())
	data, err := mtr.Mtr(t.host, t.srcAddr, t.maxHops, t.count, t.timeout, icmpID, t.mtrtype, t.ipv6)
	if err != nil {
		level.Error(t.logger).Log("type", "MTR", "func", "mtr", "msg", fmt.Sprintf("%s", err))
	}

	t.Lock()
	defer t.Unlock()
	summaryMap := t.result.HopSummaryMap
	t.result = data
	for _, hop := range data.Hops {
		summary := summaryMap[strconv.Itoa(hop.TTL)+"_"+hop.AddressTo]
		if summary == nil {
			summary = &common.IcmpSummary{}
			summaryMap[strconv.Itoa(hop.TTL)+"_"+hop.AddressTo] = summary
		}
		summary.AddressFrom = hop.AddressFrom
		summary.AddressTo = hop.AddressTo
		summary.Snt += hop.Snt
		summary.SntTime += hop.SumTime
		summary.SntFail += hop.SntFail
	}
	t.result.HopSummaryMap = summaryMap

	bytes, err2 := json.Marshal(t.result)
	if err2 != nil {
		level.Error(t.logger).Log("type", "MTR", "func", "mtr", "msg", fmt.Sprintf("%s", err2))
	}
	level.Debug(t.logger).Log("type", "MTR", "func", "mtr", "msg", bytes)
}

// Compute returns the results of the MTR metrics
func (t *MTR) Compute() *mtr.MtrResult {
	t.RLock()
	defer t.RUnlock()

	if t.result == nil {
		return nil
	}
	return t.result
}

// Name returns name
func (t *MTR) Name() string {
	t.RLock()
	defer t.RUnlock()
	return t.name
}

// Host returns host
func (t *MTR) Host() string {
	t.RLock()
	defer t.RUnlock()
	return t.host
}

// Labels returns labels
func (t *MTR) Labels() map[string]string {
	t.RLock()
	defer t.RUnlock()
	return t.labels
}
