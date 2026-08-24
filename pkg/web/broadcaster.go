package web

import (
	"sync"
	"time"
)

type ProbeEvent struct {
	RawTime        time.Time `json:"-"`
	Timestamp      string    `json:"timestamp"`
	Sequence       uint      `json:"sequence"`
	Success        bool    `json:"success"`
	RTT            float64 `json:"rtt"`
	Target         string  `json:"target"`
	Hostname       string  `json:"hostname"`
	IP             string  `json:"ip"`
	Port           uint16  `json:"port"`
	Protocol       string  `json:"protocol"`
	Diagnostics    string  `json:"diagnostics,omitempty"`
	Error          string  `json:"error,omitempty"`
	DNSTime        float64 `json:"dns_time,omitempty"`
	TCPTime        float64 `json:"tcp_time,omitempty"`
	TLSTime        float64 `json:"tls_time,omitempty"`
	HTTPStatus     int     `json:"http_status,omitempty"`
	TotalSent      uint    `json:"total_sent"`
	TotalSuccess   uint    `json:"total_success"`
	TotalFailed    uint    `json:"total_failed"`
	PacketLoss     float64 `json:"packet_loss"`
	AvgRTT         float64 `json:"avg_rtt"`
	MinRTT         float64 `json:"min_rtt"`
	MaxRTT         float64 `json:"max_rtt"`
	P95RTT         float64 `json:"p95_rtt"`
	P99RTT         float64 `json:"p99_rtt"`
	Jitter         float64 `json:"jitter"`
	UptimeDuration string  `json:"uptime_duration"`
}

// Broadcaster manages real-time Server-Sent Events subscriber channels and probe history.
type Broadcaster struct {
	mu          sync.RWMutex
	subscribers map[chan ProbeEvent]struct{}
	history     []ProbeEvent
	maxHistory  int
}

// NewBroadcaster constructs a new event broadcaster with a 1,000,000 event capacity.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[chan ProbeEvent]struct{}),
		history:     make([]ProbeEvent, 0, 500),
		maxHistory:  1000000,
	}
}

// SetMaxHistory sets the maximum in-memory event retention limit (capped between 100 and 5,000,000).
func (b *Broadcaster) SetMaxHistory(limit int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit <= 0 {
		limit = 1000000
	}
	if limit > 5000000 {
		limit = 5000000
	}
	b.maxHistory = limit
	if len(b.history) > b.maxHistory {
		b.history = b.history[len(b.history)-b.maxHistory:]
	}
}

// GetMaxHistory returns the configured maximum in-memory event retention limit.
func (b *Broadcaster) GetMaxHistory() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.maxHistory <= 0 {
		return 1000000
	}
	return b.maxHistory
}

// GetHistoryCount returns the current count of stored historical probe events.
func (b *Broadcaster) GetHistoryCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.history)
}

// Subscribe registers a new subscriber channel.
func (b *Broadcaster) Subscribe() chan ProbeEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan ProbeEvent, 32)
	b.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes and closes a subscriber channel.
func (b *Broadcaster) Unsubscribe(ch chan ProbeEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

// GetHistory returns a copy of all accumulated probe events.
func (b *Broadcaster) GetHistory() []ProbeEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	res := make([]ProbeEvent, len(b.history))
	copy(res, b.history)
	return res
}

// GetProbes retrieves a paginated and optionally filtered window of probe events from history (newest first).
func (b *Broadcaster) GetProbes(target string, status string, limit int, offset int) ([]ProbeEvent, int) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	filtered := make([]ProbeEvent, 0, min(limit, len(b.history)))
	totalMatching := 0

	for i := len(b.history) - 1; i >= 0; i-- {
		ev := b.history[i]
		if target != "" && ev.Target != target && ev.Hostname != target && ev.IP != target {
			continue
		}
		if status == "success" && !ev.Success {
			continue
		}
		if status == "failed" && ev.Success {
			continue
		}
		totalMatching++
		if totalMatching > offset && len(filtered) < limit {
			filtered = append(filtered, ev)
		}
	}

	return filtered, totalMatching
}

// Broadcast sends a ProbeEvent to all active subscribers and stores it in history.
func (b *Broadcaster) Broadcast(event ProbeEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if event.RawTime.IsZero() {
		event.RawTime = time.Now()
	}
	if event.Timestamp == "" {
		event.Timestamp = event.RawTime.Format("15:04:05.000")
	}

	b.history = append(b.history, event)
	maxCap := b.maxHistory
	if maxCap <= 0 {
		maxCap = 1000000
	}
	if len(b.history) > maxCap {
		b.history = b.history[len(b.history)-maxCap:]
	}

	for ch := range b.subscribers {
		select {
		case ch <- event:
		default:
			// Non-blocking drop if client buffer is full
		}
	}
}

// ClearHistory resets the broadcaster probe history.
func (b *Broadcaster) ClearHistory() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.history = make([]ProbeEvent, 0, 500)
}
