package web

import (
	"sync"
	"time"
)

type ProbeEvent struct {
	Timestamp      string  `json:"timestamp"`
	Sequence       uint    `json:"sequence"`
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

// Broadcaster manages real-time Server-Sent Events subscriber channels.
type Broadcaster struct {
	mu          sync.RWMutex
	subscribers map[chan ProbeEvent]struct{}
}

// NewBroadcaster constructs a new event broadcaster.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[chan ProbeEvent]struct{}),
	}
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

// Broadcast sends a ProbeEvent to all active subscribers without blocking.
func (b *Broadcaster) Broadcast(event ProbeEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if event.Timestamp == "" {
		event.Timestamp = time.Now().Format("15:04:05.000")
	}

	for ch := range b.subscribers {
		select {
		case ch <- event:
		default:
			// Non-blocking drop if client buffer is full
		}
	}
}
