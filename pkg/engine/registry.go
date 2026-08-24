package engine

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/edsilegx/netping/internal/printers"
	"github.com/edsilegx/netping/pkg/consts"
	"github.com/edsilegx/netping/pkg/stats"
)

// DynamicTarget represents an active background-monitored target in Trigger Mode.
type DynamicTarget struct {
	ID          string
	Target      string
	Host        string
	IP          netip.Addr
	Port        uint16
	Protocol    string
	ServiceName string
	Interval    time.Duration
	Stats       *stats.Statistics
	cancel      context.CancelFunc
	CreatedAt   time.Time
}

// DynamicTargetRegistry stores target statistics and active fleet workers.
type DynamicTargetRegistry struct {
	mu      sync.RWMutex
	targets map[string]*DynamicTarget
	stats   map[string]*stats.Statistics
}

// NewDynamicTargetRegistry constructs a new target registry.
func NewDynamicTargetRegistry() *DynamicTargetRegistry {
	return &DynamicTargetRegistry{
		targets: make(map[string]*DynamicTarget),
		stats:   make(map[string]*stats.Statistics),
	}
}

// GetOrCreateStats retrieves or registers a stats object for a target.
func (r *DynamicTargetRegistry) GetOrCreateStats(targetKey, host string, ip netip.Addr, port uint16, proto consts.Protocol, svc string) *stats.Statistics {
	r.mu.Lock()
	defer r.mu.Unlock()

	if st, ok := r.stats[targetKey]; ok {
		return st
	}

	st := stats.NewStatistics(stats.Options{
		Hostname: host,
		IP:       ip,
		Port:     port,
		Protocol: proto,
	})

	r.stats[targetKey] = st
	return st
}

// RegisterTarget registers a dynamic background target and starts its worker.
func (r *DynamicTargetRegistry) RegisterTarget(t *DynamicTarget) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.targets[t.Target]; exists {
		return fmt.Errorf("target %q is already registered", t.Target)
	}

	r.targets[t.Target] = t
	r.stats[t.Target] = t.Stats
	return nil
}

// RemoveTarget stops and deregisters a dynamic target from the fleet.
func (r *DynamicTargetRegistry) RemoveTarget(targetID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for k, t := range r.targets {
		if k == targetID || t.Target == targetID || t.Host == targetID || t.ID == targetID {
			if t.cancel != nil {
				t.cancel()
			}
			delete(r.targets, k)
			delete(r.stats, k)
			return true
		}
	}

	return false
}

// GetFleetTargets returns a slice of FleetTarget snapshots for web metrics and API queries.
func (r *DynamicTargetRegistry) GetFleetTargets() []printers.FleetTarget {
	r.mu.RLock()
	defer r.mu.RUnlock()

	fleet := make([]printers.FleetTarget, 0, len(r.stats))

	// Include registered background targets
	for _, t := range r.targets {
		fleet = append(fleet, printers.FleetTarget{
			Target:      t.Target,
			Host:        t.Host,
			Port:        t.Port,
			Protocol:    t.Protocol,
			ServiceName: t.ServiceName,
			Stats:       t.Stats,
		})
	}

	// Include ad-hoc triggered stats that aren't background targets
	for key, st := range r.stats {
		if _, exists := r.targets[key]; !exists {
			fleet = append(fleet, printers.FleetTarget{
				Target:   key,
				Host:     st.Hostname,
				Port:     st.Port,
				Protocol: string(st.Protocol),
				Stats:    st,
			})
		}
	}

	return fleet
}

// TargetCount returns the total number of tracked targets.
func (r *DynamicTargetRegistry) TargetCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.stats)
}

// Reset clears all in-memory stats.
func (r *DynamicTargetRegistry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, st := range r.stats {
		st.Reset()
	}
}
