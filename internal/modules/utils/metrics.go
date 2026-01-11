package utils

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds application metrics
type Metrics struct {
	mu sync.RWMutex

	// Scan metrics
	ActiveScans    int32
	CompletedScans int64
	FailedScans    int64
	TotalScans     int64

	// Performance metrics
	StartTime      time.Time
	LastScanTime   time.Time

	// Error metrics
	TotalErrors    int64
	DiscordErrors  int64
	ScanErrors     int64

	// File metrics
	FilesSent      int64
	FilesFailedSend int64
}

var (
	// GlobalMetrics is the global metrics instance
	GlobalMetrics *Metrics
	metricsOnce   sync.Once
)

// InitMetrics initializes the global metrics
func InitMetrics() *Metrics {
	metricsOnce.Do(func() {
		GlobalMetrics = &Metrics{
			StartTime: time.Now(),
		}
	})
	return GlobalMetrics
}

// GetMetrics returns the global metrics instance
func GetMetrics() *Metrics {
	if GlobalMetrics == nil {
		return InitMetrics()
	}
	return GlobalMetrics
}

// Scan tracking
func (m *Metrics) IncrementActiveScans() {
	atomic.AddInt32(&m.ActiveScans, 1)
	atomic.AddInt64(&m.TotalScans, 1)
}

func (m *Metrics) DecrementActiveScans() {
	atomic.AddInt32(&m.ActiveScans, -1)
}

func (m *Metrics) IncrementCompletedScans() {
	atomic.AddInt64(&m.CompletedScans, 1)
	m.mu.Lock()
	m.LastScanTime = time.Now()
	m.mu.Unlock()
}

func (m *Metrics) IncrementFailedScans() {
	atomic.AddInt64(&m.FailedScans, 1)
}

// Error tracking
func (m *Metrics) IncrementErrors() {
	atomic.AddInt64(&m.TotalErrors, 1)
}

func (m *Metrics) IncrementDiscordErrors() {
	atomic.AddInt64(&m.DiscordErrors, 1)
	atomic.AddInt64(&m.TotalErrors, 1)
}

func (m *Metrics) IncrementScanErrors() {
	atomic.AddInt64(&m.ScanErrors, 1)
	atomic.AddInt64(&m.TotalErrors, 1)
}

// File tracking
func (m *Metrics) IncrementFilesSent() {
	atomic.AddInt64(&m.FilesSent, 1)
}

func (m *Metrics) IncrementFilesFailedSend() {
	atomic.AddInt64(&m.FilesFailedSend, 1)
}

// GetSnapshot returns a snapshot of current metrics
func (m *Metrics) GetSnapshot() MetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return MetricsSnapshot{
		ActiveScans:     atomic.LoadInt32(&m.ActiveScans),
		CompletedScans:  atomic.LoadInt64(&m.CompletedScans),
		FailedScans:     atomic.LoadInt64(&m.FailedScans),
		TotalScans:      atomic.LoadInt64(&m.TotalScans),
		TotalErrors:     atomic.LoadInt64(&m.TotalErrors),
		DiscordErrors:   atomic.LoadInt64(&m.DiscordErrors),
		ScanErrors:      atomic.LoadInt64(&m.ScanErrors),
		FilesSent:       atomic.LoadInt64(&m.FilesSent),
		FilesFailedSend: atomic.LoadInt64(&m.FilesFailedSend),
		Uptime:          time.Since(m.StartTime).Seconds(),
		LastScanTime:    m.LastScanTime,
	}
}

// MetricsSnapshot is a point-in-time snapshot of metrics
type MetricsSnapshot struct {
	ActiveScans     int32     `json:"active_scans"`
	CompletedScans  int64     `json:"completed_scans"`
	FailedScans     int64     `json:"failed_scans"`
	TotalScans      int64     `json:"total_scans"`
	TotalErrors     int64     `json:"total_errors"`
	DiscordErrors   int64     `json:"discord_errors"`
	ScanErrors      int64     `json:"scan_errors"`
	FilesSent       int64     `json:"files_sent"`
	FilesFailedSend int64     `json:"files_failed_send"`
	Uptime          float64   `json:"uptime_seconds"`
	LastScanTime    time.Time `json:"last_scan_time"`
}
