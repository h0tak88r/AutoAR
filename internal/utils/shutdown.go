package utils

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// ShutdownManager handles graceful shutdown
type ShutdownManager struct {
	mu              sync.RWMutex
	shutdownFlag    bool
	activeScans     int
	shutdownTimeout time.Duration
	logger          *logrus.Logger
	onShutdown      []func() error
}

var (
	// GlobalShutdownManager is the global shutdown manager
	GlobalShutdownManager *ShutdownManager
	shutdownOnce          sync.Once
)

// InitShutdownManager initializes the shutdown manager
func InitShutdownManager(timeout time.Duration, logger *logrus.Logger) *ShutdownManager {
	shutdownOnce.Do(func() {
		if timeout == 0 {
			timeout = 5 * time.Minute // Default 5 minutes
		}
		GlobalShutdownManager = &ShutdownManager{
			shutdownTimeout: timeout,
			logger:          logger,
			onShutdown:      make([]func() error, 0),
		}
	})
	return GlobalShutdownManager
}

// GetShutdownManager returns the global shutdown manager
func GetShutdownManager() *ShutdownManager {
	if GlobalShutdownManager == nil {
		return InitShutdownManager(5*time.Minute, GetLogger())
	}
	return GlobalShutdownManager
}

// RegisterShutdownHook registers a function to be called on shutdown
func (sm *ShutdownManager) RegisterShutdownHook(fn func() error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onShutdown = append(sm.onShutdown, fn)
}

// IsShuttingDown returns true if shutdown has been initiated
func (sm *ShutdownManager) IsShuttingDown() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.shutdownFlag
}

// IncrementActiveScans increments the active scan counter
func (sm *ShutdownManager) IncrementActiveScans() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.activeScans++
}

// DecrementActiveScans decrements the active scan counter
func (sm *ShutdownManager) DecrementActiveScans() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.activeScans > 0 {
		sm.activeScans--
	}
}

// GetActiveScans returns the number of active scans
func (sm *ShutdownManager) GetActiveScans() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.activeScans
}

// Shutdown initiates graceful shutdown
func (sm *ShutdownManager) Shutdown(ctx context.Context) error {
	sm.mu.Lock()
	sm.shutdownFlag = true
	activeScans := sm.activeScans
	sm.mu.Unlock()

	if sm.logger != nil {
		sm.logger.WithFields(logrus.Fields{
			"active_scans": activeScans,
			"timeout":      sm.shutdownTimeout,
		}).Info("Initiating graceful shutdown")
	}

	// Wait for active scans to complete or timeout
	if activeScans > 0 {
		if sm.logger != nil {
			sm.logger.Infof("Waiting for %d active scan(s) to complete...", activeScans)
		}

		shutdownCtx, cancel := context.WithTimeout(ctx, sm.shutdownTimeout)
		defer cancel()

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-shutdownCtx.Done():
				remaining := sm.GetActiveScans()
				if sm.logger != nil {
					sm.logger.Warnf("Shutdown timeout reached, %d scan(s) still active", remaining)
				}
				goto cleanup
			case <-ticker.C:
				if sm.GetActiveScans() == 0 {
					if sm.logger != nil {
						sm.logger.Info("All active scans completed")
					}
					goto cleanup
				}
			}
		}
	}

cleanup:
	// Execute shutdown hooks
	sm.mu.RLock()
	hooks := sm.onShutdown
	sm.mu.RUnlock()

	for _, hook := range hooks {
		if err := hook(); err != nil {
			if sm.logger != nil {
				sm.logger.WithError(err).Error("Shutdown hook failed")
			}
		}
	}

	if sm.logger != nil {
		sm.logger.Info("Graceful shutdown complete")
	}

	return nil
}

// WaitForShutdownSignal blocks until SIGTERM or SIGINT is received
func (sm *ShutdownManager) WaitForShutdownSignal() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigChan
	if sm.logger != nil {
		sm.logger.WithField("signal", sig.String()).Info("Received shutdown signal")
	}

	// Initiate shutdown
	ctx := context.Background()
	if err := sm.Shutdown(ctx); err != nil {
		if sm.logger != nil {
			sm.logger.WithError(err).Error("Shutdown failed")
		}
		os.Exit(1)
	}

	os.Exit(0)
}
