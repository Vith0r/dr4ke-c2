package utils

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type ResourceManager struct {
	maxMemoryMB     int64
	maxThreads      int64
	currentThreads  int64
	memoryThreshold float64 
	cleanupInterval time.Duration
	stopChan        chan struct{}
	mu              sync.RWMutex
}

func NewResourceManager(maxMemoryMB, maxThreads int64, memoryThreshold float64) *ResourceManager {
	if maxMemoryMB <= 0 {
		maxMemoryMB = 1024 
	}
	if maxThreads <= 0 {
		maxThreads = int64(runtime.NumCPU() * 100) 
	}
	if memoryThreshold <= 0 || memoryThreshold >= 1 {
		memoryThreshold = 0.8 
	}

	rm := &ResourceManager{
		maxMemoryMB:     maxMemoryMB,
		maxThreads:      maxThreads,
		memoryThreshold: memoryThreshold,
		cleanupInterval: 30 * time.Second,
		stopChan:        make(chan struct{}),
	}

	go rm.startMonitoring()
	return rm
}

func (rm *ResourceManager) AcquireThread() error {
	current := atomic.AddInt64(&rm.currentThreads, 1)
	if current > rm.maxThreads {
		atomic.AddInt64(&rm.currentThreads, -1)
		return fmt.Errorf("thread limit exceeded: %d/%d", current-1, rm.maxThreads)
	}
	return nil
}

func (rm *ResourceManager) ReleaseThread() {
	atomic.AddInt64(&rm.currentThreads, -1)
}

func (rm *ResourceManager) CheckMemoryUsage() error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	usedMB := float64(m.Alloc) / 1024 / 1024
	thresholdMB := float64(rm.maxMemoryMB) * rm.memoryThreshold

	if usedMB > thresholdMB {
		return fmt.Errorf("memory usage exceeded threshold: %.2fMB/%.2fMB", usedMB, thresholdMB)
	}
	return nil
}

func (rm *ResourceManager) ForceGC() {
	runtime.GC()
}

func (rm *ResourceManager) GetMemoryStats() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf(
		"Alloc: %s, TotalAlloc: %s, Sys: %s, NumGC: %d",
		FormatBytes(int64(m.Alloc)),
		FormatBytes(int64(m.TotalAlloc)),
		FormatBytes(int64(m.Sys)),
		m.NumGC,
	)
}

func (rm *ResourceManager) GetThreadStats() string {
	return fmt.Sprintf(
		"Current: %d, Max: %d, CPU: %d",
		atomic.LoadInt64(&rm.currentThreads),
		rm.maxThreads,
		runtime.NumCPU(),
	)
}

func (rm *ResourceManager) startMonitoring() {
	ticker := time.NewTicker(rm.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.monitorResources()
		case <-rm.stopChan:
			return
		}
	}
}

func (rm *ResourceManager) monitorResources() {
	defer RecoverWithLog()

	if err := rm.CheckMemoryUsage(); err != nil {
		LogOutput("[WARNING] Memory threshold exceeded: %v", err)
		rm.ForceGC()
	}

	LogOutput("[INFO] Resource stats - Memory: %s, Threads: %s",
		rm.GetMemoryStats(),
		rm.GetThreadStats(),
	)
}

func (rm *ResourceManager) Close() {
	close(rm.stopChan)
}

func (rm *ResourceManager) WithThreadLimit(fn func() error) error {
	if err := rm.AcquireThread(); err != nil {
		return err
	}
	defer rm.ReleaseThread()
	return fn()
}

func (rm *ResourceManager) WithMemoryCheck(fn func() error) error {
	if err := rm.CheckMemoryUsage(); err != nil {
		return err
	}
	return fn()
}
