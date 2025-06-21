package utils

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type ServerMetrics struct {
	TotalRAM              uint64    `json:"totalRAM"`
	AvailableRAM          uint64    `json:"availableRAM"`
	RAMUsage              float64   `json:"ramUsage"`
	CPUUsage              float64   `json:"cpuUsage"`
	CPUCores              int       `json:"cpuCores"`
	DiskTotal             uint64    `json:"diskTotal"`
	DiskFree              uint64    `json:"diskFree"`
	DiskUsage             float64   `json:"diskUsage"`
	ConnectedClients      int       `json:"connectedClients"`
	ActiveClients         int       `json:"activeClients"`
	IdleClients           int       `json:"idleClients"`
	DeadClients           int       `json:"deadClients"`
	ClientLimit           int       `json:"clientLimit"`
	ClientCapacityUsed    float64   `json:"clientCapacityUsed"`
	DatabaseType          string    `json:"databaseType"`
	DatabaseWriteOps      int64     `json:"databaseWriteOps"`
	DatabaseReadOps       int64     `json:"databaseReadOps"`
	WriteQueueLength      int       `json:"writeQueueLength"`
	AvgResponseTime       float64   `json:"avgResponseTime"`
	RequestsPerSecond     float64   `json:"requestsPerSecond"`
	PeakRequestsPerSecond float64   `json:"peakRequestsPerSecond"`
	BatchSize             int       `json:"batchSize"`
	QueueSize             int       `json:"queueSize"`
	FlushInterval         int       `json:"flushInterval"`
	StartTime             time.Time `json:"startTime"`
	Uptime                string    `json:"uptime"`
	GoRoutines            int       `json:"goRoutines"`
	HeapAlloc             uint64    `json:"heapAlloc"`
	HeapIdle              uint64    `json:"heapIdle"`
	HeapInuse             uint64    `json:"heapInuse"`
	HeapObjects           uint64    `json:"heapObjects"`
	GCPause               float64   `json:"gcPause"`
}

var (
	metrics          *ServerMetrics
	metricsMutex     sync.RWMutex
	startTime        time.Time
	databaseWriteOps int64
	databaseReadOps  int64
	requestTimes     []time.Duration
	requestTimeMux   sync.Mutex
	batchSize        int
	queueSize        int
	flushInterval    int
	clientLimit      int
	databaseType     string
)

func InitMonitoring(dbType string, cLimit, bSize, qSize, fInterval int) {
	startTime = time.Now()
	databaseType = dbType
	clientLimit = cLimit
	batchSize = bSize
	queueSize = qSize
	flushInterval = fInterval
	metrics = &ServerMetrics{
		StartTime:     startTime,
		CPUCores:      runtime.NumCPU(),
		DatabaseType:  dbType,
		ClientLimit:   cLimit,
		BatchSize:     bSize,
		QueueSize:     qSize,
		FlushInterval: fInterval,
	}
	go collectMetrics()
}
func IncrementDatabaseWrite() {
	metricsMutex.Lock()
	databaseWriteOps++
	metricsMutex.Unlock()
}
func IncrementDatabaseRead() {
	metricsMutex.Lock()
	databaseReadOps++
	metricsMutex.Unlock()
}
func TrackRequestTime(duration time.Duration) {
	requestTimeMux.Lock()
	defer requestTimeMux.Unlock()
	if len(requestTimes) >= 1000 {
		requestTimes = requestTimes[1:]
	}
	requestTimes = append(requestTimes, duration)
}
func UpdateClientCounts(connected, active, idle, dead int, writeQueueLen int) {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	if metrics != nil {
		metrics.ConnectedClients = connected
		metrics.ActiveClients = active
		metrics.IdleClients = idle
		metrics.DeadClients = dead
		metrics.WriteQueueLength = writeQueueLen
		if clientLimit > 0 {
			metrics.ClientCapacityUsed = float64(connected) / float64(clientLimit) * 100
		}
	}
}
func GetMetricsJSON() ([]byte, error) {
	metricsMutex.RLock()
	defer metricsMutex.RUnlock()
	if metrics == nil {
		return []byte("{}"), nil
	}
	metrics.Uptime = formatDuration(time.Since(startTime))
	return json.Marshal(metrics)
}
func collectMetrics() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		updateSystemMetrics()
		updateRuntimeMetrics()
		updatePerformanceMetrics()
	}
}
func updateSystemMetrics() {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	if metrics == nil {
		return
	}
	sysResources, err := GetSystemResources()
	if err == nil {
		metrics.TotalRAM = sysResources.TotalRAM
		metrics.AvailableRAM = sysResources.AvailableRAM
		if sysResources.TotalRAM > 0 {
			usedRAM := sysResources.TotalRAM - sysResources.AvailableRAM
			metrics.RAMUsage = float64(usedRAM) / float64(sysResources.TotalRAM) * 100
		}
		metrics.CPUCores = sysResources.CPULogicalCores
	}
	diskInfo, err := GetDiskUsage("C:\\")
	if err == nil {
		metrics.DiskTotal = diskInfo.Total
		metrics.DiskFree = diskInfo.Free
		metrics.DiskUsage = 100 - (float64(diskInfo.Free) / float64(diskInfo.Total) * 100)
	}
	metrics.CPUUsage = estimateCPUUsage()
	metrics.DatabaseWriteOps = databaseWriteOps
	metrics.DatabaseReadOps = databaseReadOps
}
func updateRuntimeMetrics() {
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	if metrics == nil {
		return
	}
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	metrics.GoRoutines = runtime.NumGoroutine()
	metrics.HeapAlloc = memStats.HeapAlloc
	metrics.HeapIdle = memStats.HeapIdle
	metrics.HeapInuse = memStats.HeapInuse
	metrics.HeapObjects = memStats.HeapObjects
	metrics.GCPause = float64(memStats.PauseNs[(memStats.NumGC+255)%256]) / 1000000
}
func updatePerformanceMetrics() {
	requestTimeMux.Lock()
	times := make([]time.Duration, len(requestTimes))
	copy(times, requestTimes)
	requestTimeMux.Unlock()
	metricsMutex.Lock()
	defer metricsMutex.Unlock()
	if metrics == nil || len(times) == 0 {
		return
	}
	var totalTime time.Duration
	for _, t := range times {
		totalTime += t
	}
	avgTime := totalTime / time.Duration(len(times))
	metrics.AvgResponseTime = float64(avgTime) / float64(time.Millisecond)
	recentWindow := times
	if len(recentWindow) > 0 {
		rps := float64(len(recentWindow)) / (1.0 + 0.001*float64(len(recentWindow)))
		metrics.RequestsPerSecond = rps
		if rps > metrics.PeakRequestsPerSecond {
			metrics.PeakRequestsPerSecond = rps
		}
	}
}
func estimateCPUUsage() float64 {
	numG := float64(runtime.NumGoroutine())
	baseUsage := 5.0 // minimal 5%
	scaledUsage := numG / 100.0 * 90.0
	if scaledUsage > 90.0 {
		scaledUsage = 90.0
	}
	return baseUsage + scaledUsage
}
func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

type DiskUsageInfo struct {
	Path  string `json:"path"`
	Total uint64 `json:"total"`
	Free  uint64 `json:"free"`
	Used  uint64 `json:"used"`
}

func GetDiskUsage(path string) (*DiskUsageInfo, error) {
	var info DiskUsageInfo
	info.Path = path
	h := syscall.MustLoadDLL("kernel32.dll").MustFindProc("GetDiskFreeSpaceExW")
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	ret, _, err := h.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if ret == 0 {
		return nil, err
	}
	info.Total = totalBytes
	info.Free = totalFreeBytes
	info.Used = totalBytes - totalFreeBytes
	return &info, nil
}
