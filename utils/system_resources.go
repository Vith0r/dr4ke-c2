package utils

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type SystemResources struct {
	TotalRAM         uint64
	AvailableRAM     uint64
	CPUCores         int
	CPULogicalCores  int
	ProcessorSpeed   uint32
	Is64BitOperating bool
	CPUUsage         float64
	DiskTotal        uint64
	DiskFree         uint64
	MemoryPressure   float64
}

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

type systemInfo struct {
	wProcessorArchitecture      uint16
	wReserved                   uint16
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       uintptr
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

var (
	memoryPressureThreshold = 95.0 // Increased from 85% to 95%
	memoryPressureMutex     sync.RWMutex
	lastMemoryCheck         time.Time
	memoryCheckInterval     = 5 * time.Second
)

func GetSystemResources() (*SystemResources, error) {
	resources := &SystemResources{}
	var memInfo memoryStatusEx
	memInfo.dwLength = uint32(unsafe.Sizeof(memInfo))
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")
	r1, _, err := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memInfo)))
	if r1 == 0 {
		return nil, fmt.Errorf("failed to get memory info: %v", err)
	}
	resources.TotalRAM = memInfo.ullTotalPhys
	resources.AvailableRAM = memInfo.ullAvailPhys
	resources.CPUCores = runtime.NumCPU()
	resources.CPULogicalCores = resources.CPUCores

	if resources.TotalRAM > 0 {
		usedRAM := resources.TotalRAM - resources.AvailableRAM
		resources.MemoryPressure = float64(usedRAM) / float64(resources.TotalRAM) * 100
	}

	var sysInfo systemInfo
	getSystemInfo := kernel32.NewProc("GetSystemInfo")
	getSystemInfo.Call(uintptr(unsafe.Pointer(&sysInfo)))
	resources.Is64BitOperating = runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
	resources.ProcessorSpeed = getCPUSpeedFromEnv()
	return resources, nil
}

func getCPUSpeedFromEnv() uint32 {
	cpuInfo := os.Getenv("PROCESSOR_IDENTIFIER")
	if strings.Contains(cpuInfo, "@") {
		parts := strings.Split(cpuInfo, "@")
		if len(parts) > 1 {
			speedStr := strings.TrimSpace(parts[1])
			if strings.Contains(speedStr, "GHz") {
				speedStr = strings.Replace(speedStr, "GHz", "", -1)
				speedStr = strings.TrimSpace(speedStr)
				if speedFloat, err := strconv.ParseFloat(speedStr, 32); err == nil {
					return uint32(speedFloat * 1000) // Convert GHz to MHz
				}
			} else if strings.Contains(speedStr, "MHz") {
				speedStr = strings.Replace(speedStr, "MHz", "", -1)
				speedStr = strings.TrimSpace(speedStr)
				if speedInt, err := strconv.Atoi(speedStr); err == nil {
					return uint32(speedInt)
				}
			}
		}
	}
	return 2000
}

func CalculateOptimalBatchSize(resources *SystemResources) int {
	ramFactor := float64(resources.AvailableRAM) / (1024 * 1024 * 1024)
	cpuFactor := float64(resources.CPULogicalCores)
	batchSize := int(50 * ramFactor * cpuFactor)
	if batchSize < 100 {
		batchSize = 100
	} else if batchSize > 1000 {
		batchSize = 1000
	}
	return batchSize
}

func CalculateOptimalClientLimit(resources *SystemResources) int {
	clientMemoryUsage := uint64(5 * 1024)

	availableForClients := uint64(float64(resources.TotalRAM) * 0.95)
	maxClientsByRAM := availableForClients / clientMemoryUsage

	clientLimit := maxClientsByRAM

	if resources.MemoryPressure > 95.0 {
		clientLimit = uint64(float64(clientLimit) * 0.9)
	}

	return int(clientLimit)
}

func CalculateOptimalQueueSize(resources *SystemResources) int {
	ramGB := float64(resources.AvailableRAM) / (1024 * 1024 * 1024)
	queueSize := int(500 * ramGB)
	if queueSize < 1000 {
		queueSize = 1000
	} else if queueSize > 20000 {
		queueSize = 20000
	}
	return queueSize
}

func GetOptimalServerConfigs() (batchSize, clientLimit, queueSize int, err error) {
	resources, err := GetSystemResources()
	if err != nil {
		return 200, 5000, 1000, err
	}
	LogOutput("[INFO] System Resources: %d GB RAM, %d CPU cores", resources.TotalRAM/(1024*1024*1024), resources.CPULogicalCores)
	batchSize = CalculateOptimalBatchSize(resources)
	clientLimit = CalculateOptimalClientLimit(resources)
	queueSize = CalculateOptimalQueueSize(resources)
	LogOutput("[INFO] Optimal configurations: batch size=%d, client limit=%d, queue size=%d",
		batchSize, clientLimit, queueSize)
	return batchSize, clientLimit, queueSize, nil
}

func CheckMemoryPressure() bool {
	memoryPressureMutex.RLock()
	if time.Since(lastMemoryCheck) < memoryCheckInterval {
		currentResources, err := GetSystemResources()
		if err != nil {
			memoryPressureMutex.RUnlock()
			return false
		}
		pressure := currentResources.MemoryPressure
		memoryPressureMutex.RUnlock()
		return pressure > memoryPressureThreshold
	}
	memoryPressureMutex.RUnlock()

	memoryPressureMutex.Lock()
	defer memoryPressureMutex.Unlock()

	resources, err := GetSystemResources()
	if err != nil {
		return false
	}

	lastMemoryCheck = time.Now()
	return resources.MemoryPressure > memoryPressureThreshold
}

func SetMemoryPressureThreshold(threshold float64) {
	if threshold < 0 || threshold > 100 {
		return
	}
	memoryPressureMutex.Lock()
	memoryPressureThreshold = threshold
	memoryPressureMutex.Unlock()
}
