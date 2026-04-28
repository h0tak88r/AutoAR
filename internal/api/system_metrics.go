package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

type SystemMetrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	MemoryUsed    uint64  `json:"memory_used"`
	MemoryTotal   uint64  `json:"memory_total"`
	DiskPercent   float64 `json:"disk_percent"`
	Uptime        uint64  `json:"uptime"`
	Timestamp     int64   `json:"timestamp"`
}

type RuntimeLimitsResponse struct {
	SmallVPS               bool  `json:"small_vps"`
	MaxConcurrentScans     int   `json:"max_concurrent_scans"`
	MaxScanResults         int   `json:"max_scan_results"`
	MaxScanResultsBytes    int64 `json:"max_scan_results_bytes"`
	ScanOutputCaptureBytes int   `json:"scan_output_capture_bytes"`
	MinFreeMemBytes        int64 `json:"min_free_mem_bytes"`
	EstimatedFreeMemBytes  int64 `json:"estimated_free_mem_bytes"`
}

// GET /api/system/metrics
func apiGetSystemMetrics(c *gin.Context) {
	v, _ := mem.VirtualMemory()
	cPercent, _ := cpu.Percent(time.Second, false)
	d, _ := disk.Usage("/")

	var cpuP float64
	if len(cPercent) > 0 {
		cpuP = cPercent[0]
	}

	metrics := SystemMetrics{
		CPUPercent:    cpuP,
		MemoryPercent: v.UsedPercent,
		MemoryUsed:    v.Used,
		MemoryTotal:   v.Total,
		DiskPercent:   d.UsedPercent,
		Timestamp:     time.Now().Unix(),
	}

	c.JSON(http.StatusOK, metrics)
}

// GET /api/system/limits
func apiGetRuntimeLimits(c *gin.Context) {
	initRuntimeResourceLimits()
	c.JSON(http.StatusOK, RuntimeLimitsResponse{
		SmallVPS:               isTruthyEnv("AUTOAR_SMALL_VPS"),
		MaxConcurrentScans:     maxConcurrentScans,
		MaxScanResults:         maxScanResults,
		MaxScanResultsBytes:    maxScanResultsBytes,
		ScanOutputCaptureBytes: scanOutputCaptureBytes,
		MinFreeMemBytes:        minRuntimeFreeMemBytes,
		EstimatedFreeMemBytes:  availableMemoryBytes(),
	})
}
