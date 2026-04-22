package gobot

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
