// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/moby/moby/client"
)

// ContainerStats holds resource usage stats for a single container.
type ContainerStats struct {
	Name         string  `json:"name"`
	ID           string  `json:"id"`
	Status       string  `json:"status"`
	Image        string  `json:"image"`
	CPUPercent   float64 `json:"cpu_percent"`
	MemUsageMB   float64 `json:"mem_usage_mb"`
	MemLimitMB   float64 `json:"mem_limit_mb"`
	MemPercent   float64 `json:"mem_percent"`
	NetRxMB      float64 `json:"net_rx_mb"`
	NetTxMB      float64 `json:"net_tx_mb"`
	BlockReadMB  float64 `json:"block_read_mb"`
	BlockWriteMB float64 `json:"block_write_mb"`
}

// AllContainerStats collects resource stats for all running containers.
// Stats are fetched concurrently since each Docker stats call blocks ~1-2s.
func (c *Client) AllContainerStats(ctx context.Context) []ContainerStats {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	opts := client.ContainerListOptions{}
	if c.composeProject != "" {
		opts.Filters = make(client.Filters).Add(
			"label", "com.docker.compose.project="+c.composeProject)
	}
	containers, err := c.listContainers(ctx, opts)
	if err != nil || len(containers) == 0 {
		return nil
	}

	// Cap concurrency at 20 goroutines
	workers := len(containers)
	if workers > 20 {
		workers = 20
	}

	results := make([]ContainerStats, len(containers))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	for i, ctr := range containers {
		wg.Add(1)
		go func(idx int, id string, names []string, state, image string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			name := ""
			if len(names) > 0 {
				name = names[0]
				if len(name) > 0 && name[0] == '/' {
					name = name[1:]
				}
			}

			stat := ContainerStats{
				Name:   name,
				ID:     id[:minInt(12, len(id))],
				Status: state,
				Image:  image,
			}

			statsCtx, statsCancel := context.WithTimeout(ctx, 5*time.Second)
			defer statsCancel()

			resp, err := c.docker.ContainerStats(statsCtx, id, client.ContainerStatsOptions{})
			if err != nil {
				results[idx] = stat
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				results[idx] = stat
				return
			}

			var raw dockerStatsJSON
			if err := json.Unmarshal(body, &raw); err != nil {
				results[idx] = stat
				return
			}

			// CPU %
			cpuDelta := float64(raw.CPUStats.CPUUsage.TotalUsage - raw.PreCPUStats.CPUUsage.TotalUsage)
			sysDelta := float64(raw.CPUStats.SystemCPUUsage - raw.PreCPUStats.SystemCPUUsage)
			numCPUs := raw.CPUStats.OnlineCPUs
			if numCPUs == 0 {
				numCPUs = uint32(len(raw.CPUStats.CPUUsage.PercpuUsage))
				if numCPUs == 0 {
					numCPUs = 1
				}
			}
			if sysDelta > 0 {
				stat.CPUPercent = roundF(cpuDelta/sysDelta*float64(numCPUs)*100, 2)
			}

			// Memory — subtract inactive file cache (cgroup v1)
			memUsage := raw.MemoryStats.Usage
			cache := raw.MemoryStats.Stats.InactiveFile
			if cache > 0 && memUsage > cache {
				memUsage -= cache
			}
			memLimit := raw.MemoryStats.Limit
			stat.MemUsageMB = roundF(float64(memUsage)/MB, 1)
			stat.MemLimitMB = roundF(float64(memLimit)/MB, 1)
			if memLimit > 0 {
				stat.MemPercent = roundF(float64(memUsage)/float64(memLimit)*100, 1)
			}

			// Net I/O
			var netRx, netTx uint64
			for _, iface := range raw.Networks {
				netRx += iface.RxBytes
				netTx += iface.TxBytes
			}
			stat.NetRxMB = roundF(float64(netRx)/MB, 2)
			stat.NetTxMB = roundF(float64(netTx)/MB, 2)

			// Block I/O
			for _, entry := range raw.BlkioStats.IOServiceBytesRecursive {
				switch entry.Op {
				case "read", "Read":
					stat.BlockReadMB += float64(entry.Value)
				case "write", "Write":
					stat.BlockWriteMB += float64(entry.Value)
				}
			}
			stat.BlockReadMB = roundF(stat.BlockReadMB/MB, 2)
			stat.BlockWriteMB = roundF(stat.BlockWriteMB/MB, 2)

			results[idx] = stat
		}(i, ctr.ID, ctr.Names, string(ctr.State), ctr.Image)
	}

	wg.Wait()
	return results
}

const MB = 1024 * 1024

// Docker stats JSON structures (subset we need).

type dockerStatsJSON struct {
	CPUStats    cpuStatsJSON            `json:"cpu_stats"`
	PreCPUStats cpuStatsJSON            `json:"precpu_stats"`
	MemoryStats memStatsJSON            `json:"memory_stats"`
	Networks    map[string]netStatsJSON `json:"networks"`
	BlkioStats  blkioStatsJSON          `json:"blkio_stats"`
}

type cpuStatsJSON struct {
	CPUUsage       cpuUsageJSON `json:"cpu_usage"`
	SystemCPUUsage uint64       `json:"system_cpu_usage"`
	OnlineCPUs     uint32       `json:"online_cpus"`
}

type cpuUsageJSON struct {
	TotalUsage  uint64   `json:"total_usage"`
	PercpuUsage []uint64 `json:"percpu_usage"`
}

type memStatsJSON struct {
	Usage uint64            `json:"usage"`
	Limit uint64            `json:"limit"`
	Stats memStatsInnerJSON `json:"stats"`
}

type memStatsInnerJSON struct {
	InactiveFile uint64 `json:"inactive_file"`
}

type netStatsJSON struct {
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

type blkioStatsJSON struct {
	IOServiceBytesRecursive []blkioEntryJSON `json:"io_service_bytes_recursive"`
}

type blkioEntryJSON struct {
	Op    string `json:"op"`
	Value uint64 `json:"value"`
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func roundF(val float64, places int) float64 {
	shift := 1.0
	for i := 0; i < places; i++ {
		shift *= 10
	}
	return float64(int64(val*shift+0.5)) / shift
}
