// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
)

// Device sensor endpoints for companion / Tier 5 nodes.
//
// These used to return hardcoded mock data ("Mock image: indoor office
// scene", GPS pinned to 37.7749/-122.4194). That was actively misleading:
// the coordinator would confidently describe a room that does not exist,
// and a caller had no way to tell a real reading from a stub.
//
// The rule now is: return REAL data, or an explicit error. Never fiction.
//   - battery/thermal/network — real, from sysfs (any Linux host)
//   - location                — real, from configuration (see below)
//   - camera/mic              — 503 when absent, 501 until capture is wired
//   - clipboard/screenshot     — 501, they need a display server
//
// Sensor *presence* is advertised through the heartbeat
// (hardware.DetectSensors), so the gateway only routes a tool call here
// when the hardware actually exists.

type deviceRequest struct {
	Describe        *bool `json:"describe,omitempty"`
	DurationSeconds *int  `json:"duration_seconds,omitempty"`
}

// sensorError writes a machine-readable failure.
//
// 503 = the hardware is not present on this host.
// 501 = the hardware may be present but this agent cannot read it yet.
// The distinction matters: 503 means "wrong node", 501 means "unfinished
// code". An operator seeing them conflated would chase the wrong problem.
func sensorError(w http.ResponseWriter, status int, sensor, reason string) {
	writeJSON(w, status, map[string]any{
		"error":     reason,
		"sensor":    sensor,
		"available": false,
	})
}

func (s *Server) handleDeviceCamera(w http.ResponseWriter, r *http.Request) {
	var req deviceRequest
	json.NewDecoder(r.Body).Decode(&req)
	_ = req

	if !hardware.HasSensor(hardware.SensorCamera) {
		sensorError(w, http.StatusServiceUnavailable, hardware.SensorCamera,
			"no capture camera detected on this host (a Pi's codec/ISP video "+
				"nodes are not cameras); attach a USB webcam or CSI module")
		return
	}
	// Hardware present but capture unimplemented. Returning a placeholder
	// image here would reintroduce exactly what this rewrite removed.
	sensorError(w, http.StatusNotImplemented, hardware.SensorCamera,
		"camera detected but capture is not implemented in the node-agent yet")
}

func (s *Server) handleDeviceAudio(w http.ResponseWriter, r *http.Request) {
	var req deviceRequest
	json.NewDecoder(r.Body).Decode(&req)
	_ = req

	if !hardware.HasSensor(hardware.SensorMic) {
		sensorError(w, http.StatusServiceUnavailable, hardware.SensorMic,
			"no ALSA capture device detected on this host")
		return
	}
	sensorError(w, http.StatusNotImplemented, hardware.SensorMic,
		"microphone detected but audio capture is not implemented in the node-agent yet")
}

// handleDeviceLocation reports the node's configured location.
//
// There is no GPS on a typical edge host, and IP-geolocation would mean
// calling an external service from inside the cluster. For a device that
// does not move, a configured coordinate IS ground truth — so it is
// returned with an explicit `source` field rather than dressed up as a
// fix. A real receiver (NOO_SENSOR_GPS_DEVICE) can add source:"gps" later
// without changing the response shape.
func (s *Server) handleDeviceLocation(w http.ResponseWriter, r *http.Request) {
	latRaw := strings.TrimSpace(os.Getenv("NOO_DEVICE_LAT"))
	lonRaw := strings.TrimSpace(os.Getenv("NOO_DEVICE_LON"))
	if latRaw == "" || lonRaw == "" {
		sensorError(w, http.StatusNotImplemented, "location",
			"no location configured; set NOO_DEVICE_LAT and NOO_DEVICE_LON "+
				"(this host has no GPS)")
		return
	}
	lat, errLat := strconv.ParseFloat(latRaw, 64)
	lon, errLon := strconv.ParseFloat(lonRaw, 64)
	if errLat != nil || errLon != nil ||
		lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		sensorError(w, http.StatusInternalServerError, "location",
			"NOO_DEVICE_LAT/NOO_DEVICE_LON are not valid coordinates")
		return
	}

	resp := map[string]any{
		"lat":    lat,
		"lon":    lon,
		"source": "configured",
	}
	if addr := strings.TrimSpace(os.Getenv("NOO_DEVICE_ADDRESS")); addr != "" {
		resp["address"] = addr
	}
	// NODE_LOCATION is the site label the heartbeat already reports (e.g.
	// "fl-controller"); surface it so callers see the same name as the
	// dashboard.
	if site := strings.TrimSpace(os.Getenv("NODE_LOCATION")); site != "" {
		resp["site"] = site
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDeviceBattery reports real power, thermal and network telemetry.
//
// On a mains-powered host battery_pct is null rather than a fabricated
// percentage: CompanionPolicy's battery gate should be inapplicable, not
// satisfied by fiction.
func (s *Server) handleDeviceBattery(w http.ResponseWriter, r *http.Request) {
	ps := hardware.ReadPowerStatus()
	mem := hardware.ReadMemoryInfo()

	resp := map[string]any{
		"battery_pct":   ps.BatteryPct, // null on mains
		"is_charging":   ps.IsCharging,
		"power_source":  ps.PowerSource,
		"thermal_state": ps.ThermalState,
		"network_type":  ps.NetworkType,
		"cpu_load":      hardware.CPULoad(),
		"mem_total_gb":  float64(mem.TotalKB) / 1024.0 / 1024.0,
		"mem_used_gb":   float64(mem.TotalKB-mem.AvailableKB) / 1024.0 / 1024.0,
	}
	if ps.TempC != nil {
		resp["temp_c"] = *ps.TempC
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeviceClipboard(w http.ResponseWriter, r *http.Request) {
	sensorError(w, http.StatusNotImplemented, "clipboard",
		"clipboard requires a display server; not available on a headless node")
}

func (s *Server) handleDeviceScreenshot(w http.ResponseWriter, r *http.Request) {
	sensorError(w, http.StatusNotImplemented, "screen",
		"screenshot requires a display server; not available on a headless node")
}
