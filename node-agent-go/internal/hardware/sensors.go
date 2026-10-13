// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Sensor identifiers.
//
// These MUST match the vocabulary the gateway's device_sensors tool looks
// up (`required_sensor` in src/noomesh/tools/device_sensors.py). A
// mismatch fails silently: the tool simply never finds a device.
const (
	SensorCamera = "camera"
	SensorMic    = "mic"
	SensorGPS    = "gps"
)

// Filesystem roots, as variables so tests can point them at fixtures
// instead of depending on whatever hardware the CI runner happens to have.
var (
	sysfsRoot = "/sys"
	procRoot  = "/proc"
	devRoot   = "/dev"
)

// Camera detection uses TWO independent signals, because measurement showed
// that neither one alone is correct across platforms.
//
// Measured on host9 (Raspberry Pi 4, no camera attached, 14 video nodes):
//
//		video10 bcm2835-codec  M2M_MPLANE  -> codec
//		video13 bcm2835-isp    OUTPUT      -> not capture
//		video14 bcm2835-isp    CAPTURE     -> !! looks like a camera !!
//		video19 rpivid         M2M_MPLANE  -> codec
//
//	 1. VIDIOC_QUERYCAP capability bits (v4l2_linux.go) reject mem2mem codecs
//	    on ANY SoC without knowing driver names — Pi bcm2835-codec, Rockchip
//	    rkvdec/rkvenc, Jetson nvhost-nvdec all advertise M2M. This is the
//	    platform-agnostic half, and it is what makes detection work on
//	    hardware nobody here has tested.
//
//	 2. Capabilities alone are NOT enough: the Pi's four ISP nodes
//	    (video14/15/21/22) advertise plain CAPTURE with no M2M bit, so a
//	    capability-only check reports FOUR cameras on a Pi with none. Hence a
//	    denylist of ISP driver names as the second filter.
//
// The denylist is deliberately small and matches on the v4l2 DRIVER field
// (bcm2835-isp), not the card/name string, because driver names are stable
// while card strings vary per board. Any ISP family not listed here will
// false-positive on that platform — NOO_SENSOR_CAMERA_DISABLE=1 is the
// escape hatch until its driver name is added.
var ispDrivers = []string{
	"bcm2835-isp", // Raspberry Pi — confirmed by measurement
	"rkisp",       // Rockchip (RK3588 et al) — by convention, untested
	"ipu3-imgu",   // Intel IPU3 ISP — by convention, untested
}

// isISPDriver reports whether a v4l2 driver is an ISP block rather than a
// real sensor.
func isISPDriver(driver string) bool {
	d := strings.ToLower(strings.TrimSpace(driver))
	if d == "" {
		return false
	}
	for _, frag := range ispDrivers {
		if strings.Contains(d, frag) {
			return true
		}
	}
	return false
}

// hasCamera reports whether a real capture camera is attached.
//
// Escape hatches for platforms whose ISP drivers are not yet in the
// denylist, or where autodetection is simply wrong:
//
//	NOO_SENSOR_CAMERA_DISABLE=1     never advertise a camera
//	NOO_SENSOR_CAMERA_DEVICE=/dev/x trust this node, skip detection
func hasCamera() bool {
	if truthy(os.Getenv("NOO_SENSOR_CAMERA_DISABLE")) {
		return false
	}
	if forced := strings.TrimSpace(os.Getenv("NOO_SENSOR_CAMERA_DEVICE")); forced != "" {
		_, err := os.Stat(forced)
		return err == nil
	}

	entries, err := os.ReadDir(filepath.Join(sysfsRoot, "class", "video4linux"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		// The sysfs entry can outlive the device node; require both.
		devPath := filepath.Join(devRoot, e.Name())
		if _, err := os.Stat(devPath); err != nil {
			continue
		}
		info := queryV4L2(devPath)
		if !info.Queried {
			// Could not query (permissions, or fixture dirs in tests) —
			// treating an unqueryable node as a camera would resurrect the
			// false-positive-on-every-Pi bug, so stay conservative.
			continue
		}
		if !info.IsCaptureCapable() || isISPDriver(info.Driver) {
			continue
		}
		return true
	}
	return false
}

// truthy accepts the usual shell-ish spellings of "yes".
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// hasMic reports whether ALSA exposes any capture stream.
//
// Reads /proc/asound/pcm rather than shelling out to `arecord -l`, so no
// extra package is needed in the Alpine image.
func hasMic() bool {
	raw, err := os.ReadFile(filepath.Join(procRoot, "asound", "pcm"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(strings.ToLower(line), "capture") {
			return true
		}
	}
	return false
}

// gpsDevice returns the configured GPS serial device, or "".
//
// Deliberately opt-in via NOO_SENSOR_GPS_DEVICE rather than probing for
// /dev/ttyACM* or /dev/ttyUSB*: those match any USB serial adapter, and
// advertising a `gps` sensor that returns nothing is worse than not
// advertising one at all.
func gpsDevice() string {
	dev := strings.TrimSpace(os.Getenv("NOO_SENSOR_GPS_DEVICE"))
	if dev == "" {
		return ""
	}
	if _, err := os.Stat(dev); err != nil {
		return ""
	}
	return dev
}

// DetectSensors returns the sensors physically present on this host.
//
// Called every heartbeat so the list is self-maintaining: plug in a USB
// webcam and the next heartbeat advertises "camera", with no
// re-registration and no hand-edited node record. Equally, a device that
// disappears stops being advertised, so the coordinator never routes a
// tool call to hardware that has been unplugged.
func DetectSensors() []string {
	sensors := []string{}
	if hasCamera() {
		sensors = append(sensors, SensorCamera)
	}
	if hasMic() {
		sensors = append(sensors, SensorMic)
	}
	if gpsDevice() != "" {
		sensors = append(sensors, SensorGPS)
	}
	return sensors
}

// HasSensor reports whether a named sensor is present right now.
//
// Deliberately re-probes rather than caching: hardware can be hot-plugged,
// and a stale "yes" turns into a confusing 501 at the handler instead of
// an honest 503.
func HasSensor(name string) bool {
	for _, s := range DetectSensors() {
		if s == name {
			return true
		}
	}
	return false
}

// PowerStatus is the power/thermal/network telemetry the gateway persists
// from each heartbeat and CompanionPolicy gates work on.
type PowerStatus struct {
	// BatteryPct is nil on mains-powered hosts — a Pi has no battery, and
	// reporting a fake 100% would make CompanionPolicy's battery gate
	// meaningless rather than inapplicable.
	BatteryPct   *float64 `json:"battery_pct"`
	IsCharging   bool     `json:"is_charging"`
	PowerSource  string   `json:"power_source"` // "battery" | "mains"
	TempC        *float64 `json:"temp_c"`
	ThermalState string   `json:"thermal_state"` // nominal|fair|serious|critical
	NetworkType  string   `json:"network_type"`  // wifi|ethernet|offline
}

// Default thermal thresholds, in °C.
//
// These are tuned for Pi-class ARM SBCs, which soft-throttle at 80 °C and
// hard-throttle at 85 °C — so "serious" (which CompanionPolicy blocks)
// starts where throttling actually begins.
//
// They are NOT universal. A Jetson runs to ~99 °C and an x86 CPU to ~100 °C
// before throttling, so these defaults would report "critical" on hardware
// that is perfectly healthy. Override per node:
//
//	NOO_THERMAL_FAIR_C / NOO_THERMAL_SERIOUS_C / NOO_THERMAL_CRITICAL_C
//
// Deriving these from the kernel's own trip points was the obvious fix and
// does not work: host9 declares exactly one trip point, critical=110 °C,
// which is the SoC's destruct limit, not its throttle point. Trusting it
// would report "nominal" at 100 °C on a Pi that has been throttling for
// 20 °C. The firmware throttle points are not exposed through sysfs at all.
const (
	defaultThermalFairC     = 70.0
	defaultThermalSeriousC  = 80.0
	defaultThermalCriticalC = 85.0
)

// envFloat reads a float from the environment, falling back to def when
// unset, unparseable, or non-positive.
func envFloat(key string, def float64) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// thermalStateFor maps a temperature to the vocabulary CompanionPolicy
// expects (node.py:102 — nominal/fair/serious/critical; the policy blocks
// "serious" and "critical" by default).
func thermalStateFor(tempC float64) string {
	fair := envFloat("NOO_THERMAL_FAIR_C", defaultThermalFairC)
	serious := envFloat("NOO_THERMAL_SERIOUS_C", defaultThermalSeriousC)
	critical := envFloat("NOO_THERMAL_CRITICAL_C", defaultThermalCriticalC)

	switch {
	case tempC >= critical:
		return "critical"
	case tempC >= serious:
		return "serious"
	case tempC >= fair:
		return "fair"
	default:
		return "nominal"
	}
}

// readMaxTempC returns the hottest thermal zone in °C, or nil if sysfs
// exposes none (common in VMs and some containers).
func readMaxTempC() *float64 {
	entries, err := os.ReadDir(filepath.Join(sysfsRoot, "class", "thermal"))
	if err != nil {
		return nil
	}
	var max float64
	found := false
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "thermal_zone") {
			continue
		}
		raw, err := os.ReadFile(
			filepath.Join(sysfsRoot, "class", "thermal", e.Name(), "temp"))
		if err != nil {
			continue
		}
		milli, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
		if err != nil {
			continue
		}
		// sysfs reports millidegrees.
		if c := milli / 1000.0; !found || c > max {
			max, found = c, true
		}
	}
	if !found {
		return nil
	}
	return &max
}

// readBattery returns (percentage, charging, present).
func readBattery() (float64, bool, bool) {
	base := filepath.Join(sysfsRoot, "class", "power_supply")
	entries, err := os.ReadDir(base)
	if err != nil {
		return 0, false, false
	}
	for _, e := range entries {
		typ, err := os.ReadFile(filepath.Join(base, e.Name(), "type"))
		if err != nil || strings.TrimSpace(string(typ)) != "Battery" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(base, e.Name(), "capacity"))
		if err != nil {
			continue
		}
		pct, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
		if err != nil {
			continue
		}
		status, _ := os.ReadFile(filepath.Join(base, e.Name(), "status"))
		charging := strings.TrimSpace(string(status)) == "Charging"
		return pct, charging, true
	}
	return 0, false, false
}

// skipIface matches interfaces that never represent the host's real
// uplink — loopback, container bridges, and the Tailscale overlay (which
// rides on top of whatever the real link is).
func skipIface(name string) bool {
	for _, p := range []string{"lo", "docker", "br-", "veth", "tailscale", "virbr"} {
		if name == p || strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// detectNetworkType reports wifi / ethernet / offline, or "" for unknown.
//
// Wi-Fi is identified by a `wireless` directory in sysfs, which is how the
// kernel marks an 802.11 device — more reliable than guessing from the
// interface name (wlan0 vs wlp3s0 vs a renamed link).
//
// Only PHYSICAL interfaces count, identified by a `device` symlink into the
// bus (mmc/PCI/USB). This is not a refinement, it is load-bearing: the
// node-agent normally runs on a bridge network, where /sys/class/net shows
// the container's veth `eth0` and nothing else. Measured on host9, whose
// host is on Wi-Fi:
//
//	container eth0  -> no device symlink   (veth)
//	host wlan0      -> device -> mmc1:0001:1
//	host docker0    -> no device symlink   (bridge)
//
// Without the filter the agent confidently reports "ethernet" for a
// Wi-Fi host, because a veth has no `wireless` directory.
//
// When nothing physical is visible we return "" rather than guessing.
// Empty is the correct "unknown": CompanionPolicy short-circuits on a
// falsy network_type and skips the check, whereas "offline" — or a wrong
// "ethernet" — would silently mis-gate work. Operators who know better
// can set NOO_NETWORK_TYPE, and running the agent with network_mode:host
// makes detection work directly.
func detectNetworkType() string {
	if forced := strings.TrimSpace(os.Getenv("NOO_NETWORK_TYPE")); forced != "" {
		return forced
	}

	base := filepath.Join(sysfsRoot, "class", "net")
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	sawPhysical := false
	best := ""
	for _, e := range entries {
		if skipIface(e.Name()) {
			continue
		}
		// A physical NIC has a device symlink; veth/bridge/tun do not.
		if _, err := os.Stat(filepath.Join(base, e.Name(), "device")); err != nil {
			continue
		}
		sawPhysical = true

		state, err := os.ReadFile(filepath.Join(base, e.Name(), "operstate"))
		if err != nil || strings.TrimSpace(string(state)) != "up" {
			continue
		}
		if _, err := os.Stat(filepath.Join(base, e.Name(), "wireless")); err == nil {
			// Wi-Fi is the weaker link; keep looking for ethernet, which
			// CompanionPolicy also allows and which will not drop.
			if best == "" {
				best = "wifi"
			}
			continue
		}
		return "ethernet"
	}
	if best == "" && sawPhysical {
		// Real NICs exist, all of them down — genuinely offline.
		return "offline"
	}
	return best
}

// ReadPowerStatus gathers power, thermal and network telemetry.
func ReadPowerStatus() PowerStatus {
	ps := PowerStatus{
		PowerSource: "mains",
		// A mains-powered host is never depleting, so "charging" is the
		// honest answer for CompanionPolicy.require_charging_for_inference.
		IsCharging:   true,
		ThermalState: "nominal",
		NetworkType:  detectNetworkType(),
	}
	if pct, charging, present := readBattery(); present {
		ps.BatteryPct = &pct
		ps.IsCharging = charging
		ps.PowerSource = "battery"
	}
	if temp := readMaxTempC(); temp != nil {
		ps.TempC = temp
		ps.ThermalState = thermalStateFor(*temp)
	}
	return ps
}
