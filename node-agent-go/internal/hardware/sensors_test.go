// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile creates path (and parents) containing body.
func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// fakeRoots points the package at fixture directories for one test.
func fakeRoots(t *testing.T) (sys, proc, dev string) {
	t.Helper()
	base := t.TempDir()
	sys, proc, dev = filepath.Join(base, "sys"),
		filepath.Join(base, "proc"), filepath.Join(base, "dev")

	oldSys, oldProc, oldDev := sysfsRoot, procRoot, devRoot
	sysfsRoot, procRoot, devRoot = sys, proc, dev
	t.Cleanup(func() { sysfsRoot, procRoot, devRoot = oldSys, oldProc, oldDev })
	return sys, proc, dev
}

// ─── camera detection ────────────────────────────────────────────────
//
// hasCamera() needs a real VIDIOC_QUERYCAP ioctl, which fixture files
// cannot answer — queryV4L2 returns Queried=false for them and the node is
// skipped. That conservative default is itself the property worth pinning:
// an unqueryable node must never be reported as a camera, because that is
// exactly the false-positive-on-every-Pi bug.
//
// The classification logic is tested directly against the capability
// values MEASURED on host9, which is stronger than a fixture anyway.

func TestUnqueryableNodesAreNeverCameras(t *testing.T) {
	sys, _, dev := fakeRoots(t)
	for _, node := range []string{"video0", "video10", "video14"} {
		writeFile(t, filepath.Join(sys, "class", "video4linux", node, "name"), "whatever\n")
		writeFile(t, filepath.Join(dev, node), "")
	}
	if hasCamera() {
		t.Fatal("plain files are not v4l2 devices; must not report a camera")
	}
}

// Capability values captured from host9 (Pi 4, no camera, 14 video nodes).
// The ISP rows are the important ones: they advertise plain CAPTURE with no
// M2M bit, so a capability-only check reports four cameras on a Pi with
// none. That is why isISPDriver exists.
func TestSmallBoardCapabilityClassification(t *testing.T) {
	cases := []struct {
		node       string
		driver     string
		caps       uint32
		wantCap    bool // passes the capability test alone
		wantCamera bool // passes capability AND driver test
	}{
		{"video10", "bcm2835-codec", 0x04204000, false, false}, // M2M_MPLANE
		{"video11", "bcm2835-codec", 0x04204000, false, false},
		{"video13", "bcm2835-isp", 0x04200002, false, false}, // OUTPUT only
		{"video14", "bcm2835-isp", 0x04200001, true, false},  // CAPTURE -> ISP
		{"video15", "bcm2835-isp", 0x04200001, true, false},
		{"video16", "bcm2835-isp", 0x04a00000, false, false}, // no caps
		{"video19", "rpivid", 0x04204000, false, false},      // M2M_MPLANE
		{"video21", "bcm2835-isp", 0x04200001, true, false},
		{"video22", "bcm2835-isp", 0x04200001, true, false},
		{"video31", "bcm2835-codec", 0x04204000, false, false},
	}
	for _, c := range cases {
		info := v4l2Info{Driver: c.driver, Caps: c.caps, Queried: true}
		if got := info.IsCaptureCapable(); got != c.wantCap {
			t.Errorf("%s IsCaptureCapable = %v, want %v", c.node, got, c.wantCap)
		}
		gotCamera := info.IsCaptureCapable() && !isISPDriver(info.Driver)
		if gotCamera != c.wantCamera {
			t.Errorf("%s classified as camera=%v, want %v", c.node, gotCamera, c.wantCamera)
		}
	}
}

// A USB webcam: CAPTURE, no M2M, driver uvcvideo (not an ISP).
func TestRealWebcamClassifiedAsCamera(t *testing.T) {
	info := v4l2Info{Driver: "uvcvideo", Caps: capVideoCapture, Queried: true}
	if !info.IsCaptureCapable() || isISPDriver(info.Driver) {
		t.Fatal("a uvcvideo CAPTURE node must classify as a camera")
	}
}

// The platform-agnostic half: hardware codecs on SoCs nobody here has
// tested must be rejected by the M2M bit alone, without their driver names
// appearing in any list.
func TestForeignCodecsRejectedByCapabilityAlone(t *testing.T) {
	for _, drv := range []string{"rkvdec", "rkvenc", "nvhost-nvdec", "amphion-vpu", "hantro-vpu"} {
		info := v4l2Info{Driver: drv, Caps: capVideoCaptureMplane | capVideoM2MMplane, Queried: true}
		if info.IsCaptureCapable() {
			t.Errorf("%s advertises M2M and must not be capture-capable", drv)
		}
		if isISPDriver(drv) {
			t.Errorf("%s should be rejected by capability, not by name", drv)
		}
	}
}

func TestUnqueriedInfoIsNeverCapture(t *testing.T) {
	if (v4l2Info{Caps: capVideoCapture}).IsCaptureCapable() {
		t.Fatal("Queried=false must never be capture-capable")
	}
}

func TestISPDriverMatching(t *testing.T) {
	for _, d := range []string{"bcm2835-isp", "rkisp1", "ipu3-imgu", "BCM2835-ISP"} {
		if !isISPDriver(d) {
			t.Errorf("%q should be recognised as an ISP driver", d)
		}
	}
	for _, d := range []string{"uvcvideo", "tegra-video", "imx708", ""} {
		if isISPDriver(d) {
			t.Errorf("%q must NOT be treated as an ISP driver", d)
		}
	}
}

// Escape hatches for platforms whose ISP driver is not yet in the denylist.
func TestCameraOverrides(t *testing.T) {
	_, _, dev := fakeRoots(t)

	forced := filepath.Join(dev, "video99")
	writeFile(t, forced, "")
	t.Setenv("NOO_SENSOR_CAMERA_DEVICE", forced)
	if !hasCamera() {
		t.Error("NOO_SENSOR_CAMERA_DEVICE must force detection on")
	}

	t.Setenv("NOO_SENSOR_CAMERA_DEVICE", filepath.Join(dev, "missing"))
	if hasCamera() {
		t.Error("a forced device that does not exist must not report a camera")
	}

	t.Setenv("NOO_SENSOR_CAMERA_DEVICE", forced)
	t.Setenv("NOO_SENSOR_CAMERA_DISABLE", "1")
	if hasCamera() {
		t.Error("NOO_SENSOR_CAMERA_DISABLE must win over the forced device")
	}
}

// ─── mic detection ───────────────────────────────────────────────────

func TestMicDetection(t *testing.T) {
	_, proc, _ := fakeRoots(t)
	// Pi's built-in audio is playback-only.
	writeFile(t, filepath.Join(proc, "asound", "pcm"),
		"00-00: bcm2835 ALSA : bcm2835 ALSA : playback 8\n")
	if hasMic() {
		t.Fatal("playback-only ALSA must not be reported as a mic")
	}

	writeFile(t, filepath.Join(proc, "asound", "pcm"),
		"00-00: bcm2835 ALSA : bcm2835 ALSA : playback 8\n"+
			"01-00: USB Audio : USB Audio : capture 1\n")
	if !hasMic() {
		t.Fatal("an ALSA capture stream must be detected as a mic")
	}
}

func TestNoAlsaAtAll(t *testing.T) {
	fakeRoots(t) // nothing written
	if hasMic() {
		t.Fatal("missing /proc/asound/pcm must mean no mic, not a panic")
	}
}

// ─── gps ─────────────────────────────────────────────────────────────

// GPS is opt-in: probing for /dev/ttyUSB* would match any serial adapter,
// and advertising a gps sensor that returns nothing is worse than silence.
func TestGPSRequiresExplicitConfig(t *testing.T) {
	_, _, dev := fakeRoots(t)
	writeFile(t, filepath.Join(dev, "ttyUSB0"), "")
	t.Setenv("NOO_SENSOR_GPS_DEVICE", "")
	if gpsDevice() != "" {
		t.Fatal("a bare serial device must not be advertised as gps")
	}

	real := filepath.Join(dev, "ttyACM0")
	writeFile(t, real, "")
	t.Setenv("NOO_SENSOR_GPS_DEVICE", real)
	if gpsDevice() != real {
		t.Fatal("configured + existing gps device must be reported")
	}

	t.Setenv("NOO_SENSOR_GPS_DEVICE", filepath.Join(dev, "does-not-exist"))
	if gpsDevice() != "" {
		t.Fatal("configured but missing gps device must not be advertised")
	}
}

// ─── thermal ─────────────────────────────────────────────────────────

// Thresholds track the Pi's real behaviour (soft-throttle 80 °C, hard 85 °C)
// rather than round numbers. CompanionPolicy blocks serious+critical, so a
// lower bound would park a busy Pi in a blocked state during normal load.
func TestThermalStateThresholds(t *testing.T) {
	cases := []struct {
		temp float64
		want string
	}{
		{20, "nominal"}, {47.7, "nominal"}, {69.9, "nominal"},
		{70, "fair"}, {79.9, "fair"},
		{80, "serious"}, {84.9, "serious"},
		{85, "critical"}, {95, "critical"},
	}
	for _, c := range cases {
		if got := thermalStateFor(c.temp); got != c.want {
			t.Errorf("thermalStateFor(%.1f) = %q, want %q", c.temp, got, c.want)
		}
	}
}

func TestReadMaxTempPicksHottestZone(t *testing.T) {
	sys, _, _ := fakeRoots(t)
	writeFile(t, filepath.Join(sys, "class", "thermal", "thermal_zone0", "temp"), "47712\n")
	writeFile(t, filepath.Join(sys, "class", "thermal", "thermal_zone1", "temp"), "61000\n")

	got := readMaxTempC()
	if got == nil {
		t.Fatal("expected a temperature")
	}
	if *got != 61.0 {
		t.Fatalf("got %.1f °C, want 61.0 (hottest zone, millidegrees converted)", *got)
	}
}

func TestNoThermalZonesIsNotAnError(t *testing.T) {
	fakeRoots(t)
	if readMaxTempC() != nil {
		t.Fatal("absent thermal sysfs must yield nil, not a fabricated value")
	}
	if ps := ReadPowerStatus(); ps.ThermalState != "nominal" {
		t.Fatalf("thermal_state = %q, want nominal fallback", ps.ThermalState)
	}
}

// ─── power ───────────────────────────────────────────────────────────

// The honesty requirement: a mains host reports battery_pct = nil, NOT a
// fake 100%. CompanionPolicy's battery gate must be inapplicable rather
// than satisfied by fiction.
func TestMainsPoweredHostReportsNullBattery(t *testing.T) {
	fakeRoots(t) // no power_supply entries — like host9
	ps := ReadPowerStatus()
	if ps.BatteryPct != nil {
		t.Fatalf("battery_pct = %v, want nil on a mains host", *ps.BatteryPct)
	}
	if ps.PowerSource != "mains" {
		t.Fatalf("power_source = %q, want mains", ps.PowerSource)
	}
	if !ps.IsCharging {
		t.Fatal("a mains host is never depleting; is_charging must be true")
	}
}

func TestBatteryHostReportsRealPercentage(t *testing.T) {
	sys, _, _ := fakeRoots(t)
	base := filepath.Join(sys, "class", "power_supply")
	// A non-battery supply must be skipped, not misread.
	writeFile(t, filepath.Join(base, "ADP1", "type"), "Mains\n")
	writeFile(t, filepath.Join(base, "BAT0", "type"), "Battery\n")
	writeFile(t, filepath.Join(base, "BAT0", "capacity"), "42\n")
	writeFile(t, filepath.Join(base, "BAT0", "status"), "Discharging\n")

	ps := ReadPowerStatus()
	if ps.BatteryPct == nil || *ps.BatteryPct != 42 {
		t.Fatalf("battery_pct = %v, want 42", ps.BatteryPct)
	}
	if ps.PowerSource != "battery" || ps.IsCharging {
		t.Fatalf("got source=%q charging=%v, want battery/false", ps.PowerSource, ps.IsCharging)
	}
}

// ─── network ─────────────────────────────────────────────────────────

func TestNetworkTypeDetection(t *testing.T) {
	sys, _, _ := fakeRoots(t)
	base := filepath.Join(sys, "class", "net")
	// Virtual interfaces that must never be treated as the uplink.
	// tailscale0 matters most: it rides on top of the real link, so
	// reporting it would mask whether the host is on wifi or ethernet.
	for _, n := range []string{"lo", "docker0", "br-08b2ffadce93", "tailscale0"} {
		writeFile(t, filepath.Join(base, n, "operstate"), "up\n")
	}
	if got := detectNetworkType(); got != "" {
		t.Fatalf("only virtual interfaces: got %q, want \"\" (unknown)", got)
	}

	// wlan0 up, physical (device symlink), wireless marker -> wifi.
	writeFile(t, filepath.Join(base, "wlan0", "operstate"), "up\n")
	writeFile(t, filepath.Join(base, "wlan0", "device", "uevent"), "")
	writeFile(t, filepath.Join(base, "wlan0", "wireless", "dummy"), "")
	if got := detectNetworkType(); got != "wifi" {
		t.Fatalf("got %q, want wifi", got)
	}

	// Ethernet wins over wifi when both are up — stabler link, and
	// CompanionPolicy allows either.
	writeFile(t, filepath.Join(base, "eth0", "operstate"), "up\n")
	writeFile(t, filepath.Join(base, "eth0", "device", "uevent"), "")
	if got := detectNetworkType(); got != "ethernet" {
		t.Fatalf("got %q, want ethernet to win over wifi", got)
	}
}

// THE container regression, measured on host9. The agent runs on a bridge
// network, so it sees only a veth "eth0" with no wireless marker. Without
// the physical-interface filter it reports "ethernet" for a host that is
// actually on Wi-Fi.
func TestContainerVethIsNotReportedAsEthernet(t *testing.T) {
	sys, _, _ := fakeRoots(t)
	base := filepath.Join(sys, "class", "net")
	// Exactly what the container sees: eth0 + lo, no device symlinks.
	writeFile(t, filepath.Join(base, "eth0", "operstate"), "up\n")
	writeFile(t, filepath.Join(base, "lo", "operstate"), "up\n")

	got := detectNetworkType()
	if got == "ethernet" {
		t.Fatal("veth eth0 reported as ethernet; this is the wrong-answer bug")
	}
	if got != "" {
		t.Fatalf("got %q, want \"\" so CompanionPolicy skips the check", got)
	}
}

// An operator who knows the host's link can state it.
func TestNetworkTypeOverride(t *testing.T) {
	sys, _, _ := fakeRoots(t)
	writeFile(t, filepath.Join(sys, "class", "net", "eth0", "operstate"), "up\n")
	t.Setenv("NOO_NETWORK_TYPE", "wifi")
	if got := detectNetworkType(); got != "wifi" {
		t.Fatalf("got %q, want the override to win", got)
	}
}

// Real NICs that are all down is genuinely offline — distinct from
// "no physical NICs visible", which is unknown.
func TestDownPhysicalInterfaceIsOffline(t *testing.T) {
	sys, _, _ := fakeRoots(t)
	base := filepath.Join(sys, "class", "net")
	writeFile(t, filepath.Join(base, "eth0", "operstate"), "down\n")
	writeFile(t, filepath.Join(base, "eth0", "device", "uevent"), "")
	if got := detectNetworkType(); got != "offline" {
		t.Fatalf("got %q, want offline for a down physical link", got)
	}
}

// ─── DetectSensors contract ──────────────────────────────────────────

// Must be an empty slice, never nil: it is marshalled straight into the
// heartbeat, and nil would serialise as JSON null where the gateway
// expects a list.
func TestDetectSensorsIsEmptySliceNotNil(t *testing.T) {
	fakeRoots(t)
	got := DetectSensors()
	if got == nil {
		t.Fatal("DetectSensors returned nil; must be an empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want no sensors on a bare host", got)
	}
}

func TestHasSensorMatchesDetectSensors(t *testing.T) {
	_, proc, _ := fakeRoots(t)
	writeFile(t, filepath.Join(proc, "asound", "pcm"), "01-00: USB Audio : capture 1\n")

	if !HasSensor(SensorMic) {
		t.Fatal("HasSensor(mic) must agree with DetectSensors")
	}
	if HasSensor(SensorCamera) {
		t.Fatal("HasSensor(camera) must be false with no camera present")
	}
}

// ─── thermal thresholds are platform-tunable ─────────────────────────

// The defaults are Pi-tuned (soft-throttle 80 °C, hard 85 °C). A Jetson
// runs to ~99 °C and an x86 CPU to ~100 °C before throttling, so without
// an override those defaults would report "critical" on healthy hardware.
func TestThermalThresholdsAreOverridable(t *testing.T) {
	// 90 °C is critical on a Pi...
	if got := thermalStateFor(90); got != "critical" {
		t.Fatalf("default: thermalStateFor(90) = %q, want critical", got)
	}
	// ...and unremarkable on a Jetson.
	t.Setenv("NOO_THERMAL_FAIR_C", "85")
	t.Setenv("NOO_THERMAL_SERIOUS_C", "95")
	t.Setenv("NOO_THERMAL_CRITICAL_C", "99")
	if got := thermalStateFor(90); got != "fair" {
		t.Errorf("jetson-tuned: thermalStateFor(90) = %q, want fair", got)
	}
	if got := thermalStateFor(96); got != "serious" {
		t.Errorf("jetson-tuned: thermalStateFor(96) = %q, want serious", got)
	}
	if got := thermalStateFor(99); got != "critical" {
		t.Errorf("jetson-tuned: thermalStateFor(99) = %q, want critical", got)
	}
}

// Garbage must not silently disable the gate.
func TestThermalOverridesRejectNonsense(t *testing.T) {
	t.Setenv("NOO_THERMAL_CRITICAL_C", "not-a-number")
	if got := thermalStateFor(85); got != "critical" {
		t.Errorf("unparseable override must fall back to default: got %q", got)
	}
	t.Setenv("NOO_THERMAL_CRITICAL_C", "-10")
	if got := thermalStateFor(85); got != "critical" {
		t.Errorf("negative override must fall back to default: got %q", got)
	}
}
