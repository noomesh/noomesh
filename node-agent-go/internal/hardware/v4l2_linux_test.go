// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import "testing"

// The capability tests read the Linux v4l2 constants and fields
// (v4l2_linux.go); on other platforms v4l2Info has no capabilities
// (v4l2_other.go), so these live in a _linux test file.

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
