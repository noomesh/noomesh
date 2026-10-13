// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hardware

import (
	"encoding/binary"
	"os"
	"syscall"
	"unsafe"
)

// V4L2 capability probing.
//
// VIDIOC_QUERYCAP = _IOR('V', 0, struct v4l2_capability), where the struct
// is 104 bytes: driver[16] card[32] bus_info[32] version:u32
// capabilities:u32 device_caps:u32 reserved[3]u32.
const (
	vidiocQuerycap = 0x80685600

	capVideoCapture       = 0x00000001
	capVideoCaptureMplane = 0x00001000
	capVideoM2MMplane     = 0x00004000
	capVideoM2M           = 0x00008000
	capDeviceCaps         = 0x80000000

	querycapStructSize = 104
	offsetDriver       = 0
	offsetCapabilities = 84
	offsetDeviceCaps   = 88
)

// v4l2Info is what QUERYCAP tells us about one /dev/videoN node.
type v4l2Info struct {
	Driver  string
	Caps    uint32
	Queried bool // false when the ioctl failed (permissions, not a v4l2 node)
}

// IsCaptureCapable reports whether the node can capture video and is not a
// mem2mem (codec) device.
//
// The M2M exclusion is the platform-agnostic half of camera detection: it
// rejects hardware decoders/encoders on ANY SoC without needing to know
// their driver names — Pi bcm2835-codec, Rockchip rkvdec/rkvenc, Jetson
// nvhost-nvdec all advertise M2M.
func (v v4l2Info) IsCaptureCapable() bool {
	if !v.Queried {
		return false
	}
	isCapture := v.Caps&(capVideoCapture|capVideoCaptureMplane) != 0
	isM2M := v.Caps&(capVideoM2M|capVideoM2MMplane) != 0
	return isCapture && !isM2M
}

// queryV4L2 runs VIDIOC_QUERYCAP against a device node.
func queryV4L2(devPath string) v4l2Info {
	f, err := os.OpenFile(devPath, os.O_RDWR, 0)
	if err != nil {
		return v4l2Info{}
	}
	defer f.Close()

	buf := make([]byte, querycapStructSize)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		uintptr(vidiocQuerycap), uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return v4l2Info{}
	}

	caps := binary.LittleEndian.Uint32(buf[offsetCapabilities : offsetCapabilities+4])
	// When DEVICE_CAPS is advertised, the per-node capabilities are the
	// authoritative ones; the top-level field describes the whole device.
	if caps&capDeviceCaps != 0 {
		caps = binary.LittleEndian.Uint32(buf[offsetDeviceCaps : offsetDeviceCaps+4])
	}
	return v4l2Info{
		Driver:  cString(buf[offsetDriver : offsetDriver+16]),
		Caps:    caps,
		Queried: true,
	}
}

// cString trims a NUL-padded fixed-width C string.
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
