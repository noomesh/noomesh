package hardware

import "testing"

// A discrete CUDA card on amd64 is never unified memory, whatever the
// RAM-to-VRAM ratio: the ratio rule is DGX Spark-class (arm64) only.
func TestCudaPoolIsRAMOnlyOnArm64(t *testing.T) {
	cases := []struct {
		name      string
		goarch    string
		vram, ram float64
		want      bool
	}{
		{"one 24 GB card in a 16 GB amd64 desktop", "amd64", 24, 16, false},
		{"one 24 GB card with 24 GB RAM on amd64", "amd64", 24, 24, false},
		{"two P40s (24 GB per card) with 24 GB RAM on amd64", "amd64", 24, 24, false},
		{"two P40s (24 GB per card) with 32 GB RAM on amd64", "amd64", 24, 32, false},
		{"DGX Spark-class: arm64, the CUDA pool is the RAM", "arm64", 119, 128, true},
		{"arm64 with a pool well under RAM is discrete", "arm64", 16, 64, false},
	}
	for _, c := range cases {
		if got := cudaPoolIsRAM(c.goarch, "cuda", c.vram, c.ram); got != c.want {
			t.Errorf("%s: cudaPoolIsRAM(%s, cuda, %v, %v) = %v, want %v", c.name, c.goarch, c.vram, c.ram, got, c.want)
		}
	}
	if cudaPoolIsRAM("arm64", "none", 119, 128) {
		t.Error("a non-CUDA API is never the CUDA-pool rule")
	}
}
