//go:build amd64
// +build amd64

package jwt

import "github.com/klauspost/cpuid/v2"

type AmdZEN int8

func (a AmdZEN) String() string {
	switch a {
	case 1:
		return "Zen 1"
	case 2:
		return "Zen 2"
	default:
		return "unknown"
	}
}

//go:noescape
func CpuId(eax uint32) (eaxOut, ebx, ecx, edx uint32)

func isZen1OrZen2(cpu cpuid.CPUInfo) AmdZEN {

	if cpu.Family == 0x17 {
		switch cpu.Model {
		case 0x1, 0x8, 0x11, 0x18: // Zen 1 models
			return 1
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F: // Zen 2 models
			return 2
		}
	}
	return 0
}

func getProcessorInfo() (family, model uint32) {
	eax, _, _, _ := CpuId(1)

	baseFamily := (eax >> 8) & 0xF
	extendedFamily := (eax >> 20) & 0xFF

	baseModel := (eax >> 4) & 0xF
	extendedModel := (eax >> 16) & 0xF

	if baseFamily == 0xF {
		baseFamily += extendedFamily
	}
	if baseFamily == 0x6 || baseFamily == 0xF {
		baseModel += extendedModel << 4
	}

	return baseFamily, baseModel
}
