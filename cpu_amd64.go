//go:build amd64
// +build amd64

package jwt

//go:noescape
func CpuId(eax uint32) (eaxOut, ebx, ecx, edx uint32)

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

func isZen1() bool {
	family, model := getProcessorInfo()
	if family == 0x17 {
		switch model {
		case 0x1, 0x8, 0x11, 0x18:
			return true
		}
	}
	return false
}
