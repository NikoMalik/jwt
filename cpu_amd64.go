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
