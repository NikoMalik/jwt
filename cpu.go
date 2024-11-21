package jwt

import (
	"github.com/klauspost/cpuid/v2"

	cp "golang.org/x/sys/cpu"
)

type CPU uint64

var (
	X86 CPU = ABIx86()
)

func (cpu CPU) Has(feature Feature) bool {
	return cpuid.CPU.Has(cpuid.FeatureID(feature))
}

func (cpu *CPU) set(feature Feature, enabled bool) {
	if enabled {
		*cpu |= CPU(feature)
	} else {
		*cpu &= ^CPU(feature)
	}
}

type Feature cpuid.FeatureID

const (
	SSE Feature = 1 << iota
	SSE2
	SSE3
	SSE41
	SSE42
	SSE4A
	SSSE3
	AVX
	AVX2
	AVX512BF16
	AVX512BITALG
	AVX512BW
	AVX512CD
	AVX512DQ
	AVX512ER
	AVX512F
	AVX512IFMA
	AVX512PF
	AVX512VBMI
	AVX512VBMI2
	AVX512VL
	AVX512VNNI
	AVX512VP2INTERSECT
	AVX512VPOPCNTDQ
	CMOV
)

func ABIx86() CPU {
	cpu := CPU(0)
	cpu.set(SSE, true)
	cpu.set(SSE2, cp.X86.HasSSE2)
	cpu.set(SSE3, cp.X86.HasSSE3)
	cpu.set(SSE41, cp.X86.HasSSE41)
	cpu.set(SSE42, cp.X86.HasSSE42)
	cpu.set(SSE4A, false)
	cpu.set(SSSE3, cp.X86.HasSSSE3)
	cpu.set(AVX, cp.X86.HasAVX)
	cpu.set(AVX2, cp.X86.HasAVX2)
	cpu.set(AVX512BF16, cp.X86.HasAVX512BF16)
	cpu.set(AVX512BITALG, cp.X86.HasAVX512BITALG)
	cpu.set(AVX512BW, cp.X86.HasAVX512BW)
	cpu.set(AVX512CD, cp.X86.HasAVX512CD)
	cpu.set(AVX512DQ, cp.X86.HasAVX512DQ)
	cpu.set(AVX512ER, cp.X86.HasAVX512ER)
	cpu.set(AVX512F, cp.X86.HasAVX512F)
	cpu.set(AVX512IFMA, cp.X86.HasAVX512IFMA)
	cpu.set(AVX512PF, cp.X86.HasAVX512PF)
	cpu.set(AVX512VBMI, cp.X86.HasAVX512VBMI)
	cpu.set(AVX512VBMI2, cp.X86.HasAVX512VBMI2)
	cpu.set(AVX512VL, cp.X86.HasAVX512VL)
	cpu.set(AVX512VNNI, cp.X86.HasAVX512VNNI)
	cpu.set(AVX512VP2INTERSECT, false)
	cpu.set(AVX512VPOPCNTDQ, cp.X86.HasAVX512VPOPCNTDQ)
	cpu.set(CMOV, true)
	return cpu
}
