//go:build !amd64

TEXT ·BoringCrypto(SB),$0
	RET

TEXT ·FIPSOnly(SB),$0
	RET

TEXT ·StandardCrypto(SB),$0
	RET
