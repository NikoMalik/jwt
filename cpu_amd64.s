#include "textflag.h"


TEXT ·CpuId(SB),NOSPLIT,$0-12
        MOVL ax+8(FP), AX
        CPUID
        MOVQ info+0(FP), DI
        MOVL AX, 0(DI)
        MOVL BX, 4(DI)
        MOVL CX, 8(DI)
        MOVL DX, 12(DI)
        RET
