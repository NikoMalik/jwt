#include "go_asm.h"
#include "funcdata.h"
#include "textflag.h"

TEXT ·MoreStack(SB), $0-8
    NO_LOCAL_POINTERS
_entry:
    MOVQ (TLS), R14
    MOVQ size+0(FP), R12
    NOTQ R12
    LEAQ (SP)(R12*1), R12
    CMPQ R12, 16(R14)
    JBE  _stack_grow
    RET
_stack_grow:
    CALL runtime·morestack_noctxt<>(SB)
    JMP  _entry





