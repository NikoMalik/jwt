#include "textflag.h"
#include "go_asm.h"
#include "funcdata.h"




DATA MASK1<>+0x00(SB)/8, $2
DATA MASK1<>+0x08(SB)/8, $6
DATA MASK1<>+0x10(SB)/8, $10
DATA MASK1<>+0x18(SB)/8, $14
DATA MASK1<>+0x20(SB)/8, $0x80
DATA MASK1<>+0x28(SB)/8, $0x80
DATA MASK1<>+0x30(SB)/8, $0x80
DATA MASK1<>+0x38(SB)/8, $0x80
DATA MASK1<>+0x40(SB)/8, $0x80 
DATA MASK1 <>+0x48(SB)/8, $0x80
DATA MASK1<>+0x50(SB)/8, $0x80
DATA MASK1<>+0x58(SB)/8, $0x80
DATA MASK1<>+0x60(SB)/8, $0x80
DATA MASK1<>+0x68(SB)/8, $0x80
DATA MASK1<>+0x70(SB)/8, $0x80
DATA MASK1<>+0x78(SB)/8, $0x80
DATA MASK1<>+0x80(SB)/8, $2 
DATA MASK1<>+0x88(SB)/8, $6
DATA MASK1<>+0x90(SB)/8, $10
DATA MASK1<>+0x98(SB)/8, $14
DATA MASK1<>+0xA0(SB)/8, $0x80
DATA MASK1<>+0xA8(SB)/8, $0x80
DATA MASK1<>+0xB0(SB)/8, $0x80
DATA MASK1<>+0xB8(SB)/8, $0x80
DATA MASK1<>+0xC0(SB)/8, $0x80
DATA MASK1<>+0xC8(SB)/8, $0x80
DATA MASK1<>+0xD0(SB)/8, $0x80
DATA MASK1<>+0xD8(SB)/8, $0x80
DATA MASK1<>+0xE0(SB)/8, $0x80
DATA MASK1<>+0xE8(SB)/8, $0x80
DATA MASK1<>+0xF0(SB)/8, $0x80
DATA MASK1<>+0xF8(SB)/8, $0x80


GLOBL MASK1(SB),RODATA|NOPTR,  $32



DATA MASK2<>+0x00(SB)/8, $0x80
DATA MASK2<>+0x08(SB)/8, $0x80
DATA MASK2<>+0x10(SB)/8, $0x80
DATA MASK2<>+0x18(SB)/8, $0x80
DATA MASK2<>+0x20(SB)/8, $2
DATA MASK2<>+0x28(SB)/8, $6
DATA MASK2<>+0x30(SB)/8, $0xA
DATA MASK2<>+0x38(SB)/8, $0xE
DATA MASK2<>+0x40(SB)/8, $0x80
DATA MASK2<>+0x48(SB)/8, $0x80
DATA MASK2<>+0x50(SB)/8, $0x80
DATA MASK2<>+0x58(SB)/8, $0x80
DATA MASK2<>+0x60(SB)/8, $0x80
DATA MASK2<>+0x68(SB)/8, $0x80
DATA MASK2<>+0x70(SB)/8, $0x80
DATA MASK2<>+0x78(SB)/8, $0x80
DATA MASK2<>+0x80(SB)/8, $0x80
DATA MASK2<>+0x88(SB)/8, $0x80
DATA MASK2<>+0x90(SB)/8, $0x80
DATA MASK2<>+0x98(SB)/8, $0x80
DATA MASK2<>+0xA0(SB)/8, $2
DATA MASK2<>+0xA8(SB)/8, $6
DATA MASK2<>+0xB0(SB)/8, $10
DATA MASK2<>+0xB8(SB)/8, $14 
DATA MASK2<>+0xC0(SB)/8, $0x80
DATA MASK2<>+0xC8(SB)/8, $0x80
DATA MASK2<>+0xD0(SB)/8, $0x80
DATA MASK2<>+0xD8(SB)/8, $0x80
DATA MASK2<>+0xE0(SB)/8, $0x80
DATA MASK2<>+0xE8(SB)/8, $0x80
DATA MASK2<>+0xF0(SB)/8, $0x80
DATA MASK2<>+0xF8(SB)/8, $0x80

GLOBL MASK2(SB),RODATA|NOPTR, $32

DATA MASK3<>+0x00(SB)/8, $0x80
DATA MASK3<>+0x08(SB)/8, $0x80
DATA MASK3<>+0x10(SB)/8, $0x80
DATA MASK3<>+0x18(SB)/8, $0x80
DATA MASK3<>+0x20(SB)/8, $0x80
DATA MASK3<>+0x28(SB)/8, $0x80
DATA MASK3<>+0x30(SB)/8, $0x80
DATA MASK3<>+0x38(SB)/8, $0x80
DATA MASK3<>+0x40(SB)/8, $2
DATA MASK3<>+0x48(SB)/8, $6
DATA MASK3<>+0x50(SB)/8, $0xA
DATA MASK3<>+0x58(SB)/8, $0xE
DATA MASK3<>+0x60(SB)/8, $0x80
DATA MASK3<>+0x68(SB)/8, $0x80
DATA MASK3<>+0x70(SB)/8, $0x80
DATA MASK3<>+0x78(SB)/8, $0x80
DATA MASK3<>+0x80(SB)/8, $0x80
DATA MASK3<>+0x88(SB)/8, $0x80
DATA MASK3<>+0x90(SB)/8, $0x80
DATA MASK3<>+0x98(SB)/8, $0x80
DATA MASK3<>+0xA0(SB)/8, $0x80
DATA MASK3<>+0xA8(SB)/8, $0x80
DATA MASK3<>+0xB0(SB)/8, $0x80
DATA MASK3<>+0xB8(SB)/8, $0x80
DATA MASK3<>+0xC0(SB)/8, $2
DATA MASK3<>+0xC8(SB)/8, $6
DATA MASK3<>+0xD0(SB)/8, $0xA
DATA MASK3<>+0xD8(SB)/8, $0xE
DATA MASK3<>+0xE0(SB)/8, $0x80
DATA MASK3<>+0xE8(SB)/8, $0x80
DATA MASK3<>+0xF0(SB)/8, $0x80
DATA MASK3<>+0xF8(SB)/8, $0x80

GLOBL MASK3(SB),RODATA|NOPTR, $32

DATA MASK4<>+0x00(SB)/8, $0x80
DATA MASK4<>+0x08(SB)/8, $0x80
DATA MASK4<>+0x10(SB)/8, $0x80
DATA MASK4<>+0x18(SB)/8, $0x80
DATA MASK4<>+0x20(SB)/8, $0x80
DATA MASK4<>+0x28(SB)/8, $0x80
DATA MASK4<>+0x30(SB)/8, $0x80
DATA MASK4<>+0x38(SB)/8, $0x80
DATA MASK4<>+0x40(SB)/8, $0x80
DATA MASK4<>+0x48(SB)/8, $0x80
DATA MASK4<>+0x50(SB)/8, $0x80
DATA MASK4<>+0x58(SB)/8, $0x80
DATA MASK4<>+0x60(SB)/8, $2
DATA MASK4<>+0x68(SB)/8, $6
DATA MASK4<>+0x70(SB)/8, $0xA
DATA MASK4<>+0x78(SB)/8, $0xE
DATA MASK4<>+0x80(SB)/8, $0x80
DATA MASK4<>+0x88(SB)/8, $0x80
DATA MASK4<>+0x90(SB)/8, $0x80
DATA MASK4<>+0x98(SB)/8, $0x80
DATA MASK4<>+0xA0(SB)/8, $0x80
DATA MASK4<>+0xA8(SB)/8, $0x80
DATA MASK4<>+0xB0(SB)/8, $0x80
DATA MASK4<>+0xB8(SB)/8, $0x80
DATA MASK4<>+0xC0(SB)/8, $0x80
DATA MASK4<>+0xC8(SB)/8, $0x80
DATA MASK4<>+0xD0(SB)/8, $0x80
DATA MASK4<>+0xD8(SB)/8, $0x80
DATA MASK4<>+0xE0(SB)/8, $2
DATA MASK4<>+0xE8(SB)/8, $6
DATA MASK4<>+0xF0(SB)/8, $0xA
DATA MASK4<>+0xF8(SB)/8, $0xE




GLOBL MASK4(SB),RODATA|NOPTR,  $32

DATA P_MASK<>+0x00(SB)/8, $0
DATA P_MASK<>+0x08(SB)/8, $4
DATA P_MASK<>+0x10(SB)/8, $1
DATA P_MASK<>+0x18(SB)/8, $5
DATA P_MASK<>+0x20(SB)/8, $2
DATA P_MASK<>+0x28(SB)/8, $6
DATA P_MASK<>+0x30(SB)/8, $3
DATA P_MASK<>+0x38(SB)/8, $7
// 8
GLOBL P_Mask(SB),RODATA|NOPTR,  $32


//TEXT ·hasAVX2(SB), NOSPLIT, $0-1
//    MOVQ ·cpuid(SB), AX    
//    BTL $0x08, AX                
//    SETCC AL                  
//    MOVBQZX AL, AX               
//    RET

//if len < 32, dont' use avx2
TEXT ·copy_AVX2_32(SB), NOSPLIT , $0-48
	MOVQ dst_data+0(FP),  DI
	MOVQ src_data+24(FP), SI
	MOVQ src_len+32(FP),      BX
    XORQ AX, AX

LOOP:
	VMOVDQU 0(SI)(AX*1), Y0
	VMOVDQU Y0, 0(DI)(AX*1)

    
	ADDQ $32, AX
	CMPQ AX, BX
	JL   LOOP
	RET


TEXT ·copy_AVX2_64(SB), NOSPLIT , $0-48
    MOVQ dst_data+0(FP),  DI
    MOVQ src_data+24(FP), SI
    MOVQ src_len+32(FP),      BX
    XORQ AX, AX

LOOP:

    //VMOVDQU 0(SI)(AX*1), Y0 

    //VMOVDQU Y0, 0(DI)(AX*1) 


    //ADDQ $32, AX 

    //CMPQ AX, BX 
    //JGE END 


    //VMOVDQU 0(SI)(AX*1), Y1 

    //VMOVDQU Y1, 0(DI)(AX*1) 


    //ADDQ $32, AX 
    //CMPQ AX, BX 
    //JL LOOP 
    //RET

    VMOVDQU 0(SI)(AX*1), Y0 

    VMOVDQU  32(SI)(AX*1),Y1

    VMOVDQU Y0, 0(DI)(AX*1)

    VMOVDQU Y1, 32(DI)(AX*1)


    ADDQ $64, AX 

    CMPQ AX, BX 
    JL LOOP 
    RET




TEXT ·copy_AVX2_128(SB), NOSPLIT , $0-48
    MOVQ dst_data+0(FP),  DI
    MOVQ src_data+24(FP), SI
    MOVQ src_len+32(FP),      BX
    XORQ AX,AX

LOOP:
    // load 128 byte (4 * 32 byte) for once
    VMOVDQU 0(SI)(AX*1), Y0
    VMOVDQU 32(SI)(AX*1), Y1
    VMOVDQU 64(SI)(AX*1), Y2
    VMOVDQU 96(SI)(AX*1), Y3

    // save 128 bytes
    VMOVDQU Y0, 0(DI)(AX*1)
    VMOVDQU Y1, 32(DI)(AX*1)
    VMOVDQU Y2, 64(DI)(AX*1)
    VMOVDQU Y3, 96(DI)(AX*1)

    // count 128 index
    ADDQ $128, AX

    // check 
    CMPQ AX, BX
    JL LOOP   

    RET      


TEXT ·copy_AVX2_256(SB), NOSPLIT , $0-24 // TODO: finnaly this sh
    MOVQ dst_data+0(FP),  DI
    MOVQ src_data+24(FP), SI
    MOVQ src_len+32(FP),      BX
    XORQ AX,AX

LOOP:
    VMOVDQU 0(SI)(AX*1), Y0
    VMOVDQU Y0, 0(DI)(AX*1)
    ADDQ $128,AX 
    CMPQ AX, BX
    JGE END

    VMOVDQU 0(SI)(AX*1), Y1
    VMOVDQU Y1, 0(DI)(AX*1)
    ADDQ $128,AX
    CMPQ AX, BX
    JL LOOP

    CMPQ AX, BX
    JL   LOOP
    RET
END:
    RET


//use from 512
TEXT ·_copy_(SB),NOSPLIT, $0-48
    MOVQ    dst_base+0x00(FP), AX
   	MOVQ    src_base+0x18(FP), CX
	MOVQ    dst_len+0x08(FP), DX
	MOVQ    src_len+0x20(FP), BX

   	CMPQ    BX, DX
	CMOVQLT BX, DX
	MOVQ    DX, ret+0x30(FP)
    VMOVDQU MASK1+0(SB), Y10     // Load MASK1 into Y10 register
    VMOVDQU MASK2+8(SB), Y11     // Load MASK2 into Y11 register
    VMOVDQU MASK3+16(SB), Y12     // Load MASK3 into Y12 register
    VMOVDQU MASK4+24(SB), Y13     // Load MASK4 into Y13 register
    VMOVDQU P_Mask+32(SB), Y14    // Load P_Mask into Y14 register


tail:
	CMPQ DX,$0x00
    JEQ   done



	CMPQ DX, $0x02
    JBE   handle1to2



	CMPQ DX, $0x03
	JBE  handle2to3



	CMPQ DX, $0x04
	JE   handle4



	CMPQ DX, $0x08
	JE   handle8
	JB   handle5to7





	CMPQ DX, $0x10
	JBE  handle9to16


	CMPQ DX, $32 
    BTL  $0x08, ·X86+0(SB)
    JCC  handle17to32
    JBE avx2_tail_1to32
    
    CALL ·copy_AVX2_32+0(SB)
    


	CMPQ DX, $0x40 // 64
    BTL  $0x08, ·X86+8(SB)
	JCC  handle33to64
    JB avx2_tail

    CALL ·copy_AVX2_64+0(SB)
   
   
    //CALL ·copy_AVX2(SB)
	CMPQ DX, $0x00000080 
    JB   avx2_tail
    CALL ·copy_AVX2_128+0(SB)
	//JMP  avx2

    CMPQ DX, $0x00000100
    JB   avx2_tail
    JMP  avx2

// runtime·memmove(SB)
done:
	RET

handle1to2:
    MOVB (CX), AX              // Load the first byte from source (CX) to AX
    MOVB -1(CX)(DX*1), CL      // Load the second byte from source (CX + DX) into CL
    MOVB 1(CX), CL             // Load the third byte from source (CX + 1) into CL
    MOVB CL, 1(AX)             // Store the byte in the destination (AX + 1)
    RET

handle1:
    MOVB (CX), CL 
    MOVB CL, (AX)
    RET            

handle2to3:
	CMPQ DX, 2                
    JE handle2               
    MOVW (CX), BX           
    MOVB 2(CX), CL         
    MOVW BX, (AX)         
    MOVB CL, 2(AX)       
    RET                 

handle2:
    MOVW (CX), BX      
    MOVW BX, (AX)     
    RET


generic:
    MOVOU (CX), X0                     // Load 128 bits from CX into X0
    MOVOU 16(CX), X1                   // Load next 128 bits from CX+16 into X1
    MOVOU 32(CX), X2                   // Load next 128 bits from CX+32 into X2
    MOVOU 48(CX), X3                   // Load next 128 bits from CX+48 into X3
    
    MOVOU X0, (AX)                     // Store 128 bits from X0 into AX
    MOVOU X1, 16(AX)                   // Store 128 bits from X1 into AX+16
    MOVOU X2, 32(AX)                   // Store 128 bits from X2 into AX+32
    MOVOU X3, 48(AX)                   // Store 128 bits from X3 into AX+48
    
    PAND  X1, X0                       // Perform bitwise AND between X0 and X1
    PAND  X3, X2                       // Perform bitwise AND between X2 and X3
    PAND  X5, X4                       // Example additional bitwise AND operation
    PAND  X7, X6                       // Example additional bitwise AND operation

    MOVOU X0, (AX)                     // Store results back to memory (AX)
    MOVOU X2, 16(AX)                   // Store results at AX+16
    MOVOU X4, 32(AX)                   // Store results at AX+32
    MOVOU X6, 48(AX)                   // Store results at AX+48

    ADDQ  $0x40, CX                    // Move source pointer forward by 64 bytes
    ADDQ  $0x40, AX                    // Move destination pointer forward by 64 bytes
    SUBQ  $0x40, DX                    // Decrease the remaining length (DX)

    CMPQ  DX, $0x40                     // If remaining length <= 64, jump to tail
    JBE   tail

    JMP   generic                       // Otherwise, continue processing more data


handle4:
	MOVL (CX), CX
	MOVL CX, (AX)
	RET

handle5to7:
	MOVL (CX), BX
	MOVL -4(CX)(DX*1), CX
	MOVL BX, (AX)
	MOVL CX, -4(AX)(DX*1)
	RET

handle8:
	MOVQ (CX), CX
	MOVQ CX, (AX)
	RET

handle9to16:
	MOVQ (CX), BX
	MOVQ -8(CX)(DX*1), CX
	MOVQ BX, (AX)
	MOVQ CX, -8(AX)(DX*1)
	RET

handle17to32:
	MOVOU (CX), X0
	MOVOU -16(CX)(DX*1), X1
	MOVOU X0, (AX)
	MOVOU X1, -16(AX)(DX*1)
	RET

handle33to64:
	MOVOU (CX), X0
	MOVOU 16(CX), X1
	MOVOU -32(CX)(DX*1), X2
	MOVOU -16(CX)(DX*1), X3
	MOVOU X0, (AX)
	MOVOU X1, 16(AX)
	MOVOU X2, -32(AX)(DX*1)
	MOVOU X3, -16(AX)(DX*1)
	RET

avx:
    VMOVDQU 0(CX)(SI*1),Y0 
    VMOVDQU Y0, 0(AX)(SI*1)
    ADDQ $32, SI
    CMPQ SI, DX
    JZ avx2_done
    JAE   avx

avx2:
    VMOVDQU (CX), Y0
	VMOVDQU 32(CX), Y1
	VMOVDQU 64(CX), Y2
	VMOVDQU 96(CX), Y3
	VMOVDQU Y0, (AX)
	VMOVDQU Y1, 32(AX)
	VMOVDQU Y2, 64(AX)
	VMOVDQU Y3, 96(AX)

    VPSHUFB Y10, Y0, Y0
    VPSHUFB Y11, Y1, Y1
    VPSHUFB Y12, Y2, Y2
    VPSHUFB Y13, Y3, Y3
    
    VPOR Y0, Y1, Y0 
    VPOR Y2, Y3, Y2
    VPOR Y0, Y2, Y0

    VPERMD Y0,Y14,Y0

    VMOVDQU Y0, (CX)
    VMOVDQU Y0, (AX)
	ADDQ    $0x20, CX
	ADDQ    $0x20, AX
	SUBQ    $0x20, DX
	JZ      avx2_done
	CMPQ    DX, CX
	JAE     avx2

avx2_tail:
	CMPQ    DX, $0x40
	JBE     avx2_tail_1to64
	VMOVDQU (CX), Y0
	VMOVDQU 32(CX), Y1
	VMOVDQU -64(CX)(DX*1), Y2
	VMOVDQU -32(CX)(DX*1), Y3
	VMOVDQU Y0, (AX)
	VMOVDQU Y1, 32(AX)
	VMOVDQU Y2, -64(AX)(DX*1)
	VMOVDQU Y3, -32(AX)(DX*1)
	JMP     avx2_done

avx2_tail_1to64:
	VMOVDQU -64(CX)(DX*1), Y0
	VMOVDQU -32(CX)(DX*1), Y1
	VMOVDQU Y0, -64(AX)(DX*1)
	VMOVDQU Y1, -32(AX)(DX*1)


avx2_tail_1to32:
    VMOVDQU (CX), Y0
    VMOVDQU -32(CX)(DX*1), Y1
    VMOVDQU Y0, (AX)
    VMOVDQU Y1, -32(AX)(DX*1)



avx2_done:
	VZEROUPPER
	RET


