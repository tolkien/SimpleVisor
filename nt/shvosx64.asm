;++
;
; Copyright (c) Alex Ionescu.  All rights reserved.
;
; Module:
;
;    shvvmxhvx64.asm
;
; Abstract:
;
;    This module implements AMD64-specific code for NT support of SimpleVisor.
;
; Author:
;
;    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version
;
; Environment:
;
;    Kernel mode only.
;
;--

include ksamd64.inc

    LEAF_ENTRY _str, _TEXT$00
        str word ptr [rcx]          ; Store TR value
        ret                         ; Return
    LEAF_END _str, _TEXT$00

    LEAF_ENTRY _sldt, _TEXT$00
        sldt word ptr [rcx]         ; Store LDTR value
        ret                         ; Return
    LEAF_END _sldt, _TEXT$00

    LEAF_ENTRY ShvVmxCleanup, _TEXT$00
        mov     ds, cx              ; set DS to parameter 1
        mov     es, cx              ; set ES to parameter 1
        mov     fs, dx              ; set FS to parameter 2
        ret                         ; return
    LEAF_END ShvVmxCleanup, _TEXT$00

    LEAF_ENTRY __lgdt, _TEXT$00
        lgdt    fword ptr [rcx]     ; load the GDTR with the value in parameter 1
        ret                         ; return
    LEAF_END __lgdt, _TEXT$00

    LEAF_ENTRY ShvOsRestoreContext , _TEXT$00

    movaps  xmm0, xmmword ptr [rcx+1A0h]
    movaps  xmm1, xmmword ptr [rcx+1B0h]
    movaps  xmm2, xmmword ptr [rcx+1C0h]
    movaps  xmm3, xmmword ptr [rcx+1D0h]
    movaps  xmm4, xmmword ptr [rcx+1E0h]
    movaps  xmm5, xmmword ptr [rcx+1F0h]
    movaps  xmm6, xmmword ptr [rcx+200h]
    movaps  xmm7, xmmword ptr [rcx+210h]
    movaps  xmm8, xmmword ptr [rcx+220h]
    movaps  xmm9, xmmword ptr [rcx+230h]
    movaps  xmm10, xmmword ptr [rcx+240h]
    movaps  xmm11, xmmword ptr [rcx+250h]
    movaps  xmm12, xmmword ptr [rcx+260h]
    movaps  xmm13, xmmword ptr [rcx+270h]
    movaps  xmm14, xmmword ptr [rcx+280h]
    movaps  xmm15, xmmword ptr [rcx+290h]
    ldmxcsr dword ptr [rcx+34h]

    mov     rax, [rcx+78h]
    mov     rdx, [rcx+88h]
    mov     r8, [rcx+0B8h]
    mov     r9, [rcx+0C0h]
    mov     r10, [rcx+0C8h]
    mov     r11, [rcx+0D0h]
    cli

    mov     rbx, [rcx+90h]
    mov     rsi, [rcx+0A8h]
    mov     rdi, [rcx+0B0h]
    mov     rbp, [rcx+0A0h]
    mov     r12, [rcx+0D8h]
    mov     r13, [rcx+0E0h]
    mov     r14, [rcx+0E8h]
    mov     r15, [rcx+0F0h]

    push    [rcx+44h]
    popfq

    mov     rsp, [rcx+98h]
    push    [rcx+0F8h]

    mov     rcx, [rcx+80h]
    ret
    LEAF_END ShvOsRestoreContext, _TEXT$00

    end
