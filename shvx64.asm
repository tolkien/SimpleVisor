;++
;
; Copyright (c) Alex Ionescu.  All rights reserved.
;
; Module:
;
;    shvx64.asm
;
; Abstract:
;
;    This module implements AMD64-specific routines for the Simple Hyper Visor.
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

    extern ShvVmxEntryHandler:proc
    extern RtlCaptureContext:proc

    LEAF_ENTRY _str, _TEXT$00

    str word ptr [rcx]          ; Store TR value
    ret                         ; Return

    LEAF_END _str, _TEXT$00

    LEAF_ENTRY _sldt, _TEXT$00

    sldt word ptr [rcx]         ; Store LDTR value
    ret                         ; Return

    LEAF_END _sldt, _TEXT$00

    NESTED_ENTRY ShvVmxEntry, _TEXT$00

    push_reg rcx                ; save RCX, as we will need to orverride it
    END_PROLOGUE                ; done messing with the stack

    lea     rcx, [rsp+8h]       ; store the context in the stack, bias for
                                ; the return address and the push we just did.
    call    RtlCaptureContext   ; save the current register state.
                                ; note that this is a specially written function
                                ; which has the following key characteristics:
                                ;   1) it does not taint the value of RCX
                                ;   2) it does not spill any registers, nor
                                ;      expect home space to be allocated for it

    jmp     ShvVmxEntryHandler  ; jump to the C code handler. we assume that it
                                ; compiled with optimizations and does not use
                                ; home space, which is true of release builds.

    NESTED_END ShvVmxEntry, _TEXT$00

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

    end
