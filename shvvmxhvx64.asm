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

    end
