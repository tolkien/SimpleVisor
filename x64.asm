
EXTERN ShvVmxEntryHandler : PROC
EXTERN RtlCaptureContext : PROC

.CODE

ShvVmxEntry PROC
    push rcx
    lea rcx, [rsp+8h]
    call RtlCaptureContext
    jmp ShvVmxEntryHandler
ShvVmxEntry ENDP

ShvVmxCleanup PROC
    mov ds, cx
    mov es, cx
    mov fs, dx
    ret
ShvVmxCleanup ENDP

__lgdt PROC
    lgdt fword ptr [rcx]
    ret
__lgdt ENDP

END
