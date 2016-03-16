/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    shvvmxhv.c

Abstract:

    This module implements the Simple Hyper Visor itself.

Author:

    Alex Ionescu (alex.ionescu@reactos.com)   16-Mar-2016

Environment:

    Hypervisor mode only.

--*/

#include "shv.h"

DECLSPEC_NORETURN
VOID
ShvVmxResume (
    VOID
    )
{
    __vmx_vmresume();
}

ULONG_PTR
ShvVmxRead (
    _In_ ULONG VmcsFieldId
    )
{
    SIZE_T FieldData;

    __vmx_vmread(VmcsFieldId, &FieldData);

    return FieldData;
}

VOID
ShvVmxHandleInvd (
    VOID
    )
{
    __wbinvd();
}

VOID
ShvVmxHandleCpuid (
    _In_ PSHV_VP_STATE VpState
    )
{
    INT cpu_info[4];

    if ((VpState->VpRegs->Rax == 0x41414141) &&
        (VpState->VpRegs->Rcx == 0x42424242) &&
        ((ShvVmxRead(GUEST_CS_SELECTOR) & RPL_MASK) == DPL_SYSTEM))
    {
        VpState->ExitVm = TRUE;
        return;
    }

    __cpuidex(cpu_info, (INT)VpState->VpRegs->Rax, (INT)VpState->VpRegs->Rcx);

    if (VpState->VpRegs->Rax == 1)
    {
        cpu_info[2] |= 0x80000000;
    }

    VpState->VpRegs->Rax = cpu_info[0];
    VpState->VpRegs->Rbx = cpu_info[1];
    VpState->VpRegs->Rcx = cpu_info[2];
    VpState->VpRegs->Rdx = cpu_info[3];
}

VOID
ShvVmxHandleXsetbv (
    _In_ PSHV_VP_STATE VpState
    )
{
    _xsetbv((ULONG)VpState->VpRegs->Rcx,
            VpState->VpRegs->Rdx << 32 |
            VpState->VpRegs->Rax);
}

VOID
ShvVmxHandleVmx (
    _In_ PSHV_VP_STATE VpState
    )
{
    VpState->GuestEFlags |= 0x1; // VM_FAIL_INVALID
    __vmx_vmwrite(GUEST_RFLAGS, VpState->GuestEFlags);
}

VOID
ShvVmxHandleExit (
    _In_ PSHV_VP_STATE VpState
    )
{
    switch (VpState->ExitReason)
    {
    case EXIT_REASON_CPUID:
        ShvVmxHandleCpuid(VpState);
        break;
    case EXIT_REASON_INVD:
        ShvVmxHandleInvd();
        break;
    case EXIT_REASON_XSETBV:
        ShvVmxHandleXsetbv(VpState);
        break;
    case EXIT_REASON_VMCALL:
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
        ShvVmxHandleVmx(VpState);
        break;
    default:
        NT_ASSERT(FALSE);
        break;
    }

    VpState->GuestRip += ShvVmxRead(VM_EXIT_INSTRUCTION_LEN);
    __vmx_vmwrite(GUEST_RIP, VpState->GuestRip);
}

DECLSPEC_NORETURN
EXTERN_C
VOID
ShvVmxEntryHandler (
    _In_ PCONTEXT Context
    )
{
    SHV_VP_STATE guestContext;
    PSHV_VP_DATA vpData;

    KeRaiseIrql(CLOCK_LEVEL - 1, &guestContext.GuestIrql);

    Context->Rcx = *(PULONG64)((ULONG_PTR)Context - sizeof(Context->Rcx));
    Context->Rsp += sizeof(Context->Rcx);

    vpData = &ShvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)];

    guestContext.GuestEFlags = ShvVmxRead(GUEST_RFLAGS);
    guestContext.GuestRip = ShvVmxRead(GUEST_RIP);
    guestContext.GuestRsp = ShvVmxRead(GUEST_RSP);
    guestContext.ExitReason = ShvVmxRead(VM_EXIT_REASON) & 0xFFFF;
    guestContext.VpRegs = Context;
    guestContext.ExitVm = FALSE;
    ShvVmxHandleExit(&guestContext);

    if (guestContext.ExitVm)
    {
        __lgdt(&vpData->HostState.SpecialRegisters.Gdtr.Limit);
        __lidt(&vpData->HostState.SpecialRegisters.Idtr.Limit);
        __writecr3(ShvVmxRead(GUEST_CR3));

        Context->Rsp = guestContext.GuestRsp;
        Context->Rip = (ULONG64)guestContext.GuestRip;

        __vmx_off();
    }
    else
    {
        Context->Rip = (ULONG64)ShvVmxResume;
    }

    KeLowerIrql(guestContext.GuestIrql);

    RtlRestoreContext(Context, NULL);
}

