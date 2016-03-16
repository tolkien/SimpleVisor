/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    shvvmx.c

Abstract:

    This module implements Intel VMX (Vanderpool/VT-x)-specific routines.

Author:

    Alex Ionescu (alex.ionescu@reactos.com)   16-Mar-2016

Environment:

    Kernel mode only.

--*/

#include "shv.h"

BOOLEAN
ShvVmxEnterRootModeOnVp (
    _In_ PSHV_VP_DATA VpData
    )
{
    PKSPECIAL_REGISTERS Registers = &VpData->HostState.SpecialRegisters;

    if (((VpData->MsrData[0].QuadPart & VMX_BASIC_MEMORY_TYPE_MASK) >> 50) != MTRR_TYPE_WB)
    {
        return FALSE;
    }

    if (((VpData->MsrData[0].QuadPart) & VMX_BASIC_DEFAULT1_ZERO) == 0)
    {
        return FALSE;
    }

    VpData->VmxOn.RevisionId = VpData->MsrData[0].LowPart;
    VpData->Vmcs.RevisionId = VpData->MsrData[0].LowPart;

    VpData->VmxOnPhysicalAddress = MmGetPhysicalAddress(&VpData->VmxOn).QuadPart;
    VpData->VmcsPhysicalAddress = MmGetPhysicalAddress(&VpData->Vmcs).QuadPart;
    VpData->MsrBitmapPhysicalAddress = MmGetPhysicalAddress(ShvGlobalData->MsrBitmap).QuadPart;

    Registers->Cr0 &= VpData->MsrData[7].LowPart;
    Registers->Cr0 |= VpData->MsrData[6].LowPart;

    Registers->Cr4 &= VpData->MsrData[9].LowPart;
    Registers->Cr4 |= VpData->MsrData[8].LowPart;

    __writecr0(Registers->Cr0);
    __writecr4(Registers->Cr4);

    if (__vmx_on(&VpData->VmxOnPhysicalAddress))
    {
        return FALSE;
    }
 
    if (__vmx_vmclear(&VpData->VmcsPhysicalAddress))
    {
        return FALSE;
    }

    if (__vmx_vmptrld(&VpData->VmcsPhysicalAddress))
    {
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
ShvVmxSetupVmcsForVp (
    _In_ PSHV_VP_DATA VpData
    )
{
    PKPROCESSOR_STATE state = &VpData->HostState;
    VMX_GDTENTRY64 vmxGdtEntry;
    ULONG error = 0;

    error |= __vmx_vmwrite(VMCS_LINK_POINTER, MAXULONG64);
    error |= __vmx_vmwrite(MSR_BITMAP, VpData->MsrBitmapPhysicalAddress);

    error |= __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL,
                           ShvUtilAdjustMsr(VpData->MsrData[11],
                                            SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_XSAVES));
    error |= __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL,
                           ShvUtilAdjustMsr(VpData->MsrData[13], 0));
    error |= __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL,
                           ShvUtilAdjustMsr(VpData->MsrData[14],
                                            CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS));
    error |= __vmx_vmwrite(VM_EXIT_CONTROLS,
                           ShvUtilAdjustMsr(VpData->MsrData[15],
                                            VM_EXIT_ACK_INTR_ON_EXIT | VM_EXIT_IA32E_MODE));
    error |= __vmx_vmwrite(VM_ENTRY_CONTROLS,
                           ShvUtilAdjustMsr(VpData->MsrData[16],
                                            VM_ENTRY_IA32E_MODE));

    ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegEs, &vmxGdtEntry);
    error |= __vmx_vmwrite(GUEST_ES_SELECTOR, vmxGdtEntry.Selector);
    error |= __vmx_vmwrite(GUEST_ES_LIMIT, vmxGdtEntry.Limit);
    error |= __vmx_vmwrite(GUEST_ES_AR_BYTES, vmxGdtEntry.AccessRights);
    error |= __vmx_vmwrite(GUEST_ES_BASE, vmxGdtEntry.Base);
    error |= __vmx_vmwrite(HOST_ES_SELECTOR, state->ContextFrame.SegEs & ~RPL_MASK);
 
    ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegCs, &vmxGdtEntry);
    error |= __vmx_vmwrite(GUEST_CS_SELECTOR, vmxGdtEntry.Selector);
    error |= __vmx_vmwrite(GUEST_CS_LIMIT, vmxGdtEntry.Limit);
    error |= __vmx_vmwrite(GUEST_CS_AR_BYTES, vmxGdtEntry.AccessRights);
    error |= __vmx_vmwrite(GUEST_CS_BASE, vmxGdtEntry.Base);
    error |= __vmx_vmwrite(HOST_CS_SELECTOR, state->ContextFrame.SegCs & ~RPL_MASK);
 
    ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegSs, &vmxGdtEntry);
    error |= __vmx_vmwrite(GUEST_SS_SELECTOR, vmxGdtEntry.Selector);
    error |= __vmx_vmwrite(GUEST_SS_LIMIT, vmxGdtEntry.Limit);
    error |= __vmx_vmwrite(GUEST_SS_AR_BYTES, vmxGdtEntry.AccessRights);
    error |= __vmx_vmwrite(GUEST_SS_BASE, vmxGdtEntry.Base);
    error |= __vmx_vmwrite(HOST_SS_SELECTOR, state->ContextFrame.SegSs & ~RPL_MASK);
 
    ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegDs, &vmxGdtEntry);
    error |= __vmx_vmwrite(GUEST_DS_SELECTOR, vmxGdtEntry.Selector);
    error |= __vmx_vmwrite(GUEST_DS_LIMIT, vmxGdtEntry.Limit);
    error |= __vmx_vmwrite(GUEST_DS_AR_BYTES, vmxGdtEntry.AccessRights);
    error |= __vmx_vmwrite(GUEST_DS_BASE, vmxGdtEntry.Base);
    error |= __vmx_vmwrite(HOST_DS_SELECTOR, state->ContextFrame.SegDs & ~RPL_MASK);
 
    ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegFs, &vmxGdtEntry);
    error |= __vmx_vmwrite(GUEST_FS_SELECTOR, vmxGdtEntry.Selector);
    error |= __vmx_vmwrite(GUEST_FS_LIMIT, vmxGdtEntry.Limit);
    error |= __vmx_vmwrite(GUEST_FS_AR_BYTES, vmxGdtEntry.AccessRights);
    error |= __vmx_vmwrite(GUEST_FS_BASE, vmxGdtEntry.Base);
    error |= __vmx_vmwrite(HOST_FS_BASE, vmxGdtEntry.Base);
    error |= __vmx_vmwrite(HOST_FS_SELECTOR, state->ContextFrame.SegFs & ~RPL_MASK);
 
    ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegGs, &vmxGdtEntry);
    error |= __vmx_vmwrite(GUEST_GS_SELECTOR, vmxGdtEntry.Selector);
    error |= __vmx_vmwrite(GUEST_GS_LIMIT, vmxGdtEntry.Limit);
    error |= __vmx_vmwrite(GUEST_GS_AR_BYTES, vmxGdtEntry.AccessRights);
    error |= __vmx_vmwrite(GUEST_GS_BASE, state->SpecialRegisters.MsrGsBase);
    error |= __vmx_vmwrite(HOST_GS_BASE, state->SpecialRegisters.MsrGsBase);
    error |= __vmx_vmwrite(HOST_GS_SELECTOR, state->ContextFrame.SegGs & ~RPL_MASK);
 
    ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Tr, &vmxGdtEntry);
    error |= __vmx_vmwrite(GUEST_TR_SELECTOR, vmxGdtEntry.Selector);
    error |= __vmx_vmwrite(GUEST_TR_LIMIT, vmxGdtEntry.Limit);
    error |= __vmx_vmwrite(GUEST_TR_AR_BYTES, vmxGdtEntry.AccessRights);
    error |= __vmx_vmwrite(GUEST_TR_BASE, vmxGdtEntry.Base);
    error |= __vmx_vmwrite(HOST_TR_BASE, vmxGdtEntry.Base);
    error |= __vmx_vmwrite(HOST_TR_SELECTOR, state->SpecialRegisters.Tr & ~RPL_MASK);
 
    ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Ldtr, &vmxGdtEntry);
    error |= __vmx_vmwrite(GUEST_LDTR_SELECTOR, vmxGdtEntry.Selector);
    error |= __vmx_vmwrite(GUEST_LDTR_LIMIT, vmxGdtEntry.Limit);
    error |= __vmx_vmwrite(GUEST_LDTR_AR_BYTES, vmxGdtEntry.AccessRights);
    error |= __vmx_vmwrite(GUEST_LDTR_BASE, vmxGdtEntry.Base);

    error |= __vmx_vmwrite(GUEST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base);
    error |= __vmx_vmwrite(GUEST_GDTR_LIMIT, state->SpecialRegisters.Gdtr.Limit);
    error |= __vmx_vmwrite(HOST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base);

    error |= __vmx_vmwrite(GUEST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base);
    error |= __vmx_vmwrite(GUEST_IDTR_LIMIT, state->SpecialRegisters.Idtr.Limit);
    error |= __vmx_vmwrite(HOST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base);

    error |= __vmx_vmwrite(GUEST_DR7, state->SpecialRegisters.KernelDr7);
    error |= __vmx_vmwrite(GUEST_RSP, state->ContextFrame.Rsp);
    error |= __vmx_vmwrite(GUEST_RIP, state->ContextFrame.Rip);
    error |= __vmx_vmwrite(GUEST_RFLAGS, state->ContextFrame.EFlags);

    error |= __vmx_vmwrite(CR0_READ_SHADOW, state->SpecialRegisters.Cr0);
    error |= __vmx_vmwrite(HOST_CR0, state->SpecialRegisters.Cr0);
    error |= __vmx_vmwrite(GUEST_CR0, state->SpecialRegisters.Cr0);

    error |= __vmx_vmwrite(HOST_CR3, VpData->SystemDirectoryTableBase);
    error |= __vmx_vmwrite(GUEST_CR3, state->SpecialRegisters.Cr3);

    error |= __vmx_vmwrite(HOST_CR4, state->SpecialRegisters.Cr4);
    error |= __vmx_vmwrite(GUEST_CR4, state->SpecialRegisters.Cr4);
    error |= __vmx_vmwrite(CR4_READ_SHADOW, state->SpecialRegisters.Cr4);

    error |= __vmx_vmwrite(GUEST_IA32_DEBUGCTL, state->SpecialRegisters.DebugControl);

    error |= __vmx_vmwrite(HOST_RSP, (ULONG_PTR)VpData->ShvStackLimit + KERNEL_STACK_SIZE - sizeof(CONTEXT));
    error |= __vmx_vmwrite(HOST_RIP, (ULONG_PTR)ShvVmxEntry);

    return error == 0;
}

BOOLEAN
ShvVmxProbe (
    VOID
    )
{
    INT cpu_info[4];
    ULONGLONG featureControl;

    __cpuid(cpu_info, 1);
    if ((cpu_info[2] & 0x20) == FALSE)
    {
        return FALSE;
    }

    featureControl = __readmsr(IA32_FEATURE_CONTROL_MSR);
    if (!(featureControl & IA32_FEATURE_CONTROL_MSR_LOCK))
    {
        return FALSE;
    }

    if (!(featureControl & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX))
    {
        return FALSE;
    }

    return TRUE;
}

VOID
ShvVmxLaunchOnVp (
    _In_ PSHV_VP_DATA VpData
    )
{
    if (ShvVmxEnterRootModeOnVp(VpData))
    {
        if (ShvVmxSetupVmcsForVp(VpData))
        {
            VpData->VmxEnabled = 1;
            __vmx_vmlaunch();
        }

        __vmx_off();
    }
}
