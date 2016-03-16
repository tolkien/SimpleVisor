#include "shv.h"

PSHV_GLOBAL_DATA ShvGlobalData;

VOID
ShvUtilConvertGdtEntry (
    _In_ PVOID GdtBase,
    _In_ USHORT Offset,
    _Out_ PVMX_GDTENTRY64 VmxGdtEntry
    )
{
    PKGDTENTRY64 gdtEntry;

    gdtEntry = (PKGDTENTRY64)((ULONG_PTR)GdtBase + (Offset & ~RPL_MASK));

    VmxGdtEntry->Selector = Offset;
    VmxGdtEntry->Limit = __segmentlimit(Offset);
    VmxGdtEntry->Base = ((gdtEntry->Bytes.BaseHigh << 24) |
                         (gdtEntry->Bytes.BaseMiddle << 16) |
                         (gdtEntry->BaseLow)) & MAXULONG;
    VmxGdtEntry->Base |= ((gdtEntry->Bits.Type & 0x10) == 0) ?
                         ((ULONG_PTR)gdtEntry->BaseUpper << 32) : 0;
    VmxGdtEntry->AccessRights = 0;
    VmxGdtEntry->Bytes.Flags1 = gdtEntry->Bytes.Flags1;
    VmxGdtEntry->Bytes.Flags2 = gdtEntry->Bytes.Flags2;
    VmxGdtEntry->Bits.Reserved = 0;
    VmxGdtEntry->Bits.Unusable = !gdtEntry->Bits.Present;
}

ULONG
ShvUtilAdjustMsr (
    _In_ LARGE_INTEGER ControlValue,
    _In_ ULONG DesiredValue
    )
{
    DesiredValue &= ControlValue.HighPart;
    DesiredValue |= ControlValue.LowPart;
    return DesiredValue;
}

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
ShvHandleInvd (
    VOID
    )
{
    __wbinvd();
}

VOID
ShvHandleCpuid (
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
ShvHandleXsetbv (
    _In_ PSHV_VP_STATE VpState
    )
{
    _xsetbv((ULONG)VpState->VpRegs->Rcx,
            VpState->VpRegs->Rdx << 32 |
            VpState->VpRegs->Rax);
}

VOID
ShvHandleVmx (
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
        ShvHandleCpuid(VpState);
        break;
    case EXIT_REASON_INVD:
        ShvHandleInvd();
        break;
    case EXIT_REASON_XSETBV:
        ShvHandleXsetbv(VpState);
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
        ShvHandleVmx(VpState);
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

BOOLEAN
ShvVpEnterVmx (
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
ShvVpInitializeVmcs (
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

VOID
ShvVpInitialize (
    _In_ PSHV_VP_DATA Data
    )
{
    KeSaveStateForHibernate(&Data->HostState);
    RtlCaptureContext(&Data->HostState.ContextFrame);

    if (ShvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)].VmxEnabled == 1)
    {
        ShvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)].VmxEnabled = 2;

        RtlRestoreContext(&ShvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)].HostState.ContextFrame, NULL);
    }
    else if (Data->VmxEnabled == 0)
    {
        if (ShvVpEnterVmx(Data))
        {
            if (ShvVpInitializeVmcs(Data))
            {
                Data->VmxEnabled = 1;
                __vmx_vmlaunch();
            }

            __vmx_off();
        }
    }
}

VOID
ShvVpUninitialize (
    _In_ PSHV_VP_DATA VpData
    )
{
    INT dummy[4];
    UNREFERENCED_PARAMETER(VpData);

    __cpuidex(dummy, 0x41414141, 0x42424242);
    ShvVmxCleanup(KGDT64_R3_DATA | RPL_MASK, KGDT64_R3_CMTEB | RPL_MASK);
}

VOID
ShvVpVmxDpc (
    _In_ PRKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PSHV_VP_DATA vpData;
    ULONG i;
    UNREFERENCED_PARAMETER(Dpc);

    vpData = &ShvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)];

    if (Context)
    {
        vpData->VpIndex = KeGetCurrentProcessorNumberEx(NULL);
        vpData->SystemDirectoryTableBase = (ULONG64)Context;
        __stosq((PULONGLONG)vpData->ShvStackLimit, 0xCC, KERNEL_STACK_SIZE / sizeof(ULONGLONG));

        for (i = 0; i < RTL_NUMBER_OF(vpData->MsrData); i++)
        {
            vpData->MsrData[i].QuadPart = __readmsr(MSR_IA32_VMX_BASIC + i);
        }

        ShvVpInitialize(vpData);
    }
    else
    {
        ShvVpUninitialize(vpData);
    }

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

PSHV_GLOBAL_DATA
ShvMemInitialize (
    VOID
    )
{
    PHYSICAL_ADDRESS lowest, highest;
    PSHV_GLOBAL_DATA data;
    ULONG cpuCount, size;

    lowest.QuadPart = 0;
    highest.QuadPart = -1;

    cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    size = FIELD_OFFSET(SHV_GLOBAL_DATA, VpData) + cpuCount * sizeof(SHV_VP_DATA);

    data = (PSHV_GLOBAL_DATA)MmAllocateContiguousNodeMemory(size,
                                                            lowest,
                                                            highest,
                                                            lowest,
                                                            PAGE_READWRITE,
                                                            MM_ANY_NODE_OK);
    if (data != NULL)
    {
        __stosq((PULONGLONG)data, 0, size / sizeof(ULONGLONG));
    }

    return data;
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

NTSTATUS
ShvInitialize (
    VOID
    )
{
    if (HviIsAnyHypervisorPresent())
    {
        return STATUS_HV_OBJECT_IN_USE;
    }

    if (!ShvVmxProbe())
    {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    ShvGlobalData = ShvMemInitialize();
    if (!ShvGlobalData) 
    {
        return STATUS_HV_INSUFFICIENT_BUFFER;
    }

    KeGenericCallDpc(ShvVpVmxDpc, (PVOID)__readcr3());

    if (HviIsAnyHypervisorPresent() == FALSE)
    {
        MmFreeContiguousMemory(ShvGlobalData);
        ShvGlobalData = NULL;
        return STATUS_HV_NOT_PRESENT;
    }

    return STATUS_SUCCESS;
}

VOID
ShvUnload (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    KeGenericCallDpc(ShvVpVmxDpc, NULL);

    if (ShvGlobalData != NULL)
    {
        MmFreeContiguousMemory(ShvGlobalData);
    }

    DbgPrintEx(77, 0, "The SHV has been uninstalled.\n");
}

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = ShvUnload;

    Status = ShvInitialize();
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    DbgPrintEx(77, 0, "The SHV has been installed.\n");
    return Status;
}
