/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shvvp.c

Abstract:

    This module implements Virtual Processor (VP) management for the Simple Hyper Visor.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Kernel mode only, IRQL DISPATCH_LEVEL.

--*/

#include "shv.h"

BOOLEAN
ShvIsOurHypervisorPresent (
    VOID
    )
{
    INT cpuInfo[4];

    //
    // Check if ECX[31h] ("Hypervisor Present Bit") is set in CPUID 1h
    //
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & HYPERV_HYPERVISOR_PRESENT_BIT)
    {
        //
        // Next, check if this is a compatible Hypervisor, and if it has the
        // SimpleVisor signature
        //
        __cpuid(cpuInfo, HYPERV_CPUID_INTERFACE);
        if (cpuInfo[0] == ' vhS')
        {
            //
            // It's us!
            //
            return TRUE;
        }
    }

    //
    // No Hypervisor, or someone else's
    //
    return FALSE;
}

VOID
ShvCaptureSpecialRegisters (
    _In_ PSHV_SPECIAL_REGISTERS SpecialRegisters
    )
{
    //
    // Use compiler intrinsics to get the data we need
    //
    SpecialRegisters->Cr0 = __readcr0();
    SpecialRegisters->Cr3 = __readcr3();
    SpecialRegisters->Cr4 = __readcr4();
    SpecialRegisters->DebugControl = __readmsr(MSR_DEBUG_CTL);
    SpecialRegisters->MsrGsBase = __readmsr(MSR_GS_BASE);
    SpecialRegisters->KernelDr7 = __readdr(7);
    _sgdt(&SpecialRegisters->Gdtr.Limit);
    __sidt(&SpecialRegisters->Idtr.Limit);

    //
    // Use assembly to get these two
    //
    _str(&SpecialRegisters->Tr);
    _sldt(&SpecialRegisters->Ldtr);
}

DECLSPEC_NORETURN
VOID
ShvVpRestoreAfterLaunch (
    VOID
    )
{
    PSHV_VP_DATA vpData;

    //
    // Get the per-processor data. This routine temporarily executes on the
    // same stack as the hypervisor (using no real stack space except the home
    // registers), so we can retrieve the VP the same way the hypervisor does.
    //
    vpData = (PSHV_VP_DATA)((ULONG_PTR)_AddressOfReturnAddress() +
                            sizeof(CONTEXT) -
                            KERNEL_STACK_SIZE);

    //
    // Record that VMX is now enabled by returning back to ShvVpInitialize with
    // the Alignment Check (AC) bit set.
    //
    vpData->ContextFrame.EFlags |= EFLAGS_ALIGN_CHECK;

    //
    // And finally, restore the context, so that all register and stack
    // state is finally restored.
    //
    ShvOsRestoreContext(&vpData->ContextFrame);
}

VOID
ShvVpInitialize (
    _In_ PSHV_VP_DATA Data
    )
{
    //
    // Read the special control registers for this processor
    // Note: KeSaveStateForHibernate(&Data->HostState) can be used as a Windows
    // specific undocumented function that can also get this data.
    //
    ShvCaptureSpecialRegisters(&Data->SpecialRegisters);

    //
    // Then, capture the entire register state. We will need this, as once we
    // launch the VM, it will begin execution at the defined guest instruction
    // pointer, which we set to ShvVpRestoreAfterLaunch, with the registers set
    // to whatever value they were deep inside the VMCS/VMX inialization code.
    // By using RtlRestoreContext, that function sets the AC flag in EFLAGS and
    // returns here with our registers restored.
    //
    RtlCaptureContext(&Data->ContextFrame);
    if ((__readeflags() & EFLAGS_ALIGN_CHECK) == 0)
    {
        //
        // If the AC bit is not set in EFLAGS, it means that we have not yet
        // launched the VM. Attempt to initialize VMX on this processor.
        //
        ShvVmxLaunchOnVp(Data);
    }
}

VOID
ShvVpUnloadCallback (
    _In_ PSHV_CALLBACK_CONTEXT Context
    )
{
    INT cpuInfo[4];
    PSHV_VP_DATA vpData;
    UNREFERENCED_PARAMETER(Context);

    //
    // Send the magic shutdown instruction sequence. It will return in EAX:EBX
    // the VP data for the current CPU, which we must free.
    //
    __cpuidex(cpuInfo, 0x41414141, 0x42424242);
    vpData = (PSHV_VP_DATA)((ULONG64)cpuInfo[0] << 32 | cpuInfo[1]);
    ShvOsFreeContiguousAlignedMemory(vpData);

    //
    // The processor will return here after the hypervisor issues a VMXOFF
    // instruction and restores the CPU context to this location. Unfortunately
    // because this is done with RtlRestoreContext which returns using "iretq",
    // this causes the processor to remove the RPL bits off the segments. As
    // the x64 kernel does not expect kernel-mode code to change the value of
    // any segments, this results in the DS and ES segments being stuck 0x20,
    // and the FS segment being stuck at 0x50, until the next context switch.
    //
    // If the DPC happened to have interrupted either the idle thread or system
    // thread, that's perfectly fine (albeit unusual). If the DPC interrupted a
    // 64-bit long-mode thread, that's also fine. However if the DPC interrupts
    // a thread in compatibility-mode, running as part of WoW64, it will hit a
    // GPF instantenously and crash.
    //
    // Thus, set the segments to their correct value, one more time, as a fix.
    //
    ShvVmxCleanup(KGDT64_R3_DATA | RPL_MASK, KGDT64_R3_CMTEB | RPL_MASK);
}

PSHV_VP_DATA
ShvVpAllocateData (
    VOID
    )
{
    PSHV_VP_DATA data;

    //
    // Allocate a contiguous chunk of RAM to back this allocation
    data = ShvOsAllocateContigousAlignedMemory(sizeof(*data));
    if (data != NULL)
    {
        //
        // Zero out the entire data region
        //
        __stosq((PULONG64)data, 0, sizeof(*data) / sizeof(ULONG64));
    }

    //
    // Return what is hopefully a valid pointer, otherwise NULL.
    //
    return data;
}

VOID
ShvVpLoadCallback (
    _In_ PSHV_CALLBACK_CONTEXT Context
    )
{
    ULONG cpuIndex;
    PSHV_VP_DATA vpData;
    NTSTATUS status;

    //
    // Detect if the hardware appears to support VMX root mode to start.
    // No attempts are made to enable this if it is lacking or disabled.
    //
    if (!ShvVmxProbe())
    {
        status = STATUS_HV_FEATURE_UNAVAILABLE;
        goto Failure;
    }

    //
    // Allocate the per-VP data for this logical processor
    //
    vpData = ShvVpAllocateData();
    if (vpData == NULL)
    {
        status = STATUS_HV_NO_RESOURCES;
        goto Failure;
    }

    //
    // First, capture the value of the PML4 for the SYSTEM process, so that all
    // virtual processors, regardless of which process the current LP has
    // interrupted, can share the correct kernel address space.
    //
    vpData->SystemDirectoryTableBase = Context->Cr3;

    //
    // Initialize the virtual processor
    //
    ShvVpInitialize(vpData);

    //
    // Our hypervisor should now be seen as present on this LP, as the SHV
    // correctly handles CPUID ECX features register.
    //
    if (ShvIsOurHypervisorPresent() == FALSE)
    {
        //
        // Free the per-processor data
        //
        ShvOsFreeContiguousAlignedMemory(vpData);
        status = STATUS_HV_NOT_PRESENT;
        goto Failure;
    }

    //
    // This CPU is hyperjacked!
    //
    _InterlockedIncrement((PLONG)&Context->InitCount);
    return;

Failure:
    //
    // Return failure
    //
    cpuIndex = KeGetCurrentProcessorNumberEx(NULL);
    Context->FailedCpu = cpuIndex;
    Context->FailureStatus = status;
    return;
}
