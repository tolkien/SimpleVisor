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

VOID
ShvVpInitialize (
    _In_ PSHV_VP_DATA Data,
    _In_ ULONG64 SystemDirectoryTableBase
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
    // pointer, which is being captured as part of this call. In other words,
    // we will return right where we were, but with all our registers corrupted
    // by the VMCS/VMX initialization code (as guest state does not include
    // register state). By saving the context here, which includes all general
    // purpose registers, we guarantee that we return with all of our starting
    // register values as well!
    //
    RtlCaptureContext(&Data->ContextFrame);

    //
    // As per the above, we might be here because the VM has actually launched.
    // We can check this by verifying the value of the VmxEnabled field, which
    // is set to 1 right before VMXLAUNCH is performed. We do not use the Data
    // parameter or any other local register in this function, and in fact have
    // defined VmxEnabled as volatile, because as per the above, our register
    // state is currently dirty due to the VMCALL itself. By using the global
    // variable combined with an API call, we also make sure that the compiler
    // will not optimize this access in any way, even on LTGC/Ox builds.
    //
    if (ShvGlobalData[KeGetCurrentProcessorNumberEx(NULL)]->VmxEnabled == 1)
    {
        //
        // We now indicate that the VM has launched, and that we are about to
        // restore the GPRs back to their original values. This will have the
        // effect of putting us yet *AGAIN* at the previous line of code, but
        // this time the value of VmxEnabled will be two, bypassing the if and
        // else if checks.
        //
        ShvGlobalData[KeGetCurrentProcessorNumberEx(NULL)]->VmxEnabled = 2;

        //
        // And finally, restore the context, so that all register and stack
        // state is finally restored. Note that by continuing to reference the
        // per-VP data this way, the compiler will continue to generate non-
        // optimized accesses, guaranteeing that no previous register state
        // will be used.
        //
        RtlRestoreContext(&ShvGlobalData[KeGetCurrentProcessorNumberEx(NULL)]->ContextFrame, NULL);
    }
    //
    // If we are in this branch comparison, it means that we have not yet
    // attempted to launch the VM, nor that we have launched it. In other
    // words, this is the first time in ShvVpInitialize. Because of this,
    // we are free to use all register state, as it is ours to use.
    //
    else if (Data->VmxEnabled == 0)
    {
        //
        // First, capture the value of the PML4 for the SYSTEM process, so that
        // all virtual processors, regardless of which process the current LP
        // has interrupted, can share the correct kernel address space.
        //
        Data->SystemDirectoryTableBase = SystemDirectoryTableBase;

        //
        // Then, attempt to initialize VMX on this processor
        //
        ShvVmxLaunchOnVp(Data);
    }
}

VOID
ShvVpUninitialize (
    VOID
    )
{
    INT dummy[4];

    //
    // Send the magic shutdown instruction sequence
    //
    __cpuidex(dummy, 0x41414141, 0x42424242);

    //
    // The processor will return here after the hypervisor issues a VMXOFF
    // instruction and restores the CPU context to this location. Unfortunately
    // because this is done with RtlRestoreContext which returns using "iretq",
    // this causes the processor to remove the RPL bits off the segments. As
    // the x64 kernel does not expect kernel-mode code to chang ethe value of
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
    PHYSICAL_ADDRESS lowest, highest;
    PSHV_VP_DATA data;

    //
    // The entire address range is OK for this allocation
    //
    lowest.QuadPart = 0;
    highest.QuadPart = lowest.QuadPart - 1;

    //
    // Allocate a contiguous chunk of RAM to back this allocation and make sure
    // that it is RW only, instead of RWX, by using the new Windows 8 API.
    //
    data = MmAllocateContiguousNodeMemory(sizeof(SHV_VP_DATA),
                                          lowest,
                                          highest,
                                          lowest,
                                          PAGE_READWRITE,
                                          KeGetCurrentNodeNumber());
    if (data != NULL)
    {
        //
        // Zero out the entire data region
        //
        __stosq((PULONG64)data, 0, sizeof(SHV_VP_DATA) / sizeof(ULONG64));
    }

    //
    // Return what is hopefully a valid pointer, otherwise NULL.
    //
    return data;
}

VOID
ShvVpCallbackDpc (
    _In_ PRKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PSHV_DPC_CONTEXT dpcContext = Context;
    ULONG cpuIndex;
    UNREFERENCED_PARAMETER(Dpc);

    //
    // Detect if the hardware appears to support VMX root mode to start.
    // No attempts are made to enable this if it is lacking or disabled.
    //
    if (!ShvVmxProbe())
    {
        dpcContext->FailureStatus = STATUS_HV_FEATURE_UNAVAILABLE;
        goto Quickie;
    }

    //
    // Check if we are loading, or unloading, and which CPU this is
    //
    cpuIndex = KeGetCurrentProcessorNumberEx(NULL);
    if (dpcContext->Cr3 != 0)
    {
        //
        // Allocate the per-VP data for this logical processor
        //
        ShvGlobalData[cpuIndex] = ShvVpAllocateData();
        if (ShvGlobalData[cpuIndex] == NULL)
        {
            dpcContext->FailureStatus = STATUS_HV_NO_RESOURCES;
            goto Quickie;
        }

        //
        // Initialize the virtual processor
        //
        ShvVpInitialize(ShvGlobalData[cpuIndex], dpcContext->Cr3);

        //
        // Our hypervisor should now be seen as present on this LP,
        // as the SHV correctly handles CPUID ECX features register.
        //
        if (ShvIsOurHypervisorPresent() == FALSE)
        {
            //
            // Free the per-processor data
            //
            MmFreeContiguousMemory(ShvGlobalData[cpuIndex]);
            ShvGlobalData[cpuIndex] = NULL;
            dpcContext->FailureStatus = STATUS_HV_NOT_PRESENT;
            goto Quickie;
        }

        //
        // This CPU is hyperjacked!
        //
        dpcContext->InitMask |= (1ULL << cpuIndex);
    }
    else
    {
        //
        // Tear down the virtual processor
        //
        ShvVpUninitialize(ShvGlobalData[cpuIndex]);
        NT_ASSERT(ShvIsOurHypervisorPresent() == FALSE);

        //
        // Free the VP data
        //
        MmFreeContiguousMemory(ShvGlobalData[cpuIndex]);
        ShvGlobalData[cpuIndex] = NULL;
    }

Quickie:
    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}
