/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    shvvp.c

Abstract:

    This module implements Virtual Processor (VP) management for the Simple Hyper Visor.

Author:

    Alex Ionescu (alex.ionescu@reactos.com)   16-Mar-2016

Environment:

    Kernel mode only.

--*/

#include "shv.h"

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
        ShvVmxLaunchOnVp(Data);
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
ShvVpCallbackDpc (
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
ShvVpAllocateGlobalData (
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

