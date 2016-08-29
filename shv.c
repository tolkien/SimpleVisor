/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shv.c

Abstract:

    This module implements the Driver Entry/Unload for the Simple Hyper Visor.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#include "shv.h"

VOID
ShvUnload (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    SHV_DPC_CONTEXT dpcContext;
    UNREFERENCED_PARAMETER(DriverObject);

    //
    // Attempt to exit VMX root mode on all logical processors. This will
    // broadcast a DPC interrupt which will execute the callback routine in
    // parallel on the LPs. Send the callback routine a NULL context in order
    // to indicate that this is the unload, not load, path.
    //
    // Note that if SHV is not loaded on any of the LPs, this routine will not
    // perform any work, but will not fail in any way.
    //
    dpcContext.Cr3 = 0;
    KeGenericCallDpc(ShvVpCallbackDpc, &dpcContext);

    //
    // Indicate unload
    //
    DbgPrintEx(77, 0, "The SHV has been uninstalled.\n");
}

NTSTATUS
ShvInitialize (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    SHV_DPC_CONTEXT dpcContext;
    UNREFERENCED_PARAMETER(RegistryPath);

    //
    // Attempt to enter VMX root mode on all logical processors. This will
    // broadcast a DPC interrupt which will execute the callback routine in
    // parallel on the LPs. Send the callback routine the physical address of
    // the PML4 of the system process, which is what this driver entrypoint
    // should be executing in.
    //
    NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);
    dpcContext.Cr3 = __readcr3();
    dpcContext.FailureStatus = STATUS_SUCCESS;
    dpcContext.FailedCpu = -1;
    dpcContext.InitCount = 0;
    KeGenericCallDpc(ShvVpCallbackDpc, &dpcContext);

    //
    // Check if all LPs are now hypervised. Return the failure code of at least
    // one of them. 
    //
    // Note that each VP is responsible for freeing its VP data on failure.
    //
    if (dpcContext.InitCount != KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS))
    {
        DbgPrintEx(77, 0, "The SHV failed to initialize (0x%lX) Failed CPU: %d\n",
                   dpcContext.FailureStatus, dpcContext.FailedCpu);
        NT_ASSERT(dpcContext.FailureStatus != STATUS_SUCCESS);
        return dpcContext.FailureStatus;
    }

    //
    // Make the driver (and SHV itself) unloadable, and indicate success.
    //
    DriverObject->DriverUnload = ShvUnload;
    DbgPrintEx(77, 0, "The SHV has been installed.\n");
    return STATUS_SUCCESS;
}
