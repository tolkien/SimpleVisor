/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    shv.h

Abstract:

    This header defines the structures and functions of the Simple Hyper Visor.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#pragma once
#pragma warning(disable:4201)
#pragma warning(disable:4214)
#include <ntifs.h>
#include <intrin.h>
#include "ntint.h"
#include "vmx.h"

typedef struct _SHV_SPECIAL_REGISTERS
{
    ULONG64 Cr0;
    ULONG64 Cr3;
    ULONG64 Cr4;
    ULONG64 MsrGsBase;
    USHORT Tr;
    USHORT Ldtr;
    ULONG64 DebugControl;
    ULONG64 KernelDr7;
    KDESCRIPTOR Idtr;
    KDESCRIPTOR Gdtr;
} SHV_SPECIAL_REGISTERS, *PSHV_SPECIAL_REGISTERS;

typedef struct _SHV_VP_DATA
{
    SHV_SPECIAL_REGISTERS SpecialRegisters;
    CONTEXT ContextFrame;
    ULONG VpIndex;
    volatile ULONG VmxEnabled;
    ULONG64 SystemDirectoryTableBase;
    LARGE_INTEGER MsrData[17];
    ULONGLONG VmxOnPhysicalAddress;
    ULONGLONG VmcsPhysicalAddress;
    ULONGLONG MsrBitmapPhysicalAddress;
    ULONGLONG EptPml4PhysicalAddress;

    DECLSPEC_ALIGN(PAGE_SIZE) UCHAR ShvStackLimit[KERNEL_STACK_SIZE];
    VMX_VMCS VmxOn;
    VMX_VMCS Vmcs;
} SHV_VP_DATA, *PSHV_VP_DATA;

C_ASSERT(sizeof(SHV_VP_DATA) == (KERNEL_STACK_SIZE + 3 * PAGE_SIZE));

C_ASSERT(sizeof(VMX_EPTP) == sizeof(ULONGLONG));
C_ASSERT(sizeof(VMX_EPML4E) == sizeof(ULONGLONG));

#define PML4E_ENTRY_COUNT 512
#define PDPTE_ENTRY_COUNT 512
typedef struct _SHV_GLOBAL_DATA
{
    UCHAR MsrBitmap[PAGE_SIZE];
    VMX_EPML4E Epml4[PML4E_ENTRY_COUNT];
    VMX_HUGE_PDPTE Epdpt[PDPTE_ENTRY_COUNT];
    SHV_VP_DATA VpData[ANYSIZE_ARRAY];
} SHV_GLOBAL_DATA, *PSHV_GLOBAL_DATA;

C_ASSERT((FIELD_OFFSET(SHV_GLOBAL_DATA, Epml4) % PAGE_SIZE) == 0);
C_ASSERT((FIELD_OFFSET(SHV_GLOBAL_DATA, Epdpt) % PAGE_SIZE) == 0);

typedef struct _SHV_VP_STATE
{
    PCONTEXT VpRegs;
    ULONG_PTR GuestRip;
    ULONG_PTR GuestRsp;
    ULONG_PTR GuestEFlags;
    USHORT ExitReason;
    KIRQL GuestIrql;
    BOOLEAN ExitVm;
} SHV_VP_STATE, *PSHV_VP_STATE;

VOID
ShvVmxEntry (
    VOID
    );

VOID 
ShvVmxCleanup (
    _In_ USHORT Data,
    _In_ USHORT Teb
    );

VOID
_sldt (
    _In_ PUSHORT Ldtr
    );

VOID
_str (
    _In_ PUSHORT Tr
    );

VOID
__lgdt (
    _In_ PVOID Gdtr
    );

VOID
ShvVmxLaunchOnVp (
    _In_ PSHV_VP_DATA VpData
    );

VOID
ShvUtilConvertGdtEntry (
    _In_ PVOID GdtBase,
    _In_ USHORT Offset,
    _Out_ PVMX_GDTENTRY64 VmxGdtEntry
    );

ULONG
ShvUtilAdjustMsr (
    _In_ LARGE_INTEGER ControlValue,
    _In_ ULONG DesiredValue
    );

PSHV_GLOBAL_DATA
ShvVpAllocateGlobalData (
    VOID
    );

BOOLEAN
ShvVmxProbe (
    VOID
    );

VOID
ShvVmxEptInitialize (
    VOID
    );

KDEFERRED_ROUTINE ShvVpCallbackDpc;

extern PSHV_GLOBAL_DATA ShvGlobalData;
