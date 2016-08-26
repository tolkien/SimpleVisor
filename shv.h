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

typedef struct _VMX_GDTENTRY64
{
    ULONG_PTR Base;
    ULONG Limit;
    union
    {
        struct
        {
            UCHAR Flags1;
            UCHAR Flags2;
            UCHAR Flags3;
            UCHAR Flags4;
        } Bytes;
        struct
        {
            USHORT SegmentType : 4;
            USHORT DescriptorType : 1;
            USHORT Dpl : 2;
            USHORT Present : 1;

            USHORT Reserved : 4;
            USHORT System : 1;
            USHORT LongMode : 1;
            USHORT DefaultBig : 1;
            USHORT Granularity : 1;

            USHORT Unusable : 1;
            USHORT Reserved2 : 15;
        } Bits;
        ULONG AccessRights;
    };
    USHORT Selector;
} VMX_GDTENTRY64, *PVMX_GDTENTRY64;

typedef struct DECLSPEC_ALIGN(PAGE_SIZE) _VMX_VMCS
{
    ULONG RevisionId;
    ULONG AbortIndicator;
    UCHAR Data[PAGE_SIZE - 8];
} VMX_VMCS, *PVMX_VMCS;

typedef struct _VMX_EPTP
{
    union
    {
        struct
        {
            ULONGLONG Type : 3;
            ULONGLONG PageWalkLength : 3;
            ULONGLONG EnableAccessAndDirtyFlags : 1;
            ULONGLONG Reserved : 5;
            ULONGLONG PageFrameNumber : 36;
            ULONGLONG ReservedHigh : 16;
        };
        ULONGLONG AsUlonglong;
    };
} VMX_EPTP, *PVMX_EPTP;

typedef struct _VMX_EPML4E
{
    union
    {
        struct
        {
            ULONGLONG Read : 1;
            ULONGLONG Write : 1;
            ULONGLONG Execute : 1;
            ULONGLONG Reserved : 5;
            ULONGLONG Accessed : 1;
            ULONGLONG SoftwareUse : 3;
            ULONGLONG PageFrameNumber : 36;
            ULONGLONG ReservedHigh : 4;
            ULONGLONG SoftwareUseHigh : 12;
        };
        ULONGLONG AsUlonglong;
    };
} VMX_EPML4E, *PVMX_EPML4E;

typedef struct _VMX_HUGE_PDPTE
{
    union
    {
        struct
        {
            ULONGLONG Read : 1;
            ULONGLONG Write : 1;
            ULONGLONG Execute : 1;
            ULONGLONG Type : 3;
            ULONGLONG IgnorePat : 1;
            ULONGLONG Large : 1;
            ULONGLONG Accessed : 1;
            ULONGLONG Dirty : 1;
            ULONGLONG SoftwareUse : 2;
            ULONGLONG Reserved : 18;
            ULONGLONG PageFrameNumber : 18;
            ULONGLONG ReservedHigh : 4;
            ULONGLONG SoftwareUseHigh : 11;
            ULONGLONG SupressVme : 1;
        };
        ULONGLONG AsUlonglong;
    };
} VMX_HUGE_PDPTE, *PVMX_HUGE_PDPTE;

typedef struct _SHV_VP_DATA
{
    KPROCESSOR_STATE HostState;
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
