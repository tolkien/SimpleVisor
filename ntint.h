/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    ntint.h

Abstract:

    This header contains selected NT structures and functions from ntosp.h

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#pragma once

//
// Define pseudo descriptor structures for both 64- and 32-bit mode.
//

typedef struct _KDESCRIPTOR {
    USHORT Pad[3];
    USHORT Limit;
    PVOID Base;
} KDESCRIPTOR, *PKDESCRIPTOR;

//
// Define descriptor privilege levels for user and system.
//

#define DPL_USER 3
#define DPL_SYSTEM 0

//
// Define limit granularity.
//

#define GRANULARITY_BYTE 0
#define GRANULARITY_PAGE 1

//
// Define processor number packing constants.
//
// The compatibility processor number is encoded in the FS segment descriptor.
//
// Bits 19:14 of the segment limit encode the compatible processor number.
// Bits 13:10 are set to ones to ensure that segment limit is at least 15360.
// Bits 9:0 of the segment limit encode the extended processor number.
//

#define KGDT_LEGACY_LIMIT_SHIFT 14
#define KGDT_LIMIT_ENCODE_MASK (0xf << 10)

#define SELECTOR_TABLE_INDEX 0x04

#define KGDT64_NULL         0x00
#define KGDT64_R0_CODE      0x10
#define KGDT64_R0_DATA      0x18
#define KGDT64_R3_CMCODE    0x20
#define KGDT64_R3_DATA      0x28
#define KGDT64_R3_CODE      0x30
#define KGDT64_SYS_TSS      0x40
#define KGDT64_R3_CMTEB     0x50
#define KGDT64_R0_LDT       0x60

#define MSR_GS_BASE         0xC0000101
#define MSR_DEBUG_CTL       0x1D9

#define RPL_MASK 3

#define MTRR_TYPE_WB 6

#define EFLAGS_ALIGN_CHECK  0x40000

typedef union _KGDTENTRY64 {
    struct {
        USHORT LimitLow;
        USHORT BaseLow;
        union {
            struct {
                UCHAR BaseMiddle;
                UCHAR Flags1;
                UCHAR Flags2;
                UCHAR BaseHigh;
            } Bytes;

            struct {
                ULONG BaseMiddle : 8;
                ULONG Type : 5;
                ULONG Dpl : 2;
                ULONG Present : 1;
                ULONG LimitHigh : 4;
                ULONG System : 1;
                ULONG LongMode : 1;
                ULONG DefaultBig : 1;
                ULONG Granularity : 1;
                ULONG BaseHigh : 8;
            } Bits;
        };

        ULONG BaseUpper;
        ULONG MustBeZero;
    };

    struct {
        LONG64 DataLow;
        LONG64 DataHigh;
    };

} KGDTENTRY64, *PKGDTENTRY64;

NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc (
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID Context
    );

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone (
    _In_ PVOID SystemArgument1
    );

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize (
    _In_ PVOID SystemArgument2
    );

DECLSPEC_NORETURN
NTSYSAPI
VOID
__cdecl
RtlRestoreContext(
    _In_ PCONTEXT ContextRecord,
    _In_opt_ struct _EXCEPTION_RECORD * ExceptionRecord
    );
