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
// Definitions from ntosp.h
//
#define DPL_USER            3
#define DPL_SYSTEM          0
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
#define RPL_MASK            3
#define MTRR_TYPE_WB        6
#define EFLAGS_ALIGN_CHECK  0x40000

//
// Structures from ntosp.h
//
typedef struct _KDESCRIPTOR
{
    USHORT Pad[3];
    USHORT Limit;
    PVOID Base;
} KDESCRIPTOR, *PKDESCRIPTOR;
typedef union _KGDTENTRY64
{
    struct
    {
        USHORT LimitLow;
        USHORT BaseLow;
        union
        {
            struct
            {
                UCHAR BaseMiddle;
                UCHAR Flags1;
                UCHAR Flags2;
                UCHAR BaseHigh;
            } Bytes;
            struct 
            {
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
    struct
    {
        LONG64 DataLow;
        LONG64 DataHigh;
    };

} KGDTENTRY64, *PKGDTENTRY64;
