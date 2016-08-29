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
#define PAGE_SIZE           4096
#define KERNEL_STACK_SIZE   24 * 1024

#define VOID                void
#define DECLSPEC_ALIGN(x)   __declspec(align(x))
#define DECLSPEC_NORETURN   __declspec(noreturn)
#define FORCEINLINE         __forceinline
#define C_ASSERT(x)         static_assert(x, "Error")
#define FIELD_OFFSET        offsetof
#define TRUE                1
#define FALSE               0
#define UNREFERENCED_PARAMETER(x)   (x)

typedef struct _KDESCRIPTOR
{
    UINT16 Pad[3];
    UINT16 Limit;
    void* Base;
} KDESCRIPTOR, *PKDESCRIPTOR;
typedef union _KGDTENTRY64
{
    struct
    {
        UINT16 LimitLow;
        UINT16 BaseLow;
        union
        {
            struct
            {
                UINT8 BaseMiddle;
                UINT8 Flags1;
                UINT8 Flags2;
                UINT8 BaseHigh;
            } Bytes;
            struct 
            {
                UINT32 BaseMiddle : 8;
                UINT32 Type : 5;
                UINT32 Dpl : 2;
                UINT32 Present : 1;
                UINT32 LimitHigh : 4;
                UINT32 System : 1;
                UINT32 LongMode : 1;
                UINT32 DefaultBig : 1;
                UINT32 Granularity : 1;
                UINT32 BaseHigh : 8;
            } Bits;
        };
        UINT32 BaseUpper;
        UINT32 MustBeZero;
    };
    struct
    {
        INT64 DataLow;
        INT64 DataHigh;
    };
} KGDTENTRY64, *PKGDTENTRY64;

typedef struct DECLSPEC_ALIGN(16) _M128A
{
    UINT64 Low;
    INT64 High;
} M128A, *PM128A;

typedef struct DECLSPEC_ALIGN(16) _XSAVE_FORMAT
{
    UINT16 ControlWord;
    UINT16 StatusWord;
    UINT8 TagWord;
    UINT8 Reserved1;
    UINT16 ErrorOpcode;
    UINT32 ErrorOffset;
    UINT16 ErrorSelector;
    UINT16 Reserved2;
    UINT32 DataOffset;
    UINT16 DataSelector;
    UINT16 Reserved3;
    UINT32 MxCsr;
    UINT32 MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    UINT8 Reserved4[96];
} XSAVE_FORMAT, *PXSAVE_FORMAT;
typedef XSAVE_FORMAT XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

typedef struct DECLSPEC_ALIGN(16) _CONTEXT
{
    UINT64 P1Home;
    UINT64 P2Home;
    UINT64 P3Home;
    UINT64 P4Home;
    UINT64 P5Home;
    UINT64 P6Home;
    UINT32 ContextFlags;
    UINT32 MxCsr;
    UINT16 SegCs;
    UINT16 SegDs;
    UINT16 SegEs;
    UINT16 SegFs;
    UINT16 SegGs;
    UINT16 SegSs;
    UINT32 EFlags;
    UINT64 Dr0;
    UINT64 Dr1;
    UINT64 Dr2;
    UINT64 Dr3;
    UINT64 Dr6;
    UINT64 Dr7;
    UINT64 Rax;
    UINT64 Rcx;
    UINT64 Rdx;
    UINT64 Rbx;
    UINT64 Rsp;
    UINT64 Rbp;
    UINT64 Rsi;
    UINT64 Rdi;
    UINT64 R8;
    UINT64 R9;
    UINT64 R10;
    UINT64 R11;
    UINT64 R12;
    UINT64 R13;
    UINT64 R14;
    UINT64 R15;
    UINT64 Rip;
    union
    {
        XMM_SAVE_AREA32 FltSave;
        struct
        {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        };
    };
    M128A VectorRegister[26];
    ULONG64 VectorControl;
    ULONG64 DebugControl;
    ULONG64 LastBranchToRip;
    ULONG64 LastBranchFromRip;
    ULONG64 LastExceptionToRip;
    ULONG64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

typedef union _LARGE_INTEGER
{
    struct
    {
        UINT32 LowPart;
        INT32 HighPart;
    };
    UINT64 QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;
