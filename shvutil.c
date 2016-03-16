/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    shvutil.c

Abstract:

    This module implements utility functions for the Simple Hyper Visor.

Author:

    Alex Ionescu (alex.ionescu@reactos.com)   16-Mar-2016

Environment:

    Kernel mode only.

--*/

#include "shv.h"

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

