/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    shv_x.h

Abstract:

    This header defines the externally visible structures and functions of the
    Simple Hyper Visor which are visible between the OS layer and SimpleVisor.

Author:

    Alex Ionescu (@aionescu) 29-Aug-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#pragma once

#define SHV_STATUS_SUCCESS          0
#define SHV_STATUS_NOT_AVAILABLE    -1
#define SHV_STATUS_NO_RESOURCES     -2
#define SHV_STATUS_NOT_PRESENT      -3

typedef struct _SHV_CALLBACK_CONTEXT
{
    UINT64 Cr3;
    volatile long InitCount;
    INT32 FailedCpu;
    INT32 FailureStatus;
} SHV_CALLBACK_CONTEXT, *PSHV_CALLBACK_CONTEXT;

typedef
void
SHV_CPU_CALLBACK (
    _In_ PSHV_CALLBACK_CONTEXT Context
    );
typedef SHV_CPU_CALLBACK *PSHV_CPU_CALLBACK;

INT32
ShvLoad (
    VOID
    );

VOID
ShvUnload (
    VOID
    );

SHV_CPU_CALLBACK ShvVpLoadCallback;
SHV_CPU_CALLBACK ShvVpUnloadCallback;
