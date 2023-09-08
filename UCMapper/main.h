#pragma once

#define UMDF_USING_NTSTATUS
#include <Windows.h>
#include <ntstatus.h>
#include <strsafe.h>

#include "halamd64.h"
#include "ntdll.h"
#include "driver.h"
#include "mapper.h"
#include "routine.h"
#include "hook.h"
#include "hde64.h"
#include "registry.h"

#pragma intrinsic(memcpy)
#pragma intrinsic(memset)

#ifndef DISABLE_NTSTATUS_ERROR_OUTPUT
#define PRINT_ERROR_STATUS(ErrorCode)                                                                                                                                                                       \
    {                                                                                                                                                                                                       \
        LPVOID Message;                                                                                                                                                                                     \
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&Message, 0, NULL); \
        wprintf(L"[!] %hs[%u]: %ws", __FUNCTION__, __LINE__, (LPWSTR)Message);                                                                                                                              \
        LocalFree(Message);                                                                                                                                                                                 \
    }

#define PRINT_ERROR_NTSTATUS(Status) PRINT_ERROR_STATUS(RtlNtStatusToDosError(Status))
#else
#define PRINT_ERROR_STATUS(ErrorCode)
#define PRINT_ERROR_NTSTATUS(Status)
#endif
