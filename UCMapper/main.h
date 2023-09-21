#pragma once

#pragma warning(disable : 4995 4201)

#ifdef __cplusplus
extern "C" {
#endif

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
#include "filerw.h"
#include "driverlist.h"
#include "kernel.h"

#pragma intrinsic(memcpy)
#pragma intrinsic(memset)

#ifndef DISABLE_NTSTATUS_ERROR_OUTPUT
#define DEBUG_PRINT(Format, ...) DebugPrint(L##Format L"\r\n", __VA_ARGS__)
#define DEBUG_PRINT_NTSTATUS(Status)                                        \
    {                                                                       \
        PVOID Message;                                                      \
                                                                            \
        FormatMessageW(                                                     \
            (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM    \
             | FORMAT_MESSAGE_IGNORE_INSERTS),                              \
            NULL,                                                           \
            RtlNtStatusToDosError(Status),                                  \
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),                      \
            (LPWSTR)&Message,                                               \
            0,                                                              \
            NULL);                                                          \
                                                                            \
        if NT_SUCCESS (Status) {                                            \
            DEBUG_PRINT(                                                    \
                "[+] Succeed on %hs[%u]:\r\n\tDescription: %ws\tFile: %hs", \
                __FUNCTION__,                                               \
                __LINE__,                                                   \
                (LPWSTR)Message,                                            \
                __FILE__);                                                  \
        } else {                                                            \
            DEBUG_PRINT(                                                    \
                "[!] Error on %hs[%u]:\r\n\tDescription: %ws\tFile: %hs",   \
                __FUNCTION__,                                               \
                __LINE__,                                                   \
                (LPWSTR)Message,                                            \
                __FILE__);                                                  \
        }                                                                   \
        LocalFree(Message);                                                 \
    }
#define MSG_BOX(Format, ...) MsgBoxFormat(L##Format, __VA_ARGS__)

static VOID DebugPrint(LPCWSTR Format, ...)
{
    UNICODE_STRING UnicodeString;
    LPWSTR Storage;
    ULONG NumberOfWritten;
    HANDLE StandardHandle;
    CONSOLE_SCREEN_BUFFER_INFO ScreenInformation;
    USHORT PrevAttr, NewAttr;
    HRESULT hr;
    CONSOLE_FONT_INFOEX FontInformation;

    Storage        = RtlAllocateMemory(PAGE_SIZE);
    StandardHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    PrevAttr       = 0;
    NewAttr        = 0;

    if (GetConsoleScreenBufferInfo(StandardHandle, &ScreenInformation)) {
        PrevAttr = *(&ScreenInformation.wAttributes);
    }

    FontInformation.cbSize = sizeof(CONSOLE_FONT_INFOEX);

    // Populate cfi with the screen buffer's current font info
    if (GetCurrentConsoleFontEx(StandardHandle, FALSE, &FontInformation)
        && FontInformation.FontWeight != 700) {
        // Modify the font size in cfi
        //FontInformation.dwFontSize.X = 12;
        //FontInformation.dwFontSize.Y = 24;
        FontInformation.FontWeight = 700;
        //StringCchCopyW(FontInformation.FaceName, RTL_NUMBER_OF(FontInformation.FaceName), L"Cascadia Mono");
        // Use cfi to set the screen buffer's new font
        SetCurrentConsoleFontEx(StandardHandle, FALSE, &FontInformation);

        //ScreenInformation.dwMaximumWindowSize.X = 400;
        //ScreenInformation.dwMaximumWindowSize.Y = 400;
        //ScreenInformation.dwSize.X              = 400;
        //ScreenInformation.dwSize.Y              = 400;
        //SetConsoleScreenBufferInfoEx(StandardHandle, &ScreenInformation);
        //SetConsoleScreenBufferSize(StandardHandle, ScreenInformation.dwMaximumWindowSize);
    }

    va_list argList;
    va_start(argList, Format);
    hr = StringVPrintfWorkerW(Storage, PAGE_SIZE / sizeof(WCHAR), NULL, Format, argList);
    va_end(argList);

    if SUCCEEDED (hr) {
        RtlInitUnicodeString(&UnicodeString, Storage);

        switch (UnicodeString.Buffer[1]) {
        case L'i':
        case L'+':
            NewAttr = FOREGROUND_GREEN;
            break;

        case L'-':
        case L'!':
            NewAttr = FOREGROUND_RED;
            break;

        default:
            NewAttr = PrevAttr;
            break;
        }

        SetConsoleTextAttribute(StandardHandle, NewAttr);

        WriteConsoleW(
            StandardHandle,
            UnicodeString.Buffer,
            UnicodeString.Length / sizeof(WCHAR),
            &NumberOfWritten,
            NULL);

        SetConsoleTextAttribute(StandardHandle, PrevAttr);
    }

    RtlFreeMemory(Storage);
}

static VOID MsgBoxFormat(LPCWSTR Message, ...)
{
    WCHAR Storage[MAX_PATH];

    va_list argList;
    va_start(argList, Message);
    StringVPrintfWorkerW(Storage, MAX_PATH, NULL, Message, argList);
    va_end(argList);

    MessageBox(GetForegroundWindow(), Storage, NULL, MB_OK | MB_TOPMOST);
}

#else
#define DEBUG_PRINT(Format, ...)
#define DEBUG_PRINT_NTSTATUS(Status)
#endif

#ifdef __cplusplus
}
#endif
