#include "main.h"

ULONGLONG GetSystemModuleBaseA(_In_ LPCSTR ModuleName)
{
    ULONG BufferLength;
    PVOID Buffer;
    NTSTATUS Status;
    ULONGLONG SystemModuleBase;
    PRTL_PROCESS_MODULES ModuleList;
    PCHAR BaseModuleName;
    ANSI_STRING ModuleNameA;
    ANSI_STRING BaseModuleNameA;

    BufferLength     = sizeof(PVOID);
    Buffer           = RtlAllocateMemory(BufferLength);
    Status           = STATUS_INFO_LENGTH_MISMATCH;
    SystemModuleBase = 0;

    while (Status != STATUS_SUCCESS) {
        Status = NtQuerySystemInformation(SystemModuleInformation, Buffer, BufferLength, &BufferLength);

        if (Status == STATUS_INFO_LENGTH_MISMATCH) {
            RtlFreeMemory(Buffer);
            Buffer = RtlAllocateMemory(BufferLength);
        }
    }

    RtlInitString(&ModuleNameA, ModuleName);
    ModuleList = (PRTL_PROCESS_MODULES)Buffer;
    for (ULONG i = 0; i < ModuleList->NumberOfModules; i++) {
        BaseModuleName = RtlOffsetToPointer(ModuleList->Modules[i].FullPathName, ModuleList->Modules[i].OffsetToFileName);
        RtlInitString(&BaseModuleNameA, BaseModuleName);

        if (RtlEqualString(&BaseModuleNameA, &ModuleNameA, TRUE) == TRUE) {
            SystemModuleBase = (ULONGLONG)ModuleList->Modules[i].ImageBase;
            break;
        }
    }

    if (Buffer) {
        RtlFreeMemory(Buffer);
        Buffer = NULL;
    }

    return SystemModuleBase;
}

ULONGLONG GetSystemModuleBaseW(_In_ LPCWSTR ModuleName)
{
    ULONGLONG Destination;
    ANSI_STRING AnsiString;
    UNICODE_STRING UnicodeString;

    Destination = 0;

    RtlInitUnicodeString(&UnicodeString, ModuleName);
    if NT_SUCCESS (RtlUnicodeStringToAnsiString(&AnsiString, &UnicodeString, TRUE)) {
        Destination = GetSystemModuleBaseA(AnsiString.Buffer);
        RtlFreeAnsiString(&AnsiString);
    }
    return Destination;
}

ULONGLONG GetSystemRoutineAddressA(_In_ LPCSTR RoutineName)
{
    UNICODE_STRING unicodeString;
    ULONGLONG ImageBase;
    NTSTATUS status;
    ULONGLONG Address;
    WCHAR moduleName[13];
    moduleName[0]  = L'n';
    moduleName[1]  = L't';
    moduleName[2]  = L'o';
    moduleName[3]  = L's';
    moduleName[4]  = L'k';
    moduleName[5]  = L'r';
    moduleName[6]  = L'n';
    moduleName[7]  = L'l';
    moduleName[8]  = L'.';
    moduleName[9]  = L'e';
    moduleName[10] = L'x';
    moduleName[11] = L'e';
    moduleName[12] = L'\0';

    RtlInitUnicodeString(&unicodeString, moduleName);
    status = LdrLoadDll(NULL, NULL, &unicodeString, (PVOID*)&ImageBase);
    if NT_ERROR (status) {
        PRINT_ERROR_NTSTATUS(status);
        return 0;
    }

    Address = (ULONGLONG)RtlFindExportedRoutineByName((PVOID)ImageBase, (PSTR)RoutineName);
    status  = LdrUnloadDll((PVOID)ImageBase);

    if (Address != 0) {
        Address -= ImageBase;
        Address += GetSystemModuleBaseW(moduleName);
        RTL_ASSERT(GetSystemModuleBaseW(moduleName) != 0);
    }

    return Address;
}

ULONGLONG GetSystemRoutineAddressW(_In_ LPCWSTR RoutineName)
{
    UNICODE_STRING unicodeString;
    ANSI_STRING ansiString;
    ULONGLONG Destination;

    Destination = 0;

    RtlInitUnicodeString(&unicodeString, RoutineName);
    if NT_SUCCESS (RtlUnicodeStringToAnsiString(&ansiString, &unicodeString, TRUE)) {
        Destination = GetSystemRoutineAddressA(ansiString.Buffer);
        RtlFreeAnsiString(&ansiString);
    }
    return Destination;
}
