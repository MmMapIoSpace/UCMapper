#include "main.h"

NTSTATUS ObGetObjectByHandle(_In_ HANDLE Handle, _Out_ PULONGLONG Pointer)
{
    PSYSTEM_HANDLE_INFORMATION_EX SystemHandleInfo;
    ULONG i;
    ULONG BufferLength = 0;
    PVOID Buffer       = NULL;
    NTSTATUS Status;

    *Pointer     = 0;
    BufferLength = sizeof(PVOID);
    Buffer       = RtlAllocateMemory(BufferLength);
    Status       = STATUS_INFO_LENGTH_MISMATCH;

    while (Status != STATUS_SUCCESS) {
        Status = NtQuerySystemInformation(
            SystemExtendedHandleInformation,
            Buffer,
            BufferLength,
            &BufferLength);

        if (Status == STATUS_INFO_LENGTH_MISMATCH) {
            RtlFreeMemory(Buffer);
            Buffer = RtlAllocateMemory(BufferLength);
        }
    }

    Status           = STATUS_NOT_FOUND;
    SystemHandleInfo = Buffer;
    for (i = 0; i < SystemHandleInfo->NumberOfHandles; ++i) {
        if (SystemHandleInfo->Handles[i].UniqueProcessId
                == (ULONGLONG)NtCurrentTeb()->ClientId.UniqueProcess
            && SystemHandleInfo->Handles[i].HandleValue == (ULONGLONG)Handle) {
            *Pointer = (ULONGLONG)SystemHandleInfo->Handles[i].Object;
            Status   = STATUS_SUCCESS;
            break;
        }
    }

    RtlFreeMemory(Buffer);
    return Status;
}

NTSTATUS MmGetSystemModuleA(
    _In_ LPCSTR ModuleName,
    _Out_ PRTL_PROCESS_MODULE_INFORMATION ModuleInformation)
{
    NTSTATUS Status;
    ULONG BufferLength;
    PRTL_PROCESS_MODULES ModuleList;
    PCHAR BaseModuleName;
    ANSI_STRING ModuleNameA;
    ANSI_STRING BaseModuleNameA;

    RtlSecureZeroMemory(ModuleInformation, sizeof(RTL_PROCESS_MODULE_INFORMATION));
    BufferLength = sizeof(PVOID);
    ModuleList   = RtlAllocateMemory(BufferLength);
    Status       = STATUS_INFO_LENGTH_MISMATCH;

    while (Status != STATUS_SUCCESS) {
        Status = NtQuerySystemInformation(
            SystemModuleInformation,
            ModuleList,
            BufferLength,
            &BufferLength);

        if (Status == STATUS_INFO_LENGTH_MISMATCH) {
            RtlFreeMemory(ModuleList);
            ModuleList = RtlAllocateMemory(BufferLength);
        }
    }

    Status = STATUS_DLL_NOT_FOUND;
    RtlInitString(&ModuleNameA, ModuleName);
    for (ULONG i = 0; i < ModuleList->NumberOfModules; i++) {
        BaseModuleName = RtlOffsetToPointer(
            ModuleList->Modules[i].FullPathName,
            ModuleList->Modules[i].OffsetToFileName);

        RtlInitString(&BaseModuleNameA, BaseModuleName);
        if (RtlEqualString(&BaseModuleNameA, &ModuleNameA, TRUE) == TRUE) {
            *ModuleInformation = ModuleList->Modules[i];
            Status             = STATUS_SUCCESS;
            break;
        }
    }

    if (ModuleList) {
        RtlFreeMemory(ModuleList);
        ModuleList = NULL;
    }

    return Status;
}

NTSTATUS MmGetSystemModuleW(
    _In_ LPCWSTR ModuleName,
    _Out_ PRTL_PROCESS_MODULE_INFORMATION ModuleInformation)
{
    ANSI_STRING AnsiString;
    UNICODE_STRING UnicodeString;
    NTSTATUS Status;

    RtlInitUnicodeString(&UnicodeString, ModuleName);
    Status = RtlUnicodeStringToAnsiString(&AnsiString, &UnicodeString, TRUE);

    if NT_SUCCESS (Status) {
        Status = MmGetSystemModuleA(AnsiString.Buffer, ModuleInformation);
        RtlFreeAnsiString(&AnsiString);
    }

    return Status;
}

NTSTATUS MmGetSystemRoutineAddressA(_In_ LPCSTR RoutineName, _Out_ PULONGLONG Pointer)
{
    NTSTATUS Status;
    UNICODE_STRING UnicodeString;
    ULONGLONG ImageBase;
    ULONGLONG Address;
    RTL_PROCESS_MODULE_INFORMATION ModuleInformation;

    *Pointer = 0;
    Status   = MmGetSystemModuleW(L"ntoskrnl.exe", &ModuleInformation);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTERROR(Status);
        return Status;
    }

    RtlInitUnicodeString(&UnicodeString, L"ntoskrnl.exe");
    Status = LdrLoadDll(NULL, NULL, &UnicodeString, (PVOID*)&ImageBase);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTERROR(Status);
        return Status;
    }

    Status  = STATUS_PROCEDURE_NOT_FOUND;
    Address = (ULONGLONG)RtlFindExportedRoutineByName((PVOID)ImageBase, (PSTR)RoutineName);
    LdrUnloadDll((PVOID)ImageBase);

    if (Address != 0) {
        Address  -= ImageBase;
        Address  += (ULONGLONG)ModuleInformation.ImageBase;
        *Pointer  = Address;
        Status    = STATUS_SUCCESS;
    }

    return Status;
}

NTSTATUS MmGetSystemRoutineAddressW(_In_ LPCWSTR ModuleName, _Out_ PULONGLONG Pointer)
{
    ANSI_STRING AnsiString;
    UNICODE_STRING UnicodeString;
    NTSTATUS Status;

    RtlInitUnicodeString(&UnicodeString, ModuleName);
    Status = RtlUnicodeStringToAnsiString(&AnsiString, &UnicodeString, TRUE);

    if NT_SUCCESS (Status) {
        Status = MmGetSystemRoutineAddressA(AnsiString.Buffer, Pointer);
        RtlFreeAnsiString(&AnsiString);
    }

    return Status;
}
