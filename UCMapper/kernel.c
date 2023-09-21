#include "main.h"

NTSTATUS KiExAllocatePool2(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ SIZE_T NumberOfBytes,
    _Out_ PULONGLONG Pointer)
{
    NTSTATUS Status;
    ULONGLONG Address;
    UCHAR Storage[12];

    *Pointer = 0;

    Status = MmGetSystemRoutineAddressW(L"ExAllocatePool2", &Address);
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

    Status = MmGetSystemRoutineAddressW(L"ExFreePoolWithTag", &Address);
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

    Status = MmGetSystemRoutineAddressW(L"ExReleaseResourceLite", &Address);
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

    Status = MmGetSystemRoutineAddressW(L"ExAcquireResourceExclusiveLite", &Address);
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

    Status = MmGetSystemRoutineAddressW(L"RtlDeleteElementGenericTableAvl", &Address);
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

    Status = MmGetSystemRoutineAddressW(L"RtlLookupElementGenericTableAvl", &Address);
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
