#include "main.h"

NTSTATUS HookSystemRoutine(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ ULONGLONG NewAddress,
    _Out_writes_bytes_(12) PUCHAR Native)
{
    UCHAR Shellcode[12];
    NTSTATUS Status;
    ULONGLONG Address;
    WCHAR v1[] = {L'N', L't', L'S', L'e', L't', L'E', L'a', L'F', L'i', L'l', L'e', L'\0'};

    Address = GetSystemRoutineAddressW(v1);
    if (Address == 0) {
        Status = STATUS_NOT_FOUND;
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    RtlZeroMemory(Shellcode, sizeof(Shellcode));
    Shellcode[0]               = 0x48;
    Shellcode[1]               = 0xB8;
    *(ULONGLONG*)&Shellcode[2] = NewAddress;
    Shellcode[10]              = 0xFF;
    Shellcode[11]              = 0xE0;

    Status = Driver->ReadMemory(Driver->DeviceHandle, Address, Native, sizeof(Shellcode));
    if NT_SUCCESS (Status) {
        Status = Driver->WriteMemory(Driver->DeviceHandle, Address, Shellcode, sizeof(Shellcode));
    }

    return Status;
}

NTSTATUS UnhookSystemRoutine(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_reads_bytes_(12) PUCHAR Native)
{
    ULONGLONG routineAddr;
    WCHAR v1[] = {L'N', L't', L'S', L'e', L't', L'E', L'a', L'F', L'i', L'l', L'e', L'\0'};

    routineAddr = GetSystemRoutineAddressW(v1);
    if (routineAddr == 0)
        return STATUS_NOT_FOUND;

    return Driver->WriteMemory(Driver->DeviceHandle, routineAddr, Native, 12);
}
