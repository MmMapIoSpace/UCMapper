#include "main.h"

#pragma data_seg(push)
#pragma data_seg(".global")
PDEVICE_DRIVER_OBJECT Driver = NULL;
#pragma data_seg(pop)

NTSTATUS wmain(_In_ LONG ArgumentCount, _In_ LPWSTR* Argument)
{
    NTSTATUS Status;
    PVOID ImageBase;
    SIZE_T ImageSize;
    LPWSTR DriverPath;

    if (ArgumentCount != 2) {
        Status = STATUS_INVALID_PARAMETER;
        DEBUG_PRINT_NTERROR(STATUS_INVALID_PARAMETER);
        DEBUG_PRINT("[!] invalid arguments.\r\n\t%ws <Driver Path>\r\n", Argument[0]);
        return Status;
    }

    DriverPath = Argument[1];
    Status     = RtlFileMapImage(DriverPath, &ImageBase, &ImageSize);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTERROR(Status);
        return Status;
    }

    Driver               = RtlAllocateMemory(sizeof(DEVICE_DRIVER_OBJECT));
    Driver->ReadMemory   = ReadSystemMemory;
    Driver->WriteMemory  = WriteSystemMemory;
    Driver->DeviceHandle = NULL;


    Status = LoadDriver(&Driver->DeviceHandle);
    if NT_SUCCESS (Status) {
        Status = MmLoadSystemImage(Driver, ImageBase);
        DEBUG_PRINT("[+] Mapping result: 0x%08X.", Status);
        UnloadDriver(Driver->DeviceHandle);
    }

    RtlFileUnmap(ImageBase);
    RtlFreeMemory(Driver);
    Driver = NULL;
    return Status;
}
