#include "main.h"

#pragma data_seg(push)
#pragma data_seg(".global")
PDEVICE_DRIVER_OBJECT Driver = NULL;
#pragma data_seg(pop)

int __cdecl wmain(_In_ int argc, _In_ wchar_t** argv)
{
    NTSTATUS Status;
    PVOID ImageBase;
    SIZE_T ImageSize;
    LPWSTR DriverPath;

    if (argc != 2) {
        Status = STATUS_INVALID_PARAMETER;
        DEBUG_PRINT_NTERROR(STATUS_INVALID_PARAMETER);
        DEBUG_PRINT("[!] invalid arguments.\r\n\t%ws <Driver Path>\r\n", argv[0]);
        return Status;
    }

    DriverPath = argv[1];
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
