#include "main.h"

int __cdecl wmain(_In_ int argc, _In_ wchar_t** argv)
{
    NTSTATUS Status;
    PVOID ImageBase;
    SIZE_T ImageSize;
    LPWSTR DriverPath;
    DEVICE_DRIVER_OBJECT Driver;

    if (argc != 2) {
        Status = STATUS_INVALID_PARAMETER;
        DEBUG_PRINT_NTSTATUS(Status);
        DEBUG_PRINT("[!] invalid arguments.\r\n\t%ws <Driver Path>\r\n", argv[0]);
        return Status;
    }

    //
    // Map File as Image.
    //
    DriverPath = argv[1];
    Status     = RtlFileMapImage(DriverPath, &ImageBase, &ImageSize);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    //
    // Load driver and map image.
    //
    Status = LoadDriver(&Driver);
    if NT_SUCCESS (Status) {
        Status = MmLoadSystemImage(&Driver, ImageBase);
        DEBUG_PRINT("[+] Mapping result: 0x%08X.", Status);
        UnloadDriver(&Driver);
    }

    RtlFileUnmap(ImageBase);
    return Status;
}
