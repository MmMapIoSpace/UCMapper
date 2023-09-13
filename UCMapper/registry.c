#include "main.h"

NTSTATUS RtlRegSetKeyValue(
    _In_ LPCWSTR RegistryPath,
    _In_ LPCWSTR Valuename,
    _In_ ULONG Type,
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength)
{
    HANDLE RegistryHandle;
    UNICODE_STRING UnicodeString;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES objectAttributes;

    RtlInitUnicodeString(&UnicodeString, RegistryPath);
    InitializeObjectAttributes(&objectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&RegistryHandle, KEY_ALL_ACCESS, &objectAttributes);

    if NT_ERROR (Status) {
        Status = NtCreateKey(
            &RegistryHandle,
            KEY_ALL_ACCESS,
            &objectAttributes,
            0,
            NULL,
            REG_OPTION_VOLATILE,
            NULL);
    }

    if NT_SUCCESS (Status) {
        RtlInitUnicodeString(&UnicodeString, Valuename);
        Status = NtSetValueKey(RegistryHandle, &UnicodeString, 0, Type, Buffer, BufferLength);

        NtClose(RegistryHandle);
    }

    return Status;
}

NTSTATUS RtlRegGetKeyValue(
    _In_ LPCWSTR RegistryPath,
    _In_ LPCWSTR Valuename,
    _Out_writes_bytes_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength)
{
    UNICODE_STRING UnicodeString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    HANDLE RegistryHandle;
    ULONG PartialInformationSize;
    PKEY_VALUE_PARTIAL_INFORMATION PartialInformation;
    ULONG ResultLength;

    ResultLength = 0;

    RtlInitUnicodeString(&UnicodeString, RegistryPath);
    InitializeObjectAttributes(
        &ObjectAttributes,
        &UnicodeString,
        (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE),
        NULL,
        NULL);

    Status = NtOpenKey(&RegistryHandle, KEY_ALL_ACCESS, &ObjectAttributes);

    if NT_SUCCESS (Status) {
        RtlInitUnicodeString(&UnicodeString, Valuename);
        PartialInformationSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + BufferLength - 1;
        PartialInformation     = RtlAllocateMemory(PartialInformationSize);

        Status = NtQueryValueKey(
            RegistryHandle,
            &UnicodeString,
            KeyValuePartialInformation,
            PartialInformation,
            PartialInformationSize,
            &ResultLength);

        if NT_SUCCESS (Status)
            RtlCopyMemory(Buffer, PartialInformation->Data, PartialInformation->DataLength);

        RtlFreeMemory(PartialInformation);
        NtClose(RegistryHandle);
    }

    return Status;
}

NTSTATUS RtlRegDeleteKey(_In_ LPCWSTR RegistryPath)
{
    HANDLE RegistryHandle;
    UNICODE_STRING unicodeString;
    NTSTATUS status;

    RtlInitUnicodeString(&unicodeString, RegistryPath);
    OBJECT_ATTRIBUTES objectAttributes
        = RTL_CONSTANT_OBJECT_ATTRIBUTES(&unicodeString, OBJ_CASE_INSENSITIVE);

    status = NtOpenKey(&RegistryHandle, KEY_ALL_ACCESS, &objectAttributes);
    if NT_SUCCESS (status) {
        status = NtDeleteKey(RegistryHandle);
        NtClose(RegistryHandle);
    }

    return status;
}
