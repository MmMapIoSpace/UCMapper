#pragma once

NTSTATUS RtlRegSetKeyValue(_In_ LPCWSTR RegistryPath, _In_ LPCWSTR Valuename, _In_ ULONG Type, _In_reads_bytes_(BufferLength) PVOID Buffer, _In_ ULONG BufferLength);
NTSTATUS RtlRegGetKeyValue(_In_ LPCWSTR RegistryPath, _In_ LPCWSTR Valuename, _Out_writes_bytes_(BufferLength) PVOID Buffer, _In_ ULONG BufferLength);
NTSTATUS RtlRegDeleteKey(_In_ LPCWSTR RegistryPath);

FORCEINLINE NTSTATUS RtlRegSetKeyValue32(_In_ LPCWSTR RegistryPath, _In_ LPCWSTR Valuename, ULONG Value)
{
    return RtlRegSetKeyValue(RegistryPath, Valuename, REG_DWORD, &Value, sizeof(ULONG));
}

FORCEINLINE NTSTATUS RtlRegSetKeyValue64(_In_ LPCWSTR RegistryPath, _In_ LPCWSTR Valuename, ULONGLONG Value)
{
    return RtlRegSetKeyValue(RegistryPath, Valuename, REG_QWORD, &Value, sizeof(ULONGLONG));
}
