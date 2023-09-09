#pragma once

NTSTATUS WriteFileFromMemory(_In_ LPCWSTR Destination, _In_reads_bytes_(BufferLength) PVOID Buffer, _In_ SIZE_T BufferLength);
NTSTATUS DeleteFileFromDisk(_In_ LPCWSTR FilePath);
