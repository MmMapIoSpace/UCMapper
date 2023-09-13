#pragma once

NTSTATUS RtlFileWrite(
    _In_ LPCWSTR Destination,
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_ SIZE_T BufferLength);
NTSTATUS RtlFileMap(_In_ LPCWSTR Source, _Out_ PVOID* BaseAddress, _Out_ PSIZE_T ViewSize);
NTSTATUS RtlFileMapImage(_In_ LPCWSTR Source, _Out_ PVOID* BaseAddress, _Out_ PSIZE_T ViewSize);
NTSTATUS RtlFileUnmap(_In_ PVOID BaseAddress);
NTSTATUS RtlFileDelete(_In_ LPCWSTR FilePath);
NTSTATUS RtlFileToImage(_In_ LPCWSTR Source, _In_ LPCWSTR Destination);
