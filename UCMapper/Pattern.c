#include "main.h"

#define MI_PATTERN_WILDCARD 0xAEUI8

NTSTATUS MmFindPattern(
    _In_reads_bytes_(SizeOfAddress) PVOID BaseAddress,
    _In_ SIZE_T SizeOfAddress,
    _In_reads_bytes_(PatternLength) PUCHAR Pattern,
    _In_ SIZE_T PatternLength,
    _Out_ PVOID* Pointer)
{
    NTSTATUS Status;
    SIZE_T i, j;

    *Pointer = NULL;
    Status   = STATUS_NOT_FOUND;
    if (Pattern != NULL && BaseAddress != NULL) {
        for (i = 0; i < SizeOfAddress - PatternLength; i++) {
            Status = STATUS_SUCCESS;
            for (j = 0; j < PatternLength; j++) {
                if (Pattern[j] != MI_PATTERN_WILDCARD
                    && Pattern[j] != ((PUCHAR)BaseAddress)[i + j]) {
                    Status = STATUS_INVALID_SIGNATURE;
                    break;
                }
            }

            if NT_SUCCESS (Status) {
                *Pointer = (PUCHAR)BaseAddress + i;
                Status   = STATUS_SUCCESS;
                break;
            }
        }
    }

    return Status;
}

NTSTATUS MmFindPattern2(
    _In_reads_bytes_(SizeOfAddress) PVOID BaseAddress,
    _In_ SIZE_T SizeOfAddress,
    _In_ PUCHAR Pattern,
    _In_ PCHAR Mask,
    _Out_ PVOID* Pointer)
{
    ANSI_STRING v1;
    BOOLEAN v3;
    SIZE_T i;
    PUCHAR v4;
    SIZE_T j;
    NTSTATUS s;

    s = STATUS_NOT_FOUND;
    RtlInitString(&v1, Mask);
    for (j = 0; j < (SizeOfAddress - v1.Length); j += 1) {
        v3 = TRUE;
        v4 = (PUCHAR)BaseAddress + j;

        for (i = 0; i < v1.Length; i += 1) {
            if (v1.Buffer[i] == 'x' && Pattern[i] != v4[i]) {
                v3 = FALSE;
                break;
            }
        }

        if (v3 == TRUE) {
            *Pointer = (PVOID)((PCHAR)BaseAddress + j);
            s        = STATUS_SUCCESS;
            break;
        }
    }
    return s;
}

NTSTATUS MmRelativeVirtualAddress(
    _In_ PVOID BaseAddress,
    _In_ LONG Offsets,
    _In_ SIZE_T Size,
    _Out_ PVOID* Pointer)
{
    NTSTATUS Status;
    LONG RVA;

    RVA    = *(PLONG)((ULONGLONG)BaseAddress + Offsets);
    Status = RVA != 0 ? STATUS_SUCCESS : STATUS_CONFLICTING_ADDRESSES;
    if NT_SUCCESS (Status)
        *Pointer = (PVOID)((ULONGLONG)BaseAddress + Size + RVA);

    return Status;
}
