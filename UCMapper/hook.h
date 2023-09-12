#pragma once

NTSTATUS HookSystemRoutine(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ ULONGLONG NewAddress, _Out_writes_bytes_(12) PUCHAR Native);
NTSTATUS UnhookSystemRoutine(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_reads_bytes_(12) PUCHAR Native);

//
// Kernel Routine
//

ULONGLONG ExAllocatePool2(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ SIZE_T NumberOfBytes);

BOOLEAN ExAcquireResourceExclusiveLite(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ PVOID Resource, _In_ BOOLEAN Wait);
BOOLEAN KiRtlDeleteElementGenericTableAvl(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer);

PVOID KiRtlLookupElementGenericTableAvl(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer);

VOID ExFreePool(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ ULONGLONG Pointer);
VOID ExReleaseResourceLite(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ PVOID Resource);
