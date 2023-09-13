#pragma once

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS KiExAllocatePool2(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ SIZE_T NumberOfBytes,
    _Out_ PULONGLONG Pointer);
NTSTATUS KiExFreePool(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ ULONGLONG Pointer);
NTSTATUS KiExReleaseResourceLite(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ PVOID Resource);
NTSTATUS KiExAcquireResourceExclusiveLite(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ PVOID Resource,
    _In_ BOOLEAN Wait);
NTSTATUS KiRtlDeleteElementGenericTableAvl(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer);
NTSTATUS KiRtlLookupElementGenericTableAvl(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer,
    _Out_ PVOID* Pointer);

#ifdef __cplusplus
}
#endif
