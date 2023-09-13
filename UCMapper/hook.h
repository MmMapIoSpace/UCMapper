#pragma once

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS HookSystemRoutine(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ ULONGLONG NewAddress,
    _Out_writes_bytes_(12) PUCHAR Native);
NTSTATUS UnhookSystemRoutine(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_reads_bytes_(12) PUCHAR Native);

#ifdef __cplusplus
}
#endif
