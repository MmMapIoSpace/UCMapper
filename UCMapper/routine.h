#pragma once

FORCEINLINE PVOID RtlAllocateMemory(_In_ SIZE_T NumberOfBytes)
{
    PVOID Pointer = NULL;
    while (Pointer == NULL)
        Pointer = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, NumberOfBytes);
    return Pointer;
}

FORCEINLINE PVOID RtlReAllocateMemory(_In_ PVOID Pointer, _In_ SIZE_T NumberOfBytes)
{
    return RtlReAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Pointer, NumberOfBytes);
}

FORCEINLINE BOOLEAN RtlFreeMemory(_In_ PVOID Pointer)
{
    return RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Pointer);
}

NTSTATUS ObGetObjectByHandle(_In_ HANDLE Handle, _Out_ PULONGLONG Pointer);
NTSTATUS MmGetSystemModuleA(
    _In_ LPCSTR ModuleName,
    _Out_ PRTL_PROCESS_MODULE_INFORMATION ModuleInformation);
NTSTATUS MmGetSystemModuleW(
    _In_ LPCWSTR ModuleName,
    _Out_ PRTL_PROCESS_MODULE_INFORMATION ModuleInformation);
NTSTATUS MmGetSystemRoutineAddressA(_In_ LPCSTR RoutineName, _Out_ PULONGLONG Pointer);
NTSTATUS MmGetSystemRoutineAddressW(_In_ LPCWSTR ModuleName, _Out_ PULONGLONG Pointer);

FORCEINLINE ULONGLONG MmGetSystemModuleBaseA(_In_ LPCSTR ModuleName)
{
    RTL_PROCESS_MODULE_INFORMATION mi;

    if NT_SUCCESS (MmGetSystemModuleA(ModuleName, &mi))
        return (ULONGLONG)mi.ImageBase;

    return 0;
}

FORCEINLINE ULONGLONG MmGetSystemModuleBaseW(_In_ LPCWSTR ModuleName)
{
    RTL_PROCESS_MODULE_INFORMATION mi;

    if NT_SUCCESS (MmGetSystemModuleW(ModuleName, &mi))
        return (ULONGLONG)mi.ImageBase;

    return 0;
}

FORCEINLINE ULONGLONG GetSystemRoutineAddressA(_In_ LPCSTR RoutineName)
{
    ULONGLONG Pointer;
    if NT_SUCCESS (MmGetSystemRoutineAddressA(RoutineName, &Pointer))
        return Pointer;

    return 0;
}

FORCEINLINE ULONGLONG GetSystemRoutineAddressW(_In_ LPCWSTR RoutineName)
{
    ULONGLONG Pointer;
    if NT_SUCCESS (MmGetSystemRoutineAddressW(RoutineName, &Pointer))
        return Pointer;

    return 0;
}
