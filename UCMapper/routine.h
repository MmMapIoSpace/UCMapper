#pragma once

#define RtlAllocateMemory(Size)            RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size)
#define RtlFreeMemory(Pointer)             RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Pointer)
#define RtlReAllocateMemory(Pointer, Size) RtlReAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Pointer, Size)

#define NtAllocateMemory(BaseAddress, RegionSize) \
    NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
#define NtFreeMemory(BaseAddress)                                                        \
    {                                                                                    \
        SIZE_T RegionSize = 0;                                                           \
        NtFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE); \
    }

#define NtLockMemory(BaseAddress, RegionSize)                NtLockVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, MAP_PROCESS)
#define NtUnlockMemory(BaseAddress, RegionSize)              NtUnlockVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, MAP_PROCESS)
#define NtProtectMemory(BaseAddress, RegionSize, Protection) NtProtectVirtualMemory(NtCurrentProcess(), &B, &RegionSize, Protection, &Protection)

ULONGLONG GetSystemModuleBaseA(_In_ LPCSTR ModuleName);
ULONGLONG GetSystemModuleBaseW(_In_ LPCWSTR ModuleName);
ULONGLONG GetSystemRoutineAddressA(_In_ LPCSTR RoutineName);
ULONGLONG GetSystemRoutineAddressW(_In_ LPCWSTR RoutineName);

ULONGLONG GetObjectByHandle(_In_ HANDLE ObjectHandle);

BOOLEAN GetSystemModuleInformationA(_In_ LPCSTR ModuleName, _Out_ PRTL_PROCESS_MODULE_INFORMATION Result);
