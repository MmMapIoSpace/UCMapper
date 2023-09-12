#include "main.h"

#define WINDOWS_11_22H2
#if defined(WINDOWS_11_22H2)
//SigMakerEx: Finding signature for 0000000086A1A2.
//Address SIG: 0x0000000086A1A2, 22 bytes 12, wildcards.
//IDA: "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B C3 48 83 C4"
//"\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x8B\xC3\x48\x83\xC4", "xxx????x????x????xxxxx"

static UCHAR PiDDBLockPattern[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x8B\xC3\x48\x83\xC4";
static CHAR PiDDBLockMask[]     = "xxx????x????x????xxxxx";

//SigMakerEx: Finding signature for 0000000074DFB2.
//Address SIG: 0x0000000074DFB2, 14 bytes 4, wildcards.
//IDA: "48 8D 0D ?? ?? ?? ?? 45 33 F6 48 89 44 24"
//"\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xF6\x48\x89\x44\x24", "xxx????xxxxxxx"

static UCHAR PiDDBCacheTablePattern[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xF6\x48\x89\x44\x24";
static CHAR PiDDBCacheTableMask[]     = "xxx????xxxxxxx";
static UCHAR HashBucketListPattern[]  = "\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00";
static CHAR HashBucketListMask[]      = "xxx????x?xxxxxxx";
static UCHAR HashCacheLockPattern[]   = "\x48\x8D\x0D";
static CHAR HashCacheLockMask[]       = "xxx";
#endif

#define Log(_Format, ...) wprintf_s(L##_Format L"\r\n", __VA_ARGS__)

//
// Utility
//

PVOID MiFindPattern(_In_reads_bytes_(Length) PVOID BaseAddress, _In_ SIZE_T Length, _In_ PUCHAR Pattern, _In_ PCHAR Mask)
{
    ANSI_STRING v1;
    PVOID v2;
    BOOLEAN v3;
    SIZE_T i;
    PUCHAR v4;
    SIZE_T j;

    v2 = NULL;
    RtlInitString(&v1, Mask);
    for (j = 0; j < (Length - v1.Length); j += 1) {
        v3 = TRUE;
        v4 = (PUCHAR)BaseAddress + j;

        for (i = 0; i < v1.Length; i += 1) {
            if (v1.Buffer[i] == 'x' && Pattern[i] != v4[i]) {
                v3 = FALSE;
                break;
            }
        }

        if (v3 == TRUE) {
            v2 = (PVOID)((PCHAR)BaseAddress + j);
            break;
        }
    }
    return v2;
}

PVOID KiFindPattern(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ PVOID BaseAddress, _In_ SIZE_T Length, _In_ PUCHAR Pattern, _In_ PCHAR Mask)
{
    ULONGLONG v1 = 0;
    PVOID v2     = RtlAllocateMemory(Length);

    if NT_SUCCESS (Driver->ReadMemory(Driver->DeviceHandle, (ULONGLONG)BaseAddress, v2, Length)) {
        v1 = (ULONGLONG)MiFindPattern(v2, Length, Pattern, Mask);

        if (v1 != 0) {
            v1 -= (ULONGLONG)v2;
            v1 += (ULONGLONG)BaseAddress;
        }

        RtlFreeMemory(v2);
    }

    return (PVOID)v1;
}

PVOID KiRelativeVirtualAddress(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ PVOID Address, _In_ LONG Offsets, _In_ SIZE_T Size)
{
    LONG VA        = 0;
    PVOID Resolved = 0;

    if NT_SUCCESS (Driver->ReadMemory(Driver->DeviceHandle, (ULONGLONG)Address + Offsets, &VA, sizeof(LONG))) {
        Resolved = (PVOID)((ULONGLONG)Address + Size + VA);
    }

    return Resolved;
}

//
// Main code.
//

BOOLEAN MmUnloadedDriver(_In_ PDEVICE_DRIVER_OBJECT Driver)
{
    ULONGLONG ProcessAddr;
    ULONGLONG DeviceObject;
    ULONGLONG DriverObject;
    ULONGLONG DriverSection;
    UNICODE_STRING BaseDllName;
    WCHAR DriverName[MAX_PATH];

    ProcessAddr = GetObjectByHandle(Driver->DeviceHandle);
    if (ProcessAddr) {
        RtlSecureZeroMemory(DriverName, sizeof(DriverName));
        if NT_ERROR (Driver->ReadMemory(Driver->DeviceHandle, ProcessAddr + 0x8, &DeviceObject, sizeof(DeviceObject)) || !DeviceObject) {
            Log("[!] Failed to find DeviceObject");
            return FALSE;
        }

        if NT_ERROR (Driver->ReadMemory(Driver->DeviceHandle, DeviceObject + offsetof(DEVICE_OBJECT, DriverObject), &DriverObject, sizeof(DriverObject))
                     || !DriverObject) {
            Log("[!] Failed to find DriverObject");
            return FALSE;
        }

        if NT_ERROR (Driver->ReadMemory(Driver->DeviceHandle, DriverObject + offsetof(DRIVER_OBJECT, DriverSection), &DriverSection, sizeof(DriverSection))
                     || !DriverSection) {
            Log("[!] Failed to find DriverSection");
            return FALSE;
        }

        if NT_ERROR (Driver->ReadMemory(Driver->DeviceHandle, DriverSection + offsetof(LDR_DATA_TABLE_ENTRY, BaseDllName), &BaseDllName, sizeof(BaseDllName))
                     || BaseDllName.Length == 0) {
            Log("[!] Failed to find DriverName");
            return FALSE;
        }

        if NT_ERROR (Driver->ReadMemory(Driver->DeviceHandle, (ULONGLONG)BaseDllName.Buffer, DriverName, BaseDllName.Length)) {
            Log("[!] Failed to read DriverName");
            return FALSE;
        }

        Log("[+] Found %ws on Ldr Table Entry.", DriverName);
        // MiRememberUnloadedDriver will check
        // if the length > 0 to save the unloaded
        // driver
        BaseDllName.Length = 0;
        if NT_ERROR (Driver->WriteMemory(Driver->DeviceHandle,
                                         DriverSection + offsetof(LDR_DATA_TABLE_ENTRY, BaseDllName),
                                         &BaseDllName,
                                         sizeof(BaseDllName))) {
            Log("[!] Failed to write driver name length");
            return FALSE;
        }

        return TRUE;
    }

    return FALSE;
}

BOOLEAN PidDBCacheTable(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ LPWSTR DriverFilename, _In_ ULONG TimeDateStamp)
{
    PVOID PiDDBLock;
    PRTL_AVL_TABLE PiDDBCacheTable;
    RTL_PROCESS_MODULE_INFORMATION KernelModule;
    PPIDDB_CACHE_ENTRY pFoundEntry;
    PIDDB_CACHE_ENTRY LocalEntry;
    CHAR v1[] = {'n', 't', 'o', 's', 'k', 'r', 'n', 'l', '.', 'e', 'x', 'e', '\0'};

    RtlZeroMemory(&KernelModule, sizeof(KernelModule));
    GetSystemModuleInformationA(v1, &KernelModule);
    RTL_ASSERT(KernelModule.ImageBase != NULL);

    PiDDBLock       = KiFindPattern(Driver, KernelModule.ImageBase, KernelModule.ImageSize, PiDDBLockPattern, PiDDBLockMask);
    PiDDBCacheTable = KiFindPattern(Driver, KernelModule.ImageBase, KernelModule.ImageSize, PiDDBCacheTablePattern, PiDDBCacheTableMask);
    if (PiDDBLock && PiDDBCacheTable) {
        PiDDBLock       = KiRelativeVirtualAddress(Driver, PiDDBLock, 3, 7);
        PiDDBCacheTable = KiRelativeVirtualAddress(Driver, PiDDBCacheTable, 3, 7);
    }

    if (PiDDBLock == 0 || PiDDBCacheTable == 0) {
        Log("[-] PiDDBLock: 0x%p.", PiDDBLock);
        Log("[-] PiDDBCacheTable: 0x%p.", PiDDBCacheTable);

        return FALSE;
    }

    //
    // context part is not used by lookup, lock or delete why we should use it?
    //

    if (!ExAcquireResourceExclusiveLite(Driver, PiDDBLock, TRUE)) {
        Log("[-] Can't lock PiDDBCacheTable");
        return FALSE;
    }

    //
    // search our entry in the table
    //
    LocalEntry.TimeDateStamp = TimeDateStamp;
    RtlInitUnicodeString(&LocalEntry.DriverName, DriverFilename);
    pFoundEntry = KiRtlLookupElementGenericTableAvl(Driver, PiDDBCacheTable, &LocalEntry);
    if (pFoundEntry == NULL) {
        Log("[-] Not found in cache");
        ExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    // first, unlink from the list
    PLIST_ENTRY PreviousList = NULL;
    if NT_ERROR (Driver->ReadMemory(Driver->DeviceHandle,
                                    (ULONGLONG)pFoundEntry + FIELD_OFFSET(PIDDB_CACHE_ENTRY, List.Blink),
                                    &PreviousList,
                                    sizeof(PLIST_ENTRY))) {
        Log("[-] Can't get prev entry");
        ExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    PLIST_ENTRY next = NULL;
    if NT_ERROR (Driver->ReadMemory(Driver->DeviceHandle, (ULONGLONG)pFoundEntry + FIELD_OFFSET(PIDDB_CACHE_ENTRY, List.Flink), &next, sizeof(PLIST_ENTRY))) {
        Log("[-] Can't get next entry");
        ExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    if NT_ERROR (Driver->WriteMemory(Driver->DeviceHandle, (ULONGLONG)PreviousList + FIELD_OFFSET(struct _LIST_ENTRY, Flink), &next, sizeof(PLIST_ENTRY))) {
        Log("[-] Can't set next entry");
        ExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    if NT_ERROR (Driver->WriteMemory(Driver->DeviceHandle, (ULONGLONG)next + FIELD_OFFSET(struct _LIST_ENTRY, Blink), &PreviousList, sizeof(PLIST_ENTRY))) {
        Log("[-] Can't set prev entry");
        ExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    // then delete the element from the avl table
    if (!KiRtlDeleteElementGenericTableAvl(Driver, PiDDBCacheTable, pFoundEntry)) {
        Log("[-] Can't delete from PiDDBCacheTable");
        ExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    //
    // Decrement delete count
    //

    ULONG cacheDeleteCount = 0;
    Driver->ReadMemory(Driver->DeviceHandle, (ULONGLONG)PiDDBCacheTable + (FIELD_OFFSET(struct _RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
    if (cacheDeleteCount > 0) {
        cacheDeleteCount--;
        if NT_ERROR (Driver->WriteMemory(Driver->DeviceHandle,
                                         (ULONGLONG)PiDDBCacheTable + (FIELD_OFFSET(struct _RTL_AVL_TABLE, DeleteCount)),
                                         &cacheDeleteCount,
                                         sizeof(ULONG))) {
            Log("[-] Failed WriteSystemMemory to cacheDeleteCount.");
        }
    }

    //
    // release the ddb resource lock
    //

    ExReleaseResourceLite(Driver, PiDDBLock);
    Log("[+] PidDb Cleaned.");
    return TRUE;
}

BOOLEAN KernelHashBucketList(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ LPWSTR DriverFilename)
{
    RTL_PROCESS_MODULE_INFORMATION ModuleInformation;
    CHAR v1[] = {'c', 'i', '.', 'd', 'l', 'l', '\0'};


    if (GetSystemModuleInformationA(v1, &ModuleInformation) == FALSE)
        return FALSE;

    // Thanks @KDIo3 and @Swiftik from UnknownCheats
    PVOID HashBucketList = KiFindPattern(Driver, ModuleInformation.ImageBase, ModuleInformation.ImageSize, HashBucketListPattern, HashBucketListMask);
    PVOID HashBucketLock = KiFindPattern(Driver, (PCHAR)HashBucketList - 50, 50, HashCacheLockPattern, HashCacheLockMask);
    if (HashBucketList && HashBucketLock) {
        HashBucketList = KiRelativeVirtualAddress(Driver, HashBucketList, 3, 7);
        HashBucketLock = KiRelativeVirtualAddress(Driver, HashBucketLock, 3, 7);
    }

    if (!HashBucketList || !HashBucketLock) {
        Log("[-] HashBucketList: 0x%p.", HashBucketList);
        Log("[-] HashBucketLock: 0x%p.", HashBucketLock);
        return FALSE;
    }

    if (ExAcquireResourceExclusiveLite(Driver, HashBucketLock, TRUE) == TRUE) {
        PHASH_BUCKET_ENTRY HashBucketPrev  = HashBucketList;
        PHASH_BUCKET_ENTRY HashBucketEntry = NULL;

        if NT_ERROR (Driver->ReadMemory(Driver->DeviceHandle, (ULONGLONG)HashBucketPrev, &HashBucketEntry, sizeof(HashBucketEntry))) {
            Log("[-] Failed to read first HashBucketEntry: 0x%p.", HashBucketEntry);
            goto Exit;
        }

        if (!HashBucketEntry) {
            Log("[!] g_KernelHashBucketList looks empty!");
            ExReleaseResourceLite(Driver, HashBucketLock);
            return TRUE;
        }

        do {
            PHASH_BUCKET_ENTRY HashBucketNext = 0;
            HASH_BUCKET_ENTRY HashBucket;
            LPWSTR lpDriverName;

            if NT_SUCCESS (Driver->ReadMemory(Driver->DeviceHandle, (ULONGLONG)HashBucketEntry, &HashBucket, sizeof(HashBucket))) {
                lpDriverName = RtlAllocateMemory(HashBucket.DriverName.MaximumLength);

                if NT_SUCCESS (Driver->ReadMemory(Driver->DeviceHandle, (ULONGLONG)HashBucket.DriverName.Buffer, lpDriverName, HashBucket.DriverName.Length)) {
                    if (wcsstr(lpDriverName, DriverFilename)) {
                        if NT_SUCCESS (Driver->ReadMemory(Driver->DeviceHandle, (ULONGLONG)HashBucketEntry, &HashBucketNext, sizeof(HashBucketNext))) {
                            if (NT_SUCCESS(Driver->WriteMemory(Driver->DeviceHandle, (ULONGLONG)HashBucketPrev, &HashBucketNext, sizeof(HashBucketNext)))) {
                                ExFreePool(Driver, (ULONGLONG)HashBucketEntry);
                                ExReleaseResourceLite(Driver, HashBucketLock);

                                Log("[+] Found %ws on HashBucketList.", lpDriverName);
                                RtlFreeMemory(lpDriverName);
                                return TRUE;
                            }
                        }
                    }
                }
                RtlFreeMemory(lpDriverName);
            }

            // Read Next
            HashBucketPrev = HashBucketEntry;
            if NT_ERROR (Driver->ReadMemory(Driver->DeviceHandle, (ULONGLONG)HashBucketEntry, &HashBucketEntry, sizeof(HashBucketEntry))) {
                Log("[-] Failed to read HashBucketEntry next entry: 0x%p.", HashBucketEntry);
                goto Exit;
            }

        } while (HashBucketEntry != HashBucketPrev);

    Exit:

        ExReleaseResourceLite(Driver, HashBucketLock);
    }

    return FALSE;
}

//
// Public api
//

BOOLEAN RemoveDriverRuntimeList(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ LPCWSTR DriverName, _In_ ULONG TimedateStamps)
{
    BOOLEAN v1;

    v1 = PidDBCacheTable(Driver, (LPWSTR)DriverName, TimedateStamps);

    if (v1 == TRUE)
        v1 = KernelHashBucketList(Driver, (LPWSTR)DriverName);

    if (v1 == TRUE)
        v1 = MmUnloadedDriver(Driver);

    return v1;
}
