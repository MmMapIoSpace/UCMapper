#pragma once

//
// Prototype
//

typedef struct _MDL* PMDL;
typedef struct _EPROCESS* PEPROCESS;

typedef struct _MM_COPY_ADDRESS
{
    union
    {
        PVOID VirtualAddress;
        PHYSICAL_ADDRESS PhysicalAddress;
    };
} MM_COPY_ADDRESS, *PMMCOPY_ADDRESS;

typedef enum _MEMORY_CACHING_TYPE
{
    MmNonCached,
    MmCached,
    MmWriteCombined,
    MmHardwareCoherentCached,
    MmNonCachedUnordered,
    MmUSWCCached,
    MmMaximumCacheType,
    MmNotMapped
} MEMORY_CACHING_TYPE;

typedef enum _MM_PAGE_PRIORITY
{
    LowPagePriority,
    NormalPagePriority = 16,
    HighPagePriority   = 32
} MM_PAGE_PRIORITY;

typedef enum _LOCK_OPERATION
{
    IoReadAccess,
    IoWriteAccess,
    IoModifyAccess
} LOCK_OPERATION;

#define MdlMappingNoWrite       0x80000000 // Create the mapping as nowrite
#define MdlMappingNoExecute     0x40000000 // Create the mapping as noexecute
#define MdlMappingWithGuardPtes 0x20000000 // Create the mapping with guard PTEs


typedef NTSTATUS (*ZwClose_t)(HANDLE);
typedef NTSTATUS (*PsGetThreadExitStatus_t)(_In_ PVOID Thread);
typedef LONG_PTR (*ObfDereferenceObject_t)(_In_ PVOID Object);
typedef PVOID (*ExAllocatePool2_t)(_In_ ULONGLONG Flags, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag);
typedef void (*ExFreePoolWithTag_t)(PVOID P, ULONG Tag);
typedef void (*MmFreePagesFromMdl_t)(PVOID MemoryDescriptorList);
typedef PIMAGE_NT_HEADERS (*RtlImageNtHeader_t)(_In_ PVOID Base);
typedef NTSTATUS (*PsTerminateSystemThread_t)(NTSTATUS ExitStatus);
typedef NTSTATUS (*PDRIVER_INITIALIZE)(PDRIVER_OBJECT, PUNICODE_STRING);
typedef PVOID (*RtlFindExportedRoutineByName_t)(_In_ PVOID BaseOfImage, _In_ PSTR RoutineName);
typedef void (*RtlFreeUnicodeString_t)(PUNICODE_STRING UnicodeString);
typedef PVOID (*MmGetSystemRoutineAddress_t)(PUNICODE_STRING SystemRoutineName);
typedef NTSTATUS (*MmProtectMdlSystemAddress_t)(PVOID MemoryDescriptorList, ULONG NewProtect);
typedef void (*IoFreeMdl_t)(PVOID Mdl);
typedef VOID (*MmUnmapLockedPages_t)(_In_ PVOID BaseAddress, _Inout_ PMDL MemoryDescriptorList);
typedef VOID (*MmUnlockPages_t)(_Inout_ PMDL MemoryDescriptorList);
typedef LONG (*KeSetEvent_t)(IN OUT PRKEVENT Event, IN KPRIORITY Increment, IN BOOLEAN Wait);
typedef NTSTATUS (*MmMapViewInSystemSpace_t)(IN PVOID Section, PVOID* MappedBase, PSIZE_T ViewSize);
typedef NTSTATUS (*MmUnmapViewInSystemSpace_t)(PVOID MappedBase);
typedef NTSTATUS (*PsLookupProcessByProcessId_t)(IN HANDLE ProcessId, OUT PEPROCESS* Process);
typedef void (*MmUnmapIoSpace_t)(IN PVOID BaseAddress, IN SIZE_T NumberOfBytes);

typedef PVOID (*IoAllocateMdl_t)(
    __drv_aliasesMem PVOID VirtualAddress,
    ULONG Length,
    BOOLEAN SecondaryBuffer,
    BOOLEAN ChargeQuota,
    PVOID Irp);

typedef BOOLEAN (*RtlEqualUnicodeString_t)(
    PCUNICODE_STRING String1,
    PCUNICODE_STRING String2,
    BOOLEAN CaseInSensitive);

typedef NTSTATUS (*RtlAnsiStringToUnicodeString_t)(
    PUNICODE_STRING DestinationString,
    PCANSI_STRING SourceString,
    BOOLEAN AllocateDestinationString);

typedef VOID (
    *RtlInitAnsiString_t)(PANSI_STRING DestinationString, __drv_aliasesMem PCSZ SourceString);

typedef void* (*memcpy_t)(
    _Out_writes_bytes_all_(_Size) void* _Dst,
    _In_reads_bytes_(_Size) const void* _Src,
    _In_ size_t _Size);

typedef NTSTATUS (*PsCreateSystemThread_t)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ULONG DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ HANDLE ProcessHandle,
    _Out_opt_ PCLIENT_ID ClientId,
    _In_ PKSTART_ROUTINE StartRoutine,
    _In_opt_ _When_(return >= 0, __drv_aliasesMem) PVOID StartContext);

typedef PVOID (*MmMapLockedPagesSpecifyCache_t)(
    _Inout_ PVOID MemoryDescriptorList,
    _In_ __drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst) KPROCESSOR_MODE AccessMode,
    _In_ __drv_strictTypeMatch(__drv_typeCond) MEMORY_CACHING_TYPE CacheType,
    _In_opt_ PVOID RequestedAddress,
    _In_ ULONG BugCheckOnFailure,
    _In_ ULONG Priority);

typedef NTSTATUS (*KeWaitForSingleObject_t)(
    _In_ _Points_to_data_ PVOID Object,
    _In_ _Strict_type_match_ KWAIT_REASON WaitReason,
    _In_ __drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst) KPROCESSOR_MODE WaitMode,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);

typedef NTSTATUS (*KeDelayExecutionThread_t)(
    _In_ KPROCESSOR_MODE WaitMode,
    _In_ BOOLEAN Alertable,
    _In_ PLARGE_INTEGER Interval);

typedef PVOID (*MmAllocatePagesForMdlEx_t)(
    PHYSICAL_ADDRESS LowAddress,
    PHYSICAL_ADDRESS HighAddress,
    PHYSICAL_ADDRESS SkipBytes,
    SIZE_T TotalBytes,
    MEMORY_CACHING_TYPE CacheType,
    ULONG Flags);

typedef PVOID (*RtlImageDirectoryEntryToData_t)(
    _In_ PVOID BaseOfImage,
    _In_ BOOLEAN MappedAsImage,
    _In_ USHORT DirectoryEntry,
    _Out_ PULONG Size);

typedef NTSTATUS (*ObReferenceObjectByHandle_t)(
    _In_ HANDLE Handle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PVOID* Object,
    _Out_opt_ PVOID HandleInformation);

typedef VOID (*MmProbeAndLockPages_t)(
    _Inout_ PMDL MemoryDescriptorList,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ LOCK_OPERATION Operation);

typedef NTSTATUS (*ZwOpenEvent_t)(
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS (*ZwCreateSection_t)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN OPTIONAL HANDLE FileHandle);

typedef NTSTATUS (*ZwOpenFile_t)(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions);

typedef NTSTATUS (*MmCopyMemory_t)(
    IN PVOID TargetAddress,
    IN MM_COPY_ADDRESS SourceAddress,
    IN SIZE_T NumberOfBytes,
    IN ULONG Flags,
    OUT PSIZE_T NumberOfBytesTransferred);

typedef PVOID (*MmMapIoSpaceEx_t)(
    IN PHYSICAL_ADDRESS PhysicalAddress,
    IN SIZE_T NumberOfBytes,
    IN ULONG Protect);

typedef VOID (*RtlInitUnicodeString_t)(
    OUT PUNICODE_STRING DestinationString,
    IN OPTIONAL __drv_aliasesMem PCWSTR SourceString);

//
// Structure Data Type
//

typedef struct _KERNEL_IMPORT_TABLE
{
#if 1
    PLIST_ENTRY PsLoadedModuleList;
    PEPROCESS PsInitialSystemProcess;
    memcpy_t memcpy;
    PVOID memset;
    KeSetEvent_t KeSetEvent;
    MmMapViewInSystemSpace_t MmMapViewInSystemSpace;
    MmUnmapViewInSystemSpace_t MmUnmapViewInSystemSpace;
    MmCopyMemory_t MmCopyMemory;
    MmMapIoSpaceEx_t MmMapIoSpaceEx;
    MmUnmapIoSpace_t MmUnmapIoSpace;
    PsLookupProcessByProcessId_t PsLookupProcessByProcessId;
    RtlInitUnicodeString_t RtlInitUnicodeString;
    ZwOpenFile_t ZwOpenFile;
    ZwCreateSection_t ZwCreateSection;
    ZwOpenEvent_t ZwOpenEvent;
    MmGetSystemRoutineAddress_t MmGetSystemRoutineAddress;
    MmAllocatePagesForMdlEx_t MmAllocatePagesForMdlEx;
    MmFreePagesFromMdl_t MmFreePagesFromMdl;
    MmMapLockedPagesSpecifyCache_t MmMapLockedPagesSpecifyCache;
    MmUnmapLockedPages_t MmUnmapLockedPages;
    MmProbeAndLockPages_t MmProbeAndLockPages;
    MmProtectMdlSystemAddress_t MmProtectMdlSystemAddress;
    MmUnlockPages_t MmUnlockPages;
    KeWaitForSingleObject_t KeWaitForSingleObject;
    KeDelayExecutionThread_t KeDelayExecutionThread;
    ExAllocatePool2_t ExAllocatePool2;
    ExFreePoolWithTag_t ExFreePoolWithTag;
    RtlImageNtHeader_t RtlImageNtHeader;
    RtlInitAnsiString_t RtlInitAnsiString;
    RtlAnsiStringToUnicodeString_t RtlAnsiStringToUnicodeString;
    RtlEqualUnicodeString_t RtlEqualUnicodeString;
    RtlFreeUnicodeString_t RtlFreeUnicodeString;
    RtlImageDirectoryEntryToData_t RtlImageDirectoryEntryToData;
    RtlFindExportedRoutineByName_t RtlFindExportedRoutineByName;
    ObReferenceObjectByHandle_t ObReferenceObjectByHandle;
    ObfDereferenceObject_t ObfDereferenceObject;
    PsCreateSystemThread_t PsCreateSystemThread;
    PsTerminateSystemThread_t PsTerminateSystemThread;
    PsGetThreadExitStatus_t PsGetThreadExitStatus;
    ZwClose_t ZwClose;
    IoAllocateMdl_t IoAllocateMdl;
    IoFreeMdl_t IoFreeMdl;
#else
    PVOID PsLoadedModuleList;
    PVOID PsInitialSystemProcess;
    PVOID memcpy;
    PVOID memset;
    PVOID KeSetEvent;
    PVOID MmMapViewInSystemSpace;
    PVOID MmUnmapViewInSystemSpace;
    PVOID MmCopyMemory;
    PVOID MmMapIoSpaceEx;
    PVOID MmUnmapIoSpace;
    PVOID PsLookupProcessByProcessId;
    PVOID RtlInitUnicodeString;
    PVOID ZwOpenFile;
    PVOID ZwCreateSection;
    PVOID ZwOpenEvent;
    PVOID MmGetSystemRoutineAddress;
    PVOID MmAllocatePagesForMdlEx;
    PVOID MmFreePagesFromMdl;
    PVOID MmMapLockedPagesSpecifyCache;
    PVOID MmUnmapLockedPages;
    PVOID MmProbeAndLockPages;
    PVOID MmProtectMdlSystemAddress;
    PVOID MmUnlockPages;
    PVOID KeWaitForSingleObject;
    PVOID KeDelayExecutionThread;
    PVOID ExAllocatePool2;
    PVOID ExFreePoolWithTag;
    PVOID RtlImageNtHeader;
    PVOID RtlInitAnsiString;
    PVOID RtlAnsiStringToUnicodeString;
    PVOID RtlEqualUnicodeString;
    PVOID RtlFreeUnicodeString;
    PVOID RtlImageDirectoryEntryToData;
    PVOID RtlFindExportedRoutineByName;
    PVOID ObReferenceObjectByHandle;
    PVOID ObfDereferenceObject;
    PVOID PsCreateSystemThread;
    PVOID PsTerminateSystemThread;
    PVOID PsGetThreadExitStatus;
    PVOID ZwClose;
    PVOID IoAllocateMdl;
    PVOID IoFreeMdl;
#endif
} KERNEL_IMPORT_TABLE, *PKERNEL_IMPORT_TABLE;

C_ASSERT(sizeof(KERNEL_IMPORT_TABLE) == 336);

typedef struct _MAPPER_EXECUTOR_CONTEXT
{
    SIZE_T ContextSize;
    PKSTART_ROUTINE WorkerThread;
    NTSTATUS DriverStatus;
    PVOID ImageBase;
    SIZE_T ImageSize;
    PVOID Unloader;
    PVOID MemoryDescriptor;
    PVOID MapSection;
    KERNEL_IMPORT_TABLE ImportTable;
} MAPPER_EXECUTOR_CONTEXT, *PMAPPER_EXECUTOR_CONTEXT;

NTSTATUS MmLoadSystemImage(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ PVOID ImageBase);

//0xa0 bytes (sizeof)
typedef struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;             //0x0
    VOID* ExceptionTable;                            //0x10
    ULONG ExceptionTableSize;                        //0x18
    VOID* GpValue;                                   //0x20
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo; //0x28
    VOID* DllBase;                                   //0x30
    VOID* EntryPoint;                                //0x38
    ULONG SizeOfImage;                               //0x40
    struct _UNICODE_STRING FullDllName;              //0x48
    struct _UNICODE_STRING BaseDllName;              //0x58
    ULONG Flags;                                     //0x68
    USHORT LoadCount;                                //0x6c

    union
    {
        USHORT SignatureLevel : 4; //0x6e
        USHORT SignatureType  : 3; //0x6e
        USHORT Frozen         : 2; //0x6e
        USHORT HotPatch       : 1; //0x6e
        USHORT Unused         : 6; //0x6e
        USHORT EntireField;        //0x6e
    } u1;                          //0x6e

    VOID* SectionPointer;      //0x70
    ULONG CheckSum;            //0x78
    ULONG CoverageSectionSize; //0x7c
    VOID* CoverageSection;     //0x80
    VOID* LoadedImports;       //0x88

    union
    {
        VOID* Spare;                                     //0x90
        struct _KLDR_DATA_TABLE_ENTRY* NtDataTableEntry; //0x90
    };

    ULONG SizeOfImageNotRounded; //0x98
    ULONG TimeDateStamp;         //0x9c
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

#ifdef _WIN64
#define DEFAULT_SECURITY_COOKIE 0x00002B992DDFA232
#else
#define DEFAULT_SECURITY_COOKIE 0xBB40E64E
#endif

#define LDRP_RELOCATION_INCREMENT      0x1
#define LDRP_RELOCATION_FINAL          0x2

#define IMAGE_REL_BASED_ABSOLUTE       0
#define IMAGE_REL_BASED_HIGH           1
#define IMAGE_REL_BASED_LOW            2
#define IMAGE_REL_BASED_HIGHLOW        3
#define IMAGE_REL_BASED_HIGHADJ        4
#define IMAGE_REL_BASED_MIPS_JMPADDR   5
#define IMAGE_REL_BASED_SECTION        6
#define IMAGE_REL_BASED_REL32          7
#define IMAGE_REL_BASED_MIPS_JMPADDR16 9
#define IMAGE_REL_BASED_IA64_IMM64     9
#define IMAGE_REL_BASED_DIR64          10
