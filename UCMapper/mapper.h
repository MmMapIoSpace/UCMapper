#pragma once

//
// Prototype
//

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

#define MdlMappingNoWrite       0x80000000 // Create the mapping as nowrite
#define MdlMappingNoExecute     0x40000000 // Create the mapping as noexecute
#define MdlMappingWithGuardPtes 0x20000000 // Create the mapping with guard PTEs

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
typedef NTSTATUS (*ZwClose_t)(HANDLE);
typedef NTSTATUS (*PsGetThreadExitStatus_t)(_In_ PVOID Thread);
typedef LONG_PTR (*ObfDereferenceObject_t)(_In_ PVOID Object);
typedef PVOID (*ExAllocatePool2_t)(_In_ ULONGLONG Flags, _In_ SIZE_T NumberOfBytes, _In_ ULONG Tag);
typedef void* (*memcpy_t)(
    _Out_writes_bytes_all_(_Size) void* _Dst,
    _In_reads_bytes_(_Size) const void* _Src,
    _In_ size_t _Size);
typedef void (*ExFreePoolWithTag_t)(PVOID P, ULONG Tag);
typedef void (*MmFreePagesFromMdl_t)(PVOID MemoryDescriptorList);
typedef PIMAGE_NT_HEADERS (*RtlImageNtHeader_t)(_In_ PVOID Base);
typedef NTSTATUS (*PsTerminateSystemThread_t)(NTSTATUS ExitStatus);
typedef NTSTATUS (*PDRIVER_INITIALIZE)(PDRIVER_OBJECT, PUNICODE_STRING);
typedef PVOID (*RtlFindExportedRoutineByName_t)(_In_ PVOID BaseOfImage, _In_ PSTR RoutineName);
typedef VOID (
    *RtlInitAnsiString_t)(PANSI_STRING DestinationString, __drv_aliasesMem PCSZ SourceString);
typedef NTSTATUS (*RtlAnsiStringToUnicodeString_t)(
    PUNICODE_STRING DestinationString,
    PCANSI_STRING SourceString,
    BOOLEAN AllocateDestinationString);
typedef BOOLEAN (*RtlEqualUnicodeString_t)(
    PCUNICODE_STRING String1,
    PCUNICODE_STRING String2,
    BOOLEAN CaseInSensitive);
typedef void (*RtlFreeUnicodeString_t)(PUNICODE_STRING UnicodeString);
typedef PVOID (*MmGetSystemRoutineAddress_t)(PUNICODE_STRING SystemRoutineName);
typedef NTSTATUS (*MmProtectMdlSystemAddress_t)(PVOID MemoryDescriptorList, ULONG NewProtect);
typedef PVOID (*IoAllocateMdl_t)(
    __drv_aliasesMem PVOID VirtualAddress,
    ULONG Length,
    BOOLEAN SecondaryBuffer,
    BOOLEAN ChargeQuota,
    PVOID Irp);
typedef void (*IoFreeMdl_t)(PVOID Mdl);

//
// Structure Data Type
//

typedef struct _KERNEL_IMPORT_TABLE
{
    PLIST_ENTRY PsLoadedModuleList;
    memcpy_t memcpy;
    PVOID memset;
    MmGetSystemRoutineAddress_t MmGetSystemRoutineAddress;
    MmAllocatePagesForMdlEx_t MmAllocatePagesForMdlEx;
    MmFreePagesFromMdl_t MmFreePagesFromMdl;
    MmMapLockedPagesSpecifyCache_t MmMapLockedPagesSpecifyCache;
    MmProtectMdlSystemAddress_t MmProtectMdlSystemAddress;
    KeWaitForSingleObject_t KeWaitForSingleObject;
    KeDelayExecutionThread_t KeDelayExecutionThread;
    ExAllocatePool2_t ExAllocatePool2;
    ExFreePoolWithTag_t ExFreePoolWithTag;
    RtlImageNtHeader_t RtlImageNtHeader;
    PVOID RtlInitUnicodeString;
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
} KERNEL_IMPORT_TABLE, *PKERNEL_IMPORT_TABLE;

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
