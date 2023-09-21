#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifndef KERNEL_MODE_API
#define KERNEL_MODE_API __stdcall
#endif

// ========================================================================================================
//
// ========================================================================================================

PVOID MiFindPattern(
    _In_reads_bytes_(Length) PVOID BaseAddress,
    _In_ SIZE_T Length,
    _In_ PUCHAR Pattern,
    _In_ PCHAR Mask);

PVOID KiFindPattern(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Length,
    _In_ PUCHAR Pattern,
    _In_ PCHAR Mask);

PVOID KiRelativeVirtualAddress(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ PVOID Address,
    _In_ LONG Offsets,
    _In_ SIZE_T Size);

// ========================================================================================================
//
// ========================================================================================================

NTSTATUS KiExAllocatePool2(
    _In_ PDEVICE_DRIVER_OBJECT Driver,
    _In_ SIZE_T NumberOfBytes,
    _Out_ PULONGLONG Pointer);

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


NTSTATUS KiExFreePool(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ ULONGLONG Pointer);
NTSTATUS KiExReleaseResourceLite(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ PVOID Resource);


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

typedef void*(
    __cdecl* memset_t)(_Out_writes_bytes_all_(_Size) void* _Dst, _In_ int _Val, _In_ size_t _Size);

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

typedef BOOLEAN (*ExAcquireResourceExclusiveLite_t)(
    _Inout_ _Requires_lock_not_held_(*_Curr_)
        _When_(return != 0, _Acquires_exclusive_lock_(*_Curr_)) PERESOURCE Resource,
    _In_ _Literal_ BOOLEAN Wait);

typedef PVOID (*RtlLookupElementGenericTableAvl_t)(_In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer);
typedef BOOLEAN (*RtlDeleteElementGenericTableAvl_t)(_In_ PRTL_AVL_TABLE Table, _In_ PVOID Buffer);
typedef VOID (*ExReleaseResourceLite_t)(_Inout_ PERESOURCE Resource);

//
// Structure Data Type
//

typedef struct _KERNEL_IMPORT_TABLE
{
    PLIST_ENTRY PsLoadedModuleList;
    PEPROCESS PsInitialSystemProcess;

    ExAcquireResourceExclusiveLite_t ExAcquireResourceExclusiveLite;
    ExAllocatePool2_t ExAllocatePool2;
    ExFreePoolWithTag_t ExFreePoolWithTag;
    ExReleaseResourceLite_t ExReleaseResourceLite;
    IoAllocateMdl_t IoAllocateMdl;
    IoFreeMdl_t IoFreeMdl;
    KeDelayExecutionThread_t KeDelayExecutionThread;
    KeSetEvent_t KeSetEvent;
    KeWaitForSingleObject_t KeWaitForSingleObject;
    memcpy_t memcpy;
    memset_t memset;
    MmAllocatePagesForMdlEx_t MmAllocatePagesForMdlEx;
    MmCopyMemory_t MmCopyMemory;
    MmFreePagesFromMdl_t MmFreePagesFromMdl;
    MmGetSystemRoutineAddress_t MmGetSystemRoutineAddress;
    MmMapIoSpaceEx_t MmMapIoSpaceEx;
    MmMapLockedPagesSpecifyCache_t MmMapLockedPagesSpecifyCache;
    MmMapViewInSystemSpace_t MmMapViewInSystemSpace;
    MmProbeAndLockPages_t MmProbeAndLockPages;
    MmProtectMdlSystemAddress_t MmProtectMdlSystemAddress;
    MmUnlockPages_t MmUnlockPages;
    MmUnmapIoSpace_t MmUnmapIoSpace;
    MmUnmapLockedPages_t MmUnmapLockedPages;
    MmUnmapViewInSystemSpace_t MmUnmapViewInSystemSpace;
    ObfDereferenceObject_t ObfDereferenceObject;
    ObReferenceObjectByHandle_t ObReferenceObjectByHandle;
    PsCreateSystemThread_t PsCreateSystemThread;
    PsGetThreadExitStatus_t PsGetThreadExitStatus;
    PsLookupProcessByProcessId_t PsLookupProcessByProcessId;
    PsTerminateSystemThread_t PsTerminateSystemThread;
    RtlAnsiStringToUnicodeString_t RtlAnsiStringToUnicodeString;
    RtlDeleteElementGenericTableAvl_t RtlDeleteElementGenericTableAvl;
    RtlEqualUnicodeString_t RtlEqualUnicodeString;
    RtlFindExportedRoutineByName_t RtlFindExportedRoutineByName;
    RtlFreeUnicodeString_t RtlFreeUnicodeString;
    RtlImageDirectoryEntryToData_t RtlImageDirectoryEntryToData;
    RtlImageNtHeader_t RtlImageNtHeader;
    RtlInitAnsiString_t RtlInitAnsiString;
    RtlInitUnicodeString_t RtlInitUnicodeString;
    RtlLookupElementGenericTableAvl_t RtlLookupElementGenericTableAvl;
    ZwClose_t ZwClose;
    ZwCreateSection_t ZwCreateSection;
    ZwOpenEvent_t ZwOpenEvent;
    ZwOpenFile_t ZwOpenFile;
} KERNEL_IMPORT_TABLE, *PKERNEL_IMPORT_TABLE;

C_ASSERT(sizeof(KERNEL_IMPORT_TABLE) == 368);


NTSTATUS MiResolveImportTable(IN OUT PKERNEL_IMPORT_TABLE Table);

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

#ifdef __cplusplus
}
#endif
