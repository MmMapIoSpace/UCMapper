#pragma once

#ifndef METHOD_DECLARE_STRUCTURE
#define METHOD_DECLARE_STRUCTURE(x) \
    typedef struct _##x x, *P##x;   \
    struct _##x
#endif

#define MM_UNLOADED_DRIVER_SIZE 50

METHOD_DECLARE_STRUCTURE(DDBCACHE_ENTRY)
{
    //
    // These fields are used as matching critereon for cache lookup.
    //
    LIST_ENTRY List;
    UNICODE_STRING Name; // Driver name
    ULONG TimeDateStamp; // Link date of the driver
    //
    // Reference data for the cached entry.
    //
    NTSTATUS Status; // Status from the DDB lookup
    GUID Guid;
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
    ULONGLONG UnloadTime;
};

METHOD_DECLARE_STRUCTURE(MP_RUNTIME_DRIVERS)
{
    LIST_ENTRY DriverInfoList;
    UNICODE_STRING ImageName;
    UNICODE_STRING DriverRegistryPath;
    UNICODE_STRING CertPublisher;
    UNICODE_STRING CertIssuer;
    PVOID ImageHash;
    ULONG ImageHashAlgorithm;
    ULONG ImageHashLength;
    PVOID CertThumbprint;
    ULONG ThumbprintHashAlgorithm;
    ULONG CertificateThumbprintLength;
    PVOID ImageBase;
    SIZE_T ImageSize;
    ULONG ImageFlags;
    ULONG DriverClassification;
    ULONG ModuleEntryEnd;
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

NTSTATUS RemoveDriverRuntimeList(IN PDEVICE_DRIVER_OBJECT Driver, IN LPCWSTR DriverName);
