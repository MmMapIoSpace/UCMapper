#pragma once

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
