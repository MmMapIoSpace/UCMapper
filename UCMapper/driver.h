#pragma once

NTSTATUS LoadDriver(_Out_ PHANDLE DeviceHandle, _In_ LPCWSTR DriverFullPath, _In_ LPCWSTR ServiceName, _In_ LPCWSTR DeviceName);
NTSTATUS UnloadDriver(_In_ HANDLE DeviceHandle, _In_ LPCWSTR ServiceName);
NTSTATUS ReadSystemMemory(_In_ HANDLE DeviceHandle, _In_ ULONGLONG Source, _Out_writes_bytes_(Length) PVOID Destination, _In_ SIZE_T Length);
NTSTATUS WriteSystemMemory(_In_ HANDLE DeviceHandle, _In_ ULONGLONG Destination, _In_reads_bytes_(Length) PVOID Source, _In_ SIZE_T Length);

typedef NTSTATUS (*PFN_READSYSTEMMEMORY)(_In_ HANDLE DeviceHandle, _In_ ULONGLONG Source, _Out_writes_bytes_(Length) PVOID Destination, _In_ SIZE_T Length);
typedef NTSTATUS (*PFN_WRITESYSTEMMEMORY)(_In_ HANDLE DeviceHandle, _In_ ULONGLONG Destination, _In_reads_bytes_(Length) PVOID Source, _In_ SIZE_T Length);

typedef struct _DEVICE_DRIVER_OBJECT
{
    HANDLE DeviceHandle;
    PFN_READSYSTEMMEMORY ReadMemory;
    PFN_WRITESYSTEMMEMORY WriteMemory;
} DEVICE_DRIVER_OBJECT, *PDEVICE_DRIVER_OBJECT;

#define NVAUDIO_IOCTL_CODE 0x9C40A484

typedef enum _NVAUDIO_REQUEST_CLASS
{
    READ_CONTROL_REGISTER  = 0,
    WRITE_CONTROL_REGISTER = 1,
    GET_PHYSICAL_ADDRESS   = 0x26,
    READ_PHYSICAL_MEMORY   = 0x14,
    WRITE_PHYSICAL_MEMORY  = 0x15
} NVAUDIO_REQUEST_CLASS;

//Request.EncryptionKey[0] = 12868886329971960498;
//Request.EncryptionKey[1] = 13552922889676271240;
//Request.EncryptionKey[2] = 10838534925730813900;
//Request.EncryptionKey[3] = 11819403095038824665;
//Request.EncryptionKey[4] = 16047435637536096;
//Request.EncryptionKey[5] = 10679697536739367056;
//Request.EncryptionKey[6] = 18271467892729589711;
//Request.EncryptionKey[7] = 6472933704646412218;

#pragma pack(push, 1)

typedef struct _NVAUDIO_REQUEST
{
    NVAUDIO_REQUEST_CLASS RequestClass;

    union
    {
        struct
        {
            LONG NumberOfBytes;
            LONGLONG Destination;
            LONGLONG Source;
            UCHAR Padding0[32];
        };

        struct
        {
            LONG Reserved0;
            LONGLONG PhysicalAddress;
            LONGLONG VirtualAddress;
            UCHAR Padding1[32];
        };

        struct
        {
            LONG CRSize;
            LONG NumberOfCR;
            LONG Unk01;
            LONG Unk02;
            LONG Unk03;
            LONG Result;
            UCHAR Padding2[28];
        };
    };

    ULONGLONG EncryptionKey[64 / 8];
    UCHAR Reserved[312 - 64 - 56];

} NVAUDIO_REQUEST, *PNVAUDIO_REQUEST;

#pragma pack(pop)

static_assert(sizeof(NVAUDIO_REQUEST) == 312, "Structure Size Must be 312 Bytes.");
