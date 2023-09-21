#pragma once

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
