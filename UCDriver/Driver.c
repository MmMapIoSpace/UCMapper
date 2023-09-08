#include "Driver.h"

DRIVER_INITIALIZE DriverEntry;
KSTART_ROUTINE DriverMain;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverMain)
#endif

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    PKLDR_DATA_TABLE_ENTRY DriverTable;
    ULONG DriverNameVA;

    UNREFERENCED_PARAMETER(RegistryPath);

    Status = STATUS_ACCESS_DENIED;

    //
    // Remove Driver Runtime List
    //

    DriverTable = DriverObject->DriverSection;
    if (DriverTable != NULL) {
        DriverTable->BaseDllName.Length = 0;
    }

    //
    // Create ioctl
    //

    DriverNameVA  = sizeof(L"\\Driver\\");
    DriverNameVA -= sizeof(WCHAR);
    DriverNameVA /= sizeof(WCHAR);

    return Status;
}

VOID DriverMain(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS Status;

    Status = STATUS_SUCCESS;

    DriverObject->DriverUnload(DriverObject);
    PsTerminateSystemThread(Status);
}
