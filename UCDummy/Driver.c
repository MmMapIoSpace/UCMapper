#include <ntifs.h>

VOID DriverMain(_In_ PDRIVER_OBJECT DriverObject)
{
    HANDLE exitThread;
    LARGE_INTEGER timeout;

    DbgPrint("[+] System Thread started.");

    timeout.QuadPart = (-(
        (((LONGLONG)(2))
         * (((LONGLONG)(1000L)) * (((LONGLONG)(1000L)) * (((LONGLONG)(1000L)) / 100L))))));

    KeDelayExecutionThread(KernelMode, FALSE, &timeout);

    if NT_SUCCESS (PsCreateSystemThread(
                       &exitThread,
                       THREAD_ALL_ACCESS,
                       NULL,
                       NULL,
                       NULL,
                       DriverObject->DriverUnload,
                       DriverObject))

        ZwClose(exitThread);

    DbgPrint("[+] Driver Exit.");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

extern PLIST_ENTRY PsLoadedModuleList;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    HANDLE mainThread;

    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[+] Driver called on 0x%p.", PsGetCurrentProcess());
    DbgPrint("[+] Driver called at %02X.", KeGetCurrentIrql());
    DbgPrint("[+] Driver start at %p.", DriverObject->DriverStart);
    DbgPrint("[+] Driver size for %08X.", DriverObject->DriverSize);
    DbgPrint("[+] PsLoadedModuleList 0x%p.", PsLoadedModuleList);

    if NT_SUCCESS (PsCreateSystemThread(
                       &mainThread,
                       THREAD_ALL_ACCESS,
                       NULL,
                       NULL,
                       NULL,
                       DriverMain,
                       DriverObject))

        return ZwClose(mainThread);

    return STATUS_UNSUCCESSFUL;
}
