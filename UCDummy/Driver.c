#include <ntifs.h>

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[+] Driver called on 0x%p.", PsGetCurrentProcess());
    DbgPrint("[+] Driver called at %02X.", KeGetCurrentIrql());
    DbgPrint("[+] Driver start at %p.", DriverObject->DriverStart);
    DbgPrint("[+] Driver size for %08X.", DriverObject->DriverSize);

    return STATUS_UNSUCCESSFUL;
}
