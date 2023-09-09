#include "main.h"

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

#pragma region code_running_on_system_address_space

FORCEINLINE VOID InitSecurityCookie(_In_ PMAPPER_EXECUTOR_CONTEXT StartContext, _In_ PVOID ImageBase)
{
    PIMAGE_LOAD_CONFIG_DIRECTORY ConfigDirectory;
    PVOID Buffer;
    ULONG LoadConfigSize;
    PULONGLONG SecurityCookie;
    ULONGLONG NewCookie;

    Buffer          = StartContext->ImportTable.RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &LoadConfigSize);
    ConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)Buffer;

    if (ConfigDirectory && ConfigDirectory->SecurityCookie) {
        SecurityCookie  = (PULONGLONG)ConfigDirectory->SecurityCookie;
        NewCookie       = (ULONGLONG)SecurityCookie;
        NewCookie      ^= (ULONGLONG)ImageBase;

        if (*SecurityCookie == NewCookie)
            NewCookie += 1;

        /* If the result is 0 or the same as we got, just add one to the default value */
        if ((NewCookie == 0) || (NewCookie == *SecurityCookie))
            NewCookie = DEFAULT_SECURITY_COOKIE + 1;

        NewCookie       &= 0x0000FFFFffffFFFFi64;
        *SecurityCookie  = NewCookie;
    }
}

FORCEINLINE PIMAGE_BASE_RELOCATION LdrProcessRelocationBlockLongLong(_In_ ULONG_PTR VA, _In_ ULONG SizeOfBlock, _In_ PUSHORT NextOffset, _In_ LONGLONG Diff)
{
    PUCHAR FixupVA;
    USHORT Offset;
    LONG Temp;
    ULONGLONG Value64;

    while (SizeOfBlock--) {
        Offset  = *NextOffset & (USHORT)0xfff;
        FixupVA = (PUCHAR)(VA + Offset);

        //
        // Apply the fixups.
        //

        switch ((*NextOffset) >> 12) {
        case IMAGE_REL_BASED_HIGHLOW:
            //
            // HighLow - (32-bits) relocate the high and low half
            //      of an address.
            //
            *(LONG UNALIGNED*)FixupVA += (ULONG)Diff;
            break;

        case IMAGE_REL_BASED_HIGH:
            //
            // High - (16-bits) relocate the high half of an address.
            //
            Temp               = *(PUSHORT)FixupVA << 16;
            Temp              += (ULONG)Diff;
            *(PUSHORT)FixupVA  = (USHORT)(Temp >> 16);
            break;

        case IMAGE_REL_BASED_HIGHADJ:
            //
            // Adjust high - (16-bits) relocate the high half of an
            //      address and adjust for sign extension of low half.
            //

            //
            // If the address has already been relocated then don't
            // process it again now or information will be lost.
            //
            if (Offset & LDRP_RELOCATION_FINAL) {
                ++NextOffset;
                --SizeOfBlock;
                break;
            }

            Temp = *(PUSHORT)FixupVA << 16;
            ++NextOffset;
            --SizeOfBlock;
            Temp              += (LONG)(*(PSHORT)NextOffset);
            Temp              += (ULONG)Diff;
            Temp              += 0x8000;
            *(PUSHORT)FixupVA  = (USHORT)(Temp >> 16);

            break;

        case IMAGE_REL_BASED_LOW:
            //
            // Low - (16-bit) relocate the low half of an address.
            //
            Temp               = *(PSHORT)FixupVA;
            Temp              += (ULONG)Diff;
            *(PUSHORT)FixupVA  = (USHORT)Temp;
            break;

        case IMAGE_REL_BASED_IA64_IMM64:

            //
            // Align it to bundle address before fixing up the
            // 64-bit immediate value of the movl instruction.
            //

            FixupVA = (PUCHAR)((ULONG_PTR)FixupVA & ~(15));
            Value64 = (ULONGLONG)0;

            //
            // Extract the lower 32 bits of IMM64 from bundle
            //

            break;

        case IMAGE_REL_BASED_DIR64:

            *(ULONGLONG UNALIGNED*)FixupVA += Diff;

            break;

        case IMAGE_REL_BASED_MIPS_JMPADDR:
            //
            // JumpAddress - (32-bits) relocate a MIPS jump address.
            //
            Temp              = (*(PULONG)FixupVA & 0x3ffffff) << 2;
            Temp             += (ULONG)Diff;
            *(PULONG)FixupVA  = (*(PULONG)FixupVA & ~0x3ffffff) | ((Temp >> 2) & 0x3ffffff);

            break;

        case IMAGE_REL_BASED_ABSOLUTE:
            //
            // Absolute - no fixup required.
            //
            break;

        case IMAGE_REL_BASED_SECTION:
            //
            // Section Relative reloc.  Ignore for now.
            //
            break;

        case IMAGE_REL_BASED_REL32:
            //
            // Relative intrasection. Ignore for now.
            //
            break;

        default:
            //
            // Illegal - illegal relocation type.
            //

            return (PIMAGE_BASE_RELOCATION)NULL;
        }
        ++NextOffset;
    }
    return (PIMAGE_BASE_RELOCATION)NextOffset;
}

FORCEINLINE PVOID LdrGetSystemModuleBaseA(_In_ PMAPPER_EXECUTOR_CONTEXT StartContext, _In_ LPCSTR ModuleName)
{
    ANSI_STRING AnsiString;
    UNICODE_STRING UnicodeString;
    NTSTATUS Status;
    PKLDR_DATA_TABLE_ENTRY Destination;
    PKERNEL_IMPORT_TABLE ImportTable;
    PKLDR_DATA_TABLE_ENTRY Entry;
    PLIST_ENTRY Link;

    ImportTable = &StartContext->ImportTable;
    Destination = NULL;

    ImportTable->RtlInitAnsiString(&AnsiString, ModuleName);
    Status = ImportTable->RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);

    if NT_SUCCESS (Status) {
        for (Link = ImportTable->PsLoadedModuleList; Link != ImportTable->PsLoadedModuleList->Blink; Link = Link->Flink) {
            Entry = CONTAINING_RECORD(Link, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (ImportTable->RtlEqualUnicodeString(&Entry->BaseDllName, &UnicodeString, TRUE) || ImportTable->RtlEqualUnicodeString(&Entry->FullDllName, &UnicodeString, TRUE)) {
                Destination = Entry;
                break;
            }
        }

        ImportTable->RtlFreeUnicodeString(&UnicodeString);
    }

    return Destination;
}

FORCEINLINE PVOID LdrGetSystemRoutineAddressA(_In_ PMAPPER_EXECUTOR_CONTEXT StartContext, _In_ LPCSTR ModuleName)
{
    PVOID Destination;
    UNICODE_STRING unicodeString;
    PKERNEL_IMPORT_TABLE ImportTable;
    NTSTATUS Status;
    ANSI_STRING AnsiString;

    ImportTable = &StartContext->ImportTable;
    Destination = 0;

    ImportTable->RtlInitAnsiString(&AnsiString, ModuleName);
    Status = ImportTable->RtlAnsiStringToUnicodeString(&unicodeString, &AnsiString, TRUE);

    if NT_SUCCESS (Status) {
        Destination = ImportTable->MmGetSystemRoutineAddress(&unicodeString);
        ImportTable->RtlFreeUnicodeString(&unicodeString);
    }
    return Destination;
}

FORCEINLINE NTSTATUS ResolveImageReferences(_In_ PMAPPER_EXECUTOR_CONTEXT StartContext, _In_ PCHAR ImageBase)
{
    ULONG ImportDescriptorSize;
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
    PCHAR ModuleName;
    ULONG Count;
    PVOID ModuleBase;
    PIMAGE_THUNK_DATA NameThunk;
    PIMAGE_THUNK_DATA AddrThunk;
    PIMAGE_IMPORT_BY_NAME ImportNameTable;
    PCHAR ProcedureName;
    PVOID ProcedureAddress;
    PKERNEL_IMPORT_TABLE ImportTable;

    ImportTable = &StartContext->ImportTable;

    // Always Test for buffer.
    if (ImportTable->RtlImageNtHeader(ImageBase) == NULL) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ImportDescriptor = ImportTable->RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ImportDescriptorSize);

    // ============================
    // No Import to be resolved.
    // ============================
    if (!ImportDescriptor) {
        return STATUS_SUCCESS;
    }

    // Count the number of imports so we can allocate enough room to
    // store them all chained off this module's LDR_DATA_TABLE_ENTRY.
    //

    Count = 0;
    for (PIMAGE_IMPORT_DESCRIPTOR Imp = ImportDescriptor; Imp->Name && Imp->OriginalFirstThunk; Imp += 1) {
        Count += 1;
    }

    while (ImportDescriptor->Name && ImportDescriptor->OriginalFirstThunk) {
        ModuleName = ImageBase + ImportDescriptor->Name;
        ModuleBase = LdrGetSystemModuleBaseA(StartContext, ModuleName);

        if (ModuleBase == NULL) {
            return STATUS_NOT_SUPPORTED;
        }

        //
        // Walk through the IAT and snap all the thunks.
        //

        if (ImportDescriptor->OriginalFirstThunk) {
            NameThunk = (PIMAGE_THUNK_DATA)(ImageBase + ImportDescriptor->OriginalFirstThunk);
            AddrThunk = (PIMAGE_THUNK_DATA)(ImageBase + ImportDescriptor->FirstThunk);

            while (NameThunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(NameThunk->u1.Ordinal)) {
                    ProcedureName = (PCHAR)IMAGE_ORDINAL(NameThunk->u1.Ordinal);
                } else {
                    ImportNameTable = (PIMAGE_IMPORT_BY_NAME)(ImageBase + NameThunk->u1.AddressOfData);

                    if (!ImportNameTable)
                        return STATUS_PROCEDURE_NOT_FOUND;

                    ProcedureName = ImportNameTable->Name;
                }

                //
                // First, try from LdrGetSystemRoutineAddressA for ntoskrnl and hal
                // if result null then try from RtlFindExportedRoutineByName by ModuleBase.
                //
                ProcedureAddress = LdrGetSystemRoutineAddressA(StartContext, ProcedureName);
                if (ProcedureAddress == NULL)
                    ProcedureAddress = ImportTable->RtlFindExportedRoutineByName(ModuleBase, ProcedureName);

                if (ProcedureAddress == NULL) {
                    return STATUS_PROCEDURE_NOT_FOUND;
                }

                AddrThunk->u1.Function  = (ULONGLONG)ProcedureAddress;
                NameThunk              += 1;
                AddrThunk              += 1;
            }
        }

        ImportDescriptor += 1;
    }

    return STATUS_SUCCESS;
}

FORCEINLINE NTSTATUS RelocateImage(_In_ PMAPPER_EXECUTOR_CONTEXT StartContext, _In_ PVOID ImageBase)
{
    LONGLONG Diff;
    ULONG TotalCountBytes = 0;
    ULONG_PTR VA;
    ULONGLONG OldBase;
    ULONG SizeOfBlock;
    PUSHORT NextOffset = NULL;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION NextBlock;
    NTSTATUS Status;

    NtHeaders = StartContext->ImportTable.RtlImageNtHeader(ImageBase);
    if (NtHeaders == NULL) {
        Status = STATUS_INVALID_IMAGE_FORMAT;
        goto Exit;
    }

    switch (NtHeaders->OptionalHeader.Magic) {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:

        OldBase = ((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.ImageBase;
        break;

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:

        OldBase = ((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.ImageBase;
        break;

    default:

        Status = STATUS_INVALID_IMAGE_FORMAT;
        goto Exit;
    }

    //
    // Locate the relocation section.
    //

    NextBlock = StartContext->ImportTable.RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &TotalCountBytes);

    //
    // It is possible for a file to have no relocations, but the relocations
    // must not have been stripped.
    //

    if (!NextBlock || !TotalCountBytes) {
        Status = (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) ? STATUS_CONFLICTING_ADDRESSES : STATUS_SUCCESS;
        goto Exit;
    }

    //
    // If the image has a relocation table, then apply the specified fixup
    // information to the image.
    //
    Diff = (ULONG_PTR)ImageBase - OldBase;
    while (TotalCountBytes) {
        SizeOfBlock = NextBlock->SizeOfBlock;

        // Prevent crash
        if (SizeOfBlock == 0) {
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto Exit;
        }

        TotalCountBytes -= SizeOfBlock;
        SizeOfBlock     -= sizeof(IMAGE_BASE_RELOCATION);
        SizeOfBlock     /= sizeof(USHORT);
        NextOffset       = (PUSHORT)((PCHAR)NextBlock + sizeof(IMAGE_BASE_RELOCATION));

        VA        = (ULONG_PTR)ImageBase + NextBlock->VirtualAddress;
        NextBlock = LdrProcessRelocationBlockLongLong(VA, SizeOfBlock, NextOffset, Diff);

        if (!NextBlock) {
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto Exit;
        }
    }

    Status = STATUS_SUCCESS;
Exit:
    return Status;
}

VOID MiUnloadSystemImage(_In_ PDRIVER_OBJECT DriverObject)
{
    PMAPPER_EXECUTOR_CONTEXT SectionContext;
    PVOID DriverStart;
    ULONG DriverSize;
    ExFreePoolWithTag_t ExFreePool;
    PsTerminateSystemThread_t PsTerminate;
    PVOID DriverUnload;
    LARGE_INTEGER timeout;

    DriverStart      = DriverObject->DriverStart;
    DriverSize       = DriverObject->DriverSize;
    SectionContext   = DriverObject->DriverSection;
    DriverUnload     = DriverObject->DriverUnload;
    ExFreePool       = SectionContext->ImportTable.ExFreePoolWithTag;
    PsTerminate      = SectionContext->ImportTable.PsTerminateSystemThread;
    timeout.QuadPart = RELATIVE_TIME(SECONDS(2));

    // Delay execution for 2 seconds so driver can exit perfectly.
    SectionContext->ImportTable.KeDelayExecutionThread(0, FALSE, &timeout);

    if (DriverStart && DriverSize) {
        SectionContext->ImportTable.MmFreePagesFromMdl(SectionContext->MemoryDescriptor);
        ExFreePool(SectionContext->MemoryDescriptor, 0);
    }

    ExFreePool(DriverObject, 0);
    ExFreePool(SectionContext, 0);

    // Release this executor allocation.
    ExFreePool(DriverUnload, 0);

    // since the allocation already released, should never be hitted.
    PsTerminate(STATUS_SUCCESS);
    return;
}

VOID MiLoadSystemImageWorker(_In_ PMAPPER_EXECUTOR_CONTEXT StartContext)
{
    PVOID ImageBase;
    PKERNEL_IMPORT_TABLE ImportTable;
    NTSTATUS status;
    PIMAGE_NT_HEADERS NtHeader;
    PDRIVER_INITIALIZE DriverEntry;
    PDRIVER_OBJECT DriverObject;
    PIMAGE_SECTION_HEADER ImageSection;
    USHORT NumberOfSection, i;
    PCHAR SectionStart;
    ULONG SectionSize;
    ULONG Characteristics;
    ULONG SectionProtection;
    ULONG HeaderSize;
    PVOID MdlHack;

    ImageBase   = StartContext->MapSection;
    ImportTable = &StartContext->ImportTable;
    NtHeader    = ImportTable->RtlImageNtHeader(ImageBase);

    //
    // Relocate Image
    //

    status = RelocateImage(StartContext, ImageBase);
    if NT_ERROR (status) {
        ImportTable->MmFreePagesFromMdl(StartContext->MemoryDescriptor);
        ImportTable->ExFreePoolWithTag(StartContext->MemoryDescriptor, 0);
        goto ExitPoint;
    }

    //
    // Resolve Image Reference.
    //

    status = ResolveImageReferences(StartContext, ImageBase);
    if NT_ERROR (status) {
        ImportTable->MmFreePagesFromMdl(StartContext->MemoryDescriptor);
        ImportTable->ExFreePoolWithTag(StartContext->MemoryDescriptor, 0);
        goto ExitPoint;
    }

    //
    // Init Security Cookie.
    //

    InitSecurityCookie(StartContext, ImageBase);

    //
    // Create Driver Object as params.
    //

    DriverObject = ImportTable->ExAllocatePool2(0x0000000000000040UI64, sizeof(DRIVER_OBJECT), (ULONG)((ULONGLONG)ImageBase));

    DriverObject->DriverStart   = ImageBase;
    DriverObject->DriverSize    = NtHeader->OptionalHeader.SizeOfImage;
    DriverObject->DriverSection = StartContext;
    DriverObject->DriverUnload  = StartContext->Unloader;
    DriverObject->DriverInit    = RtlOffsetToPointer(ImageBase, NtHeader->OptionalHeader.AddressOfEntryPoint);
    DriverEntry                 = DriverObject->DriverInit;

    //
    // Invoke DriverEntry.
    //

    status = DriverEntry(DriverObject, NULL);

    //
    // Post Mapping process.
    //

    if NT_SUCCESS (status) {
        ImageSection    = IMAGE_FIRST_SECTION(NtHeader);
        HeaderSize      = ImageSection->VirtualAddress;
        NumberOfSection = NtHeader->FileHeader.NumberOfSections;

        for (i = 0; i < NumberOfSection; i += 1) {
            Characteristics   = ImageSection[i].Characteristics;
            SectionStart      = RtlOffsetToPointer(ImageBase, ImageSection[i].VirtualAddress);
            SectionSize       = ImageSection[i].Misc.VirtualSize;
            SectionProtection = 0;

            if (Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
                for (PULONG j = (PULONG)SectionStart; j < (PULONG)(SectionStart + SectionSize); j++) {
                    *j ^= (ULONG)((ULONGLONG)SectionStart);
                }

                SectionProtection = PAGE_READONLY;
            } else if (!(Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(Characteristics & IMAGE_SCN_MEM_WRITE)) {
                SectionProtection = PAGE_READONLY;
            } else if ((Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(Characteristics & IMAGE_SCN_MEM_WRITE)) {
                SectionProtection = PAGE_EXECUTE_READ;
            } else if ((Characteristics & IMAGE_SCN_MEM_WRITE)) {
                SectionProtection = PAGE_READWRITE;
            }

            if (SectionProtection != 0) {
                //ImportTable->MmSetPageProtection(SectionStart, SectionSize, SectionProtection);

                MdlHack = ImportTable->IoAllocateMdl(SectionStart, SectionSize, FALSE, FALSE, NULL);
                if (MdlHack != NULL) {
                    ImportTable->MmProtectMdlSystemAddress(MdlHack, SectionProtection);
                    ImportTable->IoFreeMdl(MdlHack);
                }
            }
        }

        for (PULONG k = ImageBase; k < (PULONG)((PCHAR)ImageBase + HeaderSize); k++) {
            *k ^= (ULONG)((ULONGLONG)k);
        }

        MdlHack = ImportTable->IoAllocateMdl(ImageBase, HeaderSize, FALSE, FALSE, NULL);
        if (MdlHack != NULL) {
            ImportTable->MmProtectMdlSystemAddress(MdlHack, PAGE_READONLY);
            ImportTable->IoFreeMdl(MdlHack);
        }
        //ImportTable->MmSetPageProtection(ImageBase, HeaderSize, PAGE_READONLY);
    }

    if NT_ERROR (status) {
        ImportTable->MmFreePagesFromMdl(StartContext->MemoryDescriptor);
        ImportTable->ExFreePoolWithTag(StartContext->MemoryDescriptor, 0);
        ImportTable->ExFreePoolWithTag(DriverObject, 0);
    }

ExitPoint:
    ImportTable->PsTerminateSystemThread(status);
    return;
}

NTSTATUS MiLoadSystemImage(_In_ PMAPPER_EXECUTOR_CONTEXT StartContext)
{
    HANDLE threadHandle;
    NTSTATUS status;
    SIZE_T ContextSize;
    PKERNEL_IMPORT_TABLE ImportTable;
    PKSTART_ROUTINE WorkerThread;
    PVOID threadObject;
    PMAPPER_EXECUTOR_CONTEXT WorkerContext;
    PVOID MdlHack;
    PHYSICAL_ADDRESS LowestAddress;
    PHYSICAL_ADDRESS HighestAddress;
    PVOID ImageBase;
    SIZE_T ImageSize;
    PVOID MapSection;

    status      = STATUS_UNSUCCESSFUL;
    ContextSize = sizeof(MAPPER_EXECUTOR_CONTEXT);

    //
    // Try to verify based on the context a bit.
    //

    if (StartContext == NULL || ((PCHAR)StartContext + ContextSize) <= (PCHAR)StartContext || StartContext->ContextSize != ContextSize) {
        status = STATUS_INVALID_PARAMETER;
        return status;
    }

    ImportTable                = &StartContext->ImportTable;
    WorkerThread               = StartContext->WorkerThread;
    StartContext->DriverStatus = STATUS_FAILED_DRIVER_ENTRY;

    //
    // Allocate memory for context in system address.
    //

    WorkerContext = ImportTable->ExAllocatePool2(0x0000000000000040UI64, ContextSize, (ULONG)((ULONGLONG)StartContext->ImageBase));
    if (WorkerContext == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        return status;
    }

    //
    // Allocate Memory for mapping allocation from system ptes.
    //

    LowestAddress.QuadPart  = 0;
    HighestAddress.QuadPart = MAXLONGLONG;
    ImageBase               = StartContext->ImageBase;
    ImageSize               = StartContext->ImageSize;

    MdlHack = ImportTable->MmAllocatePagesForMdlEx(LowestAddress, HighestAddress, LowestAddress, ImageSize, MmNonCached, 0x00000020);
    if (MdlHack == NULL) {
        ImportTable->ExFreePoolWithTag(WorkerContext, 0);
        status = STATUS_MEMORY_NOT_ALLOCATED;
        return status;
    }

    MapSection = ImportTable->MmMapLockedPagesSpecifyCache(MdlHack, 0, MmCached, NULL, FALSE, HighPagePriority);
    if (MapSection == NULL) {
        ImportTable->MmFreePagesFromMdl(MdlHack);
        ImportTable->ExFreePoolWithTag(MdlHack, 0);
        ImportTable->ExFreePoolWithTag(WorkerContext, 0);

        status = STATUS_MEMORY_NOT_ALLOCATED;
        return status;
    }

    StartContext->MapSection       = MapSection;
    StartContext->MemoryDescriptor = MdlHack;
    ImportTable->memcpy(MapSection, StartContext->ImageBase, ImageSize);
    ImportTable->memcpy(WorkerContext, StartContext, ContextSize);

    //
    // Create Worker Thread that run on system process context.
    //

    status = ImportTable->PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, WorkerThread, WorkerContext);
    if NT_SUCCESS (status) {
        status = ImportTable->ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, NULL, 0, &threadObject, NULL);
        if NT_SUCCESS (status) {
            status = ImportTable->KeWaitForSingleObject(threadObject, Executive, 0, FALSE, NULL);
            if NT_SUCCESS (status)
                StartContext->DriverStatus = ImportTable->PsGetThreadExitStatus(threadObject);

            ImportTable->ObfDereferenceObject(threadObject);
        }

        ImportTable->ZwClose(threadHandle);
    }

    if NT_ERROR (status)
        ImportTable->ExFreePoolWithTag(WorkerContext, 0);

    return status;
}

#pragma endregion code_running_on_system_address_space

NTSTATUS MmLoadSystemImage(_In_ PDEVICE_DRIVER_OBJECT Driver, _In_ PVOID ImageBase)
{
    typedef NTSTATUS (*PROTOTYPE_ROUTINE)(PVOID StartContex);

    SIZE_T procSize, procSize2, procSize3;
    ULONGLONG Executor;
    ULONGLONG Worker;
    ULONGLONG Unloader;
    NTSTATUS status;
    PROTOTYPE_ROUTINE MiLoadSystemImageRoutine;
    UCHAR hookBuffer[12];
    MAPPER_EXECUTOR_CONTEXT Context;
    ULONGLONG i;
    PULONGLONG CurrentImport;

    status    = STATUS_MEMORY_NOT_ALLOCATED;
    procSize  = GetProcedureSize(MiLoadSystemImage);
    procSize2 = GetProcedureSize(MiLoadSystemImageWorker);
    procSize3 = GetProcedureSize(MiUnloadSystemImage);

    Executor = ExAllocatePool2(Driver, procSize);
    Worker   = ExAllocatePool2(Driver, procSize2);
    Unloader = ExAllocatePool2(Driver, procSize3);

    MiLoadSystemImageRoutine = (PROTOTYPE_ROUTINE)NtSetEaFile;

    if (Executor != 0 && Worker != 0 && Unloader != 0) {
        //
        // write to allocation.
        //

        status = Driver->WriteMemory(Driver->DeviceHandle, Executor, MiLoadSystemImage, procSize);
        if NT_ERROR (status) {
            PRINT_ERROR_NTSTATUS(status);
            ExFreePool(Driver, Executor);
            ExFreePool(Driver, Unloader);
            ExFreePool(Driver, Worker);
            return status;
        }

        status = Driver->WriteMemory(Driver->DeviceHandle, Worker, MiLoadSystemImageWorker, procSize2);
        if NT_ERROR (status) {
            PRINT_ERROR_NTSTATUS(status);
            ExFreePool(Driver, Executor);
            ExFreePool(Driver, Unloader);
            ExFreePool(Driver, Worker);
            return status;
        }

        status = Driver->WriteMemory(Driver->DeviceHandle, Unloader, MiUnloadSystemImage, procSize3);
        if NT_ERROR (status) {
            PRINT_ERROR_NTSTATUS(status);
            ExFreePool(Driver, Executor);
            ExFreePool(Driver, Unloader);
            ExFreePool(Driver, Worker);
            return status;
        }

        //
        // Create Context.
        //

        Context.ContextSize      = sizeof(MAPPER_EXECUTOR_CONTEXT);
        Context.DriverStatus     = STATUS_UNSUCCESSFUL;
        Context.WorkerThread     = (PKSTART_ROUTINE)Worker;
        Context.ImageBase        = ImageBase;
        Context.ImageSize        = RtlImageNtHeader(ImageBase)->OptionalHeader.SizeOfImage;
        Context.MemoryDescriptor = 0;
        Context.MapSection       = 0;
        Context.Unloader         = (PVOID)Unloader;

        //
        // Resolve Import Table.
        //

        Context.ImportTable.PsLoadedModuleList           = (PVOID)GetSystemRoutineAddressA("PsLoadedModuleList");
        Context.ImportTable.memcpy                       = (PVOID)GetSystemRoutineAddressA("memcpy");
        Context.ImportTable.memset                       = (PVOID)GetSystemRoutineAddressA("memset");
        Context.ImportTable.MmGetSystemRoutineAddress    = (PVOID)GetSystemRoutineAddressA("MmGetSystemRoutineAddress");
        Context.ImportTable.MmAllocatePagesForMdlEx      = (PVOID)GetSystemRoutineAddressA("MmAllocatePagesForMdlEx");
        Context.ImportTable.MmFreePagesFromMdl           = (PVOID)GetSystemRoutineAddressA("MmFreePagesFromMdl");
        Context.ImportTable.MmMapLockedPagesSpecifyCache = (PVOID)GetSystemRoutineAddressA("MmMapLockedPagesSpecifyCache");
        Context.ImportTable.MmProtectMdlSystemAddress    = (PVOID)GetSystemRoutineAddressA("MmProtectMdlSystemAddress");
        Context.ImportTable.KeWaitForSingleObject        = (PVOID)GetSystemRoutineAddressA("KeWaitForSingleObject");
        Context.ImportTable.KeDelayExecutionThread       = (PVOID)GetSystemRoutineAddressA("KeDelayExecutionThread");
        Context.ImportTable.ExAllocatePool2              = (PVOID)GetSystemRoutineAddressA("ExAllocatePool2");
        Context.ImportTable.ExFreePoolWithTag            = (PVOID)GetSystemRoutineAddressA("ExFreePoolWithTag");
        Context.ImportTable.RtlImageNtHeader             = (PVOID)GetSystemRoutineAddressA("RtlImageNtHeader");
        Context.ImportTable.RtlInitUnicodeString         = (PVOID)GetSystemRoutineAddressA("RtlInitUnicodeString");
        Context.ImportTable.RtlInitAnsiString            = (PVOID)GetSystemRoutineAddressA("RtlInitAnsiString");
        Context.ImportTable.RtlAnsiStringToUnicodeString = (PVOID)GetSystemRoutineAddressA("RtlAnsiStringToUnicodeString");
        Context.ImportTable.RtlEqualUnicodeString        = (PVOID)GetSystemRoutineAddressA("RtlEqualUnicodeString");
        Context.ImportTable.RtlFreeUnicodeString         = (PVOID)GetSystemRoutineAddressA("RtlFreeUnicodeString");
        Context.ImportTable.RtlImageDirectoryEntryToData = (PVOID)GetSystemRoutineAddressA("RtlImageDirectoryEntryToData");
        Context.ImportTable.RtlFindExportedRoutineByName = (PVOID)GetSystemRoutineAddressA("RtlFindExportedRoutineByName");
        Context.ImportTable.ObReferenceObjectByHandle    = (PVOID)GetSystemRoutineAddressA("ObReferenceObjectByHandle");
        Context.ImportTable.ObfDereferenceObject         = (PVOID)GetSystemRoutineAddressA("ObfDereferenceObject");
        Context.ImportTable.PsCreateSystemThread         = (PVOID)GetSystemRoutineAddressA("PsCreateSystemThread");
        Context.ImportTable.PsTerminateSystemThread      = (PVOID)GetSystemRoutineAddressA("PsTerminateSystemThread");
        Context.ImportTable.PsGetThreadExitStatus        = (PVOID)GetSystemRoutineAddressA("PsGetThreadExitStatus");
        Context.ImportTable.ZwClose                      = (PVOID)GetSystemRoutineAddressA("ZwClose");
        Context.ImportTable.IoAllocateMdl                = (PVOID)GetSystemRoutineAddressA("IoAllocateMdl");
        Context.ImportTable.IoFreeMdl                    = (PVOID)GetSystemRoutineAddressA("IoFreeMdl");

        CurrentImport = (PULONGLONG)&Context.ImportTable;
        for (i = 0; i < sizeof(Context.ImportTable) / sizeof(PVOID); i += 1) {
            if (CurrentImport[i] == 0) {
                wprintf(L"[!] CurrentImport[%llu] not found: 0x%llX.", i, CurrentImport[i]);

                status = STATUS_PROCEDURE_NOT_FOUND;
                PRINT_ERROR_NTSTATUS(status);
                ExFreePool(Driver, Executor);
                ExFreePool(Driver, Unloader);
                ExFreePool(Driver, Worker);
                return status;
            }
        }

        //
        // Invoke executor.
        //

        status = HookSystemRoutine(Driver, Executor, hookBuffer);
        if NT_SUCCESS (status) {
            status = MiLoadSystemImageRoutine(&Context);
            UnhookSystemRoutine(Driver, hookBuffer);
        }
    }

    //
    // Release allocation
    //
    if (Executor)
        ExFreePool(Driver, Executor);

    if (Worker)
        ExFreePool(Driver, Worker);

    if NT_ERROR (status)
        if (Unloader)
            ExFreePool(Driver, Unloader);

    return status;
}
