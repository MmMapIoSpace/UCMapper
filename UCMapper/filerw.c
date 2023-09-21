#include "main.h"

NTSTATUS RtlFileRead(_In_ LPCWSTR Source, _Out_ PVOID* Buffer, _Out_ PSIZE_T FileSize)
{
    NTSTATUS Status;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING UnicodeString;
    FILE_STANDARD_INFORMATION FileInformation = {0};
    PVOID Allocation;
    LARGE_INTEGER FileOffsets;

    *Buffer              = NULL;
    *FileSize            = 0;
    FileOffsets.QuadPart = 0;

    if (Source[0] == L'\\')
        RtlInitUnicodeString(&UnicodeString, Source);
    else
        RtlDosPathNameToNtPathName_U(Source, &UnicodeString, NULL, NULL);

    InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(
        &FileHandle,
        FILE_GENERIC_READ,
        &ObjectAttributes,
        &IoStatus,
        FILE_SHARE_READ,
        FILE_NON_DIRECTORY_FILE);

    if (Source[0] != L'\\')
        RtlFreeUnicodeString(&UnicodeString);

    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    Status = NtQueryInformationFile(
        FileHandle,
        &IoStatus,
        &FileInformation,
        sizeof(FileInformation),
        FileStandardInformation);

    if NT_ERROR (Status) {
        NtClose(FileHandle);

        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    Allocation = RtlAllocateMemory(FileInformation.EndOfFile.QuadPart);
    Status     = NtReadFile(
        FileHandle,
        NULL,
        NULL,
        NULL,
        &IoStatus,
        Allocation,
        FileInformation.EndOfFile.LowPart,
        &FileOffsets,
        NULL);

    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(FileHandle, FALSE, NULL);
        if NT_SUCCESS (Status)
            Status = IoStatus.Status;
    }

    if NT_ERROR (Status) {
        NtClose(FileHandle);
        RtlFreeMemory(Allocation);

        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    *FileSize = FileInformation.EndOfFile.QuadPart;
    *Buffer   = Allocation;

    Status = NtClose(FileHandle);
    return Status;
}

NTSTATUS RtlFileWrite(
    _In_ LPCWSTR Destination,
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_ SIZE_T BufferLength)
{
    UNICODE_STRING UnicodeString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER FileOffsets;

    FileSize.QuadPart    = BufferLength;
    FileOffsets.QuadPart = 0;

    if (Destination[0] == L'\\')
        RtlInitUnicodeString(&UnicodeString, Destination);
    else
        RtlDosPathNameToNtPathName_U(Destination, &UnicodeString, NULL, NULL);

    InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(
        &FileHandle,
        FILE_ALL_ACCESS,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
        FILE_SUPERSEDE,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0);

    if (Destination[0] != L'\\')
        RtlFreeUnicodeString(&UnicodeString);

    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    Status = NtWriteFile(
        FileHandle,
        NULL,
        NULL,
        NULL,
        &IoStatusBlock,
        Buffer,
        FileSize.LowPart,
        &FileOffsets,
        NULL);

    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(FileHandle, FALSE, NULL);
        if NT_SUCCESS (Status)
            Status = IoStatusBlock.Status;
    }

    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        NtClose(FileHandle);
        return Status;
    }

    Status = NtClose(FileHandle);
    return Status;
}

NTSTATUS RtlFileMap(_In_ LPCWSTR Source, _Out_ PVOID* BaseAddress, _Out_ PSIZE_T ViewSize)
{
    NTSTATUS Status;
    UNICODE_STRING UnicodeString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE FileHandle;
    HANDLE SectionHandle;
    IO_STATUS_BLOCK IoStatus;

    *BaseAddress = NULL;
    *ViewSize    = 0;

    if (Source[0] == L'\\')
        RtlInitUnicodeString(&UnicodeString, Source);
    else
        RtlDosPathNameToNtPathName_U(Source, &UnicodeString, NULL, NULL);

    InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(
        &FileHandle,
        SECTION_ALL_ACCESS,
        &ObjectAttributes,
        &IoStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE);

    if (Source[0] != L'\\')
        RtlFreeUnicodeString(&UnicodeString);

    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    InitializeObjectAttributes(&ObjectAttributes, NULL, (OBJ_CASE_INSENSITIVE), NULL, NULL);
    Status = NtCreateSection(
        &SectionHandle,
        SECTION_ALL_ACCESS,
        &ObjectAttributes,
        (PLARGE_INTEGER)NULL,
        PAGE_READWRITE,
        SEC_RESERVE,
        FileHandle);

    if NT_ERROR (Status) {
        NtClose(FileHandle);
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }


    Status = NtMapViewOfSection(
        SectionHandle,
        NtCurrentProcess(),
        BaseAddress,
        0,
        0,
        NULL,
        ViewSize,
        ViewUnmap,
        0,
        PAGE_READWRITE);

    NtClose(SectionHandle);
    NtClose(FileHandle);
    if NT_ERROR (Status) {
        *BaseAddress = NULL;
        *ViewSize    = 0;

        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    return Status;
}

NTSTATUS RtlFileMapImage(_In_ LPCWSTR Source, _Out_ PVOID* BaseAddress, _Out_ PSIZE_T ViewSize)
{
    NTSTATUS Status;
    UNICODE_STRING UnicodeString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE FileHandle;
    HANDLE SectionHandle;
    IO_STATUS_BLOCK IoStatus;

    *BaseAddress = NULL;
    *ViewSize    = 0;

    if (Source[0] == L'\\')
        RtlInitUnicodeString(&UnicodeString, Source);
    else
        RtlDosPathNameToNtPathName_U(Source, &UnicodeString, NULL, NULL);

    InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status
        = NtOpenFile(&FileHandle, FILE_EXECUTE, &ObjectAttributes, &IoStatus, FILE_SHARE_READ, 0);

    if (Source[0] != L'\\')
        RtlFreeUnicodeString(&UnicodeString);

    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    InitializeObjectAttributes(&ObjectAttributes, NULL, (OBJ_CASE_INSENSITIVE), NULL, NULL);
    Status = NtCreateSection(
        &SectionHandle,
        SECTION_ALL_ACCESS,
        &ObjectAttributes,
        (PLARGE_INTEGER)NULL,
        PAGE_EXECUTE,
        SEC_IMAGE,
        FileHandle);

    if NT_ERROR (Status) {
        NtClose(FileHandle);
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    Status = NtMapViewOfSection(
        SectionHandle,
        NtCurrentProcess(),
        BaseAddress,
        0,
        0,
        NULL,
        ViewSize,
        ViewUnmap,
        0,
        PAGE_EXECUTE);

    NtClose(SectionHandle);
    NtClose(FileHandle);
    if NT_ERROR (Status) {
        *BaseAddress = NULL;
        *ViewSize    = 0;

        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    return Status;
}

NTSTATUS RtlFileUnmap(_In_ PVOID BaseAddress)
{
    return NtUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
}

NTSTATUS RtlFileDelete(_In_ LPCWSTR FilePath)
{
    NTSTATUS Status;
    UNICODE_STRING UnicodeString;
    OBJECT_ATTRIBUTES ObjectAttributes;

    if (FilePath[0] == L'\\')
        RtlInitUnicodeString(&UnicodeString, FilePath);
    else
        RtlDosPathNameToNtPathName_U(FilePath, &UnicodeString, NULL, NULL);

    InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtDeleteFile(&ObjectAttributes);

    if (FilePath[0] != L'\\')
        RtlFreeUnicodeString(&UnicodeString);

    return Status;
}

NTSTATUS RtlFileToImage(_In_ LPCWSTR Source, _In_ LPCWSTR Destination)
{
    NTSTATUS Status;
    PCHAR ImageBase, FileBase;
    SIZE_T FileSize, ImageSize;
    PIMAGE_NT_HEADERS ImageHeader;
    USHORT i;
    PIMAGE_SECTION_HEADER ImageSection;

    Status = RtlFileRead(Source, &FileBase, &FileSize);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    ImageHeader = RtlImageNtHeader(FileBase);
    if (ImageHeader == NULL) {
        Status = STATUS_INVALID_IMAGE_FORMAT;
        DEBUG_PRINT_NTSTATUS(Status);
        return Status;
    }

    ImageSize = ImageHeader->OptionalHeader.SizeOfImage;
    ImageBase = RtlAllocateMemory(ImageSize);

    //
    // Copy Header.
    //

    ImageSection = IMAGE_FIRST_SECTION(ImageHeader);

    RtlCopyMemory(ImageBase, FileBase, ImageSection->VirtualAddress);
    for (i = 0; i < ImageHeader->FileHeader.NumberOfSections; i += 1) {
        // clang-format off
        RtlCopyMemory(
            ImageBase + ImageSection[i].VirtualAddress,
            FileBase + ImageSection[i].PointerToRawData,
            ImageSection[i].SizeOfRawData);
        // clang-format on
    }

    Status = RtlFileWrite(Destination, ImageBase, ImageSize);
    if NT_ERROR (Status) {
        DEBUG_PRINT_NTSTATUS(Status);
    }

    RtlFreeMemory(FileBase);
    RtlFreeMemory(ImageBase);
    return Status;
}
