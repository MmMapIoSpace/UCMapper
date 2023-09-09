#include "main.h"

NTSTATUS WriteFileFromMemory(_In_ LPCWSTR Destination, _In_reads_bytes_(BufferLength) PVOID Buffer, _In_ SIZE_T BufferLength)
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

    RtlDosPathNameToNtPathName_U(Destination, &UnicodeString, NULL, NULL);
    InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&FileHandle, FILE_ALL_ACCESS, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, FILE_OVERWRITE, FILE_NON_DIRECTORY_FILE, NULL, 0);
    RtlFreeUnicodeString(&UnicodeString);

    if NT_ERROR (Status) {
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(Status));
        return Status;
    }

    Status = NtWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, FileSize.LowPart, &FileOffsets, NULL);

    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(FileHandle, FALSE, NULL);
        if NT_SUCCESS (Status)
            Status = IoStatusBlock.Status;
    }

    if NT_ERROR (Status) {
        PRINT_ERROR_STATUS(RtlNtStatusToDosError(Status));
        NtClose(FileHandle);
        return Status;
    }

    return NtClose(FileHandle);
}

NTSTATUS DeleteFileFromDisk(_In_ LPCWSTR FilePath)
{
    NTSTATUS Status;
    UNICODE_STRING UnicodeString;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlDosPathNameToNtPathName_U(FilePath, &UnicodeString, NULL, NULL);
    InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtDeleteFile(&ObjectAttributes);
    RtlFreeUnicodeString(&UnicodeString);

    return Status;
}
