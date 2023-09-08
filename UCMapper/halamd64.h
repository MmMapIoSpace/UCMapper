/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2020
*  Taken from publicly available Microsoft sources or mentioned elsewhere.
*
*  TITLE:       HALAMD64.H
*
*  VERSION:     1.11
*
*  DATE:        12 Feb 2020
*
*  Common header file for the ntos HAL AMD64 definitions.
*
*  Depends on:    Windows.h
*
*  Include:       Windows.h
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef HALAMD64_RTL
#define HALAMD64_RTL

#pragma warning(push)
#pragma warning(disable : 4214)
#pragma warning(disable : 4201)

//
// HALAMD64_RTL HEADER BEGIN
//

#pragma pack(push, 2)

typedef struct _FAR_JMP_16
{
    UCHAR  OpCode; // = 0xe9
    USHORT Offset;
} FAR_JMP_16;

typedef struct _FAR_TARGET_32
{
    ULONG  Offset;
    USHORT Selector;
} FAR_TARGET_32;

typedef struct _PSEUDO_DESCRIPTOR_32
{
    USHORT Limit;
    ULONG  Base;
} PSEUDO_DESCRIPTOR_32;

#pragma pack(pop)

typedef union _KGDTENTRY64
{
    struct
    {
        USHORT LimitLow;
        USHORT BaseLow;

        union
        {
            struct
            {
                UCHAR BaseMiddle;
                UCHAR Flags1;
                UCHAR Flags2;
                UCHAR BaseHigh;
            } Bytes;

            struct
            {
                ULONG BaseMiddle  : 8;
                ULONG Type        : 5;
                ULONG Dpl         : 2;
                ULONG Present     : 1;
                ULONG LimitHigh   : 4;
                ULONG System      : 1;
                ULONG LongMode    : 1;
                ULONG DefaultBig  : 1;
                ULONG Granularity : 1;
                ULONG BaseHigh    : 8;
            } Bits;
        };

        ULONG BaseUpper;
        ULONG MustBeZero;
    };

    ULONGLONG Alignment;
} KGDTENTRY64, *PKGDTENTRY64;

typedef union _KIDTENTRY64
{
    struct
    {
        USHORT OffsetLow;
        USHORT Selector;
        USHORT IstIndex  : 3;
        USHORT Reserved0 : 5;
        USHORT Type      : 5;
        USHORT Dpl       : 2;
        USHORT Present   : 1;
        USHORT OffsetMiddle;
        ULONG  OffsetHigh;
        ULONG  Reserved1;
    };

    ULONGLONG Alignment;
} KIDTENTRY64, *PKIDTENTRY64;

typedef union _KGDT_BASE
{
    struct
    {
        USHORT BaseLow;
        UCHAR  BaseMiddle;
        UCHAR  BaseHigh;
        ULONG  BaseUpper;
    };

    ULONGLONG Base;
} KGDT_BASE, *PKGDT_BASE;

typedef union _KGDT_LIMIT
{
    struct
    {
        USHORT LimitLow;
        USHORT LimitHigh  : 4;
        USHORT MustBeZero : 12;
    };

    ULONG Limit;
} KGDT_LIMIT, *PKGDT_LIMIT;

#define PSB_GDT32_MAX 3

typedef struct _KDESCRIPTOR
{
    USHORT Pad[3];
    USHORT Limit;
    PVOID  Base;
} KDESCRIPTOR, *PKDESCRIPTOR;

typedef struct _KDESCRIPTOR32
{
    USHORT Pad[3];
    USHORT Limit;
    ULONG  Base;
} KDESCRIPTOR32, *PKDESCRIPTOR32;

typedef struct _KSPECIAL_REGISTERS
{
    ULONGLONG   Cr0;
    ULONGLONG   Cr2;
    ULONGLONG   Cr3;
    ULONGLONG   Cr4;
    ULONGLONG   KernelDr0;
    ULONGLONG   KernelDr1;
    ULONGLONG   KernelDr2;
    ULONGLONG   KernelDr3;
    ULONGLONG   KernelDr6;
    ULONGLONG   KernelDr7;
    KDESCRIPTOR Gdtr;
    KDESCRIPTOR Idtr;
    USHORT      Tr;
    USHORT      Ldtr;
    ULONG       MxCsr;
    ULONGLONG   DebugControl;
    ULONGLONG   LastBranchToRip;
    ULONGLONG   LastBranchFromRip;
    ULONGLONG   LastExceptionToRip;
    ULONGLONG   LastExceptionFromRip;
    ULONGLONG   Cr8;
    ULONGLONG   MsrGsBase;
    ULONGLONG   MsrGsSwap;
    ULONGLONG   MsrStar;
    ULONGLONG   MsrLStar;
    ULONGLONG   MsrCStar;
    ULONGLONG   MsrSyscallMask;
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

typedef struct _KPROCESSOR_STATE
{
    KSPECIAL_REGISTERS SpecialRegisters;
    CONTEXT            ContextFrame;
} KPROCESSOR_STATE, *PKPROCESSOR_STATE;

typedef struct _PROCESSOR_START_BLOCK* PPROCESSOR_START_BLOCK;

typedef struct _PROCESSOR_START_BLOCK
{
    //
    // The block starts with a jmp instruction to the end of the block
    //

    FAR_JMP_16             Jmp;

    //
    // Completion flag is set to non-zero when the target processor has
    // started
    //

    ULONG                  CompletionFlag;

    //
    // Pseudo descriptors for GDT and IDT.
    //

    PSEUDO_DESCRIPTOR_32   Gdt32;
    PSEUDO_DESCRIPTOR_32   Idt32;

    //
    // The temporary 32-bit GDT itself resides here.
    //

    KGDTENTRY64            Gdt[PSB_GDT32_MAX + 1];

    //
    // Physical address of the 64-bit top-level identity-mapped page table.
    //

    ULONGLONG              TiledCr3;

    //
    // Far jump target from Rm to Pm code
    //

    FAR_TARGET_32          PmTarget;

    //
    // Far jump target from Pm to Lm code
    //

    FAR_TARGET_32          LmIdentityTarget;

    //
    // Address of LmTarget
    //

    PVOID                  LmTarget;

    //
    // Linear address of this structure
    //

    PPROCESSOR_START_BLOCK SelfMap;

    //
    // Contents of the PAT msr
    //

    ULONGLONG              MsrPat;

    //
    // Contents of the EFER msr
    //

    ULONGLONG              MsrEFER;

    //
    // Initial processor state for the processor to be started
    //

    KPROCESSOR_STATE       ProcessorState;

} PROCESSOR_START_BLOCK;

#pragma warning(pop)

//
// HALAMD64_RTL HEADER END
//

#endif HALAMD64_RTL
