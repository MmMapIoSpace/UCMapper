/*
 * Hacker Disassembler Engine 64
 * Copyright (c) 2008-2009, Vyacheslav Patkov.
 * All rights reserved.
 *
 * hde64.h: C/C++ header file
 *
 */

#ifndef _HDE64_H_
#define _HDE64_H_

/* stdint.h - C99 standard header
 * http://en.wikipedia.org/wiki/stdint.h
 *
 * if your compiler doesn't contain "stdint.h" header (for
 * example, Microsoft Visual C++), you can download file:
 *   http://www.azillionmonkeys.com/qed/pstdint.h
 * and change next line to:
 *   #include "pstdint.h"
 */

#define F_MODRM             0x00000001
#define F_SIB               0x00000002
#define F_IMM8              0x00000004
#define F_IMM16             0x00000008
#define F_IMM32             0x00000010
#define F_IMM64             0x00000020
#define F_DISP8             0x00000040
#define F_DISP16            0x00000080
#define F_DISP32            0x00000100
#define F_RELATIVE          0x00000200
#define F_ERROR             0x00001000
#define F_ERROR_OPCODE      0x00002000
#define F_ERROR_LENGTH      0x00004000
#define F_ERROR_LOCK        0x00008000
#define F_ERROR_OPERAND     0x00010000
#define F_PREFIX_REPNZ      0x01000000
#define F_PREFIX_REPX       0x02000000
#define F_PREFIX_REP        0x03000000
#define F_PREFIX_66         0x04000000
#define F_PREFIX_67         0x08000000
#define F_PREFIX_LOCK       0x10000000
#define F_PREFIX_SEG        0x20000000
#define F_PREFIX_REX        0x40000000
#define F_PREFIX_ANY        0x7f000000

#define PREFIX_SEGMENT_CS   0x2e
#define PREFIX_SEGMENT_SS   0x36
#define PREFIX_SEGMENT_DS   0x3e
#define PREFIX_SEGMENT_ES   0x26
#define PREFIX_SEGMENT_FS   0x64
#define PREFIX_SEGMENT_GS   0x65
#define PREFIX_LOCK         0xf0
#define PREFIX_REPNZ        0xf2
#define PREFIX_REPX         0xf3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

#pragma pack(push, 1)

typedef struct
{
    UCHAR len;
    UCHAR p_rep;
    UCHAR p_lock;
    UCHAR p_seg;
    UCHAR p_66;
    UCHAR p_67;
    UCHAR rex;
    UCHAR rex_w;
    UCHAR rex_r;
    UCHAR rex_x;
    UCHAR rex_b;
    UCHAR opcode;
    UCHAR opcode2;
    UCHAR modrm;
    UCHAR modrm_mod;
    UCHAR modrm_reg;
    UCHAR modrm_rm;
    UCHAR sib;
    UCHAR sib_scale;
    UCHAR sib_index;
    UCHAR sib_base;

    union
    {
        UCHAR imm8;
        USHORT imm16;
        ULONG imm32;
        ULONGLONG imm64;
    } imm;

    union
    {
        UCHAR disp8;
        USHORT disp16;
        ULONG disp32;
    } disp;

    ULONG flags;
} hde64s;

#pragma pack(pop)

#ifdef __cplusplus
extern "C"
{
#endif

unsigned int hde64_disasm(const void* code, hde64s* hs);

FORCEINLINE SIZE_T GetProcedureSize(PVOID Procedure)
{
    hde64s hde;
    SIZE_T c;

    c = 0;

    RtlZeroMemory(&hde, sizeof(hde));
    while (hde.opcode != 0xC3 && hde.opcode != 0xCC) {
        hde64_disasm((PVOID)((PCHAR)Procedure + c), &hde);
        if (hde.flags & F_ERROR)
            break;
        c += hde.len;
    }

    return c;
}

#ifdef __cplusplus
}
#endif

#endif /* _HDE64_H_ */
