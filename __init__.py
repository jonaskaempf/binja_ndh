#-*- coding: utf-8 -*-
import struct
from ctypes import c_uint16, c_int8

from binaryninja import *

'''

NDH architecture description taken from https://github.com/JonathanSalwan/VMNDH-2k12.

https://github.com/JonathanSalwan/VMNDH-2k12/blob/master/includes/op.h:

/*
** vmndh - Release v0.1
** Jonathan Salwan - http://twitter.com/JonathanSalwan
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef   __OP_H__
#define   __OP_H__

/****************************************
 *
 *
 * ------------------------------- Mapping memory:
 *
 *  STACK   [0000 - 7FFF]  (default ASLR is disable. Possibility to set ASLR with -aslr)
 *  Program [8000 - FFFE]  (default NX & PIE is disable. Possibility to set NX & PIE with -nx -pie)
 *
 *  ASLR genered with:
 *                    __asm__("mov %gs:0x14, %eax");
 *                    __asm__("shr $0x08, %eax");
 *                    __asm__("mov %%eax, %0" : "=m"(aslr));
 *                    aslr = aslr % 0x3000 + 0x4ffe;
 *
 *  PIE genered with:
 *                    __asm__("mov %gs:0x14, %eax");
 *                    __asm__("shr $0x08, %eax");
 *                    __asm__("mov %%eax, %0" : "=m"(pie));
 *                    pie = pie % 0x3000 + 0x8000;
 *
 *
 *
 *   ^   0000>+-----------------+
 *   |        |                 |             The size max of binary is 0x7ffe.
 *   |        |     STACK    ^^ |
 *   |        |              || |             Before the program is executed atgv and argc is pushed on the stack.
 *   |        |                 |             If a arguments is set with (-arg), argc = 1 and argv points to the string.
 *   |        +-----------------+< SP & BP
 *   6        |     ARG         |             If you don't set a arguments argc and argv is pushed with value 0x00.
 *   4   8000>+-----------------+< PC
 *   K        |                 |
 *   |        |              || |             Exemple1: ./vmndh -file ./binary
 *   |        |     CODE     vv |
 *   |        |                 |                       [SP] 0x00 0x00 0x00 0x00 0x00 0x00
 *   |        |                 |                            <--argc-> <-argv-->
 *   |        |                 |
 *   v   ffff>+-----------------+             Exemple2: ./vmndh -file ./binary -arg "abcd"
 *
 *  -------------------------------                     [SP] 0x01 0x00 0xac 0x7f 0x00 0x00
 *                                                           <--argc-> <-argv-->
 *
 *
 *  ------------------------------- File format (fichier .ndh)
 *
 *  [MAGIC][size .text][.text content]
 *
 *  MAGIC: ".NDH"
 *  SIZE:  size of section TEXT
 *  CODE:  our instructions
 *  -------------------------------
 *
 *
 *  ------------------------------------- Instruction encoding:
 *
 *  [OPCODE] [OP_FLAGS | !] [OPERAND #1] [OPERAND #2]
 *
 *
 *  [ADD]   <opcode> <FLAG> <REG> <REG | DIR8 | DIR16> (size = 4 or 5 bytes)
 *          - reg   = add
 *          - dir8  = addb
 *          - dir16 = addl
 *
 *  [AND]   <opcode> <FLAG> <REG> <REG | DIR8 | DIR16> (size = 4 or 5 bytes)
 *          - reg   = and
 *          - dir8  = andb
 *          - dir16 = andl
 *
 *  [CALL]  <opcode> <FLAG> <REG | DIR16> (size = 3 or 4 bytes)
 *  [CMP]   <opcode> <FLAG> <REG> <REG | DIR8 | DIR16> (size = 4 or 5 bytes)
 *          - reg   = cmp
 *          - dir8  = cmpb
 *          - dir16 = cmpl
 *
 *  [DEC]   <opcode> <REG> (size = 2)
 *  [DIV]   <opcode> <FLAG> <REG> <REG | DIR8 | DIR16> (size = 4 or 5 bytes)
 *          - reg   = div
 *          - dir8  = divb
 *          - dir16 = divl
 *
 *  [END]   <opcode> (size = 1 byte)
 *  [INC]   <opcode> <REG> (size = 2 bytes)
 *  [JMPL]  <opcode> <DIR16> (size = 3 bytes)
 *  [JMPS]  <opcode> <DIR8> (size = 2 bytes)
 *  [JNZ]   <opcode> <DIR16> (size = 3 bytes)
 *  [JZ]    <opcode> <DIR16> (size = 3 bytes)
 *  [JA]    <opcode> <DIR16> (size = 3 bytes)
 *  [JB]    <opcode> <DIR16> (size = 3 bytes)
 *  [MOV]   <opcode> <FLAG> <REG | REG_INDIRECT> <REG | REG_INDIRECT | DIR8 | DIR16> (size = 4 or 5 bytes)
 *          - reg   = mov
 *          - dir8  = movb
 *          - dir16 = movl
 *          - indir = mov [rX]
 *
 *  [MUL]   <opcode> <FLAG> <REG> <REG | DIR8 | DIR16> (size = 4 or 5 bytes)
 *          - reg   = mul
 *          - dir8  = mulb
 *          - dir16 = mull
 *
 *  [NOP]   <opcode> (size = 1 byte)
 *  [NOT]   <opcode> <REG> (size = 2 bytes)
 *  [OR]    <opcode> <FLAG> <REG> <REG | DIR8 | DIR16> (size = 4 or 5 bytes)
 *          - reg   = or
 *          - dir8  = orb
 *          - dir16 = orl
 *
 *  [POP]   <opcode> <REG> (size = 2 bytes)
 *  [PUSH]  <opcode> <FLAG> <REG | DIR08 | DIR16> (size = 3 or 4 bytes)
 *          - reg   = push
 *          - dir8  = pushb
 *          - dir16 = pushl
 *  [RET]   <opcode> (size = 1 byte)
 *  [SUB]   <opcode> <FLAG> <REG> <REG | DIR8 | DIR16> (size = 4 or 5 bytes)
 *          - reg   = sub
 *          - dir8  = subb
 *          - dir16 = subl
 *  [SYSCALL] <opcode> (size = 1 byte)
 *  [TEST]  <opcode> <REG> <REG> (size = 3 bytes)
 *  [XCHG]  <opcode> <REG> <REG> (size = 3 bytes
 *  [XOR]   <opcode> <FLAG> <REG> <REG | DIR8 | DIR16> (size = 4 or 5 bytes)
 *          - reg   = xor
 *          - dir8  = xorb
 *          - dir16 = xorl
 *
 *  -------------------------------------
 *
 *
 *
 *  ------------------------------------- Syscall:
 *
 *  r0 = syscall number
 *  r1 = arg1
 *  r2 = arg2
 *  r3 = arg3
 *  r4 = arg4
 *
 *
 *  syscalls supported: open(), read(), write(), close(), exit(), setuid(), setgid(), dup2(), send()
 *                      recv(), socket(), listen(), bind(), accept(), chdir(), chmod(), lseek(),
 *                      getpid(), getuid(), pause()
 *
 *  [sys_open]    r1 = uint16_t *
 *                r2 = uint16_t
 *                r3 = uint16_t
 *
 *  [sys_exit]    r1 = uint16_t
 *
 *  [sys_read]    r1 = uint16_t
 *                r2 = uint16_t *
 *                r3 = uint16_t
 *
 *  [sys_write]   r1 = uint16_t
 *                r2 = uint16_t *
 *                r3 = uint16_t
 *
 *  [sys_close]   r1 = uint16_t
 *
 *  [sys_exit]    r1 = uint16_t
 *
 *  [sys_setuid]  r1 = uint16_t
 *
 *  [sys_setgid]  r1 = uint16_t
 *
 *  [sys_dup2]    r1 = uint16_t
 *                r2 = uint16_t
 *
 *  [sys_send]    r1 = uint16_t
 *                r2 = uint16_t *
 *                r3 = uint16_t
 *                r4 = uint16_t
 *
 *
 *  [sys_recv]    r1 = uint16_t
 *                r2 = uint16_t *
 *                r3 = uint16_t
 *                r4 = uint16_t
 *
 *  [sys_socket]  r1 = uint16_t
 *                r2 = uint16_t
 *                r3 = uint16_t
 *
 *  [sys_listen]  r1 = uint16_t
 *                r2 = uint16_t
 *
 *  [sys_bind]    r1 = uint16_t (socket)
 *                r2 = uint16_t (port)
 *
 *  [sys_accept]  r1 = uint16_t (socket)
 *
 *  [SYS_CHDIR]   r1 = uint16_t *
 *
 *  [SYS_CHMOD]   r1 = uint16_t *
 *                r2 = uint16_t
 *
 *  [SYS_LSEEK]   r1 = uint16_t
 *                r2 = uint16_t
 *                r3 = uint16_t
 *
 *  [SYS_GETPID]  n/a
 *
 *  [SYS_GETUID]  n/a
 *
 *  [SYS_PAUSE]   n/a
 *
 *
 *
 *  The return value is set in r0.
 *
 *  --------------------------------------
 *
 *  -------------------------------------- Zero Flag:
 *
 *  ZF is set with following instructions:
 *
 *    - ADD
 *    - SUB
 *    - MUL
 *    - DIC
 *    - INC
 *    - DEC
 *    - OR
 *    - XOR
 *    - AND
 *    - NOT
 *    - TEST
 *    - CMP
 *
 *  --------------------------------------
 *

    test r1 r2

    r1 == 0 && r2 == 0  -> zf = 1
    _                   -> zf = 0

 *
 *  -------------------------------------- BF/AF Flag:
 *
 *  AF & BF is set with following instructions:
 *
 *    - CMP
 *
 *  AF & BF is used for JA and JB instructions.
 *

https://github.com/JonathanSalwan/VMNDH-2k12/blob/master/src_vm/op_cmp.c#L36-L59:

    cmp r1 r2

    r1 == r2 -> zf = 1, af = 0, bf = 0
    r1 > r2  -> zf = 0, af = 1, bf = 0
    r1 < r2  -> zf = 0, af = 0, bf = 1

 *  --------------------------------------
 *
 *  ****************************************/
'''
OP_FLAG_REG_REG = 0x00
OP_FLAG_REG_DIRECT08 = 0x01
OP_FLAG_REG_DIRECT16 = 0x02
OP_FLAG_REG = 0x03
OP_FLAG_DIRECT16 = 0x04
OP_FLAG_DIRECT08 = 0x05
OP_FLAG_REGINDIRECT_REG = 0x06
OP_FLAG_REGINDIRECT_DIRECT08 = 0x07
OP_FLAG_REGINDIRECT_DIRECT16 = 0x08
OP_FLAG_REGINDIRECT_REGINDIRECT = 0x09
OP_FLAG_REG_REGINDIRECT = 0x0a

OP_FLAG_EMPTY = 0xff

# Encode operands in bitmask (src | dst): xxxx | yyyy
OPERAND_REG = 1 << 0
OPERAND_DIRECT08 = 1 << 1
OPERAND_DIRECT16 = 1 << 2
OPERAND_REGINDIRECT = 1 << 3

REG_0 = 0x00
REG_1 = 0x01
REG_2 = 0x02
REG_3 = 0x03
REG_4 = 0x04
REG_5 = 0x05
REG_6 = 0x06
REG_7 = 0x07
REG_SP = 0x08
REG_BP = 0x09

#/* Stack */
OP_PUSH = 0x01
OP_POP = 0x03

#/* Memory */
OP_MOV = 0x04
#/*OP_STRCPY = 0x05*/

#/* Arithmetics */
OP_ADD = 0x06
OP_SUB = 0x07
OP_MUL = 0x08
OP_DIV = 0x09
OP_INC = 0x0A
OP_DEC = 0x0B

#/* Logic */
OP_OR = 0x0C
OP_AND = 0x0D
OP_XOR = 0x0E
OP_NOT = 0x0F

#/* Control */
OP_JZ = 0x10
OP_JNZ = 0x11
OP_JMPS = 0x16 #/* jmp short operande 8 bits */
OP_TEST = 0x17
OP_CMP = 0x18
OP_CALL = 0x19
OP_RET = 0x1A
OP_JMPL = 0x1B #/* jmp long operande 16 bit */
OP_END = 0x1C
OP_XCHG = 0x1D
OP_JA = 0x1E
OP_JB = 0x1F

#/* SYSCALLS */
OP_SYSCALL = 0x30
OP_NOP = 0x02

'''
/**
 *
 * Syscalls Number
 *
 * **/
'''
SYS_EXIT = 0x01
SYS_OPEN = 0x02
SYS_READ = 0x03
SYS_WRITE = 0x04
SYS_CLOSE = 0x05
SYS_SETUID = 0x06
SYS_SETGID = 0x07
SYS_DUP2 = 0x08
SYS_SEND = 0x09
SYS_RECV = 0x0a
SYS_SOCKET = 0x0b
SYS_LISTEN = 0x0c
SYS_BIND = 0x0d
SYS_ACCEPT = 0x0e
SYS_CHDIR = 0x0f
SYS_CHMOD = 0x10
SYS_LSEEK = 0x11
SYS_GETPID = 0x12
SYS_GETUID = 0x13
SYS_PAUSE = 0x14

#endif     /* !__OP_H__ */

FlagToOperandTypes = {
    OP_FLAG_EMPTY: (0, 0),
    OP_FLAG_REG: (OPERAND_REG, 0),
    OP_FLAG_DIRECT08: (OPERAND_DIRECT08, 0),
    OP_FLAG_DIRECT16: (OPERAND_DIRECT16, 0),
    OP_FLAG_REG_REG: (OPERAND_REG, OPERAND_REG),
    OP_FLAG_REG_DIRECT08: (OPERAND_REG, OPERAND_DIRECT08),
    OP_FLAG_REG_DIRECT16: (OPERAND_REG, OPERAND_DIRECT16),
    OP_FLAG_REGINDIRECT_REG: (OPERAND_REGINDIRECT, OPERAND_REG),
    OP_FLAG_REG_REGINDIRECT: (OPERAND_REG, OPERAND_REGINDIRECT),
    OP_FLAG_REGINDIRECT_REGINDIRECT: (OPERAND_REGINDIRECT, OPERAND_REGINDIRECT),
    OP_FLAG_REGINDIRECT_DIRECT08: (OPERAND_REGINDIRECT, OPERAND_DIRECT08),
    OP_FLAG_REGINDIRECT_DIRECT16: (OPERAND_REGINDIRECT, OPERAND_DIRECT16),
}
def ParseFlag(flag):
    op0, op1 = FlagToOperandTypes[flag]
    op0_sz = 1 if op0 == OPERAND_DIRECT08 else 2
    op1_sz = 1 if op1 == OPERAND_DIRECT08 else 2
    return op0, op0_sz, op1, op1_sz

OpMnemonic = {
    OP_ADD     : lambda f: 'add' + flag_suffix(f),
    OP_AND     : lambda f: 'and' + flag_suffix(f),
    OP_CALL    : lambda f: 'call',
    OP_CMP     : lambda f: 'cmp' + flag_suffix(f),
    OP_DEC     : lambda f: 'dec',
    OP_DIV     : lambda f: 'div' + flag_suffix(f),
    OP_END     : lambda f: 'end',
    OP_INC     : lambda f: 'inc',
    OP_JA      : lambda f: 'ja',
    OP_JB      : lambda f: 'jb',
    OP_JMPL    : lambda f: 'jmpl',
    OP_JMPS    : lambda f: 'jmps',
    OP_JNZ     : lambda f: 'jnz',
    OP_JZ      : lambda f: 'jz',
    OP_MOV     : lambda f: 'mov' + flag_suffix(f),
    OP_MUL     : lambda f: 'mul' + flag_suffix(f),
    OP_NOP     : lambda f: 'nop',
    OP_NOT     : lambda f: 'not',
    OP_OR      : lambda f: 'or' + flag_suffix(f),
    OP_POP     : lambda f: 'pop',
    OP_PUSH    : lambda f: 'push' + flag_suffix(f),
    OP_RET     : lambda f: 'ret',
    OP_SUB     : lambda f: 'sub' + flag_suffix(f),
    OP_SYSCALL : lambda f: 'syscall',
    OP_TEST    : lambda f: 'test',
    OP_XCHG    : lambda f: 'xchg',
    OP_XOR     : lambda f: 'xor' + flag_suffix(f),
}

def flag_suffix(f):
    _, op1 = FlagToOperandTypes[f]
    if op1 == OPERAND_DIRECT08:
        return 'b'
    elif op1 == OPERAND_DIRECT16:
        return 'l'
    else:
        return ''

def int8(x): return c_int8(x).value
def uint16(x): return c_uint16(x).value

RegNames = {
    0: 'r0', 1: 'r1', 2: 'r2', 3: 'r3', 4: 'r4', 5: 'r5',
    6: 'r6', 7: 'r7', 8: 'sp', 9: 'bp'
}

def _derive_flag(opcode):
    '''Determine op format (i.e. flag type) for ops that don't include flag'''
    if opcode in [OP_RET, OP_SYSCALL, OP_NOP, OP_END]:
        return OP_FLAG_EMPTY

    elif opcode in [OP_DEC, OP_INC, OP_NOT, OP_POP]:
        return OP_FLAG_REG

    elif opcode in [OP_TEST, OP_XCHG]:
        return OP_FLAG_REG_REG

    elif opcode in [OP_JMPS]:
        return OP_FLAG_DIRECT08

    elif opcode in [OP_JZ, OP_JA, OP_JB, OP_JNZ, OP_JMPL]:
        return OP_FLAG_DIRECT16

    else:
        return None

# Operands come in these groups (and OP_FLAG_EMPTY)
FlagShort = [OP_FLAG_REG, OP_FLAG_DIRECT08]
FlagShortShort = [
    OP_FLAG_REG_REG, OP_FLAG_REG_DIRECT08, OP_FLAG_REGINDIRECT_REG,
    OP_FLAG_REGINDIRECT_DIRECT08, OP_FLAG_REGINDIRECT_REGINDIRECT,
    OP_FLAG_REG_REGINDIRECT
]
FlagLong = [OP_FLAG_DIRECT16]
FlagShortLong = [ OP_FLAG_REG_DIRECT16, OP_FLAG_REGINDIRECT_DIRECT16]


def _decode_instr(data, addr):
    '''
    Decode instruction into (length, opcode, flag, args), where

        length = instruction length in bytes
        opcode = one of OP_*
        flag = flag specifying format of 'args' (may be explicitly contained in instruction,
            or derived from opcode)
        args = list of args

    '''
    opcode = ord(data[0])
    if opcode not in OpMnemonic:
        log_error('Cannot decode OP {:#x} @ {:#x}'.format(opcode, addr))
        return None, None, None, None

    n = 1

    flag = _derive_flag(opcode)
    if flag is None:    # then flag must be included in data
        flag = ord(data[n])
        n += 1

    if flag == OP_FLAG_EMPTY:
        return n, opcode, flag, []
    elif flag in FlagShortShort:
        return n + 2, opcode, flag, [ord(data[n]), ord(data[n+1])]
    elif flag in FlagShort:
        return n + 1, opcode, flag, [ord(data[n])]
    elif flag in FlagShortLong:
        reg1 = ord(data[n])
        imm16 = struct.unpack('<H', data[n+1:n+3])[0]
        return n + 3, opcode, flag, [reg1, imm16]
    elif flag in FlagLong:
        imm16 = struct.unpack('<H', data[n:n+2])[0]
        return n + 2, opcode, flag, [imm16]


class Dis:
    '''Namespace for helpers for outputting disassembly tokens'''
    Txt = InstructionTextTokenType.TextToken
    Mnemonic = InstructionTextTokenType.InstructionToken
    Sep = InstructionTextTokenType.OperandSeparatorToken
    Reg = InstructionTextTokenType.RegisterToken
    Int = InstructionTextTokenType.IntegerToken
    Addr = InstructionTextTokenType.PossibleAddressToken
    Float = InstructionTextTokenType.FloatingPointToken
    Token = InstructionTextToken

    tokenize_operand = {
        0: [],
        OPERAND_REG: lambda r: [ Dis.Token( Dis.Reg, RegNames[r] ) ],
        OPERAND_REGINDIRECT: lambda r: [ 
            Dis.Token( InstructionTextTokenType.BeginMemoryOperandToken, '[' ), 
            Dis.Token( Dis.Reg, RegNames[r] ), 
            Dis.Token( InstructionTextTokenType.EndMemoryOperandToken, ']' )
        ],
        OPERAND_DIRECT08: lambda x: [ Dis.Token( Dis.Int, hex(x), x ) ],
        OPERAND_DIRECT16: lambda x: [ Dis.Token( Dis.Int, hex(x), x ) ],
    }

    @staticmethod
    def disassemble(addr, length, opcode, flag, args):
        tokens = [ Dis.Token( Dis.Mnemonic, OpMnemonic[opcode](flag) ) ]

        def addr16(x): return [ Dis.Token( Dis.Addr, hex(x), x )]
        comma = [ Dis.Token( Dis.Sep, ', ' )]

        # Special-case jumps since their operand can be converted to address
        if flag == OP_FLAG_EMPTY:
            pass

        elif flag == OP_FLAG_DIRECT16 and opcode in [OP_CALL, OP_JMPL, OP_JZ, OP_JNZ, OP_JA, OP_JB]:
            tokens += addr16(uint16(args[0] + addr + length))

        elif flag == OP_FLAG_DIRECT08 and opcode in [OP_JMPS]:
            tokens += addr16(int8(args[0]) + addr + length)

        else:
            op0, _, op1, _ = ParseFlag(flag)
            tokens += Dis.tokenize_operand[op0](args[0])
            if op1 != 0:
                tokens += comma
                tokens += Dis.tokenize_operand[op1](args[1])

        if len(tokens) > 1:     # non-empty opcode
            tokens.insert(1, Dis.Token( Dis.Sep, ' ' ))

        return tokens


class Lift:
    '''Namespace for lifting to Lifted IL'''
    word_size = 2
    addr_size = 2

    operand = {
        OPERAND_REG: lambda il, arg: il.reg(2, RegNames[arg]),
        OPERAND_DIRECT08: lambda il, arg: il.const(1, arg),
        OPERAND_DIRECT16: lambda il, arg: il.const(2, arg),
        # Right-hand side (src)
        OPERAND_REGINDIRECT: lambda il, arg: il.load(2, il.reg(2, RegNames[arg]))
    }

    @staticmethod
    def cond_branch(il, cond, true_target, false_target):
        '''
        https://github.com/joshwatson/binaryninja-msp430/blob/master/__init__.py#L329-L363

        For NDH, we have JNZ, JZ, JA and JB.
        '''
        t = il.get_label_for_address(Architecture['ndh'], true_target)

        if t is None:
            # t is not an address in the current function scope.
            t = LowLevelILLabel()
            indirect = True
        else:
            indirect = False

        f_label_found = True
        f = il.get_label_for_address(Architecture['ndh'], false_target)

        if f is None:
            f = LowLevelILLabel()
            f_label_found = False

        il.append(il.if_expr(cond, t, f))

        if indirect:
            # If the destination is not in the current function,
            # then a jump, rather than a goto, needs to be added to
            # the IL.
            il.mark_label(t)
            il.append(il.jump(il.const(Lift.addr_size, true_target)))

        if not f_label_found:
            il.mark_label(f)

    @staticmethod
    def lifted_il(il, addr, length, opcode, flag, args):
        '''Lift instruction to Lifted IL'''
        if opcode == None: il.append(il.unimplemented())
        elif opcode == OP_ADD     :
            dst_t, dst_sz, src_t, src_sz = ParseFlag(flag)
            dst = Lift.operand[dst_t](il, args[0])
            src = Lift.operand[src_t](il, args[1])
            rhs = il.add(dst_sz, dst, src, flags='z')
            il.append(il.set_reg(dst_sz, RegNames[args[0]], rhs))

        elif opcode == OP_AND     :
            dst_t, dst_sz, src_t, src_sz = ParseFlag(flag)
            dst = Lift.operand[dst_t](il, args[0])
            src = Lift.operand[src_t](il, args[1])
            rhs = il.and_expr(dst_sz, dst, src, flags='z')
            il.append(il.set_reg(dst_sz, RegNames[args[0]], rhs))

        elif opcode == OP_CALL    :
            dst_t, dst_sz, _, _ = ParseFlag(flag)
            if dst_t == OPERAND_REG:
                il.append(il.unimplemented())
            elif dst_t == OPERAND_DIRECT16:
                addr_calc = il.const(Lift.word_size, uint16(addr + length + args[0]))
                il.append(il.call(addr_calc))

        # TODO: Implement
        elif opcode == OP_CMP     : il.append(il.unimplemented())
        elif opcode == OP_DEC     :
            dst_t, dst_sz, _, _ = ParseFlag(flag)
            rhs = il.sub(2, Lift.operand[dst_t](il, args[0]), il.const(2, 1), flags=None)
            il.append(il.set_reg(dst_sz, RegNames[args[0]], rhs))

        elif opcode == OP_DIV     :
            dst_t, dst_sz, src_t, src_sz = ParseFlag(flag)
            dst = Lift.operand[dst_t](il, args[0])
            src = Lift.operand[src_t](il, args[1])
            rhs = il.div_unsigned(dst_sz, dst, src, flags='z')
            il.append(il.set_reg(dst_sz, RegNames[args[0]], rhs))

        # TODO: Why you no work!?
        elif opcode == OP_END     :
            #il.append(il.no_ret())
            il.append(il.unimplemented())

        elif opcode == OP_INC     :
            dst_t, dst_sz, _, _ = ParseFlag(flag)
            rhs = il.add(2, Lift.operand[dst_t](il, args[0]), il.const(2, 1), flags=None)
            il.append(il.set_reg(dst_sz, RegNames[args[0]], rhs))

        elif opcode == OP_JA      :
            true_addr = uint16(addr + length + args[0])
            false_addr = uint16(addr + length)
            true_cond = il.compare_equal(1, il.flag('a'), il.const(1, 0))
            Lift.cond_branch(il, true_cond, true_addr, false_addr)

        elif opcode == OP_JB      :
            true_addr = uint16(addr + length + args[0])
            false_addr = uint16(addr + length)
            true_cond = il.compare_equal(1, il.flag('b'), il.const(1, 0))
            Lift.cond_branch(il, true_cond, true_addr, false_addr)

        elif opcode == OP_JMPL    :
            addr_calc = il.const(Lift.word_size, uint16(addr + length + args[0]))
            il.append(il.jump(addr_calc))

        elif opcode == OP_JMPS    :
            addr_calc = il.const(Lift.word_size, uint16(addr + length + int8(args[0])))
            il.append(il.jump(addr_calc))

        elif opcode == OP_JNZ     :
            true_addr = uint16(addr + length + args[0])
            false_addr = uint16(addr + length)
            true_cond = il.compare_not_equal(1, il.flag('z'), il.const(1, 0))
            Lift.cond_branch(il, true_cond, true_addr, false_addr)
            
        elif opcode == OP_JZ      :
            true_addr = uint16(addr + length + args[0])
            false_addr = uint16(addr + length)
            true_cond = il.compare_equal(1, il.flag('z'), il.const(1, 1))
            Lift.cond_branch(il, true_cond, true_addr, false_addr)

        elif opcode == OP_MOV:
            dst_t, dst_sz, src_t, src_sz = ParseFlag(flag)

            if dst_t == OPERAND_REG:
                src = Lift.operand[src_t](il, args[1])
                expr = il.set_reg(src_sz, RegNames[args[0]], src)

            elif dst_t == OPERAND_REGINDIRECT:
                dst = il.reg(Lift.word_size, RegNames[args[0]])
                src = Lift.operand[src_t](il, args[1])
                expr = il.store(src_sz, dst, src)

            else:
                log_error('Invalid mov instruction: ({:#x}, {}, {}, {}, {})'.format(
                    addr, length, opcode, flag, args))
                expr = il.unimplemented()

            il.append(expr)

        elif opcode == OP_MUL     :
            dst_t, dst_sz, src_t, src_sz = ParseFlag(flag)
            dst = Lift.operand[dst_t](il, args[0])
            src = Lift.operand[src_t](il, args[1])
            rhs = il.mult(dst_sz, dst, src, flags='z')
            il.append(il.set_reg(dst_sz, RegNames[args[0]], rhs))

        elif opcode == OP_NOP     :
            il.append(il.nop())

        elif opcode == OP_NOT     :
            dst_t, dst_sz, src_t, src_sz = ParseFlag(flag)
            dst = Lift.operand[dst_t](il, args[0])
            rhs = il.not_expr(Lift.word_size, dst, flags='z')
            il.append(il.set_reg(Lift.word_size, RegNames[args[0]], rhs))

        elif opcode == OP_OR      :
            dst_t, dst_sz, src_t, src_sz = ParseFlag(flag)
            dst = Lift.operand[dst_t](il, args[0])
            src = Lift.operand[src_t](il, args[1])
            rhs = il.or_expr(dst_sz, dst, src, flags='z')
            il.append(il.set_reg(dst_sz, RegNames[args[0]], rhs))

        elif opcode == OP_POP     :
            il.append(il.set_reg(2, RegNames[args[0]], il.pop(2)))

        elif opcode == OP_PUSH    :
            dst_t, dst_sz, _, _ = ParseFlag(flag)
            dst = Lift.operand[dst_t](il, args[0])
            il.append(il.push(dst_sz, dst))

        elif opcode == OP_RET     :
            il.append(il.ret(il.pop(Lift.addr_size)))

        elif opcode == OP_SUB     :
            dst_t, dst_sz, src_t, src_sz = ParseFlag(flag)
            dst = Lift.operand[dst_t](il, args[0])
            src = Lift.operand[src_t](il, args[1])
            rhs = il.sub(dst_sz, dst, src, flags='z')
            il.append(il.set_reg(dst_sz, RegNames[args[0]], rhs))

        elif opcode == OP_SYSCALL :
            il.append(il.system_call())

        # TODO Does not seem to work as intended; in LLIL it shows as just "reg", e.g. "r0";
        #   in x86_64 it shows as "and.b ..." (in LLIL)
        elif opcode == OP_TEST    :
            dst_t, dst_sz, src_t, src_sz = ParseFlag(flag)
            dst = Lift.operand[dst_t](il, args[0])
            src = Lift.operand[src_t](il, args[1])
            test_expr = il.and_expr(2, dst, src, flags='z')
            il.append(test_expr)
            #il.flag_condition(il.LowLevelFlagILFlagCondition.LLFC_NE)
            #il.append(test_expr)

        elif opcode == OP_XCHG    :
            dst_reg = RegNames[args[0]]
            dst = il.reg(Lift.word_size, dst_reg)
            src_reg = RegNames[args[1]]
            src = il.reg(Lift.word_size, src_reg)
            tmp = LLIL_TEMP(0)
            il.append(il.set_reg(Lift.word_size, tmp, src))
            il.append(il.set_reg(Lift.word_size, src_reg, dst))
            il.append(il.set_reg(Lift.word_size, dst_reg, il.reg(Lift.word_size, tmp)))

        elif opcode == OP_XOR     :
            dst_t, dst_sz, src_t, src_sz = ParseFlag(flag)
            dst = Lift.operand[dst_t](il, args[0])
            src = Lift.operand[src_t](il, args[1])
            rhs = il.xor_expr(dst_sz, dst, src, flags='z')
            il.append(il.set_reg(dst_sz, RegNames[args[0]], rhs))


class NDH(Architecture):
    name = 'ndh'

    # Address space is 16-bit
    address_size = 2
    # Instructions can be up to 5 bytes
    max_instr_length = 5
    default_int_size = 2

    regs = {
        'pc': RegisterInfo('pc', 2),
        'sp': RegisterInfo('sp', 2),
        'bp': RegisterInfo('bp', 2),
        'r0': RegisterInfo('r0', 2),
        'r1': RegisterInfo('r1', 2),
        'r2': RegisterInfo('r2', 2),
        'r3': RegisterInfo('r3', 2),
        'r4': RegisterInfo('r4', 2),
        'r5': RegisterInfo('r5', 2),
        'r6': RegisterInfo('r6', 2),
        'r7': RegisterInfo('r7', 2),
    }
    stack_pointer = 'sp'
    flags = [ 'z', 'a', 'b' ]
    # BUG in flag_write_types: https://github.com/Vector35/binaryninja-api/issues/513
    flag_write_types = [ '', 'z', 'a', 'b' ]
    flags_written_by_flag_write_type = {
        'z': ['z'],
        'a': ['a'],
        'b': ['b'],
    }
    flag_roles = {
        'z': FlagRole.ZeroFlagRole,
        'a': FlagRole.SpecialFlagRole,
        'b': FlagRole.SpecialFlagRole,
    }
    flags_required_for_flag_condition = { }

    def _decode(self, data, addr):
        return _decode_instr(data, addr)

    def perform_get_instruction_info(self, data, addr):
        length, opcode, flag, args = self._decode(data, addr)
        if length is None:
            return None

        info = InstructionInfo()
        info.length = length

        # Branching
        if opcode in [OP_RET]:
            info.add_branch(BranchType.FunctionReturn)

        elif opcode in [OP_JMPL]:
            info.add_branch(BranchType.UnconditionalBranch, uint16(args[0] + addr + length))

        elif opcode in [OP_JZ, OP_JNZ, OP_JA, OP_JB]:
            info.add_branch(BranchType.TrueBranch, uint16(args[0] + addr + length))
            info.add_branch(BranchType.FalseBranch, uint16(addr + length))

        elif opcode in [OP_JMPS]:
            info.add_branch(BranchType.UnconditionalBranch, int8(args[0]) + addr + length)

        elif opcode in [OP_CALL]:
            if flag == OP_FLAG_REG:
                info.add_branch(BranchType.CallDestination)

            elif flag == OP_FLAG_DIRECT16:
                info.add_branch(BranchType.CallDestination, uint16(args[0] + addr + length))

        elif opcode in [OP_SYSCALL]:
            info.add_branch(BranchType.SystemCall)

        return info

    def perform_get_instruction_text(self, data, addr):
        length, opcode, flag, args = self._decode(data, addr)
        tokens = Dis.disassemble(addr, length, opcode, flag, args)
        return tokens, length

    def perform_get_instruction_low_level_il(self, data, addr, il):
        length, opcode, flag, args = self._decode(data, addr)
        Lift.lifted_il(il, addr, length, opcode, flag, args)
        return length

    def perform_convert_to_nop(self, data, addr):
        n = len(data)
        return chr(OP_NOP) * n


class NDHView(BinaryView):
    name = 'NDH'
    long_name = 'NDH Executable'

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)

    @classmethod
    def is_valid_for_data(cls, data):
        hdr = data.read(0, 4)
        return hdr == '.NDH'

    @staticmethod
    def name_syscall_wrappers(bv):
        '''Hackish identification and renaming of syscall wrappers; does not rely on LLIL as it should!'''
        syscall_blocks = []
        for func in bv.functions:
            if len(func.basic_blocks) != 1:
                continue
            else:
                block = func.basic_blocks[0]
                prev = None
                for ln in block.disassembly_text:
                    if 'syscall' in [str(t) for t in ln.tokens]:
                        syscall_blocks.append((block, prev))
                        break
                    prev = ln

        for block, r0 in syscall_blocks:
            syscall_num = r0.tokens[-1].value
            for key, value in globals().items():
                if key.startswith('SYS_') and value == syscall_num:
                    bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, block.start, key.lower()))


    def init(self):
        self.platform = Architecture['ndh'].standalone_platform
        self.arch = Architecture['ndh']

        hdr_sz = 0x6
        hdr = self.parent_view.read(0, hdr_sz)
        text_sz = struct.unpack('<H', hdr[4:6])[0]

        if hdr[0:4] != '.NDH' or len(self.parent_view) != text_sz + hdr_sz:
            log_error('Not an .NDH, or invalid size ({} vs. {})'.format(
                text_sz, len(self.parent_view) - hdr_sz))
            return False

        load_addr = 0x8000
        self.entry_addr = load_addr
        self.add_entry_point(load_addr)

        # Executable
        self.add_auto_segment(load_addr, text_sz, hdr_sz, text_sz,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

        # Some typical symbols
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.entry_addr, "_entry"))

        PluginCommand.register('Name syscall wrappers', 'Attempt to identify and name NDH syscall wrappers',
                NDHView.name_syscall_wrappers)

        return True

    def perform_is_valid_offset(self, addr):
        return 0x0 <= addr and addr <= 0xffff

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_addr


NDH.register()
NDHView.register()

