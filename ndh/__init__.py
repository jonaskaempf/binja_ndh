#-*- coding: utf-8 -*-
import struct
from ctypes import c_uint16, c_int8

from binaryninja import *

'''
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
 *
 *  -------------------------------------- BF/AF Flag:
 *
 *  AF & BF is set with following instructions:
 *
 *    - CMP
 *
 *  AF & BF is used for JA and JB instructions.
 *
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

OpMnemonic = {
    OP_PUSH    : lambda f: 'push' + flag_suffix(f),
    OP_POP     : lambda f: 'pop',
    OP_MOV     : lambda f: 'mov' + flag_suffix(f),
    OP_ADD     : lambda f: 'add' + flag_suffix(f),
    OP_SUB     : lambda f: 'sub' + flag_suffix(f),
    OP_MUL     : lambda f: 'mul' + flag_suffix(f),
    OP_DIV     : lambda f: 'div' + flag_suffix(f),
    OP_INC     : lambda f: 'inc',
    OP_DEC     : lambda f: 'dec',
    OP_OR      : lambda f: 'or' + flag_suffix(f),
    OP_AND     : lambda f: 'and' + flag_suffix(f),
    OP_XOR     : lambda f: 'xor' + flag_suffix(f),
    OP_NOT     : lambda f: 'not',
    OP_JZ      : lambda f: 'jz',
    OP_JNZ     : lambda f: 'jnz',
    OP_JMPS    : lambda f: 'jmps',
    OP_TEST    : lambda f: 'test',
    OP_CMP     : lambda f: 'cmp' + flag_suffix(f),
    OP_CALL    : lambda f: 'call',
    OP_RET     : lambda f: 'ret',
    OP_JMPL    : lambda f: 'jmpl',
    OP_END     : lambda f: 'end',
    OP_XCHG    : lambda f: 'xchg',
    OP_JA      : lambda f: 'ja',
    OP_JB      : lambda f: 'jb',
    OP_SYSCALL : lambda f: 'syscall',
    OP_NOP     : lambda f: 'nop',
}

def flag_suffix(f):
    if f in [OP_FLAG_DIRECT08, OP_FLAG_REG_DIRECT08]:
        return '.b'
    elif f in [OP_FLAG_DIRECT16, OP_FLAG_REG_DIRECT16]:
        return '.l'
    else:
        return ''

def int8(x): return c_int8(x).value
def uint16(x): return c_uint16(x).value

RegNames = {
    0: 'r0', 1: 'r1', 2: 'r2', 3: 'r3', 4: 'r4', 5: 'r5',
    6: 'r6', 7: 'r7', 8: 'sp', 9: 'bp'
}

def _get_pseudo_flag(opcode):
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
    Decode instruction into length, opcode, flag, args, where

        length = instruction length in bytes
        opcode = one of OP_*
        flag = flag specifying format of 'args' (may be contained in length
            or derived from opcode)
        args = list of args
    
    '''
    opcode = ord(data[0])
    if opcode not in OpMnemonic:
        log_error('Cannot decode OP {:#x} @ {:#x}'.format(opcode, addr))
        return None, None, None, None

    n = 1

    flag = _get_pseudo_flag(opcode)
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


# Short hands
_d_txt = InstructionTextTokenType.TextToken
_d_instr = InstructionTextTokenType.InstructionToken
_d_opSep = InstructionTextTokenType.OperandSeparatorToken
_d_regName = InstructionTextTokenType.RegisterToken
_d_intLit = InstructionTextTokenType.IntegerToken
_d_posAddr = InstructionTextTokenType.PossibleAddressToken
_d_bMem = InstructionTextTokenType.BeginMemoryOperandToken
_d_eMem = InstructionTextTokenType.EndMemoryOperandToken
_d_floatLit = InstructionTextTokenType.FloatingPointToken
_dI = InstructionTextToken

def _disassemble(addr, length, opcode, flag, args):
    tokens = [ _dI( _d_instr, OpMnemonic[opcode](flag) ), _dI( _d_opSep, ' ' )]

    # TODO: Defined outside closure for better performance?
    def reg(r): return [ _dI( _d_regName, RegNames[r]) ]
    def indirect(r): return [ _dI( _d_bMem, '[' ), _dI( _d_regName, RegNames[r] ), _dI( _d_eMem, ']' )]
    def imm08(x): return [ _dI( _d_intLit, hex(x), x )]
    def imm16(x): return [ _dI( _d_intLit, hex(x), x )]
    def addr16(x): return [ _dI( _d_posAddr, hex(x), x )]
    def comma(): return [ _dI( _d_opSep, ', ' )]

    if flag == OP_FLAG_EMPTY:
        pass

    elif flag == OP_FLAG_REG_REG:
        tokens += reg(args[0])
        tokens += comma()
        tokens += reg(args[1])

    elif flag == OP_FLAG_REG_DIRECT08:
        tokens += reg(args[0])
        tokens += comma()
        tokens += imm08(args[1])

    elif flag == OP_FLAG_REG_DIRECT16:
        tokens += reg(args[0])
        tokens += comma()
        tokens += imm16(args[1])

    elif flag == OP_FLAG_REG:
        tokens += reg(args[0])

    # Jumps to addr + length + (uint16)imm16
    elif flag == OP_FLAG_DIRECT16 and opcode in [OP_CALL, OP_JMPL, OP_JZ, OP_JNZ, OP_JA, OP_JB]:
        tokens += addr16(uint16(args[0] + addr + length))

    elif flag == OP_FLAG_DIRECT16:
        tokens += imm16(args[0])

    elif flag == OP_FLAG_DIRECT08 and opcode in [OP_JMPS]:
        tokens += addr16(int8(args[0]) + addr + length)

    elif flag == OP_FLAG_DIRECT08:
        tokens += imm08(args[0])

    elif flag == OP_FLAG_REGINDIRECT_REG:
        tokens += indirect(args[0])
        tokens += comma()
        tokens += reg(args[1])

    elif flag == OP_FLAG_REGINDIRECT_DIRECT08:
        tokens += indirect(args[0])
        tokens += comma()
        tokens += imm08(args[1])

    elif flag == OP_FLAG_REGINDIRECT_DIRECT16:
        tokens += indirect(args[0])
        tokens += comma()
        tokens += imm16(args[1])

    elif flag == OP_FLAG_REGINDIRECT_REGINDIRECT:
        tokens += indirect(args[0])
        tokens += comma()
        tokens += indirect(args[1])

    elif flag == OP_FLAG_REG_REGINDIRECT:
        tokens += reg(args[0])
        tokens += comma()
        tokens += indirect(args[1])

    return tokens


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
    flags = [ 'zf', 'af', 'bf' ]
    flag_write_types = []
    flags_written_by_flag_write_type = { }
    flag_roles = {
        'zf': FlagRole.ZeroFlagRole
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

        return info

    def perform_get_instruction_text(self, data, addr):
        length, opcode, flag, args = self._decode(data, addr)
        tokens = _disassemble(addr, length, opcode, flag, args)
        return tokens, length

    def perform_get_instruction_low_level_il(self, data, addr, il):
        #length, opcode, flag, args = self._decode(data, addr)
        #il.append(il.unimplemented())
        #return length
        return None


class NDHView(BinaryView):
    name = 'NDH'
    long_name = 'NDH Executable'

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)

    @classmethod
    def is_valid_for_data(cls, data):
        hdr = data.read(0, 4)
        return hdr == '.NDH'

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

        return True

    def perform_is_valid_offset(self, addr):
        return 0x0 <= addr and addr <= 0xffff

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_addr


NDH.register()
NDHView.register()
