import struct
from .instruction import Instruction
from dataclasses import dataclass
from enum import Enum



@dataclass
class RexPrefix:
    
    w: bool = False  
    r: bool = False  
    x: bool = False  
    b: bool = False  

@dataclass
class Prefixes:
    
    rex: RexPrefix | None = None
    operand_size_override: bool = False  
    address_size_override: bool = False  
    lock: bool = False                   
    rep: bool = False                    
    repne: bool = False                  
    segment_override: int | None = None  
    size: int = 0                        

class OpSize(Enum):
    BYTE = 1
    WORD = 2
    DWORD = 4
    QWORD = 8

@dataclass
class ModRM:
    
    mod: int          
    reg: int          
    rm: int           
    reg_str: str      
    rm_str: str       
    size: int         



REGS_64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
REGS_32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
REGS_16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]
REGS_8_LEGACY = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]
REGS_8_REX = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
SEG_PREFIX_MAP = {
    0x26: "es",
    0x2E: "cs",
    0x36: "ss",
    0x3E: "ds",
    0x64: "fs",
    0x65: "gs",
}

def _get_reg(index: int, size: OpSize, rex_ext: bool = False, rex_present: bool = False) -> str:
    
    idx = index + (8 if rex_ext else 0)
    if size == OpSize.QWORD: return REGS_64[idx]
    if size == OpSize.DWORD: return REGS_32[idx]
    if size == OpSize.WORD: return REGS_16[idx]
    if size == OpSize.BYTE:
        if rex_present:
            return REGS_8_REX[idx]
        else:
            if idx > 7: raise ValueError("Invalid 8-bit register index without REX")
            return REGS_8_LEGACY[idx]
    raise ValueError(f"Unsupported register size: {size}")



def _parse_modrm(bytecode: bytes, prefixes: Prefixes, op_size: OpSize, modrm_address: int) -> ModRM | None:
   
    if not bytecode: return None

    rex = prefixes.rex if prefixes.rex else RexPrefix()
    rex_present = prefixes.rex is not None

    modrm_byte = bytecode[0]
    mod = (modrm_byte >> 6) & 0x03
    reg_index = (modrm_byte >> 3) & 0x07
    rm_index = modrm_byte & 0x07
    
    reg_str = _get_reg(reg_index, op_size, rex.r, rex_present)
    
    current_offset = 1
    rm_str = ""
    
    
    if mod == 3:
        rm_str = _get_reg(rm_index, op_size, rex.b, rex_present)
        return ModRM(mod, reg_index, rm_index, reg_str, rm_str, 1)

    
    ptr_size_map = {
        OpSize.QWORD: "qword", OpSize.DWORD: "dword",
        OpSize.WORD: "word", OpSize.BYTE: "byte"
    }
    ptr_size = ptr_size_map.get(op_size, "ptr")
    
    seg_prefix = ""
    if prefixes.segment_override:
        seg_name = SEG_PREFIX_MAP.get(prefixes.segment_override)
        if seg_name: seg_prefix = f"{seg_name}:"

    
    if rm_index == 4:
        if len(bytecode) < 2: return None
        sib_byte = bytecode[current_offset]
        current_offset += 1
        
        scale = (sib_byte >> 6) & 0x03
        index_reg_idx = (sib_byte >> 3) & 0x07
        base_reg_idx = sib_byte & 0x07

        address_parts = []
        
        if mod == 0 and base_reg_idx == 5:
            
            if len(bytecode) < current_offset + 4: return None
            disp32 = struct.unpack('<i', bytecode[current_offset:current_offset+4])[0]
            current_offset += 4
            address_parts.append(f"0x{disp32:x}")
        else:
            base_reg = _get_reg(base_reg_idx, OpSize.QWORD, rex.b, rex_present)
            address_parts.append(base_reg)

        
        if index_reg_idx != 4: 
            index_reg = _get_reg(index_reg_idx, OpSize.QWORD, rex.x, rex_present)
            scale_val = 1 << scale
            if scale_val > 1:
                address_parts.append(f"{index_reg}*{scale_val}")
            else:
                address_parts.append(index_reg)
        
        rm_str = f"{ptr_size} ptr [{seg_prefix}{' + '.join(address_parts)}]"
    
    else:
        if mod == 0 and rm_index == 5:
            if len(bytecode) < current_offset + 4: return None
            disp = struct.unpack('<i', bytecode[current_offset:current_offset+4])[0]
            current_offset += 4
            
            next_instr_addr = modrm_address + current_offset
            target_addr = next_instr_addr + disp
            rm_str = f"{ptr_size} ptr [{seg_prefix}0x{target_addr:x}]" 
        else:
            rm_reg = _get_reg(rm_index, OpSize.QWORD, rex.b, rex_present)
            rm_str = f"{ptr_size} ptr [{seg_prefix}{rm_reg}]"

    
    if mod == 1: 
        if len(bytecode) < current_offset + 1: return None
        disp = struct.unpack('<b', bytecode[current_offset:current_offset+1])[0]
        current_offset += 1
        op = "+" if disp >= 0 else "-"
        rm_str = f"{rm_str[:-1]} {op} 0x{abs(disp):x}]"
    elif mod == 2: 
        if len(bytecode) < current_offset + 4: return None
        disp = struct.unpack('<i', bytecode[current_offset:current_offset+4])[0]
        current_offset += 4
        op = "+" if disp >= 0 else "-"
        rm_str = f"{rm_str[:-1]} {op} 0x{abs(disp):x}]"

    return ModRM(mod, reg_index, rm_index, reg_str, rm_str, current_offset)


def _get_op_size(prefixes: Prefixes, default_size: OpSize = OpSize.DWORD) -> OpSize:
    
    if prefixes.rex and prefixes.rex.w:
        return OpSize.QWORD
    if prefixes.operand_size_override:
        return OpSize.WORD
    return default_size

def parse_nop(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction:
    
    return Instruction(address, 1, "nop", "", bytecode[0:1])

def parse_ret(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction:
    
    return Instruction(address, 1, "ret", "", bytecode[0:1])

def parse_int3(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction:
    
    return Instruction(address, 1, "int", "3", bytecode[0:1])

def parse_int1(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction:
    return Instruction(address, 1, "icebp", "", bytecode[0:1])

def parse_jmp_rel32(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    
    if len(bytecode) < 5: return None
    rel_offset = struct.unpack('<i', bytecode[1:5])[0]
    target_addr = address + 5 + rel_offset
    operands = f"0x{target_addr:x}"
    return Instruction(address, 5, "jmp", operands, bytecode[0:5])

def parse_call_rel32(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    
    if len(bytecode) < 5: return None
    rel_offset = struct.unpack('<i', bytecode[1:5])[0]
    target_addr = address + 5 + rel_offset
    operands = f"0x{target_addr:x}"
    return Instruction(address, 5, "call", operands, bytecode[0:5])

def parse_push_r64(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction:
    """Разбирает инструкцию PUSH r64 (0x50-0x57)."""
    reg_index = bytecode[0] & 0x07
    rex = prefixes.rex if prefixes.rex else RexPrefix()
    reg_name = _get_reg(reg_index, OpSize.QWORD, rex.b, prefixes.rex is not None)
    return Instruction(address, 1, "push", reg_name, bytecode[0:1])

def parse_pop_r64(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction:
    """Разбирает инструкцию POP r64 (0x58-0x5F)."""
    reg_index = bytecode[0] & 0x07
    rex = prefixes.rex if prefixes.rex else RexPrefix()
    reg_name = _get_reg(reg_index, OpSize.QWORD, rex.b, prefixes.rex is not None)
    return Instruction(address, 1, "pop", reg_name, bytecode[0:1])

def parse_mov_r_imm(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает инструкцию MOV r, imm (0xb8+r)."""
    reg_index = bytecode[0] & 0x07
    rex = prefixes.rex if prefixes.rex else RexPrefix()
    op_size = _get_op_size(prefixes)
    reg_name = _get_reg(reg_index, op_size, rex.b, prefixes.rex is not None)

    if op_size == OpSize.QWORD:
        imm_size, unpack_fmt = 8, '<q'
    elif op_size == OpSize.WORD:
        imm_size, unpack_fmt = 2, '<h'
    else:
        
        imm_size, unpack_fmt = 4, '<i'

    size = 1 + imm_size
    if len(bytecode) < size: return None

    imm_val = struct.unpack(unpack_fmt, bytecode[1:size])[0]

    operands = f"{reg_name}, 0x{imm_val:x}" if imm_val >= 0 else f"{reg_name}, -0x{abs(imm_val):x}"
    return Instruction(address, size, "mov", operands, bytecode[0:size])

def parse_push_imm32(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    
    if len(bytecode) < 5: return None
    imm_val = struct.unpack('<i', bytecode[1:5])[0]
    operands = f"0x{imm_val:x}" if imm_val >= 0 else f"-0x{-imm_val:x}"
    return Instruction(address, 5, "push", operands, bytecode[0:5])

def parse_push_imm8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает инструкцию PUSH imm8 (0x6a)."""
    if len(bytecode) < 2: return None
    imm_val = struct.unpack('<b', bytecode[1:2])[0]
    operands = f"0x{imm_val:x}" if imm_val >= 0 else f"-0x{-imm_val:x}"
    return Instruction(address, 2, "push", operands, bytecode[0:2])

def parse_jmp_rel8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает инструкцию JMP rel8 (0xeb cb)."""
    if len(bytecode) < 2: return None
    rel_offset = struct.unpack('<b', bytecode[1:2])[0]
    target_addr = address + 2 + rel_offset
    operands = f"0x{target_addr:x}"
    return Instruction(address, 2, "jmp", operands, bytecode[0:2])



def _create_modrm_instruction(bytecode: bytes, address: int, prefixes: Prefixes, mnemonic: str, op_order: tuple, op_size: OpSize, imm_size: int = 0) -> Instruction | None:
    """Обобщенная функция для создания инструкций с ModR/M."""
    modrm_offset = 1 
    modrm = _parse_modrm(bytecode[modrm_offset:], prefixes, op_size, address + modrm_offset)
    if not modrm: return None

    total_size = modrm_offset + modrm.size
    operands = {"reg": modrm.reg_str, "rm": modrm.rm_str}

    if imm_size > 0:
        if len(bytecode) < total_size + imm_size: return None
        imm_bytes = bytecode[total_size : total_size + imm_size]
        if imm_size == 4:
            imm_val = struct.unpack('<i', imm_bytes)[0]
        elif imm_size == 1:
            imm_val = struct.unpack('<b', imm_bytes)[0]
        
        operands["imm"] = f"0x{imm_val:x}" if imm_val >= 0 else f"-0x{abs(imm_val):x}"
        total_size += imm_size

    op_str = ", ".join(operands[o] for o in op_order)
    return Instruction(address, total_size, mnemonic, op_str, bytecode[:total_size])

def parse_add_rm_r(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает ADD r/m, r (0x01)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "add", ("rm", "reg"), op_size)

def parse_add_r_rm(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает ADD r, r/m (0x03)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "add", ("reg", "rm"), op_size)

def parse_sub_rm_r(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает SUB r/m, r (0x29)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "sub", ("rm", "reg"), op_size)

def parse_sub_r_rm(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает SUB r, r/m (0x2B)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "sub", ("reg", "rm"), op_size)

def parse_xor_rm_r(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает XOR r/m, r (0x31)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "xor", ("rm", "reg"), op_size)

def parse_xor_r_rm(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает XOR r, r/m (0x33)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "xor", ("reg", "rm"), op_size)

def parse_cmp_rm_r(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает CMP r/m, r (0x39)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "cmp", ("rm", "reg"), op_size)

def parse_cmp_r_rm(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает CMP r, r/m (0x3B)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "cmp", ("reg", "rm"), op_size)

def parse_mov_rm8_r8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает MOV r/m8, r8 (0x88)."""
    return _create_modrm_instruction(bytecode, address, prefixes, "mov", ("rm", "reg"), OpSize.BYTE)

def parse_mov_rm_r(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает MOV r/m, r (0x89)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "mov", ("rm", "reg"), op_size)

def parse_mov_r8_rm8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает MOV r8, r/m8 (0x8A)."""
    return _create_modrm_instruction(bytecode, address, prefixes, "mov", ("reg", "rm"), OpSize.BYTE)

def parse_mov_r_rm(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает MOV r, r/m (0x8b)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "mov", ("reg", "rm"), op_size)

def parse_lea_r_m(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает LEA r, m (0x8d)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "lea", ("reg", "rm"), op_size)

def parse_test_rm_r(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает TEST r/m, r (0x85)."""
    op_size = _get_op_size(prefixes)
    return _create_modrm_instruction(bytecode, address, prefixes, "test", ("rm", "reg"), op_size)

def parse_group1_rm_imm32(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает группу 1 (ADD, OR, ..., CMP) r/m, imm32 (0x81)."""
    op_size = _get_op_size(prefixes)
    modrm = _parse_modrm(bytecode[1:], prefixes, op_size, address + 1)
    if not modrm: return None
    
    mnemonics = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
    mnemonic = mnemonics[modrm.reg]

    imm_size = 4
    total_size = 1 + modrm.size + imm_size
    if len(bytecode) < total_size: return None

    imm_val = struct.unpack('<i', bytecode[1 + modrm.size : total_size])[0]
    imm_str = f"0x{imm_val:x}" if imm_val >= 0 else f"-0x{abs(imm_val):x}"
    
    operands = f"{modrm.rm_str}, {imm_str}"
    return Instruction(address, total_size, mnemonic, operands, bytecode[:total_size])

def parse_group1_rm_imm8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает группу 1 (ADD, OR, ..., CMP) r/m, imm8 (0x83)."""
    op_size = _get_op_size(prefixes)
    modrm = _parse_modrm(bytecode[1:], prefixes, op_size, address + 1)
    if not modrm: return None
    
    mnemonics = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
    mnemonic = mnemonics[modrm.reg]

    imm_size = 1
    total_size = 1 + modrm.size + imm_size
    if len(bytecode) < total_size: return None

    imm_val = struct.unpack('<b', bytecode[1 + modrm.size : total_size])[0]
    imm_str = f"0x{imm_val:x}" if imm_val >= 0 else f"-0x{abs(imm_val):x}"
    
    operands = f"{modrm.rm_str}, {imm_str}"
    return Instruction(address, total_size, mnemonic, operands, bytecode[:total_size])

def parse_mov_rm8_imm8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает MOV r/m8, imm8 (0xC6)."""
    op_size = OpSize.BYTE
    modrm = _parse_modrm(bytecode[1:], prefixes, op_size, address + 1)
    if not modrm: return None

    if modrm.reg != 0: return None 

    imm_size = 1
    total_size = 1 + modrm.size + imm_size
    if len(bytecode) < total_size: return None

    imm_val = struct.unpack('<B', bytecode[1 + modrm.size : total_size])[0]
    operands = f"{modrm.rm_str}, 0x{imm_val:x}"
    return Instruction(address, total_size, "mov", operands, bytecode[:total_size])

def parse_mov_rm_imm(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает MOV r/m, imm32 (0xC7)."""
    op_size = _get_op_size(prefixes)
    modrm = _parse_modrm(bytecode[1:], prefixes, op_size, address + 1)
    if not modrm: return None

    
    if modrm.reg != 0: return None
    
    
    
    
    imm_size = 2 if op_size == OpSize.WORD else 4
    total_size = 1 + modrm.size + imm_size
    if len(bytecode) < total_size: return None

    imm_bytes = bytecode[1 + modrm.size : total_size]
    if imm_size == 4:
        imm_val = struct.unpack('<i', imm_bytes)[0]
    else:
        imm_val = struct.unpack('<h', imm_bytes)[0]
    
    imm_str = f"0x{imm_val:x}" if imm_val >= 0 else f"-0x{abs(imm_val):x}"
    operands = f"{modrm.rm_str}, {imm_str}"
    return Instruction(address, total_size, "mov", operands, bytecode[:total_size])

def parse_pop_rm(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает POP r/m (8F /0)."""
    op_size = _get_op_size(prefixes, default_size=OpSize.QWORD)
    modrm = _parse_modrm(bytecode[1:], prefixes, op_size, address + 1)
    if not modrm: return None
    
    if modrm.reg != 0: return None 

    total_size = 1 + modrm.size
    return Instruction(address, total_size, "pop", modrm.rm_str, bytecode[:total_size])

def parse_group_ff(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает группу FF (INC, DEC, CALL, JMP, PUSH)."""
    op_size = _get_op_size(prefixes)
    modrm = _parse_modrm(bytecode[1:], prefixes, op_size, address + 1)
    if not modrm: return None
    
    op_type = modrm.reg
    mnemonics = {
        0: "inc",
        1: "dec",
        2: "call",
        
        4: "jmp",
        
        6: "push",
    }
    mnemonic = mnemonics.get(op_type)
    if not mnemonic: return None
    total_size = 1 + modrm.size
    return Instruction(address, total_size, mnemonic, modrm.rm_str, bytecode[:total_size])

def parse_group_f7(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает группу F7 (TEST, NOT, NEG, MUL, IMUL, DIV, IDIV)."""
    op_size = _get_op_size(prefixes)
    modrm = _parse_modrm(bytecode[1:], prefixes, op_size, address + 1)
    if not modrm: return None

    op_type = modrm.reg
    mnemonics = {
        0: "test", 
        2: "not",
        3: "neg",
        4: "mul",
        5: "imul",
        6: "div",
        7: "idiv",
    }
    mnemonic = mnemonics.get(op_type)
    if not mnemonic: return None

    
    if op_type == 0:
        
        
        
        imm_size = 2 if op_size == OpSize.WORD else 4
        total_size = 1 + modrm.size + imm_size
        if len(bytecode) < total_size: return None
        
        imm_bytes = bytecode[1 + modrm.size : total_size]
        if imm_size == 4:
            imm_val = struct.unpack('<i', imm_bytes)[0]
        else:
            imm_val = struct.unpack('<h', imm_bytes)[0]
        
        imm_str = f"0x{imm_val:x}" if imm_val >= 0 else f"-0x{abs(imm_val):x}"
        operands = f"{modrm.rm_str}, {imm_str}"
        return Instruction(address, total_size, mnemonic, operands, bytecode[:total_size])
    else:
        total_size = 1 + modrm.size
        return Instruction(address, total_size, mnemonic, modrm.rm_str, bytecode[:total_size])

def parse_group2(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает группу 2 (ROL, ROR, SHL, SHR, SAR, ...) (D0-D3)."""
    opcode = bytecode[0]
    op_size = OpSize.BYTE if opcode in (0xD0, 0xD2) else _get_op_size(prefixes)
    shift_by_cl = opcode in (0xD2, 0xD3)
    
    modrm = _parse_modrm(bytecode[1:], prefixes, op_size, address + 1)
    if not modrm: return None

    mnemonics = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"]
    mnemonic = mnemonics[modrm.reg]
    operands = f"{modrm.rm_str}, {'cl' if shift_by_cl else '1'}"
    total_size = 1 + modrm.size
    return Instruction(address, total_size, mnemonic, operands, bytecode[:total_size])

def parse_arith_rm8_r8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает арифметические/логические инструкции r/m8, r8."""
    mnemonics = {
        0x00: "add", 0x08: "or", 0x10: "adc", 0x18: "sbb",
        0x20: "and", 0x28: "sub", 0x30: "xor", 0x38: "cmp",
    }
    mnemonic = mnemonics.get(bytecode[0])
    if not mnemonic: return None
    return _create_modrm_instruction(bytecode, address, prefixes, mnemonic, ("rm", "reg"), OpSize.BYTE)

def parse_arith_r8_rm8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает арифметические/логические инструкции r8, r/m8."""
    mnemonics = {
        0x02: "add", 0x0A: "or", 0x12: "adc", 0x1A: "sbb",
        0x22: "and", 0x2A: "sub", 0x32: "xor", 0x3A: "cmp",
    }
    mnemonic = mnemonics.get(bytecode[0])
    if not mnemonic: return None
    return _create_modrm_instruction(bytecode, address, prefixes, mnemonic, ("reg", "rm"), OpSize.BYTE)

def parse_arith_al_imm8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает арифметические/логические инструкции AL, imm8."""
    if len(bytecode) < 2: return None
    mnemonics = {
        0x04: "add", 0x0C: "or", 0x14: "adc", 0x1C: "sbb",
        0x24: "and", 0x2C: "sub", 0x34: "xor", 0x3C: "cmp",
    }
    mnemonic = mnemonics.get(bytecode[0])
    if not mnemonic: return None
    imm_val = struct.unpack('<B', bytecode[1:2])[0]
    operands = f"al, 0x{imm_val:x}"
    return Instruction(address, 2, mnemonic, operands, bytecode[0:2])

def parse_arith_ax_imm(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает арифметические/логические инструкции rAX, imm."""
    mnemonics = {0x05: "add", 0x0D: "or", 0x15: "adc", 0x1D: "sbb", 0x25: "and", 0x2D: "sub", 0x35: "xor", 0x3D: "cmp"}
    mnemonic = mnemonics.get(bytecode[0])
    if not mnemonic: return None
    op_size = _get_op_size(prefixes)
    reg_name = _get_reg(0, op_size)
    imm_size, unpack_fmt = (2, '<h') if op_size == OpSize.WORD else (4, '<i')
    size = 1 + imm_size
    if len(bytecode) < size: return None
    imm_val = struct.unpack(unpack_fmt, bytecode[1:size])[0]
    imm_str = f"0x{imm_val:x}" if imm_val >= 0 else f"-0x{abs(imm_val):x}"
    operands = f"{reg_name}, {imm_str}"
    return Instruction(address, size, mnemonic, operands, bytecode[0:size])



JCC_REL8_MNEMONICS = {
    0x70: "jo", 0x71: "jno", 0x72: "jb", 0x73: "jae",
    0x74: "je", 0x75: "jne", 0x76: "jbe", 0x77: "ja",
    0x78: "js", 0x79: "jns", 0x7a: "jp", 0x7b: "jnp",
    0x7c: "jl", 0x7d: "jge", 0x7e: "jle", 0x7f: "jg",
}

def parse_jcc_rel8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает условные переходы Jcc rel8 (0x70-0x7F)."""
    if len(bytecode) < 2: return None
    opcode = bytecode[0]
    mnemonic = JCC_REL8_MNEMONICS.get(opcode)
    if not mnemonic: return None 

    rel_offset = struct.unpack('<b', bytecode[1:2])[0]
    target_addr = address + 2 + rel_offset
    operands = f"0x{target_addr:x}"
    return Instruction(address, 2, mnemonic, operands, bytecode[0:2])



JCC_REL32_MNEMONICS = {
    0x80: "jo", 0x81: "jno", 0x82: "jb", 0x83: "jae",
    0x84: "je", 0x85: "jne", 0x86: "jbe", 0x87: "ja",
    0x88: "js", 0x89: "jns", 0x8a: "jp", 0x8b: "jnp",
    0x8c: "jl", 0x8d: "jge", 0x8e: "jle", 0x8f: "jg",
}

def parse_jcc_rel32(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает условные переходы Jcc rel32 (0x0F 8x)."""
    
    if len(bytecode) < 6: return None 
    opcode = bytecode[1]
    mnemonic = JCC_REL32_MNEMONICS.get(opcode)
    if not mnemonic: return None

    rel_offset = struct.unpack('<i', bytecode[2:6])[0]
    target_addr = address + 6 + rel_offset
    operands = f"0x{target_addr:x}"
    return Instruction(address, 6, mnemonic, operands, bytecode[0:6])

def parse_imul_r_rm(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает IMUL r, r/m (0x0F 0xAF)."""
    op_size = _get_op_size(prefixes)
    
    modrm = _parse_modrm(bytecode[2:], prefixes, op_size, address + 2)
    if not modrm: return None

    total_size = 2 + modrm.size  
    operands = f"{modrm.reg_str}, {modrm.rm_str}"
    return Instruction(address, total_size, "imul", operands, bytecode[:total_size])

def _parse_mov_ext(bytecode: bytes, address: int, prefixes: Prefixes, mnemonic: str, src_op_size: OpSize) -> Instruction | None:
    """Обобщенный парсер для MOVZX и MOVSX."""
    
    dest_op_size = _get_op_size(prefixes)
    
    
    modrm = _parse_modrm(bytecode[2:], prefixes, src_op_size, address + 2)
    if not modrm: return None

    
    rex = prefixes.rex if prefixes.rex else RexPrefix()
    dest_reg_str = _get_reg(modrm.reg, dest_op_size, rex.r, prefixes.rex is not None)

    total_size = 2 + modrm.size 
    operands = f"{dest_reg_str}, {modrm.rm_str}"
    return Instruction(address, total_size, mnemonic, operands, bytecode[:total_size])

def parse_movzx_r_rm8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает MOVZX r, r/m8 (0x0F 0xB6)."""
    return _parse_mov_ext(bytecode, address, prefixes, "movzx", OpSize.BYTE)

def parse_movzx_r_rm16(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает MOVZX r, r/m16 (0x0F 0xB7)."""
    return _parse_mov_ext(bytecode, address, prefixes, "movzx", OpSize.WORD)

def parse_movsx_r_rm8(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает MOVSX r, r/m8 (0x0F 0xBE)."""
    return _parse_mov_ext(bytecode, address, prefixes, "movsx", OpSize.BYTE)

def parse_movsx_r_rm16(bytecode: bytes, address: int, prefixes: Prefixes) -> Instruction | None:
    """Разбирает MOVSX r, r/m16 (0x0F 0xBF)."""
    return _parse_mov_ext(bytecode, address, prefixes, "movsx", OpSize.WORD)



SINGLE_BYTE_OPCODES = {
    
    **{op: parse_arith_rm8_r8 for op in [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38]},
    0x01: parse_add_rm_r,
    **{op: parse_arith_r8_rm8 for op in [0x02, 0x0A, 0x12, 0x1A, 0x22, 0x2A, 0x32, 0x3A]},
    0x03: parse_add_r_rm,
    **{op: parse_arith_al_imm8 for op in [0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34, 0x3C]},
    **{op: parse_arith_ax_imm for op in [0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D]},
    0x29: parse_sub_rm_r,
    0x2B: parse_sub_r_rm,
    0x31: parse_xor_rm_r,
    0x33: parse_xor_r_rm,
    0x39: parse_cmp_rm_r,
    0x3B: parse_cmp_r_rm,
    
    **{op: parse_push_r64 for op in range(0x50, 0x58)},
    **{op: parse_pop_r64 for op in range(0x58, 0x60)},
    0x68: parse_push_imm32,
    0x6A: parse_push_imm8,
    
    **{op: parse_jcc_rel8 for op in range(0x70, 0x80)},
    
    0x90: parse_nop,
    0xC3: parse_ret,
    0xCC: parse_int3,
    0xF1: parse_int1,
    0xE8: parse_call_rel32,
    0xE9: parse_jmp_rel32,
    0xEB: parse_jmp_rel8,
    
    0x81: parse_group1_rm_imm32,
    0x83: parse_group1_rm_imm8,
    0x85: parse_test_rm_r,
    0x88: parse_mov_rm8_r8,
    0x89: parse_mov_rm_r,
    0x8A: parse_mov_r8_rm8,
    0x8B: parse_mov_r_rm,
    0x8D: parse_lea_r_m,
    0x8F: parse_pop_rm,
    0xC6: parse_mov_rm8_imm8,
    0xC7: parse_mov_rm_imm,
    **{op: parse_group2 for op in range(0xD0, 0xD4)},
    0xF7: parse_group_f7,
    0xFF: parse_group_ff,
}


OPCODES_B8_BF = {op: parse_mov_r_imm for op in range(0xB8, 0xC0)}


TWO_BYTE_OPCODE_MAP = {
    
    **{op: parse_jcc_rel32 for op in range(0x80, 0x90)},
    
    0xAF: parse_imul_r_rm,
    0xB6: parse_movzx_r_rm8,
    0xB7: parse_movzx_r_rm16,
    0xBE: parse_movsx_r_rm8,
    0xBF: parse_movsx_r_rm16,
}


OPCODE_MAP = {
    **SINGLE_BYTE_OPCODES,
    **OPCODES_B8_BF
}