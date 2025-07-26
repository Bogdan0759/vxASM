import struct
from . import x86_opcodes as isa
from .instruction import Instruction
from .x86_opcodes import Prefixes

class Disassembler:
    
    def __init__(self, bytecode: bytes, base_address: int = 0):
        self.bytecode = bytecode
        self.offset = 0
        self.base_address = base_address

    def disassemble(self) -> list[Instruction]:
        
        instructions = []
        while self.offset < len(self.bytecode):
            
            
            instr = self._decode_one()
            instructions.append(instr)
            self.offset += instr.size
        return instructions

    def _decode_one(self) -> Instruction:
        
        address = self.base_address + self.offset

        
        prefixes = self._parse_prefixes()

        code_offset = self.offset + prefixes.size
        if code_offset >= len(self.bytecode):
            
            
            size = len(self.bytecode) - self.offset
            if size == 0:
                
                
                return Instruction(address, 0, "db", "EOF", b'', is_error=True)

            bytes_slice = self.bytecode[self.offset : self.offset + size]
            operands = ', '.join(f'0x{b:02x}' for b in bytes_slice)
            return Instruction(address, size, "db", operands, bytes_slice)

        
        parser = None
        code_to_parse = self.bytecode[code_offset:]
        opcode = code_to_parse[0]

        is_two_byte_opcode = False
        if opcode == 0x0F:
            if len(code_to_parse) > 1:
                is_two_byte_opcode = True
                opcode2 = code_to_parse[1]
                parser = isa.TWO_BYTE_OPCODE_MAP.get(opcode2)
        else:
            parser = isa.OPCODE_MAP.get(opcode)

        if parser:
            
            
            
            
            instr = parser(code_to_parse, address, prefixes)
            if instr:
                
                total_size = prefixes.size + instr.size
                instr.bytes = self.bytecode[self.offset : self.offset + total_size]
                instr.size = total_size
                return instr

        
        
        
        
        num_opcode_bytes = 2 if is_two_byte_opcode else 1
        size = prefixes.size + num_opcode_bytes

        
        size = min(size, len(self.bytecode) - self.offset)

        bytes_slice = self.bytecode[self.offset : self.offset + size]
        operands = ', '.join(f'0x{b:02x}' for b in bytes_slice)
        return Instruction(address, size, "db", operands, bytes_slice)

    def _parse_prefixes(self) -> Prefixes:
        
        p = Prefixes()
        temp_offset = 0

        
        legacy_prefixes_end = False
        while not legacy_prefixes_end and (self.offset + temp_offset) < len(self.bytecode):
            byte = self.bytecode[self.offset + temp_offset]

            is_legacy_prefix = True
            if byte == 0x66:
                p.operand_size_override = True
            elif byte == 0x67:
                p.address_size_override = True
            elif byte == 0xF0:
                p.lock = True
            elif byte == 0xF2:
                p.repne = True
            elif byte == 0xF3:
                p.rep = True
            elif byte in isa.SEG_PREFIX_MAP:
                p.segment_override = byte
            else:
                is_legacy_prefix = False

            if is_legacy_prefix:
                temp_offset += 1
            else:
                legacy_prefixes_end = True

        
        if (self.offset + temp_offset) < len(self.bytecode):
            byte = self.bytecode[self.offset + temp_offset]
            if 0x40 <= byte <= 0x4F:
                p.rex = isa.RexPrefix(
                    w=(byte & 0x08) != 0,
                    r=(byte & 0x04) != 0,
                    x=(byte & 0x02) != 0,
                    b=(byte & 0x01) != 0,
                )
                temp_offset += 1

        p.size = temp_offset
        return p