import dataclasses
import struct
from typing import List, Optional, TYPE_CHECKING
import re

from .instruction import Instruction

if TYPE_CHECKING:
    import pefile

try:
    import pefile
except ImportError:
    pefile = None

@dataclasses.dataclass
class FoundVariable:
    """Представляет переменную (например, строку или константу), найденную в секциях данных."""
    address: int
    type: str  
    value: str 
    xrefs: List[int] = dataclasses.field(default_factory=list)

def _is_printable_ascii(data: bytes) -> bool:
    """Проверяет, является ли последовательность байтов вероятной ASCII-строкой для печати."""
    if not data or len(data) < 4:
        return False
    
    printable_chars = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    alpha_chars = sum(1 for b in data if ord('a') <= b <= ord('z') or ord('A') <= b <= ord('Z'))
    
    
    return (printable_chars / len(data)) > 0.8 and alpha_chars > 0

def _is_plausible_utf16_le(data: bytes) -> bool:
    """
    Проверяет, является ли последовательность байтов вероятной строкой UTF-16 LE.
    Проверяет, что каждый второй байт - ноль, а остальные - печатаемые ASCII.
    """
    if not data:
        return False

    # For very short strings, this check is unreliable.
    if len(data) < 4:
        # Check if all chars are valid UTF-16LE printable ASCII
        try:
            decoded = data.decode('utf-16-le')
            return all(32 <= ord(c) < 127 or c in '\t\n\r' for c in decoded)
        except UnicodeDecodeError:
            return False

    # For longer strings, the null-byte pattern is more reliable.
    if len(data) < 2 or len(data) % 2 != 0:
        return False
    
    
    for i in range(1, len(data), 2):
        if data[i] != 0x00:
            return False
            
    
    char_bytes = data[0::2]
    return _is_printable_ascii(char_bytes)

def _get_variable_at_address(pe: "pefile.PE", addr: int, rva: int) -> Optional[FoundVariable]:
    """
    Анализирует данные по указанному адресу и пытается определить тип переменной.
    Возвращает объект FoundVariable или None.
    """
    try:
        data = pe.get_data(rva, 128) 
    except Exception:
        return None

    # Check for null-terminated ASCII string
    null_pos = data.find(b'\x00')
    if 3 < null_pos < 128:
        str_data = data[:null_pos]
        if _is_printable_ascii(str_data):
            value_repr = str_data.decode('ascii', errors='ignore')
            return FoundVariable(address=addr, type="string", value=f'"{value_repr}"')

    # Check for null-terminated UTF-16 string
    null_pos_w = data.find(b'\x00\x00')
    if 3 < null_pos_w < 127 and null_pos_w % 2 == 0:
        str_data_w = data[:null_pos_w]
        if _is_plausible_utf16_le(str_data_w):
            try:
                value_repr = str_data_w.decode('utf-16-le', errors='ignore')
                return FoundVariable(address=addr, type="wstring", value=f'L"{value_repr}"')
            except UnicodeDecodeError:
                pass

    # Check for Pascal-style ShortString (length-prefixed)
    if len(data) > 1:
        length = data[0]
        if 3 < length < 128 and len(data) > length:
            str_data = data[1 : 1 + length]
            # Check if the character after the string is a null-terminator or something non-printable
            # to reduce false positives.
            if (len(data) == 1 + length or data[1 + length] < 32) and _is_printable_ascii(str_data):
                 value_repr = str_data.decode('ascii', errors='ignore')
                 return FoundVariable(address=addr, type="pstring", value=f'#"{value_repr}"')

    # Check for GUID
    if len(data) >= 16:
        try:
            d1, d2, d3, d4_0, d4_1, d4_2, d4_3, d4_4, d4_5, d4_6, d4_7 = struct.unpack('<LHHBBBBBBBB', data[:16])
            # A simple heuristic to avoid matching random data. Real GUIDs rarely start with all zeros.
            if d1 != 0 or d2 != 0 or d3 != 0:
                guid_str = f"{{{d1:08X}-{d2:04X}-{d3:04X}-{d4_0:02X}{d4_1:02X}-{d4_2:02X}{d4_3:02X}{d4_4:02X}{d4_5:02X}{d4_6:02X}{d4_7:02X}}}"
                return FoundVariable(address=addr, type="guid", value=guid_str)
        except struct.error:
            pass

    # Check for floating point numbers
    try:
        if len(data) >= 8:
            double_val = struct.unpack('<d', data[:8])[0]
            if 1e-9 < abs(double_val) < 1e9 and not str(double_val).startswith('nan'):
                return FoundVariable(address=addr, type="double", value=f"{double_val}")
        
        if len(data) >= 4:
            float_val = struct.unpack('<f', data[:4])[0]
            if 1e-9 < abs(float_val) < 1e9 and not str(float_val).startswith('nan'):
                return FoundVariable(address=addr, type="float", value=f"{float_val:.4f}")
    except (struct.error, IndexError):
        pass

    # Fallback to integer types
    is_64bit = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']
    unpack_fmt, type_str, size = ('<Q', 'qword', 8) if is_64bit else ('<I', 'dword', 4)
    if len(data) >= size:
        val = struct.unpack(unpack_fmt, data[:size])[0]
        return FoundVariable(address=addr, type=type_str, value=f"0x{val:x}")
    
    return None

def _scan_data_sections(pe: "pefile.PE", existing_vars: dict) -> List[FoundVariable]:
    """
    Сканирует секции данных в поисках ненайденных переменных, таких как строки,
    массивы указателей и т.д.
    """
    found_vars = []
    locally_found_addrs = set()
    image_base = pe.OPTIONAL_HEADER.ImageBase
    is_64bit = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']
    ptr_size, unpack_fmt = (8, '<Q') if is_64bit else (4, '<I')

    text_section = next((s for s in pe.sections if s.Name.startswith(b'.text')), None)
    code_rva_range = (-1, -1)
    if text_section:
        code_rva_range = (text_section.VirtualAddress, text_section.VirtualAddress + text_section.Misc_VirtualSize)

    data_sections = [s for s in pe.sections if s.Name.startswith((b'.rdata', b'.data'))]

    # Pattern for null-terminated ASCII strings
    ascii_pattern = re.compile(b'([ -~\\t\\n\\r]{4,256})\x00')
    # Pattern for Pascal-style ShortStrings
    pascal_pattern = re.compile(b'([\x04-\xff])([ -~\\t\\n\\r]+)')

    for section in data_sections:
        data = section.get_data()
        section_base_addr = image_base + section.VirtualAddress

        # Scan for ASCII strings
        for match in ascii_pattern.finditer(data):
            addr = image_base + section.VirtualAddress + match.start()
            if addr in existing_vars or addr in locally_found_addrs:
                continue 

            str_data = match.group(1)
            if _is_printable_ascii(str_data):
                value_repr = str_data.decode('ascii', errors='ignore')
                found_vars.append(FoundVariable(address=addr, type="string", value=f'"{value_repr}"'))
                locally_found_addrs.add(addr)

        # Scan for Pascal strings
        for match in pascal_pattern.finditer(data):
            addr = section_base_addr + match.start()
            if addr in existing_vars or addr in locally_found_addrs:
                continue

            length = match.group(1)[0]
            str_data = match.group(2)
            if len(str_data) >= length and _is_printable_ascii(str_data[:length]):
                value_repr = str_data[:length].decode('ascii', errors='ignore')
                found_vars.append(FoundVariable(address=addr, type="pstring", value=f'#"{value_repr}"'))
                locally_found_addrs.add(addr)

        # Scan for pointer arrays (vtables, etc.)
        if text_section:
            for i in range(0, len(data) - ptr_size + 1, ptr_size):
                addr = section_base_addr + i
                if addr in existing_vars or addr in locally_found_addrs:
                    continue

                try:
                    ptr_val = struct.unpack_from(unpack_fmt, data, i)[0]
                    ptr_rva = ptr_val - image_base
                except struct.error:
                    continue

                if code_rva_range[0] <= ptr_rva < code_rva_range[1]:
                    # Found a pointer to the code section, check for more
                    count = 1
                    for j in range(i + ptr_size, len(data) - ptr_size + 1, ptr_size):
                        try:
                            next_ptr_val = struct.unpack_from(unpack_fmt, data, j)[0]
                        except struct.error:
                            break
                        if not (code_rva_range[0] <= (next_ptr_val - image_base) < code_rva_range[1]):
                            break
                        count += 1
                    
                    if count >= 3: # Heuristic: at least 3 consecutive pointers to code
                        found_vars.append(FoundVariable(address=addr, type="ptr_array", value=f"Array of {count} pointers to code"))
                        # Mark all pointers in the array as "found"
                        for k in range(count):
                            locally_found_addrs.add(addr + k * ptr_size)
    
    return found_vars

def find_variables(instructions: List[Instruction], pe: "pefile.PE") -> List[FoundVariable]:
    """
    Анализирует инструкции и секции данных для поиска потенциальных переменных.
    Это эвристический подход.
    """
    if not pe or not pefile:
        return []

    variables: Dict[int, FoundVariable] = {}
    image_base = pe.OPTIONAL_HEADER.ImageBase

    data_sections = [s for s in pe.sections if s.Name.startswith((b'.rdata', b'.data'))]
    if not data_sections:
        return []
    
    data_rva_ranges = [(s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize) for s in data_sections]

    def is_rva_in_data_sections(rva: int) -> bool:
        return any(start_rva <= rva < end_rva for start_rva, end_rva in data_rva_ranges)

    def add_variable_xref(addr: int, xref_addr: int):
        if addr in variables:
            if xref_addr not in variables[addr].xrefs:
                variables[addr].xrefs.append(xref_addr)
            return

        rva = addr - image_base
        if not is_rva_in_data_sections(rva):
            return
        
        var = _get_variable_at_address(pe, addr, rva)
        if var:
            var.xrefs.append(xref_addr)
            variables[addr] = var

    # Regex for strong references (memory operands)
    strong_ref_pattern = re.compile(r'\[\s*(?:rip\s*[+-])?\s*(0x[0-9a-fA-F]{5,})\s*\]')
    # Regex for weak references (immediate values that look like addresses)
    weak_ref_pattern = re.compile(r'\b(0x[0-9a-fA-F]{5,})\b')

    for instr in instructions:
        # Stage 1: Prioritize strong references (e.g., lea rax, [0x...])
        strong_matches = strong_ref_pattern.findall(instr.operands)
        if strong_matches:
            for match_str in strong_matches:
                try:
                    addr = int(match_str, 16)
                    add_variable_xref(addr, instr.address)
                except (ValueError, TypeError):
                    continue
            continue # Move to next instruction if we found a strong reference

        # Stage 2: Look for weak references (e.g., mov rax, 0x...)
        # This is less reliable and should only be used for specific instructions
        if instr.mnemonic in ('mov', 'push', 'cmp', 'test'):
            weak_matches = weak_ref_pattern.findall(instr.operands)
            for match_str in weak_matches:
                # Avoid matching the address part of a memory operand again
                if f'[{match_str}]' in instr.operands.replace(" ", ""):
                    continue
                try:
                    addr = int(match_str, 16)
                    add_variable_xref(addr, instr.address)
                except (ValueError, TypeError):
                    continue

    # Stage 3: Scan data sections for unreferenced data (strings, pointers)
    # and then try to find xrefs to them.
    unreferenced_vars = _scan_data_sections(pe, variables)
    for var in unreferenced_vars:
        if var.address not in variables:
            # Now, try to find xrefs for this newly found variable
            addr_hex = f'0x{var.address:x}'
            for instr in instructions:
                if addr_hex in instr.operands:
                    if instr.address not in var.xrefs:
                        var.xrefs.append(instr.address)
            variables[var.address] = var

    return sorted(list(variables.values()), key=lambda v: v.address)