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
    type: str  # например, "string", "float", "dword"
    value: str # Строковое представление значения
    xrefs: List[int] = dataclasses.field(default_factory=list)

def _is_printable_ascii(data: bytes) -> bool:
    """Проверяет, является ли последовательность байтов вероятной ASCII-строкой для печати."""
    if not data or len(data) < 4:
        return False
    
    printable_chars = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    alpha_chars = sum(1 for b in data if ord('a') <= b <= ord('z') or ord('A') <= b <= ord('Z'))
    
    # Требуем, чтобы большинство символов были печатаемыми и чтобы были буквы
    return (printable_chars / len(data)) > 0.8 and alpha_chars > 0

def _is_plausible_utf16_le(data: bytes) -> bool:
    """
    Проверяет, является ли последовательность байтов вероятной строкой UTF-16 LE.
    Проверяет, что каждый второй байт - ноль, а остальные - печатаемые ASCII.
    """
    if len(data) < 2 or len(data) % 2 != 0:
        return False
    
    # Проверяем, что каждый второй байт - это 0x00
    for i in range(1, len(data), 2):
        if data[i] != 0x00:
            return False
            
    # Проверяем, что "символьные" байты являются печатаемыми
    char_bytes = data[0::2]
    return _is_printable_ascii(char_bytes)

def _get_variable_at_address(pe: "pefile.PE", addr: int, rva: int) -> Optional[FoundVariable]:
    """
    Анализирует данные по указанному адресу и пытается определить тип переменной.
    Возвращает объект FoundVariable или None.
    """
    try:
        data = pe.get_data(rva, 128) # Читаем до 128 байт для анализа
    except Exception:
        return None

    # Эвристика 1: ASCII-строка с нулевым терминатором
    null_pos = data.find(b'\x00')
    if 3 < null_pos < 128:
        str_data = data[:null_pos]
        if _is_printable_ascii(str_data):
            value_repr = str_data.decode('ascii', errors='ignore')
            return FoundVariable(address=addr, type="string", value=f'"{value_repr}"')

    # Эвристика 2: Unicode-строка (UTF-16 LE) с двойным нулевым терминатором
    null_pos_w = data.find(b'\x00\x00')
    if 3 < null_pos_w < 127 and null_pos_w % 2 == 0:
        str_data_w = data[:null_pos_w]
        if _is_plausible_utf16_le(str_data_w):
            try:
                value_repr = str_data_w.decode('utf-16-le', errors='ignore')
                return FoundVariable(address=addr, type="wstring", value=f'L"{value_repr}"')
            except UnicodeDecodeError:
                pass

    # Эвристика 3: GUID (16 байт)
    if len(data) >= 16:
        try:
            # Формат GUID: {DWORD-WORD-WORD-BYTE-BYTE-BYTE-BYTE-BYTE-BYTE-BYTE-BYTE}
            d1, d2, d3, d4_0, d4_1, d4_2, d4_3, d4_4, d4_5, d4_6, d4_7 = struct.unpack('<LHHBBBBBBBB', data[:16])
            # Простая проверка на "разумность" GUID (не нулевой)
            if d1 != 0 or d2 != 0 or d3 != 0:
                guid_str = f"{{{d1:08X}-{d2:04X}-{d3:04X}-{d4_0:02X}{d4_1:02X}-{d4_2:02X}{d4_3:02X}{d4_4:02X}{d4_5:02X}{d4_6:02X}{d4_7:02X}}}"
                return FoundVariable(address=addr, type="guid", value=guid_str)
        except struct.error:
            pass

    # Эвристика 4: Float/Double
    try:
        # Проверяем double
        if len(data) >= 8:
            double_val = struct.unpack('<d', data[:8])[0]
            if 1e-9 < abs(double_val) < 1e9 and not str(double_val).startswith('nan'):
                return FoundVariable(address=addr, type="double", value=f"{double_val}")
        # Проверяем float
        if len(data) >= 4:
            float_val = struct.unpack('<f', data[:4])[0]
            if 1e-9 < abs(float_val) < 1e9 and not str(float_val).startswith('nan'):
                return FoundVariable(address=addr, type="float", value=f"{float_val:.4f}")
    except (struct.error, IndexError):
        pass

    # Эвристика 5: DWORD/QWORD (как запасной вариант)
    is_64bit = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']
    unpack_fmt, type_str, size = ('<Q', 'qword', 8) if is_64bit else ('<I', 'dword', 4)
    if len(data) >= size:
        val = struct.unpack(unpack_fmt, data[:size])[0]
        return FoundVariable(address=addr, type=type_str, value=f"0x{val:x}")
    
    return None

def _find_pointer_arrays(pe: "pefile.PE", existing_vars: dict) -> List[FoundVariable]:
    """Ищет в секциях данных массивы указателей (например, vtables)."""
    found_arrays = []
    image_base = pe.OPTIONAL_HEADER.ImageBase
    is_64bit = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']
    ptr_size, unpack_fmt = (8, '<Q') if is_64bit else (4, '<I')

    text_section = next((s for s in pe.sections if s.Name.startswith(b'.text')), None)
    if not text_section:
        return []
    code_rva_range = (text_section.VirtualAddress, text_section.VirtualAddress + text_section.Misc_VirtualSize)

    data_sections = [s for s in pe.sections if s.Name.startswith((b'.rdata', b'.data'))]
    for section in data_sections:
        data = section.get_data()
        for i in range(0, len(data) - ptr_size + 1, ptr_size):
            addr = image_base + section.VirtualAddress + i
            if addr in existing_vars: continue

            ptr_val = struct.unpack(unpack_fmt, data[i:i+ptr_size])[0]
            ptr_rva = ptr_val - image_base

            if code_rva_range[0] <= ptr_rva < code_rva_range[1]:
                count = 1
                for j in range(i + ptr_size, len(data) - ptr_size + 1, ptr_size):
                    next_ptr_val = struct.unpack(unpack_fmt, data[j:j+ptr_size])[0]
                    if not (code_rva_range[0] <= (next_ptr_val - image_base) < code_rva_range[1]):
                        break
                    count += 1
                
                if count >= 3:
                    found_arrays.append(FoundVariable(address=addr, type="ptr_array", value=f"Array of {count} pointers to code"))
    return found_arrays

def _scan_data_sections_for_strings(pe: "pefile.PE", existing_vars: dict) -> List[FoundVariable]:
    """
    Сканирует секции данных напрямую в поисках ненайденных строк.
    """
    found_strings = []
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data_sections = [s for s in pe.sections if s.Name.startswith((b'.rdata', b'.data'))]

    # Ищем ASCII строки (от 5 до 256 символов)
    string_pattern = re.compile(b'([ -~\\t\\n\\r]{5,256})\x00')

    for section in data_sections:
        data = section.get_data()
        for match in string_pattern.finditer(data):
            addr = image_base + section.VirtualAddress + match.start()
            if addr in existing_vars:
                continue # Уже нашли эту переменную через xref

            str_data = match.group(1)
            if _is_printable_ascii(str_data):
                value_repr = str_data.decode('ascii', errors='ignore')
                found_strings.append(FoundVariable(address=addr, type="string", value=f'"{value_repr}"'))

    return found_strings

def find_variables(instructions: List[Instruction], pe: "pefile.PE") -> List[FoundVariable]:
    """
    Анализирует инструкции и секции данных для поиска потенциальных переменных.
    Это эвристический подход.
    """
    if not pe or not pefile:
        return []

    variables = {}
    image_base = pe.OPTIONAL_HEADER.ImageBase
    hex_pattern = re.compile(r'0x[0-9a-fA-F]+')

    data_sections = [s for s in pe.sections if s.Name.startswith(b'.rdata') or s.Name.startswith(b'.data')]
    if not data_sections:
        return []

    # Создаем карту допустимых диапазонов RVA данных
    data_rva_ranges = [(s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize) for s in data_sections]

    for instr in instructions:
        # Ищем инструкции, которые загружают адрес, например, mov reg, offset data_addr
        matches = hex_pattern.findall(instr.operands)
        for match in matches:
            try:
                addr = int(match, 16)
                rva = addr - image_base

                # Проверяем, указывает ли адрес на секцию данных
                is_in_data = any(start_rva <= rva < end_rva for start_rva, end_rva in data_rva_ranges)
                if not is_in_data:
                    continue

                # Если мы уже нашли эту переменную, просто добавляем перекрестную ссылку
                if addr in variables:
                    if instr.address not in variables[addr].xrefs:
                        variables[addr].xrefs.append(instr.address)
                    continue

                # Используем новую функцию для определения типа переменной
                var = _get_variable_at_address(pe, addr, rva)
                if var:
                    var.xrefs.append(instr.address)
                    variables[addr] = var

            except (ValueError, TypeError):
                continue

    # Добавляем строки и массивы указателей, найденные прямым сканированием
    for item in _scan_data_sections_for_strings(pe, variables) + _find_pointer_arrays(pe, variables):
        if item.address not in variables:
            variables[item.address] = item

    return sorted(list(variables.values()), key=lambda v: v.address)