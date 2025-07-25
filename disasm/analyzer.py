import dataclasses
import re
import struct
from .instruction import Instruction
from typing import List, Set, Dict, Optional, TYPE_CHECKING
import pefile

if TYPE_CHECKING:
    from utils.progress import AnalysisWorker

@dataclasses.dataclass
class BasicBlock:
    
    start_address: int
    end_address: int
    successors: List[int] = dataclasses.field(default_factory=list)
    terminator: Optional[Instruction] = None
    has_errors: bool = False

@dataclasses.dataclass
class FoundFunction:
    
    address: int
    name: str
    blocks: List[BasicBlock] = dataclasses.field(default_factory=list)
    has_errors: bool = False
    is_stub: bool = False

def _is_function_a_stub(instructions_slice: List[Instruction]) -> bool:
    
    if not instructions_slice or len(instructions_slice) > 3:
        return False

    
    if instructions_slice[-1].mnemonic != 'jmp':
        return False

    
    if len(instructions_slice) == 1:
        return True

    
    
    
    allowed_mnemonics = {'mov', 'lea', 'add', 'sub', 'push'}
    for instr in instructions_slice[:-1]:
        if instr.mnemonic not in allowed_mnemonics:
            return False
            
    return True

def _collect_jump_targets(instructions: List[Instruction]) -> Set[int]:
    
    targets = set()
    for instr in instructions:
        
        if instr.mnemonic.startswith('j'):
            try:
                
                target_addr = int(instr.operands, 16)
                targets.add(target_addr)
            except (ValueError, TypeError):
                
                pass
    return targets
    
def _find_call_targets(instructions: List[Instruction], valid_addresses: Set[int]) -> Set[int]:
    
    entry_points = set()
    for instr in instructions:
        if instr.mnemonic == "call":
            try:
                target_addr = int(instr.operands, 16)
                if target_addr in valid_addresses:
                    entry_points.add(target_addr)
            except (ValueError, TypeError):
                pass 
    return entry_points

def _find_after_flow_separators(instructions: List[Instruction]) -> Set[int]:
    
    entry_points = set()
    
    separator_mnemonics = {'jmp', 'ret', 'retn', 'retf', 'iret', 'iretd', 'iretq'}

    for i in range(len(instructions) - 1):
        current_instr = instructions[i]
        next_instr = instructions[i+1]

        is_separator = current_instr.mnemonic in separator_mnemonics
        is_next_separator = next_instr.mnemonic in separator_mnemonics

        
        
        if is_separator and not is_next_separator and next_instr.mnemonic != 'db':
            entry_points.add(next_instr.address)
            
    return entry_points

def _find_standard_prologues(instructions: List[Instruction]) -> Set[int]:
    
    entry_points = set()
    processed_addresses = set()

    for i in range(len(instructions)):
        if instructions[i].address in processed_addresses:
            continue

        
        if i + 1 < len(instructions):
            instr1, instr2 = instructions[i], instructions[i+1]
            ops = [o.strip() for o in instr2.operands.split(',')]
            is_classic_prologue = (
                instr1.mnemonic == "push" and instr1.operands in ('rbp', 'ebp') and
                instr2.mnemonic == "mov" and len(ops) == 2 and
                ops[0] == instr1.operands and ops[1] in ('rsp', 'esp')
            )
            if is_classic_prologue:
                entry_points.add(instr1.address)
                processed_addresses.add(instr1.address)
                processed_addresses.add(instr2.address)
                
                if i + 2 < len(instructions):
                    third_instr = instructions[i+2]
                    if third_instr.mnemonic == 'sub' and third_instr.operands.startswith(('rsp,', 'esp,')):
                        processed_addresses.add(third_instr.address)
                continue

        
        instr = instructions[i]
        if instr.mnemonic == 'sub' and instr.operands.startswith(('rsp,', 'esp,')):
            try:
                val_str = instr.operands.split(',')[1].strip()
                val = int(val_str, 16)
                if val >= 0x20:
                    entry_points.add(instr.address)
                    processed_addresses.add(instr.address)
            except (ValueError, IndexError):
                pass

    return entry_points

def _find_after_padding_blocks(instructions: List[Instruction]) -> Set[int]:
    
    entry_points = set()
    padding_bytes = {b'\xcc', b'\x90'}
    flow_terminators = {'ret', 'retn', 'jmp', 'iret'}

    i = 0
    while i < len(instructions):
        current_instr = instructions[i]
        if current_instr.bytes in padding_bytes:
            block_start_index = i
            while i < len(instructions) and instructions[i].bytes in padding_bytes:
                i += 1
            block_size = i - block_start_index

            is_valid_candidate = False
            if block_size >= 2:
                is_valid_candidate = True
            elif block_size == 1 and block_start_index > 0:
                prev_instr = instructions[block_start_index - 1]
                if prev_instr.mnemonic in flow_terminators:
                    is_valid_candidate = True

            if is_valid_candidate and i < len(instructions):
                if instructions[i].bytes not in padding_bytes:
                    entry_points.add(instructions[i].address)
        else:
            i += 1
            
    return entry_points

def _resolve_jump_table(
    jmp_instr: Instruction,
    pe: "pefile.PE",
) -> List[int]:
    
    if not pe:
        return []

    
    match = re.search(r'(0x[0-9a-fA-F]{5,}|[a-fA-F0-9]{5,}h)', jmp_instr.operands)
    if not match:
        return []

    try:
        table_base_addr = int(match.group(1).replace('h', ''), 16)
    except (ValueError, IndexError):
        return []

    image_base = pe.OPTIONAL_HEADER.ImageBase
    is_64bit = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']
    ptr_size, unpack_fmt = (8, '<Q') if is_64bit else (4, '<I')

    try:
        table_rva = table_base_addr - image_base
        
        table_data = pe.get_data(table_rva, 256 * ptr_size)
    except Exception:
        return []

    targets = []
    text_section = next((s for s in pe.sections if s.Name.startswith(b'.text')), None)
    if not text_section:
        return []
    code_rva_range = (text_section.VirtualAddress, text_section.VirtualAddress + text_section.Misc_VirtualSize)

    for i in range(0, len(table_data), ptr_size):
        if i + ptr_size > len(table_data):
            break
        target_addr = struct.unpack(unpack_fmt, table_data[i:i+ptr_size])[0]
        target_rva = target_addr - image_base

        if code_rva_range[0] <= target_rva < code_rva_range[1]:
            targets.append(target_addr)
        else:
            break
    
    return targets if len(targets) >= 3 else []

def find_xrefs(
    instructions: List[Instruction],
    valid_addr_range: Optional[tuple[int, int]] = None
) -> Dict[int, Set[int]]:
    
    
    
    xrefs: Dict[int, Set[int]] = {}
    hex_pattern = re.compile(r'0x[0-9a-fA-F]+')

    for instr in instructions:
        
        matches = hex_pattern.findall(instr.operands)
        for match in matches:
            try:
                target_addr = int(match, 16)
                
                
                if valid_addr_range and not (valid_addr_range[0] <= target_addr < valid_addr_range[1]):
                    continue
                xrefs.setdefault(target_addr, set()).add(instr.address)
            except (ValueError, TypeError):
                continue
    return xrefs

def flag_consecutive_errors(instructions: List[Instruction], threshold: int = 3):
    
    if not instructions:
        return

    i = 0
    while i < len(instructions):
        if instructions[i].mnemonic == 'db':
            block_start_index = i
            while i < len(instructions) and instructions[i].mnemonic == 'db':
                i += 1
            
            if (i - block_start_index) >= threshold:
                for j in range(block_start_index, i):
                    instructions[j].is_error = True
        else:
            i += 1

def find_functions(
    instructions: List[Instruction],
    pe: Optional["pefile.PE"] = None,
    entry_point: Optional[int] = None,
    user_labels: Optional[Dict[int, str]] = None,
    exports: Optional[Dict[int, str]] = None,
    use_prologues: bool = True,
    use_separators: bool = True,
    use_padding: bool = True,
    analyze_blocks: bool = True,
    worker: Optional["AnalysisWorker"] = None,
) -> List[FoundFunction]:
    
    if not instructions:
        return []

    entry_points = set()
    
    if worker: worker.queue.put(("status", "Поиск точек входа..."))

    if entry_point:
        entry_points.add(entry_point)
    
    valid_addresses = {instr.address for instr in instructions}
    
    if worker: worker.queue.put(("status", "Поиск целей вызовов (call)..."))
    entry_points.update(_find_call_targets(instructions, valid_addresses))
    
    jmp_targets = _collect_jump_targets(instructions)

    if use_prologues:
        if worker: worker.queue.put(("status", "Анализ стандартных прологов..."))
        prologue_candidates = _find_standard_prologues(instructions)
        entry_points.update(p for p in prologue_candidates if p not in jmp_targets)

    if use_separators:
        if worker: worker.queue.put(("status", "Поиск кода после инструкций-разделителей..."))
        separator_candidates = _find_after_flow_separators(instructions)
        entry_points.update(s for s in separator_candidates if s not in jmp_targets)

    if use_padding:
        if worker: worker.queue.put(("status", "Поиск кода после блоков выравнивания..."))
        padding_candidates = _find_after_padding_blocks(instructions)
        entry_points.update(p for p in padding_candidates if p not in jmp_targets)

    if exports:
        entry_points.update(addr for addr in exports.keys() if addr in valid_addresses)

    
    valid_entry_points = {addr for addr in entry_points if addr in valid_addresses}

    if exports is None:
        exports = {}
    if user_labels is None:
        user_labels = {}

    sorted_starts = sorted(list(valid_entry_points))
    addr_to_instr_idx = {instr.address: i for i, instr in enumerate(instructions)}

    total_functions = len(sorted_starts)
    found_functions_with_blocks = []
    for i, start_addr in enumerate(sorted_starts):
        if worker:
            
            progress_percent = int((i / total_functions) * 100) if total_functions > 0 else 0
            worker.queue.put(("progress", progress_percent))
            
            worker.queue.put(("status", f"Анализ функции {i+1}/{total_functions} по адресу 0x{start_addr:x}..."))
        
        name = user_labels.get(start_addr, exports.get(start_addr, f"sub_{start_addr:x}"))
        
        blocks = []
        function_has_errors = False
        is_stub = False
        
        
        end_addr_exclusive = sorted_starts[i+1] if (i + 1) < len(sorted_starts) else instructions[-1].address + instructions[-1].size
        
        func_instructions_slice = [instr for instr in instructions if start_addr <= instr.address < end_addr_exclusive]
        
        if analyze_blocks:
            
            is_stub = _is_function_a_stub(func_instructions_slice)

            if not func_instructions_slice:
                found_functions_with_blocks.append(FoundFunction(address=start_addr, name=name, blocks=[], has_errors=False, is_stub=is_stub))
                continue

            
            function_has_errors = any(instr.is_error for instr in func_instructions_slice)

            
            leaders = {start_addr}
            for instr in func_instructions_slice:
                
                if instr.mnemonic.startswith('j') or instr.mnemonic == 'call' or instr.mnemonic == 'ret':
                    next_instr_addr = instr.address + instr.size
                    if next_instr_addr < end_addr_exclusive and next_instr_addr in addr_to_instr_idx:
                        leaders.add(next_instr_addr)
                
                
                if instr.mnemonic.startswith('j') or instr.mnemonic == 'call':
                    try:
                        target_addr = int(instr.operands, 16)
                        if start_addr <= target_addr < end_addr_exclusive and target_addr in addr_to_instr_idx:
                            leaders.add(target_addr)
                    except (ValueError, TypeError):
                        pass
            
            
            sorted_leaders = sorted(list(leaders))
            for j, leader_addr in enumerate(sorted_leaders):
                block_start_addr = leader_addr
                block_end_addr_exclusive = sorted_leaders[j+1] if (j + 1) < len(sorted_leaders) else end_addr_exclusive
                
                block_instructions = [instr for instr in func_instructions_slice if block_start_addr <= instr.address < block_end_addr_exclusive]
                block_has_errors = any(instr.is_error for instr in block_instructions)
                
                terminator = None
                successors = []
                last_instr_addr = block_start_addr

                if block_instructions:
                    last_instr_addr = block_instructions[-1].address
                    terminator = block_instructions[-1]
                    next_instr_addr = terminator.address + terminator.size

                    
                    if terminator.mnemonic == 'jmp':
                        try:
                            target_addr = int(terminator.operands, 16)
                            if start_addr <= target_addr < end_addr_exclusive:
                                successors.append(target_addr)
                        except (ValueError, TypeError):
                            pass 
                    
                    elif terminator.mnemonic.startswith('j'):
                        if next_instr_addr < end_addr_exclusive: 
                            successors.append(next_instr_addr)
                        try: 
                            target_addr = int(terminator.operands, 16)
                            if start_addr <= target_addr < end_addr_exclusive:
                                successors.append(target_addr)
                        except (ValueError, TypeError): pass
                    
                    elif 'ret' not in terminator.mnemonic:
                        if next_instr_addr < end_addr_exclusive:
                            successors.append(next_instr_addr)

                blocks.append(BasicBlock(start_address=block_start_addr, end_address=last_instr_addr, has_errors=block_has_errors, successors=successors, terminator=terminator))

               
                if terminator and terminator.mnemonic == 'jmp':
                    is_indirect = False
                    try:
                        int(terminator.operands, 16)
                    except (ValueError, TypeError):
                        is_indirect = True
                    
                    if is_indirect:
                        jump_table_targets = _resolve_jump_table(terminator, pe)
                        if jump_table_targets:
                            successors.extend(jump_table_targets)
                        else:
                            break 

        found_functions_with_blocks.append(FoundFunction(address=start_addr, name=name, blocks=blocks, has_errors=function_has_errors, is_stub=is_stub))

    if worker:
        worker.queue.put(("status", "Завершение..."))
        worker.queue.put(("progress", 100))
    return found_functions_with_blocks