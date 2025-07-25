import dataclasses
from typing import List, Dict, Optional
import re

from .instruction import Instruction
from .info_analyzer import ImportedFunction

@dataclasses.dataclass
class DetectionResult:
    """Представляет один результат обнаружения анти-отладочной техники."""
    address: int
    name: str
    description: str

    def __repr__(self) -> str:
        return f"DetectionResult(address=0x{self.address:x}, name='{self.name}')"

def _find_trap_flag_trick(instructions: List[Instruction]) -> List[DetectionResult]:
    """Ищет паттерн установки Trap Flag (pushf; or [rsp], 0x100; popf)."""
    results = []
    push_mnemonics = {'pushf', 'pushfd', 'pushfq'}
    pop_mnemonics = {'popf', 'popfd', 'popfq'}

    for i, instr in enumerate(instructions):
        if instr.mnemonic not in push_mnemonics:
            continue

        
        for k in range(i + 1, min(i + 10, len(instructions))):
            next_instr = instructions[k]
            if next_instr.mnemonic in pop_mnemonics:
                
                for j in range(i + 1, k):
                    inner_instr = instructions[j]
                    
                    
                    is_or_on_stack = (
                        inner_instr.mnemonic == 'or' and
                        '0x100' in inner_instr.operands and  
                        ('rsp' in inner_instr.operands or 'esp' in inner_instr.operands)
                    )
                    if is_or_on_stack:
                        results.append(DetectionResult(
                            instr.address,
                            "Trap Flag Check (INT 1)",
                            "Обнаружен паттерн установки Trap Flag для обнаружения отладчика."
                        ))
                        break  
                break  
    return results

def _find_timing_attacks(instructions: List[Instruction]) -> List[DetectionResult]:
    """Ищет тайминговые атаки, используя пары rdtsc/rdpmc и последующий анализ."""
    results = []
    timing_mnemonics = {'rdtsc', 'rdpmc'}
    timing_indices = [i for i, instr in enumerate(instructions) if instr.mnemonic in timing_mnemonics]

    if len(timing_indices) < 2:
        return []

    for i in range(len(timing_indices) - 1):
        idx1, idx2 = timing_indices[i], timing_indices[i+1]
        instr1, instr2 = instructions[idx1], instructions[idx2]

        
        if (instr2.address - instr1.address) > 512:
            continue

        
        for k in range(idx2 + 1, min(idx2 + 15, len(instructions))):
            check_instr = instructions[k]
            
            if check_instr.mnemonic in ('cmp', 'sub') and any(reg in check_instr.operands.lower() for reg in ['eax', 'rax', 'edx', 'rdx']):
                mnemonic_name = instr1.mnemonic.upper()
                results.append(DetectionResult(
                    instr1.address,
                    f"Timing Attack ({mnemonic_name})",
                    f"Обнаружен паттерн замера времени ({mnemonic_name}) с последующим сравнением."
                ))
                break  
    return results

def _find_peb_being_debugged_check(instructions: List[Instruction]) -> List[DetectionResult]:
    """Ищет паттерн проверки флага BeingDebugged в PEB."""
    results = []
    for i, instr in enumerate(instructions):
        
        is_peb_load = (
            instr.mnemonic == 'mov' and
            ('fs:[30' in instr.operands.replace(' ', '') or 'gs:[60' in instr.operands.replace(' ', ''))
        )
        if not is_peb_load:
            continue

        try:
            dest_reg = instr.operands.split(',')[0].strip()
        except IndexError:
            continue

        
        for k in range(i + 1, min(i + 6, len(instructions))):
            next_instr = instructions[k]
            
            # Более надежная проверка для доступа к памяти, например [reg+2], [reg+0x2] и т.д.
            # Учитывает разное количество пробелов и шестнадцатеричное/десятичное представление.
            pattern = re.compile(rf'\b{re.escape(dest_reg)}\s*\+\s*(?:0x)?2\b', re.IGNORECASE)
            if pattern.search(next_instr.operands):
                results.append(DetectionResult(
                    instr.address,
                    "PEB BeingDebugged Check",
                    "Обнаружена проверка флага BeingDebugged в Process Environment Block (offset +0x2)."
                ))
                break  
    return results

def _find_peb_ntglobalflag_check(instructions: List[Instruction]) -> List[DetectionResult]:
    """Ищет паттерн проверки флага NtGlobalFlag в PEB."""
    results = []
    for i, instr in enumerate(instructions):
        
        is_peb_load = (
            instr.mnemonic == 'mov' and
            ('fs:[30' in instr.operands.replace(' ', '') or 'gs:[60' in instr.operands.replace(' ', ''))
        )
        if not is_peb_load:
            continue

        try:
            dest_reg = instr.operands.split(',')[0].strip()
        except IndexError:
            continue

        
        
        
        for k in range(i + 1, min(i + 8, len(instructions))):
            next_instr = instructions[k]
            operands = next_instr.operands.replace(' ', '').lower()
            
            is_x86_check = f'[{dest_reg}+68' in operands and '70' in operands
            is_x64_check = f'[{dest_reg}+bc' in operands and '70' in operands

            if next_instr.mnemonic == 'test' and (is_x86_check or is_x64_check):
                results.append(DetectionResult(
                    instr.address,
                    "PEB NtGlobalFlag Check",
                    "Обнаружена проверка флагов отладки в PEB (NtGlobalFlag at +0x68/BC)."
                ))
                break
    return results

def _find_peb_heap_flags_check(instructions: List[Instruction]) -> List[DetectionResult]:
    """Ищет паттерн проверки флагов кучи (Heap Flags/ForceFlags) в PEB."""
    results = []
    for i, instr in enumerate(instructions):
        is_peb_load = (
            instr.mnemonic == 'mov' and
            ('fs:[30' in instr.operands.replace(' ', '') or 'gs:[60' in instr.operands.replace(' ', ''))
        )
        if not is_peb_load:
            continue

        try:
            peb_reg = instr.operands.split(',')[0].strip()
        except IndexError:
            continue

        
        for k in range(i + 1, min(i + 8, len(instructions))):
            
            is_heap_load_x86 = f'[{peb_reg}+18' in instructions[k].operands.replace(' ', '').lower()
            is_heap_load_x64 = f'[{peb_reg}+30' in instructions[k].operands.replace(' ', '').lower()

            if instructions[k].mnemonic == 'mov' and (is_heap_load_x86 or is_heap_load_x64):
                try:
                    heap_reg = instructions[k].operands.split(',')[0].strip()
                except IndexError:
                    continue

                
                for l in range(k + 1, min(k + 8, len(instructions))):
                    final_instr = instructions[l]
                    final_operands = final_instr.operands.replace(' ', '').lower()
                    
                    is_flags_check = any(s in final_operands for s in (f'[{heap_reg}+40', f'[{heap_reg}+44', f'[{heap_reg}+70', f'[{heap_reg}+74'))

                    if final_instr.mnemonic in ('mov', 'test', 'cmp') and is_flags_check:
                        results.append(DetectionResult(
                            instr.address, "PEB Heap Flags Check",
                            "Обнаружена проверка флагов отладки кучи в PEB (ProcessHeap->Flags)."
                        ))
                        break  
                break  
    return results

def _find_manual_isdebuggerpresent(instructions: List[Instruction]) -> List[DetectionResult]:
    """Ищет ручную реализацию IsDebuggerPresent через PEB."""
    results = []
    for i in range(len(instructions) - 2):
        instr1, instr2, instr3 = instructions[i], instructions[i+1], instructions[i+2]

        
        is_peb_load = (
            instr1.mnemonic == 'mov' and
            ('rax' in instr1.operands or 'eax' in instr1.operands) and
            ('gs:[60' in instr1.operands.replace(' ', '') or 'fs:[30' in instr1.operands.replace(' ', ''))
        )
        if not is_peb_load:
            continue
        
        
        is_flag_read = (
            instr2.mnemonic == 'movzx' and
            ('eax' in instr2.operands or 'rax' in instr2.operands)
        )
        if not is_flag_read:
            continue

        # Надежная проверка чтения флага, например, movzx eax, byte ptr [rax+2]
        flag_read_pattern = re.compile(r'\[\s*(?:rax|eax)\s*\+\s*(?:0x)?2\s*\]', re.IGNORECASE)
        
        is_ret = instr3.mnemonic == 'ret'

        if flag_read_pattern.search(instr2.operands) and is_ret:
             results.append(DetectionResult(
                instr1.address,
                "Manual IsDebuggerPresent",
                "Обнаружена функция, вручную читающая флаг BeingDebugged из PEB и возвращающая его."
            ))
    return results

def _find_exception_based_tricks(
    instructions: List[Instruction],
    iat_address_to_func_name: Dict[int, str]
) -> List[DetectionResult]:
    """Ищет трюки, основанные на генерации исключений, например, SetUnhandledExceptionFilter + int3."""
    results = []
    exception_triggers = {'int3', 'ud2'}

    
    suef_call_indices = []
    for i, instr in enumerate(instructions):
        if instr.mnemonic == 'call' and instr.operands.startswith('0x'):
            try:
                target_addr = int(instr.operands, 16)
                if iat_address_to_func_name.get(target_addr) == 'setunhandledexceptionfilter':
                    suef_call_indices.append(i)
            except (ValueError, TypeError):
                pass

    for call_index in suef_call_indices:
        
        for k in range(call_index + 1, min(call_index + 20, len(instructions))):
            check_instr = instructions[k]
            if check_instr.mnemonic in exception_triggers or (check_instr.mnemonic == 'int' and '3' in check_instr.operands):
                results.append(DetectionResult(
                    instructions[call_index].address, "UnhandledExceptionFilter Trap",
                    "Обнаружена установка обработчика исключений с последующим вызовом прерывания."
                ))
                break  
    return results

def analyze_anti_debug(
    instructions: List[Instruction],
    imports: Optional[Dict[str, List[ImportedFunction]]]
) -> List[DetectionResult]:
    """
    Анализирует инструкции и импорты на наличие известных техник
    анти-отладки и анти-виртуализации.
    """
    results: List[DetectionResult] = []
    if imports is None:
        imports = {}

    suspicious_imports = {
        "isdebuggerpresent": ("IsDebuggerPresent Check", "Прямая проверка наличия отладчика через API."),
        "checkremotedebuggerpresent": ("CheckRemoteDebuggerPresent Check", "Проверка наличия удаленного отладчика через API."),
        "outputdebugstringa": ("OutputDebugString Timing Check", "Может использоваться для замера времени выполнения и обнаружения отладчика."),
        "outputdebugstringw": ("OutputDebugString Timing Check", "Может использоваться для замера времени выполнения и обнаружения отладчика."),
        "ntqueryinformationprocess": ("NtQueryInformationProcess Check", "Может использоваться для получения отладочного порта процесса."),
        "ntquerysysteminformation": ("NtQuerySystemInformation Check", "Может использоваться для обнаружения отладчика ядра (Kernel Debugger)."),
        "closehandle": ("Invalid Handle Check (CloseHandle)", "Вызов CloseHandle с невалидным хендлом вызывает исключение, которое обрабатывается иначе под отладчиком."),
        "setunhandledexceptionfilter": ("SetUnhandledExceptionFilter Hook", "Может использоваться для перехвата исключений и обнаружения отладчика."),
    }

    iat_address_to_func_name: Dict[int, str] = {}
    for dll, funcs in imports.items():
        for func in funcs:
            iat_address_to_func_name[func.address] = func.name.lower()

    suspicious_single_instructions = {
        b'\xf1': ("ICEBP Interrupt (INT1)", "Инструкция INT1, вызывает отладочное прерывание, которое перехватывается только отладчиком."),
    }

    for i, instr in enumerate(instructions):
        
        if instr.mnemonic == 'call' and instr.operands.startswith('0x'):
            try:
                target_addr = int(instr.operands, 16)
                func_name = iat_address_to_func_name.get(target_addr)
                if func_name and func_name in suspicious_imports:
                    name, desc = suspicious_imports[func_name]
                    results.append(DetectionResult(instr.address, name, desc))
            except (ValueError, TypeError):
                pass

        
        if instr.bytes in suspicious_single_instructions:
            name, desc = suspicious_single_instructions[instr.bytes]
            results.append(DetectionResult(instr.address, name, desc))

        
        if instr.mnemonic == 'in' and 'eax, dx' in instr.operands.lower().replace(' ', ''):
            is_vmware_check = False
            
            if i > 0:
                prev_instr = instructions[i - 1]
                if prev_instr.mnemonic == 'mov' and 'eax' in prev_instr.operands and '0x564d5868' in prev_instr.operands.lower():
                    is_vmware_check = True
            
            if is_vmware_check:
                results.append(DetectionResult(
                    instr.address,
                    "VMware Backdoor Check",
                    "Обнаружена инструкция IN с магическим числом VMware ('VMXh') для связи с гипервизором."
                ))
            else:
                results.append(DetectionResult(
                    instr.address, "Potential Hypervisor Check (IN instruction)",
                    "Обнаружена инструкция IN, которая может использоваться для связи с гипервизором (например, VirtualPC)."
                ))

        
        if instr.mnemonic.startswith('int') and '2d' in instr.operands.lower():
            results.append(DetectionResult(
                instr.address,
                "Kernel Debugger Check (INT 2D)",
                "Вызывает исключение, которое перехватывается отладчиком уровня ядра."
            ))

        
        if instr.mnemonic == 'mov':
            for op in instr.operands.split(','):
                op = op.strip().lower()
                if op.startswith('dr') and op[2:].isdigit() and 0 <= int(op[2:]) <= 7:
                    results.append(DetectionResult(
                        instr.address,
                        "Hardware Breakpoint Check",
                        "Обнаружен доступ к отладочным регистрам (DR0-DR7)."
                    ))
                    break 

    results.extend(_find_timing_attacks(instructions))
    results.extend(_find_trap_flag_trick(instructions))
    results.extend(_find_peb_being_debugged_check(instructions))
    results.extend(_find_peb_ntglobalflag_check(instructions))
    results.extend(_find_peb_heap_flags_check(instructions))
    results.extend(_find_manual_isdebuggerpresent(instructions))
    results.extend(_find_exception_based_tricks(instructions, iat_address_to_func_name))
    
    
    unique_results_dict = { (r.address, r.name): r for r in results }
    return sorted(list(unique_results_dict.values()), key=lambda r: r.address)