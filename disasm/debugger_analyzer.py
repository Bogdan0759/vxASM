import dataclasses
from typing import List, Dict, Optional
import re

from .instruction import Instruction
from .info_analyzer import ImportedFunction

@dataclasses.dataclass
class DetectionResult:
    
    address: int
    name: str
    description: str

    def __repr__(self) -> str:
        return f"DetectionResult(address=0x{self.address:x}, name='{self.name}')"

def _find_trap_flag_trick(instructions: List[Instruction]) -> List[DetectionResult]:
    
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

def _find_standalone_interrupts(instructions: List[Instruction]) -> List[DetectionResult]:
    
    results = []
    interrupt_mnemonics = {'int3', 'icebp'}

    for i, instr in enumerate(instructions):
        if instr.mnemonic not in interrupt_mnemonics:
            continue

        if instr.is_error:
            continue

        is_likely_padding = False
        if i > 0 and instructions[i-1].mnemonic in interrupt_mnemonics:
            is_likely_padding = True
        if i < len(instructions) - 1 and instructions[i+1].mnemonic in interrupt_mnemonics:
            is_likely_padding = True
        
        if not is_likely_padding:
            if instr.mnemonic == 'icebp':
                name = "ICEBP Interrupt (INT 1)"
                desc = "Обнаружена инструкция INT 1, которая вызывает отладочное прерывание."
            else: 
                name = "Software Breakpoint (INT 3)"
                desc = "Обнаружена инструкция INT 3, которая может использоваться для проверки наличия отладчика."
            
            results.append(DetectionResult(instr.address, name, desc))
            
    return results

def _find_cpuid_hypervisor_check(instructions: List[Instruction]) -> List[DetectionResult]:
    
    results = []
    for i, instr in enumerate(instructions):
        
        is_hypervisor_leaf = (
            instr.mnemonic == 'mov' and
            'eax' in instr.operands.lower() and
            '0x40000000' in instr.operands.lower()
        )
        if not is_hypervisor_leaf:
            continue

        
        for k in range(i + 1, min(i + 4, len(instructions))):
            if instructions[k].mnemonic == 'cpuid':
                results.append(DetectionResult(
                    instr.address,
                    "CPUID Hypervisor Check",
                    "Обнаружен запрос к CPUID с 'листом' 0x40000000 для получения информации о гипервизоре."
                ))
                break
    return results

def _find_sidt_check(instructions: List[Instruction]) -> List[DetectionResult]:
    results = []
    for instr in instructions:
        if instr.mnemonic == 'sidt':
            results.append(DetectionResult(
                instr.address,
                "SIDT Instruction Check",
                "Обнаружена инструкция SIDT, которая может использоваться для определения работы в виртуальной машине (Red Pill)."
            ))
    return results

def _find_ntqueryinformationprocess_checks(
    instructions: List[Instruction],
    iat_address_to_func_name: Dict[int, str]
) -> List[DetectionResult]:
    results = []
    
    
    debug_classes = { 7: "ProcessDebugPort", 0x1e: "ProcessDebugObjectHandle", 0x1f: "ProcessDebugFlags" }
    
    ntqip_call_indices = []
    for i, instr in enumerate(instructions):
        if instr.mnemonic == 'call' and instr.operands.startswith('0x'):
            try:
                
                target_addr = int(instr.operands, 16)
                if iat_address_to_func_name.get(target_addr) == 'ntqueryinformationprocess':
                    ntqip_call_indices.append(i)
            except ValueError:
                continue 

    for call_index in ntqip_call_indices:
        
        for k in range(max(0, call_index - 15), call_index):
            instr = instructions[k]
            
            match = re.search(r'(?:mov|push)\s+.*[,\s]\s*(0x[0-9a-f]+|[0-9]+)\b', instr.operands, re.IGNORECASE)
            if match:
                try:
                    val = int(match.group(1), 0) 
                    if val in debug_classes:
                        class_name = debug_classes[val]
                        results.append(DetectionResult(instr.address, f"NtQueryInformationProcess Check ({class_name})", f"Обнаружен вызов NtQueryInformationProcess с классом {class_name} для проверки отладчика."))
                        break 
                except (ValueError, TypeError):
                    continue
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
        
        "ntquerysysteminformation": ("NtQuerySystemInformation Check", "Может использоваться для обнаружения отладчика ядра (Kernel Debugger)."),
        "closehandle": ("Invalid Handle Check (CloseHandle)", "Вызов CloseHandle с невалидным хендлом вызывает исключение, которое обрабатывается иначе под отладчиком."),
        "setunhandledexceptionfilter": ("SetUnhandledExceptionFilter Hook", "Может использоваться для перехвата исключений и обнаружения отладчика."),
    }

    iat_address_to_func_name: Dict[int, str] = {}
    for dll, funcs in imports.items():
        for func in funcs:
            iat_address_to_func_name[func.address] = func.name.lower()

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
    results.extend(_find_standalone_interrupts(instructions))
    results.extend(_find_cpuid_hypervisor_check(instructions))
    results.extend(_find_sidt_check(instructions))
    results.extend(_find_ntqueryinformationprocess_checks(instructions, iat_address_to_func_name))
    
    
    unique_results_dict = { (r.address, r.name): r for r in results }
    return sorted(list(unique_results_dict.values()), key=lambda r: r.address)