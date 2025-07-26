import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
import traceback
from typing import List, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import pefile
    from disasm.instruction import Instruction
    from disasm.analyzer import FoundFunction

class AnalysisWorker(threading.Thread):
    
    def __init__(self, pe: "pefile.PE", instructions: List["Instruction"], settings: Dict, user_labels: Dict):
        super().__init__()
        self.queue = queue.Queue()
        self.pe = pe
        self.instructions = instructions
        self.settings = settings
        self.user_labels = user_labels

    def run(self):
        
        try:
            
            from disasm import (
                analyze_pe_info,
                analyze_structure,
                analyze_anti_debug,
                find_xrefs, find_functions,
                find_classes, 
                find_variables,
                SignatureScanner, SIGNATURES
            )

            
            self.queue.put(('status', 'Анализ PE-заголовков...'))
            analyze_all_sections = self.settings.get("analyze_all_sections_for_compiler", True)
            file_info = analyze_pe_info(self.pe, analyze_all_sections=analyze_all_sections)
            
            self.queue.put(('status', 'Анализ структуры файла...'))
            file_structure = analyze_structure(self.pe, file_info)

            anti_debug_results = []
            if self.settings.get("analyze_anti_debug", False):
                self.queue.put(('status', 'Поиск анти-отладочных техник...'))
                anti_debug_results = analyze_anti_debug(self.instructions, file_info.imports if file_info else None)

            xrefs = {}
            if self.settings.get("analyze_xrefs", True):
                self.queue.put(('status', 'Поиск перекрестных ссылок (XRefs)...'))
                valid_addr_min = self.pe.OPTIONAL_HEADER.ImageBase
                valid_addr_max = valid_addr_min + self.pe.OPTIONAL_HEADER.SizeOfImage
                xrefs = find_xrefs(self.instructions, (valid_addr_min, valid_addr_max))

            entry_point_va = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            
            functions = find_functions(
                instructions=self.instructions,
                pe=self.pe,
                entry_point=entry_point_va,
                user_labels=self.user_labels,
                exports=file_info.exports if file_info else None,
                use_prologues=self.settings.get("use_prologue_heuristic", True),
                use_separators=self.settings.get("use_separator_heuristic", True),
                use_padding=self.settings.get("use_padding_heuristic", True),
                analyze_blocks=self.settings.get("analyze_basic_blocks", True),
                worker=self
            )

            classes = []
            if self.settings.get("analyze_classes", True):
                self.queue.put(('status', 'Поиск RTTI и классов...'))
                classes = find_classes(self.pe, file_info)

            variables = []
            if self.settings.get("analyze_variables", True):
                self.queue.put(('status', 'Поиск глобальных переменных и строк...'))
                variables = find_variables(self.instructions, self.pe)

            scan_results = []
            if self.settings.get("analyze_signatures", True):
                self.queue.put(('status', 'Поиск по сигнатурам...'))
                scanner = SignatureScanner(SIGNATURES)
                scan_results = scanner.scan(self.pe)

            
            final_result = {
                "file_info": file_info,
                "file_structure": file_structure,
                "anti_debug_results": anti_debug_results,
                "xrefs": xrefs,
                "functions": functions,
                "classes": classes,
                "variables": variables,
                "scan_results": scan_results,
            }
            self.queue.put(('finished', final_result))

        except Exception as e:
            traceback.print_exc()
            self.queue.put(('error', str(e)))

class ProgressDialog(tk.Toplevel):
    
    def __init__(self, parent, worker: AnalysisWorker):
        super().__init__(parent)
        self.worker = worker
        self.parent = parent

        self.title("Анализ...")
        self.geometry("450x120")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(expand=True, fill=tk.BOTH)

        self.status_var = tk.StringVar(value="Инициализация...")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, anchor='w')
        status_label.pack(fill='x', pady=(5, 5))

        self.progress_var = tk.IntVar(value=0)
        progress_bar = ttk.Progressbar(main_frame, orient='horizontal', mode='determinate', variable=self.progress_var, maximum=100)
        progress_bar.pack(fill='x', expand=True, pady=(5, 10))

        
        self.protocol("WM_DELETE_WINDOW", lambda: None)

        self.check_queue()

    def check_queue(self):
        """Проверяет очередь сообщений от рабочего потока."""
        try:
            while True:
                message_type, data = self.worker.queue.get_nowait()
                if message_type == 'progress':
                    self.progress_var.set(data)
                elif message_type == 'status':
                    self.status_var.set(data)
                elif message_type == 'finished':
                    self.parent.on_analysis_complete(data)
                    self.destroy()
                    return 
                elif message_type == 'error':
                    messagebox.showerror("Ошибка анализа", f"В процессе анализа произошла ошибка:\n{data}", parent=self.parent)
                    self.parent.on_analysis_complete({}) 
                    self.destroy()
                    return 
        except queue.Empty:
            pass 

        
        self.after(100, self.check_queue)