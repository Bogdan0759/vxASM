import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, font, simpledialog
import sys
import os
import re
import json
from typing import Dict, Set, Optional, List

from disasm import ( 
    Disassembler, Instruction,
    find_functions, FoundFunction, find_xrefs, flag_consecutive_errors,
    find_classes, FoundClass, SecurityFeatures, SectionInfo, is_dotnet_assembly,
    analyze_pe_info, FileInfo, ImportedFunction,
    analyze_anti_debug, DetectionResult,
    analyze_structure, ExplorerNode,
    find_variables, FoundVariable
)

class DisassemblerApp(tk.Tk):
    """
    GUI-обертка для дизассемблера.
    """
    def __init__(self):
        super().__init__()

        self.pefile = self._import_pefile()
        if not self.pefile:
            self.destroy()
            sys.exit(1)
        
        self.title("Vexapay Disassembler")
        self.geometry("1200x700")

        
        self.settings = self._load_settings()
        self.current_filepath = None
        self.instructions: list[Instruction] = []
        self.functions: list[FoundFunction] = []
        self.classes: list[FoundClass] = []
        self.variables: list[FoundVariable] = []
        self.anti_debug_results: list[DetectionResult] = []
        self.file_info: FileInfo | None = None
        self.pe_object: "pefile.PE | None" = None
        self.file_structure: ExplorerNode | None = None
        self.base_address = 0
        self.user_labels: Dict[int, str] = {}
        self.function_map: Dict[int, FoundFunction] = {}
        self._context_line_text: Optional[str] = None
        self.explorer_iid_to_node: Dict[str, ExplorerNode] = {}
        self.section_name = ""
        self.xrefs: Dict[int, Set[int]] = {}
        self.address_to_instruction: Dict[int, Instruction] = {}
        self.line_to_instruction: Dict[str, Instruction] = {}
        
        self.colors = {}
        self.address_to_line: dict[int, str] = {}

        
        self.top_frame = ttk.Frame(self)
        self.top_frame.pack(fill=tk.X, padx=5, pady=5)

        self.open_button = ttk.Button(self.top_frame, text="Открыть файл...", command=self.open_file)
        self.open_button.pack(side=tk.LEFT)

        self.export_button = ttk.Button(self.top_frame, text="Экспорт в .asm...", command=self.export_asm, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=5)

        self.settings_button = ttk.Button(self.top_frame, text="Настройки", command=self._open_settings_window)
        self.settings_button.pack(side=tk.LEFT)

        
        self.main_pane = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        self.main_pane.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        
        left_notebook = ttk.Notebook(self.main_pane)

        
        functions_tab = ttk.Frame(left_notebook)
        left_notebook.add(functions_tab, text="Функции")

        self.functions_tree = ttk.Treeview(functions_tab, show="tree headings", columns=("name",))
        self.functions_tree.heading("#0", text="Адрес")
        self.functions_tree.heading("name", text="Имя")
        self.functions_tree.column("#0", width=100, stretch=tk.NO, anchor='w')
        self.functions_tree.column("name", anchor='w')
        self.functions_tree.pack(expand=True, fill=tk.BOTH)
        self.functions_tree.bind("<<TreeviewSelect>>", self._on_function_select)
        self.functions_tree.bind("<Button-3>", self._show_function_context_menu)
        self.function_context_menu = tk.Menu(self, tearoff=0)
        self.function_context_menu.add_command(label="Переименовать", command=self._rename_function)

        
        blocks_tab = ttk.Frame(left_notebook)
        left_notebook.add(blocks_tab, text="Basic Blocks")
        self.blocks_tree = ttk.Treeview(blocks_tab, show="tree")
        self.blocks_tree.pack(expand=True, fill=tk.BOTH)
        self.blocks_tree.bind("<Double-1>", self._on_basic_block_select)

        # --- Вкладка "Классы" ---
        classes_tab = ttk.Frame(left_notebook)
        left_notebook.add(classes_tab, text="Классы")

        self.classes_tree = ttk.Treeview(classes_tab, show="tree headings", columns=("address",))
        self.classes_tree.heading("#0", text="Имя класса")
        self.classes_tree.heading("address", text="Адрес")
        self.classes_tree.column("#0", anchor='w')
        self.classes_tree.column("address", width=120, stretch=tk.NO, anchor='w')
        self.classes_tree.pack(expand=True, fill=tk.BOTH)
        self.classes_tree.bind("<<TreeviewSelect>>", self._on_class_select)

        # --- Вкладка "Переменные" ---
        variables_tab = ttk.Frame(left_notebook)
        left_notebook.add(variables_tab, text="Переменные")

        self.variables_tree = ttk.Treeview(variables_tab, show="headings", columns=("address", "type", "value"))
        self.variables_tree.heading("address", text="Адрес")
        self.variables_tree.heading("type", text="Тип")
        self.variables_tree.heading("value", text="Значение")
        self.variables_tree.column("address", width=120, stretch=tk.NO, anchor='w')
        self.variables_tree.column("type", width=80, stretch=tk.NO, anchor='w')
        self.variables_tree.column("value", anchor='w')
        self.variables_tree.pack(expand=True, fill=tk.BOTH)
        self.variables_tree.bind("<Double-1>", self._on_variable_select)

        # --- Вкладка "Info" ---
        info_tab = ttk.Frame(left_notebook)
        left_notebook.add(info_tab, text="Info")
        
        self.info_text_area = scrolledtext.ScrolledText(info_tab, wrap=tk.WORD, relief=tk.FLAT, bd=0)
        self.info_text_area.pack(expand=True, fill=tk.BOTH, padx=2, pady=2)
        self.info_text_area.config(state=tk.DISABLED)

        # --- Вкладка "Imports" ---
        imports_main_tab = ttk.Frame(left_notebook)
        left_notebook.add(imports_main_tab, text="Imports")

        # Вкладки для импортов и экспортов
        imp_exp_notebook = ttk.Notebook(imports_main_tab)
        imp_exp_notebook.pack(expand=True, fill=tk.BOTH)

        # Вкладка "Imports"
        imports_sub_tab = ttk.Frame(imp_exp_notebook)
        imp_exp_notebook.add(imports_sub_tab, text="Imports")
        self.imports_tree = ttk.Treeview(imports_sub_tab, show="tree")
        self.imports_tree.bind("<Double-1>", self._on_import_select)
        self.imports_tree.pack(expand=True, fill=tk.BOTH)

        # Вкладка "Exports"
        exports_sub_tab = ttk.Frame(imp_exp_notebook)
        imp_exp_notebook.add(exports_sub_tab, text="Exports")
        self.exports_tree = ttk.Treeview(exports_sub_tab, show="tree")
        self.exports_tree.heading("#0", text="Address & Name")
        self.exports_tree.pack(expand=True, fill=tk.BOTH)

        # --- Вкладка "Explorer" ---
        explorer_tab = ttk.Frame(left_notebook)
        left_notebook.add(explorer_tab, text="Explorer")
        self.explorer_tree = ttk.Treeview(explorer_tab, show="tree")
        self.explorer_context_menu = tk.Menu(self, tearoff=0)
        self.explorer_context_menu.add_command(label="Извлечь...", command=self._export_from_explorer, state=tk.DISABLED)
        self.explorer_tree.bind("<Button-3>", self._show_explorer_context_menu)
        self.explorer_tree.bind("<Double-1>", self._on_explorer_double_click)
        self._selected_explorer_node: Optional[ExplorerNode] = None

        self.explorer_tree.pack(expand=True, fill=tk.BOTH)

        self.main_pane.add(left_notebook, width=300, minsize=200)

        # --- Правая панель: Листинг дизассемблера ---
        self._create_right_panel()

        # --- Регулярные выражения для подсветки операндов ---
        all_regs = [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
            "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
            "rip"
        ]
        self.reg_pattern = re.compile(r'\b(' + '|'.join(all_regs) + r')\b')
        self.hex_pattern = re.compile(r'0x[0-9a-fA-F]+')
        self.ptr_pattern = re.compile(r'\b(ptr|byte|word|dword|qword)\b')

        # --- Контекстное меню ---
        self._context_target_addr: Optional[int] = None
        self.text_area.bind("<Button-3>", self._show_context_menu)
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Показать перекрестные ссылки", command=self._show_xrefs, state=tk.DISABLED)
        self.context_menu.add_command(label="Копировать строку", command=self._copy_line, state=tk.DISABLED)

        # --- Привязка событий для кликабельных ссылок в листинге ---
        self.text_area.tag_bind("address_link", "<Button-1>", self._on_address_link_click)
        self.text_area.tag_bind("address_link", "<Enter>", lambda e: self.text_area.config(cursor="hand2"))
        self.text_area.tag_bind("address_link", "<Leave>", lambda e: self.text_area.config(cursor=""))

        # --- Панель поиска ---
        self._create_search_bar()
        self.bind_all("<Control-f>", self._toggle_search_bar)
        self.bind_all("<Escape>", self._hide_search_bar_on_escape)
        self._apply_theme()

    def _import_pefile(self):
        """Импортирует pefile и показывает ошибку в GUI, если он не найден."""
        try:
            import pefile
            return pefile
        except ImportError:
            messagebox.showerror(
                "Критическая ошибка",
                "Библиотека 'pefile' не найдена.\n\n"
                "Пожалуйста, установите ее командой:\n"
                "pip install pefile"
            )
            return None

    def _apply_theme(self):
        """Применяет светлую или темную тему ко всем элементам GUI."""
        is_dark = self.settings.get("dark_theme", False)

        # Настройки шрифта
        # Убрали кастомные шрифты, используем стандартный
        font_family = "Courier New"
        font_size = 10
        listing_font = (font_family, font_size)
        info_font = (font_family, max(8, font_size - 1)) # Шрифт для инфо-панели чуть меньше
        info_bold_font = (font_family, max(8, font_size - 1), "bold")

        style = ttk.Style(self)

        if is_dark:
            # --- Палитра темной темы ---
            bg, fg = "#2b2b2b", "#bbbbbb"
            widget_bg, select_bg = "#3c3f41", "#4f5563"
            colors = {
                "bg": bg, "fg": fg, "widget_bg": widget_bg, "select_bg": select_bg,
                "cursor": "white", "address": "#666666", "bytes": "#888888",
                "mnemonic": "#cc7832", "register": "#9876aa", "immediate": "#6897bb", "search_highlight_bg": "#55634f", "link_fg": "#6897bb", "warning_fg": "#ffb366", "stub_fg": "#c19a6b",
                "ptr": "#a5c261", "comment": "#808080", "selection_highlight": select_bg, "error_bg": "#5a2d2d",
                "error_fg": "#ff8080",
                "info_title_fg": "#cc7832", "info_key_fg": "#9876aa",
                "tree_heading_bg": "#45494a"
            }
            style.theme_use('clam')
        else:
            # --- Палитра светлой темы ---
            bg, fg = "SystemButtonFace", "black"
            widget_bg, select_bg = "white", "#cce5ff"
            colors = {
                "bg": bg, "fg": fg, "widget_bg": widget_bg, "select_bg": select_bg,
                "cursor": "black", "address": "#888888", "bytes": "gray", "stub_fg": "#8b4513",
                "mnemonic": "#0000ff", "register": "#d70000", "immediate": "#800080", "search_highlight_bg": "#b4e8b4", "link_fg": "#0000ee", "warning_fg": "#d9534f",
                "ptr": "#008b8b", "comment": "#008000", "selection_highlight": "#fff8a5", "error_bg": "#ffdddd",
                "error_fg": "#c00000",
                "info_title_fg": "black", "info_key_fg": "black",
                "tree_heading_bg": bg
            }
            style.theme_use('default')
        
        self.colors = colors
        # Применение стилей
        self.config(bg=colors["bg"])
        style.configure('.', background=colors["bg"], foreground=colors["fg"], borderwidth=1, relief=tk.FLAT)
        style.configure('TFrame', background=colors["bg"])
        style.configure('TButton', background=colors["widget_bg"], foreground=colors["fg"], borderwidth=1)
        style.map('TButton', background=[('active', colors["select_bg"])])
        style.configure('TNotebook', background=colors["bg"], borderwidth=0)
        style.configure('TNotebook.Tab', background=colors["widget_bg"], foreground=colors["fg"], padding=[5, 2], borderwidth=0)
        style.map('TNotebook.Tab', background=[('selected', colors["bg"])])
        style.configure("Treeview", background=colors["widget_bg"], foreground=colors["fg"], fieldbackground=colors["widget_bg"], rowheight=22)
        style.map('Treeview', background=[('selected', colors["select_bg"])])
        style.configure("Treeview.Heading", background=colors["tree_heading_bg"], foreground=colors["fg"], relief="flat")
        style.map("Treeview.Heading", relief=[('active','groove'),('pressed','sunken')])

        # Прямая настройка виджетов
        self.main_pane.config(bg=colors["bg"], sashrelief=tk.FLAT)
        for text_widget in [self.text_area, self.info_text_area]:
            text_widget.config(background=colors["widget_bg"], foreground=colors["fg"], insertbackground=colors["cursor"], selectbackground=colors["select_bg"])
        
        # Применяем шрифты
        self.text_area.config(font=listing_font)
        self.info_text_area.config(font=info_font)

        # Обновление тегов
        tag_colors = {"address": "address", "bytes": "bytes", "mnemonic": "mnemonic", "register": "register", "immediate": "immediate", "ptr": "ptr", "comment": "comment"}
        for tag, color_key in tag_colors.items():
            self.text_area.tag_configure(tag, foreground=colors[color_key])
        self.text_area.tag_configure("address_link", foreground=colors["link_fg"], underline=True)

        # Обновляем жирный шрифт для мнемоник
        self.text_area.tag_configure("mnemonic", font=(font_family, font_size, "bold"))
        self.text_area.tag_configure("selection_highlight", background=colors["selection_highlight"])
        self.text_area.tag_configure("search_highlight", background=colors["search_highlight_bg"])
        self.text_area.tag_configure("error_line", background=colors["error_bg"])

        # Конфигурируем теги для деревьев
        for tree in [self.functions_tree, self.blocks_tree, self.classes_tree]:
            tree.tag_configure("has_error", foreground=colors["error_fg"])
            tree.tag_configure("is_stub", foreground=colors["stub_fg"])

        # Обновляем теги для инфо-панели
        self.info_text_area.tag_configure("title", foreground=colors["info_title_fg"], font=(font_family, font_size, "bold", "underline"))
        self.info_text_area.tag_configure("key", foreground=colors["info_key_fg"], font=info_bold_font)

        # Стиль для предупреждающих надписей
        style.configure("Warning.TLabel", foreground=colors["warning_fg"], font=(font_family, max(8, font_size - 2), "bold"))

    def _get_default_settings(self):
        """Возвращает словарь с настройками по умолчанию."""
        return {
            "show_padding": False,
            "dark_theme": False,
            "show_bytes": True,
            "uppercase_mnemonics": False,
            "use_prologue_heuristic": True,
            "use_separator_heuristic": True,
            "use_padding_heuristic": True,
            "analyze_basic_blocks": True,
            "analyze_xrefs": True,
            "analyze_variables": True,
            "analyze_classes": True,
            "show_errors_highlight": True,
            "analyze_anti_debug": False,
            "auto_section_search": True,
            "analyze_all_sections_for_compiler": True,
        }

    def _load_settings(self):
        """Загружает настройки из файла settings.json."""
        defaults = self._get_default_settings()
        try:
            with open("settings.json", "r") as f:
                loaded_settings = json.load(f)
                defaults.update(loaded_settings)
        except (FileNotFoundError, json.JSONDecodeError):
            pass # Используем значения по умолчанию
        return defaults

    def _save_settings(self):
        """Сохраняет текущие настройки в файл settings.json."""
        try:
            with open("settings.json", "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            messagebox.showerror("Ошибка сохранения настроек", f"Не удалось сохранить настройки.\n{e}")

    def _open_settings_window(self):
        """Открывает окно настроек."""
        SettingsWindow(self, self.settings, self._get_default_settings())

    def _create_search_bar(self):
        """Создает виджеты для панели поиска."""
        self.search_frame = ttk.Frame(self, padding=5)
        
        search_label = ttk.Label(self.search_frame, text="Поиск:")
        search_label.pack(side=tk.LEFT, padx=(0, 5))

        self.search_entry = ttk.Entry(self.search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind("<Return>", self._find_next)
        self.search_entry.bind("<KP_Enter>", self._find_next)

        find_next_button = ttk.Button(self.search_frame, text="Далее", command=self._find_next)
        find_next_button.pack(side=tk.LEFT, padx=(5, 0))

        find_prev_button = ttk.Button(self.search_frame, text="Назад", command=self._find_prev)
        find_prev_button.pack(side=tk.LEFT, padx=(5, 0))

        close_button = ttk.Button(self.search_frame, text="×", command=self._toggle_search_bar, width=3)
        close_button.pack(side=tk.LEFT, padx=(5, 0))

    def _toggle_search_bar(self, event=None):
        """Показывает или скрывает панель поиска."""
        if self.search_frame.winfo_viewable():
            self.search_frame.pack_forget()
            self.text_area.focus_set()
            self.text_area.tag_remove("search_highlight", "1.0", tk.END)
        else:
            self.search_frame.pack(side=tk.BOTTOM, fill=tk.X, before=self.top_frame, anchor='s')
            self.search_frame.lift()
            self.search_entry.focus_set()
            self.search_entry.selection_range(0, tk.END)

    def _hide_search_bar_on_escape(self, event=None):
        """Скрывает панель поиска по нажатию Escape."""
        if self.search_frame.winfo_viewable():
            self._toggle_search_bar()

    def _find_next(self, event=None):
        self._find(forward=True)

    def _find_prev(self, event=None):
        self._find(forward=False)

    def _find(self, forward: bool):
        """Основная логика поиска текста в листинге."""
        query = self.search_entry.get()
        if not query: return

        self.text_area.tag_remove("search_highlight", "1.0", tk.END)
        
        start_pos = self.text_area.index(tk.INSERT)
        if forward:
            pos = self.text_area.search(query, f"{start_pos}+1c", stopindex=tk.END, nocase=True)
            if not pos: pos = self.text_area.search(query, "1.0", stopindex=tk.END, nocase=True) # Wrap around
        else:
            pos = self.text_area.search(query, start_pos, stopindex="1.0", nocase=True, backwards=True)
            if not pos: pos = self.text_area.search(query, tk.END, stopindex="1.0", nocase=True, backwards=True) # Wrap around

        if pos:
            end_pos = f"{pos}+{len(query)}c"
            self.text_area.tag_add("search_highlight", pos, end_pos)
            self.text_area.see(pos)
            self.text_area.mark_set(tk.INSERT, pos)
            self.search_entry.focus_set()
        else:
            messagebox.showinfo("Поиск", f"Не найдено совпадений для '{query}'", parent=self)

    def _create_right_panel(self):
        """Создает правую панель с листингом дизассемблера."""
        listing_frame = ttk.Frame(self.main_pane)
        self.text_area = scrolledtext.ScrolledText(listing_frame, wrap=tk.NONE)
        self.text_area.pack(expand=True, fill=tk.BOTH)
        self.text_area.config(state=tk.DISABLED)
        self.main_pane.add(listing_frame, minsize=400)

    def open_file(self):
        """Открывает диалог выбора файла и запускает дизассемблирование."""
        filepath = filedialog.askopenfilename(
            title="Выберите PE файл",
            filetypes=(("Executable files", "*.exe *.dll"), ("All files", "*.*"))
        )
        if not filepath:
            return

        # Сбрасываем пользовательские метки при открытии нового файла
        self.user_labels.clear()
        self.current_filepath = filepath
        try:
            self.pe_object = self.pefile.PE(self.current_filepath)
        except self.pefile.PEFormatError as e:
            messagebox.showerror("Ошибка", f"Файл не является валидным PE файлом.\n{e}")
            self.pe_object = None
            return
        except FileNotFoundError:
            messagebox.showerror("Ошибка", f"Файл не найден по пути '{self.current_filepath}'")
            self.pe_object = None
            return
        self._disassemble_and_analyze()

    def _disassemble_and_analyze(self):
        """Читает PE файл, дизассемблирует и отображает результат в текстовом поле."""
        if not self.pe_object:
            return

        if self.settings.get("auto_section_search", True):
            # --- Автоматический поиск секции ---
            code_section = None
            entry_point_rva = 0
            try:
                entry_point_rva = self.pe_object.OPTIONAL_HEADER.AddressOfEntryPoint
                code_section = self.pe_object.get_section_by_rva(entry_point_rva)
            except (AttributeError, TypeError):
                pass

            if not code_section:
                messagebox.showwarning(
                    "Нестандартная точка входа",
                    f"Точка входа (RVA: 0x{entry_point_rva:x}) находится вне известных секций. "
                    "Файл может быть упакован, поврежден или иметь необычную структуру.\n\n"
                    "Будет предпринята попытка анализа первой исполняемой секции."
                )
                for section in self.pe_object.sections:
                    if section.Characteristics & self.pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
                        code_section = section
                        break
        else:
            # --- Ручной выбор секции ---
            dialog = SectionSelectionWindow(self, self.pe_object)
            self.wait_window(dialog) # Ждем закрытия диалога
            code_section = dialog.selected_section

        if not code_section:
            # Если автоматический поиск не дал результатов, показываем ошибку.
            # Если ручной - пользователь просто закрыл окно, ничего не делаем.
            if self.settings.get("auto_section_search", True):
                messagebox.showerror("Критическая ошибка", "Не удалось найти ни одной исполняемой секции в файле. Анализ невозможен.")
            return
        
        section_name_str = code_section.Name.decode(errors='ignore').strip('\x00')
        if not (code_section.Characteristics & self.pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']):
            messagebox.showwarning(
                "Предупреждение",
                f"Секция '{section_name_str}', содержащая точку входа, не помечена как исполняемая. "
                "Анализ может быть некорректным."
            )

        self.section_name = section_name_str
        self.base_address = self.pe_object.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
        self.title(f"Vexapay Disassembler - {os.path.basename(self.current_filepath)} [{section_name_str}]")

        # Проверяем, является ли файл .NET сборкой, и пропускаем нативный дизассемблер
        if self.pe_object and is_dotnet_assembly(self.pe_object):
            self.instructions = []
        else:
            bytecode = code_section.get_data()
            dis = Disassembler(bytecode, base_address=self.base_address)
            self.instructions = dis.disassemble()

        # Новый шаг: интеллектуальный анализ ошибок.
        flag_consecutive_errors(self.instructions)
        self.address_to_instruction = {instr.address: instr for instr in self.instructions}

        self._run_analysis_and_populate_views()

    def _run_analysis_and_populate_views(self):
        """Запускает анализ и заполняет все представления (деревья, листинг)."""
        if not self.pe_object or not self.instructions:
            return

        # --- Анализ ---
        analyze_all_sections = self.settings.get("analyze_all_sections_for_compiler", True)
        self.file_info = analyze_pe_info(self.pe_object, analyze_all_sections=analyze_all_sections)
        self.file_structure = analyze_structure(self.pe_object, self.file_info)

        # Анализ на анти-отладочные техники (если включено в настройках)
        if self.settings.get("analyze_anti_debug", False):
            self.anti_debug_results = analyze_anti_debug(
                self.instructions,
                self.file_info.imports if self.file_info else None
            )
        else:
            self.anti_debug_results = []

        if self.settings.get("analyze_xrefs", True):
            # Улучшение: передаем диапазон адресов модуля для более точного поиска ссылок
            valid_addr_min = self.pe_object.OPTIONAL_HEADER.ImageBase
            valid_addr_max = valid_addr_min + self.pe_object.OPTIONAL_HEADER.SizeOfImage
            self.xrefs = find_xrefs(self.instructions, (valid_addr_min, valid_addr_max))
        else:
            self.xrefs = {}

        entry_point_va = 0
        try:
            entry_point_va = self.pe_object.OPTIONAL_HEADER.ImageBase + self.pe_object.OPTIONAL_HEADER.AddressOfEntryPoint
        except (AttributeError, TypeError):
            pass

        self.functions = find_functions(
            self.instructions,
            entry_point=entry_point_va if entry_point_va != 0 else None,
            user_labels=self.user_labels,
            exports=self.file_info.exports if self.file_info else None,
            use_prologues=self.settings.get("use_prologue_heuristic", True),
            use_separators=self.settings.get("use_separator_heuristic", True),
            use_padding=self.settings.get("use_padding_heuristic", True),
            analyze_blocks=self.settings.get("analyze_basic_blocks", True),
        )
        self.function_map = {f.address: f for f in self.functions}

        if self.settings.get("analyze_classes", True):
            self.classes = find_classes(self.pe_object, self.file_info)
        else:
            self.classes = []

        if self.settings.get("analyze_variables", True):
            self.variables = find_variables(self.instructions, self.pe_object)
        else:
            self.variables = []

        # --- Заполнение UI ---
        self._populate_info_tab()
        self._populate_explorer_tree()
        self._populate_basic_blocks_tree()
        self._populate_functions_tree()
        self._populate_imports_exports_trees()
        self._populate_classes_tree()
        self._populate_variables_tree()
        self._redisplay_listing()
        self.export_button.config(state=tk.NORMAL)

        # Приятное улучшение: автоматически прокручиваем к точке входа после анализа
        try:
            entry_point_va = self.pe_object.OPTIONAL_HEADER.ImageBase + self.pe_object.OPTIONAL_HEADER.AddressOfEntryPoint
            self._scroll_to_address(entry_point_va)
        except (AttributeError, TypeError):
            pass # Ничего страшного, если не удалось

    def _redisplay_listing(self):
        """Перерисовывает листинг с учетом текущих настроек, не перезапуская анализ."""
        if not self.current_filepath:
            return

        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete("1.0", tk.END)
        self.address_to_line.clear()
        self.line_to_instruction.clear()

        # Специальное сообщение для сборок .NET, так как их нельзя дизассемблировать как нативный код
        if self.pe_object and is_dotnet_assembly(self.pe_object):
            header = f"; --- Анализ сборки .NET: {os.path.basename(self.current_filepath)} ---\n\n"
            message = (
                "; Это сборка .NET. Основной код представлен в виде Common Intermediate Language (CIL),\n"
                "; а не в виде нативного кода x86. Он компилируется в машинный код (JIT) во время выполнения.\n\n"
                "; Полноценное дизассемблирование CIL не поддерживается. Вместо этого, используйте вкладки:\n"
                ";  - 'Классы' для просмотра управляемых классов и методов.\n"
                ";  - 'Info' для общей информации о сборке.\n"
                ";  - 'Explorer' для просмотра структуры файла.\n"
            )
            
            self.text_area.insert(tk.END, header, "comment")
            self.text_area.insert(tk.END, message, "comment")
            
            self.text_area.config(state=tk.DISABLED)
            return

        self._insert_header()

        for instr in self._get_filtered_instructions():
            self._insert_and_highlight_instruction(instr)

        self.text_area.config(state=tk.DISABLED)

    def _get_filtered_instructions(self) -> list[Instruction]:
        """Возвращает список инструкций с учетом фильтра байт-заполнителей."""
        if self.settings.get("show_padding", False):
            return self.instructions
        return [instr for instr in self.instructions if instr.bytes not in (b'\xcc', b'\x90')]

    def _populate_functions_tree(self):
        """Очищает и заполняет дерево функций."""
        for item in self.functions_tree.get_children():
            self.functions_tree.delete(item)
        
        if not self.functions:
            # iid должен быть строкой, чтобы избежать конфликтов
            self.functions_tree.insert("", "end", text="Функции не найдены", iid="fn_not_found", open=False)
            return

        for func in self.functions:
            # Используем префикс для iid, чтобы избежать конфликтов и сделать код понятнее
            iid = f"fn_{func.address}"
            tags = []
            if func.has_errors and self.settings.get("show_errors_highlight", True):
                tags.append("has_error")
            if func.is_stub:
                tags.append("is_stub")
            self.functions_tree.insert("", "end", text=f"0x{func.address:x}", values=(func.name,), iid=iid, tags=tuple(tags))

    def _populate_basic_blocks_tree(self):
        """Очищает и заполняет дерево базовых блоков."""
        for item in self.blocks_tree.get_children():
            self.blocks_tree.delete(item)

        if not self.functions or not self.settings.get("analyze_basic_blocks", True):
            self.blocks_tree.insert("", "end", text="Анализ блоков отключен", iid="bb_disabled")
            return

        for func in self.functions:
            func_iid = f"bb_fn_{func.address}"
            func_tags = ("has_error",) if func.has_errors and self.settings.get("show_errors_highlight", True) else ()
            func_node = self.blocks_tree.insert("", "end", text=f"▶ {func.name}", iid=func_iid, open=False, tags=func_tags)
            
            for i, block in enumerate(func.blocks):
                block_iid = f"bb_{block.start_address}"
                block_tags = ("has_error",) if block.has_errors and self.settings.get("show_errors_highlight", True) else ()
                block_text = f"  Блок {i+1} (0x{block.start_address:x} - 0x{block.end_address:x})"
                self.blocks_tree.insert(func_node, "end", text=block_text, iid=block_iid, tags=block_tags)

    def _populate_classes_tree(self):
        """Очищает и заполняет дерево классов."""
        for item in self.classes_tree.get_children():
            self.classes_tree.delete(item)
        
        if not self.classes:
            self.classes_tree.insert("", "end", text="Классы не найдены", iid="cls_not_found", open=False)
            return

        for cls in self.classes:
            # Родительский узел для класса
            class_iid = f"cls_{cls.vtable_address}"
            
            # Для .NET vtable_address - это RID, а не адрес. Не показываем его.
            is_dotnet = bool(cls.method_names)
            vtable_str = f"vtable: 0x{cls.vtable_address:x}" if cls.vtable_address != 0 and not is_dotnet else ""
            
            tags = ("is_stub",) if cls.is_stub else ()
            class_node = self.classes_tree.insert(
                "", "end", text=cls.name,
                values=(vtable_str,),
                iid=class_iid,
                tags=tags
            )

            # Добавляем узлы для базовых классов
            if cls.base_classes:
                bases_node_iid = f"bases_{cls.vtable_address}"
                bases_node = self.classes_tree.insert(class_node, "end", text="[Base Classes]", iid=bases_node_iid, open=True)
                for base_name in cls.base_classes:
                    base_iid = f"base_{cls.vtable_address}_{base_name}"
                    self.classes_tree.insert(bases_node, "end", text=base_name, iid=base_iid)

            # Группируем методы под отдельным узлом для наглядности
            if cls.methods:
                # Для .NET используем другое название
                methods_node_name = "[Methods]" if is_dotnet else "[Virtual Methods]"
                methods_node_iid = f"methods_{cls.vtable_address}"
                methods_node = self.classes_tree.insert(class_node, "end", text=methods_node_name, iid=methods_node_iid, open=False)
                for method_addr in cls.methods:
                    method_iid = f"method_{method_addr}"
                    # Используем имя метода из method_names, если оно есть
                    method_name = cls.method_names.get(method_addr, f"method_{method_addr:x}")
                    addr_text = f"0x{method_addr:x}"
                    
                    self.classes_tree.insert(
                        methods_node, "end", text=method_name,
                        values=(addr_text,),
                        iid=method_iid
                    )

    def _populate_variables_tree(self):
        """Очищает и заполняет дерево переменных."""
        for item in self.variables_tree.get_children():
            self.variables_tree.delete(item)
        
        if not self.variables:
            self.variables_tree.insert("", "end", values=("Переменные не найдены", "", ""))
            return

        for var in self.variables:
            # iid - это адрес, должен быть строкой
            iid = str(var.address)
            self.variables_tree.insert(
                "", "end",
                values=(f"0x{var.address:x}", var.type, var.value),
                iid=iid
            )

    def _populate_info_tab(self):
        """Заполняет вкладку 'Info' данными из анализатора."""
        self.info_text_area.config(state=tk.NORMAL)
        self.info_text_area.delete("1.0", tk.END)

        if not self.file_info:
            self.info_text_area.insert(tk.END, "Информация не доступна.")
            self.info_text_area.config(state=tk.DISABLED)
            return

        info = self.file_info

        # Hashes
        self.info_text_area.insert(tk.END, "Hashes\n", "title")
        for name, value in info.hashes.items():
            self.info_text_area.insert(tk.END, f"{name.upper():<8}", "key")
            self.info_text_area.insert(tk.END, f"{value}\n")
        self.info_text_area.insert(tk.END, "\n")

        # General Info
        self.info_text_area.insert(tk.END, "General\n", "title")
        for name, value in info.general.items():
            self.info_text_area.insert(tk.END, f"{name:<16}", "key")
            self.info_text_area.insert(tk.END, f"{str(value)}\n")
        self.info_text_area.insert(tk.END, "\n")

        # Analysis
        self.info_text_area.insert(tk.END, "Analysis\n", "title")
        self.info_text_area.insert(tk.END, f"{'Compiler':<16}", "key")
        self.info_text_area.insert(tk.END, f"{info.compiler}\n")
        self.info_text_area.insert(tk.END, f"{'Language':<16}", "key")
        self.info_text_area.insert(tk.END, f"{info.language}\n")
        self.info_text_area.insert(tk.END, "\n")
        if info.packer != "N/A":
            self.info_text_area.insert(tk.END, f"{'Packer':<16}", "key")
            self.info_text_area.insert(tk.END, f"{info.packer}\n")
            self.info_text_area.insert(tk.END, "\n")

        # Security Features
        self.info_text_area.insert(tk.END, "Security Features\n", "title")
        sec = info.security
        features = [
            ("ASLR (Dynamic Base)", sec.aslr),
            ("DEP (NX Compat)", sec.dep),
            ("SafeSEH", sec.safe_seh),
            ("Control Flow Guard (CFG)", sec.control_flow_guard),
            ("Authenticode Signature", sec.authenticode),
            ("TLS Callbacks", sec.tls_callbacks),
            ("High Entropy Sections", sec.high_entropy_sections),
        ]
        for name, present in features:
            status = "Present" if present else "Absent"
            color = "comment" if present else "error_fg"
            self.info_text_area.insert(tk.END, f"{name:<28}", "key")
            self.info_text_area.insert(tk.END, f"{status}\n", color)
        self.info_text_area.insert(tk.END, "\n")

        # Sections
        self.info_text_area.insert(tk.END, "Sections\n", "title")
        header = f"{'Name':<10} {'Address':<18} {'Size':<12} {'Entropy':<10} {'Flags'}\n"
        self.info_text_area.insert(tk.END, header, "key")
        self.info_text_area.insert(tk.END, "-"*len(header) + "\n")
        for s in info.sections:
            name_str = f"{s.name:<10}"
            addr_str = f"0x{s.virtual_address:<16x}"
            size_str = f"{s.virtual_size:<12}"
            entropy_str = f"{s.entropy:<9.2f} "
            self.info_text_area.insert(tk.END, f"{name_str} {addr_str} {size_str} {entropy_str} {' '.join(s.characteristics)}\n")

        # Anti-Analysis
        if self.anti_debug_results:
            self.info_text_area.insert(tk.END, "Anti-Analysis\n", "title")
            for result in self.anti_debug_results:
                addr_text = f"0x{result.address:x}"
                tag_name = f"addr_link_{result.address}"
                self.info_text_area.insert(tk.END, f"{addr_text:<16}", ("key", tag_name))
                self.info_text_area.insert(tk.END, f"{result.name} - {result.description}\n")
                self.info_text_area.tag_config(tag_name, foreground=self.colors["link_fg"], underline=True)
                self.info_text_area.tag_bind(tag_name, "<Button-1>", lambda e, addr=result.address: self._scroll_to_address(addr))
                self.info_text_area.tag_bind(tag_name, "<Enter>", lambda e: self.info_text_area.config(cursor="hand2"))
                self.info_text_area.tag_bind(tag_name, "<Leave>", lambda e: self.info_text_area.config(cursor=""))

        self.info_text_area.config(state=tk.DISABLED)

    def _populate_imports_exports_trees(self):
        """Заполняет деревья импортов и экспортов."""
        # Очистка
        for item in self.imports_tree.get_children():
            self.imports_tree.delete(item)
        for item in self.exports_tree.get_children():
            self.exports_tree.delete(item)

        if not self.file_info:
            return

        # Заполнение импортов
        if self.file_info.imports:
            for dll, funcs in sorted(self.file_info.imports.items()):
                dll_node = self.imports_tree.insert("", "end", text=dll, open=False)
                for func in sorted(funcs, key=lambda f: f.name):
                    iid = f"imp_{func.address}"
                    self.imports_tree.insert(dll_node, "end", text=func.name, iid=iid)
        else:
            self.imports_tree.insert("", "end", text="Импорты не найдены")

        # Заполнение экспортов
        if self.file_info.exports:
            for addr, func_name in sorted(self.file_info.exports.items()):
                self.exports_tree.insert("", "end", text=f"0x{addr:x}  {func_name}")
        else:
            self.exports_tree.insert("", "end", text="Экспорты не найдены")

    def _populate_explorer_tree(self):
        """Заполняет дерево проводника структурой файла."""
        for item in self.explorer_tree.get_children():
            self.explorer_tree.delete(item)
        self.explorer_iid_to_node.clear()

        if not self.file_structure:
            self.explorer_tree.insert("", "end", text="Структура не найдена", iid="exp_not_found")
            return

        def add_node(parent_iid, node: ExplorerNode, is_root: bool = False):
            # Используем текстовые "иконки" для наглядности
            prefix = "📁" if node.node_type == 'directory' else "📄"
            node_text = f"{prefix} {node.name}"
            
            # Для файлов можно добавить размер
            if node.node_type == 'file' and node.size > 0:
                size_str = f" ({node.size // 1024} KB)" if node.size >= 1024 else f" ({node.size} B)"
                node_text += size_str

            node_iid = self.explorer_tree.insert(parent_iid, "end", text=node_text, open=is_root)
            self.explorer_iid_to_node[node_iid] = node
            
            # Рекурсивно добавляем дочерние узлы
            for child in sorted(node.children, key=lambda n: (n.node_type, n.name)):
                add_node(node_iid, child)

        add_node("", self.file_structure, is_root=True)

    def _on_function_select(self, event):
        """Обрабатывает клик по элементу в дереве функций и прокручивает текст."""
        selected_items = self.functions_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        
        # iid имеет формат "fn_<адрес>"
        if not item_id.startswith("fn_"):
            return

        try:
            address = int(item_id.split('_', 1)[1])
            self._scroll_to_address(address)
        except (ValueError, TypeError, IndexError):
            return # Ошибка парсинга iid

    def _on_basic_block_select(self, event):
        """Обрабатывает двойной клик по элементу в дереве базовых блоков."""
        selected_items = self.blocks_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        if not item_id.startswith("bb_"):
            return

        try:
            address = int(item_id.split('_', 1)[1])
            self._scroll_to_address(address)
        except (ValueError, TypeError, IndexError):
            pass

    def _on_class_select(self, event):
        """Обрабатывает клик по элементу в дереве классов и прокручивает текст."""
        selected_items = self.classes_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        
        # iid имеет формат "cls_<адрес>" или "method_<адрес>"
        try:
            id_type, addr_str = item_id.split('_', 1)
            address = int(addr_str)
            
            # Ищем класс, к которому относится этот метод, чтобы проверить, не .NET ли он.
            is_dotnet_method = False
            if id_type == 'method':
                for cls in self.classes:
                    if address in cls.methods:
                        if cls.method_names: # Признак .NET класса
                            is_dotnet_method = True
                        break
            
            # Для методов .NET не нужно прокручивать, т.к. это CIL, а не нативный код.
            if is_dotnet_method:
                return

            # Адрес vtable может не быть в листинге кода, но адрес метода должен быть.
            self._scroll_to_address(address)

        except (ValueError, TypeError, IndexError):
            return # Клик по "Не найдено" или неверный формат iid

    def _on_variable_select(self, event):
        """Обрабатывает двойной клик по переменной и показывает ее использования."""
        selected_items = self.variables_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0] # iid - это адрес
        try:
            address = int(item_id)
            # Находим объект переменной
            variable = next((v for v in self.variables if v.address == address), None)
            if not variable or not variable.xrefs:
                messagebox.showinfo("Перекрестные ссылки", f"Не найдено ссылок на переменную по адресу 0x{address:x}")
                return

            # Если одна ссылка - переходим. Если несколько - показываем окно.
            if len(variable.xrefs) == 1:
                self._scroll_to_address(variable.xrefs[0])
            else:
                XrefsWindow(self, address, set(variable.xrefs), self.address_to_instruction, self.functions)
        except (ValueError, TypeError, StopIteration):
            return # Это может произойти при клике на элемент "не найдено"

    def _scroll_to_address(self, address: int):
        """Прокручивает листинг к указанному адресу."""
        line_index = self.address_to_line.get(address)
        if line_index:
            self.text_area.see(line_index)
            self.text_area.tag_remove("selection_highlight", "1.0", tk.END)
            self.text_area.tag_add("selection_highlight", line_index, f"{line_index} lineend")

    def _on_import_select(self, event):
        """Обрабатывает двойной клик по импортируемой функции и ищет ее использования."""
        selected_items = self.imports_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        if not item_id.startswith("imp_"):
            return

        try:
            iat_address = int(item_id.split('_', 1)[1])
        except (ValueError, TypeError, IndexError):
            return

        # Ищем перекрестные ссылки на адрес этой функции в IAT
        source_addrs = self.xrefs.get(iat_address)
        
        if not source_addrs:
            messagebox.showinfo("Перекрестные ссылки", f"Не найдено ссылок на импорт (адрес IAT: 0x{iat_address:x})")
            return
        
        # Если ссылка одна, просто переходим к ней. Если несколько - показываем окно выбора.
        if len(source_addrs) == 1:
            self._scroll_to_address(list(source_addrs)[0])
        else:
            XrefsWindow(self, iat_address, source_addrs, self.address_to_instruction, self.functions)

    def _show_explorer_context_menu(self, event):
        """Показывает контекстное меню для проводника."""
        self._selected_explorer_node = None
        iid = self.explorer_tree.identify_row(event.y)
        if not iid:
            return
        
        # Выделяем элемент под курсором
        self.explorer_tree.selection_set(iid)
        
        node = self.explorer_iid_to_node.get(iid)
        # Включаем опцию, только если узел можно извлечь
        can_export = node and (
            (node.node_type == 'file' and node.data_len > 0) or
            (node.node_type == 'directory' and node.children)
        )

        if can_export:
            self._selected_explorer_node = node
            self.explorer_context_menu.entryconfig("Извлечь...", state=tk.NORMAL)
        else:
            self.explorer_context_menu.entryconfig("Извлечь...", state=tk.DISABLED)
            
        self.explorer_context_menu.tk_popup(event.x_root, event.y_root)

    def _export_from_explorer(self):
        """Запускает процесс извлечения файла или папки из проводника."""
        if not self._selected_explorer_node or not self.pe_object:
            return
        
        node = self._selected_explorer_node
        
        if node.node_type == 'file':
            self._export_explorer_file(node)
        elif node.node_type == 'directory':
            self._export_explorer_directory(node)

    def _export_explorer_file(self, node: ExplorerNode):
        """Извлекает один файл."""
        filepath = filedialog.asksaveasfilename(
            title=f"Сохранить файл '{node.name}'",
            initialfile=node.name,
            defaultextension=".*"
        )
        if not filepath: return
        
        try:
            file_data = self.pe_object.get_data(node.data_pos, node.data_len)
            with open(filepath, "wb") as f:
                f.write(file_data)
            messagebox.showinfo("Готово", f"Файл '{node.name}' успешно извлечен.")
        except Exception as e:
            messagebox.showerror("Ошибка извлечения", f"Не удалось извлечь файл.\n{e}")

    def _export_explorer_directory(self, node: ExplorerNode):
        """Рекурсивно извлекает содержимое директории."""
        dir_path = filedialog.askdirectory(title=f"Выберите папку для извлечения '{node.name}'")
        if not dir_path: return

        target_path = os.path.join(dir_path, node.name)
        try:
            os.makedirs(target_path, exist_ok=True)
            for child in node.children:
                self._save_node_recursively(child, target_path)

            messagebox.showinfo("Готово", f"Папка '{node.name}' успешно извлечена в:\n{dir_path}")
        except Exception as e:
            messagebox.showerror("Ошибка извлечения", f"Не удалось извлечь папку.\n{e}")

    def _save_node_recursively(self, node: ExplorerNode, current_path: str):
        """Вспомогательная рекурсивная функция для сохранения узлов."""
        node_path = os.path.join(current_path, node.name)
        if node.node_type == 'directory':
            os.makedirs(node_path, exist_ok=True)
            for child in node.children:
                self._save_node_recursively(child, node_path)
        elif node.node_type == 'file' and node.data_len > 0:
            file_data = self.pe_object.get_data(node.data_pos, node.data_len)
            with open(node_path, "wb") as f:
                f.write(file_data)

    def _insert_header(self):
        """Вставляет заголовок с информацией о файле."""
        header = f"; --- Дизассемблирование секции {self.section_name} из '{os.path.basename(self.current_filepath)}' ---\n"
        header += f"; --- Базовый адрес: 0x{self.base_address:x} ---\n\n"
        
        header_start_index = self.text_area.index(tk.END)
        self.text_area.insert(tk.END, header)
        self.text_area.tag_add("comment", header_start_index, f"{header_start_index} + {len(header)} chars")


    def _insert_and_highlight_instruction(self, instr: Instruction):
        """Вставляет одну инструкцию и применяет подсветку синтаксиса."""
        # Запоминаем начальный индекс строки для текущего адреса для навигации
        start_index = self.text_area.index(tk.END)
        line_num = start_index.split('.')[0]
        self.line_to_instruction[line_num] = instr
        self.address_to_line[instr.address] = start_index.split('.')[0] + ".0"

        # Мы собираем строку по частям, чтобы применить теги к каждой части отдельно
        addr_str = f"0x{instr.address:08x}: "
        
        bytes_str = ""
        if self.settings.get("show_bytes", True):
            hex_bytes = ' '.join(f'{b:02x}' for b in instr.bytes)
            bytes_str = f"{hex_bytes:<24} "

        mnemonic = instr.mnemonic
        if self.settings.get("uppercase_mnemonics", False):
            mnemonic = mnemonic.upper()
        mnemonic_str = f"{mnemonic} "

        # Проверяем, не является ли операнд вызовом известной функции
        operands_str = self._resolve_operand_names(instr)

        # Вставляем части и сразу применяем теги
        self.text_area.insert(tk.END, addr_str, "address")
        if bytes_str:
            self.text_area.insert(tk.END, bytes_str, "bytes")

        self.text_area.insert(tk.END, mnemonic_str, "mnemonic")

        # Для операндов нужна более сложная подсветка на основе регулярных выражений
        operands_start_index = self.text_area.index(tk.END)
        self.text_area.insert(tk.END, operands_str)
        self._highlight_substrings(self.ptr_pattern, "ptr", operands_start_index, operands_str)
        self._highlight_substrings(self.reg_pattern, "register", operands_start_index, operands_str)

        # Умная подсветка для шестнадцатеричных значений (адреса vs. непосредственные операнды)
        for match in self.hex_pattern.finditer(operands_str):
            start, end = match.start(), match.end()
            hex_val_str = match.group(0)
            start_pos = f"{operands_start_index} + {start} chars"
            end_pos = f"{operands_start_index} + {end} chars"

            try:
                addr = int(hex_val_str, 16)
                # Проверяем, является ли значение валидным адресом в пределах PE-файла
                is_known_address = (
                    self.pe_object and
                    self.pe_object.OPTIONAL_HEADER.ImageBase <= addr < self.pe_object.OPTIONAL_HEADER.ImageBase + self.pe_object.OPTIONAL_HEADER.SizeOfImage
                )

                if is_known_address:
                    self.text_area.tag_add("address_link", start_pos, end_pos)
                else:
                    self.text_area.tag_add("immediate", start_pos, end_pos)
            except (ValueError, TypeError):
                self.text_area.tag_add("immediate", start_pos, end_pos)

        self.text_area.insert(tk.END, "\n")

        # Применяем тег ошибки ко всей строке, если необходимо
        if instr.is_error:
            if self.settings.get("show_errors_highlight", True):
                line_start = start_index.split('.')[0] + ".0"
                self.text_area.tag_add("error_line", line_start, f"{line_start} lineend")

    def _resolve_operand_names(self, instr: Instruction) -> str:
        """Заменяет адреса в операндах на имена функций, если они известны."""
        if instr.mnemonic.startswith('call') or instr.mnemonic.startswith('j'):
            try:
                target_addr = int(instr.operands, 16)
                if target_addr in self.function_map:
                    return self.function_map[target_addr].name
            except (ValueError, TypeError):
                # Операнд не является простым адресом (например, 'rax')
                pass
        return instr.operands

    def _highlight_substrings(self, pattern: re.Pattern, tag: str, start_index: str, text: str):
        """Находит все совпадения паттерна в тексте и применяет тег."""
        for match in pattern.finditer(text):
            start = match.start()
            end = match.end()
            self.text_area.tag_add(tag, f"{start_index} + {start} chars", f"{start_index} + {end} chars")

    def export_asm(self):
        """Открывает диалог сохранения и экспортирует текст из текстового поля."""
        if not self.current_filepath:
            return
        
        base_name = os.path.basename(self.current_filepath)
        default_filename = os.path.splitext(base_name)[0] + '.asm'

        filepath = filedialog.asksaveasfilename(
            title="Сохранить как...",
            initialfile=default_filename,
            defaultextension=".asm",
            filetypes=(("Assembly files", "*.asm"), ("Text files", "*.txt"), ("All files", "*.*"))
        )
        if not filepath:
            return

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(self.text_area.get("1.0", tk.END))
            messagebox.showinfo("Готово", f"Результат сохранен в файл:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Ошибка сохранения", f"Не удалось сохранить файл.\n{e}")

    def _copy_line(self):
        """Копирует текст выбранной строки в буфер обмена."""
        if self._context_line_text:
            self.clipboard_clear()
            self.clipboard_append(self._context_line_text)

    def _show_function_context_menu(self, event):
        """Показывает контекстное меню для списка функций."""
        iid = self.functions_tree.identify_row(event.y)
        if not iid:
            return
        
        self.functions_tree.selection_set(iid)
        self.function_context_menu.tk_popup(event.x_root, event.y_root)

    def _rename_function(self):
        """Открывает диалог для переименования выбранной функции."""
        selected_items = self.functions_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        if not item_id.startswith("fn_"):
            return

        try:
            address = int(item_id.split('_', 1)[1])
            current_name = self.function_map[address].name
            new_name = simpledialog.askstring("Переименовать функцию", f"Введите новое имя для 0x{address:x}:", initialvalue=current_name)
            
            if new_name and new_name != current_name:
                self.user_labels[address] = new_name
                self._run_analysis_and_populate_views() # Перерисовываем все с новым именем
        except (ValueError, TypeError, IndexError, KeyError):
            messagebox.showerror("Ошибка", "Не удалось переименовать функцию.")

    def apply_settings(self, old_settings: dict):
        """Применяет новые настройки, перерисовывая или перезапуская анализ только при необходимости."""
        new_settings = self.settings

        # Определяем, что изменилось
        theme_changed = old_settings.get("dark_theme") != new_settings.get("dark_theme")

        analysis_keys = {
            "use_prologue_heuristic", "use_separator_heuristic", "use_padding_heuristic",
            "analyze_basic_blocks", "analyze_xrefs", "analyze_classes", "analyze_anti_debug", "analyze_variables",
            "analyze_all_sections_for_compiler"
        }
        analysis_changed = any(old_settings.get(k) != new_settings.get(k) for k in analysis_keys)

        listing_keys = {
            "show_padding", "show_bytes", "uppercase_mnemonics", "show_errors_highlight"
        }
        listing_changed = any(old_settings.get(k) != new_settings.get(k) for k in listing_keys)

        # Применяем изменения
        if theme_changed:
            self._apply_theme()

        # Если файл не открыт, больше ничего делать не нужно
        if not self.current_filepath:
            return

        if analysis_changed:
            # Полный перезапуск анализа, который также перерисовывает листинг
            self._run_analysis_and_populate_views()
        elif theme_changed or listing_changed:
            # Перезапуск анализа не нужен, достаточно перерисовать листинг
            # (например, для применения новой темы или опций отображения)
            self._redisplay_listing()

    def _on_address_link_click(self, event):
        """Обрабатывает клик по ссылке на адрес в листинге."""
        pos = self.text_area.index(f"@{event.x},{event.y}")

        # Получаем диапазон слова под курсором
        word_start = self.text_area.index(f"{pos} wordstart")
        word_end = self.text_area.index(f"{pos} wordend")

        # Проверяем, есть ли на этом слове наш тег
        if "address_link" in self.text_area.tag_names(word_start):
            word = self.text_area.get(word_start, word_end)
            try:
                self._scroll_to_address(int(word, 16))
            except (ValueError, TypeError):
                pass # Не удалось сконвертировать, ничего страшного

    def _show_context_menu(self, event):
        """Показывает контекстное меню при правом клике."""
        self._context_target_addr = None
        self._context_line_text = None

        pos = self.text_area.index(f"@{event.x},{event.y}")
        line_num = pos.split('.')[0]

        # Логика для копирования строки
        line_text = self.text_area.get(f"{line_num}.0", f"{line_num}.end").strip()
        if line_text:
            self._context_line_text = line_text
            self.context_menu.entryconfig("Копировать строку", state=tk.NORMAL)
        else:
            self.context_menu.entryconfig("Копировать строку", state=tk.DISABLED)

        # Логика для перекрестных ссылок
        instr = self.line_to_instruction.get(line_num)
        
        target_addr = None
        if instr:
            # Сначала проверяем, есть ли ссылки на адрес самой инструкции (например, это начало функции)
            if instr.address in self.xrefs:
                target_addr = instr.address
            else:
                # Если нет, ищем адрес в операндах
                matches = self.hex_pattern.findall(instr.operands)
                if matches:
                    try:
                        # Берем первый попавшийся адрес из операндов
                        op_addr = int(matches[0], 16)
                        if op_addr in self.xrefs:
                            target_addr = op_addr
                    except (ValueError, TypeError):
                        pass
        
        if target_addr:
            self._context_target_addr = target_addr
            self.context_menu.entryconfig("Показать перекрестные ссылки", state=tk.NORMAL)
        else:
            self.context_menu.entryconfig("Показать перекрестные ссылки", state=tk.DISABLED)
            
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def _show_xrefs(self):
        """Открывает окно с перекрестными ссылками для выбранного адреса."""
        if self._context_target_addr is None:
            return
        
        source_addrs = self.xrefs.get(self._context_target_addr, set())
        if not source_addrs:
            messagebox.showinfo("Перекрестные ссылки", f"Не найдено ссылок на 0x{self._context_target_addr:x}")
            return
            
        XrefsWindow(self, self._context_target_addr, source_addrs, self.address_to_instruction, self.functions)

    def _on_explorer_double_click(self, event):
        """Обрабатывает двойной клик в проводнике для быстрого извлечения файла."""
        iid = self.explorer_tree.identify_row(event.y)
        if not iid:
            return

        node = self.explorer_iid_to_node.get(iid)
        
        # По двойному клику извлекаем только файлы.
        # Папки по-прежнему раскрываются/сворачиваются стандартным образом.
        if node and node.node_type == 'file' and node.data_len > 0:
            self._export_explorer_file(node)

class SectionSelectionWindow(tk.Toplevel):
    """Модальное окно для ручного выбора секции для анализа."""
    def __init__(self, parent: DisassemblerApp, pe: "pefile.PE"):
        super().__init__(parent)
        self.parent = parent
        self.pe = pe
        self.selected_section: Optional["pefile.SectionStructure"] = None

        self.title("Выберите секцию для анализа")
        self.geometry("650x400")
        self.transient(parent)
        self.grab_set()

        # --- Treeview для секций ---
        tree_frame = ttk.Frame(self, padding=5)
        tree_frame.pack(expand=True, fill=tk.BOTH)

        columns = ("name", "va", "vsize", "rsize", "flags")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        self.tree.heading("name", text="Имя")
        self.tree.heading("va", text="Адрес (VA)")
        self.tree.heading("vsize", text="Вирт. размер")
        self.tree.heading("rsize", text="RAW размер")
        self.tree.heading("flags", text="Флаги")

        self.tree.column("name", width=100, anchor='w')
        self.tree.column("va", width=120, anchor='e')
        self.tree.column("vsize", width=100, anchor='e')
        self.tree.column("rsize", width=100, anchor='e')
        self.tree.column("flags", width=100, anchor='center')

        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._populate_sections()
        self.tree.bind("<<TreeviewSelect>>", self._on_select_change)
        self.tree.bind("<Double-1>", self._analyze_and_close)

        # --- Кнопки ---
        button_frame = ttk.Frame(self, padding=5)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        button_frame.columnconfigure(0, weight=1)

        self.analyze_button = ttk.Button(button_frame, text="Анализировать", command=self._analyze_and_close, state=tk.DISABLED)
        self.analyze_button.grid(row=0, column=1, padx=5)

        cancel_button = ttk.Button(button_frame, text="Отмена", command=self.destroy)
        cancel_button.grid(row=0, column=2, padx=5)

    def _populate_sections(self):
        for i, section in enumerate(self.pe.sections):
            name = section.Name.decode(errors='ignore').strip('\x00')
            va = f"0x{self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress:x}"
            vsize = f"{section.Misc_VirtualSize}"
            rsize = f"{section.SizeOfRawData}"
            
            flags = ""
            if section.Characteristics & self.parent.pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']: flags += "R"
            else: flags += "-"
            if section.Characteristics & self.parent.pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']: flags += "W"
            else: flags += "-"
            if section.Characteristics & self.parent.pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']: flags += "X"
            else: flags += "-"

            self.tree.insert("", "end", iid=str(i), values=(name, va, vsize, rsize, flags))

    def _on_select_change(self, event=None):
        self.analyze_button.config(state=tk.NORMAL if self.tree.selection() else tk.DISABLED)

    def _analyze_and_close(self, event=None):
        selection = self.tree.selection()
        if not selection:
            return
        
        try:
            section_index = int(selection[0])
            self.selected_section = self.pe.sections[section_index]
        except (ValueError, IndexError):
            self.selected_section = None
        
        self.destroy()

class XrefsWindow(tk.Toplevel):
    """Модальное окно для отображения перекрестных ссылок."""
    def __init__(self, parent: DisassemblerApp, target_addr: int, source_addrs: Set[int], addr_to_instr: Dict[int, Instruction], functions: List[FoundFunction]):
        super().__init__(parent)
        self.parent = parent
        self.title(f"Ссылки на 0x{target_addr:x}")
        self.geometry("800x400")
        self.transient(parent)
        self.grab_set()

        tree = ttk.Treeview(self, columns=("function", "address", "instruction"), show="headings")
        tree.heading("function", text="Функция")
        tree.heading("address", text="Адрес")
        tree.heading("instruction", text="Инструкция")
        tree.column("function", width=250, anchor='w')
        tree.column("address", width=120, stretch=tk.NO, anchor='w')
        tree.column("instruction", anchor='w')
        tree.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        # Create a map of function ranges for quick lookups
        func_ranges = []
        if functions:
            sorted_funcs = sorted(functions, key=lambda f: f.address)
            for i, func in enumerate(sorted_funcs):
                start = func.address
                end = sorted_funcs[i+1].address if i + 1 < len(sorted_funcs) else float('inf')
                func_ranges.append((start, end, func.name))

        def get_func_name(addr: int) -> str:
            """Finds the function name for a given address."""
            for start, end, name in func_ranges:
                if start <= addr < end:
                    return name
            return "N/A"

        for addr in sorted(list(source_addrs)):
            instr = addr_to_instr.get(addr)
            func_name = get_func_name(addr)
            if instr:
                instr_text = f"{instr.mnemonic} {instr.operands}"
                tree.insert("", tk.END, values=(func_name, f"0x{addr:x}", instr_text), iid=str(addr))
            else:
                tree.insert("", tk.END, values=(func_name, f"0x{addr:x}", "(нет данных)"), iid=str(addr))
            
        tree.bind("<Double-1>", self._on_select)
        self.tree = tree

    def _on_select(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        
        item_id = selection[0]
        try:
            addr = int(item_id)
            self.parent._scroll_to_address(addr)
            self.destroy() # Закрываем окно после перехода
        except (ValueError, TypeError):
            pass


class SettingsWindow(tk.Toplevel):
    """Модальное окно для настроек приложения."""
    def __init__(self, parent: DisassemblerApp, settings: dict, defaults: dict):
        super().__init__(parent)
        self.parent = parent
        self.settings = settings
        self.defaults = defaults

        self.title("Настройки")
        self.geometry("450x490")
        self.resizable(False, False)

        # Сделать окно модальным
        self.transient(parent)
        self.grab_set()

        # --- Основной фрейм и вкладки ---
        main_frame = ttk.Frame(self, padding=(10, 10, 10, 0))
        main_frame.pack(expand=True, fill=tk.BOTH)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(expand=True, fill=tk.BOTH)

        # --- Вкладка "Вид" ---
        appearance_tab = ttk.Frame(notebook, padding="10")
        notebook.add(appearance_tab, text="Вид")

        self.dark_theme_var = tk.BooleanVar(value=self.settings.get("dark_theme", False))
        cb_dark = ttk.Checkbutton(
            appearance_tab,
            text="Темная тема",
            variable=self.dark_theme_var
        )
        cb_dark.pack(anchor='w', padx=5, pady=(5, 10))

        # --- Вкладка "Листинг" (бывшая "Дизассемблер") ---
        listing_tab = ttk.Frame(notebook, padding="10")
        notebook.add(listing_tab, text="Листинг")

        # --- Визуальные опции дизассемблера ---
        disasm_view_frame = ttk.LabelFrame(listing_tab, text="Отображение")
        disasm_view_frame.pack(fill=tk.X, pady=5, padx=5)

        self.show_padding_var = tk.BooleanVar(value=self.settings.get("show_padding", False))
        cb_padding = ttk.Checkbutton(
            disasm_view_frame,
            text="Показывать байты-заполнители (int3, nop)",
            variable=self.show_padding_var
        )
        cb_padding.pack(anchor='w', padx=5, pady=2)

        self.show_bytes_var = tk.BooleanVar(value=self.settings.get("show_bytes", True))
        cb_bytes = ttk.Checkbutton(
            disasm_view_frame,
            text="Показывать байты инструкции",
            variable=self.show_bytes_var
        )
        cb_bytes.pack(anchor='w', padx=5, pady=2)

        self.uppercase_mnemonics_var = tk.BooleanVar(value=self.settings.get("uppercase_mnemonics", False))
        cb_upper_mnem = ttk.Checkbutton(
            disasm_view_frame,
            text="Отображать мнемоники в верхнем регистре",
            variable=self.uppercase_mnemonics_var
        )
        cb_upper_mnem.pack(anchor='w', padx=5, pady=2)

        self.show_errors_highlight_var = tk.BooleanVar(value=self.settings.get("show_errors_highlight", True))
        cb_errors = ttk.Checkbutton(
            disasm_view_frame,
            text="Подсвечивать ошибки анализа красным",
            variable=self.show_errors_highlight_var
        )
        cb_errors.pack(anchor='w', padx=5, pady=2)

        # --- Вкладка "Анализ" ---
        analysis_tab = ttk.Frame(notebook, padding="10")
        notebook.add(analysis_tab, text="Анализ")

        # --- Опции загрузки ---
        loading_frame = ttk.LabelFrame(analysis_tab, text="Загрузка файла")
        loading_frame.pack(fill=tk.X, pady=5, padx=5)

        self.auto_section_search_var = tk.BooleanVar(value=self.settings.get("auto_section_search", True))
        cb_auto_section = ttk.Checkbutton(
            loading_frame, text="Автоматический поиск секции для анализа", variable=self.auto_section_search_var
        )
        cb_auto_section.pack(anchor='w', padx=5, pady=2)
        # --- Опции анализа ---
        analysis_frame = ttk.LabelFrame(analysis_tab, text="Анализ функций")
        analysis_frame.pack(fill=tk.X, pady=5, padx=5)

        self.use_prologue_heuristic_var = tk.BooleanVar(value=self.settings.get("use_prologue_heuristic", True))
        cb_prologue = ttk.Checkbutton(analysis_frame, text="Искать стандартные прологи", variable=self.use_prologue_heuristic_var)
        cb_prologue.pack(anchor='w', padx=5, pady=2)

        self.use_separator_heuristic_var = tk.BooleanVar(value=self.settings.get("use_separator_heuristic", True))
        cb_separator = ttk.Checkbutton(analysis_frame, text="Искать код после ret/jmp", variable=self.use_separator_heuristic_var)
        cb_separator.pack(anchor='w', padx=5, pady=2)

        self.use_padding_heuristic_var = tk.BooleanVar(value=self.settings.get("use_padding_heuristic", True))
        cb_padding_h = ttk.Checkbutton(analysis_frame, text="Искать код после блоков-заполнителей", variable=self.use_padding_heuristic_var)
        cb_padding_h.pack(anchor='w', padx=5, pady=2)

        self.analyze_basic_blocks_var = tk.BooleanVar(value=self.settings.get("analyze_basic_blocks", True))
        cb_blocks = ttk.Checkbutton(analysis_frame, text="Анализировать базовые блоки", variable=self.analyze_basic_blocks_var)
        cb_blocks.pack(anchor='w', padx=5, pady=2)

        # --- Опции других анализаторов ---
        other_analysis_frame = ttk.LabelFrame(analysis_tab, text="Прочие анализаторы")
        other_analysis_frame.pack(fill=tk.X, pady=5, padx=5)

        self.analyze_xrefs_var = tk.BooleanVar(value=self.settings.get("analyze_xrefs", True))
        cb_xrefs = ttk.Checkbutton(other_analysis_frame, text="Анализировать перекрестные ссылки (xrefs)", variable=self.analyze_xrefs_var)
        cb_xrefs.pack(anchor='w', padx=5, pady=2)

        self.analyze_classes_var = tk.BooleanVar(value=self.settings.get("analyze_classes", True))
        cb_classes = ttk.Checkbutton(other_analysis_frame, text="Анализировать классы C++", variable=self.analyze_classes_var)
        cb_classes.pack(anchor='w', padx=5, pady=2)

        self.analyze_variables_var = tk.BooleanVar(value=self.settings.get("analyze_variables", True))
        cb_vars = ttk.Checkbutton(other_analysis_frame, text="Анализировать переменные в секциях данных", variable=self.analyze_variables_var)
        cb_vars.pack(anchor='w', padx=5, pady=2)

        self.analyze_all_sections_var = tk.BooleanVar(value=self.settings.get("analyze_all_sections_for_compiler", True))
        cb_all_sections = ttk.Checkbutton(
            other_analysis_frame,
            text="Искать сигнатуры по всему файлу (рекомендуется)",
            variable=self.analyze_all_sections_var
        )
        cb_all_sections.pack(anchor='w', padx=5, pady=(10, 2))

        # --- Настройка Anti-Debug ---
        anti_debug_frame = ttk.Frame(other_analysis_frame)
        anti_debug_frame.pack(anchor='w', fill='x', padx=5, pady=(10, 2))

        self.analyze_anti_debug_var = tk.BooleanVar(value=self.settings.get("analyze_anti_debug", False))
        cb_anti_debug = ttk.Checkbutton(
            anti_debug_frame,
            text="Анализировать Anti-Debug/VM техники",
            variable=self.analyze_anti_debug_var
        )
        cb_anti_debug.pack(side=tk.LEFT)

        warning_label = ttk.Label(anti_debug_frame, text="(Beta, возможны ложные срабатывания)", style="Warning.TLabel")
        warning_label.pack(side=tk.LEFT, padx=(5, 0))

        # --- Кнопки ---
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(15, 0))
        button_frame.columnconfigure(1, weight=1) # Центральная колонка растягивается

        reset_button = ttk.Button(button_frame, text="Сбросить", command=self._reset_to_defaults)
        reset_button.grid(row=0, column=0, sticky=tk.W, padx=5)

        ok_button = ttk.Button(button_frame, text="OK", command=self._apply_and_close)
        ok_button.grid(row=0, column=1, sticky=tk.E, padx=5)

        cancel_button = ttk.Button(button_frame, text="Отмена", command=self.destroy)
        cancel_button.grid(row=0, column=2, sticky=tk.W, padx=5)

    def _apply_and_close(self):
        """Применяет настройки, сохраняет их и закрывает окно."""
        old_settings = self.parent.settings.copy()
        self.parent.settings["show_padding"] = self.show_padding_var.get()
        self.parent.settings["dark_theme"] = self.dark_theme_var.get()
        self.parent.settings["show_bytes"] = self.show_bytes_var.get()
        self.parent.settings["uppercase_mnemonics"] = self.uppercase_mnemonics_var.get()
        self.parent.settings["use_prologue_heuristic"] = self.use_prologue_heuristic_var.get()
        self.parent.settings["use_separator_heuristic"] = self.use_separator_heuristic_var.get()
        self.parent.settings["use_padding_heuristic"] = self.use_padding_heuristic_var.get()
        self.parent.settings["analyze_basic_blocks"] = self.analyze_basic_blocks_var.get()
        self.parent.settings["analyze_xrefs"] = self.analyze_xrefs_var.get()
        self.parent.settings["analyze_classes"] = self.analyze_classes_var.get()
        self.parent.settings["show_errors_highlight"] = self.show_errors_highlight_var.get()
        self.parent.settings["analyze_variables"] = self.analyze_variables_var.get()
        self.parent.settings["analyze_anti_debug"] = self.analyze_anti_debug_var.get()
        self.parent.settings["auto_section_search"] = self.auto_section_search_var.get()
        self.parent.settings["analyze_all_sections_for_compiler"] = self.analyze_all_sections_var.get()

        self.parent._save_settings()
        self.parent.apply_settings(old_settings)
        self.destroy()

    def _reset_to_defaults(self):
        """Сбрасывает все опции в окне к значениям по умолчанию."""
        self.show_padding_var.set(self.defaults["show_padding"])
        self.dark_theme_var.set(self.defaults["dark_theme"])
        self.show_bytes_var.set(self.defaults["show_bytes"])
        self.uppercase_mnemonics_var.set(self.defaults["uppercase_mnemonics"])
        self.use_prologue_heuristic_var.set(self.defaults["use_prologue_heuristic"])
        self.use_separator_heuristic_var.set(self.defaults["use_separator_heuristic"])
        self.use_padding_heuristic_var.set(self.defaults["use_padding_heuristic"])
        self.analyze_basic_blocks_var.set(self.defaults["analyze_basic_blocks"])
        self.analyze_xrefs_var.set(self.defaults["analyze_xrefs"])
        self.analyze_classes_var.set(self.defaults["analyze_classes"])
        self.show_errors_highlight_var.set(self.defaults["show_errors_highlight"])
        self.analyze_variables_var.set(self.defaults["analyze_variables"])
        self.analyze_anti_debug_var.set(self.defaults["analyze_anti_debug"])
        self.auto_section_search_var.set(self.defaults["auto_section_search"])
        self.analyze_all_sections_var.set(self.defaults["analyze_all_sections_for_compiler"])