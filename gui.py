import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, font, simpledialog
import sys
import os
import re
import json
from typing import Dict, Set, Optional, List
from localization import _, init_translator

from disasm import ( 
    Disassembler, Instruction,
    find_functions, FoundFunction, find_xrefs, flag_consecutive_errors,
    find_classes, FoundClass, SecurityFeatures, SectionInfo, is_dotnet_assembly,
    analyze_pe_info, FileInfo, ImportedFunction,
    analyze_anti_debug, DetectionResult, ScanResult,
    analyze_structure, ExplorerNode,
    find_variables, FoundVariable
)

from utils.progress import ProgressDialog, AnalysisWorker
from utils.hex_view import HexView
from utils.string_view import StringView

class ScrollableNotebook(ttk.Frame):
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.tab_area = ttk.Frame(self)
        self.tab_area.pack(side="top", fill="x", expand=False, pady=(0, 1))

        self.canvas = tk.Canvas(self.tab_area, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.tab_area, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(xscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="top", fill="x")
        self.scrollbar.pack(side="bottom", fill="x")

        self.tab_container = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.tab_container, anchor="nw")

        self._content_container = ttk.Frame(self, style="Content.TFrame")
        self._content_container.pack(side="top", fill="both", expand=True)

        self._tabs = {}
        self._selected_var = tk.StringVar()

        self.tab_container.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<MouseWheel>", self._on_mouse_wheel)
        self.tab_container.bind("<MouseWheel>", self._on_mouse_wheel)

    def add(self, child, text=""):
        tab_id = str(child)
        self._tabs[tab_id] = child
        child.pack_forget()

        button = ttk.Radiobutton(self.tab_container,
            text=text,
            variable=self._selected_var,
            value=tab_id,
            command=self._on_tab_select,
            style="WrappingTab.TButton"
        )
        button.pack(side="left", padx=1, pady=0)
        button.bind("<MouseWheel>", self._on_mouse_wheel)

        if not self._selected_var.get():
            button.invoke()

    def _on_tab_select(self):
        selected_id = self._selected_var.get()
        for tab_id, child in self._tabs.items():
            if tab_id == selected_id:
                child.pack(in_=self._content_container, fill="both", expand=True, padx=2, pady=2)
            else:
                child.pack_forget()

    def _on_frame_configure(self, event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.canvas.config(height=self.tab_container.winfo_reqheight())

    def _on_mouse_wheel(self, event):
        if sys.platform == "win32":
            self.canvas.xview_scroll(-1 * (event.delta // 120), "units")
        elif sys.platform == "darwin":
            self.canvas.xview_scroll(event.delta, "units")
        else: # Linux
            if event.num == 4:
                self.canvas.xview_scroll(-1, "units")
            elif event.num == 5:
                self.canvas.xview_scroll(1, "units")

class DisassemblerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.pefile = self._import_pefile()
        if not self.pefile:
            self.destroy()
            sys.exit(1)
        
        self.settings = self._load_settings()
        init_translator(self.settings.get("language", "ru"))
        self._ = _

        self.title(_("app_title"))
        self.geometry("1200x700")
        self.current_filepath = None
        self.instructions: list[Instruction] = []
        self.functions: list[FoundFunction] = []
        self.classes: list[FoundClass] = []
        self.scan_results: list[ScanResult] = []
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
        
        self.strings_view_widget: Optional[StringView] = None
        self.hex_view_widget: Optional[HexView] = None
        self.colors = {}
        self.address_to_line: dict[int, str] = {}

        
        self.top_frame = ttk.Frame(self)
        self.top_frame.pack(fill=tk.X, padx=5, pady=5)

        self.open_button = ttk.Button(self.top_frame, text=_("open_file_btn"), command=self.open_file)
        self.open_button.pack(side=tk.LEFT)

        self.export_button = ttk.Button(self.top_frame, text=_("export_asm_btn"), command=self.export_asm, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=5)

        self.settings_button = ttk.Button(self.top_frame, text=_("settings_btn"), command=self._open_settings_window)
        self.settings_button.pack(side=tk.LEFT)

        self.main_pane = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        self.main_pane.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        
        self.left_notebook = ScrollableNotebook(self.main_pane)

        if self.settings.get("component_functions_enabled", True):
            functions_tab = ttk.Frame(self.left_notebook)
            self.left_notebook.add(functions_tab, text=_("functions_tab"))
            self.functions_tree = ttk.Treeview(functions_tab, show="tree headings", columns=("name",))
            self.functions_tree.heading("#0", text=_("address_col"))
            self.functions_tree.heading("name", text=_("name_col"))
            self.functions_tree.column("#0", width=100, stretch=tk.NO, anchor='w')
            self.functions_tree.column("name", anchor='w')
            self.functions_tree.pack(expand=True, fill=tk.BOTH)
            self.functions_tree.bind("<<TreeviewSelect>>", self._on_function_select)
            self.functions_tree.bind("<Button-3>", self._show_function_context_menu)
            self.function_context_menu = tk.Menu(self, tearoff=0)
            self.function_context_menu.add_command(label=_("rename_menu"), command=self._rename_function)

        if self.settings.get("component_blocks_enabled", True):
            blocks_tab = ttk.Frame(self.left_notebook)
            self.left_notebook.add(blocks_tab, text=_("blocks_tab"))
            self.blocks_tree = ttk.Treeview(blocks_tab, show="tree")
            self.blocks_tree.pack(expand=True, fill=tk.BOTH)
            self.blocks_tree.bind("<Double-1>", self._on_basic_block_select)

        if self.settings.get("component_classes_enabled", True):
            classes_tab = ttk.Frame(self.left_notebook)
            self.left_notebook.add(classes_tab, text=_("classes_tab"))
            self.classes_tree = ttk.Treeview(classes_tab, show="tree headings", columns=("address",))
            self.classes_tree.heading("#0", text=_("class_name_col"))
            self.classes_tree.heading("address", text=_("address_col"))
            self.classes_tree.column("#0", anchor='w')
            self.classes_tree.column("address", width=120, stretch=tk.NO, anchor='w')
            self.classes_tree.pack(expand=True, fill=tk.BOTH)
            self.classes_tree.bind("<<TreeviewSelect>>", self._on_class_select)

        if self.settings.get("component_variables_enabled", True):
            variables_tab = ttk.Frame(self.left_notebook)
            self.left_notebook.add(variables_tab, text=_("variables_tab"))
            self.variables_tree = ttk.Treeview(variables_tab, show="headings", columns=("address", "type", "value"))
            self.variables_tree.heading("address", text=_("address_col"))
            self.variables_tree.heading("type", text=_("type_col"))
            self.variables_tree.heading("value", text=_("value_col"))
            self.variables_tree.column("address", width=120, stretch=tk.NO, anchor='w')
            self.variables_tree.column("type", width=80, stretch=tk.NO, anchor='w')
            self.variables_tree.column("value", anchor='w')
            self.variables_tree.pack(expand=True, fill=tk.BOTH)
            self.variables_tree.bind("<Double-1>", self._on_variable_select)

        if self.settings.get("component_signatures_enabled", True):
            signatures_tab = ttk.Frame(self.left_notebook)
            self.left_notebook.add(signatures_tab, text=_("signatures_tab"))
            self.signatures_tree = ttk.Treeview(signatures_tab, show="headings", columns=("address", "type", "name"))
            self.signatures_tree.heading("address", text=self._("address_col"))
            self.signatures_tree.heading("type", text=self._("type_col"))
            self.signatures_tree.heading("name", text=self._("name_col"))
            self.signatures_tree.column("address", width=120, stretch=tk.NO, anchor='w')
            self.signatures_tree.column("type", width=80, stretch=tk.NO, anchor='w')
            self.signatures_tree.column("name", anchor='w')
            self.signatures_tree.pack(expand=True, fill=tk.BOTH)
            self.signatures_tree.bind("<Double-1>", self._on_signature_select)

        if self.settings.get("component_strings_enabled", True):
            strings_tab = ttk.Frame(self.left_notebook)
            self.left_notebook.add(strings_tab, text=_("strings_tab"))
            self.strings_view_frame = strings_tab
            self.strings_view_widget: Optional[StringView] = None

        if self.settings.get("component_info_enabled", True):
            info_tab = ttk.Frame(self.left_notebook)
            self.left_notebook.add(info_tab, text=_("info_tab"))
            self.info_text_area = scrolledtext.ScrolledText(info_tab, wrap=tk.WORD, relief=tk.FLAT, bd=0)
            self.info_text_area.pack(expand=True, fill=tk.BOTH, padx=2, pady=2)
            self.info_text_area.config(state=tk.DISABLED)

        if self.settings.get("component_imports_enabled", True):
            imports_main_tab = ttk.Frame(self.left_notebook)
            self.left_notebook.add(imports_main_tab, text=_("imports_tab"))
            imp_exp_notebook = ttk.Notebook(imports_main_tab)
            imp_exp_notebook.pack(expand=True, fill=tk.BOTH)
            imports_sub_tab = ttk.Frame(imp_exp_notebook)
            imp_exp_notebook.add(imports_sub_tab, text=_("imports_tab"))
            self.imports_tree = ttk.Treeview(imports_sub_tab, show="tree")
            self.imports_tree.bind("<Double-1>", self._on_import_select)
            self.imports_tree.pack(expand=True, fill=tk.BOTH)
            exports_sub_tab = ttk.Frame(imp_exp_notebook)
            imp_exp_notebook.add(exports_sub_tab, text=_("exports_tab"))
            self.exports_tree = ttk.Treeview(exports_sub_tab, show="tree")
            self.exports_tree.heading("#0", text=_("addr_name_col"))
            self.exports_tree.pack(expand=True, fill=tk.BOTH)

        if self.settings.get("component_explorer_enabled", True):
            explorer_tab = ttk.Frame(self.left_notebook)
            self.left_notebook.add(explorer_tab, text=_("explorer_tab"))
            self.explorer_tree = ttk.Treeview(explorer_tab, show="tree")
            self.explorer_context_menu = tk.Menu(self, tearoff=0)
            self.explorer_context_menu.add_command(label=_("extract_menu"), command=self._export_from_explorer, state=tk.DISABLED)
            self.explorer_tree.bind("<Button-3>", self._show_explorer_context_menu)
            self.explorer_tree.bind("<Double-1>", self._on_explorer_double_click)
            self._selected_explorer_node: Optional[ExplorerNode] = None
            self.explorer_tree.pack(expand=True, fill=tk.BOTH)

        self.main_pane.add(self.left_notebook, width=300, minsize=200)
        self._create_right_panel()

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

        self._context_target_addr: Optional[int] = None
        self.text_area.bind("<Button-3>", self._show_context_menu)
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label=_("show_xrefs_menu"), command=self._show_xrefs, state=tk.DISABLED)
        self.context_menu.add_command(label=_("copy_line_menu"), command=self._copy_line, state=tk.DISABLED)

        self.text_area.tag_bind("address_link", "<Button-1>", self._on_address_link_click)
        self.text_area.tag_bind("address_link", "<Enter>", lambda e: self.text_area.config(cursor="hand2"))
        self.text_area.tag_bind("address_link", "<Leave>", lambda e: self.text_area.config(cursor=""))

        self._create_search_bar()
        self.bind_all("<Control-f>", self._toggle_search_bar)
        self.bind_all("<Escape>", self._hide_search_bar_on_escape)
        self._apply_theme()

    def _import_pefile(self):
        try:
            import pefile
            return pefile
        except ImportError:
            messagebox.showerror(
                _("pefile_not_found_title"),
                _("pefile_not_found_msg")
            )
            return None

    def _apply_theme(self):
        is_dark = self.settings.get("dark_theme", False)

        font_family = "Courier New"
        font_size = 10
        listing_font = (font_family, font_size)
        info_font = (font_family, max(8, font_size - 1)) 
        info_bold_font = (font_family, max(8, font_size - 1), "bold")

        style = ttk.Style(self)

        if is_dark:
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

        style.configure("Content.TFrame", background=colors["widget_bg"], relief="sunken", borderwidth=1)

        style.configure("WrappingTab.TButton",
            padding=[8, 4],
            relief="flat",
            background=colors["widget_bg"],
            foreground=colors["fg"]
        )
        style.map("WrappingTab.TButton",
            background=[('selected', colors["bg"]), ('active', colors["select_bg"])]
        )

        self.left_notebook.canvas.config(bg=colors["bg"])
        self.main_pane.config(bg=colors["bg"], sashrelief=tk.FLAT)
        for text_widget in [self.text_area, self.info_text_area]:
            text_widget.config(background=colors["widget_bg"], foreground=colors["fg"], insertbackground=colors["cursor"], selectbackground=colors["select_bg"])
        
        self.text_area.config(font=listing_font)
        self.info_text_area.config(font=info_font)

        tag_colors = {"address": "address", "bytes": "bytes", "mnemonic": "mnemonic", "register": "register", "immediate": "immediate", "ptr": "ptr", "comment": "comment"}
        for tag, color_key in tag_colors.items():
            self.text_area.tag_configure(tag, foreground=colors[color_key])
        self.text_area.tag_configure("address_link", foreground=colors["link_fg"], underline=True)

        self.text_area.tag_configure("mnemonic", font=(font_family, font_size, "bold"))
        self.text_area.tag_configure("selection_highlight", background=colors["selection_highlight"])
        self.text_area.tag_configure("search_highlight", background=colors["search_highlight_bg"])
        self.text_area.tag_configure("error_line", background=colors["error_bg"])

        for tree in [self.functions_tree, self.blocks_tree, self.classes_tree]:
            tree.tag_configure("has_error", foreground=colors["error_fg"])
            tree.tag_configure("is_stub", foreground=colors["stub_fg"])

        self.info_text_area.tag_configure("title", foreground=colors["info_title_fg"], font=(font_family, font_size, "bold", "underline"))
        self.info_text_area.tag_configure("key", foreground=colors["info_key_fg"], font=info_bold_font)

        
        style.configure("Warning.TLabel", foreground=colors["warning_fg"], font=(font_family, max(8, font_size - 2), "bold"))

    def _get_default_settings(self):
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
            "analyze_signatures": True,
            "auto_section_search": True,
            "analyze_all_sections_for_compiler": True,
            "component_functions_enabled": True,
            "component_blocks_enabled": True,
            "component_classes_enabled": True,
            "component_variables_enabled": True,
            "component_signatures_enabled": True,
            "component_strings_enabled": True,
            "component_info_enabled": True,
            "component_imports_enabled": True,
            "component_explorer_enabled": True,
            "language": "ru",
        }

    def _load_settings(self):
        defaults = self._get_default_settings()
        try:
            with open("settings.json", "r") as f:
                loaded_settings = json.load(f)
                defaults.update(loaded_settings)
        except (FileNotFoundError, json.JSONDecodeError):
            pass 
        return defaults

    def _save_settings(self):
        try:
            with open("settings.json", "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            messagebox.showerror(self._("save_settings_error_title"), self._("save_settings_error_msg").format(e=e))

    def _open_settings_window(self):
        SettingsWindow(self, self.settings, self._get_default_settings())

    def _create_search_bar(self):
        self.search_frame = ttk.Frame(self, padding=5)
        
        search_label = ttk.Label(self.search_frame, text=self._("search_label"))
        search_label.pack(side=tk.LEFT, padx=(0, 5))

        self.search_entry = ttk.Entry(self.search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind("<Return>", self._find_next)
        self.search_entry.bind("<KP_Enter>", self._find_next)

        find_next_button = ttk.Button(self.search_frame, text=self._("find_next_btn"), command=self._find_next)
        find_next_button.pack(side=tk.LEFT, padx=(5, 0))

        find_prev_button = ttk.Button(self.search_frame, text=self._("find_prev_btn"), command=self._find_prev)
        find_prev_button.pack(side=tk.LEFT, padx=(5, 0))

        close_button = ttk.Button(self.search_frame, text="×", command=self._toggle_search_bar, width=3)
        close_button.pack(side=tk.LEFT, padx=(5, 0))

    def _toggle_search_bar(self, event=None):
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
        if self.search_frame.winfo_viewable():
            self._toggle_search_bar()

    def _find_next(self, event=None):
        self._find(forward=True)

    def _find_prev(self, event=None):
        self._find(forward=False)

    def _find(self, forward: bool):
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
            messagebox.showinfo(self._("search_title"), self._("search_no_match").format(query=query), parent=self)

    def _create_right_panel(self):
        self.right_notebook = ttk.Notebook(self.main_pane)

        listing_frame = ttk.Frame(self.right_notebook)
        self.text_area = scrolledtext.ScrolledText(listing_frame, wrap=tk.NONE, state=tk.DISABLED)
        self.text_area.pack(expand=True, fill=tk.BOTH)
        self.right_notebook.add(listing_frame, text=self._("listing_tab"))

        self.hex_view_frame = ttk.Frame(self.right_notebook)
        self.right_notebook.add(self.hex_view_frame, text=self._("hex_view_tab"))

        self.main_pane.add(self.right_notebook, minsize=400)

    def open_file(self):
        filepath = filedialog.askopenfilename(
            title=self._("open_pe_file_title"),
            filetypes=((self._("executable_files"), "*.exe *.dll"), (self._("all_files"), "*.*"))
        )
        if not filepath:
            return

        self.user_labels.clear()
        self.current_filepath = filepath
        try:
            self.pe_object = self.pefile.PE(self.current_filepath)
        except self.pefile.PEFormatError as e:
            messagebox.showerror(self._("error_title"), self._("invalid_pe_file").format(e=e))
            self.pe_object = None
            return
        except FileNotFoundError:
            messagebox.showerror(self._("error_title"), self._("file_not_found").format(filepath=self.current_filepath))
            self.pe_object = None
            return
        self._disassemble_and_analyze()
    
    def _disassemble_and_analyze(self):
        if not self.pe_object:
            return
    
        if self.settings.get("auto_section_search", True):
            code_section = None
            entry_point_rva = 0
            try:
                entry_point_rva = self.pe_object.OPTIONAL_HEADER.AddressOfEntryPoint
                code_section = self.pe_object.get_section_by_rva(entry_point_rva)
            except (AttributeError, TypeError):
                pass
    
            if not code_section:
                messagebox.showwarning(
                    self._("unusual_entry_point_title"),
                    self._("unusual_entry_point_msg").format(rva=entry_point_rva)
                )
                for section in self.pe_object.sections:
                    if section.Characteristics & self.pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
                        code_section = section
                        break
        else:
            dialog = SectionSelectionWindow(self, self.pe_object)
            self.wait_window(dialog) # Ждем закрытия диалога
            code_section = dialog.selected_section
    
        if not code_section:
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
    
        if self.pe_object and is_dotnet_assembly(self.pe_object):
            self.instructions = []
        else:
            bytecode = code_section.get_data()
            dis = Disassembler(bytecode, base_address=self.base_address)
            self.instructions = dis.disassemble()
    
        flag_consecutive_errors(self.instructions)
        self.address_to_instruction = {instr.address: instr for instr in self.instructions}
    
        self._start_async_analysis()

    def _start_async_analysis(self):
        
        if not self.pe_object:
            return
        
        if not self.instructions:
            self._populate_views_with_results()
            return

        self.analysis_worker = AnalysisWorker(
            pe=self.pe_object,
            instructions=self.instructions,
            settings=self.settings,
            user_labels=self.user_labels
        )
        self.analysis_worker.start()
        ProgressDialog(self, self.analysis_worker)

    def on_analysis_complete(self, results: dict):
        
        if not results:
            return

        self.file_info = results.get("file_info")
        self.file_structure = results.get("file_structure")
        self.anti_debug_results = results.get("anti_debug_results", [])
        self.xrefs = results.get("xrefs", {})
        self.functions = results.get("functions", [])
        self.classes = results.get("classes", [])
        self.scan_results = results.get("scan_results", [])
        self.variables = results.get("variables", [])
        self.function_map = {f.address: f for f in self.functions}

        self._populate_views_with_results()

    def _populate_hex_view(self):
        
        if self.hex_view_widget:
            self.hex_view_widget.destroy()
            self.hex_view_widget = None

        if not self.pe_object:
            return

        file_data = self.pe_object.__data__
        listing_font = self.text_area.cget("font")
        
        self.hex_view_widget = HexView(
            self.hex_view_frame,
            file_data=file_data,
            colors=self.colors,
            font_info=listing_font
        )
        self.hex_view_widget.pack(expand=True, fill=tk.BOTH)

    def _populate_strings_view(self):
        
        if self.strings_view_widget:
            self.strings_view_widget.destroy()
            self.strings_view_widget = None

        if not self.pe_object:
            return

        translations = {
            "address_col": self._("address_col"),
            "type_col": self._("type_col"),
            "section_col": self._("section_col"),
            "string_col": self._("string_col"),
        }
        self.strings_view_widget = StringView(
            self.strings_view_frame,
            pe=self.pe_object,
            on_select=self._on_string_select,
            colors=self.colors,
            translations=translations
        )
        self.strings_view_widget.pack(expand=True, fill=tk.BOTH)

    def _populate_views_with_results(self):
       
        self._populate_info_tab()
        if self.settings.get("component_explorer_enabled", True): self._populate_explorer_tree()
        if self.settings.get("component_blocks_enabled", True): self._populate_basic_blocks_tree()
        if self.settings.get("component_functions_enabled", True): self._populate_functions_tree()
        if self.settings.get("component_signatures_enabled", True): self._populate_signatures_tree()
        if self.settings.get("component_strings_enabled", True): self._populate_strings_view()
        if self.settings.get("component_imports_enabled", True): self._populate_imports_exports_trees()
        if self.settings.get("component_classes_enabled", True): self._populate_classes_tree()
        if self.settings.get("component_variables_enabled", True): self._populate_variables_tree()
        self._populate_hex_view()
        self._redisplay_listing()
        self.export_button.config(state=tk.NORMAL)
    
        try:
            entry_point_va = self.pe_object.OPTIONAL_HEADER.ImageBase + self.pe_object.OPTIONAL_HEADER.AddressOfEntryPoint
            self._scroll_to_address(entry_point_va)
        except (AttributeError, TypeError):
            pass

    def _redisplay_listing(self):
        if not self.current_filepath:
            return

        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete("1.0", tk.END)
        self.address_to_line.clear()
        self.line_to_instruction.clear()

        if self.pe_object and is_dotnet_assembly(self.pe_object):
            header = self._("dotnet_analysis_header").format(filename=os.path.basename(self.current_filepath)) + "\n\n"
            message = self._("dotnet_analysis_body")
            
            self.text_area.insert(tk.END, header, "comment")
            self.text_area.insert(tk.END, message, "comment")
            
            self.text_area.config(state=tk.DISABLED)
            return

        self._insert_header()

        for instr in self._get_filtered_instructions():
            self._insert_and_highlight_instruction(instr)

        self.text_area.config(state=tk.DISABLED)

    def _get_filtered_instructions(self) -> list[Instruction]:
        if self.settings.get("show_padding", False):
            return self.instructions
        return [instr for instr in self.instructions if instr.bytes not in (b'\xcc', b'\x90')]

    def _populate_functions_tree(self):
        for item in self.functions_tree.get_children():
            self.functions_tree.delete(item)
        
        if not self.functions:
            self.functions_tree.insert("", "end", text=self._("functions_not_found"), iid="fn_not_found", open=False)
            return

        for func in self.functions:
            iid = f"fn_{func.address}"
            tags = []
            if func.has_errors and self.settings.get("show_errors_highlight", True):
                tags.append("has_error")
            if func.is_stub:
                tags.append("is_stub")
            self.functions_tree.insert("", "end", text=f"0x{func.address:x}", values=(func.name,), iid=iid, tags=tuple(tags))

    def _populate_basic_blocks_tree(self):
        for item in self.blocks_tree.get_children():
            self.blocks_tree.delete(item)

        if not self.functions or not self.settings.get("analyze_basic_blocks", True):
            self.blocks_tree.insert("", "end", text=self._("blocks_analysis_disabled"), iid="bb_disabled")
            return

        for func in self.functions:
            func_iid = f"bb_fn_{func.address}"
            func_tags = ("has_error",) if func.has_errors and self.settings.get("show_errors_highlight", True) else ()
            func_node = self.blocks_tree.insert("", "end", text=f"▶ {func.name}", iid=func_iid, open=False, tags=func_tags)
            
            for i, block in enumerate(func.blocks):
                block_iid = f"bb_{block.start_address}"
                block_tags = ("has_error",) if block.has_errors and self.settings.get("show_errors_highlight", True) else ()
                block_text = f"  {self._('block_prefix')} {i+1} (0x{block.start_address:x} - 0x{block.end_address:x})"
                self.blocks_tree.insert(func_node, "end", text=block_text, iid=block_iid, tags=block_tags)

    def _populate_classes_tree(self):
        for item in self.classes_tree.get_children():
            self.classes_tree.delete(item)
        
        if not self.classes:
            self.classes_tree.insert("", "end", text=self._("classes_not_found"), iid="cls_not_found", open=False)
            return

        for cls in self.classes:
            class_iid = f"cls_{cls.vtable_address}"
            is_dotnet = bool(cls.method_names)
            vtable_str = f"vtable: 0x{cls.vtable_address:x}" if cls.vtable_address != 0 and not is_dotnet else ""
            tags = ("is_stub",) if cls.is_stub else ()
            class_node = self.classes_tree.insert(
                "", "end", text=cls.name,
                values=(vtable_str,),
                iid=class_iid,
                tags=tags
            )

            if cls.base_classes:
                bases_node_iid = f"bases_{cls.vtable_address}"
                bases_node = self.classes_tree.insert(class_node, "end", text=self._("base_classes_node"), iid=bases_node_iid, open=True)
                for base_name in cls.base_classes:
                    base_iid = f"base_{cls.vtable_address}_{base_name}"
                    self.classes_tree.insert(bases_node, "end", text=base_name, iid=base_iid)

            if cls.methods:
                methods_node_name = self._("methods_node") if is_dotnet else self._("virtual_methods_node")
                methods_node_iid = f"methods_{cls.vtable_address}"
                methods_node = self.classes_tree.insert(class_node, "end", text=methods_node_name, iid=methods_node_iid, open=False)
                for method_addr in cls.methods:
                    method_iid = f"method_{method_addr}"
                    method_name = cls.method_names.get(method_addr, f"method_{method_addr:x}")
                    addr_text = f"0x{method_addr:x}"
                    
                    self.classes_tree.insert(
                        methods_node, "end", text=method_name,
                        values=(addr_text,),
                        iid=method_iid
                    )

    def _populate_variables_tree(self):
        for item in self.variables_tree.get_children():
            self.variables_tree.delete(item)
        
        if not self.variables:
            self.variables_tree.insert("", "end", values=(self._("variables_not_found"), "", ""))
            return

        for var in self.variables:
            iid = str(var.address)
            self.variables_tree.insert(
                "", "end",
                values=(f"0x{var.address:x}", var.type, var.value),
                iid=iid
            )

    def _populate_signatures_tree(self):
        for item in self.signatures_tree.get_children():
            self.signatures_tree.delete(item)
        
        if not self.scan_results:
            self.signatures_tree.insert("", "end", values=(self._("signatures_not_found"), "", ""))
            return

        for res in self.scan_results:
            iid = f"sig_{res.address}_{res.signature_id}"
            addr_str = f"0x{res.address:x}" if res.address > 4096 else f"Offset {res.address}"
            self.signatures_tree.insert(
                "", "end",
                values=(addr_str, res.type, res.name),
                iid=iid
            )

    def _populate_info_tab(self):
        self.info_text_area.config(state=tk.NORMAL)
        self.info_text_area.delete("1.0", tk.END)

        if not self.file_info:
            self.info_text_area.insert(tk.END, self._("info_not_available"))
            self.info_text_area.config(state=tk.DISABLED)
            return

        info = self.file_info

        self.info_text_area.insert(tk.END, self._("info_hashes") + "\n", "title")
        for name, value in info.hashes.items():
            self.info_text_area.insert(tk.END, f"{name.upper():<8}", "key")
            self.info_text_area.insert(tk.END, f"{value}\n")
        self.info_text_area.insert(tk.END, "\n")

        self.info_text_area.insert(tk.END, self._("info_general") + "\n", "title")
        for name, value in info.general.items():
            self.info_text_area.insert(tk.END, f"{name:<16}", "key")
            self.info_text_area.insert(tk.END, f"{str(value)}\n")
        self.info_text_area.insert(tk.END, "\n")

        self.info_text_area.insert(tk.END, self._("info_analysis") + "\n", "title")
        self.info_text_area.insert(tk.END, f"{self._('info_compiler'):<16}", "key")
        self.info_text_area.insert(tk.END, f"{info.compiler}\n")
        self.info_text_area.insert(tk.END, f"{self._('info_language'):<16}", "key")
        self.info_text_area.insert(tk.END, f"{info.language}\n")
        self.info_text_area.insert(tk.END, "\n")
        if info.packer != "N/A":
            self.info_text_area.insert(tk.END, f"{self._('info_packer'):<16}", "key")
            self.info_text_area.insert(tk.END, f"{info.packer}\n")
            self.info_text_area.insert(tk.END, "\n")

        self.info_text_area.insert(tk.END, self._("info_security") + "\n", "title")
        sec = info.security
        features = [
            (self._("sec_aslr"), sec.aslr),
            (self._("sec_dep"), sec.dep),
            (self._("sec_safeseh"), sec.safe_seh),
            (self._("sec_cfg"), sec.control_flow_guard),
            (self._("sec_auth"), sec.authenticode),
            (self._("sec_tls"), sec.tls_callbacks),
            (self._("sec_entropy"), sec.high_entropy_sections),
        ]
        for name, present in features:
            status = self._("present") if present else self._("absent")
            color = "comment" if present else "error_fg"
            self.info_text_area.insert(tk.END, f"{name:<28}", "key")
            self.info_text_area.insert(tk.END, f"{status}\n", color)
        self.info_text_area.insert(tk.END, "\n")

        self.info_text_area.insert(tk.END, self._("info_sections") + "\n", "title")
        header = f"{self._('col_name'):<10} {self._('col_address'):<18} {self._('col_size'):<12} {self._('col_entropy'):<10} {self._('col_flags')}\n"
        self.info_text_area.insert(tk.END, header, "key")
        self.info_text_area.insert(tk.END, "-"*len(header) + "\n")
        for s in info.sections:
            name_str = f"{s.name:<10}"
            addr_str = f"0x{s.virtual_address:<16x}"
            size_str = f"{s.virtual_size:<12}"
            entropy_str = f"{s.entropy:<9.2f} "
            self.info_text_area.insert(tk.END, f"{name_str} {addr_str} {size_str} {entropy_str} {' '.join(s.characteristics)}\n")

        if self.anti_debug_results:
            self.info_text_area.insert(tk.END, self._("info_anti_analysis") + "\n", "title")
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
        for item in self.imports_tree.get_children():
            self.imports_tree.delete(item)
        for item in self.exports_tree.get_children():
            self.exports_tree.delete(item)

        if not self.file_info:
            return

        if self.file_info.imports:
            for dll, funcs in sorted(self.file_info.imports.items()):
                dll_node = self.imports_tree.insert("", "end", text=dll, open=False)
                for func in sorted(funcs, key=lambda f: f.name):
                    iid = f"imp_{func.address}"
                    self.imports_tree.insert(dll_node, "end", text=func.name, iid=iid)
        else:
            self.imports_tree.insert("", "end", text=self._("imports_not_found"))

        if self.file_info.exports:
            for addr, func_name in sorted(self.file_info.exports.items()):
                self.exports_tree.insert("", "end", text=f"0x{addr:x}  {func_name}")
        else:
            self.exports_tree.insert("", "end", text=self._("exports_not_found"))

    def _populate_explorer_tree(self):
        for item in self.explorer_tree.get_children():
            self.explorer_tree.delete(item)
        self.explorer_iid_to_node.clear()

        if not self.file_structure:
            self.explorer_tree.insert("", "end", text=self._("structure_not_found"), iid="exp_not_found")
            return

        def add_node(parent_iid, node: ExplorerNode, is_root: bool = False):
            prefix = "📁" if node.node_type == 'directory' else "📄"
            node_text = f"{prefix} {node.name}"
            
            # Для файлов можно добавить размер
            if node.node_type == 'file' and node.size > 0:
                size_str = f" ({node.size // 1024} KB)" if node.size >= 1024 else f" ({node.size} B)"
                node_text += size_str

            node_iid = self.explorer_tree.insert(parent_iid, "end", text=node_text, open=is_root)
            self.explorer_iid_to_node[node_iid] = node
            for child in sorted(node.children, key=lambda n: (n.node_type, n.name)):
                add_node(node_iid, child)

        add_node("", self.file_structure, is_root=True)

    def _on_function_select(self, event):
        selected_items = self.functions_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        
        if not item_id.startswith("fn_"):
            return

        try:
            address = int(item_id.split('_', 1)[1])
            self._scroll_to_address(address)
        except (ValueError, TypeError, IndexError):
            return # Ошибка парсинга iid

    def _on_basic_block_select(self, event):
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
        selected_items = self.classes_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        
        try:
            id_type, addr_str = item_id.split('_', 1)
            address = int(addr_str)
            
            is_dotnet_method = False
            if id_type == 'method':
                for cls in self.classes:
                    if address in cls.methods:
                        if cls.method_names: # Признак .NET класса
                            is_dotnet_method = True
                        break
            
            if is_dotnet_method:
                return

            self._scroll_to_address(address)

        except (ValueError, TypeError, IndexError):
            return # Клик по "Не найдено" или неверный формат iid

    def _on_variable_select(self, event):
        selected_items = self.variables_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0] # iid - это адрес
        try:
            address = int(item_id)
            # Находим объект переменной
            variable = next((v for v in self.variables if v.address == address), None)
            if not variable or not variable.xrefs:
                messagebox.showinfo(self._("xrefs_title"), self._("xrefs_not_found_var").format(address=address))
                return

            if len(variable.xrefs) == 1:
                self._scroll_to_address(variable.xrefs[0])
            else:
                XrefsWindow(self, address, set(variable.xrefs), self.address_to_instruction, self.functions)
        except (ValueError, TypeError, StopIteration):
            return

    def _on_signature_select(self, event):
        selected_items = self.signatures_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        try:
            parts = item_id.split('_')
            address = int(parts[1])
            
            if address > 4096 and self.pe_object:
                self._scroll_to_address(address)
            elif self.hex_view_widget:
                for i in range(len(self.right_notebook.tabs())):
                    if self.right_notebook.tab(i, "text") == self._("hex_view_tab"):
                        self.right_notebook.select(i)
                        break
                self.hex_view_widget.scroll_to_offset(address)
        except (ValueError, TypeError, IndexError):
            return

    def _on_string_select(self, address: int):
        
        if not self.pe_object or not self.hex_view_widget:
            return
        
        try:
            rva = address - self.pe_object.OPTIONAL_HEADER.ImageBase
            offset = self.pe_object.get_offset_from_rva(rva)
            
            
            for i in range(len(self.right_notebook.tabs())):
                if self.right_notebook.tab(i, "text") == self._("hex_view_tab"):
                    self.right_notebook.select(i)
                    break
            
            self.hex_view_widget.scroll_to_offset(offset)
        except Exception:
            self._scroll_to_address(address)

    def _scroll_to_address(self, address: int):
        line_index = self.address_to_line.get(address)
        if line_index:
            self.text_area.see(line_index)
            self.text_area.tag_remove("selection_highlight", "1.0", tk.END)
            self.text_area.tag_add("selection_highlight", line_index, f"{line_index} lineend")

    def _on_import_select(self, event):
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

        source_addrs = self.xrefs.get(iat_address)
        
        if not source_addrs:
            messagebox.showinfo(self._("xrefs_title"), self._("xrefs_not_found_imp").format(address=iat_address))
            return
        
        if len(source_addrs) == 1:
            self._scroll_to_address(list(source_addrs)[0])
        else:
            XrefsWindow(self, iat_address, source_addrs, self.address_to_instruction, self.functions)

    def _show_explorer_context_menu(self, event):
        self._selected_explorer_node = None
        iid = self.explorer_tree.identify_row(event.y)
        if not iid:
            return
        
        self.explorer_tree.selection_set(iid)
        
        node = self.explorer_iid_to_node.get(iid)
        can_export = node and (
            (node.node_type == 'file' and node.data_len > 0) or
            (node.node_type == 'directory' and node.children)
        )

        if can_export:
            self._selected_explorer_node = node
            self.explorer_context_menu.entryconfig(self._("extract_menu"), state=tk.NORMAL)
        else:
            self.explorer_context_menu.entryconfig(self._("extract_menu"), state=tk.DISABLED)
            
        self.explorer_context_menu.tk_popup(event.x_root, event.y_root)

    def _export_from_explorer(self):
        if not self._selected_explorer_node or not self.pe_object:
            return
        
        node = self._selected_explorer_node
        
        if node.node_type == 'file':
            self._export_explorer_file(node)
        elif node.node_type == 'directory':
            self._export_explorer_directory(node)

    def _export_explorer_file(self, node: ExplorerNode):
        filepath = filedialog.asksaveasfilename(
            title=self._("save_file_title").format(name=node.name),
            initialfile=node.name,
            defaultextension=".*"
        )
        if not filepath: return
        
        try:
            file_data = self.pe_object.get_data(node.data_pos, node.data_len)
            with open(filepath, "wb") as f:
                f.write(file_data)
            messagebox.showinfo(self._("done_title"), self._("file_extracted_success").format(name=node.name))
        except Exception as e:
            messagebox.showerror(self._("extract_error_title"), self._("file_extract_error").format(e=e))

    def _export_explorer_directory(self, node: ExplorerNode):
        dir_path = filedialog.askdirectory(title=self._("select_folder_title").format(name=node.name))
        if not dir_path: return

        target_path = os.path.join(dir_path, node.name)
        try:
            os.makedirs(target_path, exist_ok=True)
            for child in node.children:
                self._save_node_recursively(child, target_path)

            messagebox.showinfo(self._("done_title"), self._("folder_extracted_success").format(name=node.name, path=dir_path))
        except Exception as e:
            messagebox.showerror(self._("extract_error_title"), self._("folder_extract_error").format(e=e))

    def _save_node_recursively(self, node: ExplorerNode, current_path: str):
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
        header = self._("disasm_header").format(section=self.section_name, filename=os.path.basename(self.current_filepath)) + "\n"
        header += self._("base_addr_header").format(address=self.base_address) + "\n\n"
        
        header_start_index = self.text_area.index(tk.END)
        self.text_area.insert(tk.END, header)
        self.text_area.tag_add("comment", header_start_index, f"{header_start_index} + {len(header)} chars")


    def _insert_and_highlight_instruction(self, instr: Instruction):
        start_index = self.text_area.index(tk.END)
        line_num = start_index.split('.')[0]
        self.line_to_instruction[line_num] = instr
        self.address_to_line[instr.address] = start_index.split('.')[0] + ".0"

        addr_str = f"0x{instr.address:08x}: "
        
        bytes_str = ""
        if self.settings.get("show_bytes", True):
            hex_bytes = ' '.join(f'{b:02x}' for b in instr.bytes)
            bytes_str = f"{hex_bytes:<24} "

        mnemonic = instr.mnemonic
        if self.settings.get("uppercase_mnemonics", False):
            mnemonic = mnemonic.upper()
        mnemonic_str = f"{mnemonic} "

        operands_str = self._resolve_operand_names(instr)

        self.text_area.insert(tk.END, addr_str, "address")
        if bytes_str:
            self.text_area.insert(tk.END, bytes_str, "bytes")

        self.text_area.insert(tk.END, mnemonic_str, "mnemonic")

        operands_start_index = self.text_area.index(tk.END)
        self.text_area.insert(tk.END, operands_str)
        self._highlight_substrings(self.ptr_pattern, "ptr", operands_start_index, operands_str)
        self._highlight_substrings(self.reg_pattern, "register", operands_start_index, operands_str)

        for match in self.hex_pattern.finditer(operands_str):
            start, end = match.start(), match.end()
            hex_val_str = match.group(0)
            start_pos = f"{operands_start_index} + {start} chars"
            end_pos = f"{operands_start_index} + {end} chars"

            try:
                addr = int(hex_val_str, 16)
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

        if instr.is_error:
            if self.settings.get("show_errors_highlight", True):
                line_start = start_index.split('.')[0] + ".0"
                self.text_area.tag_add("error_line", line_start, f"{line_start} lineend")

    def _resolve_operand_names(self, instr: Instruction) -> str:
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
        for match in pattern.finditer(text):
            start = match.start()
            end = match.end()
            self.text_area.tag_add(tag, f"{start_index} + {start} chars", f"{start_index} + {end} chars")

    def export_asm(self):
        if not self.current_filepath:
            return
        
        base_name = os.path.basename(self.current_filepath)
        default_filename = os.path.splitext(base_name)[0] + '.asm'

        filepath = filedialog.asksaveasfilename(
            title=self._("save_as_title"),
            initialfile=default_filename,
            defaultextension=".asm",
            filetypes=((self._("asm_files"), "*.asm"), (self._("txt_files"), "*.txt"), (self._("all_files_filter"), "*.*"))
        )
        if not filepath:
            return

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(self.text_area.get("1.0", tk.END))
            messagebox.showinfo(self._("done_title"), self._("save_success").format(filepath=filepath))
        except Exception as e:
            messagebox.showerror(self._("save_error_title"), self._("save_error_msg").format(e=e))

    def _copy_line(self):
        if self._context_line_text:
            self.clipboard_clear()
            self.clipboard_append(self._context_line_text)

    def _show_function_context_menu(self, event):
        iid = self.functions_tree.identify_row(event.y)
        if not iid:
            return

        self.functions_tree.selection_set(iid)
        self.function_context_menu.tk_popup(event.x_root, event.y_root)

    def _rename_function(self):
        selected_items = self.functions_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        if not item_id.startswith("fn_"):
            return

        try:
            address = int(item_id.split('_', 1)[1])
            current_name = self.function_map[address].name
            new_name = simpledialog.askstring(self._("rename_func_title"), self._("rename_func_prompt").format(address=address), initialvalue=current_name)
            
            if new_name and new_name != current_name:
                self.user_labels[address] = new_name
                self._start_async_analysis()
        except (ValueError, TypeError, IndexError, KeyError):
            messagebox.showerror(self._("error_title"), self._("rename_func_error"))

    def apply_settings(self, old_settings: dict):
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

        component_keys = [
            "component_functions_enabled", "component_blocks_enabled", "component_classes_enabled",
            "component_variables_enabled", "component_signatures_enabled", "component_strings_enabled",
            "component_info_enabled", "component_imports_enabled", "component_explorer_enabled"
        ]
        components_changed = any(old_settings.get(k) != new_settings.get(k) for k in component_keys)

        lang_changed = old_settings.get("language") != new_settings.get("language")

        if theme_changed:
            self._apply_theme()

        if lang_changed or components_changed:
            messagebox.showinfo(
                self._("restart_required_title"),
                self._("restart_required_message")
            )

        if not self.current_filepath:
            return

        if analysis_changed:
            self._start_async_analysis()
        elif theme_changed or listing_changed:
            self._redisplay_listing()

    def _on_address_link_click(self, event):
        pos = self.text_area.index(f"@{event.x},{event.y}")

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
        self._context_target_addr = None
        self._context_line_text = None

        pos = self.text_area.index(f"@{event.x},{event.y}")
        line_num = pos.split('.')[0]

        line_text = self.text_area.get(f"{line_num}.0", f"{line_num}.end").strip()
        if line_text:
            self._context_line_text = line_text
            self.context_menu.entryconfig(self._("copy_line_menu"), state=tk.NORMAL)
        else:
            self.context_menu.entryconfig(self._("copy_line_menu"), state=tk.DISABLED)

        instr = self.line_to_instruction.get(line_num)
        
        target_addr = None
        if instr:
            if instr.address in self.xrefs:
                target_addr = instr.address
            else:
                matches = self.hex_pattern.findall(instr.operands)
                if matches:
                    try:
                        op_addr = int(matches[0], 16)
                        if op_addr in self.xrefs:
                            target_addr = op_addr
                    except (ValueError, TypeError):
                        pass
        
        if target_addr:
            self._context_target_addr = target_addr
            self.context_menu.entryconfig(self._("show_xrefs_menu"), state=tk.NORMAL)
        else:
            self.context_menu.entryconfig(self._("show_xrefs_menu"), state=tk.DISABLED)
            
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def _show_xrefs(self):
        if self._context_target_addr is None:
            return
        
        source_addrs = self.xrefs.get(self._context_target_addr, set())
        if not source_addrs:
            messagebox.showinfo(self._("xrefs_title"), self._("xrefs_not_found").format(address=self._context_target_addr))
            return
            
        XrefsWindow(self, self._context_target_addr, source_addrs, self.address_to_instruction, self.functions)

    def _on_explorer_double_click(self, event):
        iid = self.explorer_tree.identify_row(event.y)
        if not iid:
            return

        node = self.explorer_iid_to_node.get(iid)
        
        if node and node.node_type == 'file' and node.data_len > 0:
            self._export_explorer_file(node)

class SectionSelectionWindow(tk.Toplevel):
    def __init__(self, parent: DisassemblerApp, pe: "pefile.PE"):
        super().__init__(parent)
        self.parent = parent
        self.pe = pe
        self.selected_section: Optional["pefile.SectionStructure"] = None

        self.title(self.parent._("select_section_title"))
        self.geometry("650x400")
        self.transient(parent)
        self.grab_set()

        tree_frame = ttk.Frame(self, padding=5)
        tree_frame.pack(expand=True, fill=tk.BOTH)

        columns = ("name", "va", "vsize", "rsize", "flags")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        self.tree.heading("name", text=self.parent._("name_col"))
        self.tree.heading("va", text=self.parent._("col_va"))
        self.tree.heading("vsize", text=self.parent._("col_vsize"))
        self.tree.heading("rsize", text=self.parent._("col_rsize"))
        self.tree.heading("flags", text=self.parent._("col_flags"))

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

        button_frame = ttk.Frame(self, padding=5)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        button_frame.columnconfigure(0, weight=1)

        self.analyze_button = ttk.Button(button_frame, text=self.parent._("analyze_btn"), command=self._analyze_and_close, state=tk.DISABLED)
        self.analyze_button.grid(row=0, column=1, padx=5)

        cancel_button = ttk.Button(button_frame, text=self.parent._("cancel_btn"), command=self.destroy)
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
    def __init__(self, parent: DisassemblerApp, target_addr: int, source_addrs: Set[int], addr_to_instr: Dict[int, Instruction], functions: List[FoundFunction]):
        super().__init__(parent)
        self.parent = parent
        self.title(self.parent._("xrefs_for_addr_title").format(address=target_addr))
        self.geometry("800x400")
        self.transient(parent)
        self.grab_set()

        tree = ttk.Treeview(self, columns=("function", "address", "instruction"), show="headings")
        tree.heading("function", text=self.parent._("col_function"))
        tree.heading("address", text=self.parent._("col_address"))
        tree.heading("instruction", text=self.parent._("col_instruction"))
        tree.column("function", width=250, anchor='w')
        tree.column("address", width=120, stretch=tk.NO, anchor='w')
        tree.column("instruction", anchor='w')
        tree.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        func_ranges = []
        if functions:
            sorted_funcs = sorted(functions, key=lambda f: f.address)
            for i, func in enumerate(sorted_funcs):
                start = func.address
                end = sorted_funcs[i+1].address if i + 1 < len(sorted_funcs) else float('inf')
                func_ranges.append((start, end, func.name))

        def get_func_name(addr: int) -> str:
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
                tree.insert("", tk.END, values=(func_name, f"0x{addr:x}", self.parent._("no_data")), iid=str(addr))
            
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
            self.destroy()
        except (ValueError, TypeError):
            pass


class SettingsWindow(tk.Toplevel):
    def __init__(self, parent: DisassemblerApp, settings: dict, defaults: dict):
        super().__init__(parent)
        self.parent = parent
        self.settings = settings
        self.defaults = defaults

        self.title("Настройки")
        self.geometry("450x520")
        self.resizable(False, False)

        self.transient(parent)
        self.grab_set()

        main_frame = ttk.Frame(self, padding=(10, 10, 10, 0))
        main_frame.pack(expand=True, fill=tk.BOTH)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(expand=True, fill=tk.BOTH)

        appearance_tab = ttk.Frame(notebook, padding="10")
        notebook.add(appearance_tab, text=self.parent._("appearance_tab"))

        lang_frame = ttk.Frame(appearance_tab)
        lang_frame.pack(anchor='w', padx=5, pady=(5, 10), fill='x')
        lang_label = ttk.Label(lang_frame, text=self.parent._("language_label"))
        lang_label.pack(side=tk.LEFT, padx=(0, 5))

        self.lang_var = tk.StringVar(value=self.settings.get("language", "ru"))
        self.lang_map = {"ru": "Русский", "en": "English"}
        self.reverse_lang_map = {v: k for k, v in self.lang_map.items()}

        self.lang_combo = ttk.Combobox(
            lang_frame,
            textvariable=tk.StringVar(value=self.lang_map.get(self.lang_var.get())),
            values=list(self.lang_map.values()),
            state="readonly"
        )
        self.lang_combo.pack(side=tk.LEFT)
        self.lang_combo.bind("<<ComboboxSelected>>", self._on_lang_select)

        self.dark_theme_var = tk.BooleanVar(value=self.settings.get("dark_theme", False))
        cb_dark = ttk.Checkbutton(
            appearance_tab,
            text=self.parent._("dark_theme_checkbox"),
            variable=self.dark_theme_var
        )
        cb_dark.pack(anchor='w', padx=5, pady=(5, 10))

        listing_tab = ttk.Frame(notebook, padding="10")
        notebook.add(listing_tab, text=self.parent._("listing_tab"))

        disasm_view_frame = ttk.LabelFrame(listing_tab, text=self.parent._("display_group"))
        disasm_view_frame.pack(fill=tk.X, pady=5, padx=5)

        self.show_padding_var = tk.BooleanVar(value=self.settings.get("show_padding", False))
        cb_padding = ttk.Checkbutton(
            disasm_view_frame,
            text=self.parent._("show_padding_checkbox"),
            variable=self.show_padding_var
        )
        cb_padding.pack(anchor='w', padx=5, pady=2)

        self.show_bytes_var = tk.BooleanVar(value=self.settings.get("show_bytes", True))
        cb_bytes = ttk.Checkbutton(
            disasm_view_frame,
            text=self.parent._("show_bytes_checkbox"),
            variable=self.show_bytes_var
        )
        cb_bytes.pack(anchor='w', padx=5, pady=2)

        self.uppercase_mnemonics_var = tk.BooleanVar(value=self.settings.get("uppercase_mnemonics", False))
        cb_upper_mnem = ttk.Checkbutton(
            disasm_view_frame,
            text=self.parent._("uppercase_mnemonics_checkbox"),
            variable=self.uppercase_mnemonics_var
        )
        cb_upper_mnem.pack(anchor='w', padx=5, pady=2)

        self.show_errors_highlight_var = tk.BooleanVar(value=self.settings.get("show_errors_highlight", True))
        cb_errors = ttk.Checkbutton(
            disasm_view_frame,
            text=self.parent._("show_errors_checkbox"),
            variable=self.show_errors_highlight_var
        )
        cb_errors.pack(anchor='w', padx=5, pady=2)

        analysis_tab = ttk.Frame(notebook, padding="10")
        notebook.add(analysis_tab, text=self.parent._("analysis_tab"))

        loading_frame = ttk.LabelFrame(analysis_tab, text=self.parent._("file_loading_group"))
        loading_frame.pack(fill=tk.X, pady=(5,0), padx=5)

        self.auto_section_search_var = tk.BooleanVar(value=self.settings.get("auto_section_search", True))
        cb_auto_section = ttk.Checkbutton(
            loading_frame, text=self.parent._("auto_section_checkbox"), variable=self.auto_section_search_var
        )
        cb_auto_section.pack(anchor='w', padx=5, pady=2)
        analysis_frame = ttk.LabelFrame(analysis_tab, text=self.parent._("func_analysis_group"))
        analysis_frame.pack(fill=tk.X, pady=(5,0), padx=5)

        self.use_prologue_heuristic_var = tk.BooleanVar(value=self.settings.get("use_prologue_heuristic", True))
        cb_prologue = ttk.Checkbutton(analysis_frame, text=self.parent._("prologue_heuristic_checkbox"), variable=self.use_prologue_heuristic_var)
        cb_prologue.pack(anchor='w', padx=5, pady=2)

        self.use_separator_heuristic_var = tk.BooleanVar(value=self.settings.get("use_separator_heuristic", True))
        cb_separator = ttk.Checkbutton(analysis_frame, text=self.parent._("separator_heuristic_checkbox"), variable=self.use_separator_heuristic_var)
        cb_separator.pack(anchor='w', padx=5, pady=2)

        self.use_padding_heuristic_var = tk.BooleanVar(value=self.settings.get("use_padding_heuristic", True))
        cb_padding_h = ttk.Checkbutton(analysis_frame, text=self.parent._("padding_heuristic_checkbox"), variable=self.use_padding_heuristic_var)
        cb_padding_h.pack(anchor='w', padx=5, pady=2)

        self.analyze_basic_blocks_var = tk.BooleanVar(value=self.settings.get("analyze_basic_blocks", True))
        cb_blocks = ttk.Checkbutton(analysis_frame, text=self.parent._("analyze_blocks_checkbox"), variable=self.analyze_basic_blocks_var)
        cb_blocks.pack(anchor='w', padx=5, pady=2)

        other_analysis_frame = ttk.LabelFrame(analysis_tab, text=self.parent._("other_analyzers_group"))
        other_analysis_frame.pack(fill=tk.X, pady=(5,0), padx=5)

        self.analyze_xrefs_var = tk.BooleanVar(value=self.settings.get("analyze_xrefs", True))
        cb_xrefs = ttk.Checkbutton(other_analysis_frame, text=self.parent._("analyze_xrefs_checkbox"), variable=self.analyze_xrefs_var)
        cb_xrefs.pack(anchor='w', padx=5, pady=2)

        self.analyze_classes_var = tk.BooleanVar(value=self.settings.get("analyze_classes", True))
        cb_classes = ttk.Checkbutton(other_analysis_frame, text=self.parent._("analyze_classes_checkbox"), variable=self.analyze_classes_var)
        cb_classes.pack(anchor='w', padx=5, pady=2)

        self.analyze_variables_var = tk.BooleanVar(value=self.settings.get("analyze_variables", True))
        cb_vars = ttk.Checkbutton(other_analysis_frame, text=self.parent._("analyze_vars_checkbox"), variable=self.analyze_variables_var)
        cb_vars.pack(anchor='w', padx=5, pady=2)

        self.analyze_signatures_var = tk.BooleanVar(value=self.settings.get("analyze_signatures", True))
        cb_sigs = ttk.Checkbutton(
            other_analysis_frame,
            text=self.parent._("analyze_signatures_checkbox"),
            variable=self.analyze_signatures_var
        )
        cb_sigs.pack(anchor='w', padx=5, pady=2)

        self.analyze_all_sections_var = tk.BooleanVar(value=self.settings.get("analyze_all_sections_for_compiler", True))
        cb_all_sections = ttk.Checkbutton(
            other_analysis_frame,
            text=self.parent._("analyze_all_sections_checkbox"),
            variable=self.analyze_all_sections_var
        )
        cb_all_sections.pack(anchor='w', padx=5, pady=(10, 2))

        anti_debug_frame = ttk.Frame(other_analysis_frame)
        anti_debug_frame.pack(anchor='w', fill='x', padx=5, pady=(10, 2))

        self.analyze_anti_debug_var = tk.BooleanVar(value=self.settings.get("analyze_anti_debug", False))
        cb_anti_debug = ttk.Checkbutton(
            anti_debug_frame,
            text=self.parent._("analyze_antidebug_checkbox"),
            variable=self.analyze_anti_debug_var
        )
        cb_anti_debug.pack(side=tk.LEFT)

        warning_label = ttk.Label(anti_debug_frame, text=self.parent._("beta_warning"), style="Warning.TLabel")
        warning_label.pack(side=tk.LEFT, padx=(5, 0))

        components_tab = ttk.Frame(notebook, padding="10")
        notebook.add(components_tab, text=self.parent._("settings_components_tab"))

        components_frame = ttk.LabelFrame(components_tab, text=self.parent._("toolbox_components_group"))
        components_frame.pack(fill=tk.X, pady=5, padx=5)

        self.component_vars = {}
        component_keys = [
            ("functions", "enable_functions_tab"), ("blocks", "enable_blocks_tab"),
            ("classes", "enable_classes_tab"), ("variables", "enable_variables_tab"),
            ("signatures", "enable_signatures_tab"), ("strings", "enable_strings_tab"),
            ("info", "enable_info_tab"), ("imports", "enable_imports_tab"),
            ("explorer", "enable_explorer_tab"),
        ]

        for key, text_key in component_keys:
            setting_key = f"component_{key}_enabled"
            self.component_vars[key] = tk.BooleanVar(value=self.settings.get(setting_key, True))
            cb = ttk.Checkbutton(
                components_frame,
                text=self.parent._(text_key),
                variable=self.component_vars[key]
            )
            cb.pack(anchor='w', padx=5, pady=2)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(15, 0))
        button_frame.columnconfigure(1, weight=1) # Центральная колонка растягивается

        reset_button = ttk.Button(button_frame, text=self.parent._("reset_btn"), command=self._reset_to_defaults)
        reset_button.grid(row=0, column=0, sticky=tk.W, padx=5)

        ok_button = ttk.Button(button_frame, text=self.parent._("ok_btn"), command=self._apply_and_close)
        ok_button.grid(row=0, column=1, sticky=tk.E, padx=5)

        cancel_button = ttk.Button(button_frame, text=self.parent._("cancel_btn"), command=self.destroy)
        cancel_button.grid(row=0, column=2, sticky=tk.W, padx=5)

    def _on_lang_select(self, event=None):
        selected_display_name = self.lang_combo.get()
        lang_code = self.reverse_lang_map.get(selected_display_name)
        if lang_code:
            self.lang_var.set(lang_code)

    def _apply_and_close(self):
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
        self.parent.settings["analyze_signatures"] = self.analyze_signatures_var.get()
        self.parent.settings["auto_section_search"] = self.auto_section_search_var.get()
        self.parent.settings["analyze_all_sections_for_compiler"] = self.analyze_all_sections_var.get()
        self.parent.settings["language"] = self.lang_var.get()

        for key, var in self.component_vars.items():
            self.parent.settings[f"component_{key}_enabled"] = var.get()

        self.parent._save_settings()
        self.parent.apply_settings(old_settings)
        self.destroy()

    def _reset_to_defaults(self):
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
        self.analyze_signatures_var.set(self.defaults["analyze_signatures"])
        self.auto_section_search_var.set(self.defaults["auto_section_search"])
        self.analyze_all_sections_var.set(self.defaults["analyze_all_sections_for_compiler"])
        self.lang_var.set(self.defaults["language"])
        self.lang_combo.set(self.lang_map.get(self.defaults["language"]))

        for key, var in self.component_vars.items():
            var.set(self.defaults[f"component_{key}_enabled"])
        self.lang_combo.set(self.lang_map.get(self.defaults["language"]))