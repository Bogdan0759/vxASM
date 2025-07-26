import tkinter as tk
from tkinter import ttk
import re
from typing import TYPE_CHECKING, List, Callable, Optional, Dict

if TYPE_CHECKING:
    import pefile

class FoundString:
    
    def __init__(self, address: int, s_type: str, value: str, section: str):
        self.address = address
        self.type = s_type
        self.value = value
        self.section = section

class StringView(ttk.Frame):
    
    def __init__(self, master, pe: "pefile.PE", on_select: Callable[[int], None], colors: dict, translations: Dict[str, str], **kwargs):
        super().__init__(master, **kwargs)
        self.pe = pe
        self.on_select = on_select
        self.colors = colors

        self.tree = ttk.Treeview(self, columns=("address", "type", "section", "value"), show="headings")
        self.tree.heading("address", text=translations.get("address_col", "Address"))
        self.tree.heading("type", text=translations.get("type_col", "Type"))
        self.tree.heading("section", text=translations.get("section_col", "Section"))
        self.tree.heading("value", text=translations.get("string_col", "String"))

        self.tree.column("address", width=120, stretch=tk.NO, anchor='w')
        self.tree.column("type", width=60, stretch=tk.NO, anchor='w')
        self.tree.column("section", width=80, stretch=tk.NO, anchor='w')
        self.tree.column("value", anchor='w')

        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self._on_double_click)

        self.find_strings()

    def _on_double_click(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        try:
            address = int(item_id)
            if self.on_select:
                self.on_select(address)
        except (ValueError, TypeError):
            pass

    def find_strings(self):
        if not self.pe:
            return

        strings = self._scan_for_strings()
        
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not strings:
            self.tree.insert("", "end", values=("(No strings found)", "", "", ""))
            return

        for s in strings:
            self.tree.insert("", "end", iid=str(s.address), values=(f"0x{s.address:x}", s.type, s.section, s.value))

    def _scan_for_strings(self) -> List[FoundString]:
        found = []
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        ascii_pattern = re.compile(b'([ -~\\t\\n\\r]{5,256})\x00')
        unicode_pattern = re.compile(b'((?:[ -~][\x00]){5,256})\x00\x00')
        data_sections = [s for s in self.pe.sections if s.Characteristics & 0x40000000 and s.SizeOfRawData > 0]

        for section in data_sections:
            data = section.get_data()
            section_name = section.Name.decode(errors='ignore').strip('\x00')
            section_addr = image_base + section.VirtualAddress
            for match in ascii_pattern.finditer(data):
                found.append(FoundString(section_addr + match.start(), "ASCII", match.group(1).decode('ascii', 'ignore'), section_name))
            for match in unicode_pattern.finditer(data):
                found.append(FoundString(section_addr + match.start(), "Unicode", match.group(1).decode('utf-16-le', 'ignore'), section_name))
        return sorted(found, key=lambda s: s.address)