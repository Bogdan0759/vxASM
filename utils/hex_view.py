import tkinter as tk
from tkinter import ttk
import sys

class HexView(ttk.Frame):
    
    def __init__(self, master, file_data: bytes, colors: dict, font_info: tuple, **kwargs):
        super().__init__(master, **kwargs)
        self.file_data = file_data if file_data else b''
        self.colors = colors
        self.font = font_info

        
        self.address_text = tk.Text(self, width=10, wrap=tk.NONE, font=self.font, padx=5)
        self.hex_text = tk.Text(self, width=50, wrap=tk.NONE, font=self.font, padx=5)
        self.ascii_text = tk.Text(self, width=18, wrap=tk.NONE, font=self.font, padx=5)
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self._on_scrollbar_drag)

        
        self.address_text.grid(row=0, column=0, sticky="ns")
        self.hex_text.grid(row=0, column=1, sticky="nsew")
        self.ascii_text.grid(row=0, column=2, sticky="ns")
        self.scrollbar.grid(row=0, column=3, sticky="ns")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        
        for widget in [self.address_text, self.hex_text, self.ascii_text]:
            widget.config(
                background=self.colors.get("widget_bg", "white"),
                foreground=self.colors.get("fg", "black"),
                selectbackground=self.colors.get("select_bg", "lightblue"),
                insertbackground=self.colors.get("cursor", "black"),
                borderwidth=0,
                highlightthickness=0,
            )
            
            widget.config(yscrollcommand=self.scrollbar.set)
            widget.bind("<MouseWheel>", self._on_mouse_wheel)
            widget.config(state=tk.DISABLED)

        self.populate_hex_view()

    def _on_scrollbar_drag(self, *args):
        
        self.address_text.yview(*args)
        self.hex_text.yview(*args)
        self.ascii_text.yview(*args)

    def _on_mouse_wheel(self, event):
        
        if sys.platform == "win32":
            delta = -1 * (event.delta // 120)
        else: 
            if event.num == 4: delta = -1
            elif event.num == 5: delta = 1
            else: delta = 0
        
        self.address_text.yview_scroll(delta, "units")
        self.hex_text.yview_scroll(delta, "units")
        self.ascii_text.yview_scroll(delta, "units")
        return "break"

    def populate_hex_view(self):
        
        for widget in [self.address_text, self.hex_text, self.ascii_text]:
            widget.config(state=tk.NORMAL)
            widget.delete("1.0", tk.END)

        if not self.file_data:
            for widget in [self.address_text, self.hex_text, self.ascii_text]:
                widget.config(state=tk.DISABLED)
            return

        bytes_per_line = 16
        addr_lines, hex_lines, ascii_lines = [], [], []

        for i in range(0, len(self.file_data), bytes_per_line):
            chunk = self.file_data[i:i+bytes_per_line]
            
            addr_lines.append(f"{i:08X}")
            hex_chunk = ' '.join(f"{b:02X}" for b in chunk)
            hex_lines.append(f"{hex_chunk:<47}") 
            ascii_lines.append(''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk))

        self.address_text.insert(tk.END, "\n".join(addr_lines))
        self.hex_text.insert(tk.END, "\n".join(hex_lines))
        self.ascii_text.insert(tk.END, "\n".join(ascii_lines))

        for widget in [self.address_text, self.hex_text, self.ascii_text]:
            widget.config(state=tk.DISABLED)

        self.address_text.tag_configure("address", foreground=self.colors.get("address", "gray"))
        self.address_text.tag_add("address", "1.0", tk.END)

        for widget in [self.address_text, self.hex_text, self.ascii_text]:
            widget.tag_configure("selection", background=self.colors.get("selection_highlight", "#fff8a5"))

    def scroll_to_offset(self, offset: int):
        
        if offset < 0 or offset >= len(self.file_data):
            return

        bytes_per_line = 16
        line_index = (offset // bytes_per_line) + 1
        
        for widget in [self.address_text, self.hex_text, self.ascii_text]:
            widget.tag_remove("selection", "1.0", tk.END)
            line_start = f"{line_index}.0"
            line_end = f"{line_index}.end"
            widget.tag_add("selection", line_start, line_end)
        
        self.address_text.yview_scroll(-self.address_text.yview()[0] * 100, "pages")
        self.address_text.yview_scroll(line_index - 5, "units")