import tkinter as tk
from tkinter import messagebox
import sys
from gui import DisassemblerApp
from localization import _, init_translator

def main():
    try:
        app = DisassemblerApp()
        app.mainloop()
    except Exception as e:
        root = tk.Tk()
        root.withdraw()  
        init_translator()
        messagebox.showerror(_("critical_startup_error_title"), _("unexpected_startup_error_msg").format(e=e))
        sys.exit(1)

if __name__ == "__main__":
    main()