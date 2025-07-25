import tkinter as tk
from tkinter import messagebox
import sys
from gui import DisassemblerApp

def main():
    """Главная функция для запуска GUI дизассемблера."""
    try:
        app = DisassemblerApp()
        app.mainloop()
    except Exception as e:
        # This is a last-resort catch-all for unexpected errors during startup.
        # It's useful if the app fails to initialize for reasons
        # not already handled inside DisassemblerApp.__init__ (like the pefile import).
        # We need a temporary root to show the messagebox if the main window failed.
        root = tk.Tk()
        root.withdraw()  # Hide the empty root window
        messagebox.showerror(
            "Критическая ошибка при запуске",
            f"Произошла непредвиденная ошибка:\n\n{e}\n\nПриложение будет закрыто."
        )
        sys.exit(1)

if __name__ == "__main__":
    main()