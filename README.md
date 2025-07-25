# vxASM - Simple Python disassembler

Hi! This is Vexapay Disassembler small project I created to learn about the internal workings of Windows executables (PE files). It's a simple yet functional tool that helps you look "under the hood" of `.exe` and `.dll` files.

The project is written in Python using Tkinter for the graphical interface, so it should run on most systems without much hassle.



##  Features


*   **Full-featured x86/x86-64 Disassembler:** Parses the code in the executable sections of a file.
*   **Interactive Interface:**
    *   User-friendly listing with syntax highlighting.
    *   Clickable addresses for quick navigation.
    *   Light and dark themes. 
*   **File Structure Analysis:**
    *   **Explorer:** Shows the internal file structure. Especially useful for unpacked PyInstaller applications—you can view and extract nested files!
    *   **Packer Detector:** Recognizes UPX and other types of packers/installers.
*   **Automatic Code Analysis:**
    *   **Function Finder:** Uses several heuristics to automatically identify functions.
    *   **Cross-References (Xrefs):** Shows where a specific address is referenced from in the code.
    *   **C++ Class Analysis:** Searches for virtual function tables (vftables) for classes compiled with MSVC and GCC/Clang. (bad working)
    *   **Anti-Debugging Technique Finder:** Detects some common tricks programs use to hinder analysis. (bad working)**
    

##  How to launch

It's simple. You'll need Python 3.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Bogdan0759/vxASM
    cd vxASM
    ```
    

2.  **Install dependencies:**


    Install the required libraries from the `requirements.txt` file:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application:**
    ```bash
    python main.py
    ```


## 🤝 Want to Contribute?

I'd be happy to receive any help! If you have ideas for improvement, found a bug, or want to add support for new instructions free to create an Issue or a Pull Request.

## 📄 License

This project is distributed under the MIT License. See `LICENSE` for more information.