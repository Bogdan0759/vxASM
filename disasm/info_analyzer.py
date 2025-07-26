import dataclasses
import hashlib
from typing import Dict, Any, TYPE_CHECKING, Optional, List
import re
import struct
import datetime
import math
 
if TYPE_CHECKING:
    import pefile

try:
    import pefile
except ImportError:
    pefile = None

def calculate_entropy(data: bytes) -> float:
    
    if not data:
        return 0.0
    
    entropy = 0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
        
    data_len = float(len(data))
    for count in byte_counts:
        if count == 0:
            continue
        p = float(count) / data_len
        entropy -= p * math.log(p, 2)
    return entropy

@dataclasses.dataclass
class SecurityFeatures:
    aslr: bool = False
    dep: bool = False
    safe_seh: bool = False
    control_flow_guard: bool = False
    authenticode: bool = False
    tls_callbacks: bool = False
    high_entropy_sections: bool = False
@dataclasses.dataclass
class ImportedFunction:
    name: str
    address: int

@dataclasses.dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: List[str]
    entropy: float

@dataclasses.dataclass
class FileInfo:
    
    hashes: Dict[str, str]
    general: Dict[str, Any]
    compiler: str
    language: str
    packer: str
    security: SecurityFeatures
    sections: List[SectionInfo]
    imports: Dict[str, List[ImportedFunction]]
    exports: Dict[int, str]

def _has_cpp_evidence(pe: "pefile.PE", search_data: bytes) -> bool:
    
    
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            
            if exp.name and (exp.name.startswith((b'?', b'@', b'_Z'))):
                return True

    
    
    
    if re.search(b'\\.\\?A[UV]|_ZTS|_ZTI', search_data):
        return True
    
    
    if re.search(b'C\\+\\+ Runtime Error', search_data):
        return True

    return False



def _detect_pyinstaller(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    pyinstaller_signatures = [
        b'pyi-windows-manifest-filename', b'pyi-archive', b'pyi-loader',
        b'pyinstaller', b'pyimod', b'Pyi-Main',
        b'python3',  
    ]
    found_sigs = []
    for sig in pyinstaller_signatures:
        if re.search(re.escape(sig), search_data, re.IGNORECASE):
            found_sigs.append(sig.decode(errors='ignore'))
    if found_sigs:
        return f"PyInstaller (sigs: {', '.join(found_sigs)})", "Python"
    return None

def _detect_dotnet(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    if not (hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR') and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct.VirtualAddress != 0):
        return None

    language = ".NET Assembly"
    try:
        metadata_rva = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct.MetaData.VirtualAddress
        metadata_size = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct.MetaData.Size
        metadata_data = pe.get_data(metadata_rva, metadata_size)

        tfm_match = re.search(b'(\\.NETCoreApp|\\.NETFramework|\\.NETStandard),Version=v([0-9\\.]+)', metadata_data)
        if tfm_match:
            framework_name_raw = tfm_match.group(1).decode(errors='ignore')
            framework_version = tfm_match.group(2).decode(errors='ignore')
            framework_map = {
                ".NETCoreApp": ".NET", ".NETFramework": ".NET Framework", ".NETStandard": ".NET Standard"
            }
            framework_name = framework_map.get(framework_name_raw, framework_name_raw)
            language = f"{framework_name} {framework_version}"
        elif metadata_data.startswith(b'BSJB'):
            version_len = struct.unpack('<I', metadata_data[12:16])[0]
            version_string_bytes = metadata_data[16 : 16 + version_len]
            version_string = version_string_bytes.partition(b'\x00')[0].decode('utf-8', errors='ignore')
            if version_string:
                language = f".NET Assembly (CLR {version_string})"
    except (AttributeError, struct.error, IndexError):
        pass
    return "N/A (.NET)", language

def _detect_dotnet_aot(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:

    
    
    if b'System.Private.CoreLib' in search_data:
        
        
        version_match = re.search(b'\\.NET(?: Core)? ([0-9]+\\.[0-9]+)', search_data)
        version_str = f" {version_match.group(1).decode(errors='ignore')}" if version_match else ""

        
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                
                if exp.name and exp.name.startswith(b'Rh'):
                    return f"Microsoft .NET{version_str} (Native AOT)", ".NET"

        return f"Microsoft .NET{version_str} (Native AOT)", ".NET"
    return None

def _detect_upx(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    if any(s.Name.startswith(b'UPX') for s in pe.sections):
        return "UPX Packer", "N/A (Packed)"
    return None

def _detect_autoit(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    if b'AU3!EA06' in search_data[-4096:]: 
        return "AutoIt v3 Script", "AutoIt"
    return None

def _detect_nsis(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    if b'NullsoftInst' in search_data or b'Nullsoft Install System' in search_data:
        return "NSIS (Nullsoft Installer)", "NSIS Script"
    return None

def _detect_inno(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    if any(s.Name.startswith(b'.itext') for s in pe.sections):
        return "Inno Setup", "Inno Script"
    if b'Inno Setup' in search_data:
        return "Inno Setup", "Inno Script"
    return None

def _detect_go(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    if any(s.Name.startswith(b'.gopclntab') for s in pe.sections) or re.search(b'go.buildid', search_data):
        return "Go Compiler", "Go"
    return None

def _detect_rust(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    rust_signatures = [b'rust_begin_unwind', b'panicking.rs', b'library/core/src', b'library/std/src']
    if any(re.search(re.escape(sig), search_data) for sig in rust_signatures) or \
       re.search(b'__rust_[a-zA-Z0-9_]+', search_data) or \
       (re.search(b'_ZN[0-9A-Za-z_]+E', search_data) and re.search(b'rustc', search_data, re.IGNORECASE)):
        return "Rust (Cargo)", "Rust"
    return None

def _detect_dlang(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.lower()
            if dll_name.startswith((b'phobos', b'druntime')):
                return "D Language", "D"
    
    if re.search(b'_Dmain|_DSO_NAME', search_data):
        return "D Language", "D"
    
    if re.search(re.escape(b'ldc.attributes'), search_data):
        return "D Language (LDC)", "D"
        
    return None

def _detect_nim(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    
    nim_signatures = [
        b'nim_main', b'nimrtl.dll', b'nimcache', b'Nim Main',
        b'invalid value for enum', b'SIGSEGV: Illegal storage access' 
    ]
    if any(re.search(re.escape(sig), search_data) for sig in nim_signatures):
        return "Nim", "Nim"
    return None

def _detect_free_pascal(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    match = re.search(b'Free Pascal.*?version ([0-9\\.]+)', search_data, re.IGNORECASE)
    if match:
        version = match.group(1).decode(errors='ignore')
        return f"Free Pascal/Lazarus (v{version})", "Pascal"

    if re.search(b'Free Pascal|FPC|Lazarus', search_data, re.IGNORECASE):
        return "Free Pascal/Lazarus", "Pascal"
    
    
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and any(exp.name and exp.name.startswith((b'FPC_', b'LAZ_')) for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols):
        return "Free Pascal/Lazarus", "Pascal"

    
    if re.search(b'\x07Classes\x05TList', search_data):
        return "Free Pascal/Lazarus", "Pascal"

    
    if re.search(b'SYSTEM_INITIALIZEUNITS', search_data):
        return "Free Pascal/Lazarus", "Pascal"
    return None

def _detect_mingw_gcc(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.lower()
            if dll_name.startswith(b'libgcc_') or dll_name.startswith(b'libstdc++'):
                return "MinGW/GCC", "C++" if b'stdc++' in dll_name else "C"
    if re.search(b'GCC: \\(GNU\\)', search_data):
        return "GCC", "C/C++"
    if re.search(b'mingw_init_ehandler', search_data):
        return "MinGW", "C/C++"
    return None

def _detect_intel(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    if re.search(b'Intel\\(R\\) C\\+\\+ Compiler', search_data):
        return "Intel C++ Compiler", "C++"
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and any(entry.dll.lower().startswith(b'libmmd') for entry in pe.DIRECTORY_ENTRY_IMPORT):
        return "Intel C++ Compiler", "C/C++"
    return None

def _detect_msvc(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    
    
    
    if hasattr(pe, 'RICH_HEADER') and hasattr(pe.RICH_HEADER, 'clear_data'):
        
        rich_prodid_to_vs = {
            81: " (VS 6.0)",
            84: " (VS 2002)",
            85: " (VS 2003)",
            86: " (VS 2005)",
            95: " (VS 2008)",
            109: " (VS 2010)",
            120: " (VS 2012)",
            121: " (VS 2013)",
            122: " (VS 2015)",
            123: " (VS 2017)", 
            141: " (VS 2019)", 
            145: " (VS 2022)", 
        }
        
        linker_prod_id = 0
        for entry in pe.RICH_HEADER.clear_data:
            
            
            if not isinstance(entry, dict):
                continue
            prod_id = entry.get('prodid', 0)
            
            if prod_id > linker_prod_id:
                linker_prod_id = prod_id

        version_str = ""
        if linker_prod_id > 0:
            
            
            best_match_key = -1
            for key in rich_prodid_to_vs.keys():
                if key <= linker_prod_id and key > best_match_key:
                    best_match_key = key
            if best_match_key != -1:
                version_str = rich_prodid_to_vs[best_match_key]
        
        if version_str or linker_prod_id > 0:
            compiler_name = f"Microsoft Visual C++{version_str}"
            
            return compiler_name, "C++" if _has_cpp_evidence(pe, search_data) else "C"

    
    
    msvc_signatures = [
        b'Microsoft Visual C\\+\\+ Runtime Library',
        b'\\.\\?A[UV]', 
    ]
    if any(re.search(sig, search_data) for sig in msvc_signatures):
        
        
        return "Microsoft Visual C++", "C++" if _has_cpp_evidence(pe, search_data) else "C"

    
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return None

    version_map = {
        '14': " (VS 2015-2022)",
        '12': " (VS 2013)", '11': " (VS 2012)", '10': " (VS 2010)",
        '90': " (VS 2008)", '80': " (VS 2005)", '71': " (VS 2003)",
        '70': " (VS 2002)", '60': " (VS 6.0)",
    }

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.lower()
        if dll_name.startswith((b'vcruntime', b'msvcp', b'msvcr')):
            match = re.search(b'(?:msvcr|msvcp|vcruntime)(\\d+)', dll_name)
            version_code = match.group(1).decode(errors='ignore') if match else ''
            version_suffix = next((v for k, v in version_map.items() if version_code.startswith(k)), "")
            compiler_name = f"Microsoft Visual C++{version_suffix}"
            return compiler_name, "C++" if _has_cpp_evidence(pe, search_data) or b'msvcp' in dll_name else "C"
    return None

def _detect_delphi(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    
    
    if any(b'Borland' in section.Name for section in pe.sections):
        return "Borland/Embarcadero Delphi or C++ Builder", "Delphi/Pascal or C++"

    
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if res_type.id == pefile.RESOURCE_TYPE['RT_RCDATA']:
                    if not hasattr(res_type, 'directory'): continue
                    for res_id in res_type.directory.entries:
                        if not hasattr(res_id, 'name') or not res_id.name or not hasattr(res_id.name, 'string'):
                            continue
                        
                        res_name = res_id.name.string
                        if res_name == b'PACKAGEINFO':
                            data_rva = res_id.directory.entries[0].data.struct.OffsetToData
                            size = res_id.directory.entries[0].data.struct.Size
                            data = pe.get_data(data_rva, size)
                            match = re.search(b'\\d{2}\\.\\d', data)
                            if match:
                                version = match.group(0).decode(errors='ignore')
                                return f"Embarcadero Delphi/C++ Builder (v{version})", "Delphi/Pascal"
                            return "Embarcadero Delphi/C++ Builder", "Delphi/Pascal"

                        if res_name in (b'DVCLAL', b'PLATFORMTARGETS'):
                            return "Borland/Embarcadero Delphi", "Delphi/Pascal"
        except Exception:
            pass
   
    
    if re.search(b'\x07TObject', search_data):
        return "Borland/Embarcadero Delphi", "Delphi/Pascal"
    if any(re.search(re.escape(sig), search_data) for sig in [b'System.SysUtils', b'System.Classes', b'Borland.Delphi', b'Embarcadero.Delphi', b'CodeGear Delphi']):
        return "Borland/Embarcadero Delphi", "Delphi/Pascal"

    return None

def _detect_vb6(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.lower()
            if dll_name == b'msvbvm60.dll':
                return "Microsoft Visual Basic 6", "Visual Basic"
            if dll_name == b'msvbvm50.dll':
                return "Microsoft Visual Basic 5", "Visual Basic"
    
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and b'ThunderRT6Main' in exp.name:
                return "Microsoft Visual Basic 6", "Visual Basic"
    return None

def _detect_assembler(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        total_imports = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
        total_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
        if total_dlls == 1 and pe.DIRECTORY_ENTRY_IMPORT[0].dll.lower() == b'kernel32.dll' and total_imports <= 5:
            return "Assembler (FASM/MASM/NASM)", "Assembly"
    elif not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return "Assembler (or Packer Stub)", "Assembly"
    return None

def _detect_protectors(pe: "pefile.PE", search_data: bytes) -> Optional[str]:
    
    if any(s.Name.startswith((b'.vmp0', b'.vmp1')) for s in pe.sections):
        return "VMProtect"
    
    if any(s.Name.startswith((b'.themida', b'.winlice')) for s in pe.sections):
        return "Themida/WinLicense"
    
    if any(s.Name.startswith(b'.enigma1') for s in pe.sections):
        return "Enigma Protector"
    return None

def _detect_qt(pe: "pefile.PE", search_data: bytes) -> Optional[tuple[str, str]]:
    rdata = next((s.get_data() for s in pe.sections if s.Name.startswith(b'.rdata')), None)
    if rdata:
        if re.search(b'Qt5Core\\.dll', rdata) or re.search(b'Qt6Core\\.dll', rdata):
            return "Qt Framework", "C++ (Qt)"
    return None

def analyze_pe_info(pe: "pefile.PE", analyze_all_sections: bool = True) -> Optional[FileInfo]:
    
    if not pe or not pefile:
        return None

    if analyze_all_sections:
        search_data = pe.__data__
    else:
        
        data_to_search = []
        for s in pe.sections:
            
            if s.Name.startswith((b'.text', b'.rdata', b'.data')):
                data_to_search.append(s.get_data())
        search_data = b''.join(data_to_search)

   
    file_data = pe.__data__
    hashes = {
        "md5": hashlib.md5(file_data).hexdigest(),
        "sha1": hashlib.sha1(file_data).hexdigest(),
        "sha256": hashlib.sha256(file_data).hexdigest(),
    }

    
    arch_map = {
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']: "x86 (32-bit)",
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']: "x86-64 (64-bit)",
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_IA64']: "Itanium",
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']: "ARM",
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']: "ARM64",
    }
    architecture = arch_map.get(pe.FILE_HEADER.Machine, "Unknown")

    try:
        timestamp_str = datetime.datetime.fromtimestamp(
            pe.FILE_HEADER.TimeDateStamp
        ).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, OSError): 
        timestamp_str = f"Invalid ({pe.FILE_HEADER.TimeDateStamp})"

    general_info = {
        "Entry Point": f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}",
        "Image Base": f"0x{pe.OPTIONAL_HEADER.ImageBase:x}",
        "Architecture": architecture,
        "Timestamp": timestamp_str,
        "Subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown"),
    }

    
    sections_info = []
    char_map = {
        'IMAGE_SCN_MEM_READ': "R", 'IMAGE_SCN_MEM_WRITE': "W", 'IMAGE_SCN_MEM_EXECUTE': "X"
    }
    for section in pe.sections:
        name = section.Name.decode(errors='ignore').strip('\x00')
        entropy = calculate_entropy(section.get_data())
        chars = [val for key, val in char_map.items() if section.Characteristics & getattr(pefile.SECTION_CHARACTERISTICS, key, 0)]
        sections_info.append(SectionInfo(
            name=name,
            virtual_address=pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress,
            virtual_size=section.Misc_VirtualSize,
            raw_size=section.SizeOfRawData,
            characteristics=chars,
            entropy=entropy
        ))

    
    security = SecurityFeatures()
    if hasattr(pe.OPTIONAL_HEADER, 'DllCharacteristics'):
        dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
        security.aslr = bool(dll_chars & pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE'])
        security.dep = bool(dll_chars & pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_NX_COMPAT'])
        security.control_flow_guard = bool(dll_chars & pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_GUARD_CF'])

    if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
        security.safe_seh = bool(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable > 0)

    if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress != 0:
        security.authenticode = True

    if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks != 0:
        security.tls_callbacks = hasattr(pe.DIRECTORY_ENTRY_TLS, 'callbacks') and bool(pe.DIRECTORY_ENTRY_TLS.callbacks)

    security.high_entropy_sections = any(s.entropy > 7.5 for s in sections_info)

    
    packer = "N/A"
    packer_detectors = [
        _detect_upx,
        _detect_protectors,
    ]
    for detector in packer_detectors:
        result = detector(pe, search_data)
        if result:
            
            if isinstance(result, tuple):
                packer = result[0]
            else:
                packer = result
            break

    
    compiler = "Unknown"
    language = "Unknown"

    
    high_level_detectors = [
        _detect_pyinstaller,
        _detect_dotnet,
        _detect_dotnet_aot,
        _detect_autoit,
        _detect_nsis,
        _detect_inno,
        _detect_vb6,
        _detect_qt,
    ]
    
    compiler_detectors = [
        _detect_go,
        _detect_rust,
        _detect_dlang,
        _detect_nim,
        _detect_free_pascal,
        _detect_mingw_gcc,
        _detect_intel,
        _detect_msvc,
        _detect_delphi,
        
        _detect_assembler,
    ]

    for detector in high_level_detectors + compiler_detectors:
        result = detector(pe, search_data)
        if result:
            compiler, language = result
            break

   
    imports = {}

    def _process_import_directory(import_entries, is_delayed=False):
        if not import_entries:
            return
        for entry in import_entries:
            try:
                dll_name_str = entry.dll.decode('utf-8', errors='ignore')
                if is_delayed:
                    
                    dll_name_str += " (delay-loaded)"

                if dll_name_str not in imports:
                    imports[dll_name_str] = []

                for imp in entry.imports:
                    func_name = f"Ordinal {imp.ordinal}"
                    if imp.name:
                        
                        func_name = imp.name.decode('utf-8', errors='surrogateescape')

                    if imp.address:
                        imports[dll_name_str].append(ImportedFunction(name=func_name, address=imp.address))
            except Exception:
                
                continue

    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        _process_import_directory(pe.DIRECTORY_ENTRY_IMPORT)

    
    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        _process_import_directory(pe.DIRECTORY_ENTRY_DELAY_IMPORT, is_delayed=True)

    exports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                
                export_va = pe.OPTIONAL_HEADER.ImageBase + exp.address
                exports[export_va] = exp.name.decode('utf-8', errors='surrogateescape')

    return FileInfo(
        hashes=hashes, general=general_info,
        compiler=compiler, language=language, packer=packer,
        security=security,
        sections=sections_info,
        imports=imports,
        exports=exports
    )