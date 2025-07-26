import dataclasses
import struct
from typing import List, TYPE_CHECKING, Optional, Dict
import re


if TYPE_CHECKING:
    import pefile
    from .info_analyzer import FileInfo

try:
    
    import pefile
except ImportError:
    pefile = None
    
try:
    import cxxfilt
except ImportError:
    cxxfilt = None

try:
    import dnfile
except ImportError:
    dnfile = None

@dataclasses.dataclass
class FoundClass:
    
    vtable_address: int
    name: str
    methods: List[int]  
    base_classes: List[str] = dataclasses.field(default_factory=list)
    method_names: Dict[int, str] = dataclasses.field(default_factory=dict)
    is_stub: bool = False

def _demangle_msvc_name(mangled_name: str) -> str:
    
    if mangled_name.startswith('.?A'):  
        
        if '@@' in mangled_name:
            name = mangled_name.split('@@')[0]
            if name.startswith('.?AV'): 
                name = name[4:]
            elif name.startswith('.?AU'): 
                name = name[4:]
            
            return name.replace('@', '::')
    return mangled_name

def _demangle_itanium_name(mangled_name: str) -> str:
    
    if not cxxfilt:
        
        if mangled_name.startswith('_ZTS'):
            return mangled_name[4:] 
        return mangled_name
    try:
        
        return cxxfilt.demangle(mangled_name)
    except Exception:
        return mangled_name 

def is_dotnet_assembly(pe: "pefile.PE") -> bool:
    
    if not pe or not pefile:
        return False
    return hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR') and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct.VirtualAddress != 0

def _is_pyinstaller_packed(pe: "pefile.PE") -> bool:
    
    if not pe:
        return False
    
    return b'MEI\x0c\x0b\x0a\x0b\x0e' in pe.__data__

def _find_dotnet_stubs(pe: "pefile.PE") -> List[int]:

    if not pe:
        return []

    text_section = next((s for s in pe.sections if s.Name.startswith(b'.text')), None)
    if not text_section:
        return []

    stubs = []
    data = text_section.get_data()
    image_base = pe.OPTIONAL_HEADER.ImageBase
    section_rva = text_section.VirtualAddress

    jmp_pattern = re.compile(b'\xff\x25')
    for match in jmp_pattern.finditer(data):
        if match.start() + 6 <= len(data):
            stub_va = image_base + section_rva + match.start()
            stubs.append(stub_va)
            
    return sorted(stubs)

def _find_dotnet_classes_with_dnfile(pe: "pefile.PE") -> Optional[List[FoundClass]]:
    
    if not dnfile:
        return None

    try:
        
        parsed_net = dnfile.dnPE(data=pe.__data__, fast_load=True)
        if not parsed_net.net or not parsed_net.net.mdtables:
            return None
    except Exception:
        return None 

    image_base = pe.OPTIONAL_HEADER.ImageBase
    found_classes_map = {}  

    type_defs = parsed_net.net.mdtables.TypeDef
    method_defs = parsed_net.net.mdtables.MethodDef
    if not type_defs or not method_defs:
        return None

    for i, type_def_row in enumerate(type_defs):
        if not type_def_row: continue
        rid = i + 1
        namespace = type_def_row.TypeNamespace.value.decode('utf-8', 'ignore')
        name = type_def_row.TypeName.value.decode('utf-8', 'ignore')
        full_name = f"{namespace}.{name}" if namespace else name
        
        method_start_index = type_def_row.MethodList.value - 1
        
        next_type_def_row = None
        for next_i in range(i + 1, len(type_defs)):
            if type_defs[next_i]:
                next_type_def_row = type_defs[next_i]
                break
        
        method_end_index = next_type_def_row.MethodList.value - 1 if next_type_def_row else len(method_defs)

        if method_start_index >= len(method_defs):
            continue

        
        cls = found_classes_map.get(rid)
        if not cls:
            cls = FoundClass(
                vtable_address=rid,
                name=full_name,
                is_stub=True,
            )
            found_classes_map[rid] = cls

        
        if type_def_row.Extends and type_def_row.Extends.row:
            base_row = type_def_row.Extends.row
            base_ns = base_row.TypeNamespace.value.decode('utf-8', 'ignore') if hasattr(base_row, 'TypeNamespace') else ''
            base_name = base_row.TypeName.value.decode('utf-8', 'ignore') if hasattr(base_row, 'TypeName') else ''
            if base_name and base_name != "Object":
                base_full_name = f"{base_ns}.{base_name}" if base_ns else base_name
                cls.base_classes.append(base_full_name)

        for method_index in range(method_start_index, method_end_index):
            method_row = method_defs[method_index]
            if not method_row: continue

            method_name = method_row.Name.value.decode('utf-8', 'ignore')
            method_rva = method_row.Rva.value
            
            if method_rva > 0:
                method_va = image_base + method_rva
                cls.methods.append(method_va)
                cls.method_names[method_va] = method_name

    
    return [cls for cls in found_classes_map.values() if cls.methods]

def _find_msvc_classes(pe: "pefile.PE") -> List[FoundClass]: 
    
    if not pe or not pefile:
        return []

    image_base = pe.OPTIONAL_HEADER.ImageBase
    is_64bit = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']
    pointer_size = 8 if is_64bit else 4
    unpack_format = '<Q' if is_64bit else '<I'

    
    data_sections = [s for s in pe.sections if s.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] and s.SizeOfRawData > 0]
    text_section = next((s for s in pe.sections if s.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']), None)

    if not data_sections or not text_section:
        return []

    
    
    type_descriptor_rvas = {}  
    name_pattern = re.compile(b'\\.\\?A[UV][A-Za-z0-9_@]+@@')
    name_offset_in_td = 16 if is_64bit else 8

    for section in data_sections:
        data = section.get_data()
        for match in name_pattern.finditer(data):
            try:
                td_rva = section.VirtualAddress + match.start() - name_offset_in_td
                
                if td_rva % 4 != 0:
                    continue
                mangled_name = match.group(0).decode('latin-1')
                type_descriptor_rvas[td_rva] = _demangle_msvc_name(mangled_name)
            except (IndexError, struct.error):
                continue

    if not type_descriptor_rvas:
        return []

    
    col_rvas = {}  
    td_rva_offset_in_col = 12  

    for section in data_sections:
        data = section.get_data()
        for i in range(0, len(data) - pointer_size + 1, 4): 
            ptr_val = struct.unpack(unpack_format, data[i : i + pointer_size])[0]
            ptr_rva = ptr_val - image_base
            if ptr_rva in type_descriptor_rvas:
                potential_col_rva = section.VirtualAddress + i - td_rva_offset_in_col
                try:
                    
                    col_data = pe.get_data(potential_col_rva, 4)
                    signature = struct.unpack('<I', col_data)[0]
                    expected_sig = 1 if is_64bit else 0
                    if signature == expected_sig:
                        col_rvas[potential_col_rva] = ptr_rva
                except Exception:
                    continue

    if not col_rvas:
        return []

    
    
    vtable_to_col = {}  

    for section in data_sections:
        data = section.get_data()
        for i in range(0, len(data) - pointer_size + 1, 4):
            ptr_val = struct.unpack(unpack_format, data[i : i + pointer_size])[0]
            ptr_rva = ptr_val - image_base
            if ptr_rva in col_rvas:
                vtable_rva = section.VirtualAddress + i + pointer_size
                vtable_va = image_base + vtable_rva
                vtable_to_col[vtable_va] = ptr_rva

    if not vtable_to_col:
        return []

    
    found_classes_dict = {}
    for vtable_va, col_rva in vtable_to_col.items():
        if vtable_va in found_classes_dict:
            continue

        td_rva = col_rvas[col_rva]
        class_name = type_descriptor_rvas[td_rva]

        
        base_classes = []
        try:
            
            chd_rva_offset_in_col = 20 if is_64bit else 16
            col_data = pe.get_data(col_rva, chd_rva_offset_in_col + 4)
            chd_rva = struct.unpack('<I', col_data[chd_rva_offset_in_col:chd_rva_offset_in_col+4])[0]

            chd_data = pe.get_data(chd_rva, 16)
            num_base_classes = struct.unpack('<I', chd_data[8:12])[0]
            base_class_array_rva = struct.unpack('<I', chd_data[12:16])[0]

            if num_base_classes > 0 and num_base_classes < 20: 
                bca_data = pe.get_data(base_class_array_rva, num_base_classes * 4)
                for i in range(num_base_classes):
                    bcd_rva = struct.unpack('<I', bca_data[i*4 : i*4+4])[0]
                    bcd_data = pe.get_data(bcd_rva, 4)
                    base_td_rva = struct.unpack('<I', bcd_data[0:4])[0]
                    if base_td_rva in type_descriptor_rvas:
                        base_classes.append(type_descriptor_rvas[base_td_rva])
        except Exception:
            pass 

        
        methods = []
        current_vtable_rva = vtable_va - image_base
        try:
            
            vtable_data = pe.get_data(current_vtable_rva, 512 * pointer_size)
            offset = 0
            while offset <= len(vtable_data) - pointer_size:
                method_va = struct.unpack(unpack_format, vtable_data[offset:offset + pointer_size])[0]
                if method_va == 0:
                    break

                method_rva = method_va - image_base
                if text_section.VirtualAddress <= method_rva < text_section.VirtualAddress + text_section.Misc_VirtualSize:
                    methods.append(method_va)
                else:
                    break  
                offset += pointer_size
        except Exception:
            pass

        if methods:
            found_classes_dict[vtable_va] = FoundClass(
                vtable_address=vtable_va, name=class_name, methods=methods, base_classes=base_classes
            )

    return sorted(list(found_classes_dict.values()), key=lambda c: c.vtable_address)

def _find_itanium_classes(pe: "pefile.PE") -> List[FoundClass]:
    
    image_base = pe.OPTIONAL_HEADER.ImageBase
    is_64bit = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']
    pointer_size = 8 if is_64bit else 4
    unpack_format = '<Q' if is_64bit else '<I'

    text_section = next((s for s in pe.sections if s.Name.startswith(b'.text')), None)
    if not text_section:
        return []

    data_sections = [s for s in pe.sections if s.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] and s.SizeOfRawData > 0]
    if not data_sections:
        return []

    
    name_string_pattern = re.compile(b'_ZTS[A-Za-z0-9_]+')
    name_rva_to_demangled_name = {}
    for section in data_sections:
        data = section.get_data()
        for match in name_string_pattern.finditer(data):
            
            if match.start() > 0 and data[match.start() - 1] != 0:
                continue

            mangled_name = match.group(0).decode('latin-1')
            name_rva = section.VirtualAddress + match.start()
            name_rva_to_demangled_name[name_rva] = _demangle_itanium_name(mangled_name)

    if not name_rva_to_demangled_name:
        return []

    
    type_info_rvas = {}  
    for section in data_sections:
        data = section.get_data()
        
        for i in range(0, len(data) - pointer_size + 1, 4):
            ptr_va = struct.unpack(unpack_format, data[i : i + pointer_size])[0]
            ptr_rva = ptr_va - image_base
            if ptr_rva in name_rva_to_demangled_name:
                
                type_info_rva = section.VirtualAddress + i - pointer_size
                type_info_rvas[type_info_rva] = name_rva_to_demangled_name[ptr_rva]

    if not type_info_rvas:
        return []

    
    found_classes: List[FoundClass] = []
    processed_vtables = set()

    for section in data_sections:
        data = section.get_data()
        for i in range(0, len(data) - pointer_size + 1, 4):
            ptr_va = struct.unpack(unpack_format, data[i : i + pointer_size])[0]
            ptr_rva = ptr_va - image_base
            if ptr_rva in type_info_rvas:
                
                vtable_rva = section.VirtualAddress + i - pointer_size
                if vtable_rva in processed_vtables:
                    continue

                class_name = type_info_rvas[ptr_rva]
                base_classes = []

                
                try:
                    ti_section = pe.get_section_by_rva(ptr_rva)
                    if ti_section:
                        ti_offset = ptr_rva - ti_section.VirtualAddress
                        ti_data = ti_section.get_data()
                        
                        base_ti_ptr_offset = ti_offset + 2 * pointer_size
                        if base_ti_ptr_offset + pointer_size <= len(ti_data):
                            base_ti_va = struct.unpack(unpack_format, ti_data[base_ti_ptr_offset : base_ti_ptr_offset + pointer_size])[0]
                            if base_ti_va != 0:
                                base_ti_rva = base_ti_va - image_base
                                if base_ti_rva in type_info_rvas:
                                    base_classes.append(type_info_rvas[base_ti_rva])
                except (struct.error, IndexError, AttributeError):
                    pass

                methods = []
                method_offset = i + pointer_size
                while method_offset < len(data) - pointer_size + 1:
                    method_va = struct.unpack(unpack_format, data[method_offset : method_offset + pointer_size])[0]
                    if method_va == 0:
                        break

                    method_rva = method_va - image_base
                    if text_section.VirtualAddress <= method_rva < text_section.VirtualAddress + text_section.Misc_VirtualSize:
                        methods.append(method_va)
                    else:
                        break
                    method_offset += pointer_size

                if methods:
                    vtable_va = image_base + vtable_rva
                    found_classes.append(FoundClass(
                        vtable_address=vtable_va, name=class_name, methods=methods, base_classes=base_classes
                    ))
                    processed_vtables.add(vtable_rva)

    return sorted(found_classes, key=lambda c: c.vtable_address)

def find_classes(pe: "pefile.PE", file_info: Optional["FileInfo"] = None) -> List[FoundClass]:
    
    if not pe or not pefile:
        return []

    
    if is_dotnet_assembly(pe):
        
        
        dotnet_classes = _find_dotnet_classes_with_dnfile(pe)
        if dotnet_classes:
            return sorted(dotnet_classes, key=lambda c: c.name)

        
        lang_str = file_info.language if file_info and ".NET" in file_info.language else ".NET Assembly"
        methods = _find_dotnet_stubs(pe)
        stub_class = FoundClass(
            vtable_address=0, 
            name=f"Managed Code ({lang_str})", 
            methods=methods,
            is_stub=True
        )
        return [stub_class]

    if _is_pyinstaller_packed(pe):
        stub_class = FoundClass(vtable_address=0, name="Python Application (PyInstaller)", methods=[], is_stub=True)
        return [stub_class]

    
    if file_info and "UPX" in file_info.compiler:
        stub_class = FoundClass(vtable_address=0, name="UPX Packed File (unpack first)", methods=[], is_stub=True)
        return [stub_class]

    
    msvc_classes = _find_msvc_classes(pe)
    itanium_classes = _find_itanium_classes(pe)

    all_classes = msvc_classes + itanium_classes
    
    unique_classes = {c.vtable_address: c for c in all_classes}.values()

    return sorted(list(unique_classes), key=lambda c: c.vtable_address)