import dataclasses
import struct
import zlib
import marshal
import math
from typing import List, Optional, TYPE_CHECKING
import pefile

if TYPE_CHECKING:
    from .info_analyzer import FileInfo


try:
    import pefile
except ImportError:
    pefile = None
@dataclasses.dataclass
class ExplorerNode:
    
    name: str
    node_type: str  
    size: int = 0
    data_pos: int = 0  
    data_len: int = 0  
    children: List['ExplorerNode'] = dataclasses.field(default_factory=list)

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

def _parse_pyinstaller_archive(pe: "pefile.PE") -> Optional[ExplorerNode]:
    
    try:
        magic = b'MEI\x0c\x0b\x0a\x0b\x0e'
        
        
        file_data = pe.__data__
        archive_start = file_data.rfind(magic)
        
        if archive_start == -1:
            return None
        
        
        header_pos = archive_start + len(magic)
        
        
        _length, toc_pos, toc_len, _py_ver = struct.unpack('<IIII', file_data[header_pos : header_pos + 16])

        
        compressed_toc_start = archive_start + toc_pos
        compressed_toc_end = compressed_toc_start + toc_len
        compressed_toc = file_data[compressed_toc_start : compressed_toc_end]
        toc = marshal.loads(zlib.decompress(compressed_toc))

        root = ExplorerNode(name="PyInstaller Archive", node_type='directory')
        
        
        dir_nodes = {'': root}

        for entry in toc:
            
            full_path, data_pos, data_size, _entry_type = entry
            if isinstance(full_path, bytes):
                full_path = full_path.decode('utf-8', errors='ignore')
            
            path_parts = full_path.replace('\\', '/').split('/')
            filename = path_parts[-1]
            current_path = ''

            
            for part in path_parts[:-1]:
                parent_path = current_path
                current_path = f"{current_path}/{part}" if current_path else part
                if current_path not in dir_nodes:
                    new_dir = ExplorerNode(name=part, node_type='directory')
                    dir_nodes[parent_path].children.append(new_dir)
                    dir_nodes[current_path] = new_dir
            
            
            absolute_data_pos = archive_start + data_pos
            file_node = ExplorerNode(name=filename, node_type='file', size=data_size, data_pos=absolute_data_pos, data_len=data_size)
            dir_nodes[current_path].children.append(file_node)

        return root

    except Exception:
        
        return None

def _analyze_upx(pe: "pefile.PE", file_info: Optional["FileInfo"] = None) -> Optional[ExplorerNode]:
    
    if file_info and "UPX" in file_info.packer:
        return ExplorerNode(name="UPX Packed File", node_type='directory')
    
    upx_sections = [s.Name.decode(errors='ignore').strip('\x00') for s in pe.sections if s.Name.startswith(b'UPX')]
    if upx_sections:
        return ExplorerNode(name=f"UPX Packed File (секции: {', '.join(upx_sections)})", node_type='directory')

    return None


def _analyze_other_packers(pe: "pefile.PE") -> Optional[ExplorerNode]:
    
    
    aspack_sections = [s.Name.decode(errors='ignore').strip('\x00') for s in pe.sections if s.Name.startswith(b'.aspack') or s.Name.startswith(b'.adata')]
    if aspack_sections:
        return ExplorerNode(name=f"ASPack Packed File (секции: {', '.join(aspack_sections)})", node_type='directory')
    
    
    mpress_sections = [s.Name.decode(errors='ignore').strip('\x00') for s in pe.sections if s.Name.startswith(b'MPRESS')]
    if mpress_sections:
        return ExplorerNode(name=f"MPRESS Packed File (секции: {', '.join(mpress_sections)})", node_type='directory')

    
    fsg_sections = [s.Name.decode(errors='ignore').strip('\x00') for s in pe.sections if s.Name.startswith(b'.fsg')]
    if fsg_sections:
        return ExplorerNode(name=f"FSG Packed File (секции: {', '.join(fsg_sections)})", node_type='directory')

    return None

def _parse_pe_headers(pe: "pefile.PE") -> Optional[ExplorerNode]:
    
    if not hasattr(pe, 'OPTIONAL_HEADER') or not hasattr(pe, 'FILE_HEADER'):
        return None

    headers_root = ExplorerNode(name="Headers", node_type='directory')

    
    headers_root.children.append(ExplorerNode(name="DOS Header", node_type='directory'))
    headers_root.children.append(ExplorerNode(name="NT Headers", node_type='directory'))
    headers_root.children.append(ExplorerNode(name="File Header", node_type='directory'))
    headers_root.children.append(ExplorerNode(name="Optional Header", node_type='directory'))

    
    if hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
        data_dirs_node = ExplorerNode(name="Data Directories", node_type='directory')
        for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if d.Size > 0:
                dir_node = ExplorerNode(
                    name=f"{d.name.replace('IMAGE_DIRECTORY_ENTRY_', '')}: RVA=0x{d.VirtualAddress:x}, Size={d.Size}",
                    node_type='file', 
                    size=d.Size,
                    data_pos=pe.get_offset_from_rva(d.VirtualAddress),
                    data_len=d.Size
                )
                data_dirs_node.children.append(dir_node)
        if data_dirs_node.children:
            headers_root.children.append(data_dirs_node)
    
    return headers_root

def _parse_resources(pe: "pefile.PE") -> Optional[ExplorerNode]:
    
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return None

    resources_root = ExplorerNode(name="Resources", node_type='directory')
    
    rt_map = {
        pefile.RESOURCE_TYPE['RT_CURSOR']: "Cursors",
        pefile.RESOURCE_TYPE['RT_BITMAP']: "Bitmaps",
        pefile.RESOURCE_TYPE['RT_ICON']: "Icons",
        pefile.RESOURCE_TYPE['RT_MENU']: "Menus",
        pefile.RESOURCE_TYPE['RT_DIALOG']: "Dialogs",
        pefile.RESOURCE_TYPE['RT_STRING']: "String Tables",
        pefile.RESOURCE_TYPE['RT_FONTDIR']: "Font Directories",
        pefile.RESOURCE_TYPE['RT_FONT']: "Fonts",
        pefile.RESOURCE_TYPE['RT_ACCELERATOR']: "Accelerators",
        pefile.RESOURCE_TYPE['RT_RCDATA']: "Raw Data (RCData)",
        pefile.RESOURCE_TYPE['RT_MESSAGETABLE']: "Message Tables",
        pefile.RESOURCE_TYPE['RT_GROUP_CURSOR']: "Cursor Groups",
        pefile.RESOURCE_TYPE['RT_GROUP_ICON']: "Icon Groups",
        pefile.RESOURCE_TYPE['RT_VERSION']: "Version Info",
        pefile.RESOURCE_TYPE['RT_DLGINCLUDE']: "Dialog Includes",
        pefile.RESOURCE_TYPE['RT_PLUGPLAY']: "Plug and Play",
        pefile.RESOURCE_TYPE['RT_VXD']: "Virtual Drivers",
        pefile.RESOURCE_TYPE['RT_ANICURSOR']: "Animated Cursors",
        pefile.RESOURCE_TYPE['RT_ANIICON']: "Animated Icons",
        pefile.RESOURCE_TYPE['RT_HTML']: "HTML",
        pefile.RESOURCE_TYPE['RT_MANIFEST']: "Manifests",
    }

    def _walk_resource_tree(node: ExplorerNode, res_dir, level: int):
        for entry in res_dir.entries:
            name = str(entry.id) if entry.id is not None else (entry.name.string if entry.name else "Unnamed")
            if level == 0 and entry.id in rt_map:
                name = rt_map[entry.id]

            child_node = ExplorerNode(name=name, node_type='directory')
            node.children.append(child_node)

            if hasattr(entry, 'directory') and entry.directory:
                _walk_resource_tree(child_node, entry.directory, level + 1)
            elif hasattr(entry, 'data') and entry.data:
                child_node.node_type = 'file'
                child_node.size = entry.data.struct.Size
                child_node.data_pos = pe.get_offset_from_rva(entry.data.struct.OffsetToData)
                child_node.data_len = entry.data.struct.Size

    _walk_resource_tree(resources_root, pe.DIRECTORY_ENTRY_RESOURCE, 0)

    return resources_root if resources_root.children else None

def _build_generic_pe_view(pe: "pefile.PE") -> Optional[ExplorerNode]:
    
    root = ExplorerNode(name="PE Structure", node_type='directory')
    has_content = False

    
    headers_node = _parse_pe_headers(pe)
    if headers_node:
        root.children.append(headers_node)
        has_content = True

    
    resources_node = _parse_resources(pe)
    if resources_node:
        root.children.append(resources_node)
        has_content = True

    
    if pe.sections:
        sections_node = ExplorerNode(name="Sections", node_type='directory')
        for section in pe.sections:
            section_name = section.Name.decode(errors='ignore').strip('\x00')
            entropy = calculate_entropy(section.get_data())
            node = ExplorerNode(
                name=f"{section_name} (Энтропия: {entropy:.2f})",
                node_type='file',
                size=section.SizeOfRawData,
                data_pos=section.PointerToRawData,
                data_len=section.SizeOfRawData
            )
            sections_node.children.append(node)
        if sections_node.children:
            root.children.append(sections_node)
            has_content = True

    
    overlay_data_start = pe.get_overlay_data_start_offset()
    if overlay_data_start is not None:
        overlay_size = len(pe.__data__) - overlay_data_start
        if overlay_size > 8:
            entropy = calculate_entropy(pe.get_overlay())
            overlay_node = ExplorerNode(
                name=f"Overlay (Энтропия: {entropy:.2f})", node_type='file', size=overlay_size,
                data_pos=overlay_data_start, data_len=overlay_size
            )
            root.children.append(overlay_node)
            has_content = True

    return root if has_content else None
def analyze_structure(pe: "pefile.PE", file_info: Optional["FileInfo"] = None) -> Optional[ExplorerNode]:
    
    if not pe:
        return None
        
    analyzers = [
        _parse_pyinstaller_archive,
        lambda p: _analyze_upx(p, file_info),
        _analyze_other_packers,
    ]

    for analyzer in analyzers:
        result = analyzer(pe)
        if result:
            return result

    
    return _build_generic_pe_view(pe)