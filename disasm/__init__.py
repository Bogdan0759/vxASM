from .disassembler import Disassembler
from .instruction import Instruction
from .analyzer import find_functions, FoundFunction, find_xrefs, flag_consecutive_errors
from .class_analyzer import find_classes, FoundClass, is_dotnet_assembly
from .debugger_analyzer import analyze_anti_debug, DetectionResult
from .info_analyzer import analyze_pe_info, FileInfo, ImportedFunction, _detect_msvc, SecurityFeatures, SectionInfo
from .explorer_analyzer import analyze_structure, ExplorerNode
from .var_search import find_variables, FoundVariable
from .signature_scanner import SignatureScanner, ScanResult
from .signatures import SIGNATURES

__all__ = [
    "Disassembler",
    "Instruction",
    "find_functions",
    "FoundFunction",
    "find_xrefs",
    "flag_consecutive_errors",
    "find_classes",
    "FoundClass",
    "is_dotnet_assembly",
    "analyze_anti_debug",
    "DetectionResult",
    "analyze_pe_info",
    "FileInfo",
    "ImportedFunction",
    "SecurityFeatures",
    "SectionInfo",
    "analyze_structure",
    "ExplorerNode",
    "_detect_msvc",
    "find_variables",
    "FoundVariable",
    "SignatureScanner",
    "ScanResult",
    "SIGNATURES",
]