import dataclasses
import re
from typing import List, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import pefile

@dataclasses.dataclass
class ScanResult:
    address: int
    name: str
    type: str
    signature_id: str

def _pattern_to_regex(pattern: bytes) -> re.Pattern:
    pattern = pattern.replace(b' ', b'')
    if len(pattern) % 2 != 0:
        return re.compile(b'(?!)') 

    regex_pattern = b''
    i = 0
    while i < len(pattern):
        byte_str = pattern[i:i+2]
        if byte_str == b'??':
            regex_pattern += b'.'
        else:
            try:
                byte_val = int(byte_str, 16)
                regex_pattern += re.escape(bytes([byte_val]))
            except ValueError:
                return re.compile(b'(?!)')
        i += 2
    return re.compile(regex_pattern, re.DOTALL)

class SignatureScanner:
    def __init__(self, signatures: Dict[str, Dict]):
        self.signatures = []
        for sig_id, sig_data in signatures.items():
            self.signatures.append({
                "id": sig_id,
                "regex": _pattern_to_regex(sig_data.get("pattern", b"")),
                "name": sig_data.get("name", "Unnamed"),
                "type": sig_data.get("type", "unknown")
            })

    def scan(self, pe: "pefile.PE") -> List[ScanResult]:
        if not pe:
            return []
        
        results = []
        file_data = pe.__data__
        image_base = pe.OPTIONAL_HEADER.ImageBase

        for sig in self.signatures:
            for match in sig["regex"].finditer(file_data):
                offset = match.start()
                address = offset
                try:
                    rva = pe.get_rva_from_offset(offset)
                    address = image_base + rva
                except Exception:
                    pass
                
                results.append(ScanResult(address=address, name=sig["name"], type=sig["type"], signature_id=sig["id"]))
        
        unique_results = { (r.address, r.signature_id): r for r in results }
        return sorted(list(unique_results.values()), key=lambda r: r.address)