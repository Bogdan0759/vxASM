import dataclasses

@dataclasses.dataclass
class Instruction:
    
    address: int
    size: int
    mnemonic: str
    operands: str
    bytes: bytes
    is_error: bool = False

    def __str__(self):
       
        hex_bytes = ' '.join(f'{b:02x}' for b in self.bytes)
        return f"0x{self.address:08x}: {hex_bytes:<24} {self.mnemonic} {self.operands}"