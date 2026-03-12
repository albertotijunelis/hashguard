"""PE (Portable Executable) analysis for HashGuard.

Inspects Windows executables (.exe, .dll, .sys) to extract:
- Section information with entropy analysis
- Import table (DLLs and functions)
- Packer / protector detection via high-entropy sections
- Suspicious API usage patterns
"""

import json
import math
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Set

from hashguard.logger import get_logger

logger = get_logger(__name__)


def _load_pe_indicators() -> tuple:
    """Load suspicious API names and packer sections from external data file."""
    # Frozen PyInstaller build
    if getattr(sys, "frozen", False):
        base = sys._MEIPASS
        path = os.path.join(base, "data", "pe_indicators.json")
    else:
        # Package data (pip install)
        pkg_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "data", "pe_indicators.json"
        )
        if os.path.isfile(pkg_path):
            path = pkg_path
        else:
            # Development fallback (project root)
            base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
            path = os.path.join(base, "data", "pe_indicators.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        apis = set(data.get("suspicious_apis", []))
        packers = data.get("packer_sections", {})
        return apis, packers
    except Exception as e:
        logger.warning(f"Could not load pe_indicators.json: {e}")
        return set(), {}


_SUSPICIOUS_APIS, _PACKER_SECTIONS = _load_pe_indicators()

PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".drv", ".ocx", ".cpl"}


def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for count in freq:
        if count:
            p = count / length
            ent -= p * math.log2(p)
    return round(ent, 4)


@dataclass
class PESection:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: str


@dataclass
class PEAnalysisResult:
    is_pe: bool = False
    machine: str = ""
    compile_time: str = ""
    entry_point: str = ""
    sections: List[PESection] = field(default_factory=list)
    imports: Dict[str, List[str]] = field(default_factory=dict)
    suspicious_imports: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    packed: bool = False
    packer_hint: str = ""
    overall_entropy: float = 0.0

    def to_dict(self) -> dict:
        return {
            "is_pe": self.is_pe,
            "machine": self.machine,
            "compile_time": self.compile_time,
            "entry_point": self.entry_point,
            "sections": [
                {
                    "name": s.name,
                    "virtual_size": s.virtual_size,
                    "raw_size": s.raw_size,
                    "entropy": s.entropy,
                    "characteristics": s.characteristics,
                }
                for s in self.sections
            ],
            "imports": self.imports,
            "suspicious_imports": self.suspicious_imports,
            "warnings": self.warnings,
            "packed": self.packed,
            "packer_hint": self.packer_hint,
            "overall_entropy": self.overall_entropy,
        }


def is_pe_file(path: str) -> bool:
    """Check if a file is a PE by extension or MZ header."""
    ext = os.path.splitext(path)[1].lower()
    if ext in PE_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except Exception:
        return False


def analyze_pe(path: str) -> PEAnalysisResult:
    """Perform deep PE analysis on a Windows executable."""
    result = PEAnalysisResult()

    if not is_pe_file(path):
        return result

    try:
        import pefile
    except ImportError:
        logger.warning("pefile not installed — PE analysis unavailable")
        return result

    try:
        pe = pefile.PE(path, fast_load=False)
    except pefile.PEFormatError:
        return result
    except Exception as e:
        logger.error(f"PE parse error: {e}")
        return result

    result.is_pe = True

    # Machine type
    machines = {0x14C: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0xAA64: "ARM64"}
    result.machine = machines.get(pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:X}")

    # Compile timestamp
    import datetime

    try:
        ts = pe.FILE_HEADER.TimeDateStamp
        result.compile_time = datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except Exception:
        result.compile_time = "Invalid"

    # Entry point
    result.entry_point = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}"

    # Sections
    high_entropy_count = 0
    total_raw = 0
    weighted_entropy = 0.0

    for section in pe.sections:
        try:
            name = section.Name.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            name = "<unknown>"

        raw_data = section.get_data()
        ent = _entropy(raw_data)
        raw_size = section.SizeOfRawData
        total_raw += raw_size
        weighted_entropy += ent * raw_size

        chars_flags = []
        if section.Characteristics & 0x20000000:
            chars_flags.append("EXEC")
        if section.Characteristics & 0x40000000:
            chars_flags.append("READ")
        if section.Characteristics & 0x80000000:
            chars_flags.append("WRITE")
        chars_str = " | ".join(chars_flags) if chars_flags else f"0x{section.Characteristics:08X}"

        pe_sec = PESection(
            name=name,
            virtual_size=section.Misc_VirtualSize,
            raw_size=raw_size,
            entropy=ent,
            characteristics=chars_str,
        )
        result.sections.append(pe_sec)

        if ent > 7.0:
            high_entropy_count += 1
        if "EXEC" in chars_str and "WRITE" in chars_str:
            result.warnings.append(f"Section '{name}' is both writable and executable")

    if total_raw > 0:
        result.overall_entropy = round(weighted_entropy / total_raw, 4)

    # Packer detection
    for section in result.sections:
        if section.name in _PACKER_SECTIONS:
            result.packed = True
            result.packer_hint = _PACKER_SECTIONS[section.name]
            break

    if not result.packed and high_entropy_count >= 2 and result.overall_entropy > 7.0:
        result.packed = True
        result.packer_hint = "Unknown (high entropy)"
        result.warnings.append("File appears to be packed or encrypted (high entropy)")

    # Imports
    try:
        pe.parse_data_directories()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode("utf-8", errors="replace")
                except Exception:
                    dll_name = "<unknown>"
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        try:
                            fname = imp.name.decode("utf-8", errors="replace")
                        except Exception:
                            fname = f"ord_{imp.ordinal}"
                        funcs.append(fname)
                        if fname in _SUSPICIOUS_APIS:
                            result.suspicious_imports.append(f"{dll_name}:{fname}")
                result.imports[dll_name] = funcs
    except Exception as e:
        logger.debug(f"Import parsing error: {e}")

    if result.suspicious_imports:
        result.warnings.append(f"Found {len(result.suspicious_imports)} suspicious API import(s)")

    pe.close()
    return result
